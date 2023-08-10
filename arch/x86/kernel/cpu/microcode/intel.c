// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Intel CPU Microcode Update Driver for Linux
 *
 * Copyright (C) 2000-2006 Tigran Aivazian <aivazian.tigran@gmail.com>
 *		 2006 Shaohua Li <shaohua.li@intel.com>
 *
 * Intel CPU microcode early update for Linux
 *
 * Copyright (C) 2012 Fenghua Yu <fenghua.yu@intel.com>
 *		      H Peter Anvin" <hpa@zytor.com>
 */
#define pr_fmt(fmt) "microcode: " fmt
#include <linux/earlycpio.h>
#include <linux/firmware.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/initrd.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/uio.h>
#include <linux/mm.h>

#include <asm/intel-family.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/setup.h>
#include <asm/msr.h>

#include "internal.h"

static const char ucode_path[] = "kernel/x86/microcode/GenuineIntel.bin";

/* Current microcode patch used in early patching on the APs. */
static struct microcode_intel *ucode_patch_va __read_mostly;
static struct microcode_intel *ucode_patch_late __read_mostly;

/* last level cache size per core */
static unsigned int llc_size_per_core __ro_after_init;

int intel_cpu_collect_info(struct ucode_cpu_info *uci)
{
	unsigned int val[2];
	unsigned int family, model;
	struct cpu_signature csig = { 0 };
	unsigned int eax, ebx, ecx, edx;

	memset(uci, 0, sizeof(*uci));

	eax = 0x00000001;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	csig.sig = eax;

	family = x86_family(eax);
	model  = x86_model(eax);

	if (model >= 5 || family > 6) {
		/* get processor flags from MSR 0x17 */
		native_rdmsr(MSR_IA32_PLATFORM_ID, val[0], val[1]);
		csig.pf = 1 << ((val[1] >> 18) & 7);
	}

	csig.rev = intel_get_microcode_revision();

	uci->cpu_sig = csig;

	return 0;
}
EXPORT_SYMBOL_GPL(intel_cpu_collect_info);

/*
 * Returns 1 if update has been found, 0 otherwise.
 */
int intel_find_matching_signature(void *mc, unsigned int csig, int cpf)
{
	struct microcode_header_intel *mc_hdr = mc;
	struct extended_sigtable *ext_hdr;
	struct extended_signature *ext_sig;
	int i;

	if (intel_cpu_signatures_match(csig, cpf, mc_hdr->sig, mc_hdr->pf))
		return 1;

	/* Look for ext. headers: */
	if (get_totalsize(mc_hdr) <= intel_microcode_get_datasize(mc_hdr) + MC_HEADER_SIZE)
		return 0;

	ext_hdr = mc + intel_microcode_get_datasize(mc_hdr) + MC_HEADER_SIZE;
	ext_sig = (void *)ext_hdr + EXT_HEADER_SIZE;

	for (i = 0; i < ext_hdr->count; i++) {
		if (intel_cpu_signatures_match(csig, cpf, ext_sig->sig, ext_sig->pf))
			return 1;
		ext_sig++;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(intel_find_matching_signature);

/**
 * intel_microcode_sanity_check() - Sanity check microcode file.
 * @mc: Pointer to the microcode file contents.
 * @print_err: Display failure reason if true, silent if false.
 * @hdr_type: Type of file, i.e. normal microcode file or In Field Scan file.
 *            Validate if the microcode header type matches with the type
 *            specified here.
 *
 * Validate certain header fields and verify if computed checksum matches
 * with the one specified in the header.
 *
 * Return: 0 if the file passes all the checks, -EINVAL if any of the checks
 * fail.
 */
int intel_microcode_sanity_check(void *mc, bool print_err, int hdr_type)
{
	unsigned long total_size, data_size, ext_table_size;
	struct microcode_header_intel *mc_header = mc;
	struct extended_sigtable *ext_header = NULL;
	u32 sum, orig_sum, ext_sigcount = 0, i;
	struct extended_signature *ext_sig;

	total_size = get_totalsize(mc_header);
	data_size = intel_microcode_get_datasize(mc_header);

	if (data_size + MC_HEADER_SIZE > total_size) {
		if (print_err)
			pr_err("Error: bad microcode data file size.\n");
		return -EINVAL;
	}

	if (mc_header->ldrver != 1 || mc_header->hdrver != hdr_type) {
		if (print_err)
			pr_err("Error: invalid/unknown microcode update format. Header type %d\n",
			       mc_header->hdrver);
		return -EINVAL;
	}

	ext_table_size = total_size - (MC_HEADER_SIZE + data_size);
	if (ext_table_size) {
		u32 ext_table_sum = 0;
		u32 *ext_tablep;

		if (ext_table_size < EXT_HEADER_SIZE ||
		    ((ext_table_size - EXT_HEADER_SIZE) % EXT_SIGNATURE_SIZE)) {
			if (print_err)
				pr_err("Error: truncated extended signature table.\n");
			return -EINVAL;
		}

		ext_header = mc + MC_HEADER_SIZE + data_size;
		if (ext_table_size != exttable_size(ext_header)) {
			if (print_err)
				pr_err("Error: extended signature table size mismatch.\n");
			return -EFAULT;
		}

		ext_sigcount = ext_header->count;

		/*
		 * Check extended table checksum: the sum of all dwords that
		 * comprise a valid table must be 0.
		 */
		ext_tablep = (u32 *)ext_header;

		i = ext_table_size / sizeof(u32);
		while (i--)
			ext_table_sum += ext_tablep[i];

		if (ext_table_sum) {
			if (print_err)
				pr_warn("Bad extended signature table checksum, aborting.\n");
			return -EINVAL;
		}
	}

	/*
	 * Calculate the checksum of update data and header. The checksum of
	 * valid update data and header including the extended signature table
	 * must be 0.
	 */
	orig_sum = 0;
	i = (MC_HEADER_SIZE + data_size) / sizeof(u32);
	while (i--)
		orig_sum += ((u32 *)mc)[i];

	if (orig_sum) {
		if (print_err)
			pr_err("Bad microcode data checksum, aborting.\n");
		return -EINVAL;
	}

	if (!ext_table_size)
		return 0;

	/*
	 * Check extended signature checksum: 0 => valid.
	 */
	for (i = 0; i < ext_sigcount; i++) {
		ext_sig = (void *)ext_header + EXT_HEADER_SIZE +
			  EXT_SIGNATURE_SIZE * i;

		sum = (mc_header->sig + mc_header->pf + mc_header->cksum) -
		      (ext_sig->sig + ext_sig->pf + ext_sig->cksum);
		if (sum) {
			if (print_err)
				pr_err("Bad extended signature checksum, aborting.\n");
			return -EINVAL;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(intel_microcode_sanity_check);

static void update_ucode_pointer(struct microcode_intel *mc)
{
	kfree(ucode_patch_va);

	/*
	 * Save the virtual address for early loading on 64bit
	 * and for eventual free on late loading.
	 *
	 * On 32-bit, that needs to store the physical address too as the
	 * APs are loading before paging has been enabled.
	 */
	ucode_patch_va = mc;
}

static void save_microcode_patch(struct microcode_intel *patch)
{
	struct microcode_intel *mc;

	mc = kmemdup(patch, get_totalsize(&patch->hdr), GFP_KERNEL);
	if (mc)
		update_ucode_pointer(mc);
	else
		pr_err("Unable to allocate microcode memory\n");
}

/* Scan CPIO for microcode matching the boot CPUs family, model, stepping */
static __init struct microcode_intel *scan_microcode(void *data, size_t size,
						     struct ucode_cpu_info *uci)
{
	struct microcode_header_intel *mc_header;
	struct microcode_intel *patch = NULL;
	u32 cur_rev = uci->cpu_sig.rev;
	unsigned int mc_size;

	for (; size >= sizeof(struct microcode_header_intel); size -= mc_size, data += mc_size) {
		mc_header = (struct microcode_header_intel *)data;

		mc_size = get_totalsize(mc_header);
		if (!mc_size || mc_size > size ||
		    intel_microcode_sanity_check(data, false, MC_HEADER_TYPE_MICROCODE) < 0)
			break;

		if (!intel_find_matching_signature(data, uci->cpu_sig.sig, uci->cpu_sig.pf))
			continue;

		/* Check whether there is newer microcode */
		if (cur_rev >= mc_header->rev)
			continue;

		patch = data;
		cur_rev = mc_header->rev;
	}

	return size ? NULL : patch;
}

static void print_ucode_info(int old_rev, int new_rev, unsigned int date)
{
	pr_info_once("updated early: 0x%x -> 0x%x, date = %04x-%02x-%02x\n",
		     old_rev, new_rev, date & 0xffff, date >> 24, (date >> 16) & 0xff);
}

#ifdef CONFIG_X86_32

static int delay_ucode_info;
static int current_mc_date;
static int early_old_rev;

/*
 * Print early updated ucode info after printk works. This is delayed info dump.
 */
void show_ucode_info_early(void)
{
	struct ucode_cpu_info uci;

	if (delay_ucode_info) {
		intel_cpu_collect_info(&uci);
		print_ucode_info(early_old_rev, uci.cpu_sig.rev, current_mc_date);
		delay_ucode_info = 0;
	}
}

/*
 * At this point, we can not call printk() yet. Delay printing microcode info in
 * show_ucode_info_early() until printk() works.
 */
static void print_ucode(int old_rev, int new_rev, int date)
{
	int *delay_ucode_info_p;
	int *current_mc_date_p;
	int *early_old_rev_p;

	delay_ucode_info_p = (int *)__pa_nodebug(&delay_ucode_info);
	current_mc_date_p = (int *)__pa_nodebug(&current_mc_date);
	early_old_rev_p = (int *)__pa_nodebug(&early_old_rev);

	*delay_ucode_info_p = 1;
	*current_mc_date_p = date;
	*early_old_rev_p = old_rev;
}
#else

static inline void print_ucode(int old_rev, int new_rev, int date)
{
	print_ucode_info(old_rev, new_rev, date);
}
#endif

static enum ucode_state apply_microcode_early(struct ucode_cpu_info *uci, bool early)
{
	struct microcode_intel *mc;
	u32 rev, old_rev;

	mc = uci->mc;
	if (!mc)
		return UCODE_NFOUND;

	/*
	 * Save us the MSR write below - which is a particular expensive
	 * operation - when the other hyperthread has updated the microcode
	 * already.
	 */
	rev = intel_get_microcode_revision();
	if (rev >= mc->hdr.rev) {
		uci->cpu_sig.rev = rev;
		return UCODE_OK;
	}

	old_rev = rev;

	/*
	 * Writeback and invalidate caches before updating microcode to avoid
	 * internal issues depending on what the microcode is updating.
	 */
	native_wbinvd();

	/* write microcode via MSR 0x79 */
	native_wrmsrl(MSR_IA32_UCODE_WRITE, (unsigned long)mc->bits);

	rev = intel_get_microcode_revision();
	if (rev != mc->hdr.rev)
		return UCODE_ERROR;

	uci->cpu_sig.rev = rev;

	if (early)
		print_ucode(old_rev, uci->cpu_sig.rev, mc->hdr.date);
	else
		print_ucode_info(old_rev, uci->cpu_sig.rev, mc->hdr.date);

	return UCODE_UPDATED;
}

static __init bool load_builtin_intel_microcode(struct cpio_data *cp)
{
	unsigned int eax = 1, ebx, ecx = 0, edx;
	struct firmware fw;
	char name[30];

	if (IS_ENABLED(CONFIG_X86_32))
		return false;

	native_cpuid(&eax, &ebx, &ecx, &edx);

	sprintf(name, "intel-ucode/%02x-%02x-%02x",
		x86_family(eax), x86_model(eax), x86_stepping(eax));

	if (firmware_request_builtin(&fw, name)) {
		cp->size = fw.size;
		cp->data = (void *)fw.data;
		return true;
	}
	return false;
}

static __init struct microcode_intel *get_ucode_from_cpio(struct ucode_cpu_info *uci)
{
	bool use_pa = IS_ENABLED(CONFIG_X86_32);
	const char *path = ucode_path;
	struct cpio_data cp;

	/* Paging is not yet enabled on 32bit! */
	if (IS_ENABLED(CONFIG_X86_32))
		path = (const char *)__pa_nodebug(ucode_path);

	/* Try built-in microcode first */
	if (!load_builtin_intel_microcode(&cp))
		cp = find_microcode_in_initrd(path, use_pa);

	if (!(cp.data && cp.size))
		return NULL;

	intel_cpu_collect_info(uci);

	return scan_microcode(cp.data, cp.size, uci);
}

static struct microcode_intel *ucode_early_pa __initdata;

/*
 * Invoked from an early init call to save the microcode blob which was
 * selected during early boot when mm was not usable. The microcode must be
 * saved because initrd is going away. It's an early init call so the APs
 * just can use the pointer and do not have to scan initrd/builtin firmware
 * again.
 */
static int __init save_microcode_from_cpio(void)
{
	struct microcode_intel *mc;

	if (!ucode_early_pa)
		return 0;

	mc = __va((void *)ucode_early_pa);
	save_microcode_patch(mc);
	return 0;
}
early_initcall(save_microcode_from_cpio);

/* Load microcode on BSP from CPIO */
void __init load_ucode_intel_bsp(void)
{
	struct ucode_cpu_info uci;

	uci.mc = get_ucode_from_cpio(&uci);
	if (!uci.mc)
		return;

	if (apply_microcode_early(&uci, true) != UCODE_UPDATED)
		return;

	if (IS_ENABLED(CONFIG_X86_64)) {
		/* Store the physical address as KASLR happens after this. */
		ucode_early_pa = (struct microcode_intel *)__pa_nodebug(uci.mc);
	} else {
		struct microcode_intel **uce;

		/* Physical address pointer required for 32-bit */
		uce = (struct microcode_intel **)__pa_nodebug(&ucode_early_pa);
		/* uci.mc is the physical address of the microcode blob */
		*uce = uci.mc;
	}
}

/* Load microcode on AP bringup */
void load_ucode_intel_ap(void)
{
	struct ucode_cpu_info uci;

	/* Must use physical address on 32bit as paging is not yet enabled */
	uci.mc = ucode_patch_va;
	if (IS_ENABLED(CONFIG_X86_32))
		uci.mc = (struct microcode_intel *)__pa_nodebug(uci.mc);

	if (uci.mc)
		apply_microcode_early(&uci, true);
}

/* Reload microcode on resume */
void reload_ucode_intel(void)
{
	struct ucode_cpu_info uci = { .mc = ucode_patch_va, };

	if (uci.mc)
		apply_microcode_early(&uci, false);
}

static int collect_cpu_info(int cpu_num, struct cpu_signature *csig)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu_num);
	unsigned int val[2];

	memset(csig, 0, sizeof(*csig));

	csig->sig = cpuid_eax(0x00000001);

	if ((c->x86_model >= 5) || (c->x86 > 6)) {
		/* get processor flags from MSR 0x17 */
		rdmsr(MSR_IA32_PLATFORM_ID, val[0], val[1]);
		csig->pf = 1 << ((val[1] >> 18) & 7);
	}

	csig->rev = c->microcode;

	return 0;
}

static enum ucode_state apply_microcode_intel(int cpu)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	bool bsp = c->cpu_index == boot_cpu_data.cpu_index;
	struct microcode_intel *mc;
	enum ucode_state ret;
	static int prev_rev;
	u32 rev;

	/* We should bind the task to the CPU */
	if (WARN_ON(raw_smp_processor_id() != cpu))
		return UCODE_ERROR;

	mc = ucode_patch_late;
	if (!mc)
		return UCODE_NFOUND;

	/*
	 * Save us the MSR write below - which is a particular expensive
	 * operation - when the other hyperthread has updated the microcode
	 * already.
	 */
	rev = intel_get_microcode_revision();
	if (rev >= mc->hdr.rev) {
		ret = UCODE_OK;
		goto out;
	}

	/*
	 * Writeback and invalidate caches before updating microcode to avoid
	 * internal issues depending on what the microcode is updating.
	 */
	native_wbinvd();

	/* write microcode via MSR 0x79 */
	wrmsrl(MSR_IA32_UCODE_WRITE, (unsigned long)mc->bits);

	rev = intel_get_microcode_revision();

	if (rev != mc->hdr.rev) {
		pr_err("CPU%d update to revision 0x%x failed\n",
		       cpu, mc->hdr.rev);
		return UCODE_ERROR;
	}

	if (bsp && rev != prev_rev) {
		pr_info("updated to revision 0x%x, date = %04x-%02x-%02x\n",
			rev,
			mc->hdr.date & 0xffff,
			mc->hdr.date >> 24,
			(mc->hdr.date >> 16) & 0xff);
		prev_rev = rev;
	}

	ret = UCODE_UPDATED;

out:
	uci->cpu_sig.rev = rev;
	c->microcode	 = rev;

	/* Update boot_cpu_data's revision too, if we're on the BSP: */
	if (bsp)
		boot_cpu_data.microcode = rev;

	return ret;
}

static enum ucode_state read_ucode_intel(int cpu, struct iov_iter *iter)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
	unsigned int curr_mc_size = 0, new_mc_size = 0;
	int cur_rev = uci->cpu_sig.rev;
	u8 *new_mc = NULL, *mc = NULL;

	while (iov_iter_count(iter)) {
		struct microcode_header_intel mc_header;
		unsigned int mc_size, data_size;
		u8 *data;

		if (!copy_from_iter_full(&mc_header, sizeof(mc_header), iter)) {
			pr_err("error! Truncated or inaccessible header in microcode data file\n");
			break;
		}

		mc_size = get_totalsize(&mc_header);
		if (mc_size < sizeof(mc_header)) {
			pr_err("error! Bad data in microcode data file (totalsize too small)\n");
			break;
		}

		data_size = mc_size - sizeof(mc_header);
		if (data_size > iov_iter_count(iter)) {
			pr_err("error! Bad data in microcode data file (truncated file?)\n");
			break;
		}

		/* For performance reasons, reuse mc area when possible */
		if (!mc || mc_size > curr_mc_size) {
			vfree(mc);
			mc = vmalloc(mc_size);
			if (!mc)
				break;
			curr_mc_size = mc_size;
		}

		memcpy(mc, &mc_header, sizeof(mc_header));
		data = mc + sizeof(mc_header);
		if (!copy_from_iter_full(data, data_size, iter) ||
		    intel_microcode_sanity_check(mc, true, MC_HEADER_TYPE_MICROCODE) < 0) {
			break;
		}

		if (cur_rev >= mc_header.rev)
			continue;

		if (!intel_find_matching_signature(mc, uci->cpu_sig.sig, uci->cpu_sig.pf))
			continue;

		vfree(new_mc);
		cur_rev = mc_header.rev;
		new_mc  = mc;
		new_mc_size = mc_size;
		mc = NULL;
	}

	vfree(mc);

	if (iov_iter_count(iter)) {
		vfree(new_mc);
		return UCODE_ERROR;
	}

	if (!new_mc)
		return UCODE_NFOUND;

	ucode_patch_late = (struct microcode_intel *)new_mc;
	return UCODE_NEW;
}

static bool is_blacklisted(unsigned int cpu)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu);

	/*
	 * Late loading on model 79 with microcode revision less than 0x0b000021
	 * and LLC size per core bigger than 2.5MB may result in a system hang.
	 * This behavior is documented in item BDF90, #334165 (Intel Xeon
	 * Processor E7-8800/4800 v4 Product Family).
	 */
	if (c->x86 == 6 &&
	    c->x86_model == INTEL_FAM6_BROADWELL_X &&
	    c->x86_stepping == 0x01 &&
	    llc_size_per_core > 2621440 &&
	    c->microcode < 0x0b000021) {
		pr_err_once("Erratum BDF90: late loading with revision < 0x0b000021 (0x%x) disabled.\n", c->microcode);
		pr_err_once("Please consider either early loading through initrd/built-in or a potential BIOS update.\n");
		return true;
	}

	return false;
}

static enum ucode_state request_microcode_fw(int cpu, struct device *device)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	const struct firmware *firmware;
	struct iov_iter iter;
	enum ucode_state ret;
	struct kvec kvec;
	char name[30];

	if (is_blacklisted(cpu))
		return UCODE_NFOUND;

	sprintf(name, "intel-ucode/%02x-%02x-%02x",
		c->x86, c->x86_model, c->x86_stepping);

	if (request_firmware_direct(&firmware, name, device)) {
		pr_debug("data file %s load failed\n", name);
		return UCODE_NFOUND;
	}

	kvec.iov_base = (void *)firmware->data;
	kvec.iov_len = firmware->size;
	iov_iter_kvec(&iter, ITER_SOURCE, &kvec, 1, firmware->size);
	ret = read_ucode_intel(cpu, &iter);

	release_firmware(firmware);

	return ret;
}

static void finalize_late_load(int result)
{
	if (!result)
		save_microcode_patch(ucode_patch_late);

	vfree(ucode_patch_late);
	ucode_patch_late = NULL;
}

static struct microcode_ops microcode_intel_ops = {
	.request_microcode_fw	= request_microcode_fw,
	.collect_cpu_info	= collect_cpu_info,
	.apply_microcode	= apply_microcode_intel,
	.finalize_late_load	= finalize_late_load,
};

static __init void calc_llc_size_per_core(struct cpuinfo_x86 *c)
{
	u64 llc_size = c->x86_cache_size * 1024ULL;

	do_div(llc_size, c->x86_max_cores);
	llc_size_per_core = (unsigned int)llc_size;
}

struct microcode_ops * __init init_intel_microcode(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	if (c->x86_vendor != X86_VENDOR_INTEL || c->x86 < 6 ||
	    cpu_has(c, X86_FEATURE_IA64)) {
		pr_err("Intel CPU family 0x%x not supported\n", c->x86);
		return NULL;
	}

	calc_llc_size_per_core(c);

	return &microcode_intel_ops;
}
