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

#include "intel.h"
#include "local.h"

#define DEBUG

static const char ucode_path[] = "kernel/x86/microcode/GenuineIntel.bin";

/* Current microcode patch used in early patching on the APs. */
static struct microcode_intel *applied_ucode_va __read_mostly;
static struct microcode_intel *applied_ucode_pa __read_mostly;
static struct microcode_intel *unapplied_ucode __read_mostly;

/* last level cache size per core */
static int llc_size_per_core __read_mostly;

/*
 * Returns 1 if update has been found, 0 otherwise.
 */
static int has_newer_microcode(void *mc, unsigned int csig, int cpf, int new_rev)
{
	struct microcode_header_intel *mc_hdr = mc;

	if (mc_hdr->rev <= new_rev)
		return 0;

	return intel_find_matching_signature(mc, csig, cpf);
}

static void update_unapplied_ucode(struct microcode_intel *mc, unsigned int size)
{
	pr_err("Updating unapplied ucode with revision 0x%x\n", mc->hdr.rev);
	unapplied_ucode = kmemdup(mc, size, GFP_KERNEL);
	if (!unapplied_ucode) {
		pr_err("Error allocating buffer for microcode\n");
		return;
	}
}

static void update_ucode_pointer(struct microcode_intel *mc)
{
	struct microcode_intel *prev_mc;

        prev_mc = applied_ucode_va;
        applied_ucode_va = mc;
        /*
         * Save for early loading on APs. On 32-bit, that needs to be a
         * physical address as the APs are invoking the load from physical
         * addresses before paging has been enabled.
         */
        if (IS_ENABLED(CONFIG_X86_32))
                applied_ucode_pa = (struct microcode_intel *)__pa_nodebug(mc);

        kfree(prev_mc);
	pr_err("Updated ucode ptr\n");
}

static void save_microcode_patch(void *data, unsigned int size)
{
	struct microcode_intel *mc;

	mc = kmemdup(data, size, GFP_KERNEL);
	pr_err("%s: saving rev 0x%x\n", __func__, mc->hdr.rev);
	if (!mc) {
		pr_err("Error allocating buffer for microcode\n");
		return;
	}
	update_ucode_pointer(mc);
}

/*
 * Get microcode matching with BSP's model. Only CPUs with the same model as
 * BSP can stay in the platform.
 */
static struct microcode_intel *
scan_microcode(void *data, size_t size, struct ucode_cpu_info *uci, bool save)
{
	struct microcode_header_intel *mc_header;
	struct microcode_intel *patch = NULL;
	unsigned int mc_size;

	while (size) {
		if (size < sizeof(struct microcode_header_intel))
			break;

		mc_header = (struct microcode_header_intel *)data;

		mc_size = get_totalsize(mc_header);
		if (!mc_size ||
		    mc_size > size ||
		    intel_microcode_sanity_check(data, false, MC_HEADER_TYPE_MICROCODE) < 0)
			break;

		size -= mc_size;

		if (!intel_find_matching_signature(data, uci->cpu_sig.sig,
						   uci->cpu_sig.pf)) {
			data += mc_size;
			continue;
		}

		if (save) {
			save_microcode_patch(data, mc_size);
			goto next;
		}


		if (!patch) {
			if (!has_newer_microcode(data,
						 uci->cpu_sig.sig,
						 uci->cpu_sig.pf,
						 uci->cpu_sig.rev))
				goto next;

		} else {
			struct microcode_header_intel *phdr = &patch->hdr;

			if (!has_newer_microcode(data,
						 phdr->sig,
						 phdr->pf,
						 phdr->rev))
				goto next;
		}

		/* We have a newer patch, save it. */
		patch = data;

next:
		data += mc_size;
	}

	if (size)
		return NULL;

	return patch;
}

static bool load_builtin_intel_microcode(struct cpio_data *cp)
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

static int apply_microcode_early(struct ucode_cpu_info *uci, bool early)
{
	struct microcode_intel *mc;
	u32 rev, old_rev;

	mc = uci->mc;
	if (!mc)
		return 0;

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
a */
	native_wbinvd();

	/* write microcode via MSR 0x79 */
	native_wrmsrl(MSR_IA32_UCODE_WRITE, (unsigned long)mc->bits);

	rev = intel_get_microcode_revision();
	if (rev != mc->hdr.rev)
		return -1;

	uci->cpu_sig.rev = rev;

	if (early)
		print_ucode(old_rev, uci->cpu_sig.rev, mc->hdr.date);
	else
		print_ucode_info(old_rev, uci->cpu_sig.rev, mc->hdr.date);

	return 0;
}

/* Load microcode from built-in or from initrd */
static struct microcode_intel *__load_ucode_intel(struct ucode_cpu_info *uci, bool save)
{
	static const char *path;
	struct cpio_data cp;
	bool use_pa;

	if (IS_ENABLED(CONFIG_X86_32)) {
		path	  = (const char *)__pa_nodebug(ucode_path);
		use_pa	  = true;
	} else {
		path	  = ucode_path;
		use_pa	  = false;
	}

	/* try built-in microcode first */
	if (!load_builtin_intel_microcode(&cp))
		cp = find_microcode_in_initrd(path, use_pa);

	if (!(cp.data && cp.size))
		return NULL;

	intel_cpu_collect_info(uci);

	return scan_microcode(cp.data, cp.size, uci, save);
}

int __init save_microcode_in_initrd_intel(void)
{
	struct ucode_cpu_info uci;

	/*
	 * Scan the microcode before bringing up the APs. If a matching
	 * version is found, duplicate it and store the pointer in
	 * intel_ucode_patch_[pv]a. sp tje A{ can use it for early loading.
	 */
	__load_ucode_intel(&uci, true);
	return 0;
}
early_initcall(save_microcode_in_initrd_intel);

void __init load_ucode_intel_bsp(void)
{
	struct ucode_cpu_info uci;

	uci.mc = __load_ucode_intel(&uci, false);
	if (uci.mc)
		apply_microcode_early(&uci, true);
}

static void __load_ucode_intel_ap(bool early)
{
	struct ucode_cpu_info uci;

	uci.mc = IS_ENABLED(CONFIG_X86_32) ? applied_ucode_pa : applied_ucode_va;
	if (uci.mc)
		apply_microcode_early(&uci, early);
}

void load_ucode_intel_ap(void)
{
	__load_ucode_intel_ap(false);
}

static struct microcode_intel *find_patch(void)
{
	return unapplied_ucode ? unapplied_ucode : applied_ucode_va;
}

void reload_ucode_intel(void)
{
	__load_ucode_intel_ap(false);
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

	/* Look for a newer patch in our cache: */
	mc = find_patch();
	if (!mc) {
		mc = uci->mc;
		if (!mc)
			return UCODE_NFOUND;
	}

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

static bool ucode_validate_minrev(struct microcode_header_intel *mc_header)
{
	int cur_rev = boot_cpu_data.microcode;

	/*
	 * When late-loading, ensure the header declares a minimum revision
	 * required to perform a late-load. The previously reserved field
	 * is 0 in older microcode blobs.
	 */
	if (!mc_header->min_req_ver) {
		pr_info("Unsafe microcode update: Microcode header does not specify a required min version\n");
		return false;
	}

	/*
	 * Check whether the minimum revision specified in the header is either
	 * greater or equal to the current revision.
	 */
	if (cur_rev < mc_header->min_req_ver) {
		pr_info("Unsafe microcode update: Current revision 0x%x too old\n", cur_rev);
		pr_info("Current should be at 0x%x or higher. Use early loading instead\n", mc_header->min_req_ver);
		return false;
	}
	return true;
}

static enum ucode_state generic_load_microcode(int cpu, struct iov_iter *iter)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
	unsigned int curr_mc_size = 0, new_mc_size = 0;
	int new_rev = uci->cpu_sig.rev;
	u8 *new_mc = NULL, *mc = NULL;
	bool new_is_safe = false;
	unsigned int csig, cpf;

	while (iov_iter_count(iter)) {
		struct microcode_header_intel mc_header;
		unsigned int mc_size, data_size;
		u8 *data;

		if (!copy_from_iter_full(&mc_header, sizeof(mc_header), iter)) {
			pr_err("error! Truncated or inaccessible header in microcode data file\n");
			goto fail;
		}

		mc_size = get_totalsize(&mc_header);
		if (mc_size < sizeof(mc_header)) {
			pr_err("error! Bad data in microcode data file (totalsize too small)\n");
			goto fail;
		}
		data_size = mc_size - sizeof(mc_header);
		if (data_size > iov_iter_count(iter)) {
			pr_err("error! Bad data in microcode data file (truncated file?)\n");
			goto fail;
		}

		/* For performance reasons, reuse mc area when possible */
		if (!mc || mc_size > curr_mc_size) {
			vfree(mc);
			mc = vmalloc(mc_size);
			if (!mc)
				goto fail;
			curr_mc_size = mc_size;
		}

		memcpy(mc, &mc_header, sizeof(mc_header));
		data = mc + sizeof(mc_header);
		if (!copy_from_iter_full(data, data_size, iter) ||
		    intel_microcode_sanity_check(mc, true, MC_HEADER_TYPE_MICROCODE) < 0)
			goto fail;

		csig = uci->cpu_sig.sig;
		cpf = uci->cpu_sig.pf;
		if (has_newer_microcode(mc, csig, cpf, new_rev)) {
			bool is_safe = ucode_validate_minrev(&mc_header);

			if (force_minrev && !is_safe)
				continue;

			vfree(new_mc);
			new_rev = mc_header.rev;
			new_mc  = mc;
			new_mc_size = mc_size;
			new_is_safe = is_safe;
			mc = NULL;
		}
	}

	if (!new_mc)
		return UCODE_NFOUND;

	pr_debug("CPU%d found a matching microcode update with version 0x%x (current=0x%x)\n",
		 cpu, new_rev, uci->cpu_sig.rev);

	update_unapplied_ucode((struct microcode_intel *)new_mc, new_mc_size);

	vfree(mc);
	vfree(new_mc);

	return new_is_safe ? UCODE_NEW_SAFE : UCODE_NEW;
fail:
	vfree(mc);
	vfree(new_mc);
	return UCODE_ERROR;
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
	ret = generic_load_microcode(cpu, &iter);

	release_firmware(firmware);

	return ret;
}

static void finalize_late_load(int result)
{
	pr_err("finalize with result %d\n", result);

	if (result) {
		if (unapplied_ucode)
			kfree(unapplied_ucode);
		pr_err("update failed freed unapplied\n");
	}
	else
		update_ucode_pointer(unapplied_ucode);


	unapplied_ucode = NULL;
}

static struct microcode_ops microcode_intel_ops = {
	.request_microcode_fw	= request_microcode_fw,
	.collect_cpu_info	= collect_cpu_info,
	.apply_microcode	= apply_microcode_intel,
	.finalize_late_load	= finalize_late_load,
	.use_nmi		= IS_ENABLED(CONFIG_X86_64),
};

static int __init calc_llc_size_per_core(struct cpuinfo_x86 *c)
{
	u64 llc_size = c->x86_cache_size * 1024ULL;

	do_div(llc_size, c->x86_max_cores);

	return (int)llc_size;
}

struct microcode_ops * __init init_intel_microcode(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	if (c->x86_vendor != X86_VENDOR_INTEL || c->x86 < 6 ||
	    cpu_has(c, X86_FEATURE_IA64)) {
		pr_err("Intel CPU family 0x%x not supported\n", c->x86);
		return NULL;
	}

	llc_size_per_core = calc_llc_size_per_core(c);

	return &microcode_intel_ops;
}
