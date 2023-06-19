/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MICROCODE_INTEL_H
#define _ASM_X86_MICROCODE_INTEL_H

#include <asm/microcode.h>

struct microcode_header_intel {
	unsigned int            hdrver;
	unsigned int            rev;
	unsigned int            date;
	unsigned int            sig;
	unsigned int            cksum;
	unsigned int            ldrver;
	unsigned int            pf;
	unsigned int            datasize;
	unsigned int            totalsize;
	unsigned int            metasize;
	unsigned int		min_req_ver;
	unsigned int		reserved3;
};

struct microcode_intel {
	struct microcode_header_intel hdr;
	unsigned int            bits[];
};

#define DEFAULT_UCODE_DATASIZE	(2000)
#define MC_HEADER_SIZE		(sizeof(struct microcode_header_intel))

#define MC_HEADER_TYPE_MICROCODE	1
#define MC_HEADER_TYPE_IFS		2

#define get_datasize(mc)				\
	(((struct microcode_intel *)mc)->hdr.datasize ? \
	 ((struct microcode_intel *)mc)->hdr.datasize : DEFAULT_UCODE_DATASIZE)

#endif /* _ASM_X86_MICROCODE_INTEL_H */
