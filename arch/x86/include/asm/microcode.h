/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MICROCODE_H
#define _ASM_X86_MICROCODE_H

struct cpu_signature {
	unsigned int sig;
	unsigned int pf;
	unsigned int rev;
};

struct ucode_cpu_info {
	struct cpu_signature	cpu_sig;
	void			*mc;
};

#ifdef CONFIG_MICROCODE
extern void __init load_ucode_bsp(void);
extern void load_ucode_ap(void);
void microcode_bsp_resume(void);
#else
static inline void __init load_ucode_bsp(void)			{ }
static inline void load_ucode_ap(void)				{ }
static inline void microcode_bsp_resume(void)			{ }
#endif

#endif /* _ASM_X86_MICROCODE_H */
