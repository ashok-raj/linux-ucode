#ifndef _ASM_X86_MICROCODE_AMD_H
#define _ASM_X86_MICROCODE_AMD_H

#ifdef CONFIG_MICROCODE_AMD
void amd_check_microcode(void);
#else
static inline void amd_check_microcode(void) {}
#endif
#endif /* _ASM_X86_MICROCODE_AMD_H */
