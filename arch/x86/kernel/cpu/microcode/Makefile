# SPDX-License-Identifier: GPL-2.0-only
microcode-y				:= core.o
obj-$(CONFIG_MICROCODE)			+= microcode.o
microcode-$(CONFIG_MICROCODE_INTEL)	+= intel.o
microcode-$(CONFIG_MICROCODE_AMD)	+= amd.o
microcode-$(CONFIG_MICROCODE_LATE_LOADING) += nmi.o
