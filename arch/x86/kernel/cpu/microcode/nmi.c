// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Intel Corporation
 *
 * X86 CPU microcode update NMI handler.
 *
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/cpu.h>
#include <linux/nmi.h>

#include <asm/microcode.h>

#define SPINUNIT	100 /* 100 nsec */

DEFINE_PER_CPU(struct core_rendez, core_sync);
DEFINE_PER_CPU(struct core_rendez *, nmi_primary_ptr);

#define SPINUNIT 100 /* 100 nsec */

static void delay(int ms)
{
	unsigned long timeout = jiffies + ((ms * HZ) / 1000);

	while (time_before(jiffies, timeout))
		cpu_relax();
}

/*
 * Siblings wait until microcode update is completed by the primary thread.
 */
static int __wait_for_update(atomic_t *t)
{
	long timeout = NSEC_PER_MSEC;

	while (!arch_atomic_read(t)) {
		cpu_relax();
		delay(2);
		//timeout -= SPINUNIT;
		//if (timeout < SPINUNIT)
			//return 1;
	}
	return 0;
}

noinstr void hold_sibling_in_nmi(void)
{
	struct	 core_rendez *pcpu_core;
	extern cpumask_t cpus_nmi_enter, cpus_nmi_exit;
	int ret = 0;

	pcpu_core = this_cpu_read(nmi_primary_ptr);
	if (likely(!pcpu_core))
		return;

	cpumask_set_cpu(smp_processor_id(), &cpus_nmi_enter);
	/*
	 * Increment the siblings_left to inform primary thread that the
	 * sibling has arrived and parked in the NMI handler
	 */
	arch_atomic_dec(&pcpu_core->siblings_left);

	ret = __wait_for_update(&pcpu_core->core_done);
	if (ret)
		atomic_inc(&pcpu_core->failed);

	/*
	 * Clear the nmi_trap, so future NMI's won't be affected
	 */
	this_cpu_write(nmi_primary_ptr, NULL);
	cpumask_set_cpu(smp_processor_id(), &cpus_nmi_exit);
}
