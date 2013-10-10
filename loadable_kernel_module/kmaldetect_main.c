/*
 * The entry point of the KMaldetect LKM. It contains init and exit functions, (for now) arch dependant functions and a method for
 * finding the sys_call_table in kernel memory.
 *
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/syscall.h>
#include <linux/syscalls.h>
#include <linux/interrupt.h>
#include "hooks.h"
#include "nl_iface.h"

MODULE_LICENSE("GPL");

//Pointer to the syscall table
static unsigned long **ref_sys_call_table;

//From the start of kernel address space, look for the beginning of the sys_call function-pointer table
static unsigned long **acquire_sys_call_table(void)
{
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX)
	{
		sct = (unsigned long **)offset;

		if (sct[__NR_close] == (unsigned long *) sys_close)
		{
			return sct;
		}

		offset += sizeof(void *);
	}
	printk(KERN_INFO "Getting syscall table failed.\n");
	return NULL;
}

//Check if the cr0 write-protect bit is set. If not, page write-protection is already disabled. If so, bitwise-AND bit 16 to zero and set it to cr0
static void disable_page_protection(void)
{
	unsigned long value;
	asm volatile("mov %%cr0, %0" : "=r"(value));
	if (!(value & 0x00010000))
	{
		return;
	}

	asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

//Check if cr0 write-protect bit is set. If so, page write-protection is already enabled. If not, bitwise-OR bit 16 to one and set it to cr0
static void enable_page_protection(void)
{
	unsigned long value;
	asm volatile("mov %%cr0, %0" : "=r" (value));

	if ((value & 0x00010000))
	{
		return;
	}

	asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}

/* Initiate the netlink interface, get the syscall table and register the hook functions */
static int __init mod_start(void)
{
	maldetect_nl_init();

	if(!(ref_sys_call_table = acquire_sys_call_table()))
	{
		return -1;
	}

	disable_irq(0);
	disable_page_protection();
	reg_hooks(ref_sys_call_table);
	enable_page_protection();
	enable_irq(0);

	printk(KERN_INFO "[kmaldetect] Initiated\n");
	return 0;
}

/* Unregister the hook functions and close the socket in the netlink interface */
static void __exit mod_end(void)
{
	if(!ref_sys_call_table)
	{
		return;
	}

	disable_page_protection();
	unreg_hooks(ref_sys_call_table);
	enable_page_protection();

	maldetect_nl_close();
	printk(KERN_INFO "[kmaldetect] Stopped\n");
}

module_init(mod_start);
module_exit(mod_end);
