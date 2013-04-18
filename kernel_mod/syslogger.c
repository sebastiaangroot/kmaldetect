#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/syscall.h>
#include <linux/syscalls.h>
#include "testfunct.h"

void **sys_call_table;
long (*ref_sys_mkdir)(const char __user *filename);
long (new_sys_mkdir)(const char __user *filename)
{
	printk(KERN_INFO "HOOK: mkdir, %s\n", filename);
	return ref_sys_mkdir(filename);
}

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

static void disable_page_protection(void)
{
	unsigned long value;
	asm volatile("mov %%cr0, %0\n" : "=r"(value));
	if (!(value & 0x00010000))
	{
		return;
	}

	asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

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

static int __init interc_start(void)
{
	printk(KERN_INFO "loaded\n");

	testlogfunct();

	if(!(sys_call_table = acquire_sys_call_table()))
	{
		return -1;
	}

	disable_page_protection();

	ref_sys_mkdir = (void *)sys_call_table[__NR_mkdir];
	sys_call_table[__NR_mkdir] = (unsigned long *)new_sys_mkdir;
	
	enable_page_protection();
	return 0;
}

static void __exit interc_end(void)
{
	printk(KERN_INFO "exiting\n");

	if(!sys_call_table)
	{
		return;
	}

	disable_page_protection();
	
	sys_call_table[__NR_mkdir] = (unsigned long *)ref_sys_mkdir;
	
	enable_page_protection();
}

module_init(interc_start);
module_exit(interc_end);
