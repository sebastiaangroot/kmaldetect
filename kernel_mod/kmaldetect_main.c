#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/syscall.h>
#include <linux/syscalls.h>
#include "hooks.h"
#include "netlink/nl_iface.h"

//Pointer to the syscall table
unsigned long **sys_call_table;

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

static int __init mod_start(void)
{
	maldetect_nl_init();

	if(!(sys_call_table = acquire_sys_call_table()))
	{
		return -1;
	}

	disable_page_protection();
	reg_hooks(sys_call_table);
	enable_page_protection();

	printk(KERN_INFO "[kmaldetect] Initiated\n");
	return 0;
}

static void __exit mod_end(void)
{
	if(!sys_call_table)
	{
		return;
	}

	disable_page_protection();
	unreg_hooks(sys_call_table);
	enable_page_protection();

	maldetect_nl_close();

	printk(KERN_INFO "[kmaldetect] Stopped\n");
}

module_init(mod_start);
module_exit(mod_end);
