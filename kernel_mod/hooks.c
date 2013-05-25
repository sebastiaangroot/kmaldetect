#include <asm/unistd.h>
#include <linux/syscalls.h>

long (*ref_sys_open)(const char __user *, int, int) = 0;

long hook_open(const char *filename, int flags, int mode)
{
	long retval = ref_sys_open(filename, flags, mode);
	printk(KERN_INFO "[kmaldetect] sys_open\n");
	return retval;
}

void reg_hooks(unsigned long **syscall_table)
{
	ref_sys_open = (void *)syscall_table[__NR_open];
	syscall_table[__NR_open] = (unsigned long *)hook_open;
}

void unreg_hooks(unsigned long **syscall_table)
{
	syscall_table[__NR_open] = (unsigned long *)ref_sys_open;
}
