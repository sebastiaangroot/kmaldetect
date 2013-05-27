#include <asm/unistd.h>
#include <linux/syscalls.h>
#include "netlink/nl_iface.h"
#include "utils.h"

long (*ref_sys_open)(const char __user *, int, int) = 0;

long hook_open(const char *filename, int flags, int mode)
{
	long retval = ref_sys_open(filename, flags, mode);
	unsigned long inode_nr = get_inode();
	SYSCALL_DUMMY mald_data;
	mald_data.id = 1;
	mald_data.inode = inode_nr;
	maldetect_nl_send_syscall(&mald_data);
	printk(KERN_INFO "Inode %ld captured\n", inode_nr);
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
