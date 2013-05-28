#include <asm/unistd.h>
#include <linux/syscalls.h>
#include <asm/thread_info.h>
#include "nl_iface.h"
#include "utils.h"
#include "kmaldetect.h"

extern pid_t maldetect_userspace_pid;
long (*ref_sys_open)(const char __user *, int, int) = 0;

long hook_open(const char *filename, int flags, int mode)
{
	long retval = ref_sys_open(filename, flags, mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 1;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
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
