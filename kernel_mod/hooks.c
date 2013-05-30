#include <asm/unistd.h>
#include <linux/syscalls.h>
#include <asm/thread_info.h>
#include "nl_iface.h"
#include "utils.h"
#include "kmaldetect.h"

/* The PID identifying our userspace receiver */
extern pid_t maldetect_userspace_pid;

/* Function prototype for the sys_open syscall */
long (*ref_sys_open)(const char __user *, int, int) = 0;

/* The sys_open hook.
 * - Call the real sys_open
 * - Obtain the ring 3 return address (not yet correctly implemented
 * - If we're not the receiver and we've connected to the receiver already
 * - Set sys_id
 * - Get the inode of the calling process
 * - Get the PID of the calling process
 * - Set the mem_loc of the calling process
 * - Send this information to the userspace receiver
 * - Return the syscall return value to the calling process
 *  */
long hook_open(const char *filename, int flags, int mode)
{
	long retval = ref_sys_open(filename, flags, mode);
	void *memval;
	asm volatile ("mov %%r10, %0" : "=r"(memval));
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 1;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
		printk(KERN_INFO "[kmaldetect] %p\n", memval);
	}
	return retval;
}

/* Store the real function pointer of sys_open to ref_sys_open and insert our own hook_open in its place */
void reg_hooks(unsigned long **syscall_table)
{
	ref_sys_open = (void *)syscall_table[__NR_open];
	syscall_table[__NR_open] = (unsigned long *)hook_open;
}

/* Restore the syscall_table to its original values */
void unreg_hooks(unsigned long **syscall_table)
{
	syscall_table[__NR_open] = (unsigned long *)ref_sys_open;
}
