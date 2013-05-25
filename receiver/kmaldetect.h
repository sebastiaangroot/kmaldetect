#ifndef KMALDETECT_H
#define KMALDETECT_H

struct syscall_struct
{
	int sys_id;
	int inode;
	int pid;
	int mloc;
};

typedef struct syscall_struct SYSCALL;

#endif
