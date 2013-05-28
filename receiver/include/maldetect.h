#ifndef KMALDETECT_H
#define KMALDETECT_H

#define NETLINK_MALDETECT 24
#define MAX_PAYLOAD 1024

typedef struct
{
	int sys_id;
	unsigned long inode;
	pid_t pid;
	unsigned long mem_loc;
} SYSCALL;

#endif
