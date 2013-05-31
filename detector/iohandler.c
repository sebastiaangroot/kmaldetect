#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

typedef struct
{
	int sys_id;
	unsigned long inode;
	pid_t pid;
	unsigned long mem_loc;
} SYSCALL;

void dprint_syscall(SYSCALL *input)
{
	printf("SYS_ID: %i, INODE: %lu, PID: %i, MEM_LOC: %lu\n", input->sys_id, input->inode, input->pid, input->mem_loc);
}

int read_syscalls_from_file(char *filename)
{
	int fd, i;
	char c;
	SYSCALL syscall;
	char buffer[200];
	int buffer_p;
	int ret;

	syscall.sys_id = 0;
	syscall.inode = 0;
	syscall.pid = 0;
	syscall.mem_loc = 0;

	fd = open(filename, O_RDONLY);
	if (!fd)
	{
		fprintf(stderr, "File error.\n");
		exit(1);
	}

	while(1)
	{
		memset(buffer, 0, 100);
		buffer_p = 0;
		while(1)
		{
			ret = read(fd, &c, 1);
			if (ret == -1)
			{
				fprintf(stderr, "Read error\n");
				exit(1);
			}
			else if (ret == 0)
			{
				break;
			}

			if (c == '>')
			{
				break;
			}
			else
			{
				buffer[buffer_p] = c;
				buffer_p++;
			}
		}
		sscanf(buffer, "%i:%lu:%i:%lu", &syscall.sys_id, &syscall.inode, &syscall.pid, &syscall.mem_loc);
		dprint_syscall(&syscall);
		if (ret == 0)
			break;
	}
}

int main(int argc, char **argv)
{
	read_syscalls_from_file(argv[1]);
	return 0;
}
