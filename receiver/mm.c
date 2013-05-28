#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include "mm.h"

static unsigned long syscall_n;
static unsigned long block_n;
static void **block_p;

int write_blocks_to_file(void)
{
	int fd;
	int i, j;
	char filename[50];
	char buffer[200];
	SYSCALL *tmpcall;

	memset(filename, 0, 50);

	sprintf(filename, "/home/maldetect/%lu.out", time(0));
	fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH);
	if (!fd)
	{
		fprintf(stderr, "File error\n");
		exit(1);
	}
	for(i = 0; i < block_n; i++)
	{
		for (j = 0; j < (i == block_n - 1 ? syscall_n : SYSCALLS_PER_BLOCK); j++)
		{
			memset(buffer, 0, 200);

			tmpcall = (SYSCALL *)(block_p[i] + (j * sizeof(SYSCALL)));
			sprintf(buffer, "%i:%lu:%i:%lu>", tmpcall->sys_id, tmpcall->inode, tmpcall->pid, tmpcall->mem_loc);
			if (write(fd, buffer, strnlen(buffer, 200)) == -1)
			{
				fprintf(stderr, "Write error\n");
				exit(1);
			}
		}
	}

	return 0;
}

static int add_block(void)
{
	if (block_n != 0)
	{
		block_p = realloc(block_p, (block_n + 1) * sizeof(void *));
		if (!block_p)
			return -1;
	}
	else
	{
		block_p = calloc(1, sizeof(void *));
		if (!block_p)
			return -1;
	}

	block_p[block_n] = calloc(1, BLOCK_SIZE);
	
	if (!block_p[block_n])
		return -1;
	
	block_n++;
	syscall_n = 0;

	return 0;
}

int store_syscall(SYSCALL *input)
{
	if (syscall_n < SYSCALLS_PER_BLOCK)
	{
		memcpy(block_p[block_n - 1] + (syscall_n * sizeof(SYSCALL)), input, sizeof(SYSCALL));
		syscall_n++;
	}
	else
	{
		if (add_block() != 0)
			return -1;
		
		memcpy(block_p[block_n - 1] + (syscall_n * sizeof(SYSCALL)), input, sizeof(SYSCALL));
		syscall_n++;
	}
	if (block_n == 10)
	{
		write_blocks_to_file();
		exit(1);
	}
	return 0;
}

int mm_init(void)
{
	block_n = 0;
	if (add_block() != 0)
	{
		return -1;
	}

	return 0;
}

