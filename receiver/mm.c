/*
 * This is the block-allocation memory management logic for the KMaldetect Receiver application.
 *
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include "mm.h"

static unsigned long syscall_n;
static unsigned long block_n;
static void **block_p;
int block_lim;

/* Write all saved syscalls to file /home/maldetect/<time>.out */
int write_blocks_to_file(void)
{
	int fd;
	int i, j;
	char filename[50];
	char buffer[200];
	SYSCALL *tmpcall;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	memset(filename, 0, 50);

	sprintf(filename, "/home/maldetect/%lu.out", (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000);
	fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH);
	if (!fd)
	{
		fprintf(stderr, "File error\n");
		exit(1);
	}
	for(i = 0; i < block_n; i++) //For each memory block of 64KB
	{
		for (j = 0; j < (i == block_n - 1 ? syscall_n : SYSCALLS_PER_BLOCK); j++) //If we're at the last block, count until syscall_n, otherwise, count till SYSCALLS_PER_BLOCK
		{
			memset(buffer, 0, 200);

			tmpcall = (SYSCALL *)(block_p[i] + (j * sizeof(SYSCALL))); //Interpeted the beginning of our block + our current offset as a SYSCALL struct
			sprintf(buffer, "%i:%lu:%i:%lu>", tmpcall->sys_id, tmpcall->inode, tmpcall->pid, tmpcall->mem_loc); //Transform our syscall variables to a char array
			if (write(fd, buffer, strnlen(buffer, 200)) == -1) //Write the C-string contained in buffer (up to a max. of 200 chars) to file
			{
				fprintf(stderr, "Write error\n");
				exit(1);
			}
		}
	}

	return 0;
}

/* Allocate a new 64KB block of memory to fit 2048 32-byte syscalls. Increment the block_n pointer and reset syscall_n */
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

/* If we're not at the end of our block yet, save the syscall. Otherwise, first add a new block. */
/* For now, this also saves all syscalls to file and terminates the application if we've reached 10 blocks */
int store_syscall(SYSCALL *input)
{
	if (block_n == block_lim)
	{
		write_blocks_to_file();
		exit(1);
	}

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
	return 0;
}

/* Allocate the first block of memory to store syscalls in */
int mm_init(void)
{
	block_n = 0;
	if (add_block() != 0)
	{
		return -1;
	}

	return 0;
}

