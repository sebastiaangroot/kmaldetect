/*
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>

#define NUM_SYSCALLS 311

typedef struct
{
	int sys_id;
	unsigned long inode;
	pid_t pid;
	unsigned long mem_loc;
	int *states;
	int states_len;
} SYSCALL;

typedef struct
{
	int state;
	char *filename;
} ENDSTATE;

extern void *malrealloc(void *ptr, size_t size);
extern void *malcalloc(size_t num, size_t size);
extern void *malmalloc(size_t size);
extern void malfree(void *ptr);
#endif
