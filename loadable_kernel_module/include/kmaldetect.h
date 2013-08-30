/*
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#ifndef KMALDETECT_H
#define KMALDETECT_H

typedef struct
{
	int sys_id;
	unsigned long inode;
	pid_t pid;
	unsigned long mem_loc;
} SYSCALL;

#endif
