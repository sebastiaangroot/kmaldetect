/*
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#ifndef MM_H
#define MM_H
#include "maldetect.h"

#define BLOCK_SIZE	64*1024
#define SYSCALLS_PER_BLOCK (BLOCK_SIZE / sizeof(SYSCALL))

extern int block_lim;

extern int write_blocks_to_file(void);
extern int mm_init(void);
extern int store_syscall(SYSCALL *input);

#endif
