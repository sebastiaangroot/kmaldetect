/*
 * Light-weight block-allocation algorithm using the default malloc, realloc and free.
 * For each bmalloc call, a preferred block_size is given by the programmer, indicating
 * in which size the algorithm will allocate chunks for memory using malloc and realloc.
 *
 * This algorithm is written for realloc-heavy applications to prevent tons of
 * realloc calls, which are both CPU intensive and bad for memory fragmenting.
 *
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#ifndef BMALLOC_H
#define BMALLOC_H

#include <stdlib.h>

void *bmalloc(size_t init_size, size_t block_size);
void *brealloc(void *ptr, size_t size);
void bfree(void *ptr);
int b_mm_init(void);
void b_mm_exit(void);

#endif
