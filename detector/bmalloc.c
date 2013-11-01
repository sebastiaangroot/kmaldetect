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

#include <stdlib.h>
#include <string.h>
#include <pthread.h> //For mutex (un)locking

//MM_REG contains the base address of the allocated space, the space that is currently allocated and the block size with which to increment the size if need be
typedef struct
{
	void *base;
	size_t alloc_size;
	size_t block_size;
} MM_REG;

static MM_REG *mm_reg_list;
static int mm_reg_list_n;
static size_t internal_alloc_size;
static size_t internal_block_size;
static pthread_mutex_t mm_mutex;

static int addr_to_index(void *ptr)
{
	int i;

	for (i = 0; i < mm_reg_list_n; i++)
	{
		if (ptr >= mm_reg_list[i].base && ptr < (mm_reg_list[i].base + mm_reg_list[i].alloc_size))
		{
			return i;
		}
	}
	return -1;
}

static void defrag_list(void)
{
	int i, last_ind;
	
	for(i = 0; i < mm_reg_list_n; i++)
	{
		last_ind = mm_reg_list_n - 1;
		if (mm_reg_list[i].base == 0)
		{
			mm_reg_list[i].base = mm_reg_list[last_ind].base;
			mm_reg_list[i].alloc_size = mm_reg_list[last_ind].alloc_size;
			mm_reg_list[i].block_size = mm_reg_list[last_ind].block_size;
			mm_reg_list_n--;
		}
	}
}

static int allocate_mm_block(void)
{
	MM_REG *tmp_list;
	
	defrag_list();
	
	if (mm_reg_list_n * sizeof(MM_REG) <= internal_alloc_size)
		return 0;
	
	tmp_list = realloc(mm_reg_list, (internal_alloc_size + internal_block_size));
	if (!tmp_list)
		return -1;

	mm_reg_list = tmp_list;
	return 0;
}

/* bmalloc: malloc that allocates in multiples of block_size */
void *bmalloc(size_t init_size, size_t block_size)
{
	size_t size_to_alloc;

	pthread_mutex_lock(&mm_mutex);
	if (internal_alloc_size < mm_reg_list_n * sizeof(MM_REG))
	{
		if (allocate_mm_block() == -1)
		{
			pthread_mutex_unlock(&mm_mutex);
			return 0;
		}
	}
	
	size_to_alloc = (init_size / block_size) * block_size;
	if (init_size % block_size != 0)
	{
		size_to_alloc += block_size;
	}

	mm_reg_list[mm_reg_list_n].base = malloc(size_to_alloc);
	mm_reg_list[mm_reg_list_n].alloc_size = size_to_alloc;
	mm_reg_list[mm_reg_list_n].block_size = block_size;
	
	if (!mm_reg_list[mm_reg_list_n].base)
	{
		memset(&mm_reg_list[mm_reg_list_n], 0, sizeof(MM_REG));
		pthread_mutex_unlock(&mm_mutex);
		return 0;
	}

	mm_reg_list_n++;

	pthread_mutex_unlock(&mm_mutex);
	return mm_reg_list[mm_reg_list_n - 1].base;
}

/* Returns the memory address on successful realloc and zero on failure. Previously allocated space is untouched when a zero is returned.
 * Unlike the standard realloc, malloc is not called when the ptr is NULL, due to the missing block size.
 */
void *brealloc(void *ptr, size_t size)
{
	size_t size_to_alloc;
	int ind;
	void *tmp_ptr;

	//Sanity check on ptr
	if (!ptr)
	{
		return 0;
	}

	pthread_mutex_lock(&mm_mutex);

	//Translate given ptr to the index in our mm_reg_list array
	ind = addr_to_index(ptr);
	if (ind == -1)
	{
		pthread_mutex_unlock(&mm_mutex);
		return 0;
	}

	//Nothing to do, a previous bmalloc / brealloc already allocated enough memory for this brealloc call
	if (mm_reg_list[ind].alloc_size >= size)
	{
		pthread_mutex_unlock(&mm_mutex);
		return ptr;
	}

	//Calc the multiple of block_size we need for this request. First we calculate the size_to_alloc as if size is a multiple of block_size. Then, we add an extra block if size wasn't.
	size_to_alloc = (size / mm_reg_list[ind].block_size) * mm_reg_list[ind].block_size;
	if (size % mm_reg_list[ind].block_size != 0)
	{
		size_to_alloc += mm_reg_list[ind].block_size;
	}

	//Attempt to realloc using that size_to_alloc
	tmp_ptr = realloc(mm_reg_list[ind].base, size_to_alloc);

	//realloc returned 0, it went wrong. We mimic reallocs behaviour here and return 0, indicating that the callers memory block is untouched.
	if (!tmp_ptr)
	{
		pthread_mutex_unlock(&mm_mutex);
		return 0;
	}
	//realloc successful, update base and alloc_size to the new size
	mm_reg_list[ind].base = tmp_ptr;
	mm_reg_list[ind].alloc_size = size_to_alloc;

	pthread_mutex_unlock(&mm_mutex);
	return mm_reg_list[ind].base;
}

/* If the ptr is registered, it calls free and clears the bmalloc entry */
void bfree(void *ptr)
{
	int ind;

	pthread_mutex_lock(&mm_mutex);

	ind = addr_to_index(ptr);
	
	if (ind == -1)
	{
		pthread_mutex_unlock(&mm_mutex);
		return;
	}
	
	free(mm_reg_list[ind].base);
	memset(&mm_reg_list[ind], 0, sizeof(MM_REG));

	pthread_mutex_unlock(&mm_mutex);
}

/* Needs to be called before making calls to any of the block-allocation functions. Initiates the data structures. */
int b_mm_init(void)
{
	if (pthread_mutex_init(&mm_mutex, NULL) != 0)
		return -1;

	internal_block_size = 128 * sizeof(MM_REG);
	mm_reg_list_n = 0;
	mm_reg_list = malloc(internal_block_size);

	if (!mm_reg_list)
	{
		pthread_mutex_destroy(&mm_mutex);
		return -1;
	}
	
	internal_alloc_size = internal_block_size;

	return 0;
}

/* Can be called to free the resources bmalloc takes up (a pthread_mutex_t and MM_REG* data structure) */
void b_mm_exit(void)
{
	if (&mm_mutex != NULL)
	{
		pthread_mutex_destroy(&mm_mutex);
	}
	
	if (mm_reg_list != NULL)
	{
		free(mm_reg_list);
	}	
}
