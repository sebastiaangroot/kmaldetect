/*
 * Contains utility code to be used in the rest of the application, including memory management and debug functions.
 *
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#include <stdlib.h>
#include <stdio.h>

void *malrealloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size);
	if (!p)
	{
		fprintf(stderr, "realloc(%p, %i) returned NULL\n", ptr, (int)size);
		exit(1);
	}
	return p;
}

void *malcalloc(size_t num, size_t size)
{
	void *p = calloc(num, size);
	if (!p)
	{
		fprintf(stderr, "calloc(%i, %i) returned NULL\n", (int)num, (int)size);
		exit(1);
	}
	return p;
}

void *malmalloc(size_t size)
{
	void *p = malloc(size);
	if (!p)
	{
		fprintf(stderr, "malloc(%i) returned NULL\n", (int)size);
		exit(1);
	}
	return p;
}

void malfree(void *ptr)
{
	if (ptr != NULL)
	{
		free(ptr);
	}
}