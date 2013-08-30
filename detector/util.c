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

#include "util.h"
extern int **transition_matrix;
extern int tm_states_len;
void dbg_print_transition_matrix(void)
{
	int i, j;
	for (i = 0; i < tm_states_len; i++)
	{
		printf("[%i]:{", i);
		for (j = 0; j < NUM_SYSCALLS; j++)
		{
			if (!j)
			{
				printf("%i", transition_matrix[i][j]);
			}
			else
			{
				printf(",%i", transition_matrix[i][j]);
			}
		}
		printf("}\n");
	}
}

#include "parser.h"
extern ENDSTATE *endstates;
extern int endstates_len;
void dbg_print_endstates(void)
{
	int i;
	for (i = 0; i < endstates_len; i++)
	{
		printf("Endstate %i:\n\tState: %i\n\tFilename: %s\n", i, endstates[i].state, endstates[i].filename);
	}
}
