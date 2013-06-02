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
extern int state_n;
void dbg_print_transition_matrix(void)
{
	int i, j;
	for (i = 0; i < state_n; i++)
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
extern int endstate_n;
void dbg_print_endstates(void)
{
	int i;
	for (i = 0; i < endstate_n; i++)
	{
		printf("Endstate %i:\n\tState: %i\n\tFilename: %s\n", i, endstates[i].state, endstates[i].filename);
	}
}
