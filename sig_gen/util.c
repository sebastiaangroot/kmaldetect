#include <stdlib.h>
#include <stdio.h>

void *malrealloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size);
	if (!p)
	{
		fprintf(stderr, "realloc(0x%X, %i) returned NULL\n", (unsigned int)ptr, (int)size);
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
