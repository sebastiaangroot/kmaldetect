#include <stdlib.h>
#include <stdio.h>
#include "util.h"
#include "parser.h"

#define MULTIPLIER  1024

extern int tm_states_len;

struct list
{
	union {
		pid_t *pids;
		unsigned long *ulongs;
	};
	int p;
	int alloc;
};
typedef struct list LIST;

LIST *inodes = NULL;
LIST *memlocs = NULL;
LIST *pids = NULL;

static void store_inode(unsigned long inode, int state)
{
	if (inodes[state].p >= inodes[state].alloc)
	{
		inodes[state].ulongs = malrealloc(inodes[state].ulongs, (inodes[state].alloc + MULTIPLIER) * sizeof(unsigned long));
		inodes[state].alloc += MULTIPLIER;
	}
	inodes[state].ulongs[inodes[state].p] = inode;
	inodes[state].p++;
}

static void store_memloc(unsigned long memloc, int state)
{
	if (memlocs[state].p >= memlocs[state].alloc)
	{
		memlocs[state].ulongs = malrealloc(memlocs[state].ulongs, (memlocs[state].alloc + MULTIPLIER) * sizeof(unsigned long));
		memlocs[state].alloc += MULTIPLIER;
	}
	memlocs[state].ulongs[memlocs[state].p] = memloc;
	memlocs[state].p++;
}

static void store_pid(pid_t pid, int state)
{
	if (pids[state].p >= pids[state].alloc)
	{
		pids[state].pids = malrealloc(pids[state].pids, (pids[state].alloc + MULTIPLIER) * sizeof(pid_t));
		pids[state].alloc += MULTIPLIER;
	}
	pids[state].pids[pids[state].p] = pid;
	pids[state].p++;
}

void store_metadata(SYSCALL *sys, int state)
{
	store_inode(sys->inode, state);
	store_memloc(sys->mem_loc, state);
	store_pid(sys->pid, state);
}

void print_metadata(int state)
{
	int i;

	printf("Inodes:\n");
	for (i = 0; i < inodes[state].p; i++)
	{
		printf("\t%lu\n", inodes[state].ulongs[i]);
	}

	printf("\nMemlocs:\n");
	for (i = 0; i < memlocs[state].p; i++)
	{
		printf("\t%lu\n", memlocs[state].ulongs[i]);
	}

	printf("\nFound pids:\n");
	for (i = 0; i < pids[state].p; i++)
	{
		printf("\t%i\n", pids[state].pids[i]);
	}
}

struct counter
{
	union {
		unsigned long unlong;
		pid_t pid;
	};
	int counter;
};

/*void print_metadata_verbose(void)
{
	int i, j;
	int least_recorded[5];
	int lr_p = 0;
	struct counter most_common[5];
	while (lr_p < 5)
	{
		for (i = 0; i < tm_states_len; i++)
		{
		}
	}
}*/

void print_metadata_very_verbose(void)
{
	int i, j;
	
	printf("Inodes:");
	for (i = 0; i < tm_states_len; i++)
	{
		for (j = 0; j < inodes[i].p; j++)
		{
			printf("\t%lu\n", inodes[i].ulongs[j]);
		}
	}

	printf("\nMemlocs:\n");
	for (i = 0; i < tm_states_len; i++)
	{
		for (j = 0; j < memlocs[i].p; j++)
		{
			printf("\t%lu\n", memlocs[i].ulongs[j]);
		}
	}

	printf("\nPids:\n");
	for (i = 0; i < tm_states_len; i++)
	{
		for (j = 0; j < pids[i].p; j++)
		{
			printf("\t%i\n", pids[i].pids[j]);
		}
	}
}

void init_logger(void)
{
	int i;

	inodes = malmalloc(tm_states_len * sizeof(LIST));
	memlocs = malmalloc(tm_states_len * sizeof(LIST));
	pids = malmalloc(tm_states_len * sizeof(LIST));
	for (i = 0; i < tm_states_len; i++)
	{
		inodes[i].ulongs = malmalloc(MULTIPLIER * sizeof(unsigned long));
		inodes[i].p = 0;
		inodes[i].alloc = MULTIPLIER;

		memlocs[i].ulongs = malmalloc(MULTIPLIER * sizeof(unsigned long));
		memlocs[i].p = 0;
		memlocs[i].alloc = MULTIPLIER;

		pids[i].pids = malmalloc(MULTIPLIER * sizeof(pid_t));
		pids[i].p = 0;
		pids[i].alloc = MULTIPLIER;
	}
}

void flush_logger(void)
{
	int i;
	for (i = 0; i < tm_states_len; i++)
	{
		inodes[i].p = 0;
		memlocs[i].p = 0;
		pids[i].p = 0;
	}
}
