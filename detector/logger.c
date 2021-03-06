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

struct pair
{
	union {
		pid_t key_pid;
		unsigned long key_ulong;
	};
	
	double score;
	int n;
};
typedef struct pair PAIR;

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

struct counter
{
	union {
		unsigned long unlong;
		pid_t pid;
	};
	int counter;
};

int ulong_get_index(PAIR *pairs, int n, unsigned long key)
{
	int i;
	for (i = 0; i < n; i++)
		if (pairs[i].key_ulong == key)
			return i;
	return -1;
}

void ulong_add_key(PAIR **pairs, int *n, unsigned long key)
{
	*pairs = malrealloc(*pairs, sizeof(PAIR) * (*n+1));
	(*pairs)[*n].key_ulong = key;
	(*pairs)[*n].n = 0;
	(*pairs)[*n].score = 0;
	*n = *n + 1;
}

void pair_quicksort(PAIR *array, int n)
{
	PAIR pivot, swp;
	int right, left;
	
	if (n > 1)
	{
		pivot = array[0];
		left = 0;
		right = n-1;
		while (left <= right)
		{
			while (array[left].score > pivot.score) left++;
			while (array[right].score < pivot.score) right--;
			if (left <= right)
			{
				swp = array[left];
				array[left] = array[right];
				array[right] = swp;
				left++;
				right--;
			}
		}
		pair_quicksort(array, right+1);
		pair_quicksort(array+left, n - left);
	}
}

void calculate_winner(void)
{
	PAIR *scores = NULL;
	int scores_n = 0;
	int i, j;
	int ind;
	
	for (i = 0; i < tm_states_len; i++)
	{
		//Amount of occurences per state
		for (j = 0; j < inodes[i].p; j++)
		{
			while ((ind = ulong_get_index(scores, scores_n, inodes[i].ulongs[j])) == -1)
			{
				//printf("[%i]inode %lu not yet registered, creating\n", i, inodes[i].ulongs[j]);
				ulong_add_key(&scores, &scores_n, inodes[i].ulongs[j]);
			}

			scores[ind].n++;
			//printf("[%i]inode %lu now at %i\n", i, inodes[i].ulongs[j], scores[ind].n);
		}
		//Percentage scores per state
		for (j = 0; j < scores_n; j++)
		{
			if (scores[j].n != 0)
			{
				scores[j].score += (double)(scores[j].n) / (double)inodes[i].p;
				//printf("[%i]Score of inode %lu at state %i now at %.2f\n", i, scores[j].key_ulong, i, scores[j].score);
			}
			scores[j].n = 0; //Reset for the next i iteration
		}
	}
	
	//Quicksort in place
	pair_quicksort(scores, scores_n);
	
	for (i = 0; i < scores_n; i++)
	{
		printf("Inode: %lu\tScore: %.2f\n", scores[i].key_ulong, scores[i].score);
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
