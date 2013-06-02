#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define MAX_SIGLEN 1024*1024
#define NUM_SYSCALLS 311

typedef struct
{
	int list_length;
	unsigned short *list;
	char *filename;
} SIGNATURE;

typedef struct
{
	int state;
	char *filename;
} ENDSTATE;

ENDSTATE *endstates;
int endstate_n;
int **transition_matrix;
int state_n;

SIGNATURE * load_signature(char *filename)
{
	FILE *file = fopen(filename, "r");
	int read_num;
	unsigned short tmp_list[MAX_SIGLEN];
	int tmp_list_p = 0;
	SIGNATURE *tmp_sig;
	unsigned short *real_list;
	int i;

	while(fscanf(file, "%u,", &read_num))
	{
		if (feof(file) || tmp_list_p >= MAX_SIGLEN)
		{
			break;
		}

		tmp_list[tmp_list_p] = (unsigned short) read_num;
		tmp_list_p++;
	}

	tmp_sig = malloc(sizeof(SIGNATURE));
	real_list = malloc(sizeof(unsigned short) * tmp_list_p);

	if (!tmp_sig || !real_list)
	{
		return NULL;
	}

	for (i = 0; i < tmp_list_p; i++)
	{
		real_list[i] = tmp_list[i];
	}
	
	tmp_sig->list_length = tmp_list_p;
	tmp_sig->list = real_list;
	tmp_sig->filename = filename;

	return tmp_sig;
}

int add_nullstate(void)
{
	int *state_array = malcalloc(NUM_SYSCALLS, sizeof(int));
	if (!transition_matrix)
	{
		transition_matrix = malmalloc(sizeof(int *));
		state_n = 1;
	}
	else
	{
		transition_matrix = malrealloc(transition_matrix, sizeof(int *) * (state_n + 1));
		state_n++;
	}
	transition_matrix[state_n - 1] = state_array;
	return state_n - 1;
}

void add_endstate(int state, char *signame)
{
	if (!endstates)
	{
		endstates = malcalloc(1, sizeof(ENDSTATE));
		endstates[0].state = state;
		endstates[0].filename = signame;
		endstate_n = 1;
	}
	else
	{
		endstates = malrealloc(endstates, sizeof(ENDSTATE) * (endstate_n + 1));
		endstates[endstate_n].state = state;
		endstates[endstate_n].filename = signame;
		endstate_n++;
	}
}

int handle_input(int state_cur, int sys_id)
{
	int state_nxt;
	while(state_cur >= state_n)
	{
		add_nullstate();
	}

	if (!transition_matrix[state_cur][sys_id])
	{
		state_nxt = add_nullstate();
		transition_matrix[state_cur][sys_id] = state_nxt;
		state_cur = state_nxt;
	}
	else
	{
		state_cur = transition_matrix[state_cur][sys_id];
	}

	return state_cur;
}

void add_signature_to_matrix(SIGNATURE *sig)
{
	int i;
	int state_cur = 1;

	for (i = 0; i < sig->list_length; i++)
	{
		state_cur = handle_input(state_cur, sig->list[i]);
		if (i == sig->list_length - 1)
		{
			add_endstate(state_cur, sig->filename);
		}
	}
}

void debug_print(void)
{
	int i, j;

	for (i = 0; i < state_n; i++)
	{
		printf("[%i]:{", i);
		
		for (j = 0; j < NUM_SYSCALLS; j++)
		{
			if (!j)
				printf(" %i", transition_matrix[i][j]);
			else
				printf(", %i", transition_matrix[i][j]);
		}

		printf(" }\n");
	}
}

int main(int argc, char *argv[])
{
	state_n = 0;
	SIGNATURE *testsig;

	testsig = load_signature(argv[1]);

	add_signature_to_matrix(testsig);

	debug_print();

	return 0;
}
