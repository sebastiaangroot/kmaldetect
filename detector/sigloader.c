#include <stdio.h>
#include <glob.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"
#include "sigloader.h"
#include "parser.h"

extern int **transition_matrix;
extern int state_n;
extern ENDSTATE *endstates;
extern int endstate_n;

static SIGNATURE *load_signature(char *filename)
{
	FILE *file = fopen(filename, "r");
	int read_num;
	unsigned short *tmp_list;
	int tmp_list_p = 0;
	SIGNATURE *tmp_sig;
	unsigned short *real_list;
	int i;

	tmp_list = malmalloc(sizeof(unsigned short) * MAX_SIGLEN);

	while (fscanf(file, "%u,", &read_num))
	{
		if (feof(file) || tmp_list_p >= MAX_SIGLEN)
		{
			break;
		}

		tmp_list[tmp_list_p] = (unsigned short) read_num;
		tmp_list_p++;
	}

	tmp_sig = malmalloc(sizeof(SIGNATURE));
	real_list = malmalloc(sizeof(unsigned short) * tmp_list_p);

	for (i = 0; i < tmp_list_p; i++)
	{
		real_list[i] = tmp_list[i];
	}

	tmp_sig->list_length = tmp_list_p;
	tmp_sig->list = real_list;
	tmp_sig->filename = strdup(filename);
	
	malfree(tmp_list);

	return tmp_sig;
}

static int add_nullstate(void)
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

static void add_endstate(int state, char *signame)
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

static int handle_input(int state_cur, int sys_id)
{
	int state_nxt;
	while (state_cur >= state_n)
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

static void add_signature_to_matrix(SIGNATURE *sig)
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

void load_signatures(void)
{
	int i, loaded_sigs;
	glob_t data;
	SIGNATURE *sig;
	loaded_sigs = 0;

	//Get a file listing of all files in the signatures folder ending in .sig
	switch(glob(SIGNATURE_FILTER, 0, NULL, &data))
	{
		case 0:
			break;
		case GLOB_NOSPACE:
			fprintf(stderr, "glob: Out of memory\n");
			exit(1);
		case GLOB_ABORTED:
			fprintf(stderr, "glob: Reading error\n");
			exit(1);
		case GLOB_NOMATCH:
			fprintf(stderr, "load_signatures: No signatures found\n");
			exit(1);
		default:
			fprintf(stderr, "glob: Unexpected error\n");
			exit(1);
	}

	//For each found .sig file, attempt to load and add it to the transition matrix
	for (i = 0; i < data.gl_pathc; i++)
	{
		printf("Loading signature: %s\n", data.gl_pathv[i]);
		sig = load_signature(data.gl_pathv[i]);
		if (!sig)
		{
			fprintf(stderr, "Error loading signature: %s\n", data.gl_pathv[i]);
		}
		else
		{
			add_signature_to_matrix(sig);
			loaded_sigs++;
			malfree(sig);
		}
	}
	if (!loaded_sigs)
	{
		fprintf(stderr, "No signatures succeeded to load\n");
		exit(1);
	}
	globfree(&data);
}
