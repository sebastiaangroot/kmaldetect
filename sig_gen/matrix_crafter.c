#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIGLEN 1024*1024
#define NUM_SYSCALLS

struct signature
{
	int list_length;
	unsigned short *list;
};

int **transition_matrix;
int state_p;

typedef struct signature SIGNATURE;

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
		tmp_list[tmp_list_p] = (unsigned short) read_num;
		tmp_list_p++;

		if (feof(file) || tmp_list_p >= MAX_SIGLEN)
		{
			break;
		}
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

	return tmp_sig;
}

void add_state(int *encoding)
{
	int i;

	realloc(&transition_matrix, (state_p + 1) * NUM_SYSCALLS * sizeof(int))
	for (i = 0; i < NUM_SYSCALLS; i++)
	{
		transition_matrix[state_p][i] = encoding[i];
	}
	state_p++;
}

int handle_input(int state, int sys_id)
{
	if (state_p < state)
	
}

void add_signature(SIGNATURE *sig)
{
	int i;
	int state = 1;
	
	for (i = 0; i < sig->list_length; i++)
	{
		state = handle_input(state, sig->list[i]);
	}
}

void add_nullstate(void)
{
	int i;
	
	if (transition_matrix == NULL)
	{
		transition_matrix = malloc(NUM_SYSCALLS * sizeof(int));
	}
	else
	{
		realloc(&transition_matrix, state_p * NUM_SYSCALLS * sizeof(int));
	}
	
	for (i = 0; i < NUM_SYSCALLS; i++)
	{
		transition_matrix[state_p] = 0;
	}
	state_p++;
}

int main(int argc, char *argv[])
{
	int i, len;
	state_p = 0;
	SIGNATURE *testsig;

	testsig = load_signature(argv[1]);

	return 0;
}
