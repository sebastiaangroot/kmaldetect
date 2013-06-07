#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include "util.h"
#include "parser.h"

int **transition_matrix = NULL;; //The rule tree we use to traverse a the signatures
int tm_states_len = 0;
ENDSTATE *endstates = NULL; //The endstates, with their number and filename
int endstates_len = 0;
SYSCALL *syscalls = NULL; //The list containing all handled syscalls
int syscalls_len = 0;
int **syscall_encoding_table = NULL;
int *set_branches = NULL;

static void update_syscall_encoding_table(int state)
{
	int i, j;
	int duplicate;

	//For each syscall
	for (i = 0; i < NUM_SYSCALLS; i++)
	{
		//We ignore it if it leads to zero
		if (transition_matrix[state][i] == 0)
		{
			continue;
		}

		//We check if we've already defined this transition
		duplicate = 0;
		for (j = 0; j < set_branches[i]; j++)
		{
			if (transition_matrix[state][i] == syscall_encoding_table[i][j])
			{
				duplicate = 1;
				break;
			}
		}

		//If this is a new transition
		if (!duplicate)
		{
			//If we defined nothing but the zero state, overwrite it
			if (syscall_encoding_table[i][0] == 0)
			{
				syscall_encoding_table[i][0] = transition_matrix[state][i];
			}
			//Otherwise, increase the size in syscall_encoding_table[i] and append it
			else
			{
				syscall_encoding_table[i] = realloc(syscall_encoding_table[i], (set_branches[i] + 1) * sizeof(int));
				syscall_encoding_table[i][set_branches[i]] = transition_matrix[state][i];
				set_branches[i]++;
			}
		}
	}
}

static void handle_input(SYSCALL *syscall)
{
	int i, branch_lim, state;

	//Follow the syscall_encoding_table
	branch_lim = set_branches[syscall->sys_id];
	for (i = 0; i < branch_lim; i++)
	{
		if ((state = syscall_encoding_table[syscall->sys_id][i]) != 0)
		{
			update_syscall_encoding_table(state);
			if (syscall->states_len == 0)
			{
				syscall->states = malcalloc(1, sizeof(int));
				syscall->states[0] = state;
				syscall->states_len = 1;
			}
			else
			{
				syscall->states = malrealloc(syscall->states, (syscall->states_len + 1) * sizeof(int));
				syscall->states[syscall->states_len] = state;
				syscall->states_len++;
			}
		}
	}

	//No states were reached, we're not saving this syscall
	if (syscall->states_len == 0)
	{
		return;
	}

	if (syscalls_len == 0)
	{
		syscalls = malcalloc(1, sizeof(SYSCALL));
		memcpy(syscalls, syscall, sizeof(SYSCALL));
		syscalls_len = 1;
	}
	else
	{
		syscalls = malrealloc(syscalls, (syscalls_len + 1) * sizeof(SYSCALL));
		memcpy(&syscalls[syscalls_len], syscall, sizeof(SYSCALL));
		syscalls_len++;
	}
}

void read_syscalls_from_file(char *filename)
{
	int fd;
	char c;
	SYSCALL syscall;
	char buffer[200];
	int buffer_p;
	int ret;

	syscall.sys_id = 0;
	syscall.inode = 0;
	syscall.pid = 0;
	syscall.mem_loc = 0;
	syscall.states = NULL;
	syscall.states_len = 0;

	fd = open(filename, O_RDONLY);
	if (!fd)
	{
		fprintf(stderr, "File error.\n");
		exit(1);
	}

	while(1)
	{
		memset(buffer, 0, 100);
		buffer_p = 0;
		while(1)
		{
			ret = read(fd, &c, 1);
			if (ret == -1)
			{
				fprintf(stderr, "Read error\n");
				exit(1);
			}
			else if (ret == 0)
			{
				break;
			}

			if (c == '>')
			{
				break;
			}
			else
			{
				buffer[buffer_p] = c;
				buffer_p++;
			}
		}
		sscanf(buffer, "%i:%lu:%i:%lu", &syscall.sys_id, &syscall.inode, &syscall.pid, &syscall.mem_loc);
		syscall.states = NULL;
		syscall.states_len = 0;
		handle_input(&syscall);
		if (ret == 0)
			break;
	}
}

void init_parser(void)
{
	int i;

	syscall_encoding_table = malcalloc(NUM_SYSCALLS, sizeof(int *));
	set_branches = malcalloc(NUM_SYSCALLS, sizeof(int));

	for (i = 0; i < NUM_SYSCALLS; i++)
	{
		syscall_encoding_table[i] = malcalloc(1, sizeof(int));
		syscall_encoding_table[i][0] = transition_matrix[1][i]; //Our syscall_encoding_table will start with the same redirection-data as is in transition_matrix's state 1
		set_branches[i] = 1; //We've allocated sizeof(int) * 1, so we only have 1 redirect for each given syscall. set_branches will increment if there are more paths for a syscall to follow
	}
}
