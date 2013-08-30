/*
 * The code responsible for the system-call trace loading phase.
 *
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include "util.h"
#include "parser.h"

int **transition_matrix = NULL; //The rule tree we use to traverse a the signatures
int **reverse_transition_matrix = NULL;
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
	unsigned long count = 0;
	unsigned long num_syscalls;
	int percentage;
	struct stat st;
	int showedstatus = 0;

	stat(filename, &st);
	num_syscalls = (unsigned long)(st.st_size / BYTES_PER_SYSCALL);

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
		count++;
		
		percentage = (int)(((double)count / (double)num_syscalls) * 100);

		if (percentage % 10 == 0 && percentage != 0 && !showedstatus)
		{
			showedstatus = 1;
			printf("Progress: %i%%\n", percentage);
		}
		else if (percentage % 10 != 0)
		{
			showedstatus = 0;
		}

		if (ret == 0)
			break;

	}
}

void remove_syscall(int i)
{
	memmove(syscalls + (sizeof(SYSCALL) * i), syscalls + (sizeof(SYSCALL) * (i + 1)), (syscalls_len - i - 1) * sizeof(SYSCALL));
	syscalls_len--;
}

void keep_duplicates(void)
{
	int i, j, k, l;
	int duplicate;

	printf("SYSCALLS_LEN PRE-FILTER: %i\n", syscalls_len);

	for (i = 0; i < syscalls_len; i++)
	{
		duplicate = 0;
		printf("Progress: %i / %i\n", i, syscalls_len);
		for (j = 0; j < syscalls_len; j++)
		{
			if (i == j)
				continue;

			if (syscalls[i].sys_id == syscalls[j].sys_id && (syscalls[i].pid == syscalls[j].pid || syscalls[i].inode == syscalls[j].inode))
			{
				for (k = 0; k < syscalls[i].states_len; k++)
				{
					for (l = 0; l < syscalls[j].states_len; l++)
					{
						if (syscalls[i].states[k] == syscalls[j].states[l])
						{
							duplicate = 1;
						}
					}
				}
			}
		}
		if (!duplicate)
		{
			remove_syscall(i);
			i--;
		}
	}

	printf("SYSCALLS_LEN POST-FILTER: %i\n", syscalls_len);
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
