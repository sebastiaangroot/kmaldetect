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
#include "logger.h"

int **transition_matrix = NULL; //The rule tree we use to traverse a the signatures
int **reverse_transition_matrix = NULL;
int tm_states_len = 0;
ENDSTATE *endstates = NULL; //The endstates, with their number and filename
int endstates_len = 0;
int **syscall_encoding_table = NULL;
int *set_branches = NULL;
int *transition_count = NULL;

int e_reached = 0;

/* Returns an index for the endstates array for a corrosponding endstate */
int get_endstate(int state)
{
	int i;
	for (i = 0; i < endstates_len; i++)
	{
		if (state == endstates[i].state)
		{
			return i;
		}
	}
	return -1;
}

void update_state_counter(int state)
{
	int i;
	
	transition_count[state]++;
	if (get_endstate(state) != -1)
	{
		e_reached = 1;
		for (i = state; i > 1; i--)
		{
			transition_count[i]--;
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
		//Could this call possibly go somewhere?
		if ((state = syscall_encoding_table[syscall->sys_id][i]) != 0)
		{
			//Can this state even be reached?
			if (transition_count[state-1] != 0)
			{
				//update_syscall_encoding_table(state);
				store_metadata(syscall, state);
				update_state_counter(state);
			}
		}
	}
}

void read_syscalls_from_file(char *filename)
{
	SYSCALL syscall;
	int fd;
	int cur, end;
	char *file_buffer;
	long file_buffer_p;
	struct stat st;
	int num_syscalls, count;

	stat(filename, &st);
	num_syscalls = (unsigned long)(st.st_size / BYTES_PER_SYSCALL);
	if (st.st_size > FILEBUF_LIM)
	{
		fprintf(stderr, "Filesize limit of 2GB exceeded.\n");
		exit(1);
	}

	fd = open(filename, O_RDONLY);
	if (!fd)
	{
		fprintf(stderr, "Error opening file.\n");
		exit(1);
	}

	file_buffer = malmalloc(sizeof(char) * (st.st_size));
	file_buffer_p = read(fd, file_buffer, st.st_size);
	cur = 0;

	while (cur < file_buffer_p)
	{
		end = cur;

		//int sys_id
		while (end < file_buffer_p && file_buffer[end] != ':') end++;
		syscall.sys_id = (int)strtol(file_buffer+cur, NULL, 10);
		cur = ++end;
		if (cur >= file_buffer_p) break;

		//ulong inode
		while (end < file_buffer_p && file_buffer[end] != ':') end++;
		syscall.inode = (unsigned long)strtol(file_buffer+cur, NULL, 10);
		cur = ++end;
		if (cur >= file_buffer_p) break;

		//pid_t pid
		while(end < file_buffer_p && file_buffer[end] != ':') end++;
		syscall.pid = (pid_t)strtol(file_buffer+cur, NULL, 10);
		cur = ++end;
		if (cur >= file_buffer_p) break;

		//ulong mem_loc
		while(end <= file_buffer_p && file_buffer[end] != '>') end++;
		syscall.mem_loc = (unsigned long)strtol(file_buffer+cur, NULL, 10);

		cur = ++end;
		syscall.states = NULL;
		syscall.states_len = 0;
		handle_input(&syscall);
		count++;
	}
	if (e_reached)
		calculate_winner();
	malfree(file_buffer);
}

void init_parser(void)
{
	int i, j;
	syscall_encoding_table = malcalloc(NUM_SYSCALLS, sizeof(int *));
	set_branches = malcalloc(NUM_SYSCALLS, sizeof(int));
	transition_count = malcalloc(tm_states_len, sizeof(int));

	//Building the syscall_encoding_table
	for (i = 0; i < NUM_SYSCALLS; i++)
	{
		for (j = 0; j < tm_states_len; j++)
		{
			if (transition_matrix[j][i] != 0)
			{
				set_branches[i]++;
				syscall_encoding_table[i] = malrealloc(syscall_encoding_table[i], sizeof(int) * set_branches[i]);
				syscall_encoding_table[i][set_branches[i]-1] = transition_matrix[j][i];
			}
		}
	}
	
	//Enable state 1
	transition_count[1] = 1;
	
	init_logger();
}
