/*
 * Responsible for the sequence matching phase. While looking for a sequence, the entire sequence must match. We're not looking for matches
 * on individual syscalls, we're looking at a chained sequence.
 *
 * This implementation uses a recursive matching algorithm that searches for candidate syscalls for this state and matches them.
 * On a match, it calls itself to search for candidate syscalls in the previous state. While doing this, it only searches for 
 * syscalls in the allowed ranges for its part in the sequence (for example, a syscall in sequence 2 may never have an index number
 * lower than the endstate syscall in sequence 1).
 *
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#include <stdio.h>
#include <string.h>
#include "util.h"
#include "parser.h"

#define DO_PRINT	2

extern SYSCALL *syscalls;
extern int syscalls_len;
unsigned long long counter = 0;

void print_dbg(int low1, int up1, int cur1, int low2, int up2, int cur2)
{
	char *buffer;
	buffer = malmalloc(((syscalls_len * 3) + 1) * sizeof(char));
	memset(buffer, 0x20, ((syscalls_len*3))*sizeof(char));
	buffer[syscalls_len*3] = '\0';
	int i;
	for (i = 0; i < syscalls_len; i++)
	{
		printf("[%i]", syscalls[i].states[0]);
	}
	if (low1 >= 0)
		buffer[low1*3] = '[';
	if (up1 >= 0)
		buffer[(up1*3)+2] = ']';
	if (cur1 >= 0)
		buffer[(cur1*3)+1] = '1';
	if (low2 >= 0)
		buffer[low2*3] = '{';
	if (up2 >= 0)
		buffer[(up2*3)+2] = '}';
	if (cur2 >= 0)
		buffer[(cur2*3)+1] = '2';
	printf(buffer);
	malfree(buffer);
	getchar();
}

int find_syscall_reverse(int state, int from, int to, int other_low, int other_up, int other_cur, int seq)
{
	int i, j;
	for (i = from; i >= to; i--)
	{
		counter++;
		if (seq == 1)
			print_dbg(to, from, i, -1, -1, -1);
		else if (seq == 2)
			print_dbg(other_low, other_up, other_cur, from, to, i);
		for (j = 0; j < syscalls[i].states_len; j++)
		{
			if (syscalls[i].states[j] == state)
			{
				return i;
			}
		}
	}
	return -1;
}

void print_syscall(SYSCALL syscall, int state)
{
	fprintf(stderr, "STATE %i = %i:%lu:%i:%lu\n", state, syscall.sys_id, syscall.inode, syscall.pid, syscall.mem_loc);
}

int match_syscalls(SYSCALL sys1, SYSCALL sys2)
{
	if (sys1.sys_id == sys2.sys_id && (sys1.inode == sys2.inode || sys1.pid == sys2.pid))
	{
		return 1;
	}
	return 0;
}

int find_statematch(int state, int seq1from, int seq2from, int first_endstate){
	int call1;
	int call2;
	int real_first_endstate;
	
	call1 = find_syscall_reverse(state, seq1from, 0, -1, -1, -1, 1);
	if (call1 == -1)
	{
		return 0;
	}
	real_first_endstate = (first_endstate == -1 ? call1 + 1: first_endstate);

	call2 = find_syscall_reverse(state, seq2from, real_first_endstate, 0, seq1from, call1, 2);
	while (call1 != -1)
	{
		while (call2 != -1)
		{
			if (match_syscalls(syscalls[call1], syscalls[call2]))
			{
//DEBUGGING INFO===============================
				//if (first_endstate == -1)
				//{
				//	fprintf(stderr, "Matching endstate %i with indexes %i and %i\n", state, call1, call2);
				//}
//DEBUGGING INFO===============================
				if (state > 2)
				{
					if (find_statematch(reverse_transition_matrix[state][syscalls[call2].sys_id], call1 - 1, call2 - 1, real_first_endstate) == DO_PRINT)
					{
						fprintf(stderr, "###############################\n");
						print_syscall(syscalls[call1], state);
						print_syscall(syscalls[call2], state);
						return DO_PRINT;
					}
				}
				else
				{
               fprintf(stderr, "DBG_COUNTER: %llu\n", counter);
					fprintf(stderr, "FOUND HIT. PRINTING THE DOUBLE TRACE:\n");
					print_syscall(syscalls[call1], state);
					print_syscall(syscalls[call2], state);
					return DO_PRINT;
				}
			}
			call2 = find_syscall_reverse(state, call2 - 1, real_first_endstate, 0, seq1from, call1, 2);
		}
		seq1from = call1 - 1;
		call1 = find_syscall_reverse(state, call1 - 1, 0, -1, -1, -1, 1);
		real_first_endstate = (first_endstate == -1 ? call1 + 1: first_endstate);

		call2 = find_syscall_reverse(state, seq2from, real_first_endstate, 0, seq1from, call1, 2);
	}
	return 0;
}
