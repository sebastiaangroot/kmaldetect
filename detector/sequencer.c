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
#include "util.h"
#include "parser.h"

#define DO_PRINT	2

extern SYSCALL *syscalls;
extern int syscalls_len;

int find_syscall_reverse(int state, int from, int to)
{
	int i, j;
	for (i = from; i >= to; i--)
	{
		for (j = 0; j < syscalls[i].states_n; j++)
		{
			if (j < STATES_BUF)
			{
				if (syscalls[i].states_a[j] == state)
				{
					return i;
				}
			}
			else
			{
				if (syscalls[i].states_p[j - STATES_BUF] == state)
				{
					return i;
				}
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
	
	call1 = find_syscall_reverse(state, seq1from, 0);
	if (call1 == -1)
	{
		return 0;
	}
	real_first_endstate = (first_endstate == -1 ? call1 + 1: first_endstate);

	call2 = find_syscall_reverse(state, seq2from, real_first_endstate);
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
					fprintf(stderr, "FOUND HIT. PRINTING THE DOUBLE TRACE:\n");
					print_syscall(syscalls[call1], state);
					print_syscall(syscalls[call2], state);
					return DO_PRINT;
				}
			}
			call2 = find_syscall_reverse(state, call2 - 1, real_first_endstate);
		}
		call1 = find_syscall_reverse(state, call1 - 1, 0);
		real_first_endstate = (first_endstate == -1 ? call1 + 1: first_endstate);

		call2 = find_syscall_reverse(state, seq2from, real_first_endstate);
	}
	return 0;
}
