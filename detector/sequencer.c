#include <stdio.h>
#include "parser.h"
#include "util.h"

extern ENDSTATE *endstates;
extern int endstates_len;
extern SYSCALL *syscalls;
extern int syscalls_len;

static int find_syscall(int state, int from, int to)
{
	int i, j;
	
	for (i = from; i <= to; i++)
	{
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

/*static int find_syscall_reverse(int state, int from, int to)
{
	int i, j;

	for (i = from; i >= to; i--)
	{
		for (j = 0; j < syscalls[i].states_len; j++)
		{
			if (syscalls[i].states[j] == state)
			{
				return i;				
			}
		}
	}
	return -1;
}*/

static int syscalls_match(int first, int second)
{
	//The sys_ids must match. Other than that, the inode number or pid must also match
	if (syscalls[first].sys_id == syscalls[second].sys_id && (syscalls[first].inode == syscalls[second].inode || syscalls[first].pid == syscalls[second].pid))
	{
		return 1;
	}
	return 0;
}

static void handle_endstate(ENDSTATE endstate)
{
	int first_end = -1;
	int second_end;
	
	while ((first_end = find_syscall(endstate.state, first_end + 1, syscalls_len - 1)) != -1)
	{
		second_end = first_end;
		while ((second_end = find_syscall(endstate.state, second_end + 1, syscalls_len - 1)) != -1)
		{
			if (syscalls_match(first_end, second_end))
			{
				printf("Endstate %i (%s) matched!\n\tIndexes: %i / %i\n\tSyscall ID: %i\n\tInode number: %lu || %lu\n\tPID: %i || %i\n\tMem Loc: %lu || %lu\n", endstate.state, endstate.filename, first_end, second_end, syscalls[first_end].sys_id, syscalls[first_end].inode, syscalls[second_end].inode, syscalls[first_end].pid, syscalls[second_end].pid, syscalls[first_end].mem_loc, syscalls[second_end].mem_loc);
			}
		}
	}
}

void parse_endstates(void)
{
	int i, j, k, num_occurences;

	for (i = 0; i < endstates_len; i++)
	{
		printf("[%i/%i] Finding sequences for %s\n", i + 1, endstates_len, endstates[i].filename);
		num_occurences = 0;
		for (j = 0; j < syscalls_len; j++)
		{
			for (k = 0; k < syscalls[j].states_len; k++)
			{
				if (syscalls[j].states[k] == endstates[i].state)
				{
					num_occurences++;
				}
			}
		}
		
		if (num_occurences >= 2)
		{
			handle_endstate(endstates[i]);
		}
	}
}

