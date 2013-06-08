//The entire sequence must match. We're not looking for matches on idividual syscalls, we're looking at a chained sequence.
//This implementation uses a recursive matching algorithm that searches for candidate syscalls for this state, matches them, and on a match, calls itself to search for candidate syscalls in the previous state. While doing this, it only searches for syscalls in the allowed ranges for its part in the sequence (for example, a syscall in sequence 2 may never have an index number lower than the endstate syscall in sequence 1).
#define DO_PRINT	2

int find_syscall_reverse(int state, int from, int to)
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
}

void print_syscall(SYSCALL *syscall, int state)
{
	fprintf(stderr, "STATE %i = %i:%lu:%i:%lu", state, syscall->sys_id, syscall->inode, syscall->pid, syscall->mem_loc);
}

int find_statematch(int state, int seq1from, int seq2from, int first_endstate)
{
	int call1;
	int call2;
	int real_first_endstate;
	
	call1 = find_syscall_reverse(state, seq1from, 0);

	real_first_endstate = (first_endstate == -1 ? call1 : first_endstate);

	call2 = find_syscall_reverse(state, seq2from, real_first_endstate);
	while (call1 != -1)
	{
		while (call2 != -1)
		{
			if (match_syscalls(syscalls[call1], syscalls[call2]))
			{
//DEBUGGING INFO===============================
				if (first_endstate == -1) //Indication that we're at the start of the sequence matching. In other words, we're at the endstate
				{
					fprintf(stderr, "Matching endstate %i with indexes %i and %i\n", state, call1, call2);
				}
//DEBUGGING INFO===============================
				if (state > 1)
				{
					if (find_statematch(reverse_transition_matrix[state][syscall[call2].sys_id], call1 - 1, call2 - 1, real_first_endstate) == DO_PRINT)
					{
						fprintf(stderr, "###############################\n");
						print_syscall(syscalls[call1], state);
						fprintf(stderr, "\n");
						print_syscall(syscalls[call2], state);
						return DO_PRINT;
					}
				}
				else
				{
					fprintf(stderr, "FOUND HIT. PRINTING THE DOUBLE TRACE:\n");
					print_syscall(syscalls[call1], state);
					fprintf(stderr, "\n");
					print_syscall(syscalls[call2], state);
					return DO_PRINT;
				}
			}
			call2 = find_syscall_reverse(state, call2 - 1, real_first_endstate);
		}
		call1 = find_syscall_reverse(state, call1 - 1, 0);
		call2 = find_syscall_reverse(state, seq2from, real_first_endstate);
	}
}