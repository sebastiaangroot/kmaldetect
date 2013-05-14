#define TM_COMPLEXITY 20
#define TM_NUM_ENDSTATES 5
#define TM_NUM_STATES 15

#define NUM_SYSCALLS 330
#define NUM_STATES TM_NUM_STATES
#define MAX_COMPLEXITY TM_BRANCH_COMPLEXITY
#define NUM_ENDSTATES TM_NUM_ENDSTATES

int transition_matrix[NUM_STATES][NUM_SYSCALLS];
int transition_matrix_endstates[NUM_ENDSTATES];
int syscall_encoding_table[NUM_SYSCALLS][MAX_COMPLEXITY];
int branches[NUM_SYSCALLS];

/*
 * Temporary init function. The transition matrix will be loaded according to file-provided signatures
 * This temporary transition matrix simply loops every input to the next state (with the exception of state 0)
 * */
int init_transition_matrix(void)
{
	int i, j;
	for (i = 0; i < NUM_STATES; i++)
	{
		for (j = 0; j < NUM_SYSCALLS; j++)
		{
			if (i == 0)
			{
				transition_matrix[i][j] = i;
			}
			else
			{
				transition_matrix[i][j] = i + 1;
			}
		}
	}

	transition_matrix_endstates[0] = 5;
	transition_matrix_endstates[1] = 7;
	transition_matrix_endstates[2] = 10;
	transition_matrix_endstates[3] = 12;
	transition_matrix_endstates[4] = 14;
} 

/*
 * Fill the syscall_encoding_table according to our transition matrix and set the branches array to one for each system call
 * */
int init_parser(void)
{
	int i;
	for (i = 0; i < NUM_SYSCALLS; i++)
	{
		//The syscall_encoding_table starts at state 1
		syscall_encoding_table[i] = transition_matrix[1][i];
		branches[i] = 1;
	}
	init_transition_matrix();
}

int update_syscall_encoding_table(int id, int state)
{
	int i;

	//Step 1: If syscall_encoding_table[id][0] == 0, we can replace this default state
	if (syscall_encoding_table[id][0] == 0)
	{
		syscall_encoding_table[id][0] = state;
		return 1;
	}

	//Step 2: Check if the to-be-added state is already present
	for (i = 0; i < branches[id]; i++)
	{
		if (syscall_encoding_table[id][i] == state)
		{
			return 1;
		}
	}

	//Step 3: Check if we're not about to overflow the syscall_encoding_table
	if (branches[id] >= MAX_BRANCHES)
	{
		return 0;
	}

	//Step 4: Add the state to the syscall_encoding_table and increment the branches array
	syscall_encoding_table[id][branches[id]] = state;
	branches[id]++;
	return 1;
}

int handle_input(struct raw_syscall input)
{
	int i;
	
	//Step 1: Follow the syscall_encoding_table
	for (i = 0; i < branches[input.id]; i++)
	{
		if ((state = syscall_encoding_table[input.id][i]) != 0)
		{
			update_syscall_encoding_table(input.id, state);
		}
	}

	//Step 2: Check for end-states
	
}

