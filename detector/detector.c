#include <stdio.h>
#include <stdlib.h>
#include "sigloader.h"
#include "util.h"
#include "sequencer.h"
#include "parser.h"
#include "sequence_algorithm.h"

extern int syscalls_len;
extern SYSCALL *syscalls;
extern ENDSTATE *endstates;
int main(int argc, char **argv)
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <kmaldetect trace file>\n", argv[0]);
		exit(1);
	}

	printf("Loading signatures...\n");
	load_signatures();

	printf("Loading syscall trace...\n");
	init_parser();
	read_syscalls_from_file(argv[1]);

	//keep_duplicates();
	find_statematch(endstates->state, syscalls_len - 2, syscalls_len - 1, -1);

	//printf("Matching sequences for each endstate...\n");
	//parse_endstates();
	
	/*printf("syscalls_len: %i\n", syscalls_len);
	for (i = 0; i < syscalls_len; i++)
	{
		counter += syscalls[i].states_len;
	}
	printf("total matched states: %ld\n", counter);*/
	return 0;
}
