#include <stdio.h>
#include <stdlib.h>
#include "sigloader.h"
#include "util.h" //TODO FOR DEBUGGING FUNCTIONS

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <kmaldetect trace file>\n", argv[0]);
		exit(1);
	}
	
	load_signatures();
	dbg_print_transition_matrix();
	dbg_print_endstates(); //TODO DEBUGGING
	//parse_syscalls(argv[1]);
	//find_patterns();
	return 0;
}
