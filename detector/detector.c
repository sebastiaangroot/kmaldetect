#include <stdio.h>
#include <stdlib.h>
#include "sigloader.h"
#include "util.h"
#include "sequencer.h"
#include "parser.h"

extern int syscalls_len;
extern SYSCALL *syscalls;
long counter = 0;
int main(int argc, char **argv)
{
	int i;
	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <kmaldetect trace file>\n", argv[0]);
		exit(1);
	}
	
	load_signatures();
	init_parser();
	read_syscalls_from_file(argv[1]);
	//parse_endstates();
	printf("syscalls_len: %i\n", syscalls_len);
	for (i = 0; i < syscalls_len; i++)
	{
		counter += syscalls[i].states_len;
	}
	printf("total matched states: %ld\n", counter);
	return 0;
}
