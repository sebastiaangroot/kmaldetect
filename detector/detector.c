/*
 * The entry point of the KMaldetect Detector application.
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
#include "sigloader.h"
#include "util.h"
#include "sequencer.h"
#include "parser.h"

extern int syscalls_len;
extern SYSCALL *syscalls;
extern ENDSTATE *endstates;
extern int endstates_len;
int main(int argc, char **argv)
{
	int i, j, k;
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

	/*for (i = 0; i < endstates_len; i++)
	{
		for (j = 0; j < syscalls_len; j++)
		{
			for (k = 0; k < syscalls[j].states_len; k++)
			{
				if (syscalls[j].states[k] == endstates[i].state)
				{
					printf("Ind %i, %lu reached endstate of %s\n", j, syscalls[j].inode, endstates[i].filename);
				}
			}
		}
	}*/

	//keep_duplicates();
	//find_statematch(endstates->state, syscalls_len - 2, syscalls_len - 1, -1);

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
