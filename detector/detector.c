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
#include "parser.h"

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

	return 0;
}
