/*
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#ifndef PARSER_H
#define PARSER_H

#include "util.h"

#define BYTES_PER_SYSCALL	16.60249
#define FILEBUF_LIM	2147483648

extern int **transition_matrix;
extern int **reverse_transition_matrix;
extern int tm_states_len;
extern ENDSTATE *endstates;
extern int endstates_len;

extern void init_parser(void);
extern void read_syscalls_from_file(char *filename);
extern void keep_duplicates(void);

#endif
