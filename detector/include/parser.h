#ifndef PARSER_H
#define PARSER_H

#include "util.h"

#define BYTES_PER_SYSCALL	16.60249

extern int **transition_matrix;
extern int tm_states_len;
extern ENDSTATE *endstates;
extern int endstates_len;
extern SYSCALL *syscalls;
extern int syscalls_len;

extern void init_parser(void);
extern void read_syscalls_from_file(char *filename);

#endif
