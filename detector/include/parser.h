#ifndef PARSER_H
#define PARSER_H

typedef struct
{
	int state;
	char *filename;
} ENDSTATE;

extern int **transition_matrix;
extern int state_n;
extern ENDSTATE *endstates;
extern int endstate_n;

#endif
