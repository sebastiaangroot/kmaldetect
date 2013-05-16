#include <stdio.h>
#include <stdlib.h>
#include "parser.h"

int main(int argc, char *argv[])
{
	int i;
	init_parser();
	printf("##Initial states##\n");
	debug_print();

	for (i = 1; i < argc; i++)
	{
		handle_input(atoi(argv[i]));
		printf("##INPUT: %i##\n", atoi(argv[i]));
		debug_print();
	}

	if (i == 20)
	{
		init_parser();
		exit(1);
	}
	else
	{
		printf("nope\n");
		exit(1);
	}


	return 0;
}
