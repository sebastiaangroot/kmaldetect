#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIGLEN 1024*1024

struct signature
{
	int list_length;
	unsigned short *list;
};

typedef struct signature SIGNATURE;

SIGNATURE * load_signature(char *filename)
{
	FILE *file = fopen(filename, "r");
	int read_num;
	unsigned short tmp_list[MAX_SIGLEN];
	int tmp_list_p = 0;
	SIGNATURE *tmp_sig;
	unsigned short *real_list;
	int i;

	while(fscanf(file, "%u,", &read_num))
	{
		tmp_list[tmp_list_p] = (unsigned short) read_num;
		tmp_list_p++;

		if (feof(file) || tmp_list_p >= MAX_SIGLEN)
		{
			break;
		}
	}

	tmp_sig = malloc(sizeof(SIGNATURE));
	real_list = malloc(sizeof(unsigned short) * tmp_list_p);

	if (!tmp_sig || !real_list)
	{
		return NULL;
	}

	for (i = 0; i < tmp_list_p; i++)
	{
		real_list[i] = tmp_list[i];
	}
	
	tmp_sig->list_length = tmp_list_p;
	tmp_sig->list = real_list;

	return tmp_sig;
}

int main(int argc, char *argv[])
{
	int i;
	SIGNATURE *testsig;

	testsig = load_signature(argv[1]);

	for (i = 0; i < testsig->list_length; i++)
	{
		printf("%u, ", testsig->list[i]);
	}

	return 0;
}
