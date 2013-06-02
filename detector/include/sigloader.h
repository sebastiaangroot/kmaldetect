#ifndef SIGLOADER_H
#define SIGLOADER_H

#define MAX_SIGLEN	(1024*1024)
#define SIGNATURE_FILTER "signatures/*.sig"

typedef struct
{
	int list_length;
	unsigned short *list;
	char *filename;
} SIGNATURE;

extern void load_signatures(void);

#endif
