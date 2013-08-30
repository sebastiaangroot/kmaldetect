/*
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

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
