#ifndef MM_H
#define MM_H
#include "maldetect.h"

#define BLOCK_SIZE	64*1024
#define SYSCALLS_PER_BLOCK (BLOCK_SIZE / sizeof(SYSCALL))

extern int block_lim;

extern int mm_init(void);
extern int store_syscall(SYSCALL *input);

#endif
