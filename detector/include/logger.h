#ifndef LOGGER_H
#define LOGGER_H

#include "util.h"

extern void print_metadata(void);
extern void init_logger(void);
extern void store_metadata(SYSCALL *sys);

#endif