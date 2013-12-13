#ifndef LOGGER_H
#define LOGGER_H

#include "util.h"

extern void print_metadata(int state);
extern void print_metadata_very_verbose(void);
extern void init_logger(void);
extern void store_metadata(SYSCALL *sys, int state);
extern void flush_logger(void);

#endif
