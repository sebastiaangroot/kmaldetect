#ifndef LOGGER_H
#define LOGGER_H

#include "util.h"

extern void init_logger(void);
extern void store_metadata(SYSCALL *sys, int state);
extern void flush_logger(void);
extern void calculate_winner(void);

#endif
