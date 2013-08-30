/*
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#ifndef NL_IFACE_H
#define NL_IFACE_H

#ifndef KMALDETECT_H
#include "kmaldetect.h"
#endif

extern pid_t nl_userspace_pid;

extern int maldetect_nl_send_syscall(SYSCALL *data);
extern void maldetect_nl_init(void);
extern void maldetect_nl_close(void);

#endif
