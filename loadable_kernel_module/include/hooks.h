/*
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#ifndef HOOKS_NEW_H
#define HOOKS_NEW_H

void reg_hooks(unsigned long **syscall_table);
void unreg_hooks(unsigned long **syscall_table);

#endif
