#ifndef HOOKS_H
#define HOOKS_H

void reg_hooks(unsigned long **sys_call_table);
void unreg_hooks(unsigned long **sys_call_table);

#endif