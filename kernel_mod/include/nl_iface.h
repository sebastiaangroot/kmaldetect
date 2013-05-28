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
