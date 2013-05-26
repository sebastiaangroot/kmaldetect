#ifndef NL_IFACE_H
#define NL_IFACE_H

#ifndef KMALDETECT_H
#include "kmaldetect.h"
#endif

typedef struct maldetect_dummy_str {
    int id;
} SYSCALL_DUMMY;


extern int maldetect_nl_send_syscall(SYSCALL_DUMMY *data);
extern void maldetect_nl_init(void);
extern void maldetect_nl_close(void);

#endif
