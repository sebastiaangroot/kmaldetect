#include <asm/unistd.h>
#include <linux/syscalls.h>
#include <asm/thread_info.h>
#include "nl_iface.h"
#include "utils.h"
#include "kmaldetect.h"

/* The PID identifying our userspace receiver */
extern pid_t maldetect_userspace_pid;

/* Function pointers */
long (*sys_read)(unsigned int fd, char __user *buf, size_t count) = NULL;
long (*sys_write)(unsigned int fd, const char __user *buf, size_t count) = NULL;
long (*sys_open)(const char __user *filename, int flags, int mode) = NULL;
long (*sys_close)(unsigned int fd) = NULL;
long (*sys_newstat)(char __user *filename, struct stat __user *statbuf) = NULL;
long (*sys_newfstat)(unsigned int fd, struct stat __user *statbuf) = NULL;
long (*sys_newlstat)(char __user *filename, struct stat __user *statbuf) = NULL;
long (*sys_poll)(struct pollfd __user *ufds, unsigned int nfds, int timeout) = NULL;
long (*sys_lseek)(unsigned int fd, off_t offset, unsigned int origin) = NULL;
long (*sys_mmap)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long) = NULL;
long (*sys_mprotect)(unsigned long start, size_t len, unsigned long prot) = NULL;
long (*sys_munmap)(unsigned long addr, size_t len) = NULL;
long (*sys_brk)(unsigned long brk) = NULL;
long (*sys_rt_sigaction)(int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize);
long (*sys_rt_sigprocmask)(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize) = NULL;
long (*sys_ioctl)(unsigned int fd, unsigned int cmd, unsigned long arg) = NULL;
long (*sys_pread64)(unsigned int fd, char __user *buf, size_t count, loff_t pos) = NULL;
long (*sys_pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t pos) = NULL;
long (*sys_readv)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen) = NULL;
long (*sys_writev)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen) = NULL;
long (*sys_access)(const char __user *filename, int mode) = NULL;
long (*sys_pipe)(int __user *fildes) = NULL;
long (*sys_select)(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp) = NULL;
long (*sys_sched_yield)(void) = NULL;
long (*sys_mremap)(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr) = NULL;
long (*sys_msync)(unsigned long start, size_t len, int flags) = NULL;
long (*sys_mincore)(unsigned long start, size_t len, unsigned char __user * vec) = NULL;
long (*sys_madvise)(unsigned long start, size_t len, int behavior) = NULL;
long (*sys_shmget)(key_t key, size_t size, int flag) = NULL;
long (*sys_shmat)(int shmid, char __user *shmaddr, int shmflg) = NULL;
long (*sys_shmctl)(int shmid, int cmd, struct shmid_ds __user *buf) = NULL;
long (*sys_dup)(unsigned int fildes) = NULL;
long (*sys_dup2)(unsigned int oldfd, unsigned int newfd) = NULL;
long (*sys_pause)(void) = NULL;
long (*sys_nanosleep)(struct timespec __user *rqtp, struct timespec __user *rmtp) = NULL;
long (*sys_getitimer)(int which, struct itimerval __user *value) = NULL;
long (*sys_alarm)(unsigned int seconds) = NULL;
long (*sys_setitimer)(int which, struct itimerval __user *value, struct itimerval __user *ovalue) = NULL;
long (*sys_getpid)(void) = NULL;
long (*sys_sendfile64)(int out_fd, int in_fd, loff_t __user *offset, size_t count) = NULL;
long (*sys_socket)(int, int, int) = NULL;
