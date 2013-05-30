#include <asm/unistd.h>
#include <linux/syscalls.h>
#include <asm/thread_info.h>
#include "nl_iface.h"
#include "utils.h"
#include "kmaldetect.h"

/* The PID identifying our userspace receiver */
extern pid_t maldetect_userspace_pid;

long (*ref_sys_read)(unsigned int fd, char __user *buf, size_t count) = NULL;
long (*ref_sys_write)(unsigned int fd, const char __user *buf,   size_t count) = NULL;
long (*ref_sys_open)(const char __user *filename, int flags, int mode) = NULL;
long (*ref_sys_close)(unsigned int fd) = NULL;
long (*ref_sys_newstat)(char __user *filename, struct stat __user *statbuf) = NULL;
long (*ref_sys_newfstat)(unsigned int fd, struct stat __user *statbuf) = NULL;
long (*ref_sys_newlstat)(char __user *filename, struct stat __user *statbuf) = NULL;
long (*ref_sys_poll)(struct pollfd __user *ufds, unsigned int nfds, int timeout) = NULL;
long (*ref_sys_lseek)(unsigned int fd, off_t offset,   unsigned int origin) = NULL;
long (*ref_sys_mmap)(unsigned long, unsigned long, unsigned long,  unsigned long, unsigned long, unsigned long) = NULL;
long (*ref_sys_mprotect)(unsigned long start, size_t len, unsigned long prot) = NULL;
long (*ref_sys_munmap)(unsigned long addr, size_t len) = NULL;
long (*ref_sys_brk)(unsigned long brk) = NULL;
long (*ref_sys_rt_sigaction)(int sig, const struct sigaction __user *act,  struct sigaction __user *oact, size_t sigsetsize) = NULL;
long (*ref_sys_rt_sigprocmask)(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize) = NULL;
long (*ref_sys_ioctl)(unsigned int fd, unsigned int cmd, unsigned long arg) = NULL;
long (*ref_sys_pread64)(unsigned int fd, char __user *buf,     size_t count, loff_t pos) = NULL;
long (*ref_sys_pwrite64)(unsigned int fd, const char __user *buf,      size_t count, loff_t pos) = NULL;
long (*ref_sys_readv)(unsigned long fd,   const struct iovec __user *vec,   unsigned long vlen) = NULL;
long (*ref_sys_writev)(unsigned long fd,    const struct iovec __user *vec,    unsigned long vlen) = NULL;
long (*ref_sys_access)(const char __user *filename, int mode) = NULL;
long (*ref_sys_pipe)(int __user *fildes) = NULL;
long (*ref_sys_select)(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp) = NULL;
long (*ref_sys_sched_yield)(void) = NULL;
long (*ref_sys_mremap)(unsigned long addr,    unsigned long old_len, unsigned long new_len,    unsigned long flags, unsigned long new_addr) = NULL;
long (*ref_sys_msync)(unsigned long start, size_t len, int flags) = NULL;
long (*ref_sys_mincore)(unsigned long start, size_t len, unsigned char __user * vec) = NULL;
long (*ref_sys_madvise)(unsigned long start, size_t len, int behavior) = NULL;
long (*ref_sys_shmget)(key_t key, size_t size, int flag) = NULL;
long (*ref_sys_shmat)(int shmid, char __user *shmaddr, int shmflg) = NULL;
long (*ref_sys_shmctl)(int shmid, int cmd, struct shmid_ds __user *buf) = NULL;
long (*ref_sys_dup)(unsigned int fildes) = NULL;
long (*ref_sys_dup2)(unsigned int oldfd, unsigned int newfd) = NULL;
long (*ref_sys_pause)(void) = NULL;
long (*ref_sys_nanosleep)(struct timespec __user *rqtp, struct timespec __user *rmtp) = NULL;
long (*ref_sys_getitimer)(int which, struct itimerval __user *value) = NULL;
long (*ref_sys_alarm)(unsigned int seconds) = NULL;
long (*ref_sys_setitimer)(int which, struct itimerval __user *value, struct itimerval __user *ovalue) = NULL;
long (*ref_sys_getpid)(void) = NULL;
long (*ref_sys_sendfile64)(int out_fd, int in_fd,        loff_t __user *offset, size_t count) = NULL;
long (*ref_sys_socket)(int, int, int) = NULL;
long (*ref_sys_connect)(int, struct sockaddr __user *, int) = NULL;
long (*ref_sys_accept)(int, struct sockaddr __user *, int __user *) = NULL;
long (*ref_sys_sendto)(int, void __user *, size_t, unsigned, struct sockaddr __user *, int) = NULL;
long (*ref_sys_recvfrom)(int, void __user *, size_t, unsigned, struct sockaddr __user *, int __user *) = NULL;
long (*ref_sys_sendmsg)(int fd, struct msghdr __user *msg, unsigned flags) = NULL;
long (*ref_sys_recvmsg)(int fd, struct msghdr __user *msg, unsigned flags) = NULL;
long (*ref_sys_shutdown)(int, int) = NULL;
long (*ref_sys_bind)(int, struct sockaddr __user *, int) = NULL;
long (*ref_sys_listen)(int, int) = NULL;
long (*ref_sys_getsockname)(int, struct sockaddr __user *, int __user *) = NULL;
long (*ref_sys_getpeername)(int, struct sockaddr __user *, int __user *) = NULL;
long (*ref_sys_socketpair)(int, int, int, int __user *) = NULL;
long (*ref_sys_setsockopt)(int fd, int level, int optname, char __user *optval, int optlen) = NULL;
long (*ref_sys_getsockopt)(int fd, int level, int optname, char __user *optval, int __user *optlen) = NULL;
long (*ref_sys_exit)(int error_code) = NULL;
long (*ref_sys_wait4)(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru) = NULL;
long (*ref_sys_kill)(int pid, int sig) = NULL;
long (*ref_sys_uname)(struct new_utsname __user *) = NULL;
long (*ref_sys_semget)(key_t key, int nsems, int semflg) = NULL;
long (*ref_sys_semop)(int semid, struct sembuf __user *sops, unsigned nsops) = NULL;
long (*ref_sys_semctl)(int semid, int semnum, int cmd, union semun arg) = NULL;
long (*ref_sys_shmdt)(char __user *shmaddr) = NULL;
long (*ref_sys_msgget)(key_t key, int msgflg) = NULL;
long (*ref_sys_msgsnd)(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg) = NULL;
long (*ref_sys_msgrcv)(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg) = NULL;
long (*ref_sys_msgctl)(int msqid, int cmd, struct msqid_ds __user *buf) = NULL;
long (*ref_sys_fcntl)(unsigned int fd, unsigned int cmd, unsigned long arg) = NULL;
long (*ref_sys_flock)(unsigned int fd, unsigned int cmd) = NULL;
long (*ref_sys_fsync)(unsigned int fd) = NULL;
long (*ref_sys_fdatasync)(unsigned int fd) = NULL;
long (*ref_sys_truncate)(const char __user *path, long length) = NULL;
long (*ref_sys_ftruncate)(unsigned int fd, unsigned long length) = NULL;
long (*ref_sys_getdents)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) = NULL;
long (*ref_sys_getcwd)(char __user *buf, unsigned long size) = NULL;
long (*ref_sys_chdir)(const char __user *filename) = NULL;
long (*ref_sys_fchdir)(unsigned int fd) = NULL;
long (*ref_sys_rename)(const char __user *oldname, const char __user *newname) = NULL;
long (*ref_sys_mkdir)(const char __user *pathname, int mode) = NULL;
long (*ref_sys_rmdir)(const char __user *pathname) = NULL;
long (*ref_sys_creat)(const char __user *pathname, int mode) = NULL;
long (*ref_sys_link)(const char __user *oldname, const char __user *newname) = NULL;
long (*ref_sys_unlink)(const char __user *pathname) = NULL;
long (*ref_sys_symlink)(const char __user *old, const char __user *new) = NULL;
long (*ref_sys_readlink)(const char __user *path, char __user *buf, int bufsiz) = NULL;
long (*ref_sys_chmod)(const char __user *filename, mode_t mode) = NULL;
long (*ref_sys_fchmod)(unsigned int fd, mode_t mode) = NULL;
long (*ref_sys_chown)(const char __user *filename, uid_t user, gid_t group) = NULL;
long (*ref_sys_fchown)(unsigned int fd, uid_t user, gid_t group) = NULL;
long (*ref_sys_lchown)(const char __user *filename, uid_t user, gid_t group) = NULL;
long (*ref_sys_umask)(int mask) = NULL;
long (*ref_sys_gettimeofday)(struct timeval __user *tv, struct timezone __user *tz) = NULL;
long (*ref_sys_getrlimit)(unsigned int resource, struct rlimit __user *rlim) = NULL;
long (*ref_sys_getrusage)(int who, struct rusage __user *ru) = NULL;
long (*ref_sys_sysinfo)(struct sysinfo __user *info) = NULL;
long (*ref_sys_times)(struct tms __user *tbuf) = NULL;
long (*ref_sys_ptrace)(long request, long pid, long addr, long data) = NULL;
long (*ref_sys_getuid)(void) = NULL;
long (*ref_sys_syslog)(int type, char __user *buf, int len) = NULL;
long (*ref_sys_getgid)(void) = NULL;
long (*ref_sys_setuid)(uid_t uid) = NULL;
long (*ref_sys_setgid)(gid_t gid) = NULL;
long (*ref_sys_geteuid)(void) = NULL;
long (*ref_sys_getegid)(void) = NULL;
long (*ref_sys_setpgid)(pid_t pid, pid_t pgid) = NULL;
long (*ref_sys_getppid)(void) = NULL;
long (*ref_sys_getpgrp)(void) = NULL;
long (*ref_sys_setsid)(void) = NULL;
long (*ref_sys_setreuid)(uid_t ruid, uid_t euid) = NULL;
long (*ref_sys_setregid)(gid_t rgid, gid_t egid) = NULL;
long (*ref_sys_getgroups)(int gidsetsize, gid_t __user *grouplist) = NULL;
long (*ref_sys_setgroups)(int gidsetsize, gid_t __user *grouplist) = NULL;
long (*ref_sys_setresuid)(uid_t ruid, uid_t euid, uid_t suid) = NULL;
long (*ref_sys_getresuid)(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) = NULL;
long (*ref_sys_setresgid)(gid_t rgid, gid_t egid, gid_t sgid) = NULL;
long (*ref_sys_getresgid)(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) = NULL;
long (*ref_sys_getpgid)(pid_t pid) = NULL;
long (*ref_sys_setfsuid)(uid_t uid) = NULL;
long (*ref_sys_setfsgid)(gid_t gid) = NULL;
long (*ref_sys_getsid)(pid_t pid) = NULL;
long (*ref_sys_capget)(cap_user_header_t header, cap_user_data_t dataptr) = NULL;
long (*ref_sys_capset)(cap_user_header_t header, const cap_user_data_t data) = NULL;
long (*ref_sys_rt_sigpending)(sigset_t __user *set, size_t sigsetsize) = NULL;
long (*ref_sys_rt_sigtimedwait)(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize) = NULL;
long (*ref_sys_rt_sigqueueinfo)(int pid, int sig, siginfo_t __user *uinfo) = NULL;
long (*ref_sys_rt_sigsuspend)(sigset_t __user *unewset, size_t sigsetsize) = NULL;
long (*ref_sys_utime)(char __user *filename, struct utimbuf __user *times) = NULL;
long (*ref_sys_mknod)(const char __user *filename, int mode, unsigned dev) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_personality)(unsigned int personality) = NULL;
long (*ref_sys_ustat)(unsigned dev, struct ustat __user *ubuf) = NULL;
long (*ref_sys_statfs)(const char __user * path, struct statfs __user *buf) = NULL;
long (*ref_sys_fstatfs)(unsigned int fd, struct statfs __user *buf) = NULL;
long (*ref_sys_sysfs)(int option, unsigned long arg1, unsigned long arg2) = NULL;
long (*ref_sys_getpriority)(int which, int who) = NULL;
long (*ref_sys_setpriority)(int which, int who, int niceval) = NULL;
long (*ref_sys_sched_setparam)(pid_t pid, struct sched_param __user *param) = NULL;
long (*ref_sys_sched_getparam)(pid_t pid, struct sched_param __user *param) = NULL;
long (*ref_sys_sched_setscheduler)(pid_t pid, int policy, struct sched_param __user *param) = NULL;
long (*ref_sys_sched_getscheduler)(pid_t pid) = NULL;
long (*ref_sys_sched_get_priority_max)(int policy) = NULL;
long (*ref_sys_sched_get_priority_min)(int policy) = NULL;
long (*ref_sys_sched_rr_get_interval)(pid_t pid, struct timespec __user *interval) = NULL;
long (*ref_sys_mlock)(unsigned long start, size_t len) = NULL;
long (*ref_sys_munlock)(unsigned long start, size_t len) = NULL;
long (*ref_sys_mlockall)(int flags) = NULL;
long (*ref_sys_munlockall)(void) = NULL;
long (*ref_sys_vhangup)(void) = NULL;
int (*ref_sys_modify_ldt)(int, void __user *, unsigned long) = NULL;
long (*ref_sys_pivot_root)(const char __user *new_root, const char __user *put_old) = NULL;
long (*ref_sys_sysctl)(struct __sysctl_args __user *args) = NULL;
long (*ref_sys_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) = NULL;
long (*ref_sys_arch_prctl)(int, unsigned long) = NULL;
long (*ref_sys_adjtimex)(struct timex __user *txc_p) = NULL;
long (*ref_sys_setrlimit)(unsigned int resource, struct rlimit __user *rlim) = NULL;
long (*ref_sys_chroot)(const char __user *filename) = NULL;
long (*ref_sys_sync)(void) = NULL;
long (*ref_sys_acct)(const char __user *name) = NULL;
long (*ref_sys_settimeofday)(struct timeval __user *tv, struct timezone __user *tz) = NULL;
long (*ref_sys_mount)(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data) = NULL;
long (*ref_sys_umount)(char __user *name, int flags) = NULL;
long (*ref_sys_swapon)(const char __user *specialfile, int swap_flags) = NULL;
long (*ref_sys_swapoff)(const char __user *specialfile) = NULL;
long (*ref_sys_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg) = NULL;
long (*ref_sys_sethostname)(char __user *name, int len) = NULL;
long (*ref_sys_setdomainname)(char __user *name, int len) = NULL;
long (*ref_sys_ioperm)(unsigned long, unsigned long, int) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_init_module)(void __user *umod, unsigned long len, const char __user *uargs) = NULL;
long (*ref_sys_delete_module)(const char __user *name_user, unsigned int flags) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_quotactl)(unsigned int cmd, const char __user *special, qid_t id, void __user *addr) = NULL;
long (*ref_sys_nfsservctl)(int cmd, struct nfsctl_arg __user *arg, void __user *res) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_gettid)(void) = NULL;
long (*ref_sys_readahead)(int fd, loff_t offset, size_t count) = NULL;
long (*ref_sys_setxattr)(const char __user *path, const char __user *name,      const void __user *value, size_t size, int flags) = NULL;
long (*ref_sys_lsetxattr)(const char __user *path, const char __user *name,       const void __user *value, size_t size, int flags) = NULL;
long (*ref_sys_fsetxattr)(int fd, const char __user *name,       const void __user *value, size_t size, int flags) = NULL;
long (*ref_sys_getxattr)(const char __user *path, const char __user *name,      void __user *value, size_t size) = NULL;
long (*ref_sys_lgetxattr)(const char __user *path, const char __user *name,       void __user *value, size_t size) = NULL;
long (*ref_sys_fgetxattr)(int fd, const char __user *name,       void __user *value, size_t size) = NULL;
long (*ref_sys_listxattr)(const char __user *path, char __user *list,       size_t size) = NULL;
long (*ref_sys_llistxattr)(const char __user *path, char __user *list,        size_t size) = NULL;
long (*ref_sys_flistxattr)(int fd, char __user *list, size_t size) = NULL;
long (*ref_sys_removexattr)(const char __user *path, const char __user *name) = NULL;
long (*ref_sys_lremovexattr)(const char __user *path,  const char __user *name) = NULL;
long (*ref_sys_fremovexattr)(int fd, const char __user *name) = NULL;
long (*ref_sys_tkill)(int pid, int sig) = NULL;
long (*ref_sys_time)(time_t __user *tloc) = NULL;
long (*ref_sys_futex)(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3) = NULL;
long (*ref_sys_sched_setaffinity)(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr) = NULL;
long (*ref_sys_sched_getaffinity)(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_io_setup)(unsigned nr_reqs, aio_context_t __user *ctx) = NULL;
long (*ref_sys_io_destroy)(aio_context_t ctx) = NULL;
long (*ref_sys_io_getevents)(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout) = NULL;
long (*ref_sys_io_submit)(aio_context_t, long, struct iocb __user * __user *) = NULL;
long (*ref_sys_io_cancel)(aio_context_t ctx_id, struct iocb __user *iocb,       struct io_event __user *result) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_lookup_dcookie)(u64 cookie64, char __user *buf, size_t len) = NULL;
long (*ref_sys_epoll_create)(int size) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_remap_file_pages)(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags) = NULL;
long (*ref_sys_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) = NULL;
long (*ref_sys_set_tid_address)(int __user *tidptr) = NULL;
long (*ref_sys_restart_syscall)(void) = NULL;
long (*ref_sys_semtimedop)(int semid, struct sembuf __user *sops, unsigned nsops, const struct timespec __user *timeout) = NULL;
long (*ref_sys_fadvise64)(int fd, loff_t offset, size_t len, int advice) = NULL;
long (*ref_sys_timer_create)(clockid_t which_clock,  struct sigevent __user *timer_event_spec,  timer_t __user * created_timer_id) = NULL;
long (*ref_sys_timer_settime)(timer_t timer_id, int flags, const struct itimerspec __user *new_setting, struct itimerspec __user *old_setting) = NULL;
long (*ref_sys_timer_gettime)(timer_t timer_id, struct itimerspec __user *setting) = NULL;
long (*ref_sys_timer_getoverrun)(timer_t timer_id) = NULL;
long (*ref_sys_timer_delete)(timer_t timer_id) = NULL;
long (*ref_sys_clock_settime)(clockid_t which_clock, const struct timespec __user *tp) = NULL;
long (*ref_sys_clock_gettime)(clockid_t which_clock, struct timespec __user *tp) = NULL;
long (*ref_sys_clock_getres)(clockid_t which_clock, struct timespec __user *tp) = NULL;
long (*ref_sys_clock_nanosleep)(clockid_t which_clock, int flags, const struct timespec __user *rqtp, struct timespec __user *rmtp) = NULL;
long (*ref_sys_exit_group)(int error_code) = NULL;
long (*ref_sys_epoll_wait)(int epfd, struct epoll_event __user *events, int maxevents, int timeout) = NULL;
long (*ref_sys_epoll_ctl)(int epfd, int op, int fd, struct epoll_event __user *event) = NULL;
long (*ref_sys_tgkill)(int tgid, int pid, int sig) = NULL;
long (*ref_sys_utimes)(char __user *filename, struct timeval __user *utimes) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_mbind)(unsigned long start, unsigned long len, unsigned long mode, unsigned long __user *nmask, unsigned long maxnode, unsigned flags) = NULL;
long (*ref_sys_set_mempolicy)(int mode, unsigned long __user *nmask, unsigned long maxnode) = NULL;
long (*ref_sys_get_mempolicy)(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags) = NULL;
long (*ref_sys_mq_open)(const char __user *name, int oflag, mode_t mode, struct mq_attr __user *attr) = NULL;
long (*ref_sys_mq_unlink)(const char __user *name) = NULL;
long (*ref_sys_mq_timedsend)(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout) = NULL;
long (*ref_sys_mq_timedreceive)(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout) = NULL;
long (*ref_sys_mq_notify)(mqd_t mqdes, const struct sigevent __user *notification) = NULL;
long (*ref_sys_mq_getsetattr)(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat) = NULL;
long (*ref_sys_kexec_load)(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags) = NULL;
long (*ref_sys_waitid)(int which, pid_t pid,    struct siginfo __user *infop,    int options, struct rusage __user *ru) = NULL;
long (*ref_sys_add_key)(const char __user *_type,     const char __user *_description,     const void __user *_payload,     size_t plen,     key_serial_t destringid) = NULL;
long (*ref_sys_request_key)(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid) = NULL;
long (*ref_sys_keyctl)(int cmd, unsigned long arg2, unsigned long arg3,    unsigned long arg4, unsigned long arg5) = NULL;
long (*ref_sys_ioprio_set)(int which, int who, int ioprio) = NULL;
long (*ref_sys_ioprio_get)(int which, int who) = NULL;
long (*ref_sys_inotify_init)(void) = NULL;
long (*ref_sys_inotify_add_watch)(int fd, const char __user *path, u32 mask) = NULL;
long (*ref_sys_inotify_rm_watch)(int fd, __s32 wd) = NULL;
long (*ref_sys_migrate_pages)(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to) = NULL;
long (*ref_sys_openat)(int dfd, const char __user *filename, int flags,    int mode) = NULL;
long (*ref_sys_mkdirat)(int dfd, const char __user * pathname, int mode) = NULL;
long (*ref_sys_mknodat)(int dfd, const char __user * filename, int mode,     unsigned dev) = NULL;
long (*ref_sys_fchownat)(int dfd, const char __user *filename, uid_t user,      gid_t group, int flag) = NULL;
long (*ref_sys_futimesat)(int dfd, char __user *filename,       struct timeval __user *utimes) = NULL;
long (*ref_sys_newfstatat)(int dfd, char __user *filename,        struct stat __user *statbuf, int flag) = NULL;
long (*ref_sys_unlinkat)(int dfd, const char __user * pathname, int flag) = NULL;
long (*ref_sys_renameat)(int olddfd, const char __user * oldname,      int newdfd, const char __user * newname) = NULL;
long (*ref_sys_linkat)(int olddfd, const char __user *oldname,    int newdfd, const char __user *newname, int flags) = NULL;
long (*ref_sys_symlinkat)(const char __user * oldname,       int newdfd, const char __user * newname) = NULL;
long (*ref_sys_readlinkat)(int dfd, const char __user *path, char __user *buf,        int bufsiz) = NULL;
long (*ref_sys_fchmodat)(int dfd, const char __user * filename,      mode_t mode) = NULL;
long (*ref_sys_faccessat)(int dfd, const char __user *filename, int mode) = NULL;
long (*ref_sys_pselect6)(int, fd_set __user *, fd_set __user *,      fd_set __user *, struct timespec __user *,      void __user *) = NULL;
long (*ref_sys_ppoll)(struct pollfd __user *, unsigned int,   struct timespec __user *, const sigset_t __user *,   size_t) = NULL;
long (*ref_sys_unshare)(unsigned long unshare_flags) = NULL;
long (*ref_sys_set_robust_list)(struct robust_list_head __user *head,     size_t len) = NULL;
long (*ref_sys_get_robust_list)(int pid,     struct robust_list_head __user * __user *head_ptr,     size_t __user *len_ptr) = NULL;
long (*ref_sys_splice)(int fd_in, loff_t __user *off_in,    int fd_out, loff_t __user *off_out,    size_t len, unsigned int flags) = NULL;
long (*ref_sys_tee)(int fdin, int fdout, size_t len, unsigned int flags) = NULL;
long (*ref_sys_sync_file_range)(int fd, loff_t offset, loff_t nbytes, unsigned int flags) = NULL;
long (*ref_sys_vmsplice)(int fd, const struct iovec __user *iov,      unsigned long nr_segs, unsigned int flags) = NULL;
long (*ref_sys_move_pages)(pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags) = NULL;
long (*ref_sys_utimensat)(int dfd, char __user *filename, struct timespec __user *utimes, int flags) = NULL;
long (*ref_sys_epoll_pwait)(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize) = NULL;
long (*ref_sys_signalfd)(int ufd, sigset_t __user *user_mask, size_t sizemask) = NULL;
long (*ref_sys_timerfd_create)(int clockid, int flags) = NULL;
long (*ref_sys_eventfd)(unsigned int count) = NULL;
long (*ref_sys_fallocate)(int fd, int mode, loff_t offset, loff_t len) = NULL;
long (*ref_sys_timerfd_settime)(int ufd, int flags,     const struct itimerspec __user *utmr,     struct itimerspec __user *otmr) = NULL;
long (*ref_sys_timerfd_gettime)(int ufd, struct itimerspec __user *otmr) = NULL;
long (*ref_sys_accept4)(int, struct sockaddr __user *, int __user *, int) = NULL;
long (*ref_sys_signalfd4)(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags) = NULL;
long (*ref_sys_eventfd2)(unsigned int count, int flags) = NULL;
long (*ref_sys_epoll_create1)(int flags) = NULL;
long (*ref_sys_dup3)(unsigned int oldfd, unsigned int newfd, int flags) = NULL;
long (*ref_sys_pipe2)(int __user *fildes, int flags) = NULL;
long (*ref_sys_inotify_init1)(int flags) = NULL;
long (*ref_sys_preadv)(unsigned long fd, const struct iovec __user *vec,    unsigned long vlen, unsigned long pos_l, unsigned long pos_h) = NULL;
long (*ref_sys_pwritev)(unsigned long fd, const struct iovec __user *vec,     unsigned long vlen, unsigned long pos_l, unsigned long pos_h) = NULL;
long (*ref_sys_rt_tgsigqueueinfo)(pid_t tgid, pid_t  pid, int sig, siginfo_t __user *uinfo) = NULL;
long (*ref_sys_perf_event_open)( struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags) = NULL;
long (*ref_sys_recvmmsg)(int fd, struct mmsghdr __user *msg,      unsigned int vlen, unsigned flags,      struct timespec __user *timeout) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_clock_adjtime)(clockid_t which_clock, struct timex __user *tx) = NULL;
long (*ref_sys_syncfs)(int fd) = NULL;
long (*ref_sys_sendmmsg)(int fd, struct mmsghdr __user *msg,      unsigned int vlen, unsigned flags) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_ni_syscall)(void) = NULL;
long (*ref_sys_process_vm_readv)(pid_t pid,      const struct iovec __user *lvec,      unsigned long liovcnt,      const struct iovec __user *rvec,      unsigned long riovcnt,      unsigned long flags) = NULL;
long (*ref_sys_process_vm_writev)(pid_t pid,       const struct iovec __user *lvec,       unsigned long liovcnt,       const struct iovec __user *rvec,       unsigned long riovcnt,       unsigned long flags) = NULL;

long hook_sys_read(unsigned int fd, char __user *buf, size_t count)
{
	long retval = ref_sys_read(fd,buf,count);
	return retval;
}

long hook_sys_write(unsigned int fd, const char __user *buf,   size_t count)
{
	long retval = ref_sys_write(fd,buf,count);
	return retval;
}

long hook_sys_open(const char __user *filename, int flags, int mode)
{
	long retval = ref_sys_open(filename,flags,mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 1;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
		printk(KERN_INFO "[kmaldetect] %p\n", memval);
	}
	return retval;
}

long hook_sys_close(unsigned int fd)
{
	long retval = ref_sys_close(fd);
	return retval;
}

long hook_sys_newstat(char __user *filename, struct stat __user *statbuf)
{
	long retval = ref_sys_newstat(filename,statbuf);
	return retval;
}

long hook_sys_newfstat(unsigned int fd, struct stat __user *statbuf)
{
	long retval = ref_sys_newfstat(fd,statbuf);
	return retval;
}

long hook_sys_newlstat(char __user *filename, struct stat __user *statbuf)
{
	long retval = ref_sys_newlstat(filename,statbuf);
	return retval;
}

long hook_sys_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout)
{
	long retval = ref_sys_poll(ufds,nfds,timeout);
	return retval;
}

long hook_sys_lseek(unsigned int fd, off_t offset,   unsigned int origin)
{
	long retval = ref_sys_lseek(fd,offset,origin);
	return retval;
}

long hook_sys_mmap(unsigned long arg0, unsigned long arg1, unsigned long arg2,  unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	long retval = ref_sys_mmap(arg0,arg1,arg2,arg3,arg4,arg5);
	return retval;
}

long hook_sys_mprotect(unsigned long start, size_t len, unsigned long prot)
{
	long retval = ref_sys_mprotect(start,len,prot);
	return retval;
}

long hook_sys_munmap(unsigned long addr, size_t len)
{
	long retval = ref_sys_munmap(addr,len);
	return retval;
}

long hook_sys_brk(unsigned long brk)
{
	long retval = ref_sys_brk(brk);
	return retval;
}

long hook_sys_rt_sigaction(int sig, const struct sigaction __user *act,  struct sigaction __user *oact, size_t sigsetsize)
{
	long retval = ref_sys_rt_sigaction(sig,act,oact,sigsetsize);
	return retval;
}

long hook_sys_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
	long retval = ref_sys_rt_sigprocmask(how,set,oset,sigsetsize);
	return retval;
}

long hook_sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	long retval = ref_sys_ioctl(fd,cmd,arg);
	return retval;
}

long hook_sys_pread64(unsigned int fd, char __user *buf,     size_t count, loff_t pos)
{
	long retval = ref_sys_pread64(fd,buf,count,pos);
	return retval;
}

long hook_sys_pwrite64(unsigned int fd, const char __user *buf,      size_t count, loff_t pos)
{
	long retval = ref_sys_pwrite64(fd,buf,count,pos);
	return retval;
}

long hook_sys_readv(unsigned long fd,   const struct iovec __user *vec,   unsigned long vlen)
{
	long retval = ref_sys_readv(fd,vec,vlen);
	return retval;
}

long hook_sys_writev(unsigned long fd,    const struct iovec __user *vec,    unsigned long vlen)
{
	long retval = ref_sys_writev(fd,vec,vlen);
	return retval;
}

long hook_sys_access(const char __user *filename, int mode)
{
	long retval = ref_sys_access(filename,mode);
	return retval;
}

long hook_sys_pipe(int __user *fildes)
{
	long retval = ref_sys_pipe(fildes);
	return retval;
}

long hook_sys_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
{
	long retval = ref_sys_select(n,inp,outp,exp,tvp);
	return retval;
}

long hook_sys_sched_yield(void)
{
	long retval = ref_sys_sched_yield();
	return retval;
}

long hook_sys_mremap(unsigned long addr,    unsigned long old_len, unsigned long new_len,    unsigned long flags, unsigned long new_addr)
{
	long retval = ref_sys_mremap(addr,old_len,new_len,flags,new_addr);
	return retval;
}

long hook_sys_msync(unsigned long start, size_t len, int flags)
{
	long retval = ref_sys_msync(start,len,flags);
	return retval;
}

long hook_sys_mincore(unsigned long start, size_t len, unsigned char __user * vec)
{
	long retval = ref_sys_mincore(start,len,vec);
	return retval;
}

long hook_sys_madvise(unsigned long start, size_t len, int behavior)
{
	long retval = ref_sys_madvise(start,len,behavior);
	return retval;
}

long hook_sys_shmget(key_t key, size_t size, int flag)
{
	long retval = ref_sys_shmget(key,size,flag);
	return retval;
}

long hook_sys_shmat(int shmid, char __user *shmaddr, int shmflg)
{
	long retval = ref_sys_shmat(shmid,shmaddr,shmflg);
	return retval;
}

long hook_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
	long retval = ref_sys_shmctl(shmid,cmd,buf);
	return retval;
}

long hook_sys_dup(unsigned int fildes)
{
	long retval = ref_sys_dup(fildes);
	return retval;
}

long hook_sys_dup2(unsigned int oldfd, unsigned int newfd)
{
	long retval = ref_sys_dup2(oldfd,newfd);
	return retval;
}

long hook_sys_pause(void)
{
	long retval = ref_sys_pause();
	return retval;
}

long hook_sys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp)
{
	long retval = ref_sys_nanosleep(rqtp,rmtp);
	return retval;
}

long hook_sys_getitimer(int which, struct itimerval __user *value)
{
	long retval = ref_sys_getitimer(which,value);
	return retval;
}

long hook_sys_alarm(unsigned int seconds)
{
	long retval = ref_sys_alarm(seconds);
	return retval;
}

long hook_sys_setitimer(int which, struct itimerval __user *value, struct itimerval __user *ovalue)
{
	long retval = ref_sys_setitimer(which,value,ovalue);
	return retval;
}

long hook_sys_getpid(void)
{
	long retval = ref_sys_getpid();
	return retval;
}

long hook_sys_sendfile64(int out_fd, int in_fd,        loff_t __user *offset, size_t count)
{
	long retval = ref_sys_sendfile64(out_fd,in_fd,offset,count);
	return retval;
}

long hook_sys_socket(int arg0, int arg1, int arg2)
{
	long retval = ref_sys_socket(arg0,arg1,arg2);
	return retval;
}

long hook_sys_connect(int arg0, struct sockaddr __user *arg1, int arg2)
{
	long retval = ref_sys_connect(arg0,arg1,arg2);
	return retval;
}

long hook_sys_accept(int arg0, struct sockaddr __user *arg1, int __user *arg2)
{
	long retval = ref_sys_accept(arg0,arg1,arg2);
	return retval;
}

long hook_sys_sendto(int arg0, void __user *arg1, size_t arg2, unsigned arg3, struct sockaddr __user *arg4, int arg5)
{
	long retval = ref_sys_sendto(arg0,arg1,arg2,arg3,arg4,arg5);
	return retval;
}

long hook_sys_recvfrom(int arg0, void __user *arg1, size_t arg2, unsigned arg3, struct sockaddr __user *arg4, int __user *arg5)
{
	long retval = ref_sys_recvfrom(arg0,arg1,arg2,arg3,arg4,arg5);
	return retval;
}

long hook_sys_sendmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	long retval = ref_sys_sendmsg(fd,msg,flags);
	return retval;
}

long hook_sys_recvmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	long retval = ref_sys_recvmsg(fd,msg,flags);
	return retval;
}

long hook_sys_shutdown(int arg0, int arg1)
{
	long retval = ref_sys_shutdown(arg0,arg1);
	return retval;
}

long hook_sys_bind(int arg0, struct sockaddr __user *arg1, int arg2)
{
	long retval = ref_sys_bind(arg0,arg1,arg2);
	return retval;
}

long hook_sys_listen(int arg0, int arg1)
{
	long retval = ref_sys_listen(arg0,arg1);
	return retval;
}

long hook_sys_getsockname(int arg0, struct sockaddr __user *arg1, int __user *arg2)
{
	long retval = ref_sys_getsockname(arg0,arg1,arg2);
	return retval;
}

long hook_sys_getpeername(int arg0, struct sockaddr __user *arg1, int __user *arg2)
{
	long retval = ref_sys_getpeername(arg0,arg1,arg2);
	return retval;
}

long hook_sys_socketpair(int arg0, int arg1, int arg2, int __user *arg3)
{
	long retval = ref_sys_socketpair(arg0,arg1,arg2,arg3);
	return retval;
}

long hook_sys_setsockopt(int fd, int level, int optname, char __user *optval, int optlen)
{
	long retval = ref_sys_setsockopt(fd,level,optname,optval,optlen);
	return retval;
}

long hook_sys_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
	long retval = ref_sys_getsockopt(fd,level,optname,optval,optlen);
	return retval;
}

long hook_sys_exit(int error_code)
{
	long retval = ref_sys_exit(error_code);
	return retval;
}

long hook_sys_wait4(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru)
{
	long retval = ref_sys_wait4(pid,stat_addr,options,ru);
	return retval;
}

long hook_sys_kill(int pid, int sig)
{
	long retval = ref_sys_kill(pid,sig);
	return retval;
}

long hook_sys_uname(struct new_utsname __user *arg0)
{
	long retval = ref_sys_uname(arg0);
	return retval;
}

long hook_sys_semget(key_t key, int nsems, int semflg)
{
	long retval = ref_sys_semget(key,nsems,semflg);
	return retval;
}

long hook_sys_semop(int semid, struct sembuf __user *sops, unsigned nsops)
{
	long retval = ref_sys_semop(semid,sops,nsops);
	return retval;
}

long hook_sys_semctl(int semid, int semnum, int cmd, union semun arg)
{
	long retval = ref_sys_semctl(semid,semnum,cmd,arg);
	return retval;
}

long hook_sys_shmdt(char __user *shmaddr)
{
	long retval = ref_sys_shmdt(shmaddr);
	return retval;
}

long hook_sys_msgget(key_t key, int msgflg)
{
	long retval = ref_sys_msgget(key,msgflg);
	return retval;
}

long hook_sys_msgsnd(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg)
{
	long retval = ref_sys_msgsnd(msqid,msgp,msgsz,msgflg);
	return retval;
}

long hook_sys_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg)
{
	long retval = ref_sys_msgrcv(msqid,msgp,msgsz,msgtyp,msgflg);
	return retval;
}

long hook_sys_msgctl(int msqid, int cmd, struct msqid_ds __user *buf)
{
	long retval = ref_sys_msgctl(msqid,cmd,buf);
	return retval;
}

long hook_sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	long retval = ref_sys_fcntl(fd,cmd,arg);
	return retval;
}

long hook_sys_flock(unsigned int fd, unsigned int cmd)
{
	long retval = ref_sys_flock(fd,cmd);
	return retval;
}

long hook_sys_fsync(unsigned int fd)
{
	long retval = ref_sys_fsync(fd);
	return retval;
}

long hook_sys_fdatasync(unsigned int fd)
{
	long retval = ref_sys_fdatasync(fd);
	return retval;
}

long hook_sys_truncate(const char __user *path, long length)
{
	long retval = ref_sys_truncate(path,length);
	return retval;
}

long hook_sys_ftruncate(unsigned int fd, unsigned long length)
{
	long retval = ref_sys_ftruncate(fd,length);
	return retval;
}

long hook_sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
	long retval = ref_sys_getdents(fd,dirent,count);
	return retval;
}

long hook_sys_getcwd(char __user *buf, unsigned long size)
{
	long retval = ref_sys_getcwd(buf,size);
	return retval;
}

long hook_sys_chdir(const char __user *filename)
{
	long retval = ref_sys_chdir(filename);
	return retval;
}

long hook_sys_fchdir(unsigned int fd)
{
	long retval = ref_sys_fchdir(fd);
	return retval;
}

long hook_sys_rename(const char __user *oldname, const char __user *newname)
{
	long retval = ref_sys_rename(oldname,newname);
	return retval;
}

long hook_sys_mkdir(const char __user *pathname, int mode)
{
	long retval = ref_sys_mkdir(pathname,mode);
	return retval;
}

long hook_sys_rmdir(const char __user *pathname)
{
	long retval = ref_sys_rmdir(pathname);
	return retval;
}

long hook_sys_creat(const char __user *pathname, int mode)
{
	long retval = ref_sys_creat(pathname,mode);
	return retval;
}

long hook_sys_link(const char __user *oldname, const char __user *newname)
{
	long retval = ref_sys_link(oldname,newname);
	return retval;
}

long hook_sys_unlink(const char __user *pathname)
{
	long retval = ref_sys_unlink(pathname);
	return retval;
}

long hook_sys_symlink(const char __user *old, const char __user *new)
{
	long retval = ref_sys_symlink(old,new);
	return retval;
}

long hook_sys_readlink(const char __user *path, char __user *buf, int bufsiz)
{
	long retval = ref_sys_readlink(path,buf,bufsiz);
	return retval;
}

long hook_sys_chmod(const char __user *filename, mode_t mode)
{
	long retval = ref_sys_chmod(filename,mode);
	return retval;
}

long hook_sys_fchmod(unsigned int fd, mode_t mode)
{
	long retval = ref_sys_fchmod(fd,mode);
	return retval;
}

long hook_sys_chown(const char __user *filename, uid_t user, gid_t group)
{
	long retval = ref_sys_chown(filename,user,group);
	return retval;
}

long hook_sys_fchown(unsigned int fd, uid_t user, gid_t group)
{
	long retval = ref_sys_fchown(fd,user,group);
	return retval;
}

long hook_sys_lchown(const char __user *filename, uid_t user, gid_t group)
{
	long retval = ref_sys_lchown(filename,user,group);
	return retval;
}

long hook_sys_umask(int mask)
{
	long retval = ref_sys_umask(mask);
	return retval;
}

long hook_sys_gettimeofday(struct timeval __user *tv, struct timezone __user *tz)
{
	long retval = ref_sys_gettimeofday(tv,tz);
	return retval;
}

long hook_sys_getrlimit(unsigned int resource, struct rlimit __user *rlim)
{
	long retval = ref_sys_getrlimit(resource,rlim);
	return retval;
}

long hook_sys_getrusage(int who, struct rusage __user *ru)
{
	long retval = ref_sys_getrusage(who,ru);
	return retval;
}

long hook_sys_sysinfo(struct sysinfo __user *info)
{
	long retval = ref_sys_sysinfo(info);
	return retval;
}

long hook_sys_times(struct tms __user *tbuf)
{
	long retval = ref_sys_times(tbuf);
	return retval;
}

long hook_sys_ptrace(long request, long pid, long addr, long data)
{
	long retval = ref_sys_ptrace(request,pid,addr,data);
	return retval;
}

long hook_sys_getuid(void)
{
	long retval = ref_sys_getuid();
	return retval;
}

long hook_sys_syslog(int type, char __user *buf, int len)
{
	long retval = ref_sys_syslog(type,buf,len);
	return retval;
}

long hook_sys_getgid(void)
{
	long retval = ref_sys_getgid();
	return retval;
}

long hook_sys_setuid(uid_t uid)
{
	long retval = ref_sys_setuid(uid);
	return retval;
}

long hook_sys_setgid(gid_t gid)
{
	long retval = ref_sys_setgid(gid);
	return retval;
}

long hook_sys_geteuid(void)
{
	long retval = ref_sys_geteuid();
	return retval;
}

long hook_sys_getegid(void)
{
	long retval = ref_sys_getegid();
	return retval;
}

long hook_sys_setpgid(pid_t pid, pid_t pgid)
{
	long retval = ref_sys_setpgid(pid,pgid);
	return retval;
}

long hook_sys_getppid(void)
{
	long retval = ref_sys_getppid();
	return retval;
}

long hook_sys_getpgrp(void)
{
	long retval = ref_sys_getpgrp();
	return retval;
}

long hook_sys_setsid(void)
{
	long retval = ref_sys_setsid();
	return retval;
}

long hook_sys_setreuid(uid_t ruid, uid_t euid)
{
	long retval = ref_sys_setreuid(ruid,euid);
	return retval;
}

long hook_sys_setregid(gid_t rgid, gid_t egid)
{
	long retval = ref_sys_setregid(rgid,egid);
	return retval;
}

long hook_sys_getgroups(int gidsetsize, gid_t __user *grouplist)
{
	long retval = ref_sys_getgroups(gidsetsize,grouplist);
	return retval;
}

long hook_sys_setgroups(int gidsetsize, gid_t __user *grouplist)
{
	long retval = ref_sys_setgroups(gidsetsize,grouplist);
	return retval;
}

long hook_sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	long retval = ref_sys_setresuid(ruid,euid,suid);
	return retval;
}

long hook_sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid)
{
	long retval = ref_sys_getresuid(ruid,euid,suid);
	return retval;
}

long hook_sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	long retval = ref_sys_setresgid(rgid,egid,sgid);
	return retval;
}

long hook_sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid)
{
	long retval = ref_sys_getresgid(rgid,egid,sgid);
	return retval;
}

long hook_sys_getpgid(pid_t pid)
{
	long retval = ref_sys_getpgid(pid);
	return retval;
}

long hook_sys_setfsuid(uid_t uid)
{
	long retval = ref_sys_setfsuid(uid);
	return retval;
}

long hook_sys_setfsgid(gid_t gid)
{
	long retval = ref_sys_setfsgid(gid);
	return retval;
}

long hook_sys_getsid(pid_t pid)
{
	long retval = ref_sys_getsid(pid);
	return retval;
}

long hook_sys_capget(cap_user_header_t header, cap_user_data_t dataptr)
{
	long retval = ref_sys_capget(header,dataptr);
	return retval;
}

long hook_sys_capset(cap_user_header_t header, const cap_user_data_t data)
{
	long retval = ref_sys_capset(header,data);
	return retval;
}

long hook_sys_rt_sigpending(sigset_t __user *set, size_t sigsetsize)
{
	long retval = ref_sys_rt_sigpending(set,sigsetsize);
	return retval;
}

long hook_sys_rt_sigtimedwait(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize)
{
	long retval = ref_sys_rt_sigtimedwait(uthese,uinfo,uts,sigsetsize);
	return retval;
}

long hook_sys_rt_sigqueueinfo(int pid, int sig, siginfo_t __user *uinfo)
{
	long retval = ref_sys_rt_sigqueueinfo(pid,sig,uinfo);
	return retval;
}

long hook_sys_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize)
{
	long retval = ref_sys_rt_sigsuspend(unewset,sigsetsize);
	return retval;
}

long hook_sys_utime(char __user *filename, struct utimbuf __user *times)
{
	long retval = ref_sys_utime(filename,times);
	return retval;
}

long hook_sys_mknod(const char __user *filename, int mode, unsigned dev)
{
	long retval = ref_sys_mknod(filename,mode,dev);
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_personality(unsigned int personality)
{
	long retval = ref_sys_personality(personality);
	return retval;
}

long hook_sys_ustat(unsigned dev, struct ustat __user *ubuf)
{
	long retval = ref_sys_ustat(dev,ubuf);
	return retval;
}

long hook_sys_statfs(const char __user * path, struct statfs __user *buf)
{
	long retval = ref_sys_statfs(path,buf);
	return retval;
}

long hook_sys_fstatfs(unsigned int fd, struct statfs __user *buf)
{
	long retval = ref_sys_fstatfs(fd,buf);
	return retval;
}

long hook_sys_sysfs(int option, unsigned long arg1, unsigned long arg2)
{
	long retval = ref_sys_sysfs(option,arg1,arg2);
	return retval;
}

long hook_sys_getpriority(int which, int who)
{
	long retval = ref_sys_getpriority(which,who);
	return retval;
}

long hook_sys_setpriority(int which, int who, int niceval)
{
	long retval = ref_sys_setpriority(which,who,niceval);
	return retval;
}

long hook_sys_sched_setparam(pid_t pid, struct sched_param __user *param)
{
	long retval = ref_sys_sched_setparam(pid,param);
	return retval;
}

long hook_sys_sched_getparam(pid_t pid, struct sched_param __user *param)
{
	long retval = ref_sys_sched_getparam(pid,param);
	return retval;
}

long hook_sys_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param)
{
	long retval = ref_sys_sched_setscheduler(pid,policy,param);
	return retval;
}

long hook_sys_sched_getscheduler(pid_t pid)
{
	long retval = ref_sys_sched_getscheduler(pid);
	return retval;
}

long hook_sys_sched_get_priority_max(int policy)
{
	long retval = ref_sys_sched_get_priority_max(policy);
	return retval;
}

long hook_sys_sched_get_priority_min(int policy)
{
	long retval = ref_sys_sched_get_priority_min(policy);
	return retval;
}

long hook_sys_sched_rr_get_interval(pid_t pid, struct timespec __user *interval)
{
	long retval = ref_sys_sched_rr_get_interval(pid,interval);
	return retval;
}

long hook_sys_mlock(unsigned long start, size_t len)
{
	long retval = ref_sys_mlock(start,len);
	return retval;
}

long hook_sys_munlock(unsigned long start, size_t len)
{
	long retval = ref_sys_munlock(start,len);
	return retval;
}

long hook_sys_mlockall(int flags)
{
	long retval = ref_sys_mlockall(flags);
	return retval;
}

long hook_sys_munlockall(void)
{
	long retval = ref_sys_munlockall();
	return retval;
}

long hook_sys_vhangup(void)
{
	long retval = ref_sys_vhangup();
	return retval;
}

int hook_sys_modify_ldt(int arg0, void __user *arg1, unsigned long arg2)
{
	int retval = ref_sys_modify_ldt(arg0,arg1,arg2);
	return retval;
}

long hook_sys_pivot_root(const char __user *new_root, const char __user *put_old)
{
	long retval = ref_sys_pivot_root(new_root,put_old);
	return retval;
}

long hook_sys_sysctl(struct __sysctl_args __user *args)
{
	long retval = ref_sys_sysctl(args);
	return retval;
}

long hook_sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	long retval = ref_sys_prctl(option,arg2,arg3,arg4,arg5);
	return retval;
}

long hook_sys_arch_prctl(int arg0, unsigned long arg1)
{
	long retval = ref_sys_arch_prctl(arg0,arg1);
	return retval;
}

long hook_sys_adjtimex(struct timex __user *txc_p)
{
	long retval = ref_sys_adjtimex(txc_p);
	return retval;
}

long hook_sys_setrlimit(unsigned int resource, struct rlimit __user *rlim)
{
	long retval = ref_sys_setrlimit(resource,rlim);
	return retval;
}

long hook_sys_chroot(const char __user *filename)
{
	long retval = ref_sys_chroot(filename);
	return retval;
}

long hook_sys_sync(void)
{
	long retval = ref_sys_sync();
	return retval;
}

long hook_sys_acct(const char __user *name)
{
	long retval = ref_sys_acct(name);
	return retval;
}

long hook_sys_settimeofday(struct timeval __user *tv, struct timezone __user *tz)
{
	long retval = ref_sys_settimeofday(tv,tz);
	return retval;
}

long hook_sys_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data)
{
	long retval = ref_sys_mount(dev_name,dir_name,type,flags,data);
	return retval;
}

long hook_sys_umount(char __user *name, int flags)
{
	long retval = ref_sys_umount(name,flags);
	return retval;
}

long hook_sys_swapon(const char __user *specialfile, int swap_flags)
{
	long retval = ref_sys_swapon(specialfile,swap_flags);
	return retval;
}

long hook_sys_swapoff(const char __user *specialfile)
{
	long retval = ref_sys_swapoff(specialfile);
	return retval;
}

long hook_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	long retval = ref_sys_reboot(magic1,magic2,cmd,arg);
	return retval;
}

long hook_sys_sethostname(char __user *name, int len)
{
	long retval = ref_sys_sethostname(name,len);
	return retval;
}

long hook_sys_setdomainname(char __user *name, int len)
{
	long retval = ref_sys_setdomainname(name,len);
	return retval;
}

long hook_sys_ioperm(unsigned long arg0, unsigned long arg1, int arg2)
{
	long retval = ref_sys_ioperm(arg0,arg1,arg2);
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_init_module(void __user *umod, unsigned long len, const char __user *uargs)
{
	long retval = ref_sys_init_module(umod,len,uargs);
	return retval;
}

long hook_sys_delete_module(const char __user *name_user, unsigned int flags)
{
	long retval = ref_sys_delete_module(name_user,flags);
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr)
{
	long retval = ref_sys_quotactl(cmd,special,id,addr);
	return retval;
}

long hook_sys_nfsservctl(int cmd, struct nfsctl_arg __user *arg, void __user *res)
{
	long retval = ref_sys_nfsservctl(cmd,arg,res);
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_gettid(void)
{
	long retval = ref_sys_gettid();
	return retval;
}

long hook_sys_readahead(int fd, loff_t offset, size_t count)
{
	long retval = ref_sys_readahead(fd,offset,count);
	return retval;
}

long hook_sys_setxattr(const char __user *path, const char __user *name,      const void __user *value, size_t size, int flags)
{
	long retval = ref_sys_setxattr(path,name,value,size,flags);
	return retval;
}

long hook_sys_lsetxattr(const char __user *path, const char __user *name,       const void __user *value, size_t size, int flags)
{
	long retval = ref_sys_lsetxattr(path,name,value,size,flags);
	return retval;
}

long hook_sys_fsetxattr(int fd, const char __user *name,       const void __user *value, size_t size, int flags)
{
	long retval = ref_sys_fsetxattr(fd,name,value,size,flags);
	return retval;
}

long hook_sys_getxattr(const char __user *path, const char __user *name,      void __user *value, size_t size)
{
	long retval = ref_sys_getxattr(path,name,value,size);
	return retval;
}

long hook_sys_lgetxattr(const char __user *path, const char __user *name,       void __user *value, size_t size)
{
	long retval = ref_sys_lgetxattr(path,name,value,size);
	return retval;
}

long hook_sys_fgetxattr(int fd, const char __user *name,       void __user *value, size_t size)
{
	long retval = ref_sys_fgetxattr(fd,name,value,size);
	return retval;
}

long hook_sys_listxattr(const char __user *path, char __user *list,       size_t size)
{
	long retval = ref_sys_listxattr(path,list,size);
	return retval;
}

long hook_sys_llistxattr(const char __user *path, char __user *list,        size_t size)
{
	long retval = ref_sys_llistxattr(path,list,size);
	return retval;
}

long hook_sys_flistxattr(int fd, char __user *list, size_t size)
{
	long retval = ref_sys_flistxattr(fd,list,size);
	return retval;
}

long hook_sys_removexattr(const char __user *path, const char __user *name)
{
	long retval = ref_sys_removexattr(path,name);
	return retval;
}

long hook_sys_lremovexattr(const char __user *path,  const char __user *name)
{
	long retval = ref_sys_lremovexattr(path,name);
	return retval;
}

long hook_sys_fremovexattr(int fd, const char __user *name)
{
	long retval = ref_sys_fremovexattr(fd,name);
	return retval;
}

long hook_sys_tkill(int pid, int sig)
{
	long retval = ref_sys_tkill(pid,sig);
	return retval;
}

long hook_sys_time(time_t __user *tloc)
{
	long retval = ref_sys_time(tloc);
	return retval;
}

long hook_sys_futex(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
	long retval = ref_sys_futex(uaddr,op,val,utime,uaddr2,val3);
	return retval;
}

long hook_sys_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	long retval = ref_sys_sched_setaffinity(pid,len,user_mask_ptr);
	return retval;
}

long hook_sys_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	long retval = ref_sys_sched_getaffinity(pid,len,user_mask_ptr);
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_io_setup(unsigned nr_reqs, aio_context_t __user *ctx)
{
	long retval = ref_sys_io_setup(nr_reqs,ctx);
	return retval;
}

long hook_sys_io_destroy(aio_context_t ctx)
{
	long retval = ref_sys_io_destroy(ctx);
	return retval;
}

long hook_sys_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout)
{
	long retval = ref_sys_io_getevents(ctx_id,min_nr,nr,events,timeout);
	return retval;
}

long hook_sys_io_submit(aio_context_t arg0, long arg1, struct iocb __user * __user *arg2)
{
	long retval = ref_sys_io_submit(arg0,arg1,arg2);
	return retval;
}

long hook_sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,       struct io_event __user *result)
{
	long retval = ref_sys_io_cancel(ctx_id,iocb,result);
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_lookup_dcookie(u64 cookie64, char __user *buf, size_t len)
{
	long retval = ref_sys_lookup_dcookie(cookie64,buf,len);
	return retval;
}

long hook_sys_epoll_create(int size)
{
	long retval = ref_sys_epoll_create(size);
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)
{
	long retval = ref_sys_remap_file_pages(start,size,prot,pgoff,flags);
	return retval;
}

long hook_sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
	long retval = ref_sys_getdents64(fd,dirent,count);
	return retval;
}

long hook_sys_set_tid_address(int __user *tidptr)
{
	long retval = ref_sys_set_tid_address(tidptr);
	return retval;
}

long hook_sys_restart_syscall(void)
{
	long retval = ref_sys_restart_syscall();
	return retval;
}

long hook_sys_semtimedop(int semid, struct sembuf __user *sops, unsigned nsops, const struct timespec __user *timeout)
{
	long retval = ref_sys_semtimedop(semid,sops,nsops,timeout);
	return retval;
}

long hook_sys_fadvise64(int fd, loff_t offset, size_t len, int advice)
{
	long retval = ref_sys_fadvise64(fd,offset,len,advice);
	return retval;
}

long hook_sys_timer_create(clockid_t which_clock,  struct sigevent __user *timer_event_spec,  timer_t __user * created_timer_id)
{
	long retval = ref_sys_timer_create(which_clock,timer_event_spec,created_timer_id);
	return retval;
}

long hook_sys_timer_settime(timer_t timer_id, int flags, const struct itimerspec __user *new_setting, struct itimerspec __user *old_setting)
{
	long retval = ref_sys_timer_settime(timer_id,flags,new_setting,old_setting);
	return retval;
}

long hook_sys_timer_gettime(timer_t timer_id, struct itimerspec __user *setting)
{
	long retval = ref_sys_timer_gettime(timer_id,setting);
	return retval;
}

long hook_sys_timer_getoverrun(timer_t timer_id)
{
	long retval = ref_sys_timer_getoverrun(timer_id);
	return retval;
}

long hook_sys_timer_delete(timer_t timer_id)
{
	long retval = ref_sys_timer_delete(timer_id);
	return retval;
}

long hook_sys_clock_settime(clockid_t which_clock, const struct timespec __user *tp)
{
	long retval = ref_sys_clock_settime(which_clock,tp);
	return retval;
}

long hook_sys_clock_gettime(clockid_t which_clock, struct timespec __user *tp)
{
	long retval = ref_sys_clock_gettime(which_clock,tp);
	return retval;
}

long hook_sys_clock_getres(clockid_t which_clock, struct timespec __user *tp)
{
	long retval = ref_sys_clock_getres(which_clock,tp);
	return retval;
}

long hook_sys_clock_nanosleep(clockid_t which_clock, int flags, const struct timespec __user *rqtp, struct timespec __user *rmtp)
{
	long retval = ref_sys_clock_nanosleep(which_clock,flags,rqtp,rmtp);
	return retval;
}

long hook_sys_exit_group(int error_code)
{
	long retval = ref_sys_exit_group(error_code);
	return retval;
}

long hook_sys_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout)
{
	long retval = ref_sys_epoll_wait(epfd,events,maxevents,timeout);
	return retval;
}

long hook_sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event)
{
	long retval = ref_sys_epoll_ctl(epfd,op,fd,event);
	return retval;
}

long hook_sys_tgkill(int tgid, int pid, int sig)
{
	long retval = ref_sys_tgkill(tgid,pid,sig);
	return retval;
}

long hook_sys_utimes(char __user *filename, struct timeval __user *utimes)
{
	long retval = ref_sys_utimes(filename,utimes);
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_mbind(unsigned long start, unsigned long len, unsigned long mode, unsigned long __user *nmask, unsigned long maxnode, unsigned flags)
{
	long retval = ref_sys_mbind(start,len,mode,nmask,maxnode,flags);
	return retval;
}

long hook_sys_set_mempolicy(int mode, unsigned long __user *nmask, unsigned long maxnode)
{
	long retval = ref_sys_set_mempolicy(mode,nmask,maxnode);
	return retval;
}

long hook_sys_get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags)
{
	long retval = ref_sys_get_mempolicy(policy,nmask,maxnode,addr,flags);
	return retval;
}

long hook_sys_mq_open(const char __user *name, int oflag, mode_t mode, struct mq_attr __user *attr)
{
	long retval = ref_sys_mq_open(name,oflag,mode,attr);
	return retval;
}

long hook_sys_mq_unlink(const char __user *name)
{
	long retval = ref_sys_mq_unlink(name);
	return retval;
}

long hook_sys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout)
{
	long retval = ref_sys_mq_timedsend(mqdes,msg_ptr,msg_len,msg_prio,abs_timeout);
	return retval;
}

long hook_sys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout)
{
	long retval = ref_sys_mq_timedreceive(mqdes,msg_ptr,msg_len,msg_prio,abs_timeout);
	return retval;
}

long hook_sys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification)
{
	long retval = ref_sys_mq_notify(mqdes,notification);
	return retval;
}

long hook_sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat)
{
	long retval = ref_sys_mq_getsetattr(mqdes,mqstat,omqstat);
	return retval;
}

long hook_sys_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags)
{
	long retval = ref_sys_kexec_load(entry,nr_segments,segments,flags);
	return retval;
}

long hook_sys_waitid(int which, pid_t pid,    struct siginfo __user *infop,    int options, struct rusage __user *ru)
{
	long retval = ref_sys_waitid(which,pid,infop,options,ru);
	return retval;
}

long hook_sys_add_key(const char __user *_type,     const char __user *_description,     const void __user *_payload,     size_t plen,     key_serial_t destringid)
{
	long retval = ref_sys_add_key(_type,_description,_payload,plen,destringid);
	return retval;
}

long hook_sys_request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid)
{
	long retval = ref_sys_request_key(_type,_description,_callout_info,destringid);
	return retval;
}

long hook_sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3,    unsigned long arg4, unsigned long arg5)
{
	long retval = ref_sys_keyctl(cmd,arg2,arg3,arg4,arg5);
	return retval;
}

long hook_sys_ioprio_set(int which, int who, int ioprio)
{
	long retval = ref_sys_ioprio_set(which,who,ioprio);
	return retval;
}

long hook_sys_ioprio_get(int which, int who)
{
	long retval = ref_sys_ioprio_get(which,who);
	return retval;
}

long hook_sys_inotify_init(void)
{
	long retval = ref_sys_inotify_init();
	return retval;
}

long hook_sys_inotify_add_watch(int fd, const char __user *path, u32 mask)
{
	long retval = ref_sys_inotify_add_watch(fd,path,mask);
	return retval;
}

long hook_sys_inotify_rm_watch(int fd, __s32 wd)
{
	long retval = ref_sys_inotify_rm_watch(fd,wd);
	return retval;
}

long hook_sys_migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to)
{
	long retval = ref_sys_migrate_pages(pid,maxnode,from,to);
	return retval;
}

long hook_sys_openat(int dfd, const char __user *filename, int flags,    int mode)
{
	long retval = ref_sys_openat(dfd,filename,flags,mode);
	return retval;
}

long hook_sys_mkdirat(int dfd, const char __user * pathname, int mode)
{
	long retval = ref_sys_mkdirat(dfd,pathname,mode);
	return retval;
}

long hook_sys_mknodat(int dfd, const char __user * filename, int mode,     unsigned dev)
{
	long retval = ref_sys_mknodat(dfd,filename,mode,dev);
	return retval;
}

long hook_sys_fchownat(int dfd, const char __user *filename, uid_t user,      gid_t group, int flag)
{
	long retval = ref_sys_fchownat(dfd,filename,user,group,flag);
	return retval;
}

long hook_sys_futimesat(int dfd, char __user *filename,       struct timeval __user *utimes)
{
	long retval = ref_sys_futimesat(dfd,filename,utimes);
	return retval;
}

long hook_sys_newfstatat(int dfd, char __user *filename,        struct stat __user *statbuf, int flag)
{
	long retval = ref_sys_newfstatat(dfd,filename,statbuf,flag);
	return retval;
}

long hook_sys_unlinkat(int dfd, const char __user * pathname, int flag)
{
	long retval = ref_sys_unlinkat(dfd,pathname,flag);
	return retval;
}

long hook_sys_renameat(int olddfd, const char __user * oldname,      int newdfd, const char __user * newname)
{
	long retval = ref_sys_renameat(olddfd,oldname,newdfd,newname);
	return retval;
}

long hook_sys_linkat(int olddfd, const char __user *oldname,    int newdfd, const char __user *newname, int flags)
{
	long retval = ref_sys_linkat(olddfd,oldname,newdfd,newname,flags);
	return retval;
}

long hook_sys_symlinkat(const char __user * oldname,       int newdfd, const char __user * newname)
{
	long retval = ref_sys_symlinkat(oldname,newdfd,newname);
	return retval;
}

long hook_sys_readlinkat(int dfd, const char __user *path, char __user *buf,        int bufsiz)
{
	long retval = ref_sys_readlinkat(dfd,path,buf,bufsiz);
	return retval;
}

long hook_sys_fchmodat(int dfd, const char __user * filename,      mode_t mode)
{
	long retval = ref_sys_fchmodat(dfd,filename,mode);
	return retval;
}

long hook_sys_faccessat(int dfd, const char __user *filename, int mode)
{
	long retval = ref_sys_faccessat(dfd,filename,mode);
	return retval;
}

long hook_sys_pselect6(int arg0, fd_set __user *arg1, fd_set __user *arg2,      fd_set __user *arg3, struct timespec __user *arg4,      void __user *arg5)
{
	long retval = ref_sys_pselect6(arg0,arg1,arg2,arg3,arg4,arg5);
	return retval;
}

long hook_sys_ppoll(struct pollfd __user *arg0, unsigned int arg1,   struct timespec __user *arg2, const sigset_t __user *arg3,   size_t arg4)
{
	long retval = ref_sys_ppoll(arg0,arg1,arg2,arg3,arg4);
	return retval;
}

long hook_sys_unshare(unsigned long unshare_flags)
{
	long retval = ref_sys_unshare(unshare_flags);
	return retval;
}

long hook_sys_set_robust_list(struct robust_list_head __user *head,     size_t len)
{
	long retval = ref_sys_set_robust_list(head,len);
	return retval;
}

long hook_sys_get_robust_list(int pid,     struct robust_list_head __user * __user *head_ptr,     size_t __user *len_ptr)
{
	long retval = ref_sys_get_robust_list(pid,head_ptr,len_ptr);
	return retval;
}

long hook_sys_splice(int fd_in, loff_t __user *off_in,    int fd_out, loff_t __user *off_out,    size_t len, unsigned int flags)
{
	long retval = ref_sys_splice(fd_in,off_in,fd_out,off_out,len,flags);
	return retval;
}

long hook_sys_tee(int fdin, int fdout, size_t len, unsigned int flags)
{
	long retval = ref_sys_tee(fdin,fdout,len,flags);
	return retval;
}

long hook_sys_sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags)
{
	long retval = ref_sys_sync_file_range(fd,offset,nbytes,flags);
	return retval;
}

long hook_sys_vmsplice(int fd, const struct iovec __user *iov,      unsigned long nr_segs, unsigned int flags)
{
	long retval = ref_sys_vmsplice(fd,iov,nr_segs,flags);
	return retval;
}

long hook_sys_move_pages(pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags)
{
	long retval = ref_sys_move_pages(pid,nr_pages,pages,nodes,status,flags);
	return retval;
}

long hook_sys_utimensat(int dfd, char __user *filename, struct timespec __user *utimes, int flags)
{
	long retval = ref_sys_utimensat(dfd,filename,utimes,flags);
	return retval;
}

long hook_sys_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize)
{
	long retval = ref_sys_epoll_pwait(epfd,events,maxevents,timeout,sigmask,sigsetsize);
	return retval;
}

long hook_sys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask)
{
	long retval = ref_sys_signalfd(ufd,user_mask,sizemask);
	return retval;
}

long hook_sys_timerfd_create(int clockid, int flags)
{
	long retval = ref_sys_timerfd_create(clockid,flags);
	return retval;
}

long hook_sys_eventfd(unsigned int count)
{
	long retval = ref_sys_eventfd(count);
	return retval;
}

long hook_sys_fallocate(int fd, int mode, loff_t offset, loff_t len)
{
	long retval = ref_sys_fallocate(fd,mode,offset,len);
	return retval;
}

long hook_sys_timerfd_settime(int ufd, int flags,     const struct itimerspec __user *utmr,     struct itimerspec __user *otmr)
{
	long retval = ref_sys_timerfd_settime(ufd,flags,utmr,otmr);
	return retval;
}

long hook_sys_timerfd_gettime(int ufd, struct itimerspec __user *otmr)
{
	long retval = ref_sys_timerfd_gettime(ufd,otmr);
	return retval;
}

long hook_sys_accept4(int arg0, struct sockaddr __user *arg1, int __user *arg2, int arg3)
{
	long retval = ref_sys_accept4(arg0,arg1,arg2,arg3);
	return retval;
}

long hook_sys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags)
{
	long retval = ref_sys_signalfd4(ufd,user_mask,sizemask,flags);
	return retval;
}

long hook_sys_eventfd2(unsigned int count, int flags)
{
	long retval = ref_sys_eventfd2(count,flags);
	return retval;
}

long hook_sys_epoll_create1(int flags)
{
	long retval = ref_sys_epoll_create1(flags);
	return retval;
}

long hook_sys_dup3(unsigned int oldfd, unsigned int newfd, int flags)
{
	long retval = ref_sys_dup3(oldfd,newfd,flags);
	return retval;
}

long hook_sys_pipe2(int __user *fildes, int flags)
{
	long retval = ref_sys_pipe2(fildes,flags);
	return retval;
}

long hook_sys_inotify_init1(int flags)
{
	long retval = ref_sys_inotify_init1(flags);
	return retval;
}

long hook_sys_preadv(unsigned long fd, const struct iovec __user *vec,    unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
	long retval = ref_sys_preadv(fd,vec,vlen,pos_l,pos_h);
	return retval;
}

long hook_sys_pwritev(unsigned long fd, const struct iovec __user *vec,     unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
	long retval = ref_sys_pwritev(fd,vec,vlen,pos_l,pos_h);
	return retval;
}

long hook_sys_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig, siginfo_t __user *uinfo)
{
	long retval = ref_sys_rt_tgsigqueueinfo(tgid,pid,sig,uinfo);
	return retval;
}

long hook_sys_perf_event_open( struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	long retval = ref_sys_perf_event_open(attr_uptr,pid,cpu,group_fd,flags);
	return retval;
}

long hook_sys_recvmmsg(int fd, struct mmsghdr __user *msg,      unsigned int vlen, unsigned flags,      struct timespec __user *timeout)
{
	long retval = ref_sys_recvmmsg(fd,msg,vlen,flags,timeout);
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_clock_adjtime(clockid_t which_clock, struct timex __user *tx)
{
	long retval = ref_sys_clock_adjtime(which_clock,tx);
	return retval;
}

long hook_sys_syncfs(int fd)
{
	long retval = ref_sys_syncfs(fd);
	return retval;
}

long hook_sys_sendmmsg(int fd, struct mmsghdr __user *msg,      unsigned int vlen, unsigned flags)
{
	long retval = ref_sys_sendmmsg(fd,msg,vlen,flags);
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	return retval;
}

long hook_sys_process_vm_readv(pid_t pid,      const struct iovec __user *lvec,      unsigned long liovcnt,      const struct iovec __user *rvec,      unsigned long riovcnt,      unsigned long flags)
{
	long retval = ref_sys_process_vm_readv(pid,lvec,liovcnt,rvec,riovcnt,flags);
	return retval;
}

long hook_sys_process_vm_writev(pid_t pid,       const struct iovec __user *lvec,       unsigned long liovcnt,       const struct iovec __user *rvec,       unsigned long riovcnt,       unsigned long flags)
{
	long retval = ref_sys_process_vm_writev(pid,lvec,liovcnt,rvec,riovcnt,flags);
	return retval;
}

/* Store the real function pointer of sys_open to ref_sys_open and insert our own hook_open in its place */
void reg_hooks(unsigned long **syscall_table)
{
	ref_sys_open = (void *)syscall_table[__NR_open];
	syscall_table[__NR_open] = (unsigned long *)hook_sys_open;
}

/* Restore the syscall_table to its original values */
void unreg_hooks(unsigned long **syscall_table)
{
	syscall_table[__NR_open] = (unsigned long *)ref_sys_open;
}