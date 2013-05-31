#include <asm/unistd.h>
#include <linux/syscalls.h>
#include <asm/thread_info.h>
#include "nl_iface.h"
#include "utils.h"
#include "kmaldetect.h"

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
long (*ref_sys_init_module)(void __user *umod, unsigned long len, const char __user *uargs) = NULL;
long (*ref_sys_delete_module)(const char __user *name_user, unsigned int flags) = NULL;
long (*ref_sys_quotactl)(unsigned int cmd, const char __user *special, qid_t id, void __user *addr) = NULL;
long (*ref_sys_nfsservctl)(int cmd, struct nfsctl_arg __user *arg, void __user *res) = NULL;
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
long (*ref_sys_io_setup)(unsigned nr_reqs, aio_context_t __user *ctx) = NULL;
long (*ref_sys_io_destroy)(aio_context_t ctx) = NULL;
long (*ref_sys_io_getevents)(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout) = NULL;
long (*ref_sys_io_submit)(aio_context_t, long, struct iocb __user * __user *) = NULL;
long (*ref_sys_io_cancel)(aio_context_t ctx_id, struct iocb __user *iocb,       struct io_event __user *result) = NULL;
long (*ref_sys_lookup_dcookie)(u64 cookie64, char __user *buf, size_t len) = NULL;
long (*ref_sys_epoll_create)(int size) = NULL;
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
long (*ref_sys_clock_adjtime)(clockid_t which_clock, struct timex __user *tx) = NULL;
long (*ref_sys_syncfs)(int fd) = NULL;
long (*ref_sys_sendmmsg)(int fd, struct mmsghdr __user *msg,      unsigned int vlen, unsigned flags) = NULL;
long (*ref_sys_process_vm_readv)(pid_t pid,      const struct iovec __user *lvec,      unsigned long liovcnt,      const struct iovec __user *rvec,      unsigned long riovcnt,      unsigned long flags) = NULL;
long (*ref_sys_process_vm_writev)(pid_t pid,       const struct iovec __user *lvec,       unsigned long liovcnt,       const struct iovec __user *rvec,       unsigned long riovcnt,       unsigned long flags) = NULL;

long hook_sys_read(unsigned int fd, char __user *buf, size_t count)
{
	long retval = ref_sys_read(fd,buf,count);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 0;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_write(unsigned int fd, const char __user *buf,   size_t count)
{
	long retval = ref_sys_write(fd,buf,count);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 1;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_open(const char __user *filename, int flags, int mode)
{
	long retval = ref_sys_open(filename,flags,mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 2;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_close(unsigned int fd)
{
	long retval = ref_sys_close(fd);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 3;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_newstat(char __user *filename, struct stat __user *statbuf)
{
	long retval = ref_sys_newstat(filename,statbuf);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 4;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_newfstat(unsigned int fd, struct stat __user *statbuf)
{
	long retval = ref_sys_newfstat(fd,statbuf);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 5;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_newlstat(char __user *filename, struct stat __user *statbuf)
{
	long retval = ref_sys_newlstat(filename,statbuf);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 6;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout)
{
	long retval = ref_sys_poll(ufds,nfds,timeout);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 7;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_lseek(unsigned int fd, off_t offset,   unsigned int origin)
{
	long retval = ref_sys_lseek(fd,offset,origin);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 8;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mmap(unsigned long arg0, unsigned long arg1, unsigned long arg2,  unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	long retval = ref_sys_mmap(arg0,arg1,arg2,arg3,arg4,arg5);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 9;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mprotect(unsigned long start, size_t len, unsigned long prot)
{
	long retval = ref_sys_mprotect(start,len,prot);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 10;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_munmap(unsigned long addr, size_t len)
{
	long retval = ref_sys_munmap(addr,len);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 11;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_brk(unsigned long brk)
{
	long retval = ref_sys_brk(brk);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 12;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_rt_sigaction(int sig, const struct sigaction __user *act,  struct sigaction __user *oact, size_t sigsetsize)
{
	long retval = ref_sys_rt_sigaction(sig,act,oact,sigsetsize);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 13;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
	long retval = ref_sys_rt_sigprocmask(how,set,oset,sigsetsize);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 14;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	long retval = ref_sys_ioctl(fd,cmd,arg);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 16;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_pread64(unsigned int fd, char __user *buf,     size_t count, loff_t pos)
{
	long retval = ref_sys_pread64(fd,buf,count,pos);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 17;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_pwrite64(unsigned int fd, const char __user *buf,      size_t count, loff_t pos)
{
	long retval = ref_sys_pwrite64(fd,buf,count,pos);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 18;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_readv(unsigned long fd,   const struct iovec __user *vec,   unsigned long vlen)
{
	long retval = ref_sys_readv(fd,vec,vlen);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 19;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_writev(unsigned long fd,    const struct iovec __user *vec,    unsigned long vlen)
{
	long retval = ref_sys_writev(fd,vec,vlen);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 20;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_access(const char __user *filename, int mode)
{
	long retval = ref_sys_access(filename,mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 21;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_pipe(int __user *fildes)
{
	long retval = ref_sys_pipe(fildes);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 22;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
{
	long retval = ref_sys_select(n,inp,outp,exp,tvp);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 23;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sched_yield(void)
{
	long retval = ref_sys_sched_yield();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 24;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mremap(unsigned long addr,    unsigned long old_len, unsigned long new_len,    unsigned long flags, unsigned long new_addr)
{
	long retval = ref_sys_mremap(addr,old_len,new_len,flags,new_addr);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 25;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_msync(unsigned long start, size_t len, int flags)
{
	long retval = ref_sys_msync(start,len,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 26;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mincore(unsigned long start, size_t len, unsigned char __user * vec)
{
	long retval = ref_sys_mincore(start,len,vec);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 27;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_madvise(unsigned long start, size_t len, int behavior)
{
	long retval = ref_sys_madvise(start,len,behavior);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 28;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_shmget(key_t key, size_t size, int flag)
{
	long retval = ref_sys_shmget(key,size,flag);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 29;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_shmat(int shmid, char __user *shmaddr, int shmflg)
{
	long retval = ref_sys_shmat(shmid,shmaddr,shmflg);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 30;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
	long retval = ref_sys_shmctl(shmid,cmd,buf);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 31;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_dup(unsigned int fildes)
{
	long retval = ref_sys_dup(fildes);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 32;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_dup2(unsigned int oldfd, unsigned int newfd)
{
	long retval = ref_sys_dup2(oldfd,newfd);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 33;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_pause(void)
{
	long retval = ref_sys_pause();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 34;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp)
{
	long retval = ref_sys_nanosleep(rqtp,rmtp);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 35;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getitimer(int which, struct itimerval __user *value)
{
	long retval = ref_sys_getitimer(which,value);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 36;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_alarm(unsigned int seconds)
{
	long retval = ref_sys_alarm(seconds);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 37;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setitimer(int which, struct itimerval __user *value, struct itimerval __user *ovalue)
{
	long retval = ref_sys_setitimer(which,value,ovalue);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 38;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getpid(void)
{
	long retval = ref_sys_getpid();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 39;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sendfile64(int out_fd, int in_fd,        loff_t __user *offset, size_t count)
{
	long retval = ref_sys_sendfile64(out_fd,in_fd,offset,count);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 40;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_socket(int arg0, int arg1, int arg2)
{
	long retval = ref_sys_socket(arg0,arg1,arg2);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 41;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_connect(int arg0, struct sockaddr __user *arg1, int arg2)
{
	long retval = ref_sys_connect(arg0,arg1,arg2);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 42;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_accept(int arg0, struct sockaddr __user *arg1, int __user *arg2)
{
	long retval = ref_sys_accept(arg0,arg1,arg2);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 43;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sendto(int arg0, void __user *arg1, size_t arg2, unsigned arg3, struct sockaddr __user *arg4, int arg5)
{
	long retval = ref_sys_sendto(arg0,arg1,arg2,arg3,arg4,arg5);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 44;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_recvfrom(int arg0, void __user *arg1, size_t arg2, unsigned arg3, struct sockaddr __user *arg4, int __user *arg5)
{
	long retval = ref_sys_recvfrom(arg0,arg1,arg2,arg3,arg4,arg5);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 45;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sendmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	long retval = ref_sys_sendmsg(fd,msg,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 46;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_recvmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	long retval = ref_sys_recvmsg(fd,msg,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 47;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_shutdown(int arg0, int arg1)
{
	long retval = ref_sys_shutdown(arg0,arg1);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 48;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_bind(int arg0, struct sockaddr __user *arg1, int arg2)
{
	long retval = ref_sys_bind(arg0,arg1,arg2);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 49;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_listen(int arg0, int arg1)
{
	long retval = ref_sys_listen(arg0,arg1);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 50;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getsockname(int arg0, struct sockaddr __user *arg1, int __user *arg2)
{
	long retval = ref_sys_getsockname(arg0,arg1,arg2);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 51;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getpeername(int arg0, struct sockaddr __user *arg1, int __user *arg2)
{
	long retval = ref_sys_getpeername(arg0,arg1,arg2);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 52;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_socketpair(int arg0, int arg1, int arg2, int __user *arg3)
{
	long retval = ref_sys_socketpair(arg0,arg1,arg2,arg3);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 53;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setsockopt(int fd, int level, int optname, char __user *optval, int optlen)
{
	long retval = ref_sys_setsockopt(fd,level,optname,optval,optlen);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 54;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
	long retval = ref_sys_getsockopt(fd,level,optname,optval,optlen);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 55;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_exit(int error_code)
{
	long retval = ref_sys_exit(error_code);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 60;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_wait4(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru)
{
	long retval = ref_sys_wait4(pid,stat_addr,options,ru);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 61;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_kill(int pid, int sig)
{
	long retval = ref_sys_kill(pid,sig);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 62;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_uname(struct new_utsname __user *arg0)
{
	long retval = ref_sys_uname(arg0);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 63;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_semget(key_t key, int nsems, int semflg)
{
	long retval = ref_sys_semget(key,nsems,semflg);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 64;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_semop(int semid, struct sembuf __user *sops, unsigned nsops)
{
	long retval = ref_sys_semop(semid,sops,nsops);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 65;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_semctl(int semid, int semnum, int cmd, union semun arg)
{
	long retval = ref_sys_semctl(semid,semnum,cmd,arg);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 66;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_shmdt(char __user *shmaddr)
{
	long retval = ref_sys_shmdt(shmaddr);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 67;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_msgget(key_t key, int msgflg)
{
	long retval = ref_sys_msgget(key,msgflg);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 68;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_msgsnd(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg)
{
	long retval = ref_sys_msgsnd(msqid,msgp,msgsz,msgflg);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 69;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg)
{
	long retval = ref_sys_msgrcv(msqid,msgp,msgsz,msgtyp,msgflg);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 70;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_msgctl(int msqid, int cmd, struct msqid_ds __user *buf)
{
	long retval = ref_sys_msgctl(msqid,cmd,buf);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 71;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	long retval = ref_sys_fcntl(fd,cmd,arg);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 72;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_flock(unsigned int fd, unsigned int cmd)
{
	long retval = ref_sys_flock(fd,cmd);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 73;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fsync(unsigned int fd)
{
	long retval = ref_sys_fsync(fd);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 74;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fdatasync(unsigned int fd)
{
	long retval = ref_sys_fdatasync(fd);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 75;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_truncate(const char __user *path, long length)
{
	long retval = ref_sys_truncate(path,length);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 76;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_ftruncate(unsigned int fd, unsigned long length)
{
	long retval = ref_sys_ftruncate(fd,length);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 77;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
	long retval = ref_sys_getdents(fd,dirent,count);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 78;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getcwd(char __user *buf, unsigned long size)
{
	long retval = ref_sys_getcwd(buf,size);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 79;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_chdir(const char __user *filename)
{
	long retval = ref_sys_chdir(filename);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 80;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fchdir(unsigned int fd)
{
	long retval = ref_sys_fchdir(fd);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 81;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_rename(const char __user *oldname, const char __user *newname)
{
	long retval = ref_sys_rename(oldname,newname);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 82;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mkdir(const char __user *pathname, int mode)
{
	long retval = ref_sys_mkdir(pathname,mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 83;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_rmdir(const char __user *pathname)
{
	long retval = ref_sys_rmdir(pathname);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 84;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_creat(const char __user *pathname, int mode)
{
	long retval = ref_sys_creat(pathname,mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 85;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_link(const char __user *oldname, const char __user *newname)
{
	long retval = ref_sys_link(oldname,newname);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 86;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_unlink(const char __user *pathname)
{
	long retval = ref_sys_unlink(pathname);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 87;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_symlink(const char __user *old, const char __user *new)
{
	long retval = ref_sys_symlink(old,new);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 88;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_readlink(const char __user *path, char __user *buf, int bufsiz)
{
	long retval = ref_sys_readlink(path,buf,bufsiz);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 89;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_chmod(const char __user *filename, mode_t mode)
{
	long retval = ref_sys_chmod(filename,mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 90;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fchmod(unsigned int fd, mode_t mode)
{
	long retval = ref_sys_fchmod(fd,mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 91;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_chown(const char __user *filename, uid_t user, gid_t group)
{
	long retval = ref_sys_chown(filename,user,group);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 92;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fchown(unsigned int fd, uid_t user, gid_t group)
{
	long retval = ref_sys_fchown(fd,user,group);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 93;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_lchown(const char __user *filename, uid_t user, gid_t group)
{
	long retval = ref_sys_lchown(filename,user,group);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 94;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_umask(int mask)
{
	long retval = ref_sys_umask(mask);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 95;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_gettimeofday(struct timeval __user *tv, struct timezone __user *tz)
{
	long retval = ref_sys_gettimeofday(tv,tz);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 96;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getrlimit(unsigned int resource, struct rlimit __user *rlim)
{
	long retval = ref_sys_getrlimit(resource,rlim);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 97;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getrusage(int who, struct rusage __user *ru)
{
	long retval = ref_sys_getrusage(who,ru);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 98;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sysinfo(struct sysinfo __user *info)
{
	long retval = ref_sys_sysinfo(info);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 99;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_times(struct tms __user *tbuf)
{
	long retval = ref_sys_times(tbuf);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 100;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_ptrace(long request, long pid, long addr, long data)
{
	long retval = ref_sys_ptrace(request,pid,addr,data);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 101;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getuid(void)
{
	long retval = ref_sys_getuid();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 102;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_syslog(int type, char __user *buf, int len)
{
	long retval = ref_sys_syslog(type,buf,len);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 103;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getgid(void)
{
	long retval = ref_sys_getgid();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 104;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setuid(uid_t uid)
{
	long retval = ref_sys_setuid(uid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 105;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setgid(gid_t gid)
{
	long retval = ref_sys_setgid(gid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 106;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_geteuid(void)
{
	long retval = ref_sys_geteuid();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 107;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getegid(void)
{
	long retval = ref_sys_getegid();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 108;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setpgid(pid_t pid, pid_t pgid)
{
	long retval = ref_sys_setpgid(pid,pgid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 109;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getppid(void)
{
	long retval = ref_sys_getppid();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 110;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getpgrp(void)
{
	long retval = ref_sys_getpgrp();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 111;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setsid(void)
{
	long retval = ref_sys_setsid();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 112;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setreuid(uid_t ruid, uid_t euid)
{
	long retval = ref_sys_setreuid(ruid,euid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 113;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setregid(gid_t rgid, gid_t egid)
{
	long retval = ref_sys_setregid(rgid,egid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 114;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getgroups(int gidsetsize, gid_t __user *grouplist)
{
	long retval = ref_sys_getgroups(gidsetsize,grouplist);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 115;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setgroups(int gidsetsize, gid_t __user *grouplist)
{
	long retval = ref_sys_setgroups(gidsetsize,grouplist);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 116;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	long retval = ref_sys_setresuid(ruid,euid,suid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 117;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid)
{
	long retval = ref_sys_getresuid(ruid,euid,suid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 118;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	long retval = ref_sys_setresgid(rgid,egid,sgid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 119;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid)
{
	long retval = ref_sys_getresgid(rgid,egid,sgid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 120;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getpgid(pid_t pid)
{
	long retval = ref_sys_getpgid(pid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 121;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setfsuid(uid_t uid)
{
	long retval = ref_sys_setfsuid(uid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 122;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setfsgid(gid_t gid)
{
	long retval = ref_sys_setfsgid(gid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 123;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getsid(pid_t pid)
{
	long retval = ref_sys_getsid(pid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 124;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_capget(cap_user_header_t header, cap_user_data_t dataptr)
{
	long retval = ref_sys_capget(header,dataptr);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 125;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_capset(cap_user_header_t header, const cap_user_data_t data)
{
	long retval = ref_sys_capset(header,data);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 126;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_rt_sigpending(sigset_t __user *set, size_t sigsetsize)
{
	long retval = ref_sys_rt_sigpending(set,sigsetsize);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 127;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_rt_sigtimedwait(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize)
{
	long retval = ref_sys_rt_sigtimedwait(uthese,uinfo,uts,sigsetsize);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 128;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_rt_sigqueueinfo(int pid, int sig, siginfo_t __user *uinfo)
{
	long retval = ref_sys_rt_sigqueueinfo(pid,sig,uinfo);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 129;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize)
{
	long retval = ref_sys_rt_sigsuspend(unewset,sigsetsize);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 130;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_utime(char __user *filename, struct utimbuf __user *times)
{
	long retval = ref_sys_utime(filename,times);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 132;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mknod(const char __user *filename, int mode, unsigned dev)
{
	long retval = ref_sys_mknod(filename,mode,dev);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 133;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = ref_sys_ni_syscall();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 134;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_personality(unsigned int personality)
{
	long retval = ref_sys_personality(personality);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 135;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_ustat(unsigned dev, struct ustat __user *ubuf)
{
	long retval = ref_sys_ustat(dev,ubuf);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 136;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_statfs(const char __user * path, struct statfs __user *buf)
{
	long retval = ref_sys_statfs(path,buf);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 137;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fstatfs(unsigned int fd, struct statfs __user *buf)
{
	long retval = ref_sys_fstatfs(fd,buf);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 138;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sysfs(int option, unsigned long arg1, unsigned long arg2)
{
	long retval = ref_sys_sysfs(option,arg1,arg2);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 139;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getpriority(int which, int who)
{
	long retval = ref_sys_getpriority(which,who);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 140;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setpriority(int which, int who, int niceval)
{
	long retval = ref_sys_setpriority(which,who,niceval);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 141;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sched_setparam(pid_t pid, struct sched_param __user *param)
{
	long retval = ref_sys_sched_setparam(pid,param);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 142;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sched_getparam(pid_t pid, struct sched_param __user *param)
{
	long retval = ref_sys_sched_getparam(pid,param);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 143;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param)
{
	long retval = ref_sys_sched_setscheduler(pid,policy,param);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 144;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sched_getscheduler(pid_t pid)
{
	long retval = ref_sys_sched_getscheduler(pid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 145;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sched_get_priority_max(int policy)
{
	long retval = ref_sys_sched_get_priority_max(policy);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 146;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sched_get_priority_min(int policy)
{
	long retval = ref_sys_sched_get_priority_min(policy);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 147;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sched_rr_get_interval(pid_t pid, struct timespec __user *interval)
{
	long retval = ref_sys_sched_rr_get_interval(pid,interval);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 148;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mlock(unsigned long start, size_t len)
{
	long retval = ref_sys_mlock(start,len);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 149;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_munlock(unsigned long start, size_t len)
{
	long retval = ref_sys_munlock(start,len);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 150;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mlockall(int flags)
{
	long retval = ref_sys_mlockall(flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 151;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_munlockall(void)
{
	long retval = ref_sys_munlockall();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 152;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_vhangup(void)
{
	long retval = ref_sys_vhangup();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 153;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

int hook_sys_modify_ldt(int arg0, void __user *arg1, unsigned long arg2)
{
	int retval = ref_sys_modify_ldt(arg0,arg1,arg2);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 154;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_pivot_root(const char __user *new_root, const char __user *put_old)
{
	long retval = ref_sys_pivot_root(new_root,put_old);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 155;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sysctl(struct __sysctl_args __user *args)
{
	long retval = ref_sys_sysctl(args);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 156;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	long retval = ref_sys_prctl(option,arg2,arg3,arg4,arg5);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 157;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_arch_prctl(int arg0, unsigned long arg1)
{
	long retval = ref_sys_arch_prctl(arg0,arg1);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 158;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_adjtimex(struct timex __user *txc_p)
{
	long retval = ref_sys_adjtimex(txc_p);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 159;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setrlimit(unsigned int resource, struct rlimit __user *rlim)
{
	long retval = ref_sys_setrlimit(resource,rlim);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 160;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_chroot(const char __user *filename)
{
	long retval = ref_sys_chroot(filename);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 161;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sync(void)
{
	long retval = ref_sys_sync();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 162;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_acct(const char __user *name)
{
	long retval = ref_sys_acct(name);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 163;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_settimeofday(struct timeval __user *tv, struct timezone __user *tz)
{
	long retval = ref_sys_settimeofday(tv,tz);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 164;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data)
{
	long retval = ref_sys_mount(dev_name,dir_name,type,flags,data);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 165;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_umount(char __user *name, int flags)
{
	long retval = ref_sys_umount(name,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 166;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_swapon(const char __user *specialfile, int swap_flags)
{
	long retval = ref_sys_swapon(specialfile,swap_flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 167;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_swapoff(const char __user *specialfile)
{
	long retval = ref_sys_swapoff(specialfile);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 168;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	long retval = ref_sys_reboot(magic1,magic2,cmd,arg);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 169;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sethostname(char __user *name, int len)
{
	long retval = ref_sys_sethostname(name,len);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 170;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setdomainname(char __user *name, int len)
{
	long retval = ref_sys_setdomainname(name,len);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 171;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_ioperm(unsigned long arg0, unsigned long arg1, int arg2)
{
	long retval = ref_sys_ioperm(arg0,arg1,arg2);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 173;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_init_module(void __user *umod, unsigned long len, const char __user *uargs)
{
	long retval = ref_sys_init_module(umod,len,uargs);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 175;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_delete_module(const char __user *name_user, unsigned int flags)
{
	long retval = ref_sys_delete_module(name_user,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 176;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr)
{
	long retval = ref_sys_quotactl(cmd,special,id,addr);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 179;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_nfsservctl(int cmd, struct nfsctl_arg __user *arg, void __user *res)
{
	long retval = ref_sys_nfsservctl(cmd,arg,res);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 180;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_gettid(void)
{
	long retval = ref_sys_gettid();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 186;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_readahead(int fd, loff_t offset, size_t count)
{
	long retval = ref_sys_readahead(fd,offset,count);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 187;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_setxattr(const char __user *path, const char __user *name,      const void __user *value, size_t size, int flags)
{
	long retval = ref_sys_setxattr(path,name,value,size,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 188;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_lsetxattr(const char __user *path, const char __user *name,       const void __user *value, size_t size, int flags)
{
	long retval = ref_sys_lsetxattr(path,name,value,size,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 189;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fsetxattr(int fd, const char __user *name,       const void __user *value, size_t size, int flags)
{
	long retval = ref_sys_fsetxattr(fd,name,value,size,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 190;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getxattr(const char __user *path, const char __user *name,      void __user *value, size_t size)
{
	long retval = ref_sys_getxattr(path,name,value,size);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 191;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_lgetxattr(const char __user *path, const char __user *name,       void __user *value, size_t size)
{
	long retval = ref_sys_lgetxattr(path,name,value,size);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 192;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fgetxattr(int fd, const char __user *name,       void __user *value, size_t size)
{
	long retval = ref_sys_fgetxattr(fd,name,value,size);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 193;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_listxattr(const char __user *path, char __user *list,       size_t size)
{
	long retval = ref_sys_listxattr(path,list,size);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 194;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_llistxattr(const char __user *path, char __user *list,        size_t size)
{
	long retval = ref_sys_llistxattr(path,list,size);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 195;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_flistxattr(int fd, char __user *list, size_t size)
{
	long retval = ref_sys_flistxattr(fd,list,size);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 196;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_removexattr(const char __user *path, const char __user *name)
{
	long retval = ref_sys_removexattr(path,name);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 197;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_lremovexattr(const char __user *path,  const char __user *name)
{
	long retval = ref_sys_lremovexattr(path,name);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 198;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fremovexattr(int fd, const char __user *name)
{
	long retval = ref_sys_fremovexattr(fd,name);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 199;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_tkill(int pid, int sig)
{
	long retval = ref_sys_tkill(pid,sig);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 200;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_time(time_t __user *tloc)
{
	long retval = ref_sys_time(tloc);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 100;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_futex(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
	long retval = ref_sys_futex(uaddr,op,val,utime,uaddr2,val3);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 202;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	long retval = ref_sys_sched_setaffinity(pid,len,user_mask_ptr);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 203;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	long retval = ref_sys_sched_getaffinity(pid,len,user_mask_ptr);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 204;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_io_setup(unsigned nr_reqs, aio_context_t __user *ctx)
{
	long retval = ref_sys_io_setup(nr_reqs,ctx);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 206;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_io_destroy(aio_context_t ctx)
{
	long retval = ref_sys_io_destroy(ctx);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 207;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout)
{
	long retval = ref_sys_io_getevents(ctx_id,min_nr,nr,events,timeout);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 208;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_io_submit(aio_context_t arg0, long arg1, struct iocb __user * __user *arg2)
{
	long retval = ref_sys_io_submit(arg0,arg1,arg2);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 209;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,       struct io_event __user *result)
{
	long retval = ref_sys_io_cancel(ctx_id,iocb,result);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 210;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_lookup_dcookie(u64 cookie64, char __user *buf, size_t len)
{
	long retval = ref_sys_lookup_dcookie(cookie64,buf,len);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 212;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_epoll_create(int size)
{
	long retval = ref_sys_epoll_create(size);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 213;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)
{
	long retval = ref_sys_remap_file_pages(start,size,prot,pgoff,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 216;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
	long retval = ref_sys_getdents64(fd,dirent,count);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 217;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_set_tid_address(int __user *tidptr)
{
	long retval = ref_sys_set_tid_address(tidptr);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 218;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_restart_syscall(void)
{
	long retval = ref_sys_restart_syscall();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 219;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_semtimedop(int semid, struct sembuf __user *sops, unsigned nsops, const struct timespec __user *timeout)
{
	long retval = ref_sys_semtimedop(semid,sops,nsops,timeout);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 220;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fadvise64(int fd, loff_t offset, size_t len, int advice)
{
	long retval = ref_sys_fadvise64(fd,offset,len,advice);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 221;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_timer_create(clockid_t which_clock,  struct sigevent __user *timer_event_spec,  timer_t __user * created_timer_id)
{
	long retval = ref_sys_timer_create(which_clock,timer_event_spec,created_timer_id);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 222;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_timer_settime(timer_t timer_id, int flags, const struct itimerspec __user *new_setting, struct itimerspec __user *old_setting)
{
	long retval = ref_sys_timer_settime(timer_id,flags,new_setting,old_setting);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 223;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_timer_gettime(timer_t timer_id, struct itimerspec __user *setting)
{
	long retval = ref_sys_timer_gettime(timer_id,setting);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 224;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_timer_getoverrun(timer_t timer_id)
{
	long retval = ref_sys_timer_getoverrun(timer_id);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 225;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_timer_delete(timer_t timer_id)
{
	long retval = ref_sys_timer_delete(timer_id);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 226;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_clock_settime(clockid_t which_clock, const struct timespec __user *tp)
{
	long retval = ref_sys_clock_settime(which_clock,tp);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 227;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_clock_gettime(clockid_t which_clock, struct timespec __user *tp)
{
	long retval = ref_sys_clock_gettime(which_clock,tp);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 228;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_clock_getres(clockid_t which_clock, struct timespec __user *tp)
{
	long retval = ref_sys_clock_getres(which_clock,tp);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 229;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_clock_nanosleep(clockid_t which_clock, int flags, const struct timespec __user *rqtp, struct timespec __user *rmtp)
{
	long retval = ref_sys_clock_nanosleep(which_clock,flags,rqtp,rmtp);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 230;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_exit_group(int error_code)
{
	long retval = ref_sys_exit_group(error_code);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 231;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout)
{
	long retval = ref_sys_epoll_wait(epfd,events,maxevents,timeout);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 232;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event)
{
	long retval = ref_sys_epoll_ctl(epfd,op,fd,event);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 233;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_tgkill(int tgid, int pid, int sig)
{
	long retval = ref_sys_tgkill(tgid,pid,sig);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 234;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_utimes(char __user *filename, struct timeval __user *utimes)
{
	long retval = ref_sys_utimes(filename,utimes);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 235;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mbind(unsigned long start, unsigned long len, unsigned long mode, unsigned long __user *nmask, unsigned long maxnode, unsigned flags)
{
	long retval = ref_sys_mbind(start,len,mode,nmask,maxnode,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 237;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_set_mempolicy(int mode, unsigned long __user *nmask, unsigned long maxnode)
{
	long retval = ref_sys_set_mempolicy(mode,nmask,maxnode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 238;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags)
{
	long retval = ref_sys_get_mempolicy(policy,nmask,maxnode,addr,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 239;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mq_open(const char __user *name, int oflag, mode_t mode, struct mq_attr __user *attr)
{
	long retval = ref_sys_mq_open(name,oflag,mode,attr);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 240;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mq_unlink(const char __user *name)
{
	long retval = ref_sys_mq_unlink(name);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 241;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout)
{
	long retval = ref_sys_mq_timedsend(mqdes,msg_ptr,msg_len,msg_prio,abs_timeout);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 242;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout)
{
	long retval = ref_sys_mq_timedreceive(mqdes,msg_ptr,msg_len,msg_prio,abs_timeout);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 243;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification)
{
	long retval = ref_sys_mq_notify(mqdes,notification);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 244;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat)
{
	long retval = ref_sys_mq_getsetattr(mqdes,mqstat,omqstat);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 245;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags)
{
	long retval = ref_sys_kexec_load(entry,nr_segments,segments,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 246;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_waitid(int which, pid_t pid,    struct siginfo __user *infop,    int options, struct rusage __user *ru)
{
	long retval = ref_sys_waitid(which,pid,infop,options,ru);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 247;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_add_key(const char __user *_type,     const char __user *_description,     const void __user *_payload,     size_t plen,     key_serial_t destringid)
{
	long retval = ref_sys_add_key(_type,_description,_payload,plen,destringid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 248;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid)
{
	long retval = ref_sys_request_key(_type,_description,_callout_info,destringid);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 249;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3,    unsigned long arg4, unsigned long arg5)
{
	long retval = ref_sys_keyctl(cmd,arg2,arg3,arg4,arg5);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 250;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_ioprio_set(int which, int who, int ioprio)
{
	long retval = ref_sys_ioprio_set(which,who,ioprio);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 251;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_ioprio_get(int which, int who)
{
	long retval = ref_sys_ioprio_get(which,who);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 252;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_inotify_init(void)
{
	long retval = ref_sys_inotify_init();
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 253;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_inotify_add_watch(int fd, const char __user *path, u32 mask)
{
	long retval = ref_sys_inotify_add_watch(fd,path,mask);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 254;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_inotify_rm_watch(int fd, __s32 wd)
{
	long retval = ref_sys_inotify_rm_watch(fd,wd);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 255;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to)
{
	long retval = ref_sys_migrate_pages(pid,maxnode,from,to);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 256;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_openat(int dfd, const char __user *filename, int flags,    int mode)
{
	long retval = ref_sys_openat(dfd,filename,flags,mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 257;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mkdirat(int dfd, const char __user * pathname, int mode)
{
	long retval = ref_sys_mkdirat(dfd,pathname,mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 258;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_mknodat(int dfd, const char __user * filename, int mode,     unsigned dev)
{
	long retval = ref_sys_mknodat(dfd,filename,mode,dev);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 259;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fchownat(int dfd, const char __user *filename, uid_t user,      gid_t group, int flag)
{
	long retval = ref_sys_fchownat(dfd,filename,user,group,flag);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 260;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_futimesat(int dfd, char __user *filename,       struct timeval __user *utimes)
{
	long retval = ref_sys_futimesat(dfd,filename,utimes);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 261;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_newfstatat(int dfd, char __user *filename,        struct stat __user *statbuf, int flag)
{
	long retval = ref_sys_newfstatat(dfd,filename,statbuf,flag);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 262;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_unlinkat(int dfd, const char __user * pathname, int flag)
{
	long retval = ref_sys_unlinkat(dfd,pathname,flag);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 263;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_renameat(int olddfd, const char __user * oldname,      int newdfd, const char __user * newname)
{
	long retval = ref_sys_renameat(olddfd,oldname,newdfd,newname);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 264;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_linkat(int olddfd, const char __user *oldname,    int newdfd, const char __user *newname, int flags)
{
	long retval = ref_sys_linkat(olddfd,oldname,newdfd,newname,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 265;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_symlinkat(const char __user * oldname,       int newdfd, const char __user * newname)
{
	long retval = ref_sys_symlinkat(oldname,newdfd,newname);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 266;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_readlinkat(int dfd, const char __user *path, char __user *buf,        int bufsiz)
{
	long retval = ref_sys_readlinkat(dfd,path,buf,bufsiz);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 267;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fchmodat(int dfd, const char __user * filename,      mode_t mode)
{
	long retval = ref_sys_fchmodat(dfd,filename,mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 268;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_faccessat(int dfd, const char __user *filename, int mode)
{
	long retval = ref_sys_faccessat(dfd,filename,mode);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 269;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_pselect6(int arg0, fd_set __user *arg1, fd_set __user *arg2,      fd_set __user *arg3, struct timespec __user *arg4,      void __user *arg5)
{
	long retval = ref_sys_pselect6(arg0,arg1,arg2,arg3,arg4,arg5);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 270;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_ppoll(struct pollfd __user *arg0, unsigned int arg1,   struct timespec __user *arg2, const sigset_t __user *arg3,   size_t arg4)
{
	long retval = ref_sys_ppoll(arg0,arg1,arg2,arg3,arg4);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 271;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_unshare(unsigned long unshare_flags)
{
	long retval = ref_sys_unshare(unshare_flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 272;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_set_robust_list(struct robust_list_head __user *head,     size_t len)
{
	long retval = ref_sys_set_robust_list(head,len);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 273;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_get_robust_list(int pid,     struct robust_list_head __user * __user *head_ptr,     size_t __user *len_ptr)
{
	long retval = ref_sys_get_robust_list(pid,head_ptr,len_ptr);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 274;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_splice(int fd_in, loff_t __user *off_in,    int fd_out, loff_t __user *off_out,    size_t len, unsigned int flags)
{
	long retval = ref_sys_splice(fd_in,off_in,fd_out,off_out,len,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 275;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_tee(int fdin, int fdout, size_t len, unsigned int flags)
{
	long retval = ref_sys_tee(fdin,fdout,len,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 276;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags)
{
	long retval = ref_sys_sync_file_range(fd,offset,nbytes,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 277;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_vmsplice(int fd, const struct iovec __user *iov,      unsigned long nr_segs, unsigned int flags)
{
	long retval = ref_sys_vmsplice(fd,iov,nr_segs,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 278;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_move_pages(pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags)
{
	long retval = ref_sys_move_pages(pid,nr_pages,pages,nodes,status,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 279;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_utimensat(int dfd, char __user *filename, struct timespec __user *utimes, int flags)
{
	long retval = ref_sys_utimensat(dfd,filename,utimes,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 280;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize)
{
	long retval = ref_sys_epoll_pwait(epfd,events,maxevents,timeout,sigmask,sigsetsize);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 281;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask)
{
	long retval = ref_sys_signalfd(ufd,user_mask,sizemask);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 282;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_timerfd_create(int clockid, int flags)
{
	long retval = ref_sys_timerfd_create(clockid,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 283;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_eventfd(unsigned int count)
{
	long retval = ref_sys_eventfd(count);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 284;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_fallocate(int fd, int mode, loff_t offset, loff_t len)
{
	long retval = ref_sys_fallocate(fd,mode,offset,len);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 285;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_timerfd_settime(int ufd, int flags,     const struct itimerspec __user *utmr,     struct itimerspec __user *otmr)
{
	long retval = ref_sys_timerfd_settime(ufd,flags,utmr,otmr);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 286;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_timerfd_gettime(int ufd, struct itimerspec __user *otmr)
{
	long retval = ref_sys_timerfd_gettime(ufd,otmr);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 287;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_accept4(int arg0, struct sockaddr __user *arg1, int __user *arg2, int arg3)
{
	long retval = ref_sys_accept4(arg0,arg1,arg2,arg3);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 288;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags)
{
	long retval = ref_sys_signalfd4(ufd,user_mask,sizemask,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 289;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_eventfd2(unsigned int count, int flags)
{
	long retval = ref_sys_eventfd2(count,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 290;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_epoll_create1(int flags)
{
	long retval = ref_sys_epoll_create1(flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 291;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_dup3(unsigned int oldfd, unsigned int newfd, int flags)
{
	long retval = ref_sys_dup3(oldfd,newfd,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 292;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_pipe2(int __user *fildes, int flags)
{
	long retval = ref_sys_pipe2(fildes,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 293;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_inotify_init1(int flags)
{
	long retval = ref_sys_inotify_init1(flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 294;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_preadv(unsigned long fd, const struct iovec __user *vec,    unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
	long retval = ref_sys_preadv(fd,vec,vlen,pos_l,pos_h);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 295;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_pwritev(unsigned long fd, const struct iovec __user *vec,     unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
	long retval = ref_sys_pwritev(fd,vec,vlen,pos_l,pos_h);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 296;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig, siginfo_t __user *uinfo)
{
	long retval = ref_sys_rt_tgsigqueueinfo(tgid,pid,sig,uinfo);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 297;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_perf_event_open( struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	long retval = ref_sys_perf_event_open(attr_uptr,pid,cpu,group_fd,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 298;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_recvmmsg(int fd, struct mmsghdr __user *msg,      unsigned int vlen, unsigned flags,      struct timespec __user *timeout)
{
	long retval = ref_sys_recvmmsg(fd,msg,vlen,flags,timeout);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 299;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_clock_adjtime(clockid_t which_clock, struct timex __user *tx)
{
	long retval = ref_sys_clock_adjtime(which_clock,tx);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 305;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_syncfs(int fd)
{
	long retval = ref_sys_syncfs(fd);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 306;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_sendmmsg(int fd, struct mmsghdr __user *msg,      unsigned int vlen, unsigned flags)
{
	long retval = ref_sys_sendmmsg(fd,msg,vlen,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 307;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_process_vm_readv(pid_t pid,      const struct iovec __user *lvec,      unsigned long liovcnt,      const struct iovec __user *rvec,      unsigned long riovcnt,      unsigned long flags)
{
	long retval = ref_sys_process_vm_readv(pid,lvec,liovcnt,rvec,riovcnt,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 310;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

long hook_sys_process_vm_writev(pid_t pid,       const struct iovec __user *lvec,       unsigned long liovcnt,       const struct iovec __user *rvec,       unsigned long riovcnt,       unsigned long flags)
{
	long retval = ref_sys_process_vm_writev(pid,lvec,liovcnt,rvec,riovcnt,flags);
	if (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)
	{
		SYSCALL data;
		data.sys_id = 311;
		data.inode = get_inode();
		data.pid = current->pid;
		data.mem_loc = 0;
		maldetect_nl_send_syscall(&data);
	}
	return retval;
}

void reg_hooks(unsigned long **syscall_table)
{
	ref_sys_read = (void *)syscall_table[__NR_read];
	syscall_table[__NR_read] = (unsigned long *)hook_sys_read;
	ref_sys_write = (void *)syscall_table[__NR_write];
	syscall_table[__NR_write] = (unsigned long *)hook_sys_write;
	ref_sys_open = (void *)syscall_table[__NR_open];
	syscall_table[__NR_open] = (unsigned long *)hook_sys_open;
	/*ref_sys_close = (void *)syscall_table[__NR_close];
	syscall_table[__NR_close] = (unsigned long *)hook_sys_close;
	ref_sys_newstat = (void *)syscall_table[__NR_stat];
	syscall_table[__NR_stat] = (unsigned long *)hook_sys_newstat;
	ref_sys_newfstat = (void *)syscall_table[__NR_fstat];
	syscall_table[__NR_fstat] = (unsigned long *)hook_sys_newfstat;
	ref_sys_newlstat = (void *)syscall_table[__NR_lstat];
	syscall_table[__NR_lstat] = (unsigned long *)hook_sys_newlstat;
	ref_sys_poll = (void *)syscall_table[__NR_poll];
	syscall_table[__NR_poll] = (unsigned long *)hook_sys_poll;
	ref_sys_lseek = (void *)syscall_table[__NR_lseek];
	syscall_table[__NR_lseek] = (unsigned long *)hook_sys_lseek;
	ref_sys_mmap = (void *)syscall_table[__NR_mmap];
	syscall_table[__NR_mmap] = (unsigned long *)hook_sys_mmap;
	ref_sys_mprotect = (void *)syscall_table[__NR_mprotect];
	syscall_table[__NR_mprotect] = (unsigned long *)hook_sys_mprotect;
	ref_sys_munmap = (void *)syscall_table[__NR_munmap];
	syscall_table[__NR_munmap] = (unsigned long *)hook_sys_munmap;
	ref_sys_brk = (void *)syscall_table[__NR_brk];
	syscall_table[__NR_brk] = (unsigned long *)hook_sys_brk;
	ref_sys_rt_sigaction = (void *)syscall_table[__NR_rt_sigaction];
	syscall_table[__NR_rt_sigaction] = (unsigned long *)hook_sys_rt_sigaction;
	ref_sys_rt_sigprocmask = (void *)syscall_table[__NR_rt_sigprocmask];
	syscall_table[__NR_rt_sigprocmask] = (unsigned long *)hook_sys_rt_sigprocmask;
	ref_sys_ioctl = (void *)syscall_table[__NR_ioctl];
	syscall_table[__NR_ioctl] = (unsigned long *)hook_sys_ioctl;
	ref_sys_pread64 = (void *)syscall_table[__NR_pread64];
	syscall_table[__NR_pread64] = (unsigned long *)hook_sys_pread64;
	ref_sys_pwrite64 = (void *)syscall_table[__NR_pwrite64];
	syscall_table[__NR_pwrite64] = (unsigned long *)hook_sys_pwrite64;
	ref_sys_readv = (void *)syscall_table[__NR_readv];
	syscall_table[__NR_readv] = (unsigned long *)hook_sys_readv;
	ref_sys_writev = (void *)syscall_table[__NR_writev];
	syscall_table[__NR_writev] = (unsigned long *)hook_sys_writev;
	ref_sys_access = (void *)syscall_table[__NR_access];
	syscall_table[__NR_access] = (unsigned long *)hook_sys_access;
	ref_sys_pipe = (void *)syscall_table[__NR_pipe];
	syscall_table[__NR_pipe] = (unsigned long *)hook_sys_pipe;
	ref_sys_select = (void *)syscall_table[__NR_select];
	syscall_table[__NR_select] = (unsigned long *)hook_sys_select;
	ref_sys_sched_yield = (void *)syscall_table[__NR_sched_yield];
	syscall_table[__NR_sched_yield] = (unsigned long *)hook_sys_sched_yield;
	ref_sys_mremap = (void *)syscall_table[__NR_mremap];
	syscall_table[__NR_mremap] = (unsigned long *)hook_sys_mremap;
	ref_sys_msync = (void *)syscall_table[__NR_msync];
	syscall_table[__NR_msync] = (unsigned long *)hook_sys_msync;
	ref_sys_mincore = (void *)syscall_table[__NR_mincore];
	syscall_table[__NR_mincore] = (unsigned long *)hook_sys_mincore;
	ref_sys_madvise = (void *)syscall_table[__NR_madvise];
	syscall_table[__NR_madvise] = (unsigned long *)hook_sys_madvise;
	ref_sys_shmget = (void *)syscall_table[__NR_shmget];
	syscall_table[__NR_shmget] = (unsigned long *)hook_sys_shmget;
	ref_sys_shmat = (void *)syscall_table[__NR_shmat];
	syscall_table[__NR_shmat] = (unsigned long *)hook_sys_shmat;
	ref_sys_shmctl = (void *)syscall_table[__NR_shmctl];
	syscall_table[__NR_shmctl] = (unsigned long *)hook_sys_shmctl;
	ref_sys_dup = (void *)syscall_table[__NR_dup];
	syscall_table[__NR_dup] = (unsigned long *)hook_sys_dup;
	ref_sys_dup2 = (void *)syscall_table[__NR_dup2];
	syscall_table[__NR_dup2] = (unsigned long *)hook_sys_dup2;
	ref_sys_pause = (void *)syscall_table[__NR_pause];
	syscall_table[__NR_pause] = (unsigned long *)hook_sys_pause;
	ref_sys_nanosleep = (void *)syscall_table[__NR_nanosleep];
	syscall_table[__NR_nanosleep] = (unsigned long *)hook_sys_nanosleep;
	ref_sys_getitimer = (void *)syscall_table[__NR_getitimer];
	syscall_table[__NR_getitimer] = (unsigned long *)hook_sys_getitimer;
	ref_sys_alarm = (void *)syscall_table[__NR_alarm];
	syscall_table[__NR_alarm] = (unsigned long *)hook_sys_alarm;
	ref_sys_setitimer = (void *)syscall_table[__NR_setitimer];
	syscall_table[__NR_setitimer] = (unsigned long *)hook_sys_setitimer;
	ref_sys_getpid = (void *)syscall_table[__NR_getpid];
	syscall_table[__NR_getpid] = (unsigned long *)hook_sys_getpid;
	ref_sys_sendfile64 = (void *)syscall_table[__NR_sendfile];
	syscall_table[__NR_sendfile] = (unsigned long *)hook_sys_sendfile64;
	ref_sys_socket = (void *)syscall_table[__NR_socket];
	syscall_table[__NR_socket] = (unsigned long *)hook_sys_socket;
	ref_sys_connect = (void *)syscall_table[__NR_connect];
	syscall_table[__NR_connect] = (unsigned long *)hook_sys_connect;
	ref_sys_accept = (void *)syscall_table[__NR_accept];
	syscall_table[__NR_accept] = (unsigned long *)hook_sys_accept;
	ref_sys_sendto = (void *)syscall_table[__NR_sendto];
	syscall_table[__NR_sendto] = (unsigned long *)hook_sys_sendto;
	ref_sys_recvfrom = (void *)syscall_table[__NR_recvfrom];
	syscall_table[__NR_recvfrom] = (unsigned long *)hook_sys_recvfrom;
	ref_sys_sendmsg = (void *)syscall_table[__NR_sendmsg];
	syscall_table[__NR_sendmsg] = (unsigned long *)hook_sys_sendmsg;
	ref_sys_recvmsg = (void *)syscall_table[__NR_recvmsg];
	syscall_table[__NR_recvmsg] = (unsigned long *)hook_sys_recvmsg;
	ref_sys_shutdown = (void *)syscall_table[__NR_shutdown];
	syscall_table[__NR_shutdown] = (unsigned long *)hook_sys_shutdown;
	ref_sys_bind = (void *)syscall_table[__NR_bind];
	syscall_table[__NR_bind] = (unsigned long *)hook_sys_bind;
	ref_sys_listen = (void *)syscall_table[__NR_listen];
	syscall_table[__NR_listen] = (unsigned long *)hook_sys_listen;
	ref_sys_getsockname = (void *)syscall_table[__NR_getsockname];
	syscall_table[__NR_getsockname] = (unsigned long *)hook_sys_getsockname;
	ref_sys_getpeername = (void *)syscall_table[__NR_getpeername];
	syscall_table[__NR_getpeername] = (unsigned long *)hook_sys_getpeername;
	ref_sys_socketpair = (void *)syscall_table[__NR_socketpair];
	syscall_table[__NR_socketpair] = (unsigned long *)hook_sys_socketpair;
	ref_sys_setsockopt = (void *)syscall_table[__NR_setsockopt];
	syscall_table[__NR_setsockopt] = (unsigned long *)hook_sys_setsockopt;
	ref_sys_getsockopt = (void *)syscall_table[__NR_getsockopt];
	syscall_table[__NR_getsockopt] = (unsigned long *)hook_sys_getsockopt;
	ref_sys_exit = (void *)syscall_table[__NR_exit];
	syscall_table[__NR_exit] = (unsigned long *)hook_sys_exit;
	ref_sys_wait4 = (void *)syscall_table[__NR_wait4];
	syscall_table[__NR_wait4] = (unsigned long *)hook_sys_wait4;
	ref_sys_kill = (void *)syscall_table[__NR_kill];
	syscall_table[__NR_kill] = (unsigned long *)hook_sys_kill;
	ref_sys_uname = (void *)syscall_table[__NR_uname];
	syscall_table[__NR_uname] = (unsigned long *)hook_sys_uname;
	ref_sys_semget = (void *)syscall_table[__NR_semget];
	syscall_table[__NR_semget] = (unsigned long *)hook_sys_semget;
	ref_sys_semop = (void *)syscall_table[__NR_semop];
	syscall_table[__NR_semop] = (unsigned long *)hook_sys_semop;
	ref_sys_semctl = (void *)syscall_table[__NR_semctl];
	syscall_table[__NR_semctl] = (unsigned long *)hook_sys_semctl;
	ref_sys_shmdt = (void *)syscall_table[__NR_shmdt];
	syscall_table[__NR_shmdt] = (unsigned long *)hook_sys_shmdt;
	ref_sys_msgget = (void *)syscall_table[__NR_msgget];
	syscall_table[__NR_msgget] = (unsigned long *)hook_sys_msgget;
	ref_sys_msgsnd = (void *)syscall_table[__NR_msgsnd];
	syscall_table[__NR_msgsnd] = (unsigned long *)hook_sys_msgsnd;
	ref_sys_msgrcv = (void *)syscall_table[__NR_msgrcv];
	syscall_table[__NR_msgrcv] = (unsigned long *)hook_sys_msgrcv;
	ref_sys_msgctl = (void *)syscall_table[__NR_msgctl];
	syscall_table[__NR_msgctl] = (unsigned long *)hook_sys_msgctl;
	ref_sys_fcntl = (void *)syscall_table[__NR_fcntl];
	syscall_table[__NR_fcntl] = (unsigned long *)hook_sys_fcntl;
	ref_sys_flock = (void *)syscall_table[__NR_flock];
	syscall_table[__NR_flock] = (unsigned long *)hook_sys_flock;
	ref_sys_fsync = (void *)syscall_table[__NR_fsync];
	syscall_table[__NR_fsync] = (unsigned long *)hook_sys_fsync;
	ref_sys_fdatasync = (void *)syscall_table[__NR_fdatasync];
	syscall_table[__NR_fdatasync] = (unsigned long *)hook_sys_fdatasync;
	ref_sys_truncate = (void *)syscall_table[__NR_truncate];
	syscall_table[__NR_truncate] = (unsigned long *)hook_sys_truncate;
	ref_sys_ftruncate = (void *)syscall_table[__NR_ftruncate];
	syscall_table[__NR_ftruncate] = (unsigned long *)hook_sys_ftruncate;
	ref_sys_getdents = (void *)syscall_table[__NR_getdents];
	syscall_table[__NR_getdents] = (unsigned long *)hook_sys_getdents;
	ref_sys_getcwd = (void *)syscall_table[__NR_getcwd];
	syscall_table[__NR_getcwd] = (unsigned long *)hook_sys_getcwd;
	ref_sys_chdir = (void *)syscall_table[__NR_chdir];
	syscall_table[__NR_chdir] = (unsigned long *)hook_sys_chdir;
	ref_sys_fchdir = (void *)syscall_table[__NR_fchdir];
	syscall_table[__NR_fchdir] = (unsigned long *)hook_sys_fchdir;
	ref_sys_rename = (void *)syscall_table[__NR_rename];
	syscall_table[__NR_rename] = (unsigned long *)hook_sys_rename;
	ref_sys_mkdir = (void *)syscall_table[__NR_mkdir];
	syscall_table[__NR_mkdir] = (unsigned long *)hook_sys_mkdir;
	ref_sys_rmdir = (void *)syscall_table[__NR_rmdir];
	syscall_table[__NR_rmdir] = (unsigned long *)hook_sys_rmdir;
	ref_sys_creat = (void *)syscall_table[__NR_creat];
	syscall_table[__NR_creat] = (unsigned long *)hook_sys_creat;
	ref_sys_link = (void *)syscall_table[__NR_link];
	syscall_table[__NR_link] = (unsigned long *)hook_sys_link;
	ref_sys_unlink = (void *)syscall_table[__NR_unlink];
	syscall_table[__NR_unlink] = (unsigned long *)hook_sys_unlink;
	ref_sys_symlink = (void *)syscall_table[__NR_symlink];
	syscall_table[__NR_symlink] = (unsigned long *)hook_sys_symlink;
	ref_sys_readlink = (void *)syscall_table[__NR_readlink];
	syscall_table[__NR_readlink] = (unsigned long *)hook_sys_readlink;
	ref_sys_chmod = (void *)syscall_table[__NR_chmod];
	syscall_table[__NR_chmod] = (unsigned long *)hook_sys_chmod;
	ref_sys_fchmod = (void *)syscall_table[__NR_fchmod];
	syscall_table[__NR_fchmod] = (unsigned long *)hook_sys_fchmod;
	ref_sys_chown = (void *)syscall_table[__NR_chown];
	syscall_table[__NR_chown] = (unsigned long *)hook_sys_chown;
	ref_sys_fchown = (void *)syscall_table[__NR_fchown];
	syscall_table[__NR_fchown] = (unsigned long *)hook_sys_fchown;
	ref_sys_lchown = (void *)syscall_table[__NR_lchown];
	syscall_table[__NR_lchown] = (unsigned long *)hook_sys_lchown;
	ref_sys_umask = (void *)syscall_table[__NR_umask];
	syscall_table[__NR_umask] = (unsigned long *)hook_sys_umask;
	ref_sys_gettimeofday = (void *)syscall_table[__NR_gettimeofday];
	syscall_table[__NR_gettimeofday] = (unsigned long *)hook_sys_gettimeofday;
	ref_sys_getrlimit = (void *)syscall_table[__NR_getrlimit];
	syscall_table[__NR_getrlimit] = (unsigned long *)hook_sys_getrlimit;
	ref_sys_getrusage = (void *)syscall_table[__NR_getrusage];
	syscall_table[__NR_getrusage] = (unsigned long *)hook_sys_getrusage;
	ref_sys_sysinfo = (void *)syscall_table[__NR_sysinfo];
	syscall_table[__NR_sysinfo] = (unsigned long *)hook_sys_sysinfo;
	ref_sys_times = (void *)syscall_table[__NR_times];
	syscall_table[__NR_times] = (unsigned long *)hook_sys_times;
	ref_sys_ptrace = (void *)syscall_table[__NR_ptrace];
	syscall_table[__NR_ptrace] = (unsigned long *)hook_sys_ptrace;
	ref_sys_getuid = (void *)syscall_table[__NR_getuid];
	syscall_table[__NR_getuid] = (unsigned long *)hook_sys_getuid;
	ref_sys_syslog = (void *)syscall_table[__NR_syslog];
	syscall_table[__NR_syslog] = (unsigned long *)hook_sys_syslog;
	ref_sys_getgid = (void *)syscall_table[__NR_getgid];
	syscall_table[__NR_getgid] = (unsigned long *)hook_sys_getgid;
	ref_sys_setuid = (void *)syscall_table[__NR_setuid];
	syscall_table[__NR_setuid] = (unsigned long *)hook_sys_setuid;
	ref_sys_setgid = (void *)syscall_table[__NR_setgid];
	syscall_table[__NR_setgid] = (unsigned long *)hook_sys_setgid;
	ref_sys_geteuid = (void *)syscall_table[__NR_geteuid];
	syscall_table[__NR_geteuid] = (unsigned long *)hook_sys_geteuid;
	ref_sys_getegid = (void *)syscall_table[__NR_getegid];
	syscall_table[__NR_getegid] = (unsigned long *)hook_sys_getegid;
	ref_sys_setpgid = (void *)syscall_table[__NR_setpgid];
	syscall_table[__NR_setpgid] = (unsigned long *)hook_sys_setpgid;
	ref_sys_getppid = (void *)syscall_table[__NR_getppid];
	syscall_table[__NR_getppid] = (unsigned long *)hook_sys_getppid;
	ref_sys_getpgrp = (void *)syscall_table[__NR_getpgrp];
	syscall_table[__NR_getpgrp] = (unsigned long *)hook_sys_getpgrp;
	ref_sys_setsid = (void *)syscall_table[__NR_setsid];
	syscall_table[__NR_setsid] = (unsigned long *)hook_sys_setsid;
	ref_sys_setreuid = (void *)syscall_table[__NR_setreuid];
	syscall_table[__NR_setreuid] = (unsigned long *)hook_sys_setreuid;
	ref_sys_setregid = (void *)syscall_table[__NR_setregid];
	syscall_table[__NR_setregid] = (unsigned long *)hook_sys_setregid;
	ref_sys_getgroups = (void *)syscall_table[__NR_getgroups];
	syscall_table[__NR_getgroups] = (unsigned long *)hook_sys_getgroups;
	ref_sys_setgroups = (void *)syscall_table[__NR_setgroups];
	syscall_table[__NR_setgroups] = (unsigned long *)hook_sys_setgroups;
	ref_sys_setresuid = (void *)syscall_table[__NR_setresuid];
	syscall_table[__NR_setresuid] = (unsigned long *)hook_sys_setresuid;
	ref_sys_getresuid = (void *)syscall_table[__NR_getresuid];
	syscall_table[__NR_getresuid] = (unsigned long *)hook_sys_getresuid;
	ref_sys_setresgid = (void *)syscall_table[__NR_setresgid];
	syscall_table[__NR_setresgid] = (unsigned long *)hook_sys_setresgid;
	ref_sys_getresgid = (void *)syscall_table[__NR_getresgid];
	syscall_table[__NR_getresgid] = (unsigned long *)hook_sys_getresgid;
	ref_sys_getpgid = (void *)syscall_table[__NR_getpgid];
	syscall_table[__NR_getpgid] = (unsigned long *)hook_sys_getpgid;
	ref_sys_setfsuid = (void *)syscall_table[__NR_setfsuid];
	syscall_table[__NR_setfsuid] = (unsigned long *)hook_sys_setfsuid;
	ref_sys_setfsgid = (void *)syscall_table[__NR_setfsgid];
	syscall_table[__NR_setfsgid] = (unsigned long *)hook_sys_setfsgid;
	ref_sys_getsid = (void *)syscall_table[__NR_getsid];
	syscall_table[__NR_getsid] = (unsigned long *)hook_sys_getsid;
	ref_sys_capget = (void *)syscall_table[__NR_capget];
	syscall_table[__NR_capget] = (unsigned long *)hook_sys_capget;
	ref_sys_capset = (void *)syscall_table[__NR_capset];
	syscall_table[__NR_capset] = (unsigned long *)hook_sys_capset;
	ref_sys_rt_sigpending = (void *)syscall_table[__NR_rt_sigpending];
	syscall_table[__NR_rt_sigpending] = (unsigned long *)hook_sys_rt_sigpending;
	ref_sys_rt_sigtimedwait = (void *)syscall_table[__NR_rt_sigtimedwait];
	syscall_table[__NR_rt_sigtimedwait] = (unsigned long *)hook_sys_rt_sigtimedwait;
	ref_sys_rt_sigqueueinfo = (void *)syscall_table[__NR_rt_sigqueueinfo];
	syscall_table[__NR_rt_sigqueueinfo] = (unsigned long *)hook_sys_rt_sigqueueinfo;
	ref_sys_rt_sigsuspend = (void *)syscall_table[__NR_rt_sigsuspend];
	syscall_table[__NR_rt_sigsuspend] = (unsigned long *)hook_sys_rt_sigsuspend;
	ref_sys_utime = (void *)syscall_table[__NR_utime];
	syscall_table[__NR_utime] = (unsigned long *)hook_sys_utime;
	ref_sys_mknod = (void *)syscall_table[__NR_mknod];
	syscall_table[__NR_mknod] = (unsigned long *)hook_sys_mknod;
	ref_sys_ni_syscall = (void *)syscall_table[__NR_uselib];
	syscall_table[__NR_uselib] = (unsigned long *)hook_sys_ni_syscall;
	ref_sys_personality = (void *)syscall_table[__NR_personality];
	syscall_table[__NR_personality] = (unsigned long *)hook_sys_personality;
	ref_sys_ustat = (void *)syscall_table[__NR_ustat];
	syscall_table[__NR_ustat] = (unsigned long *)hook_sys_ustat;
	ref_sys_statfs = (void *)syscall_table[__NR_statfs];
	syscall_table[__NR_statfs] = (unsigned long *)hook_sys_statfs;
	ref_sys_fstatfs = (void *)syscall_table[__NR_fstatfs];
	syscall_table[__NR_fstatfs] = (unsigned long *)hook_sys_fstatfs;
	ref_sys_sysfs = (void *)syscall_table[__NR_sysfs];
	syscall_table[__NR_sysfs] = (unsigned long *)hook_sys_sysfs;
	ref_sys_getpriority = (void *)syscall_table[__NR_getpriority];
	syscall_table[__NR_getpriority] = (unsigned long *)hook_sys_getpriority;
	ref_sys_setpriority = (void *)syscall_table[__NR_setpriority];
	syscall_table[__NR_setpriority] = (unsigned long *)hook_sys_setpriority;
	ref_sys_sched_setparam = (void *)syscall_table[__NR_sched_setparam];
	syscall_table[__NR_sched_setparam] = (unsigned long *)hook_sys_sched_setparam;
	ref_sys_sched_getparam = (void *)syscall_table[__NR_sched_getparam];
	syscall_table[__NR_sched_getparam] = (unsigned long *)hook_sys_sched_getparam;
	ref_sys_sched_setscheduler = (void *)syscall_table[__NR_sched_setscheduler];
	syscall_table[__NR_sched_setscheduler] = (unsigned long *)hook_sys_sched_setscheduler;
	ref_sys_sched_getscheduler = (void *)syscall_table[__NR_sched_getscheduler];
	syscall_table[__NR_sched_getscheduler] = (unsigned long *)hook_sys_sched_getscheduler;
	ref_sys_sched_get_priority_max = (void *)syscall_table[__NR_sched_get_priority_max];
	syscall_table[__NR_sched_get_priority_max] = (unsigned long *)hook_sys_sched_get_priority_max;
	ref_sys_sched_get_priority_min = (void *)syscall_table[__NR_sched_get_priority_min];
	syscall_table[__NR_sched_get_priority_min] = (unsigned long *)hook_sys_sched_get_priority_min;
	ref_sys_sched_rr_get_interval = (void *)syscall_table[__NR_sched_rr_get_interval];
	syscall_table[__NR_sched_rr_get_interval] = (unsigned long *)hook_sys_sched_rr_get_interval;
	ref_sys_mlock = (void *)syscall_table[__NR_mlock];
	syscall_table[__NR_mlock] = (unsigned long *)hook_sys_mlock;
	ref_sys_munlock = (void *)syscall_table[__NR_munlock];
	syscall_table[__NR_munlock] = (unsigned long *)hook_sys_munlock;
	ref_sys_mlockall = (void *)syscall_table[__NR_mlockall];
	syscall_table[__NR_mlockall] = (unsigned long *)hook_sys_mlockall;
	ref_sys_munlockall = (void *)syscall_table[__NR_munlockall];
	syscall_table[__NR_munlockall] = (unsigned long *)hook_sys_munlockall;
	ref_sys_vhangup = (void *)syscall_table[__NR_vhangup];
	syscall_table[__NR_vhangup] = (unsigned long *)hook_sys_vhangup;
	ref_sys_modify_ldt = (void *)syscall_table[__NR_modify_ldt];
	syscall_table[__NR_modify_ldt] = (unsigned long *)hook_sys_modify_ldt;
	ref_sys_pivot_root = (void *)syscall_table[__NR_pivot_root];
	syscall_table[__NR_pivot_root] = (unsigned long *)hook_sys_pivot_root;
	ref_sys_sysctl = (void *)syscall_table[__NR__sysctl];
	syscall_table[__NR__sysctl] = (unsigned long *)hook_sys_sysctl;
	ref_sys_prctl = (void *)syscall_table[__NR_prctl];
	syscall_table[__NR_prctl] = (unsigned long *)hook_sys_prctl;
	ref_sys_arch_prctl = (void *)syscall_table[__NR_arch_prctl];
	syscall_table[__NR_arch_prctl] = (unsigned long *)hook_sys_arch_prctl;
	ref_sys_adjtimex = (void *)syscall_table[__NR_adjtimex];
	syscall_table[__NR_adjtimex] = (unsigned long *)hook_sys_adjtimex;
	ref_sys_setrlimit = (void *)syscall_table[__NR_setrlimit];
	syscall_table[__NR_setrlimit] = (unsigned long *)hook_sys_setrlimit;
	ref_sys_chroot = (void *)syscall_table[__NR_chroot];
	syscall_table[__NR_chroot] = (unsigned long *)hook_sys_chroot;
	ref_sys_sync = (void *)syscall_table[__NR_sync];
	syscall_table[__NR_sync] = (unsigned long *)hook_sys_sync;
	ref_sys_acct = (void *)syscall_table[__NR_acct];
	syscall_table[__NR_acct] = (unsigned long *)hook_sys_acct;
	ref_sys_settimeofday = (void *)syscall_table[__NR_settimeofday];
	syscall_table[__NR_settimeofday] = (unsigned long *)hook_sys_settimeofday;
	ref_sys_mount = (void *)syscall_table[__NR_mount];
	syscall_table[__NR_mount] = (unsigned long *)hook_sys_mount;
	ref_sys_umount = (void *)syscall_table[__NR_umount2];
	syscall_table[__NR_umount2] = (unsigned long *)hook_sys_umount;
	ref_sys_swapon = (void *)syscall_table[__NR_swapon];
	syscall_table[__NR_swapon] = (unsigned long *)hook_sys_swapon;
	ref_sys_swapoff = (void *)syscall_table[__NR_swapoff];
	syscall_table[__NR_swapoff] = (unsigned long *)hook_sys_swapoff;
	ref_sys_reboot = (void *)syscall_table[__NR_reboot];
	syscall_table[__NR_reboot] = (unsigned long *)hook_sys_reboot;
	ref_sys_sethostname = (void *)syscall_table[__NR_sethostname];
	syscall_table[__NR_sethostname] = (unsigned long *)hook_sys_sethostname;
	ref_sys_setdomainname = (void *)syscall_table[__NR_setdomainname];
	syscall_table[__NR_setdomainname] = (unsigned long *)hook_sys_setdomainname;
	ref_sys_ioperm = (void *)syscall_table[__NR_ioperm];
	syscall_table[__NR_ioperm] = (unsigned long *)hook_sys_ioperm;
	ref_sys_init_module = (void *)syscall_table[__NR_init_module];
	syscall_table[__NR_init_module] = (unsigned long *)hook_sys_init_module;
	ref_sys_delete_module = (void *)syscall_table[__NR_delete_module];
	syscall_table[__NR_delete_module] = (unsigned long *)hook_sys_delete_module;
	ref_sys_quotactl = (void *)syscall_table[__NR_quotactl];
	syscall_table[__NR_quotactl] = (unsigned long *)hook_sys_quotactl;
	ref_sys_nfsservctl = (void *)syscall_table[__NR_nfsservctl];
	syscall_table[__NR_nfsservctl] = (unsigned long *)hook_sys_nfsservctl;
	ref_sys_gettid = (void *)syscall_table[__NR_gettid];
	syscall_table[__NR_gettid] = (unsigned long *)hook_sys_gettid;
	ref_sys_readahead = (void *)syscall_table[__NR_readahead];
	syscall_table[__NR_readahead] = (unsigned long *)hook_sys_readahead;
	ref_sys_setxattr = (void *)syscall_table[__NR_setxattr];
	syscall_table[__NR_setxattr] = (unsigned long *)hook_sys_setxattr;
	ref_sys_lsetxattr = (void *)syscall_table[__NR_lsetxattr];
	syscall_table[__NR_lsetxattr] = (unsigned long *)hook_sys_lsetxattr;
	ref_sys_fsetxattr = (void *)syscall_table[__NR_fsetxattr];
	syscall_table[__NR_fsetxattr] = (unsigned long *)hook_sys_fsetxattr;
	ref_sys_getxattr = (void *)syscall_table[__NR_getxattr];
	syscall_table[__NR_getxattr] = (unsigned long *)hook_sys_getxattr;
	ref_sys_lgetxattr = (void *)syscall_table[__NR_lgetxattr];
	syscall_table[__NR_lgetxattr] = (unsigned long *)hook_sys_lgetxattr;
	ref_sys_fgetxattr = (void *)syscall_table[__NR_fgetxattr];
	syscall_table[__NR_fgetxattr] = (unsigned long *)hook_sys_fgetxattr;
	ref_sys_listxattr = (void *)syscall_table[__NR_listxattr];
	syscall_table[__NR_listxattr] = (unsigned long *)hook_sys_listxattr;
	ref_sys_llistxattr = (void *)syscall_table[__NR_llistxattr];
	syscall_table[__NR_llistxattr] = (unsigned long *)hook_sys_llistxattr;
	ref_sys_flistxattr = (void *)syscall_table[__NR_flistxattr];
	syscall_table[__NR_flistxattr] = (unsigned long *)hook_sys_flistxattr;
	ref_sys_removexattr = (void *)syscall_table[__NR_removexattr];
	syscall_table[__NR_removexattr] = (unsigned long *)hook_sys_removexattr;
	ref_sys_lremovexattr = (void *)syscall_table[__NR_lremovexattr];
	syscall_table[__NR_lremovexattr] = (unsigned long *)hook_sys_lremovexattr;
	ref_sys_fremovexattr = (void *)syscall_table[__NR_fremovexattr];
	syscall_table[__NR_fremovexattr] = (unsigned long *)hook_sys_fremovexattr;
	ref_sys_tkill = (void *)syscall_table[__NR_tkill];
	syscall_table[__NR_tkill] = (unsigned long *)hook_sys_tkill;
	ref_sys_time = (void *)syscall_table[__NR_times];
	syscall_table[__NR_times] = (unsigned long *)hook_sys_time;
	ref_sys_futex = (void *)syscall_table[__NR_futex];
	syscall_table[__NR_futex] = (unsigned long *)hook_sys_futex;
	ref_sys_sched_setaffinity = (void *)syscall_table[__NR_sched_setaffinity];
	syscall_table[__NR_sched_setaffinity] = (unsigned long *)hook_sys_sched_setaffinity;
	ref_sys_sched_getaffinity = (void *)syscall_table[__NR_sched_getaffinity];
	syscall_table[__NR_sched_getaffinity] = (unsigned long *)hook_sys_sched_getaffinity;
	ref_sys_io_setup = (void *)syscall_table[__NR_io_setup];
	syscall_table[__NR_io_setup] = (unsigned long *)hook_sys_io_setup;
	ref_sys_io_destroy = (void *)syscall_table[__NR_io_destroy];
	syscall_table[__NR_io_destroy] = (unsigned long *)hook_sys_io_destroy;
	ref_sys_io_getevents = (void *)syscall_table[__NR_io_getevents];
	syscall_table[__NR_io_getevents] = (unsigned long *)hook_sys_io_getevents;
	ref_sys_io_submit = (void *)syscall_table[__NR_io_submit];
	syscall_table[__NR_io_submit] = (unsigned long *)hook_sys_io_submit;
	ref_sys_io_cancel = (void *)syscall_table[__NR_io_cancel];
	syscall_table[__NR_io_cancel] = (unsigned long *)hook_sys_io_cancel;
	ref_sys_lookup_dcookie = (void *)syscall_table[__NR_lookup_dcookie];
	syscall_table[__NR_lookup_dcookie] = (unsigned long *)hook_sys_lookup_dcookie;
	ref_sys_epoll_create = (void *)syscall_table[__NR_epoll_create];
	syscall_table[__NR_epoll_create] = (unsigned long *)hook_sys_epoll_create;
	ref_sys_remap_file_pages = (void *)syscall_table[__NR_remap_file_pages];
	syscall_table[__NR_remap_file_pages] = (unsigned long *)hook_sys_remap_file_pages;
	ref_sys_getdents64 = (void *)syscall_table[__NR_getdents64];
	syscall_table[__NR_getdents64] = (unsigned long *)hook_sys_getdents64;
	ref_sys_set_tid_address = (void *)syscall_table[__NR_set_tid_address];
	syscall_table[__NR_set_tid_address] = (unsigned long *)hook_sys_set_tid_address;
	ref_sys_restart_syscall = (void *)syscall_table[__NR_restart_syscall];
	syscall_table[__NR_restart_syscall] = (unsigned long *)hook_sys_restart_syscall;
	ref_sys_semtimedop = (void *)syscall_table[__NR_semtimedop];
	syscall_table[__NR_semtimedop] = (unsigned long *)hook_sys_semtimedop;
	ref_sys_fadvise64 = (void *)syscall_table[__NR_fadvise64];
	syscall_table[__NR_fadvise64] = (unsigned long *)hook_sys_fadvise64;
	ref_sys_timer_create = (void *)syscall_table[__NR_timer_create];
	syscall_table[__NR_timer_create] = (unsigned long *)hook_sys_timer_create;
	ref_sys_timer_settime = (void *)syscall_table[__NR_timer_settime];
	syscall_table[__NR_timer_settime] = (unsigned long *)hook_sys_timer_settime;
	ref_sys_timer_gettime = (void *)syscall_table[__NR_timer_gettime];
	syscall_table[__NR_timer_gettime] = (unsigned long *)hook_sys_timer_gettime;
	ref_sys_timer_getoverrun = (void *)syscall_table[__NR_timer_getoverrun];
	syscall_table[__NR_timer_getoverrun] = (unsigned long *)hook_sys_timer_getoverrun;
	ref_sys_timer_delete = (void *)syscall_table[__NR_timer_delete];
	syscall_table[__NR_timer_delete] = (unsigned long *)hook_sys_timer_delete;
	ref_sys_clock_settime = (void *)syscall_table[__NR_clock_settime];
	syscall_table[__NR_clock_settime] = (unsigned long *)hook_sys_clock_settime;
	ref_sys_clock_gettime = (void *)syscall_table[__NR_clock_gettime];
	syscall_table[__NR_clock_gettime] = (unsigned long *)hook_sys_clock_gettime;
	ref_sys_clock_getres = (void *)syscall_table[__NR_clock_getres];
	syscall_table[__NR_clock_getres] = (unsigned long *)hook_sys_clock_getres;
	ref_sys_clock_nanosleep = (void *)syscall_table[__NR_clock_nanosleep];
	syscall_table[__NR_clock_nanosleep] = (unsigned long *)hook_sys_clock_nanosleep;
	ref_sys_exit_group = (void *)syscall_table[__NR_exit_group];
	syscall_table[__NR_exit_group] = (unsigned long *)hook_sys_exit_group;
	ref_sys_epoll_wait = (void *)syscall_table[__NR_epoll_wait];
	syscall_table[__NR_epoll_wait] = (unsigned long *)hook_sys_epoll_wait;
	ref_sys_epoll_ctl = (void *)syscall_table[__NR_epoll_ctl];
	syscall_table[__NR_epoll_ctl] = (unsigned long *)hook_sys_epoll_ctl;
	ref_sys_tgkill = (void *)syscall_table[__NR_tgkill];
	syscall_table[__NR_tgkill] = (unsigned long *)hook_sys_tgkill;
	ref_sys_utimes = (void *)syscall_table[__NR_utimes];
	syscall_table[__NR_utimes] = (unsigned long *)hook_sys_utimes;
	ref_sys_mbind = (void *)syscall_table[__NR_mbind];
	syscall_table[__NR_mbind] = (unsigned long *)hook_sys_mbind;
	ref_sys_set_mempolicy = (void *)syscall_table[__NR_set_mempolicy];
	syscall_table[__NR_set_mempolicy] = (unsigned long *)hook_sys_set_mempolicy;
	ref_sys_get_mempolicy = (void *)syscall_table[__NR_get_mempolicy];
	syscall_table[__NR_get_mempolicy] = (unsigned long *)hook_sys_get_mempolicy;
	ref_sys_mq_open = (void *)syscall_table[__NR_mq_open];
	syscall_table[__NR_mq_open] = (unsigned long *)hook_sys_mq_open;
	ref_sys_mq_unlink = (void *)syscall_table[__NR_mq_unlink];
	syscall_table[__NR_mq_unlink] = (unsigned long *)hook_sys_mq_unlink;
	ref_sys_mq_timedsend = (void *)syscall_table[__NR_mq_timedsend];
	syscall_table[__NR_mq_timedsend] = (unsigned long *)hook_sys_mq_timedsend;
	ref_sys_mq_timedreceive = (void *)syscall_table[__NR_mq_timedreceive];
	syscall_table[__NR_mq_timedreceive] = (unsigned long *)hook_sys_mq_timedreceive;
	ref_sys_mq_notify = (void *)syscall_table[__NR_mq_notify];
	syscall_table[__NR_mq_notify] = (unsigned long *)hook_sys_mq_notify;
	ref_sys_mq_getsetattr = (void *)syscall_table[__NR_mq_getsetattr];
	syscall_table[__NR_mq_getsetattr] = (unsigned long *)hook_sys_mq_getsetattr;
	ref_sys_kexec_load = (void *)syscall_table[__NR_kexec_load];
	syscall_table[__NR_kexec_load] = (unsigned long *)hook_sys_kexec_load;
	ref_sys_waitid = (void *)syscall_table[__NR_waitid];
	syscall_table[__NR_waitid] = (unsigned long *)hook_sys_waitid;
	ref_sys_add_key = (void *)syscall_table[__NR_add_key];
	syscall_table[__NR_add_key] = (unsigned long *)hook_sys_add_key;
	ref_sys_request_key = (void *)syscall_table[__NR_request_key];
	syscall_table[__NR_request_key] = (unsigned long *)hook_sys_request_key;
	ref_sys_keyctl = (void *)syscall_table[__NR_keyctl];
	syscall_table[__NR_keyctl] = (unsigned long *)hook_sys_keyctl;
	ref_sys_ioprio_set = (void *)syscall_table[__NR_ioprio_set];
	syscall_table[__NR_ioprio_set] = (unsigned long *)hook_sys_ioprio_set;
	ref_sys_ioprio_get = (void *)syscall_table[__NR_ioprio_get];
	syscall_table[__NR_ioprio_get] = (unsigned long *)hook_sys_ioprio_get;
	ref_sys_inotify_init = (void *)syscall_table[__NR_inotify_init];
	syscall_table[__NR_inotify_init] = (unsigned long *)hook_sys_inotify_init;
	ref_sys_inotify_add_watch = (void *)syscall_table[__NR_inotify_add_watch];
	syscall_table[__NR_inotify_add_watch] = (unsigned long *)hook_sys_inotify_add_watch;
	ref_sys_inotify_rm_watch = (void *)syscall_table[__NR_inotify_rm_watch];
	syscall_table[__NR_inotify_rm_watch] = (unsigned long *)hook_sys_inotify_rm_watch;
	ref_sys_migrate_pages = (void *)syscall_table[__NR_migrate_pages];
	syscall_table[__NR_migrate_pages] = (unsigned long *)hook_sys_migrate_pages;
	ref_sys_openat = (void *)syscall_table[__NR_openat];
	syscall_table[__NR_openat] = (unsigned long *)hook_sys_openat;
	ref_sys_mkdirat = (void *)syscall_table[__NR_mkdirat];
	syscall_table[__NR_mkdirat] = (unsigned long *)hook_sys_mkdirat;
	ref_sys_mknodat = (void *)syscall_table[__NR_mknodat];
	syscall_table[__NR_mknodat] = (unsigned long *)hook_sys_mknodat;
	ref_sys_fchownat = (void *)syscall_table[__NR_fchownat];
	syscall_table[__NR_fchownat] = (unsigned long *)hook_sys_fchownat;
	ref_sys_futimesat = (void *)syscall_table[__NR_futimesat];
	syscall_table[__NR_futimesat] = (unsigned long *)hook_sys_futimesat;
	ref_sys_newfstatat = (void *)syscall_table[__NR_newfstatat];
	syscall_table[__NR_newfstatat] = (unsigned long *)hook_sys_newfstatat;
	ref_sys_unlinkat = (void *)syscall_table[__NR_unlinkat];
	syscall_table[__NR_unlinkat] = (unsigned long *)hook_sys_unlinkat;
	ref_sys_renameat = (void *)syscall_table[__NR_renameat];
	syscall_table[__NR_renameat] = (unsigned long *)hook_sys_renameat;
	ref_sys_linkat = (void *)syscall_table[__NR_linkat];
	syscall_table[__NR_linkat] = (unsigned long *)hook_sys_linkat;
	ref_sys_symlinkat = (void *)syscall_table[__NR_symlinkat];
	syscall_table[__NR_symlinkat] = (unsigned long *)hook_sys_symlinkat;
	ref_sys_readlinkat = (void *)syscall_table[__NR_readlinkat];
	syscall_table[__NR_readlinkat] = (unsigned long *)hook_sys_readlinkat;
	ref_sys_fchmodat = (void *)syscall_table[__NR_fchmodat];
	syscall_table[__NR_fchmodat] = (unsigned long *)hook_sys_fchmodat;
	ref_sys_faccessat = (void *)syscall_table[__NR_faccessat];
	syscall_table[__NR_faccessat] = (unsigned long *)hook_sys_faccessat;
	ref_sys_pselect6 = (void *)syscall_table[__NR_pselect6];
	syscall_table[__NR_pselect6] = (unsigned long *)hook_sys_pselect6;
	ref_sys_ppoll = (void *)syscall_table[__NR_ppoll];
	syscall_table[__NR_ppoll] = (unsigned long *)hook_sys_ppoll;
	ref_sys_unshare = (void *)syscall_table[__NR_unshare];
	syscall_table[__NR_unshare] = (unsigned long *)hook_sys_unshare;
	ref_sys_set_robust_list = (void *)syscall_table[__NR_set_robust_list];
	syscall_table[__NR_set_robust_list] = (unsigned long *)hook_sys_set_robust_list;
	ref_sys_get_robust_list = (void *)syscall_table[__NR_get_robust_list];
	syscall_table[__NR_get_robust_list] = (unsigned long *)hook_sys_get_robust_list;
	ref_sys_splice = (void *)syscall_table[__NR_splice];
	syscall_table[__NR_splice] = (unsigned long *)hook_sys_splice;
	ref_sys_tee = (void *)syscall_table[__NR_tee];
	syscall_table[__NR_tee] = (unsigned long *)hook_sys_tee;
	ref_sys_sync_file_range = (void *)syscall_table[__NR_sync_file_range];
	syscall_table[__NR_sync_file_range] = (unsigned long *)hook_sys_sync_file_range;
	ref_sys_vmsplice = (void *)syscall_table[__NR_vmsplice];
	syscall_table[__NR_vmsplice] = (unsigned long *)hook_sys_vmsplice;
	ref_sys_move_pages = (void *)syscall_table[__NR_move_pages];
	syscall_table[__NR_move_pages] = (unsigned long *)hook_sys_move_pages;
	ref_sys_utimensat = (void *)syscall_table[__NR_utimensat];
	syscall_table[__NR_utimensat] = (unsigned long *)hook_sys_utimensat;
	ref_sys_epoll_pwait = (void *)syscall_table[__NR_epoll_pwait];
	syscall_table[__NR_epoll_pwait] = (unsigned long *)hook_sys_epoll_pwait;
	ref_sys_signalfd = (void *)syscall_table[__NR_signalfd];
	syscall_table[__NR_signalfd] = (unsigned long *)hook_sys_signalfd;
	ref_sys_timerfd_create = (void *)syscall_table[__NR_timerfd_create];
	syscall_table[__NR_timerfd_create] = (unsigned long *)hook_sys_timerfd_create;
	ref_sys_eventfd = (void *)syscall_table[__NR_eventfd];
	syscall_table[__NR_eventfd] = (unsigned long *)hook_sys_eventfd;
	ref_sys_fallocate = (void *)syscall_table[__NR_fallocate];
	syscall_table[__NR_fallocate] = (unsigned long *)hook_sys_fallocate;
	ref_sys_timerfd_settime = (void *)syscall_table[__NR_timerfd_settime];
	syscall_table[__NR_timerfd_settime] = (unsigned long *)hook_sys_timerfd_settime;
	ref_sys_timerfd_gettime = (void *)syscall_table[__NR_timerfd_gettime];
	syscall_table[__NR_timerfd_gettime] = (unsigned long *)hook_sys_timerfd_gettime;
	ref_sys_accept4 = (void *)syscall_table[__NR_accept4];
	syscall_table[__NR_accept4] = (unsigned long *)hook_sys_accept4;
	ref_sys_signalfd4 = (void *)syscall_table[__NR_signalfd4];
	syscall_table[__NR_signalfd4] = (unsigned long *)hook_sys_signalfd4;
	ref_sys_eventfd2 = (void *)syscall_table[__NR_eventfd2];
	syscall_table[__NR_eventfd2] = (unsigned long *)hook_sys_eventfd2;
	ref_sys_epoll_create1 = (void *)syscall_table[__NR_epoll_create1];
	syscall_table[__NR_epoll_create1] = (unsigned long *)hook_sys_epoll_create1;
	ref_sys_dup3 = (void *)syscall_table[__NR_dup3];
	syscall_table[__NR_dup3] = (unsigned long *)hook_sys_dup3;
	ref_sys_pipe2 = (void *)syscall_table[__NR_pipe2];
	syscall_table[__NR_pipe2] = (unsigned long *)hook_sys_pipe2;
	ref_sys_inotify_init1 = (void *)syscall_table[__NR_inotify_init1];
	syscall_table[__NR_inotify_init1] = (unsigned long *)hook_sys_inotify_init1;
	ref_sys_preadv = (void *)syscall_table[__NR_preadv];
	syscall_table[__NR_preadv] = (unsigned long *)hook_sys_preadv;
	ref_sys_pwritev = (void *)syscall_table[__NR_pwritev];
	syscall_table[__NR_pwritev] = (unsigned long *)hook_sys_pwritev;
	ref_sys_rt_tgsigqueueinfo = (void *)syscall_table[__NR_rt_tgsigqueueinfo];
	syscall_table[__NR_rt_tgsigqueueinfo] = (unsigned long *)hook_sys_rt_tgsigqueueinfo;
	ref_sys_perf_event_open = (void *)syscall_table[__NR_perf_event_open];
	syscall_table[__NR_perf_event_open] = (unsigned long *)hook_sys_perf_event_open;
	ref_sys_recvmmsg = (void *)syscall_table[__NR_recvmmsg];
	syscall_table[__NR_recvmmsg] = (unsigned long *)hook_sys_recvmmsg;
	ref_sys_clock_adjtime = (void *)syscall_table[__NR_clock_adjtime];
	syscall_table[__NR_clock_adjtime] = (unsigned long *)hook_sys_clock_adjtime;
	ref_sys_syncfs = (void *)syscall_table[__NR_syncfs];
	syscall_table[__NR_syncfs] = (unsigned long *)hook_sys_syncfs;
	ref_sys_sendmmsg = (void *)syscall_table[__NR_sendmmsg];
	syscall_table[__NR_sendmmsg] = (unsigned long *)hook_sys_sendmmsg;
	ref_sys_process_vm_readv = (void *)syscall_table[__NR_process_vm_readv];
	syscall_table[__NR_process_vm_readv] = (unsigned long *)hook_sys_process_vm_readv;
	ref_sys_process_vm_writev = (void *)syscall_table[__NR_process_vm_writev];
	syscall_table[__NR_process_vm_writev] = (unsigned long *)hook_sys_process_vm_writev;
	*/
}

void unreg_hooks(unsigned long **syscall_table)
{
	syscall_table[__NR_read] = (unsigned long *)ref_sys_read;
	syscall_table[__NR_write] = (unsigned long *)ref_sys_write;
	syscall_table[__NR_open] = (unsigned long *)ref_sys_open;
	/*syscall_table[__NR_close] = (unsigned long *)ref_sys_close;
	syscall_table[__NR_stat] = (unsigned long *)ref_sys_newstat;
	syscall_table[__NR_fstat] = (unsigned long *)ref_sys_newfstat;
	syscall_table[__NR_lstat] = (unsigned long *)ref_sys_newlstat;
	syscall_table[__NR_poll] = (unsigned long *)ref_sys_poll;
	syscall_table[__NR_lseek] = (unsigned long *)ref_sys_lseek;
	syscall_table[__NR_mmap] = (unsigned long *)ref_sys_mmap;
	syscall_table[__NR_mprotect] = (unsigned long *)ref_sys_mprotect;
	syscall_table[__NR_munmap] = (unsigned long *)ref_sys_munmap;
	syscall_table[__NR_brk] = (unsigned long *)ref_sys_brk;
	syscall_table[__NR_rt_sigaction] = (unsigned long *)ref_sys_rt_sigaction;
	syscall_table[__NR_rt_sigprocmask] = (unsigned long *)ref_sys_rt_sigprocmask;
	syscall_table[__NR_ioctl] = (unsigned long *)ref_sys_ioctl;
	syscall_table[__NR_pread64] = (unsigned long *)ref_sys_pread64;
	syscall_table[__NR_pwrite64] = (unsigned long *)ref_sys_pwrite64;
	syscall_table[__NR_readv] = (unsigned long *)ref_sys_readv;
	syscall_table[__NR_writev] = (unsigned long *)ref_sys_writev;
	syscall_table[__NR_access] = (unsigned long *)ref_sys_access;
	syscall_table[__NR_pipe] = (unsigned long *)ref_sys_pipe;
	syscall_table[__NR_select] = (unsigned long *)ref_sys_select;
	syscall_table[__NR_sched_yield] = (unsigned long *)ref_sys_sched_yield;
	syscall_table[__NR_mremap] = (unsigned long *)ref_sys_mremap;
	syscall_table[__NR_msync] = (unsigned long *)ref_sys_msync;
	syscall_table[__NR_mincore] = (unsigned long *)ref_sys_mincore;
	syscall_table[__NR_madvise] = (unsigned long *)ref_sys_madvise;
	syscall_table[__NR_shmget] = (unsigned long *)ref_sys_shmget;
	syscall_table[__NR_shmat] = (unsigned long *)ref_sys_shmat;
	syscall_table[__NR_shmctl] = (unsigned long *)ref_sys_shmctl;
	syscall_table[__NR_dup] = (unsigned long *)ref_sys_dup;
	syscall_table[__NR_dup2] = (unsigned long *)ref_sys_dup2;
	syscall_table[__NR_pause] = (unsigned long *)ref_sys_pause;
	syscall_table[__NR_nanosleep] = (unsigned long *)ref_sys_nanosleep;
	syscall_table[__NR_getitimer] = (unsigned long *)ref_sys_getitimer;
	syscall_table[__NR_alarm] = (unsigned long *)ref_sys_alarm;
	syscall_table[__NR_setitimer] = (unsigned long *)ref_sys_setitimer;
	syscall_table[__NR_getpid] = (unsigned long *)ref_sys_getpid;
	syscall_table[__NR_sendfile] = (unsigned long *)ref_sys_sendfile64;
	syscall_table[__NR_socket] = (unsigned long *)ref_sys_socket;
	syscall_table[__NR_connect] = (unsigned long *)ref_sys_connect;
	syscall_table[__NR_accept] = (unsigned long *)ref_sys_accept;
	syscall_table[__NR_sendto] = (unsigned long *)ref_sys_sendto;
	syscall_table[__NR_recvfrom] = (unsigned long *)ref_sys_recvfrom;
	syscall_table[__NR_sendmsg] = (unsigned long *)ref_sys_sendmsg;
	syscall_table[__NR_recvmsg] = (unsigned long *)ref_sys_recvmsg;
	syscall_table[__NR_shutdown] = (unsigned long *)ref_sys_shutdown;
	syscall_table[__NR_bind] = (unsigned long *)ref_sys_bind;
	syscall_table[__NR_listen] = (unsigned long *)ref_sys_listen;
	syscall_table[__NR_getsockname] = (unsigned long *)ref_sys_getsockname;
	syscall_table[__NR_getpeername] = (unsigned long *)ref_sys_getpeername;
	syscall_table[__NR_socketpair] = (unsigned long *)ref_sys_socketpair;
	syscall_table[__NR_setsockopt] = (unsigned long *)ref_sys_setsockopt;
	syscall_table[__NR_getsockopt] = (unsigned long *)ref_sys_getsockopt;
	syscall_table[__NR_exit] = (unsigned long *)ref_sys_exit;
	syscall_table[__NR_wait4] = (unsigned long *)ref_sys_wait4;
	syscall_table[__NR_kill] = (unsigned long *)ref_sys_kill;
	syscall_table[__NR_uname] = (unsigned long *)ref_sys_uname;
	syscall_table[__NR_semget] = (unsigned long *)ref_sys_semget;
	syscall_table[__NR_semop] = (unsigned long *)ref_sys_semop;
	syscall_table[__NR_semctl] = (unsigned long *)ref_sys_semctl;
	syscall_table[__NR_shmdt] = (unsigned long *)ref_sys_shmdt;
	syscall_table[__NR_msgget] = (unsigned long *)ref_sys_msgget;
	syscall_table[__NR_msgsnd] = (unsigned long *)ref_sys_msgsnd;
	syscall_table[__NR_msgrcv] = (unsigned long *)ref_sys_msgrcv;
	syscall_table[__NR_msgctl] = (unsigned long *)ref_sys_msgctl;
	syscall_table[__NR_fcntl] = (unsigned long *)ref_sys_fcntl;
	syscall_table[__NR_flock] = (unsigned long *)ref_sys_flock;
	syscall_table[__NR_fsync] = (unsigned long *)ref_sys_fsync;
	syscall_table[__NR_fdatasync] = (unsigned long *)ref_sys_fdatasync;
	syscall_table[__NR_truncate] = (unsigned long *)ref_sys_truncate;
	syscall_table[__NR_ftruncate] = (unsigned long *)ref_sys_ftruncate;
	syscall_table[__NR_getdents] = (unsigned long *)ref_sys_getdents;
	syscall_table[__NR_getcwd] = (unsigned long *)ref_sys_getcwd;
	syscall_table[__NR_chdir] = (unsigned long *)ref_sys_chdir;
	syscall_table[__NR_fchdir] = (unsigned long *)ref_sys_fchdir;
	syscall_table[__NR_rename] = (unsigned long *)ref_sys_rename;
	syscall_table[__NR_mkdir] = (unsigned long *)ref_sys_mkdir;
	syscall_table[__NR_rmdir] = (unsigned long *)ref_sys_rmdir;
	syscall_table[__NR_creat] = (unsigned long *)ref_sys_creat;
	syscall_table[__NR_link] = (unsigned long *)ref_sys_link;
	syscall_table[__NR_unlink] = (unsigned long *)ref_sys_unlink;
	syscall_table[__NR_symlink] = (unsigned long *)ref_sys_symlink;
	syscall_table[__NR_readlink] = (unsigned long *)ref_sys_readlink;
	syscall_table[__NR_chmod] = (unsigned long *)ref_sys_chmod;
	syscall_table[__NR_fchmod] = (unsigned long *)ref_sys_fchmod;
	syscall_table[__NR_chown] = (unsigned long *)ref_sys_chown;
	syscall_table[__NR_fchown] = (unsigned long *)ref_sys_fchown;
	syscall_table[__NR_lchown] = (unsigned long *)ref_sys_lchown;
	syscall_table[__NR_umask] = (unsigned long *)ref_sys_umask;
	syscall_table[__NR_gettimeofday] = (unsigned long *)ref_sys_gettimeofday;
	syscall_table[__NR_getrlimit] = (unsigned long *)ref_sys_getrlimit;
	syscall_table[__NR_getrusage] = (unsigned long *)ref_sys_getrusage;
	syscall_table[__NR_sysinfo] = (unsigned long *)ref_sys_sysinfo;
	syscall_table[__NR_times] = (unsigned long *)ref_sys_times;
	syscall_table[__NR_ptrace] = (unsigned long *)ref_sys_ptrace;
	syscall_table[__NR_getuid] = (unsigned long *)ref_sys_getuid;
	syscall_table[__NR_syslog] = (unsigned long *)ref_sys_syslog;
	syscall_table[__NR_getgid] = (unsigned long *)ref_sys_getgid;
	syscall_table[__NR_setuid] = (unsigned long *)ref_sys_setuid;
	syscall_table[__NR_setgid] = (unsigned long *)ref_sys_setgid;
	syscall_table[__NR_geteuid] = (unsigned long *)ref_sys_geteuid;
	syscall_table[__NR_getegid] = (unsigned long *)ref_sys_getegid;
	syscall_table[__NR_setpgid] = (unsigned long *)ref_sys_setpgid;
	syscall_table[__NR_getppid] = (unsigned long *)ref_sys_getppid;
	syscall_table[__NR_getpgrp] = (unsigned long *)ref_sys_getpgrp;
	syscall_table[__NR_setsid] = (unsigned long *)ref_sys_setsid;
	syscall_table[__NR_setreuid] = (unsigned long *)ref_sys_setreuid;
	syscall_table[__NR_setregid] = (unsigned long *)ref_sys_setregid;
	syscall_table[__NR_getgroups] = (unsigned long *)ref_sys_getgroups;
	syscall_table[__NR_setgroups] = (unsigned long *)ref_sys_setgroups;
	syscall_table[__NR_setresuid] = (unsigned long *)ref_sys_setresuid;
	syscall_table[__NR_getresuid] = (unsigned long *)ref_sys_getresuid;
	syscall_table[__NR_setresgid] = (unsigned long *)ref_sys_setresgid;
	syscall_table[__NR_getresgid] = (unsigned long *)ref_sys_getresgid;
	syscall_table[__NR_getpgid] = (unsigned long *)ref_sys_getpgid;
	syscall_table[__NR_setfsuid] = (unsigned long *)ref_sys_setfsuid;
	syscall_table[__NR_setfsgid] = (unsigned long *)ref_sys_setfsgid;
	syscall_table[__NR_getsid] = (unsigned long *)ref_sys_getsid;
	syscall_table[__NR_capget] = (unsigned long *)ref_sys_capget;
	syscall_table[__NR_capset] = (unsigned long *)ref_sys_capset;
	syscall_table[__NR_rt_sigpending] = (unsigned long *)ref_sys_rt_sigpending;
	syscall_table[__NR_rt_sigtimedwait] = (unsigned long *)ref_sys_rt_sigtimedwait;
	syscall_table[__NR_rt_sigqueueinfo] = (unsigned long *)ref_sys_rt_sigqueueinfo;
	syscall_table[__NR_rt_sigsuspend] = (unsigned long *)ref_sys_rt_sigsuspend;
	syscall_table[__NR_utime] = (unsigned long *)ref_sys_utime;
	syscall_table[__NR_mknod] = (unsigned long *)ref_sys_mknod;
	syscall_table[__NR_uselib] = (unsigned long *)ref_sys_ni_syscall;
	syscall_table[__NR_personality] = (unsigned long *)ref_sys_personality;
	syscall_table[__NR_ustat] = (unsigned long *)ref_sys_ustat;
	syscall_table[__NR_statfs] = (unsigned long *)ref_sys_statfs;
	syscall_table[__NR_fstatfs] = (unsigned long *)ref_sys_fstatfs;
	syscall_table[__NR_sysfs] = (unsigned long *)ref_sys_sysfs;
	syscall_table[__NR_getpriority] = (unsigned long *)ref_sys_getpriority;
	syscall_table[__NR_setpriority] = (unsigned long *)ref_sys_setpriority;
	syscall_table[__NR_sched_setparam] = (unsigned long *)ref_sys_sched_setparam;
	syscall_table[__NR_sched_getparam] = (unsigned long *)ref_sys_sched_getparam;
	syscall_table[__NR_sched_setscheduler] = (unsigned long *)ref_sys_sched_setscheduler;
	syscall_table[__NR_sched_getscheduler] = (unsigned long *)ref_sys_sched_getscheduler;
	syscall_table[__NR_sched_get_priority_max] = (unsigned long *)ref_sys_sched_get_priority_max;
	syscall_table[__NR_sched_get_priority_min] = (unsigned long *)ref_sys_sched_get_priority_min;
	syscall_table[__NR_sched_rr_get_interval] = (unsigned long *)ref_sys_sched_rr_get_interval;
	syscall_table[__NR_mlock] = (unsigned long *)ref_sys_mlock;
	syscall_table[__NR_munlock] = (unsigned long *)ref_sys_munlock;
	syscall_table[__NR_mlockall] = (unsigned long *)ref_sys_mlockall;
	syscall_table[__NR_munlockall] = (unsigned long *)ref_sys_munlockall;
	syscall_table[__NR_vhangup] = (unsigned long *)ref_sys_vhangup;
	syscall_table[__NR_modify_ldt] = (unsigned long *)ref_sys_modify_ldt;
	syscall_table[__NR_pivot_root] = (unsigned long *)ref_sys_pivot_root;
	syscall_table[__NR__sysctl] = (unsigned long *)ref_sys_sysctl;
	syscall_table[__NR_prctl] = (unsigned long *)ref_sys_prctl;
	syscall_table[__NR_arch_prctl] = (unsigned long *)ref_sys_arch_prctl;
	syscall_table[__NR_adjtimex] = (unsigned long *)ref_sys_adjtimex;
	syscall_table[__NR_setrlimit] = (unsigned long *)ref_sys_setrlimit;
	syscall_table[__NR_chroot] = (unsigned long *)ref_sys_chroot;
	syscall_table[__NR_sync] = (unsigned long *)ref_sys_sync;
	syscall_table[__NR_acct] = (unsigned long *)ref_sys_acct;
	syscall_table[__NR_settimeofday] = (unsigned long *)ref_sys_settimeofday;
	syscall_table[__NR_mount] = (unsigned long *)ref_sys_mount;
	syscall_table[__NR_umount2] = (unsigned long *)ref_sys_umount;
	syscall_table[__NR_swapon] = (unsigned long *)ref_sys_swapon;
	syscall_table[__NR_swapoff] = (unsigned long *)ref_sys_swapoff;
	syscall_table[__NR_reboot] = (unsigned long *)ref_sys_reboot;
	syscall_table[__NR_sethostname] = (unsigned long *)ref_sys_sethostname;
	syscall_table[__NR_setdomainname] = (unsigned long *)ref_sys_setdomainname;
	syscall_table[__NR_ioperm] = (unsigned long *)ref_sys_ioperm;
	syscall_table[__NR_init_module] = (unsigned long *)ref_sys_init_module;
	syscall_table[__NR_delete_module] = (unsigned long *)ref_sys_delete_module;
	syscall_table[__NR_quotactl] = (unsigned long *)ref_sys_quotactl;
	syscall_table[__NR_nfsservctl] = (unsigned long *)ref_sys_nfsservctl;
	syscall_table[__NR_gettid] = (unsigned long *)ref_sys_gettid;
	syscall_table[__NR_readahead] = (unsigned long *)ref_sys_readahead;
	syscall_table[__NR_setxattr] = (unsigned long *)ref_sys_setxattr;
	syscall_table[__NR_lsetxattr] = (unsigned long *)ref_sys_lsetxattr;
	syscall_table[__NR_fsetxattr] = (unsigned long *)ref_sys_fsetxattr;
	syscall_table[__NR_getxattr] = (unsigned long *)ref_sys_getxattr;
	syscall_table[__NR_lgetxattr] = (unsigned long *)ref_sys_lgetxattr;
	syscall_table[__NR_fgetxattr] = (unsigned long *)ref_sys_fgetxattr;
	syscall_table[__NR_listxattr] = (unsigned long *)ref_sys_listxattr;
	syscall_table[__NR_llistxattr] = (unsigned long *)ref_sys_llistxattr;
	syscall_table[__NR_flistxattr] = (unsigned long *)ref_sys_flistxattr;
	syscall_table[__NR_removexattr] = (unsigned long *)ref_sys_removexattr;
	syscall_table[__NR_lremovexattr] = (unsigned long *)ref_sys_lremovexattr;
	syscall_table[__NR_fremovexattr] = (unsigned long *)ref_sys_fremovexattr;
	syscall_table[__NR_tkill] = (unsigned long *)ref_sys_tkill;
	syscall_table[__NR_times] = (unsigned long *)ref_sys_time;
	syscall_table[__NR_futex] = (unsigned long *)ref_sys_futex;
	syscall_table[__NR_sched_setaffinity] = (unsigned long *)ref_sys_sched_setaffinity;
	syscall_table[__NR_sched_getaffinity] = (unsigned long *)ref_sys_sched_getaffinity;
	syscall_table[__NR_io_setup] = (unsigned long *)ref_sys_io_setup;
	syscall_table[__NR_io_destroy] = (unsigned long *)ref_sys_io_destroy;
	syscall_table[__NR_io_getevents] = (unsigned long *)ref_sys_io_getevents;
	syscall_table[__NR_io_submit] = (unsigned long *)ref_sys_io_submit;
	syscall_table[__NR_io_cancel] = (unsigned long *)ref_sys_io_cancel;
	syscall_table[__NR_lookup_dcookie] = (unsigned long *)ref_sys_lookup_dcookie;
	syscall_table[__NR_epoll_create] = (unsigned long *)ref_sys_epoll_create;
	syscall_table[__NR_remap_file_pages] = (unsigned long *)ref_sys_remap_file_pages;
	syscall_table[__NR_getdents64] = (unsigned long *)ref_sys_getdents64;
	syscall_table[__NR_set_tid_address] = (unsigned long *)ref_sys_set_tid_address;
	syscall_table[__NR_restart_syscall] = (unsigned long *)ref_sys_restart_syscall;
	syscall_table[__NR_semtimedop] = (unsigned long *)ref_sys_semtimedop;
	syscall_table[__NR_fadvise64] = (unsigned long *)ref_sys_fadvise64;
	syscall_table[__NR_timer_create] = (unsigned long *)ref_sys_timer_create;
	syscall_table[__NR_timer_settime] = (unsigned long *)ref_sys_timer_settime;
	syscall_table[__NR_timer_gettime] = (unsigned long *)ref_sys_timer_gettime;
	syscall_table[__NR_timer_getoverrun] = (unsigned long *)ref_sys_timer_getoverrun;
	syscall_table[__NR_timer_delete] = (unsigned long *)ref_sys_timer_delete;
	syscall_table[__NR_clock_settime] = (unsigned long *)ref_sys_clock_settime;
	syscall_table[__NR_clock_gettime] = (unsigned long *)ref_sys_clock_gettime;
	syscall_table[__NR_clock_getres] = (unsigned long *)ref_sys_clock_getres;
	syscall_table[__NR_clock_nanosleep] = (unsigned long *)ref_sys_clock_nanosleep;
	syscall_table[__NR_exit_group] = (unsigned long *)ref_sys_exit_group;
	syscall_table[__NR_epoll_wait] = (unsigned long *)ref_sys_epoll_wait;
	syscall_table[__NR_epoll_ctl] = (unsigned long *)ref_sys_epoll_ctl;
	syscall_table[__NR_tgkill] = (unsigned long *)ref_sys_tgkill;
	syscall_table[__NR_utimes] = (unsigned long *)ref_sys_utimes;
	syscall_table[__NR_mbind] = (unsigned long *)ref_sys_mbind;
	syscall_table[__NR_set_mempolicy] = (unsigned long *)ref_sys_set_mempolicy;
	syscall_table[__NR_get_mempolicy] = (unsigned long *)ref_sys_get_mempolicy;
	syscall_table[__NR_mq_open] = (unsigned long *)ref_sys_mq_open;
	syscall_table[__NR_mq_unlink] = (unsigned long *)ref_sys_mq_unlink;
	syscall_table[__NR_mq_timedsend] = (unsigned long *)ref_sys_mq_timedsend;
	syscall_table[__NR_mq_timedreceive] = (unsigned long *)ref_sys_mq_timedreceive;
	syscall_table[__NR_mq_notify] = (unsigned long *)ref_sys_mq_notify;
	syscall_table[__NR_mq_getsetattr] = (unsigned long *)ref_sys_mq_getsetattr;
	syscall_table[__NR_kexec_load] = (unsigned long *)ref_sys_kexec_load;
	syscall_table[__NR_waitid] = (unsigned long *)ref_sys_waitid;
	syscall_table[__NR_add_key] = (unsigned long *)ref_sys_add_key;
	syscall_table[__NR_request_key] = (unsigned long *)ref_sys_request_key;
	syscall_table[__NR_keyctl] = (unsigned long *)ref_sys_keyctl;
	syscall_table[__NR_ioprio_set] = (unsigned long *)ref_sys_ioprio_set;
	syscall_table[__NR_ioprio_get] = (unsigned long *)ref_sys_ioprio_get;
	syscall_table[__NR_inotify_init] = (unsigned long *)ref_sys_inotify_init;
	syscall_table[__NR_inotify_add_watch] = (unsigned long *)ref_sys_inotify_add_watch;
	syscall_table[__NR_inotify_rm_watch] = (unsigned long *)ref_sys_inotify_rm_watch;
	syscall_table[__NR_migrate_pages] = (unsigned long *)ref_sys_migrate_pages;
	syscall_table[__NR_openat] = (unsigned long *)ref_sys_openat;
	syscall_table[__NR_mkdirat] = (unsigned long *)ref_sys_mkdirat;
	syscall_table[__NR_mknodat] = (unsigned long *)ref_sys_mknodat;
	syscall_table[__NR_fchownat] = (unsigned long *)ref_sys_fchownat;
	syscall_table[__NR_futimesat] = (unsigned long *)ref_sys_futimesat;
	syscall_table[__NR_newfstatat] = (unsigned long *)ref_sys_newfstatat;
	syscall_table[__NR_unlinkat] = (unsigned long *)ref_sys_unlinkat;
	syscall_table[__NR_renameat] = (unsigned long *)ref_sys_renameat;
	syscall_table[__NR_linkat] = (unsigned long *)ref_sys_linkat;
	syscall_table[__NR_symlinkat] = (unsigned long *)ref_sys_symlinkat;
	syscall_table[__NR_readlinkat] = (unsigned long *)ref_sys_readlinkat;
	syscall_table[__NR_fchmodat] = (unsigned long *)ref_sys_fchmodat;
	syscall_table[__NR_faccessat] = (unsigned long *)ref_sys_faccessat;
	syscall_table[__NR_pselect6] = (unsigned long *)ref_sys_pselect6;
	syscall_table[__NR_ppoll] = (unsigned long *)ref_sys_ppoll;
	syscall_table[__NR_unshare] = (unsigned long *)ref_sys_unshare;
	syscall_table[__NR_set_robust_list] = (unsigned long *)ref_sys_set_robust_list;
	syscall_table[__NR_get_robust_list] = (unsigned long *)ref_sys_get_robust_list;
	syscall_table[__NR_splice] = (unsigned long *)ref_sys_splice;
	syscall_table[__NR_tee] = (unsigned long *)ref_sys_tee;
	syscall_table[__NR_sync_file_range] = (unsigned long *)ref_sys_sync_file_range;
	syscall_table[__NR_vmsplice] = (unsigned long *)ref_sys_vmsplice;
	syscall_table[__NR_move_pages] = (unsigned long *)ref_sys_move_pages;
	syscall_table[__NR_utimensat] = (unsigned long *)ref_sys_utimensat;
	syscall_table[__NR_epoll_pwait] = (unsigned long *)ref_sys_epoll_pwait;
	syscall_table[__NR_signalfd] = (unsigned long *)ref_sys_signalfd;
	syscall_table[__NR_timerfd_create] = (unsigned long *)ref_sys_timerfd_create;
	syscall_table[__NR_eventfd] = (unsigned long *)ref_sys_eventfd;
	syscall_table[__NR_fallocate] = (unsigned long *)ref_sys_fallocate;
	syscall_table[__NR_timerfd_settime] = (unsigned long *)ref_sys_timerfd_settime;
	syscall_table[__NR_timerfd_gettime] = (unsigned long *)ref_sys_timerfd_gettime;
	syscall_table[__NR_accept4] = (unsigned long *)ref_sys_accept4;
	syscall_table[__NR_signalfd4] = (unsigned long *)ref_sys_signalfd4;
	syscall_table[__NR_eventfd2] = (unsigned long *)ref_sys_eventfd2;
	syscall_table[__NR_epoll_create1] = (unsigned long *)ref_sys_epoll_create1;
	syscall_table[__NR_dup3] = (unsigned long *)ref_sys_dup3;
	syscall_table[__NR_pipe2] = (unsigned long *)ref_sys_pipe2;
	syscall_table[__NR_inotify_init1] = (unsigned long *)ref_sys_inotify_init1;
	syscall_table[__NR_preadv] = (unsigned long *)ref_sys_preadv;
	syscall_table[__NR_pwritev] = (unsigned long *)ref_sys_pwritev;
	syscall_table[__NR_rt_tgsigqueueinfo] = (unsigned long *)ref_sys_rt_tgsigqueueinfo;
	syscall_table[__NR_perf_event_open] = (unsigned long *)ref_sys_perf_event_open;
	syscall_table[__NR_recvmmsg] = (unsigned long *)ref_sys_recvmmsg;
	syscall_table[__NR_clock_adjtime] = (unsigned long *)ref_sys_clock_adjtime;
	syscall_table[__NR_syncfs] = (unsigned long *)ref_sys_syncfs;
	syscall_table[__NR_sendmmsg] = (unsigned long *)ref_sys_sendmmsg;
	syscall_table[__NR_process_vm_readv] = (unsigned long *)ref_sys_process_vm_readv;
	syscall_table[__NR_process_vm_writev] = (unsigned long *)ref_sys_process_vm_writev;
	*/
}
