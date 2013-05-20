#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <asm/unistd.h>

extern long sys_time(time_t __user *tloc);
extern long sys_stime(time_t __user *tptr);
extern long sys_gettimeofday(struct timeval __user *tv, struct timezone __user *tz);
extern long sys_settimeofday(struct timeval __user *tv, struct timezone __user *tz);
extern long sys_adjtimex(struct timex __user *txc_p);
extern long sys_times(struct tms __user *tbuf);
extern long sys_gettid(void);
extern long sys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp);
extern long sys_alarm(unsigned int seconds);
extern long sys_getpid(void);
extern long sys_getppid(void);
extern long sys_getuid(void);
extern long sys_geteuid(void);
extern long sys_getgid(void);
extern long sys_getegid(void);
extern long sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid);
extern long sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid);
extern long sys_getpgid(pid_t pid);
extern long sys_getpgrp(void);
extern long sys_getsid(pid_t pid);
extern long sys_getgroups(int gidsetsize, gid_t __user *grouplist);
extern long sys_setregid(gid_t rgid, gid_t egid);
extern long sys_setgid(gid_t gid);
extern long sys_setreuid(uid_t ruid, uid_t euid);
extern long sys_setuid(uid_t uid);
extern long sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);
extern long sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
extern long sys_setfsuid(uid_t uid);
extern long sys_setfsgid(gid_t gid);
extern long sys_setpgid(pid_t pid, pid_t pgid);
extern long sys_setsid(void);
extern long sys_setgroups(int gidsetsize, gid_t __user *grouplist);
extern long sys_acct(const char __user *name);
extern long sys_capget(cap_user_header_t header, cap_user_data_t dataptr);
extern long sys_capset(cap_user_header_t header, const cap_user_data_t data);
extern long sys_personality(unsigned int personality);
extern long sys_sigpending(old_sigset_t __user *set);
extern long sys_sigprocmask(int how, old_sigset_t __user *set, old_sigset_t __user *oset);
extern long sys_getitimer(int which, struct itimerval __user *value);
extern long sys_setitimer(int which, struct itimerval __user *value, struct itimerval __user *ovalue);
extern long sys_timer_create(clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user * created_timer_id);
extern long sys_timer_gettime(timer_t timer_id, struct itimerspec __user *setting);
extern long sys_timer_getoverrun(timer_t timer_id);
extern long sys_timer_settime(timer_t timer_id, int flags, const struct itimerspec __user *new_setting, struct itimerspec __user *old_setting);
extern long sys_timer_delete(timer_t timer_id);
extern long sys_clock_settime(clockid_t which_clock, const struct timespec __user *tp);
extern long sys_clock_gettime(clockid_t which_clock, struct timespec __user *tp);
extern long sys_clock_getres(clockid_t which_clock, struct timespec __user *tp);
extern long sys_clock_nanosleep(clockid_t which_clock, int flags, const struct timespec __user *rqtp, struct timespec __user *rmtp);
extern long sys_nice(int increment);
extern long sys_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param);
extern long sys_sched_setparam(pid_t pid, struct sched_param __user *param);
extern long sys_sched_getscheduler(pid_t pid);
extern long sys_sched_getparam(pid_t pid, struct sched_param __user *param);
extern long sys_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
extern long sys_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
extern long sys_sched_yield(void);
extern long sys_sched_get_priority_max(int policy);
extern long sys_sched_get_priority_min(int policy);
extern long sys_sched_rr_get_interval(pid_t pid, struct timespec __user *interval);
extern long sys_setpriority(int which, int who, int niceval);
extern long sys_getpriority(int which, int who);
extern long sys_shutdown(int, int);
extern long sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg);
extern long sys_restart_syscall(void);
extern long sys_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags);
extern long sys_exit(int error_code);
extern long sys_exit_group(int error_code);
extern long sys_wait4(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru);
extern long sys_waitid(int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru);
extern long sys_waitpid(pid_t pid, int __user *stat_addr, int options);
extern long sys_set_tid_address(int __user *tidptr);
extern long sys_futex(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3);
extern long sys_init_module(void __user *umod, unsigned long len, const char __user *uargs);
extern long sys_delete_module(const char __user *name_user, unsigned int flags);
extern long sys_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize);
extern long sys_rt_sigpending(sigset_t __user *set, size_t sigsetsize);
extern long sys_rt_sigtimedwait(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize);
extern long sys_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig, siginfo_t __user *uinfo);
extern long sys_kill(int pid, int sig);
extern long sys_tgkill(int tgid, int pid, int sig);
extern long sys_tkill(int pid, int sig);
extern long sys_rt_sigqueueinfo(int pid, int sig, siginfo_t __user *uinfo);
extern long sys_sgetmask(void);
extern long sys_ssetmask(int newmask);
extern long sys_signal(int sig, __sighandler_t handler);
extern long sys_pause(void);
extern long sys_sync(void);
extern long sys_fsync(unsigned int fd);
extern long sys_fdatasync(unsigned int fd);
extern long sys_bdflush(int func, long data);
extern long sys_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data);
extern long sys_umount(char __user *name, int flags);
extern long sys_oldumount(char __user *name);
extern long sys_truncate(const char __user *path, long length);
extern long sys_ftruncate(unsigned int fd, unsigned long length);
extern long sys_stat(char __user *filename, struct __old_kernel_stat __user *statbuf);
extern long sys_statfs(const char __user * path, struct statfs __user *buf);
extern long sys_statfs64(const char __user *path, size_t sz, struct statfs64 __user *buf);
extern long sys_fstatfs(unsigned int fd, struct statfs __user *buf);
extern long sys_fstatfs64(unsigned int fd, size_t sz, struct statfs64 __user *buf);
extern long sys_lstat(char __user *filename, struct __old_kernel_stat __user *statbuf);
extern long sys_fstat(unsigned int fd, struct __old_kernel_stat __user *statbuf);
extern long sys_newstat(char __user *filename, struct stat __user *statbuf);
extern long sys_newlstat(char __user *filename, struct stat __user *statbuf);
extern long sys_newfstat(unsigned int fd, struct stat __user *statbuf);
extern long sys_ustat(unsigned dev, struct ustat __user *ubuf);
extern long sys_stat64(char __user *filename, struct stat64 __user *statbuf);
extern long sys_fstat64(unsigned long fd, struct stat64 __user *statbuf);
extern long sys_lstat64(char __user *filename, struct stat64 __user *statbuf);
extern long sys_truncate64(const char __user *path, loff_t length);
extern long sys_ftruncate64(unsigned int fd, loff_t length);
extern long sys_setxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);
extern long sys_lsetxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);
extern long sys_fsetxattr(int fd, const char __user *name, const void __user *value, size_t size, int flags);
extern long sys_getxattr(const char __user *path, const char __user *name, void __user *value, size_t size);
extern long sys_lgetxattr(const char __user *path, const char __user *name, void __user *value, size_t size);
extern long sys_fgetxattr(int fd, const char __user *name, void __user *value, size_t size);
extern long sys_listxattr(const char __user *path, char __user *list, size_t size);
extern long sys_llistxattr(const char __user *path, char __user *list, size_t size);
extern long sys_flistxattr(int fd, char __user *list, size_t size);
extern long sys_removexattr(const char __user *path, const char __user *name);
extern long sys_lremovexattr(const char __user *path, const char __user *name);
extern long sys_fremovexattr(int fd, const char __user *name);
extern long sys_brk(unsigned long brk);
extern long sys_mprotect(unsigned long start, size_t len, unsigned long prot);
extern long sys_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr);
extern long sys_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);
extern long sys_msync(unsigned long start, size_t len, int flags);
extern long sys_fadvise64(int fd, loff_t offset, size_t len, int advice);
extern long sys_fadvise64_64(int fd, loff_t offset, loff_t len, int advice);
extern long sys_munmap(unsigned long addr, size_t len);
extern long sys_mlock(unsigned long start, size_t len);
extern long sys_munlock(unsigned long start, size_t len);
extern long sys_mlockall(int flags);
extern long sys_munlockall(void);
extern long sys_madvise(unsigned long start, size_t len, int behavior);
extern long sys_mincore(unsigned long start, size_t len, unsigned char __user * vec);
extern long sys_pivot_root(const char __user *new_root, const char __user *put_old);
extern long sys_chroot(const char __user *filename);
extern long sys_mknod(const char __user *filename, int mode, unsigned dev);
extern long sys_link(const char __user *oldname, const char __user *newname);
extern long sys_symlink(const char __user *old, const char __user *new);
extern long sys_unlink(const char __user *pathname);
extern long sys_rename(const char __user *oldname, const char __user *newname);
extern long sys_chmod(const char __user *filename, mode_t mode);
extern long sys_fchmod(unsigned int fd, mode_t mode);
extern long sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
extern long sys_fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg);
extern long sys_pipe(int __user *fildes);
extern long sys_pipe2(int __user *fildes, int flags);
extern long sys_dup(unsigned int fildes);
extern long sys_dup2(unsigned int oldfd, unsigned int newfd);
extern long sys_dup3(unsigned int oldfd, unsigned int newfd, int flags);
extern long sys_ioperm(unsigned long from, unsigned long num, int on);
extern long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
extern long sys_flock(unsigned int fd, unsigned int cmd);
extern long sys_io_setup(unsigned nr_reqs, aio_context_t __user *ctx);
extern long sys_io_destroy(aio_context_t ctx);
extern long sys_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout);
extern long sys_io_submit(aio_context_t, long, struct iocb __user * __user *);
extern long sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result);
extern long sys_sendfile(int out_fd, int in_fd, off_t __user *offset, size_t count);
extern long sys_sendfile64(int out_fd, int in_fd, loff_t __user *offset, size_t count);
extern long sys_readlink(const char __user *path, char __user *buf, int bufsiz);
extern long sys_creat(const char __user *pathname, int mode);
extern long sys_open(const char __user *filename, int flags, int mode);
extern long sys_close(unsigned int fd);
extern long sys_access(const char __user *filename, int mode);
extern long sys_vhangup(void);
extern long sys_chown(const char __user *filename, uid_t user, gid_t group);
extern long sys_lchown(const char __user *filename, uid_t user, gid_t group);
extern long sys_fchown(unsigned int fd, uid_t user, gid_t group);
extern long sys_chown16(const char __user *filename, old_uid_t user, old_gid_t group);
extern long sys_lchown16(const char __user *filename, old_uid_t user, old_gid_t group);
extern long sys_fchown16(unsigned int fd, old_uid_t user, old_gid_t group);
extern long sys_setregid16(old_gid_t rgid, old_gid_t egid);
extern long sys_setgid16(old_gid_t gid);
extern long sys_setreuid16(old_uid_t ruid, old_uid_t euid);
extern long sys_setuid16(old_uid_t uid);
extern long sys_setresuid16(old_uid_t ruid, old_uid_t euid, old_uid_t suid);
extern long sys_getresuid16(old_uid_t __user *ruid, old_uid_t __user *euid, old_uid_t __user *suid);
extern long sys_setresgid16(old_gid_t rgid, old_gid_t egid, old_gid_t sgid);
extern long sys_getresgid16(old_gid_t __user *rgid, old_gid_t __user *egid, old_gid_t __user *sgid);
extern long sys_setfsuid16(old_uid_t uid);
extern long sys_setfsgid16(old_gid_t gid);
extern long sys_getgroups16(int gidsetsize, old_gid_t __user *grouplist);
extern long sys_setgroups16(int gidsetsize, old_gid_t __user *grouplist);
extern long sys_getuid16(void);
extern long sys_geteuid16(void);
extern long sys_getgid16(void);
extern long sys_getegid16(void);
extern long sys_utime(char __user *filename, struct utimbuf __user *times);
extern long sys_utimes(char __user *filename, struct timeval __user *utimes);
extern long sys_lseek(unsigned int fd, off_t offset, unsigned int origin);
extern long sys_llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int origin);
extern long sys_read(unsigned int fd, char __user *buf, size_t count);
extern long sys_readahead(int fd, loff_t offset, size_t count);
extern long sys_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
extern long sys_write(unsigned int fd, const char __user *buf, size_t count);
extern long sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
extern long sys_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos);
extern long sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
extern long sys_preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
extern long sys_pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
extern long sys_getcwd(char __user *buf, unsigned long size);
extern long sys_mkdir(const char __user *pathname, int mode);
extern long sys_chdir(const char __user *filename);
extern long sys_fchdir(unsigned int fd);
extern long sys_rmdir(const char __user *pathname);
extern long sys_lookup_dcookie(u64 cookie64, char __user *buf, size_t len);
extern long sys_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr);
extern long sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
extern long sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
extern long sys_setsockopt(int fd, int level, int optname, char __user *optval, int optlen);
extern long sys_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen);
extern long sys_bind(int, struct sockaddr __user *, int);
extern long sys_connect(int, struct sockaddr __user *, int);
extern long sys_accept(int, struct sockaddr __user *, int __user *);
extern long sys_accept4(int, struct sockaddr __user *, int __user *, int);
extern long sys_getsockname(int, struct sockaddr __user *, int __user *);
extern long sys_getpeername(int, struct sockaddr __user *, int __user *);
extern long sys_send(int, void __user *, size_t, unsigned);
extern long sys_sendto(int, void __user *, size_t, unsigned, struct sockaddr __user *, int);
extern long sys_sendmsg(int fd, struct msghdr __user *msg, unsigned flags);
extern long sys_recv(int, void __user *, size_t, unsigned);
extern long sys_recvfrom(int, void __user *, size_t, unsigned, struct sockaddr __user *, int __user *);
extern long sys_recvmsg(int fd, struct msghdr __user *msg, unsigned flags);
extern long sys_socket(int, int, int);
extern long sys_socketpair(int, int, int, int __user *);
extern long sys_socketcall(int call, unsigned long __user *args);
extern long sys_listen(int, int);
extern long sys_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout);
extern long sys_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp);
extern long sys_epoll_create(int size);
extern long sys_epoll_create1(int flags);
extern long sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event);
extern long sys_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout);
extern long sys_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize);
extern long sys_gethostname(char __user *name, int len);
extern long sys_sethostname(char __user *name, int len);
extern long sys_setdomainname(char __user *name, int len);
extern long sys_newuname(struct new_utsname __user *name);
extern long sys_getrlimit(unsigned int resource, struct rlimit __user *rlim);
extern long sys_old_getrlimit(unsigned int resource, struct rlimit __user *rlim);
extern long sys_setrlimit(unsigned int resource, struct rlimit __user *rlim);
extern long sys_getrusage(int who, struct rusage __user *ru);
extern long sys_umask(int mask);
extern long sys_msgget(key_t key, int msgflg);
extern long sys_msgsnd(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg);
extern long sys_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg);
extern long sys_msgctl(int msqid, int cmd, struct msqid_ds __user *buf);
extern long sys_semget(key_t key, int nsems, int semflg);
extern long sys_semop(int semid, struct sembuf __user *sops, unsigned nsops);
extern long sys_semctl(int semid, int semnum, int cmd, union semun arg);
extern long sys_semtimedop(int semid, struct sembuf __user *sops, unsigned nsops, const struct timespec __user *timeout);
extern long sys_shmat(int shmid, char __user *shmaddr, int shmflg);
extern long sys_shmget(key_t key, size_t size, int flag);
extern long sys_shmdt(char __user *shmaddr);
extern long sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf);
extern long sys_mq_open(const char __user *name, int oflag, mode_t mode, struct mq_attr __user *attr);
extern long sys_mq_unlink(const char __user *name);
extern long sys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout);
extern long sys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout);
extern long sys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification);
extern long sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat);
extern long sys_pciconfig_iobase(long which, unsigned long bus, unsigned long devfn);
extern long sys_pciconfig_read(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user *buf);
extern long sys_pciconfig_write(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user *buf);
extern long sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
extern long sys_swapon(const char __user *specialfile, int swap_flags);
extern long sys_swapoff(const char __user *specialfile);
extern long sys_sysctl(struct __sysctl_args __user *args);
extern long sys_sysinfo(struct sysinfo __user *info);
extern long sys_sysfs(int option, unsigned long arg1, unsigned long arg2);
extern long sys_nfsservctl(int cmd, struct nfsctl_arg __user *arg, void __user *res);
extern long sys_syslog(int type, char __user *buf, int len);
extern long sys_uselib(const char __user *library);
extern long sys_ni_syscall(void);
extern long sys_ptrace(long request, long pid, long addr, long data);
extern long sys_add_key(const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t destringid);
extern long sys_request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid);
extern long sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
extern long sys_ioprio_set(int which, int who, int ioprio);
extern long sys_ioprio_get(int which, int who);
extern long sys_set_mempolicy(int mode, unsigned long __user *nmask, unsigned long maxnode);
extern long sys_migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to);
extern long sys_move_pages(pid_t pid, unsigned long nr_pages,	const void __user * __user *pages, const int __user *nodes, int __user *status,	int flags);
extern long sys_mbind(unsigned long start, unsigned long len,	unsigned long mode,	unsigned long __user *nmask, unsigned long maxnode,	unsigned flags);
extern long sys_get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);
extern long sys_inotify_init(void);
extern long sys_inotify_init1(int flags);
extern long sys_inotify_add_watch(int fd, const char __user *path, u32 mask);
extern long sys_inotify_rm_watch(int fd, __s32 wd);
extern long sys_spu_run(int fd, __u32 __user *unpc, __u32 __user *ustatus);
extern long sys_spu_create(const char __user *name, unsigned int flags, mode_t mode, int fd);
extern long sys_mknodat(int dfd, const char __user * filename, int mode, unsigned dev);
extern long sys_mkdirat(int dfd, const char __user * pathname, int mode);
extern long sys_unlinkat(int dfd, const char __user * pathname, int flag);
extern long sys_symlinkat(const char __user * oldname, int newdfd, const char __user * newname);
extern long sys_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags);
extern long sys_renameat(int olddfd, const char __user * oldname, int newdfd, const char __user * newname);
extern long sys_futimesat(int dfd, char __user *filename, struct timeval __user *utimes);
extern long sys_faccessat(int dfd, const char __user *filename, int mode);
extern long sys_fchmodat(int dfd, const char __user * filename, mode_t mode);
extern long sys_fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag);
extern long sys_openat(int dfd, const char __user *filename, int flags, int mode);
extern long sys_newfstatat(int dfd, char __user *filename, struct stat __user *statbuf, int flag);
extern long sys_fstatat64(int dfd, char __user *filename, struct stat64 __user *statbuf, int flag);
extern long sys_readlinkat(int dfd, const char __user *path, char __user *buf, int bufsiz);
extern long sys_utimensat(int dfd, char __user *filename,	struct timespec __user *utimes, int flags);
extern long sys_unshare(unsigned long unshare_flags);
extern long sys_splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);
extern long sys_vmsplice(int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags);
extern long sys_tee(int fdin, int fdout, size_t len, unsigned int flags);
extern long sys_sync_file_range(int fd, loff_t offset, loff_t nbytes,	unsigned int flags);
extern long sys_sync_file_range2(int fd, unsigned int flags, loff_t offset, loff_t nbytes);
extern long sys_get_robust_list(int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr);
extern long sys_set_robust_list(struct robust_list_head __user *head, size_t len);
extern long sys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache);
extern long sys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask);
extern long sys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags);
extern long sys_timerfd_create(int clockid, int flags);
extern long sys_timerfd_settime(int ufd, int flags, const struct itimerspec __user *utmr, struct itimerspec __user *otmr);
extern long sys_timerfd_gettime(int ufd, struct itimerspec __user *otmr);
extern long sys_eventfd(unsigned int count);
extern long sys_eventfd2(unsigned int count, int flags);
extern long sys_fallocate(int fd, int mode, loff_t offset, loff_t len);
extern long sys_old_readdir(unsigned int, struct old_linux_dirent __user *, unsigned int);
extern long sys_pselect6(int, fd_set __user *, fd_set __user *, fd_set __user *, struct timespec __user *, void __user *);
extern long sys_ppoll(struct pollfd __user *, unsigned int, struct timespec __user *, const sigset_t __user *, size_t);
extern long sys_perf_event_open(struct perf_event_attr __user *attr_uptr,	pid_t pid, int cpu, int group_fd, unsigned long flags);
extern long sys_mmap_pgoff(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);
long hook_sys_time(time_t __user *tloc)
{
	long retval = sys_time(tloc);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_time = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_stime(time_t __user *tptr)
{
	long retval = sys_stime(tptr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_stime = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_gettimeofday(struct timeval __user *tv, struct timezone __user *tz)
{
	long retval = sys_gettimeofday(tv, tz);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_gettimeofday = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_settimeofday(struct timeval __user *tv, struct timezone __user *tz)
{
	long retval = sys_settimeofday(tv, tz);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_settimeofday = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_adjtimex(struct timex __user *txc_p)
{
	long retval = sys_adjtimex(txc_p);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_adjtimex = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_times(struct tms __user *tbuf)
{
	long retval = sys_times(tbuf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_times = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_gettid(void)
{
	long retval = sys_gettid();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_gettid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp)
{
	long retval = sys_nanosleep(rqtp, rmtp);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_nanosleep = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_alarm(unsigned int seconds)
{
	long retval = sys_alarm(seconds);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_alarm = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getpid(void)
{
	long retval = sys_getpid();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getpid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getppid(void)
{
	long retval = sys_getppid();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getppid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getuid(void)
{
	long retval = sys_getuid();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getuid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_geteuid(void)
{
	long retval = sys_geteuid();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_geteuid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getgid(void)
{
	long retval = sys_getgid();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getgid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getegid(void)
{
	long retval = sys_getegid();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getegid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid)
{
	long retval = sys_getresuid(ruid, euid, suid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getresuid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid)
{
	long retval = sys_getresgid(rgid, egid, sgid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getresgid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getpgid(pid_t pid)
{
	long retval = sys_getpgid(pid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getpgid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getpgrp(void)
{
	long retval = sys_getpgrp();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getpgrp = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getsid(pid_t pid)
{
	long retval = sys_getsid(pid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getsid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getgroups(int gidsetsize, gid_t __user *grouplist)
{
	long retval = sys_getgroups(gidsetsize, grouplist);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getgroups = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setregid(gid_t rgid, gid_t egid)
{
	long retval = sys_setregid(rgid, egid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setregid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setgid(gid_t gid)
{
	long retval = sys_setgid(gid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setgid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setreuid(uid_t ruid, uid_t euid)
{
	long retval = sys_setreuid(ruid, euid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setreuid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setuid(uid_t uid)
{
	long retval = sys_setuid(uid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setuid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	long retval = sys_setresuid(ruid, euid, suid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setresuid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	long retval = sys_setresgid(rgid, egid, sgid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setresgid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setfsuid(uid_t uid)
{
	long retval = sys_setfsuid(uid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setfsuid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setfsgid(gid_t gid)
{
	long retval = sys_setfsgid(gid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setfsgid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setpgid(pid_t pid, pid_t pgid)
{
	long retval = sys_setpgid(pid, pgid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setpgid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setsid(void)
{
	long retval = sys_setsid();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setsid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setgroups(int gidsetsize, gid_t __user *grouplist)
{
	long retval = sys_setgroups(gidsetsize, grouplist);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setgroups = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_acct(const char __user *name)
{
	long retval = sys_acct(name);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_acct = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_capget(cap_user_header_t header, cap_user_data_t dataptr)
{
	long retval = sys_capget(header, dataptr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_capget = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_capset(cap_user_header_t header, const cap_user_data_t data)
{
	long retval = sys_capset(header, data);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_capset = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_personality(u_long personality)
{
	long retval = sys_personality(personality);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_personality = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sigpending(old_sigset_t __user *set)
{
	long retval = sys_sigpending(set);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sigpending = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sigprocmask(int how, old_sigset_t __user *set, old_sigset_t __user *oset)
{
	long retval = sys_sigprocmask(how, set, oset);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sigprocmask = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getitimer(int which, struct itimerval __user *value)
{
	long retval = sys_getitimer(which, value);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getitimer = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setitimer(int which, struct itimerval __user *value, struct itimerval __user *ovalue)
{
	long retval = sys_setitimer(which, value, ovalue);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setitimer = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_timer_create(clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user * created_timer_id)
{
	long retval = sys_timer_create(which_clock, timer_event_spec, created_timer_id);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_timer_create = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_timer_gettime(timer_t timer_id, struct itimerspec __user *setting)
{
	long retval = sys_timer_gettime(timer_id, setting);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_timer_gettime = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_timer_getoverrun(timer_t timer_id)
{
	long retval = sys_timer_getoverrun(timer_id);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_timer_getoverrun = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_timer_settime(timer_t timer_id, int flags, const struct itimerspec __user *new_setting, struct itimerspec __user *old_setting)
{
	long retval = sys_timer_settime(timer_id, flags, new_setting, old_setting);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_timer_settime = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_timer_delete(timer_t timer_id)
{
	long retval = sys_timer_delete(timer_id);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_timer_delete = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_clock_settime(clockid_t which_clock, const struct timespec __user *tp)
{
	long retval = sys_clock_settime(which_clock, tp);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_clock_settime = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_clock_gettime(clockid_t which_clock, struct timespec __user *tp)
{
	long retval = sys_clock_gettime(which_clock, tp);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_clock_gettime = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_clock_getres(clockid_t which_clock, struct timespec __user *tp)
{
	long retval = sys_clock_getres(which_clock, tp);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_clock_getres = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_clock_nanosleep(clockid_t which_clock, int flags, const struct timespec __user *rqtp, struct timespec __user *rmtp)
{
	long retval = sys_clock_nanosleep(which_clock, flags, rqtp, rmtp);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_clock_nanosleep = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_nice(int increment)
{
	long retval = sys_nice(increment);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_nice = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param)
{
	long retval = sys_sched_setscheduler(pid, policy, param);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sched_setscheduler = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sched_setparam(pid_t pid, struct sched_param __user *param)
{
	long retval = sys_sched_setparam(pid, param);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sched_setparam = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sched_getscheduler(pid_t pid)
{
	long retval = sys_sched_getscheduler(pid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sched_getscheduler = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sched_getparam(pid_t pid, struct sched_param __user *param)
{
	long retval = sys_sched_getparam(pid, param);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sched_getparam = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	long retval = sys_sched_setaffinity(pid, len, user_mask_ptr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sched_setaffinity = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	long retval = sys_sched_getaffinity(pid, len, user_mask_ptr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sched_getaffinity = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sched_yield(void)
{
	long retval = sys_sched_yield();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sched_yield = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sched_get_priority_max(int policy)
{
	long retval = sys_sched_get_priority_max(policy);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sched_get_priority_max = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sched_get_priority_min(int policy)
{
	long retval = sys_sched_get_priority_min(policy);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sched_get_priority_min = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sched_rr_get_interval(pid_t pid, struct timespec __user *interval)
{
	long retval = sys_sched_rr_get_interval(pid, interval);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sched_rr_get_interval = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setpriority(int which, int who, int niceval)
{
	long retval = sys_setpriority(which, who, niceval);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setpriority = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getpriority(int which, int who)
{
	long retval = sys_getpriority(which, who);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getpriority = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_shutdown(int arg0, int arg1)
{
	long retval = sys_shutdown(arg0, arg1);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_shutdown = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	long retval = sys_reboot(magic1, magic2, cmd, arg);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_reboot = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_restart_syscall(void)
{
	long retval = sys_restart_syscall();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_restart_syscall = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags)
{
	long retval = sys_kexec_load(entry, nr_segments, segments, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_kexec_load = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_exit(int error_code)
{
	long retval = sys_exit(error_code);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_exit = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_exit_group(int error_code)
{
	long retval = sys_exit_group(error_code);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_exit_group = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_wait4(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru)
{
	long retval = sys_wait4(pid, stat_addr, options, ru);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_wait4 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_waitid(int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru)
{
	long retval = sys_waitid(which, pid, infop, options, ru);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_waitid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_waitpid(pid_t pid, int __user *stat_addr, int options)
{
	long retval = sys_waitpid(pid, stat_addr, options);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_waitpid = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_set_tid_address(int __user *tidptr)
{
	long retval = sys_set_tid_address(tidptr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_set_tid_address = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_futex(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
	long retval = sys_futex(uaddr, op, val, utime, uaddr2, val3);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_futex = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_init_module(void __user *umod, unsigned long len, const char __user *uargs)
{
	long retval = sys_init_module(umod, len, uargs);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_init_module = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_delete_module(const char __user *name_user, unsigned int flags)
{
	long retval = sys_delete_module(name_user, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_delete_module = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
	long retval = sys_rt_sigprocmask(how, set, oset, sigsetsize);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_rt_sigprocmask = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_rt_sigpending(sigset_t __user *set, size_t sigsetsize)
{
	long retval = sys_rt_sigpending(set, sigsetsize);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_rt_sigpending = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_rt_sigtimedwait(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize)
{
	long retval = sys_rt_sigtimedwait(uthese, uinfo, uts, sigsetsize);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_rt_sigtimedwait = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig, siginfo_t __user *uinfo)
{
	long retval = sys_rt_tgsigqueueinfo(tgid, pid, sig, uinfo);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_rt_tgsigqueueinfo = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_kill(int pid, int sig)
{
	long retval = sys_kill(pid, sig);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_kill = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_tgkill(int tgid, int pid, int sig)
{
	long retval = sys_tgkill(tgid, pid, sig);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_tgkill = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_tkill(int pid, int sig)
{
	long retval = sys_tkill(pid, sig);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_tkill = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_rt_sigqueueinfo(int pid, int sig, siginfo_t __user *uinfo)
{
	long retval = sys_rt_sigqueueinfo(pid, sig, uinfo);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_rt_sigqueueinfo = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sgetmask(void)
{
	long retval = sys_sgetmask();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sgetmask = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_ssetmask(int newmask)
{
	long retval = sys_ssetmask(newmask);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_ssetmask = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_signal(int sig, __sighandler_t handler)
{
	long retval = sys_signal(sig, handler);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_signal = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_pause(void)
{
	long retval = sys_pause();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_pause = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sync(void)
{
	long retval = sys_sync();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sync = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fsync(unsigned int fd)
{
	long retval = sys_fsync(fd);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fsync = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fdatasync(unsigned int fd)
{
	long retval = sys_fdatasync(fd);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fdatasync = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_bdflush(int func, long data)
{
	long retval = sys_bdflush(func, data);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_bdflush = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data)
{
	long retval = sys_mount(dev_name, dir_name, type, flags, data);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mount = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_umount(char __user *name, int flags)
{
	long retval = sys_umount(name, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_umount = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_oldumount(char __user *name)
{
	long retval = sys_oldumount(name);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_oldumount = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_truncate(const char __user *path, long length)
{
	long retval = sys_truncate(path, length);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_truncate = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_ftruncate(unsigned int fd, unsigned long length)
{
	long retval = sys_ftruncate(fd, length);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_ftruncate = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_stat(char __user *filename, struct __old_kernel_stat __user *statbuf)
{
	long retval = sys_stat(filename, statbuf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_stat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_statfs(const char __user * path, struct statfs __user *buf)
{
	long retval = sys_statfs(path, buf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_statfs = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_statfs64(const char __user *path, size_t sz, struct statfs64 __user *buf)
{
	long retval = sys_statfs64(path, sz, buf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_statfs64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fstatfs(unsigned int fd, struct statfs __user *buf)
{
	long retval = sys_fstatfs(fd, buf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fstatfs = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fstatfs64(unsigned int fd, size_t sz, struct statfs64 __user *buf)
{
	long retval = sys_fstatfs64(fd, sz, buf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fstatfs64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_lstat(char __user *filename, struct __old_kernel_stat __user *statbuf)
{
	long retval = sys_lstat(filename, statbuf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_lstat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fstat(unsigned int fd, struct __old_kernel_stat __user *statbuf)
{
	long retval = sys_fstat(fd, statbuf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fstat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_newstat(char __user *filename, struct stat __user *statbuf)
{
	long retval = sys_newstat(filename, statbuf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_newstat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_newlstat(char __user *filename, struct stat __user *statbuf)
{
	long retval = sys_newlstat(filename, statbuf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_newlstat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_newfstat(unsigned int fd, struct stat __user *statbuf)
{
	long retval = sys_newfstat(fd, statbuf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_newfstat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_ustat(unsigned dev, struct ustat __user *ubuf)
{
	long retval = sys_ustat(dev, ubuf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_ustat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_stat64(char __user *filename, struct stat64 __user *statbuf)
{
	long retval = sys_stat64(filename, statbuf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_stat64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fstat64(unsigned long fd, struct stat64 __user *statbuf)
{
	long retval = sys_fstat64(fd, statbuf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fstat64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_lstat64(char __user *filename, struct stat64 __user *statbuf)
{
	long retval = sys_lstat64(filename, statbuf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_lstat64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_truncate64(const char __user *path, loff_t length)
{
	long retval = sys_truncate64(path, length);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_truncate64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_ftruncate64(unsigned int fd, loff_t length)
{
	long retval = sys_ftruncate64(fd, length);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_ftruncate64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags)
{
	long retval = sys_setxattr(path, name, value, size, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setxattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_lsetxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags)
{
	long retval = sys_lsetxattr(path, name, value, size, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_lsetxattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fsetxattr(int fd, const char __user *name, const void __user *value, size_t size, int flags)
{
	long retval = sys_fsetxattr(fd, name, value, size, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fsetxattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getxattr(const char __user *path, const char __user *name, void __user *value, size_t size)
{
	long retval = sys_getxattr(path, name, value, size);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getxattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_lgetxattr(const char __user *path, const char __user *name, void __user *value, size_t size)
{
	long retval = sys_lgetxattr(path, name, value, size);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_lgetxattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fgetxattr(int fd, const char __user *name, void __user *value, size_t size)
{
	long retval = sys_fgetxattr(fd, name, value, size);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fgetxattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_listxattr(const char __user *path, char __user *list, size_t size)
{
	long retval = sys_listxattr(path, list, size);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_listxattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_llistxattr(const char __user *path, char __user *list, size_t size)
{
	long retval = sys_llistxattr(path, list, size);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_llistxattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_flistxattr(int fd, char __user *list, size_t size)
{
	long retval = sys_flistxattr(fd, list, size);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_flistxattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_removexattr(const char __user *path, const char __user *name)
{
	long retval = sys_removexattr(path, name);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_removexattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_lremovexattr(const char __user *path, const char __user *name)
{
	long retval = sys_lremovexattr(path, name);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_lremovexattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fremovexattr(int fd, const char __user *name)
{
	long retval = sys_fremovexattr(fd, name);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fremovexattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_brk(unsigned long brk)
{
	long retval = sys_brk(brk);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_brk = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mprotect(unsigned long start, size_t len, unsigned long prot)
{
	long retval = sys_mprotect(start, len, prot);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mprotect = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
	long retval = sys_mremap(addr, old_len, new_len, flags, new_addr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mremap = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)
{
	long retval = sys_remap_file_pages(start, size, prot, pgoff, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_remap_file_pages = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_msync(unsigned long start, size_t len, int flags)
{
	long retval = sys_msync(start, len, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_msync = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fadvise64(int fd, loff_t offset, size_t len, int advice)
{
	long retval = sys_fadvise64(fd, offset, len, advice);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fadvise64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fadvise64_64(int fd, loff_t offset, loff_t len, int advice)
{
	long retval = sys_fadvise64_64(fd, offset, len, advice);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fadvise64_64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_munmap(unsigned long addr, size_t len)
{
	long retval = sys_munmap(addr, len);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_munmap = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mlock(unsigned long start, size_t len)
{
	long retval = sys_mlock(start, len);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mlock = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_munlock(unsigned long start, size_t len)
{
	long retval = sys_munlock(start, len);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_munlock = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mlockall(int flags)
{
	long retval = sys_mlockall(flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mlockall = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_munlockall(void)
{
	long retval = sys_munlockall();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_munlockall = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_madvise(unsigned long start, size_t len, int behavior)
{
	long retval = sys_madvise(start, len, behavior);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_madvise = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mincore(unsigned long start, size_t len, unsigned char __user * vec)
{
	long retval = sys_mincore(start, len, vec);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mincore = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_pivot_root(const char __user *new_root, const char __user *put_old)
{
	long retval = sys_pivot_root(new_root, put_old);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_pivot_root = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_chroot(const char __user *filename)
{
	long retval = sys_chroot(filename);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_chroot = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mknod(const char __user *filename, int mode, unsigned dev)
{
	long retval = sys_mknod(filename, mode, dev);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mknod = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_link(const char __user *oldname, const char __user *newname)
{
	long retval = sys_link(oldname, newname);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_link = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_symlink(const char __user *old, const char __user *new)
{
	long retval = sys_symlink(old, new);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_symlink = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_unlink(const char __user *pathname)
{
	long retval = sys_unlink(pathname);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_unlink = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_rename(const char __user *oldname, const char __user *newname)
{
	long retval = sys_rename(oldname, newname);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_rename = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_chmod(const char __user *filename, mode_t mode)
{
	long retval = sys_chmod(filename, mode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_chmod = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fchmod(unsigned int fd, mode_t mode)
{
	long retval = sys_fchmod(fd, mode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fchmod = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	long retval = sys_fcntl(fd, cmd, arg);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fcntl = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	long retval = sys_fcntl64(fd, cmd, arg);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fcntl64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_pipe(int __user *fildes)
{
	long retval = sys_pipe(fildes);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_pipe = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_pipe2(int __user *fildes, int flags)
{
	long retval = sys_pipe2(fildes, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_pipe2 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_dup(unsigned int fildes)
{
	long retval = sys_dup(fildes);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_dup = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_dup2(unsigned int oldfd, unsigned int newfd)
{
	long retval = sys_dup2(oldfd, newfd);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_dup2 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_dup3(unsigned int oldfd, unsigned int newfd, int flags)
{
	long retval = sys_dup3(oldfd, newfd, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_dup3 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_ioperm(unsigned long from, unsigned long num, int on)
{
	long retval = sys_ioperm(from, num, on);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_ioperm = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	long retval = sys_ioctl(fd, cmd, arg);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_ioctl = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_flock(unsigned int fd, unsigned int cmd)
{
	long retval = sys_flock(fd, cmd);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_flock = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_io_setup(unsigned nr_reqs, aio_context_t __user *ctx)
{
	long retval = sys_io_setup(nr_reqs, ctx);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_io_setup = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_io_destroy(aio_context_t ctx)
{
	long retval = sys_io_destroy(ctx);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_io_destroy = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout)
{
	long retval = sys_io_getevents(ctx_id, min_nr, nr, events, timeout);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_io_getevents = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_io_submit(aio_context_t arg0, long arg1, struct iocb __user **arg2)
{
	long retval = sys_io_submit(arg0, arg1, arg2);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_io_submit = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result)
{
	long retval = sys_io_cancel(ctx_id, iocb, result);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_io_cancel = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sendfile(int out_fd, int in_fd, off_t __user *offset, size_t count)
{
	long retval = sys_sendfile(out_fd, in_fd, offset, count);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sendfile = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sendfile64(int out_fd, int in_fd, loff_t __user *offset, size_t count)
{
	long retval = sys_sendfile64(out_fd, in_fd, offset, count);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sendfile64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_readlink(const char __user *path, char __user *buf, int bufsiz)
{
	long retval = sys_readlink(path, buf, bufsiz);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_readlink = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_creat(const char __user *pathname, int mode)
{
	long retval = sys_creat(pathname, mode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_creat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_open(const char __user *filename, int flags, int mode)
{
	long retval = sys_open(filename, flags, mode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_open = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_close(unsigned int fd)
{
	long retval = sys_close(fd);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_close = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_access(const char __user *filename, int mode)
{
	long retval = sys_access(filename, mode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_access = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_vhangup(void)
{
	long retval = sys_vhangup();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_vhangup = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_chown(const char __user *filename, uid_t user, gid_t group)
{
	long retval = sys_chown(filename, user, group);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_chown = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_lchown(const char __user *filename, uid_t user, gid_t group)
{
	long retval = sys_lchown(filename, user, group);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_lchown = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fchown(unsigned int fd, uid_t user, gid_t group)
{
	long retval = sys_fchown(fd, user, group);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fchown = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_chown16(const char __user *filename, old_uid_t user, old_gid_t group)
{
	long retval = sys_chown16(filename, user, group);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_chown16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_lchown16(const char __user *filename, old_uid_t user, old_gid_t group)
{
	long retval = sys_lchown16(filename, user, group);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_lchown16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fchown16(unsigned int fd, old_uid_t user, old_gid_t group)
{
	long retval = sys_fchown16(fd, user, group);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fchown16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setregid16(old_gid_t rgid, old_gid_t egid)
{
	long retval = sys_setregid16(rgid, egid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setregid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setgid16(old_gid_t gid)
{
	long retval = sys_setgid16(gid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setgid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setreuid16(old_uid_t ruid, old_uid_t euid)
{
	long retval = sys_setreuid16(ruid, euid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setreuid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setuid16(old_uid_t uid)
{
	long retval = sys_setuid16(uid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setuid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setresuid16(old_uid_t ruid, old_uid_t euid, old_uid_t suid)
{
	long retval = sys_setresuid16(ruid, euid, suid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setresuid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getresuid16(old_uid_t __user *ruid, old_uid_t __user *euid, old_uid_t __user *suid)
{
	long retval = sys_getresuid16(ruid, euid, suid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getresuid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setresgid16(old_gid_t rgid, old_gid_t egid, old_gid_t sgid)
{
	long retval = sys_setresgid16(rgid, egid, sgid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setresgid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getresgid16(old_gid_t __user *rgid, old_gid_t __user *egid, old_gid_t __user *sgid)
{
	long retval = sys_getresgid16(rgid, egid, sgid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getresgid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setfsuid16(old_uid_t uid)
{
	long retval = sys_setfsuid16(uid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setfsuid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setfsgid16(old_gid_t gid)
{
	long retval = sys_setfsgid16(gid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setfsgid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getgroups16(int gidsetsize, old_gid_t __user *grouplist)
{
	long retval = sys_getgroups16(gidsetsize, grouplist);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getgroups16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setgroups16(int gidsetsize, old_gid_t __user *grouplist)
{
	long retval = sys_setgroups16(gidsetsize, grouplist);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setgroups16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getuid16(void)
{
	long retval = sys_getuid16();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getuid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_geteuid16(void)
{
	long retval = sys_geteuid16();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_geteuid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getgid16(void)
{
	long retval = sys_getgid16();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getgid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getegid16(void)
{
	long retval = sys_getegid16();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getegid16 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_utime(char __user *filename, struct utimbuf __user *times)
{
	long retval = sys_utime(filename, times);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_utime = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_utimes(char __user *filename, struct timeval __user *utimes)
{
	long retval = sys_utimes(filename, utimes);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_utimes = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_lseek(unsigned int fd, off_t offset, unsigned int origin)
{
	long retval = sys_lseek(fd, offset, origin);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_lseek = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int origin)
{
	long retval = sys_llseek(fd, offset_high, offset_low, result, origin);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_llseek = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_read(unsigned int fd, char __user *buf, size_t count)
{
	long retval = sys_read(fd, buf, count);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_read = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_readahead(int fd, loff_t offset, size_t count)
{
	long retval = sys_readahead(fd, offset, count);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_readahead = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
	long retval = sys_readv(fd, vec, vlen);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_readv = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
	long retval = sys_write(fd, buf, count);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_write = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
	long retval = sys_writev(fd, vec, vlen);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_writev = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos)
{
	long retval = sys_pread64(fd, buf, count, pos);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_pread64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos)
{
	long retval = sys_pwrite64(fd, buf, count, pos);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_pwrite64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
	long retval = sys_preadv(fd, vec, vlen, pos_l, pos_h);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_preadv = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
	long retval = sys_pwritev(fd, vec, vlen, pos_l, pos_h);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_pwritev = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getcwd(char __user *buf, unsigned long size)
{
	long retval = sys_getcwd(buf, size);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getcwd = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mkdir(const char __user *pathname, int mode)
{
	long retval = sys_mkdir(pathname, mode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mkdir = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_chdir(const char __user *filename)
{
	long retval = sys_chdir(filename);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_chdir = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fchdir(unsigned int fd)
{
	long retval = sys_fchdir(fd);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fchdir = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_rmdir(const char __user *pathname)
{
	long retval = sys_rmdir(pathname);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_rmdir = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_lookup_dcookie(u64 cookie64, char __user *buf, size_t len)
{
	long retval = sys_lookup_dcookie(cookie64, buf, len);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_lookup_dcookie = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr)
{
	long retval = sys_quotactl(cmd, special, id, addr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_quotactl = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
	long retval = sys_getdents(fd, dirent, count);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getdents = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
	long retval = sys_getdents64(fd, dirent, count);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getdents64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setsockopt(int fd, int level, int optname, char __user *optval, int optlen)
{
	long retval = sys_setsockopt(fd, level, optname, optval, optlen);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setsockopt = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
	long retval = sys_getsockopt(fd, level, optname, optval, optlen);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getsockopt = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_bind(int arg0, struct sockaddr __user *arg1, int arg2)
{
	long retval = sys_bind(arg0, arg1, arg2);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_bind = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_connect(int arg0, struct sockaddr __user *arg1, int arg2)
{
	long retval = sys_connect(arg0, arg1, arg2);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_connect = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_accept(int arg0, struct sockaddr __user *arg1, int __user *arg2)
{
	long retval = sys_accept(arg0, arg1, arg2);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_accept = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_accept4(int arg0, struct sockaddr __user *arg1, int __user *arg2, int arg3)
{
	long retval = sys_accept4(arg0, arg1, arg2, arg3);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_accept4 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getsockname(int arg0, struct sockaddr __user *arg1, int __user *arg2)
{
	long retval = sys_getsockname(arg0, arg1, arg2);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getsockname = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getpeername(int arg0, struct sockaddr __user *arg1, int __user *arg2)
{
	long retval = sys_getpeername(arg0, arg1, arg2);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getpeername = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_send(int arg0, void __user *arg1, size_t arg2, unsigned int arg3)
{
	long retval = sys_send(arg0, arg1, arg2, arg3);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_send = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sendto(int arg0, void __user *arg1, size_t arg2, unsigned int arg3, struct sockaddr __user *arg4, int arg5)
{
	long retval = sys_sendto(arg0, arg1, arg2, arg3, arg4, arg5);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sendto = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sendmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	long retval = sys_sendmsg(fd, msg, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sendmsg = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_recv(int arg0, void __user *arg1, size_t arg2, unsigned int arg3)
{
	long retval = sys_recv(arg0, arg1, arg2, arg3);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_recv = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_recvfrom(int arg0, void __user *arg1, size_t arg2, unsigned int arg3, struct sockaddr __user *arg4, int __user *arg5)
{
	long retval = sys_recvfrom(arg0, arg1, arg2, arg3, arg4, arg5);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_recvfrom = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_recvmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	long retval = sys_recvmsg(fd, msg, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_recvmsg = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_socket(int arg0, int arg1, int arg2)
{
	long retval = sys_socket(arg0, arg1, arg2);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_socket = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_socketpair(int arg0, int arg1, int arg2, int __user *arg3)
{
	long retval = sys_socketpair(arg0, arg1, arg2, arg3);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_socketpair = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_socketcall(int call, unsigned long __user *args)
{
	long retval = sys_socketcall(call, args);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_socketcall = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_listen(int arg0, int arg1)
{
	long retval = sys_listen(arg0, arg1);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_listen = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_poll(struct pollfd __user *ufds, unsigned int nfds, long timeout)
{
	long retval = sys_poll(ufds, nfds, timeout);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_poll = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
{
	long retval = sys_select(n, inp, outp, exp, tvp);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_select = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_epoll_create(int size)
{
	long retval = sys_epoll_create(size);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_epoll_create = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_epoll_create1(int flags)
{
	long retval = sys_epoll_create1(flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_epoll_create1 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event)
{
	long retval = sys_epoll_ctl(epfd, op, fd, event);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_epoll_ctl = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout)
{
	long retval = sys_epoll_wait(epfd, events, maxevents, timeout);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_epoll_wait = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize)
{
	long retval = sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_epoll_pwait = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_gethostname(char __user *name, int len)
{
	long retval = sys_gethostname(name, len);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_gethostname = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sethostname(char __user *name, int len)
{
	long retval = sys_sethostname(name, len);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sethostname = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setdomainname(char __user *name, int len)
{
	long retval = sys_setdomainname(name, len);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setdomainname = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_newuname(struct new_utsname __user *name)
{
	long retval = sys_newuname(name);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_newuname = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getrlimit(unsigned int resource, struct rlimit __user *rlim)
{
	long retval = sys_getrlimit(resource, rlim);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getrlimit = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_old_getrlimit(unsigned int resource, struct rlimit __user *rlim)
{
	long retval = sys_old_getrlimit(resource, rlim);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_old_getrlimit = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_setrlimit(unsigned int resource, struct rlimit __user *rlim)
{
	long retval = sys_setrlimit(resource, rlim);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_setrlimit = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getrusage(int who, struct rusage __user *ru)
{
	long retval = sys_getrusage(who, ru);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getrusage = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_umask(int mask)
{
	long retval = sys_umask(mask);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_umask = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_msgget(key_t key, int msgflg)
{
	long retval = sys_msgget(key, msgflg);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_msgget = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_msgsnd(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg)
{
	long retval = sys_msgsnd(msqid, msgp, msgsz, msgflg);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_msgsnd = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg)
{
	long retval = sys_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_msgrcv = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_msgctl(int msqid, int cmd, struct msqid_ds __user *buf)
{
	long retval = sys_msgctl(msqid, cmd, buf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_msgctl = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_semget(key_t key, int nsems, int semflg)
{
	long retval = sys_semget(key, nsems, semflg);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_semget = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_semop(int semid, struct sembuf __user *sops, unsigned nsops)
{
	long retval = sys_semop(semid, sops, nsops);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_semop = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_semctl(int semid, int semnum, int cmd, union semun arg)
{
	long retval = sys_semctl(semid, semnum, cmd, arg);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_semctl = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_semtimedop(int semid, struct sembuf __user *sops, unsigned nsops, const struct timespec __user *timeout)
{
	long retval = sys_semtimedop(semid, sops, nsops, timeout);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_semtimedop = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_shmat(int shmid, char __user *shmaddr, int shmflg)
{
	long retval = sys_shmat(shmid, shmaddr, shmflg);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_shmat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_shmget(key_t key, size_t size, int flag)
{
	long retval = sys_shmget(key, size, flag);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_shmget = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_shmdt(char __user *shmaddr)
{
	long retval = sys_shmdt(shmaddr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_shmdt = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
	long retval = sys_shmctl(shmid, cmd, buf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_shmctl = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mq_open(const char __user *name, int oflag, mode_t mode, struct mq_attr __user *attr)
{
	long retval = sys_mq_open(name, oflag, mode, attr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mq_open = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mq_unlink(const char __user *name)
{
	long retval = sys_mq_unlink(name);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mq_unlink = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout)
{
	long retval = sys_mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mq_timedsend = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout)
{
	long retval = sys_mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mq_timedreceive = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification)
{
	long retval = sys_mq_notify(mqdes, notification);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mq_notify = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat)
{
	long retval = sys_mq_getsetattr(mqdes, mqstat, omqstat);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mq_getsetattr = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_pciconfig_iobase(long which, unsigned long bus, unsigned long devfn)
{
	long retval = sys_pciconfig_iobase(which, bus, devfn);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_pciconfig_iobase = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_pciconfig_read(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user *buf)
{
	long retval = sys_pciconfig_read(bus, dfn, off, len, buf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_pciconfig_read = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_pciconfig_write(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user *buf)
{
	long retval = sys_pciconfig_write(bus, dfn, off, len, buf);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_pciconfig_write = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	long retval = sys_prctl(option, arg2, arg3, arg4, arg5);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_prctl = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_swapon(const char __user *specialfile, int swap_flags)
{
	long retval = sys_swapon(specialfile, swap_flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_swapon = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_swapoff(const char __user *specialfile)
{
	long retval = sys_swapoff(specialfile);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_swapoff = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sysctl(struct __sysctl_args __user *args)
{
	long retval = sys_sysctl(args);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sysctl = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sysinfo(struct sysinfo __user *info)
{
	long retval = sys_sysinfo(info);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sysinfo = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sysfs(int option, unsigned long arg1, unsigned long arg2)
{
	long retval = sys_sysfs(option, arg1, arg2);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sysfs = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_nfsservctl(int cmd, struct nfsctl_arg __user *arg, void __user *res)
{
	long retval = sys_nfsservctl(cmd, arg, res);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_nfsservctl = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_syslog(int type, char __user *buf, int len)
{
	long retval = sys_syslog(type, buf, len);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_syslog = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_uselib(const char __user *library)
{
	long retval = sys_uselib(library);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_uselib = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_ni_syscall(void)
{
	long retval = sys_ni_syscall();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_ni_syscall = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_ptrace(long request, long pid, long addr, long data)
{
	long retval = sys_ptrace(request, pid, addr, data);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_ptrace = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_add_key(const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t destringid)
{
	long retval = sys_add_key(_type, _description, _payload, plen, destringid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_add_key = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid)
{
	long retval = sys_request_key(_type, _description, _callout_info, destringid);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_request_key = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	long retval = sys_keyctl(cmd, arg2, arg3, arg4, arg5);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_keyctl = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_ioprio_set(int which, int who, int ioprio)
{
	long retval = sys_ioprio_set(which, who, ioprio);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_ioprio_set = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_ioprio_get(int which, int who)
{
	long retval = sys_ioprio_get(which, who);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_ioprio_get = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_set_mempolicy(int mode, unsigned long __user *nmask, unsigned long maxnode)
{
	long retval = sys_set_mempolicy(mode, nmask, maxnode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_set_mempolicy = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to)
{
	long retval = sys_migrate_pages(pid, maxnode, from, to);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_migrate_pages = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_move_pages(pid_t pid, unsigned long nr_pages,	const void __user * __user *pages, const int __user *nodes, int __user *status,	int flags)
{
	long retval = sys_move_pages(pid, nr_pages, pages, nodes, status, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_move_pages = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mbind(unsigned long start, unsigned long len,	unsigned long mode,	unsigned long __user *nmask, unsigned long maxnode,	unsigned flags)
{
	long retval = sys_mbind(start, len, mode, nmask, maxnode, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mbind = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags)
{
	long retval = sys_get_mempolicy(policy, nmask, maxnode, addr, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_get_mempolicy = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_inotify_init(void)
{
	long retval = sys_inotify_init();
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_inotify_init = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_inotify_init1(int flags)
{
	long retval = sys_inotify_init1(flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_inotify_init1 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_inotify_add_watch(int fd, const char __user *path, u32 mask)
{
	long retval = sys_inotify_add_watch(fd, path, mask);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_inotify_add_watch = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_inotify_rm_watch(int fd, __s32 wd)
{
	long retval = sys_inotify_rm_watch(fd, wd);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_inotify_rm_watch = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_spu_run(int fd, __u32 __user *unpc, __u32 __user *ustatus)
{
	long retval = sys_spu_run(fd, unpc, ustatus);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_spu_run = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_spu_create(const char __user *name, unsigned int flags, mode_t mode, int fd)
{
	long retval = sys_spu_create(name, flags, mode, fd);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_spu_create = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mknodat(int dfd, const char __user * filename, int mode, unsigned dev)
{
	long retval = sys_mknodat(dfd, filename, mode, dev);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mknodat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mkdirat(int dfd, const char __user * pathname, int mode)
{
	long retval = sys_mkdirat(dfd, pathname, mode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mkdirat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_unlinkat(int dfd, const char __user * pathname, int flag)
{
	long retval = sys_unlinkat(dfd, pathname, flag);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_unlinkat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_symlinkat(const char __user * oldname, int newdfd, const char __user * newname)
{
	long retval = sys_symlinkat(oldname, newdfd, newname);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_symlinkat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags)
{
	long retval = sys_linkat(olddfd, oldname, newdfd, newname, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_linkat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_renameat(int olddfd, const char __user * oldname, int newdfd, const char __user * newname)
{
	long retval = sys_renameat(olddfd, oldname, newdfd, newname);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_renameat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_futimesat(int dfd, char __user *filename, struct timeval __user *utimes)
{
	long retval = sys_futimesat(dfd, filename, utimes);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_futimesat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_faccessat(int dfd, const char __user *filename, int mode)
{
	long retval = sys_faccessat(dfd, filename, mode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_faccessat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fchmodat(int dfd, const char __user * filename, mode_t mode)
{
	long retval = sys_fchmodat(dfd, filename, mode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fchmodat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag)
{
	long retval = sys_fchownat(dfd, filename, user, group, flag);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fchownat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_openat(int dfd, const char __user *filename, int flags, int mode)
{
	long retval = sys_openat(dfd, filename, flags, mode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_openat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_newfstatat(int dfd, char __user *filename, struct stat __user *statbuf, int flag)
{
	long retval = sys_newfstatat(dfd, filename, statbuf, flag);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_newfstatat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fstatat64(int dfd, char __user *filename, struct stat64 __user *statbuf, int flag)
{
	long retval = sys_fstatat64(dfd, filename, statbuf, flag);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fstatat64 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_readlinkat(int dfd, const char __user *path, char __user *buf, int bufsiz)
{
	long retval = sys_readlinkat(dfd, path, buf, bufsiz);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_readlinkat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_utimensat(int dfd, char __user *filename,	struct timespec __user *utimes, int flags)
{
	long retval = sys_utimensat(dfd, filename, utimes, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_utimensat = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_unshare(unsigned long unshare_flags)
{
	long retval = sys_unshare(unshare_flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_unshare = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags)
{
	long retval = sys_splice(fd_in, off_in, fd_out, off_out, len, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_splice = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_vmsplice(int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags)
{
	long retval = sys_vmsplice(fd, iov, nr_segs, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_vmsplice = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_tee(int fdin, int fdout, size_t len, unsigned int flags)
{
	long retval = sys_tee(fdin, fdout, len, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_tee = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sync_file_range(int fd, loff_t offset, loff_t nbytes,	unsigned int flags)
{
	long retval = sys_sync_file_range(fd, offset, nbytes, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sync_file_range = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_sync_file_range2(int fd, unsigned int flags, loff_t offset, loff_t nbytes)
{
	long retval = sys_sync_file_range2(fd, flags, offset, nbytes);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_sync_file_range2 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_get_robust_list(int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr)
{
	long retval = sys_get_robust_list(pid, head_ptr, len_ptr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_get_robust_list = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_set_robust_list(struct robust_list_head __user *head, size_t len)
{
	long retval = sys_set_robust_list(head, len);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_set_robust_list = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache)
{
	long retval = sys_getcpu(cpu, node, cache);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_getcpu = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask)
{
	long retval = sys_signalfd(ufd, user_mask, sizemask);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_signalfd = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags)
{
	long retval = sys_signalfd4(ufd, user_mask, sizemask, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_signalfd4 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_timerfd_create(int clockid, int flags)
{
	long retval = sys_timerfd_create(clockid, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_timerfd_create = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_timerfd_settime(int ufd, int flags, const struct itimerspec __user *utmr, struct itimerspec __user *otmr)
{
	long retval = sys_timerfd_settime(ufd, flags, utmr, otmr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_timerfd_settime = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_timerfd_gettime(int ufd, struct itimerspec __user *otmr)
{
	long retval = sys_timerfd_gettime(ufd, otmr);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_timerfd_gettime = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_eventfd(unsigned int count)
{
	long retval = sys_eventfd(count);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_eventfd = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_eventfd2(unsigned int count, int flags)
{
	long retval = sys_eventfd2(count, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_eventfd2 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_fallocate(int fd, int mode, loff_t offset, loff_t len)
{
	long retval = sys_fallocate(fd, mode, offset, len);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_fallocate = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_old_readdir(unsigned int arg0, struct old_linux_dirent __user *arg1, unsigned int arg2)
{
	long retval = sys_old_readdir(arg0, arg1, arg2);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_old_readdir = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_pselect6(int arg0, fd_set __user *arg1, fd_set __user *arg2, fd_set __user *arg3, struct timespec __user *arg4, void __user *arg5)
{
	long retval = sys_pselect6(arg0, arg1, arg2, arg3, arg4, arg5);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_pselect6 = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_ppoll(struct pollfd __user *arg0, unsigned int arg1, struct timespec __user *arg2, const sigset_t __user *arg3, size_t arg4)
{
	long retval = sys_ppoll(arg0, arg1, arg2, arg3, arg4);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_ppoll = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_perf_event_open(struct perf_event_attr __user *attr_uptr,	pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	long retval = sys_perf_event_open(attr_uptr, pid, cpu, group_fd, flags);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_perf_event_open = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

long hook_sys_mmap_pgoff(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
	long retval = sys_mmap_pgoff(addr, len, prot, flags, fd, pgoff);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] sys_mmap_pgoff = %ld\n", current->pid, current->parent->pid, retval);
	return retval;
}

void reg_hooks(unsigned long **sys_call_table)
{
	sys_call_table[__NR_time] = (unsigned long *)hook_sys_time;
	sys_call_table[__NR_stime] = (unsigned long *)hook_sys_stime;
	sys_call_table[__NR_gettimeofday] = (unsigned long *)hook_sys_gettimeofday;
	sys_call_table[__NR_settimeofday] = (unsigned long *)hook_sys_settimeofday;
	sys_call_table[__NR_adjtimex] = (unsigned long *)hook_sys_adjtimex;
	sys_call_table[__NR_times] = (unsigned long *)hook_sys_times;
	sys_call_table[__NR_gettid] = (unsigned long *)hook_sys_gettid;
	sys_call_table[__NR_nanosleep] = (unsigned long *)hook_sys_nanosleep;
	sys_call_table[__NR_alarm] = (unsigned long *)hook_sys_alarm;
	sys_call_table[__NR_getpid] = (unsigned long *)hook_sys_getpid;
	sys_call_table[__NR_getppid] = (unsigned long *)hook_sys_getppid;
	sys_call_table[__NR_getuid] = (unsigned long *)hook_sys_getuid;
	sys_call_table[__NR_geteuid] = (unsigned long *)hook_sys_geteuid;
	sys_call_table[__NR_getgid] = (unsigned long *)hook_sys_getgid;
	sys_call_table[__NR_getegid] = (unsigned long *)hook_sys_getegid;
	sys_call_table[__NR_getresuid] = (unsigned long *)hook_sys_getresuid;
	sys_call_table[__NR_getresgid] = (unsigned long *)hook_sys_getresgid;
	sys_call_table[__NR_getpgid] = (unsigned long *)hook_sys_getpgid;
	sys_call_table[__NR_getpgrp] = (unsigned long *)hook_sys_getpgrp;
	sys_call_table[__NR_getsid] = (unsigned long *)hook_sys_getsid;
	sys_call_table[__NR_getgroups] = (unsigned long *)hook_sys_getgroups;
	sys_call_table[__NR_setregid] = (unsigned long *)hook_sys_setregid;
	sys_call_table[__NR_setgid] = (unsigned long *)hook_sys_setgid;
	sys_call_table[__NR_setreuid] = (unsigned long *)hook_sys_setreuid;
	sys_call_table[__NR_setuid] = (unsigned long *)hook_sys_setuid;
	sys_call_table[__NR_setresuid] = (unsigned long *)hook_sys_setresuid;
	sys_call_table[__NR_setresgid] = (unsigned long *)hook_sys_setresgid;
	sys_call_table[__NR_setfsuid] = (unsigned long *)hook_sys_setfsuid;
	sys_call_table[__NR_setfsgid] = (unsigned long *)hook_sys_setfsgid;
	sys_call_table[__NR_setpgid] = (unsigned long *)hook_sys_setpgid;
	sys_call_table[__NR_setsid] = (unsigned long *)hook_sys_setsid;
	sys_call_table[__NR_setgroups] = (unsigned long *)hook_sys_setgroups;
	sys_call_table[__NR_acct] = (unsigned long *)hook_sys_acct;
	sys_call_table[__NR_capget] = (unsigned long *)hook_sys_capget;
	sys_call_table[__NR_capset] = (unsigned long *)hook_sys_capset;
	sys_call_table[__NR_personality] = (unsigned long *)hook_sys_personality;
	sys_call_table[__NR_sigpending] = (unsigned long *)hook_sys_sigpending;
	sys_call_table[__NR_sigprocmask] = (unsigned long *)hook_sys_sigprocmask;
	sys_call_table[__NR_getitimer] = (unsigned long *)hook_sys_getitimer;
	sys_call_table[__NR_setitimer] = (unsigned long *)hook_sys_setitimer;
	sys_call_table[__NR_timer_create] = (unsigned long *)hook_sys_timer_create;
	sys_call_table[__NR_timer_gettime] = (unsigned long *)hook_sys_timer_gettime;
	sys_call_table[__NR_timer_getoverrun] = (unsigned long *)hook_sys_timer_getoverrun;
	sys_call_table[__NR_timer_settime] = (unsigned long *)hook_sys_timer_settime;
	sys_call_table[__NR_timer_delete] = (unsigned long *)hook_sys_timer_delete;
	sys_call_table[__NR_clock_settime] = (unsigned long *)hook_sys_clock_settime;
	sys_call_table[__NR_clock_gettime] = (unsigned long *)hook_sys_clock_gettime;
	sys_call_table[__NR_clock_getres] = (unsigned long *)hook_sys_clock_getres;
	sys_call_table[__NR_clock_nanosleep] = (unsigned long *)hook_sys_clock_nanosleep;
	sys_call_table[__NR_nice] = (unsigned long *)hook_sys_nice;
	sys_call_table[__NR_sched_setscheduler] = (unsigned long *)hook_sys_sched_setscheduler;
	sys_call_table[__NR_sched_setparam] = (unsigned long *)hook_sys_sched_setparam;
	sys_call_table[__NR_sched_getscheduler] = (unsigned long *)hook_sys_sched_getscheduler;
	sys_call_table[__NR_sched_getparam] = (unsigned long *)hook_sys_sched_getparam;
	sys_call_table[__NR_sched_setaffinity] = (unsigned long *)hook_sys_sched_setaffinity;
	sys_call_table[__NR_sched_getaffinity] = (unsigned long *)hook_sys_sched_getaffinity;
	sys_call_table[__NR_sched_yield] = (unsigned long *)hook_sys_sched_yield;
	sys_call_table[__NR_sched_get_priority_max] = (unsigned long *)hook_sys_sched_get_priority_max;
	sys_call_table[__NR_sched_get_priority_min] = (unsigned long *)hook_sys_sched_get_priority_min;
	sys_call_table[__NR_sched_rr_get_interval] = (unsigned long *)hook_sys_sched_rr_get_interval;
	sys_call_table[__NR_setpriority] = (unsigned long *)hook_sys_setpriority;
	sys_call_table[__NR_getpriority] = (unsigned long *)hook_sys_getpriority;
	sys_call_table[__NR_shutdown] = (unsigned long *)hook_sys_shutdown;
	sys_call_table[__NR_reboot] = (unsigned long *)hook_sys_reboot;
	sys_call_table[__NR_restart_syscall] = (unsigned long *)hook_sys_restart_syscall;
	sys_call_table[__NR_kexec_load] = (unsigned long *)hook_sys_kexec_load;
	sys_call_table[__NR_exit] = (unsigned long *)hook_sys_exit;
	sys_call_table[__NR_exit_group] = (unsigned long *)hook_sys_exit_group;
	sys_call_table[__NR_wait4] = (unsigned long *)hook_sys_wait4;
	sys_call_table[__NR_waitid] = (unsigned long *)hook_sys_waitid;
	sys_call_table[__NR_waitpid] = (unsigned long *)hook_sys_waitpid;
	sys_call_table[__NR_set_tid_address] = (unsigned long *)hook_sys_set_tid_address;
	sys_call_table[__NR_futex] = (unsigned long *)hook_sys_futex;
	sys_call_table[__NR_init_module] = (unsigned long *)hook_sys_init_module;
	sys_call_table[__NR_delete_module] = (unsigned long *)hook_sys_delete_module;
	sys_call_table[__NR_rt_sigprocmask] = (unsigned long *)hook_sys_rt_sigprocmask;
	sys_call_table[__NR_rt_sigpending] = (unsigned long *)hook_sys_rt_sigpending;
	sys_call_table[__NR_rt_sigtimedwait] = (unsigned long *)hook_sys_rt_sigtimedwait;
	sys_call_table[__NR_rt_tgsigqueueinfo] = (unsigned long *)hook_sys_rt_tgsigqueueinfo;
	sys_call_table[__NR_kill] = (unsigned long *)hook_sys_kill;
	sys_call_table[__NR_tgkill] = (unsigned long *)hook_sys_tgkill;
	sys_call_table[__NR_tkill] = (unsigned long *)hook_sys_tkill;
	sys_call_table[__NR_rt_sigqueueinfo] = (unsigned long *)hook_sys_rt_sigqueueinfo;
	sys_call_table[__NR_sgetmask] = (unsigned long *)hook_sys_sgetmask;
	sys_call_table[__NR_ssetmask] = (unsigned long *)hook_sys_ssetmask;
	sys_call_table[__NR_signal] = (unsigned long *)hook_sys_signal;
	sys_call_table[__NR_pause] = (unsigned long *)hook_sys_pause;
	sys_call_table[__NR_sync] = (unsigned long *)hook_sys_sync;
	sys_call_table[__NR_fsync] = (unsigned long *)hook_sys_fsync;
	sys_call_table[__NR_fdatasync] = (unsigned long *)hook_sys_fdatasync;
	sys_call_table[__NR_bdflush] = (unsigned long *)hook_sys_bdflush;
	sys_call_table[__NR_mount] = (unsigned long *)hook_sys_mount;
	sys_call_table[__NR_umount] = (unsigned long *)hook_sys_umount;
	sys_call_table[__NR_oldumount] = (unsigned long *)hook_sys_oldumount;
	sys_call_table[__NR_truncate] = (unsigned long *)hook_sys_truncate;
	sys_call_table[__NR_ftruncate] = (unsigned long *)hook_sys_ftruncate;
	sys_call_table[__NR_stat] = (unsigned long *)hook_sys_stat;
	sys_call_table[__NR_statfs] = (unsigned long *)hook_sys_statfs;
	sys_call_table[__NR_statfs64] = (unsigned long *)hook_sys_statfs64;
	sys_call_table[__NR_fstatfs] = (unsigned long *)hook_sys_fstatfs;
	sys_call_table[__NR_fstatfs64] = (unsigned long *)hook_sys_fstatfs64;
	sys_call_table[__NR_lstat] = (unsigned long *)hook_sys_lstat;
	sys_call_table[__NR_fstat] = (unsigned long *)hook_sys_fstat;
	sys_call_table[__NR_newstat] = (unsigned long *)hook_sys_newstat;
	sys_call_table[__NR_newlstat] = (unsigned long *)hook_sys_newlstat;
	sys_call_table[__NR_newfstat] = (unsigned long *)hook_sys_newfstat;
	sys_call_table[__NR_ustat] = (unsigned long *)hook_sys_ustat;
	sys_call_table[__NR_stat64] = (unsigned long *)hook_sys_stat64;
	sys_call_table[__NR_fstat64] = (unsigned long *)hook_sys_fstat64;
	sys_call_table[__NR_lstat64] = (unsigned long *)hook_sys_lstat64;
	sys_call_table[__NR_truncate64] = (unsigned long *)hook_sys_truncate64;
	sys_call_table[__NR_ftruncate64] = (unsigned long *)hook_sys_ftruncate64;
	sys_call_table[__NR_setxattr] = (unsigned long *)hook_sys_setxattr;
	sys_call_table[__NR_lsetxattr] = (unsigned long *)hook_sys_lsetxattr;
	sys_call_table[__NR_fsetxattr] = (unsigned long *)hook_sys_fsetxattr;
	sys_call_table[__NR_getxattr] = (unsigned long *)hook_sys_getxattr;
	sys_call_table[__NR_lgetxattr] = (unsigned long *)hook_sys_lgetxattr;
	sys_call_table[__NR_fgetxattr] = (unsigned long *)hook_sys_fgetxattr;
	sys_call_table[__NR_listxattr] = (unsigned long *)hook_sys_listxattr;
	sys_call_table[__NR_llistxattr] = (unsigned long *)hook_sys_llistxattr;
	sys_call_table[__NR_flistxattr] = (unsigned long *)hook_sys_flistxattr;
	sys_call_table[__NR_removexattr] = (unsigned long *)hook_sys_removexattr;
	sys_call_table[__NR_lremovexattr] = (unsigned long *)hook_sys_lremovexattr;
	sys_call_table[__NR_fremovexattr] = (unsigned long *)hook_sys_fremovexattr;
	sys_call_table[__NR_brk] = (unsigned long *)hook_sys_brk;
	sys_call_table[__NR_mprotect] = (unsigned long *)hook_sys_mprotect;
	sys_call_table[__NR_mremap] = (unsigned long *)hook_sys_mremap;
	sys_call_table[__NR_remap_file_pages] = (unsigned long *)hook_sys_remap_file_pages;
	sys_call_table[__NR_msync] = (unsigned long *)hook_sys_msync;
	sys_call_table[__NR_fadvise64] = (unsigned long *)hook_sys_fadvise64;
	sys_call_table[__NR_fadvise64_64] = (unsigned long *)hook_sys_fadvise64_64;
	sys_call_table[__NR_munmap] = (unsigned long *)hook_sys_munmap;
	sys_call_table[__NR_mlock] = (unsigned long *)hook_sys_mlock;
	sys_call_table[__NR_munlock] = (unsigned long *)hook_sys_munlock;
	sys_call_table[__NR_mlockall] = (unsigned long *)hook_sys_mlockall;
	sys_call_table[__NR_munlockall] = (unsigned long *)hook_sys_munlockall;
	sys_call_table[__NR_madvise] = (unsigned long *)hook_sys_madvise;
	sys_call_table[__NR_mincore] = (unsigned long *)hook_sys_mincore;
	sys_call_table[__NR_pivot_root] = (unsigned long *)hook_sys_pivot_root;
	sys_call_table[__NR_chroot] = (unsigned long *)hook_sys_chroot;
	sys_call_table[__NR_mknod] = (unsigned long *)hook_sys_mknod;
	sys_call_table[__NR_link] = (unsigned long *)hook_sys_link;
	sys_call_table[__NR_symlink] = (unsigned long *)hook_sys_symlink;
	sys_call_table[__NR_unlink] = (unsigned long *)hook_sys_unlink;
	sys_call_table[__NR_rename] = (unsigned long *)hook_sys_rename;
	sys_call_table[__NR_chmod] = (unsigned long *)hook_sys_chmod;
	sys_call_table[__NR_fchmod] = (unsigned long *)hook_sys_fchmod;
	sys_call_table[__NR_fcntl] = (unsigned long *)hook_sys_fcntl;
	sys_call_table[__NR_fcntl64] = (unsigned long *)hook_sys_fcntl64;
	sys_call_table[__NR_pipe] = (unsigned long *)hook_sys_pipe;
	sys_call_table[__NR_pipe2] = (unsigned long *)hook_sys_pipe2;
	sys_call_table[__NR_dup] = (unsigned long *)hook_sys_dup;
	sys_call_table[__NR_dup2] = (unsigned long *)hook_sys_dup2;
	sys_call_table[__NR_dup3] = (unsigned long *)hook_sys_dup3;
	sys_call_table[__NR_ioperm] = (unsigned long *)hook_sys_ioperm;
	sys_call_table[__NR_ioctl] = (unsigned long *)hook_sys_ioctl;
	sys_call_table[__NR_flock] = (unsigned long *)hook_sys_flock;
	sys_call_table[__NR_io_setup] = (unsigned long *)hook_sys_io_setup;
	sys_call_table[__NR_io_destroy] = (unsigned long *)hook_sys_io_destroy;
	sys_call_table[__NR_io_getevents] = (unsigned long *)hook_sys_io_getevents;
	sys_call_table[__NR_io_submit] = (unsigned long *)hook_sys_io_submit;
	sys_call_table[__NR_io_cancel] = (unsigned long *)hook_sys_io_cancel;
	sys_call_table[__NR_sendfile] = (unsigned long *)hook_sys_sendfile;
	sys_call_table[__NR_sendfile64] = (unsigned long *)hook_sys_sendfile64;
	sys_call_table[__NR_readlink] = (unsigned long *)hook_sys_readlink;
	sys_call_table[__NR_creat] = (unsigned long *)hook_sys_creat;
	sys_call_table[__NR_open] = (unsigned long *)hook_sys_open;
	sys_call_table[__NR_close] = (unsigned long *)hook_sys_close;
	sys_call_table[__NR_access] = (unsigned long *)hook_sys_access;
	sys_call_table[__NR_vhangup] = (unsigned long *)hook_sys_vhangup;
	sys_call_table[__NR_chown] = (unsigned long *)hook_sys_chown;
	sys_call_table[__NR_lchown] = (unsigned long *)hook_sys_lchown;
	sys_call_table[__NR_fchown] = (unsigned long *)hook_sys_fchown;
	sys_call_table[__NR_chown16] = (unsigned long *)hook_sys_chown16;
	sys_call_table[__NR_lchown16] = (unsigned long *)hook_sys_lchown16;
	sys_call_table[__NR_fchown16] = (unsigned long *)hook_sys_fchown16;
	sys_call_table[__NR_setregid16] = (unsigned long *)hook_sys_setregid16;
	sys_call_table[__NR_setgid16] = (unsigned long *)hook_sys_setgid16;
	sys_call_table[__NR_setreuid16] = (unsigned long *)hook_sys_setreuid16;
	sys_call_table[__NR_setuid16] = (unsigned long *)hook_sys_setuid16;
	sys_call_table[__NR_setresuid16] = (unsigned long *)hook_sys_setresuid16;
	sys_call_table[__NR_getresuid16] = (unsigned long *)hook_sys_getresuid16;
	sys_call_table[__NR_setresgid16] = (unsigned long *)hook_sys_setresgid16;
	sys_call_table[__NR_getresgid16] = (unsigned long *)hook_sys_getresgid16;
	sys_call_table[__NR_setfsuid16] = (unsigned long *)hook_sys_setfsuid16;
	sys_call_table[__NR_setfsgid16] = (unsigned long *)hook_sys_setfsgid16;
	sys_call_table[__NR_getgroups16] = (unsigned long *)hook_sys_getgroups16;
	sys_call_table[__NR_setgroups16] = (unsigned long *)hook_sys_setgroups16;
	sys_call_table[__NR_getuid16] = (unsigned long *)hook_sys_getuid16;
	sys_call_table[__NR_geteuid16] = (unsigned long *)hook_sys_geteuid16;
	sys_call_table[__NR_getgid16] = (unsigned long *)hook_sys_getgid16;
	sys_call_table[__NR_getegid16] = (unsigned long *)hook_sys_getegid16;
	sys_call_table[__NR_utime] = (unsigned long *)hook_sys_utime;
	sys_call_table[__NR_utimes] = (unsigned long *)hook_sys_utimes;
	sys_call_table[__NR_lseek] = (unsigned long *)hook_sys_lseek;
	sys_call_table[__NR_llseek] = (unsigned long *)hook_sys_llseek;
	sys_call_table[__NR_read] = (unsigned long *)hook_sys_read;
	sys_call_table[__NR_readahead] = (unsigned long *)hook_sys_readahead;
	sys_call_table[__NR_readv] = (unsigned long *)hook_sys_readv;
	sys_call_table[__NR_write] = (unsigned long *)hook_sys_write;
	sys_call_table[__NR_writev] = (unsigned long *)hook_sys_writev;
	sys_call_table[__NR_pread64] = (unsigned long *)hook_sys_pread64;
	sys_call_table[__NR_pwrite64] = (unsigned long *)hook_sys_pwrite64;
	sys_call_table[__NR_preadv] = (unsigned long *)hook_sys_preadv;
	sys_call_table[__NR_pwritev] = (unsigned long *)hook_sys_pwritev;
	sys_call_table[__NR_getcwd] = (unsigned long *)hook_sys_getcwd;
	sys_call_table[__NR_mkdir] = (unsigned long *)hook_sys_mkdir;
	sys_call_table[__NR_chdir] = (unsigned long *)hook_sys_chdir;
	sys_call_table[__NR_fchdir] = (unsigned long *)hook_sys_fchdir;
	sys_call_table[__NR_rmdir] = (unsigned long *)hook_sys_rmdir;
	sys_call_table[__NR_lookup_dcookie] = (unsigned long *)hook_sys_lookup_dcookie;
	sys_call_table[__NR_quotactl] = (unsigned long *)hook_sys_quotactl;
	sys_call_table[__NR_getdents] = (unsigned long *)hook_sys_getdents;
	sys_call_table[__NR_getdents64] = (unsigned long *)hook_sys_getdents64;
	sys_call_table[__NR_setsockopt] = (unsigned long *)hook_sys_setsockopt;
	sys_call_table[__NR_getsockopt] = (unsigned long *)hook_sys_getsockopt;
	sys_call_table[__NR_bind] = (unsigned long *)hook_sys_bind;
	sys_call_table[__NR_connect] = (unsigned long *)hook_sys_connect;
	sys_call_table[__NR_accept] = (unsigned long *)hook_sys_accept;
	sys_call_table[__NR_accept4] = (unsigned long *)hook_sys_accept4;
	sys_call_table[__NR_getsockname] = (unsigned long *)hook_sys_getsockname;
	sys_call_table[__NR_getpeername] = (unsigned long *)hook_sys_getpeername;
	sys_call_table[__NR_send] = (unsigned long *)hook_sys_send;
	sys_call_table[__NR_sendto] = (unsigned long *)hook_sys_sendto;
	sys_call_table[__NR_sendmsg] = (unsigned long *)hook_sys_sendmsg;
	sys_call_table[__NR_recv] = (unsigned long *)hook_sys_recv;
	sys_call_table[__NR_recvfrom] = (unsigned long *)hook_sys_recvfrom;
	sys_call_table[__NR_recvmsg] = (unsigned long *)hook_sys_recvmsg;
	sys_call_table[__NR_socket] = (unsigned long *)hook_sys_socket;
	sys_call_table[__NR_socketpair] = (unsigned long *)hook_sys_socketpair;
	sys_call_table[__NR_socketcall] = (unsigned long *)hook_sys_socketcall;
	sys_call_table[__NR_listen] = (unsigned long *)hook_sys_listen;
	sys_call_table[__NR_poll] = (unsigned long *)hook_sys_poll;
	sys_call_table[__NR_select] = (unsigned long *)hook_sys_select;
	sys_call_table[__NR_epoll_create] = (unsigned long *)hook_sys_epoll_create;
	sys_call_table[__NR_epoll_create1] = (unsigned long *)hook_sys_epoll_create1;
	sys_call_table[__NR_epoll_ctl] = (unsigned long *)hook_sys_epoll_ctl;
	sys_call_table[__NR_epoll_wait] = (unsigned long *)hook_sys_epoll_wait;
	sys_call_table[__NR_epoll_pwait] = (unsigned long *)hook_sys_epoll_pwait;
	sys_call_table[__NR_gethostname] = (unsigned long *)hook_sys_gethostname;
	sys_call_table[__NR_sethostname] = (unsigned long *)hook_sys_sethostname;
	sys_call_table[__NR_setdomainname] = (unsigned long *)hook_sys_setdomainname;
	sys_call_table[__NR_newuname] = (unsigned long *)hook_sys_newuname;
	sys_call_table[__NR_getrlimit] = (unsigned long *)hook_sys_getrlimit;
	sys_call_table[__NR_old_getrlimit] = (unsigned long *)hook_sys_old_getrlimit;
	sys_call_table[__NR_setrlimit] = (unsigned long *)hook_sys_setrlimit;
	sys_call_table[__NR_getrusage] = (unsigned long *)hook_sys_getrusage;
	sys_call_table[__NR_umask] = (unsigned long *)hook_sys_umask;
	sys_call_table[__NR_msgget] = (unsigned long *)hook_sys_msgget;
	sys_call_table[__NR_msgsnd] = (unsigned long *)hook_sys_msgsnd;
	sys_call_table[__NR_msgrcv] = (unsigned long *)hook_sys_msgrcv;
	sys_call_table[__NR_msgctl] = (unsigned long *)hook_sys_msgctl;
	sys_call_table[__NR_semget] = (unsigned long *)hook_sys_semget;
	sys_call_table[__NR_semop] = (unsigned long *)hook_sys_semop;
	sys_call_table[__NR_semctl] = (unsigned long *)hook_sys_semctl;
	sys_call_table[__NR_semtimedop] = (unsigned long *)hook_sys_semtimedop;
	sys_call_table[__NR_shmat] = (unsigned long *)hook_sys_shmat;
	sys_call_table[__NR_shmget] = (unsigned long *)hook_sys_shmget;
	sys_call_table[__NR_shmdt] = (unsigned long *)hook_sys_shmdt;
	sys_call_table[__NR_shmctl] = (unsigned long *)hook_sys_shmctl;
	sys_call_table[__NR_mq_open] = (unsigned long *)hook_sys_mq_open;
	sys_call_table[__NR_mq_unlink] = (unsigned long *)hook_sys_mq_unlink;
	sys_call_table[__NR_mq_timedsend] = (unsigned long *)hook_sys_mq_timedsend;
	sys_call_table[__NR_mq_timedreceive] = (unsigned long *)hook_sys_mq_timedreceive;
	sys_call_table[__NR_mq_notify] = (unsigned long *)hook_sys_mq_notify;
	sys_call_table[__NR_mq_getsetattr] = (unsigned long *)hook_sys_mq_getsetattr;
	sys_call_table[__NR_pciconfig_iobase] = (unsigned long *)hook_sys_pciconfig_iobase;
	sys_call_table[__NR_pciconfig_read] = (unsigned long *)hook_sys_pciconfig_read;
	sys_call_table[__NR_pciconfig_write] = (unsigned long *)hook_sys_pciconfig_write;
	sys_call_table[__NR_prctl] = (unsigned long *)hook_sys_prctl;
	sys_call_table[__NR_swapon] = (unsigned long *)hook_sys_swapon;
	sys_call_table[__NR_swapoff] = (unsigned long *)hook_sys_swapoff;
	sys_call_table[__NR_sysctl] = (unsigned long *)hook_sys_sysctl;
	sys_call_table[__NR_sysinfo] = (unsigned long *)hook_sys_sysinfo;
	sys_call_table[__NR_sysfs] = (unsigned long *)hook_sys_sysfs;
	sys_call_table[__NR_nfsservctl] = (unsigned long *)hook_sys_nfsservctl;
	sys_call_table[__NR_syslog] = (unsigned long *)hook_sys_syslog;
	sys_call_table[__NR_uselib] = (unsigned long *)hook_sys_uselib;
	sys_call_table[__NR_ni_syscall] = (unsigned long *)hook_sys_ni_syscall;
	sys_call_table[__NR_ptrace] = (unsigned long *)hook_sys_ptrace;
	sys_call_table[__NR_add_key] = (unsigned long *)hook_sys_add_key;
	sys_call_table[__NR_request_key] = (unsigned long *)hook_sys_request_key;
	sys_call_table[__NR_keyctl] = (unsigned long *)hook_sys_keyctl;
	sys_call_table[__NR_ioprio_set] = (unsigned long *)hook_sys_ioprio_set;
	sys_call_table[__NR_ioprio_get] = (unsigned long *)hook_sys_ioprio_get;
	sys_call_table[__NR_set_mempolicy] = (unsigned long *)hook_sys_set_mempolicy;
	sys_call_table[__NR_migrate_pages] = (unsigned long *)hook_sys_migrate_pages;
	sys_call_table[__NR_move_pages] = (unsigned long *)hook_sys_move_pages;
	sys_call_table[__NR_mbind] = (unsigned long *)hook_sys_mbind;
	sys_call_table[__NR_get_mempolicy] = (unsigned long *)hook_sys_get_mempolicy;
	sys_call_table[__NR_inotify_init] = (unsigned long *)hook_sys_inotify_init;
	sys_call_table[__NR_inotify_init1] = (unsigned long *)hook_sys_inotify_init1;
	sys_call_table[__NR_inotify_add_watch] = (unsigned long *)hook_sys_inotify_add_watch;
	sys_call_table[__NR_inotify_rm_watch] = (unsigned long *)hook_sys_inotify_rm_watch;
	sys_call_table[__NR_spu_run] = (unsigned long *)hook_sys_spu_run;
	sys_call_table[__NR_spu_create] = (unsigned long *)hook_sys_spu_create;
	sys_call_table[__NR_mknodat] = (unsigned long *)hook_sys_mknodat;
	sys_call_table[__NR_mkdirat] = (unsigned long *)hook_sys_mkdirat;
	sys_call_table[__NR_unlinkat] = (unsigned long *)hook_sys_unlinkat;
	sys_call_table[__NR_symlinkat] = (unsigned long *)hook_sys_symlinkat;
	sys_call_table[__NR_linkat] = (unsigned long *)hook_sys_linkat;
	sys_call_table[__NR_renameat] = (unsigned long *)hook_sys_renameat;
	sys_call_table[__NR_futimesat] = (unsigned long *)hook_sys_futimesat;
	sys_call_table[__NR_faccessat] = (unsigned long *)hook_sys_faccessat;
	sys_call_table[__NR_fchmodat] = (unsigned long *)hook_sys_fchmodat;
	sys_call_table[__NR_fchownat] = (unsigned long *)hook_sys_fchownat;
	sys_call_table[__NR_openat] = (unsigned long *)hook_sys_openat;
	sys_call_table[__NR_newfstatat] = (unsigned long *)hook_sys_newfstatat;
	sys_call_table[__NR_fstatat64] = (unsigned long *)hook_sys_fstatat64;
	sys_call_table[__NR_readlinkat] = (unsigned long *)hook_sys_readlinkat;
	sys_call_table[__NR_utimensat] = (unsigned long *)hook_sys_utimensat;
	sys_call_table[__NR_unshare] = (unsigned long *)hook_sys_unshare;
	sys_call_table[__NR_splice] = (unsigned long *)hook_sys_splice;
	sys_call_table[__NR_vmsplice] = (unsigned long *)hook_sys_vmsplice;
	sys_call_table[__NR_tee] = (unsigned long *)hook_sys_tee;
	sys_call_table[__NR_sync_file_range] = (unsigned long *)hook_sys_sync_file_range;
	sys_call_table[__NR_sync_file_range2] = (unsigned long *)hook_sys_sync_file_range2;
	sys_call_table[__NR_get_robust_list] = (unsigned long *)hook_sys_get_robust_list;
	sys_call_table[__NR_set_robust_list] = (unsigned long *)hook_sys_set_robust_list;
	sys_call_table[__NR_getcpu] = (unsigned long *)hook_sys_getcpu;
	sys_call_table[__NR_signalfd] = (unsigned long *)hook_sys_signalfd;
	sys_call_table[__NR_signalfd4] = (unsigned long *)hook_sys_signalfd4;
	sys_call_table[__NR_timerfd_create] = (unsigned long *)hook_sys_timerfd_create;
	sys_call_table[__NR_timerfd_settime] = (unsigned long *)hook_sys_timerfd_settime;
	sys_call_table[__NR_timerfd_gettime] = (unsigned long *)hook_sys_timerfd_gettime;
	sys_call_table[__NR_eventfd] = (unsigned long *)hook_sys_eventfd;
	sys_call_table[__NR_eventfd2] = (unsigned long *)hook_sys_eventfd2;
	sys_call_table[__NR_fallocate] = (unsigned long *)hook_sys_fallocate;
	sys_call_table[__NR_old_readdir] = (unsigned long *)hook_sys_old_readdir;
	sys_call_table[__NR_pselect6] = (unsigned long *)hook_sys_pselect6;
	sys_call_table[__NR_ppoll] = (unsigned long *)hook_sys_ppoll;
	sys_call_table[__NR_perf_event_open] = (unsigned long *)hook_sys_perf_event_open;
	sys_call_table[__NR_mmap_pgoff] = (unsigned long *)hook_sys_mmap_pgoff;
}

void unreg_hooks(unsigned long **sys_call_table)
{
	sys_call_table[__NR_time] = (unsigned long *)sys_time;
	sys_call_table[__NR_stime] = (unsigned long *)sys_stime;
	sys_call_table[__NR_gettimeofday] = (unsigned long *)sys_gettimeofday;
	sys_call_table[__NR_settimeofday] = (unsigned long *)sys_settimeofday;
	sys_call_table[__NR_adjtimex] = (unsigned long *)sys_adjtimex;
	sys_call_table[__NR_times] = (unsigned long *)sys_times;
	sys_call_table[__NR_gettid] = (unsigned long *)sys_gettid;
	sys_call_table[__NR_nanosleep] = (unsigned long *)sys_nanosleep;
	sys_call_table[__NR_alarm] = (unsigned long *)sys_alarm;
	sys_call_table[__NR_getpid] = (unsigned long *)sys_getpid;
	sys_call_table[__NR_getppid] = (unsigned long *)sys_getppid;
	sys_call_table[__NR_getuid] = (unsigned long *)sys_getuid;
	sys_call_table[__NR_geteuid] = (unsigned long *)sys_geteuid;
	sys_call_table[__NR_getgid] = (unsigned long *)sys_getgid;
	sys_call_table[__NR_getegid] = (unsigned long *)sys_getegid;
	sys_call_table[__NR_getresuid] = (unsigned long *)sys_getresuid;
	sys_call_table[__NR_getresgid] = (unsigned long *)sys_getresgid;
	sys_call_table[__NR_getpgid] = (unsigned long *)sys_getpgid;
	sys_call_table[__NR_getpgrp] = (unsigned long *)sys_getpgrp;
	sys_call_table[__NR_getsid] = (unsigned long *)sys_getsid;
	sys_call_table[__NR_getgroups] = (unsigned long *)sys_getgroups;
	sys_call_table[__NR_setregid] = (unsigned long *)sys_setregid;
	sys_call_table[__NR_setgid] = (unsigned long *)sys_setgid;
	sys_call_table[__NR_setreuid] = (unsigned long *)sys_setreuid;
	sys_call_table[__NR_setuid] = (unsigned long *)sys_setuid;
	sys_call_table[__NR_setresuid] = (unsigned long *)sys_setresuid;
	sys_call_table[__NR_setresgid] = (unsigned long *)sys_setresgid;
	sys_call_table[__NR_setfsuid] = (unsigned long *)sys_setfsuid;
	sys_call_table[__NR_setfsgid] = (unsigned long *)sys_setfsgid;
	sys_call_table[__NR_setpgid] = (unsigned long *)sys_setpgid;
	sys_call_table[__NR_setsid] = (unsigned long *)sys_setsid;
	sys_call_table[__NR_setgroups] = (unsigned long *)sys_setgroups;
	sys_call_table[__NR_acct] = (unsigned long *)sys_acct;
	sys_call_table[__NR_capget] = (unsigned long *)sys_capget;
	sys_call_table[__NR_capset] = (unsigned long *)sys_capset;
	sys_call_table[__NR_personality] = (unsigned long *)sys_personality;
	sys_call_table[__NR_sigpending] = (unsigned long *)sys_sigpending;
	sys_call_table[__NR_sigprocmask] = (unsigned long *)sys_sigprocmask;
	sys_call_table[__NR_getitimer] = (unsigned long *)sys_getitimer;
	sys_call_table[__NR_setitimer] = (unsigned long *)sys_setitimer;
	sys_call_table[__NR_timer_create] = (unsigned long *)sys_timer_create;
	sys_call_table[__NR_timer_gettime] = (unsigned long *)sys_timer_gettime;
	sys_call_table[__NR_timer_getoverrun] = (unsigned long *)sys_timer_getoverrun;
	sys_call_table[__NR_timer_settime] = (unsigned long *)sys_timer_settime;
	sys_call_table[__NR_timer_delete] = (unsigned long *)sys_timer_delete;
	sys_call_table[__NR_clock_settime] = (unsigned long *)sys_clock_settime;
	sys_call_table[__NR_clock_gettime] = (unsigned long *)sys_clock_gettime;
	sys_call_table[__NR_clock_getres] = (unsigned long *)sys_clock_getres;
	sys_call_table[__NR_clock_nanosleep] = (unsigned long *)sys_clock_nanosleep;
	sys_call_table[__NR_nice] = (unsigned long *)sys_nice;
	sys_call_table[__NR_sched_setscheduler] = (unsigned long *)sys_sched_setscheduler;
	sys_call_table[__NR_sched_setparam] = (unsigned long *)sys_sched_setparam;
	sys_call_table[__NR_sched_getscheduler] = (unsigned long *)sys_sched_getscheduler;
	sys_call_table[__NR_sched_getparam] = (unsigned long *)sys_sched_getparam;
	sys_call_table[__NR_sched_setaffinity] = (unsigned long *)sys_sched_setaffinity;
	sys_call_table[__NR_sched_getaffinity] = (unsigned long *)sys_sched_getaffinity;
	sys_call_table[__NR_sched_yield] = (unsigned long *)sys_sched_yield;
	sys_call_table[__NR_sched_get_priority_max] = (unsigned long *)sys_sched_get_priority_max;
	sys_call_table[__NR_sched_get_priority_min] = (unsigned long *)sys_sched_get_priority_min;
	sys_call_table[__NR_sched_rr_get_interval] = (unsigned long *)sys_sched_rr_get_interval;
	sys_call_table[__NR_setpriority] = (unsigned long *)sys_setpriority;
	sys_call_table[__NR_getpriority] = (unsigned long *)sys_getpriority;
	sys_call_table[__NR_shutdown] = (unsigned long *)sys_shutdown;
	sys_call_table[__NR_reboot] = (unsigned long *)sys_reboot;
	sys_call_table[__NR_restart_syscall] = (unsigned long *)sys_restart_syscall;
	sys_call_table[__NR_kexec_load] = (unsigned long *)sys_kexec_load;
	sys_call_table[__NR_exit] = (unsigned long *)sys_exit;
	sys_call_table[__NR_exit_group] = (unsigned long *)sys_exit_group;
	sys_call_table[__NR_wait4] = (unsigned long *)sys_wait4;
	sys_call_table[__NR_waitid] = (unsigned long *)sys_waitid;
	sys_call_table[__NR_waitpid] = (unsigned long *)sys_waitpid;
	sys_call_table[__NR_set_tid_address] = (unsigned long *)sys_set_tid_address;
	sys_call_table[__NR_futex] = (unsigned long *)sys_futex;
	sys_call_table[__NR_init_module] = (unsigned long *)sys_init_module;
	sys_call_table[__NR_delete_module] = (unsigned long *)sys_delete_module;
	sys_call_table[__NR_rt_sigprocmask] = (unsigned long *)sys_rt_sigprocmask;
	sys_call_table[__NR_rt_sigpending] = (unsigned long *)sys_rt_sigpending;
	sys_call_table[__NR_rt_sigtimedwait] = (unsigned long *)sys_rt_sigtimedwait;
	sys_call_table[__NR_rt_tgsigqueueinfo] = (unsigned long *)sys_rt_tgsigqueueinfo;
	sys_call_table[__NR_kill] = (unsigned long *)sys_kill;
	sys_call_table[__NR_tgkill] = (unsigned long *)sys_tgkill;
	sys_call_table[__NR_tkill] = (unsigned long *)sys_tkill;
	sys_call_table[__NR_rt_sigqueueinfo] = (unsigned long *)sys_rt_sigqueueinfo;
	sys_call_table[__NR_sgetmask] = (unsigned long *)sys_sgetmask;
	sys_call_table[__NR_ssetmask] = (unsigned long *)sys_ssetmask;
	sys_call_table[__NR_signal] = (unsigned long *)sys_signal;
	sys_call_table[__NR_pause] = (unsigned long *)sys_pause;
	sys_call_table[__NR_sync] = (unsigned long *)sys_sync;
	sys_call_table[__NR_fsync] = (unsigned long *)sys_fsync;
	sys_call_table[__NR_fdatasync] = (unsigned long *)sys_fdatasync;
	sys_call_table[__NR_bdflush] = (unsigned long *)sys_bdflush;
	sys_call_table[__NR_mount] = (unsigned long *)sys_mount;
	sys_call_table[__NR_umount] = (unsigned long *)sys_umount;
	sys_call_table[__NR_oldumount] = (unsigned long *)sys_oldumount;
	sys_call_table[__NR_truncate] = (unsigned long *)sys_truncate;
	sys_call_table[__NR_ftruncate] = (unsigned long *)sys_ftruncate;
	sys_call_table[__NR_stat] = (unsigned long *)sys_stat;
	sys_call_table[__NR_statfs] = (unsigned long *)sys_statfs;
	sys_call_table[__NR_statfs64] = (unsigned long *)sys_statfs64;
	sys_call_table[__NR_fstatfs] = (unsigned long *)sys_fstatfs;
	sys_call_table[__NR_fstatfs64] = (unsigned long *)sys_fstatfs64;
	sys_call_table[__NR_lstat] = (unsigned long *)sys_lstat;
	sys_call_table[__NR_fstat] = (unsigned long *)sys_fstat;
	sys_call_table[__NR_newstat] = (unsigned long *)sys_newstat;
	sys_call_table[__NR_newlstat] = (unsigned long *)sys_newlstat;
	sys_call_table[__NR_newfstat] = (unsigned long *)sys_newfstat;
	sys_call_table[__NR_ustat] = (unsigned long *)sys_ustat;
	sys_call_table[__NR_stat64] = (unsigned long *)sys_stat64;
	sys_call_table[__NR_fstat64] = (unsigned long *)sys_fstat64;
	sys_call_table[__NR_lstat64] = (unsigned long *)sys_lstat64;
	sys_call_table[__NR_truncate64] = (unsigned long *)sys_truncate64;
	sys_call_table[__NR_ftruncate64] = (unsigned long *)sys_ftruncate64;
	sys_call_table[__NR_setxattr] = (unsigned long *)sys_setxattr;
	sys_call_table[__NR_lsetxattr] = (unsigned long *)sys_lsetxattr;
	sys_call_table[__NR_fsetxattr] = (unsigned long *)sys_fsetxattr;
	sys_call_table[__NR_getxattr] = (unsigned long *)sys_getxattr;
	sys_call_table[__NR_lgetxattr] = (unsigned long *)sys_lgetxattr;
	sys_call_table[__NR_fgetxattr] = (unsigned long *)sys_fgetxattr;
	sys_call_table[__NR_listxattr] = (unsigned long *)sys_listxattr;
	sys_call_table[__NR_llistxattr] = (unsigned long *)sys_llistxattr;
	sys_call_table[__NR_flistxattr] = (unsigned long *)sys_flistxattr;
	sys_call_table[__NR_removexattr] = (unsigned long *)sys_removexattr;
	sys_call_table[__NR_lremovexattr] = (unsigned long *)sys_lremovexattr;
	sys_call_table[__NR_fremovexattr] = (unsigned long *)sys_fremovexattr;
	sys_call_table[__NR_brk] = (unsigned long *)sys_brk;
	sys_call_table[__NR_mprotect] = (unsigned long *)sys_mprotect;
	sys_call_table[__NR_mremap] = (unsigned long *)sys_mremap;
	sys_call_table[__NR_remap_file_pages] = (unsigned long *)sys_remap_file_pages;
	sys_call_table[__NR_msync] = (unsigned long *)sys_msync;
	sys_call_table[__NR_fadvise64] = (unsigned long *)sys_fadvise64;
	sys_call_table[__NR_fadvise64_64] = (unsigned long *)sys_fadvise64_64;
	sys_call_table[__NR_munmap] = (unsigned long *)sys_munmap;
	sys_call_table[__NR_mlock] = (unsigned long *)sys_mlock;
	sys_call_table[__NR_munlock] = (unsigned long *)sys_munlock;
	sys_call_table[__NR_mlockall] = (unsigned long *)sys_mlockall;
	sys_call_table[__NR_munlockall] = (unsigned long *)sys_munlockall;
	sys_call_table[__NR_madvise] = (unsigned long *)sys_madvise;
	sys_call_table[__NR_mincore] = (unsigned long *)sys_mincore;
	sys_call_table[__NR_pivot_root] = (unsigned long *)sys_pivot_root;
	sys_call_table[__NR_chroot] = (unsigned long *)sys_chroot;
	sys_call_table[__NR_mknod] = (unsigned long *)sys_mknod;
	sys_call_table[__NR_link] = (unsigned long *)sys_link;
	sys_call_table[__NR_symlink] = (unsigned long *)sys_symlink;
	sys_call_table[__NR_unlink] = (unsigned long *)sys_unlink;
	sys_call_table[__NR_rename] = (unsigned long *)sys_rename;
	sys_call_table[__NR_chmod] = (unsigned long *)sys_chmod;
	sys_call_table[__NR_fchmod] = (unsigned long *)sys_fchmod;
	sys_call_table[__NR_fcntl] = (unsigned long *)sys_fcntl;
	sys_call_table[__NR_fcntl64] = (unsigned long *)sys_fcntl64;
	sys_call_table[__NR_pipe] = (unsigned long *)sys_pipe;
	sys_call_table[__NR_pipe2] = (unsigned long *)sys_pipe2;
	sys_call_table[__NR_dup] = (unsigned long *)sys_dup;
	sys_call_table[__NR_dup2] = (unsigned long *)sys_dup2;
	sys_call_table[__NR_dup3] = (unsigned long *)sys_dup3;
	sys_call_table[__NR_ioperm] = (unsigned long *)sys_ioperm;
	sys_call_table[__NR_ioctl] = (unsigned long *)sys_ioctl;
	sys_call_table[__NR_flock] = (unsigned long *)sys_flock;
	sys_call_table[__NR_io_setup] = (unsigned long *)sys_io_setup;
	sys_call_table[__NR_io_destroy] = (unsigned long *)sys_io_destroy;
	sys_call_table[__NR_io_getevents] = (unsigned long *)sys_io_getevents;
	sys_call_table[__NR_io_submit] = (unsigned long *)sys_io_submit;
	sys_call_table[__NR_io_cancel] = (unsigned long *)sys_io_cancel;
	sys_call_table[__NR_sendfile] = (unsigned long *)sys_sendfile;
	sys_call_table[__NR_sendfile64] = (unsigned long *)sys_sendfile64;
	sys_call_table[__NR_readlink] = (unsigned long *)sys_readlink;
	sys_call_table[__NR_creat] = (unsigned long *)sys_creat;
	sys_call_table[__NR_open] = (unsigned long *)sys_open;
	sys_call_table[__NR_close] = (unsigned long *)sys_close;
	sys_call_table[__NR_access] = (unsigned long *)sys_access;
	sys_call_table[__NR_vhangup] = (unsigned long *)sys_vhangup;
	sys_call_table[__NR_chown] = (unsigned long *)sys_chown;
	sys_call_table[__NR_lchown] = (unsigned long *)sys_lchown;
	sys_call_table[__NR_fchown] = (unsigned long *)sys_fchown;
	sys_call_table[__NR_chown16] = (unsigned long *)sys_chown16;
	sys_call_table[__NR_lchown16] = (unsigned long *)sys_lchown16;
	sys_call_table[__NR_fchown16] = (unsigned long *)sys_fchown16;
	sys_call_table[__NR_setregid16] = (unsigned long *)sys_setregid16;
	sys_call_table[__NR_setgid16] = (unsigned long *)sys_setgid16;
	sys_call_table[__NR_setreuid16] = (unsigned long *)sys_setreuid16;
	sys_call_table[__NR_setuid16] = (unsigned long *)sys_setuid16;
	sys_call_table[__NR_setresuid16] = (unsigned long *)sys_setresuid16;
	sys_call_table[__NR_getresuid16] = (unsigned long *)sys_getresuid16;
	sys_call_table[__NR_setresgid16] = (unsigned long *)sys_setresgid16;
	sys_call_table[__NR_getresgid16] = (unsigned long *)sys_getresgid16;
	sys_call_table[__NR_setfsuid16] = (unsigned long *)sys_setfsuid16;
	sys_call_table[__NR_setfsgid16] = (unsigned long *)sys_setfsgid16;
	sys_call_table[__NR_getgroups16] = (unsigned long *)sys_getgroups16;
	sys_call_table[__NR_setgroups16] = (unsigned long *)sys_setgroups16;
	sys_call_table[__NR_getuid16] = (unsigned long *)sys_getuid16;
	sys_call_table[__NR_geteuid16] = (unsigned long *)sys_geteuid16;
	sys_call_table[__NR_getgid16] = (unsigned long *)sys_getgid16;
	sys_call_table[__NR_getegid16] = (unsigned long *)sys_getegid16;
	sys_call_table[__NR_utime] = (unsigned long *)sys_utime;
	sys_call_table[__NR_utimes] = (unsigned long *)sys_utimes;
	sys_call_table[__NR_lseek] = (unsigned long *)sys_lseek;
	sys_call_table[__NR_llseek] = (unsigned long *)sys_llseek;
	sys_call_table[__NR_read] = (unsigned long *)sys_read;
	sys_call_table[__NR_readahead] = (unsigned long *)sys_readahead;
	sys_call_table[__NR_readv] = (unsigned long *)sys_readv;
	sys_call_table[__NR_write] = (unsigned long *)sys_write;
	sys_call_table[__NR_writev] = (unsigned long *)sys_writev;
	sys_call_table[__NR_pread64] = (unsigned long *)sys_pread64;
	sys_call_table[__NR_pwrite64] = (unsigned long *)sys_pwrite64;
	sys_call_table[__NR_preadv] = (unsigned long *)sys_preadv;
	sys_call_table[__NR_pwritev] = (unsigned long *)sys_pwritev;
	sys_call_table[__NR_getcwd] = (unsigned long *)sys_getcwd;
	sys_call_table[__NR_mkdir] = (unsigned long *)sys_mkdir;
	sys_call_table[__NR_chdir] = (unsigned long *)sys_chdir;
	sys_call_table[__NR_fchdir] = (unsigned long *)sys_fchdir;
	sys_call_table[__NR_rmdir] = (unsigned long *)sys_rmdir;
	sys_call_table[__NR_lookup_dcookie] = (unsigned long *)sys_lookup_dcookie;
	sys_call_table[__NR_quotactl] = (unsigned long *)sys_quotactl;
	sys_call_table[__NR_getdents] = (unsigned long *)sys_getdents;
	sys_call_table[__NR_getdents64] = (unsigned long *)sys_getdents64;
	sys_call_table[__NR_setsockopt] = (unsigned long *)sys_setsockopt;
	sys_call_table[__NR_getsockopt] = (unsigned long *)sys_getsockopt;
	sys_call_table[__NR_bind] = (unsigned long *)sys_bind;
	sys_call_table[__NR_connect] = (unsigned long *)sys_connect;
	sys_call_table[__NR_accept] = (unsigned long *)sys_accept;
	sys_call_table[__NR_accept4] = (unsigned long *)sys_accept4;
	sys_call_table[__NR_getsockname] = (unsigned long *)sys_getsockname;
	sys_call_table[__NR_getpeername] = (unsigned long *)sys_getpeername;
	sys_call_table[__NR_send] = (unsigned long *)sys_send;
	sys_call_table[__NR_sendto] = (unsigned long *)sys_sendto;
	sys_call_table[__NR_sendmsg] = (unsigned long *)sys_sendmsg;
	sys_call_table[__NR_recv] = (unsigned long *)sys_recv;
	sys_call_table[__NR_recvfrom] = (unsigned long *)sys_recvfrom;
	sys_call_table[__NR_recvmsg] = (unsigned long *)sys_recvmsg;
	sys_call_table[__NR_socket] = (unsigned long *)sys_socket;
	sys_call_table[__NR_socketpair] = (unsigned long *)sys_socketpair;
	sys_call_table[__NR_socketcall] = (unsigned long *)sys_socketcall;
	sys_call_table[__NR_listen] = (unsigned long *)sys_listen;
	sys_call_table[__NR_poll] = (unsigned long *)sys_poll;
	sys_call_table[__NR_select] = (unsigned long *)sys_select;
	sys_call_table[__NR_epoll_create] = (unsigned long *)sys_epoll_create;
	sys_call_table[__NR_epoll_create1] = (unsigned long *)sys_epoll_create1;
	sys_call_table[__NR_epoll_ctl] = (unsigned long *)sys_epoll_ctl;
	sys_call_table[__NR_epoll_wait] = (unsigned long *)sys_epoll_wait;
	sys_call_table[__NR_epoll_pwait] = (unsigned long *)sys_epoll_pwait;
	sys_call_table[__NR_gethostname] = (unsigned long *)sys_gethostname;
	sys_call_table[__NR_sethostname] = (unsigned long *)sys_sethostname;
	sys_call_table[__NR_setdomainname] = (unsigned long *)sys_setdomainname;
	sys_call_table[__NR_newuname] = (unsigned long *)sys_newuname;
	sys_call_table[__NR_getrlimit] = (unsigned long *)sys_getrlimit;
	sys_call_table[__NR_old_getrlimit] = (unsigned long *)sys_old_getrlimit;
	sys_call_table[__NR_setrlimit] = (unsigned long *)sys_setrlimit;
	sys_call_table[__NR_getrusage] = (unsigned long *)sys_getrusage;
	sys_call_table[__NR_umask] = (unsigned long *)sys_umask;
	sys_call_table[__NR_msgget] = (unsigned long *)sys_msgget;
	sys_call_table[__NR_msgsnd] = (unsigned long *)sys_msgsnd;
	sys_call_table[__NR_msgrcv] = (unsigned long *)sys_msgrcv;
	sys_call_table[__NR_msgctl] = (unsigned long *)sys_msgctl;
	sys_call_table[__NR_semget] = (unsigned long *)sys_semget;
	sys_call_table[__NR_semop] = (unsigned long *)sys_semop;
	sys_call_table[__NR_semctl] = (unsigned long *)sys_semctl;
	sys_call_table[__NR_semtimedop] = (unsigned long *)sys_semtimedop;
	sys_call_table[__NR_shmat] = (unsigned long *)sys_shmat;
	sys_call_table[__NR_shmget] = (unsigned long *)sys_shmget;
	sys_call_table[__NR_shmdt] = (unsigned long *)sys_shmdt;
	sys_call_table[__NR_shmctl] = (unsigned long *)sys_shmctl;
	sys_call_table[__NR_mq_open] = (unsigned long *)sys_mq_open;
	sys_call_table[__NR_mq_unlink] = (unsigned long *)sys_mq_unlink;
	sys_call_table[__NR_mq_timedsend] = (unsigned long *)sys_mq_timedsend;
	sys_call_table[__NR_mq_timedreceive] = (unsigned long *)sys_mq_timedreceive;
	sys_call_table[__NR_mq_notify] = (unsigned long *)sys_mq_notify;
	sys_call_table[__NR_mq_getsetattr] = (unsigned long *)sys_mq_getsetattr;
	sys_call_table[__NR_pciconfig_iobase] = (unsigned long *)sys_pciconfig_iobase;
	sys_call_table[__NR_pciconfig_read] = (unsigned long *)sys_pciconfig_read;
	sys_call_table[__NR_pciconfig_write] = (unsigned long *)sys_pciconfig_write;
	sys_call_table[__NR_prctl] = (unsigned long *)sys_prctl;
	sys_call_table[__NR_swapon] = (unsigned long *)sys_swapon;
	sys_call_table[__NR_swapoff] = (unsigned long *)sys_swapoff;
	sys_call_table[__NR_sysctl] = (unsigned long *)sys_sysctl;
	sys_call_table[__NR_sysinfo] = (unsigned long *)sys_sysinfo;
	sys_call_table[__NR_sysfs] = (unsigned long *)sys_sysfs;
	sys_call_table[__NR_nfsservctl] = (unsigned long *)sys_nfsservctl;
	sys_call_table[__NR_syslog] = (unsigned long *)sys_syslog;
	sys_call_table[__NR_uselib] = (unsigned long *)sys_uselib;
	sys_call_table[__NR_ni_syscall] = (unsigned long *)sys_ni_syscall;
	sys_call_table[__NR_ptrace] = (unsigned long *)sys_ptrace;
	sys_call_table[__NR_add_key] = (unsigned long *)sys_add_key;
	sys_call_table[__NR_request_key] = (unsigned long *)sys_request_key;
	sys_call_table[__NR_keyctl] = (unsigned long *)sys_keyctl;
	sys_call_table[__NR_ioprio_set] = (unsigned long *)sys_ioprio_set;
	sys_call_table[__NR_ioprio_get] = (unsigned long *)sys_ioprio_get;
	sys_call_table[__NR_set_mempolicy] = (unsigned long *)sys_set_mempolicy;
	sys_call_table[__NR_migrate_pages] = (unsigned long *)sys_migrate_pages;
	sys_call_table[__NR_move_pages] = (unsigned long *)sys_move_pages;
	sys_call_table[__NR_mbind] = (unsigned long *)sys_mbind;
	sys_call_table[__NR_get_mempolicy] = (unsigned long *)sys_get_mempolicy;
	sys_call_table[__NR_inotify_init] = (unsigned long *)sys_inotify_init;
	sys_call_table[__NR_inotify_init1] = (unsigned long *)sys_inotify_init1;
	sys_call_table[__NR_inotify_add_watch] = (unsigned long *)sys_inotify_add_watch;
	sys_call_table[__NR_inotify_rm_watch] = (unsigned long *)sys_inotify_rm_watch;
	sys_call_table[__NR_spu_run] = (unsigned long *)sys_spu_run;
	sys_call_table[__NR_spu_create] = (unsigned long *)sys_spu_create;
	sys_call_table[__NR_mknodat] = (unsigned long *)sys_mknodat;
	sys_call_table[__NR_mkdirat] = (unsigned long *)sys_mkdirat;
	sys_call_table[__NR_unlinkat] = (unsigned long *)sys_unlinkat;
	sys_call_table[__NR_symlinkat] = (unsigned long *)sys_symlinkat;
	sys_call_table[__NR_linkat] = (unsigned long *)sys_linkat;
	sys_call_table[__NR_renameat] = (unsigned long *)sys_renameat;
	sys_call_table[__NR_futimesat] = (unsigned long *)sys_futimesat;
	sys_call_table[__NR_faccessat] = (unsigned long *)sys_faccessat;
	sys_call_table[__NR_fchmodat] = (unsigned long *)sys_fchmodat;
	sys_call_table[__NR_fchownat] = (unsigned long *)sys_fchownat;
	sys_call_table[__NR_openat] = (unsigned long *)sys_openat;
	sys_call_table[__NR_newfstatat] = (unsigned long *)sys_newfstatat;
	sys_call_table[__NR_fstatat64] = (unsigned long *)sys_fstatat64;
	sys_call_table[__NR_readlinkat] = (unsigned long *)sys_readlinkat;
	sys_call_table[__NR_utimensat] = (unsigned long *)sys_utimensat;
	sys_call_table[__NR_unshare] = (unsigned long *)sys_unshare;
	sys_call_table[__NR_splice] = (unsigned long *)sys_splice;
	sys_call_table[__NR_vmsplice] = (unsigned long *)sys_vmsplice;
	sys_call_table[__NR_tee] = (unsigned long *)sys_tee;
	sys_call_table[__NR_sync_file_range] = (unsigned long *)sys_sync_file_range;
	sys_call_table[__NR_sync_file_range2] = (unsigned long *)sys_sync_file_range2;
	sys_call_table[__NR_get_robust_list] = (unsigned long *)sys_get_robust_list;
	sys_call_table[__NR_set_robust_list] = (unsigned long *)sys_set_robust_list;
	sys_call_table[__NR_getcpu] = (unsigned long *)sys_getcpu;
	sys_call_table[__NR_signalfd] = (unsigned long *)sys_signalfd;
	sys_call_table[__NR_signalfd4] = (unsigned long *)sys_signalfd4;
	sys_call_table[__NR_timerfd_create] = (unsigned long *)sys_timerfd_create;
	sys_call_table[__NR_timerfd_settime] = (unsigned long *)sys_timerfd_settime;
	sys_call_table[__NR_timerfd_gettime] = (unsigned long *)sys_timerfd_gettime;
	sys_call_table[__NR_eventfd] = (unsigned long *)sys_eventfd;
	sys_call_table[__NR_eventfd2] = (unsigned long *)sys_eventfd2;
	sys_call_table[__NR_fallocate] = (unsigned long *)sys_fallocate;
	sys_call_table[__NR_old_readdir] = (unsigned long *)sys_old_readdir;
	sys_call_table[__NR_pselect6] = (unsigned long *)sys_pselect6;
	sys_call_table[__NR_ppoll] = (unsigned long *)sys_ppoll;
	sys_call_table[__NR_perf_event_open] = (unsigned long *)sys_perf_event_open;
	sys_call_table[__NR_mmap_pgoff] = (unsigned long *)sys_mmap_pgoff;
}
