#!/bin/bash
#This script is prepared to create signatures for a 2.6.32-358.6.1.el6.x86_64 linux kernel using the 64-bit unistd.h asm header

function usage
{
	echo "Usage: $0 -o <outfile> <executable> [arguments]"
	exit
}

function get_syscall_index
{
	case $1 in
		'read')
			return 0
			;;
		'write')
			return 1
			;;
		'open')
			return 2
			;;
		'close')
			return 3
			;;
		'stat')
			return 4
			;;
		'fstat')
			return 5
			;;
		'lstat')
			return 6
			;;
		'poll')
			return 7
			;;
		'lseek')
			return 8
			;;
		'mmap')
			return 9
			;;
		'mprotect')
			return 10
			;;
		'munmap')
			return 11
			;;
		'brk')
			return 12
			;;
		'rt_sigaction')
			return 13
			;;
		'rt_sigprocmask')
			return 14
			;;
		'ioctl')
			return 16
			;;
		'pread64')
			return 17
			;;
		'pwrite64')
			return 18
			;;
		'readv')
			return 19
			;;
		'writev')
			return 20
			;;
		'access')
			return 21
			;;
		'pipe')
			return 22
			;;
		'select')
			return 23
			;;
		'sched_yield')
			return 24
			;;
		'mremap')
			return 25
			;;
		'msync')
			return 26
			;;
		'mincore')
			return 27
			;;
		'madvise')
			return 28
			;;
		'shmget')
			return 29
			;;
		'shmat')
			return 30
			;;
		'shmctl')
			return 31
			;;
		'dup')
			return 32
			;;
		'dup2')
			return 33
			;;
		'pause')
			return 34
			;;
		'nanosleep')
			return 35
			;;
		'getitimer')
			return 36
			;;
		'alarm')
			return 37
			;;
		'setitimer')
			return 38
			;;
		'getpid')
			return 39
			;;
		'sendfile')
			return 40
			;;
		'socket')
			return 41
			;;
		'connect')
			return 42
			;;
		'accept')
			return 43
			;;
		'sendto')
			return 44
			;;
		'recvfrom')
			return 45
			;;
		'sendmsg')
			return 46
			;;
		'recvmsg')
			return 47
			;;
		'shutdown')
			return 48
			;;
		'bind')
			return 49
			;;
		'listen')
			return 50
			;;
		'getsockname')
			return 51
			;;
		'getpeername')
			return 52
			;;
		'socketpair')
			return 53
			;;
		'setsockopt')
			return 54
			;;
		'getsockopt')
			return 55
			;;
		'exit')
			return 60
			;;
		'wait4')
			return 61
			;;
		'kill')
			return 62
			;;
		'uname')
			return 63
			;;
		'semget')
			return 64
			;;
		'semop')
			return 65
			;;
		'semctl')
			return 66
			;;
		'shmdt')
			return 67
			;;
		'msgget')
			return 68
			;;
		'msgsnd')
			return 69
			;;
		'msgrcv')
			return 70
			;;
		'msgctl')
			return 71
			;;
		'fcntl')
			return 72
			;;
		'flock')
			return 73
			;;
		'fsync')
			return 74
			;;
		'fdatasync')
			return 75
			;;
		'truncate')
			return 76
			;;
		'ftruncate')
			return 77
			;;
		'getdents')
			return 78
			;;
		'getcwd')
			return 79
			;;
		'chdir')
			return 80
			;;
		'fchdir')
			return 81
			;;
		'rename')
			return 82
			;;
		'mkdir')
			return 83
			;;
		'rmdir')
			return 84
			;;
		'creat')
			return 85
			;;
		'link')
			return 86
			;;
		'unlink')
			return 87
			;;
		'symlink')
			return 88
			;;
		'readlink')
			return 89
			;;
		'chmod')
			return 90
			;;
		'fchmod')
			return 91
			;;
		'chown')
			return 92
			;;
		'fchown')
			return 93
			;;
		'lchown')
			return 94
			;;
		'umask')
			return 95
			;;
		'gettimeofday')
			return 96
			;;
		'getrlimit')
			return 97
			;;
		'getrusage')
			return 98
			;;
		'sysinfo')
			return 99
			;;
		'times')
			return 100
			;;
		'ptrace')
			return 101
			;;
		'getuid')
			return 102
			;;
		'syslog')
			return 103
			;;
		'getgid')
			return 104
			;;
		'setuid')
			return 105
			;;
		'setgid')
			return 106
			;;
		'geteuid')
			return 107
			;;
		'getegid')
			return 108
			;;
		'setpgid')
			return 109
			;;
		'getppid')
			return 110
			;;
		'getpgrp')
			return 111
			;;
		'setsid')
			return 112
			;;
		'setreuid')
			return 113
			;;
		'setregid')
			return 114
			;;
		'getgroups')
			return 115
			;;
		'setgroups')
			return 116
			;;
		'setresuid')
			return 117
			;;
		'getresuid')
			return 118
			;;
		'setresgid')
			return 119
			;;
		'getresgid')
			return 120
			;;
		'getpgid')
			return 121
			;;
		'setfsuid')
			return 122
			;;
		'setfsgid')
			return 123
			;;
		'getsid')
			return 124
			;;
		'capget')
			return 125
			;;
		'capset')
			return 126
			;;
		'rt_sigpending')
			return 127
			;;
		'rt_sigtimedwait')
			return 128
			;;
		'rt_sigqueueinfo')
			return 129
			;;
		'rt_sigsuspend')
			return 130
			;;
		'utime')
			return 132
			;;
		'mknod')
			return 133
			;;
		'uselib')
			return 134
			;;
		'personality')
			return 135
			;;
		'ustat')
			return 136
			;;
		'statfs')
			return 137
			;;
		'fstatfs')
			return 138
			;;
		'sysfs')
			return 139
			;;
		'getpriority')
			return 140
			;;
		'setpriority')
			return 141
			;;
		'sched_setparam')
			return 142
			;;
		'sched_getparam')
			return 143
			;;
		'sched_setscheduler')
			return 144
			;;
		'sched_getscheduler')
			return 145
			;;
		'sched_get_priority_max')
			return 146
			;;
		'sched_get_priority_min')
			return 147
			;;
		'sched_rr_get_interval')
			return 148
			;;
		'mlock')
			return 149
			;;
		'munlock')
			return 150
			;;
		'mlockall')
			return 151
			;;
		'munlockall')
			return 152
			;;
		'vhangup')
			return 153
			;;
		'modify_ldt')
			return 154
			;;
		'pivot_root')
			return 155
			;;
		'_sysctl')
			return 156
			;;
		'prctl')
			return 157
			;;
		'arch_prctl')
			return 158
			;;
		'adjtimex')
			return 159
			;;
		'setrlimit')
			return 160
			;;
		'chroot')
			return 161
			;;
		'sync')
			return 162
			;;
		'acct')
			return 163
			;;
		'settimeofday')
			return 164
			;;
		'mount')
			return 165
			;;
		'umount2')
			return 166
			;;
		'swapon')
			return 167
			;;
		'swapoff')
			return 168
			;;
		'reboot')
			return 169
			;;
		'sethostname')
			return 170
			;;
		'setdomainname')
			return 171
			;;
		'ioperm')
			return 173
			;;
		'create_module')
			return 174
			;;
		'init_module')
			return 175
			;;
		'delete_module')
			return 176
			;;
		'get_kernel_syms')
			return 177
			;;
		'query_module')
			return 178
			;;
		'quotactl')
			return 179
			;;
		'nfsservctl')
			return 180
			;;
		'getpmsg')
			return 181
			;;
		'putpmsg')
			return 182
			;;
		'afs_syscall')
			return 183
			;;
		'tuxcall')
			return 184
			;;
		'security')
			return 185
			;;
		'gettid')
			return 186
			;;
		'readahead')
			return 187
			;;
		'setxattr')
			return 188
			;;
		'lsetxattr')
			return 189
			;;
		'fsetxattr')
			return 190
			;;
		'getxattr')
			return 191
			;;
		'lgetxattr')
			return 192
			;;
		'fgetxattr')
			return 193
			;;
		'listxattr')
			return 194
			;;
		'llistxattr')
			return 195
			;;
		'flistxattr')
			return 196
			;;
		'removexattr')
			return 197
			;;
		'lremovexattr')
			return 198
			;;
		'fremovexattr')
			return 199
			;;
		'tkill')
			return 200
			;;
		'time')
			return 201
			;;
		'futex')
			return 202
			;;
		'sched_setaffinity')
			return 203
			;;
		'sched_getaffinity')
			return 204
			;;
		'set_thread_area')
			return 205
			;;
		'io_setup')
			return 206
			;;
		'io_destroy')
			return 207
			;;
		'io_getevents')
			return 208
			;;
		'io_submit')
			return 209
			;;
		'io_cancel')
			return 210
			;;
		'get_thread_area')
			return 211
			;;
		'lookup_dcookie')
			return 212
			;;
		'epoll_create')
			return 213
			;;
		'epoll_ctl_old')
			return 214
			;;
		'epoll_wait_old')
			return 215
			;;
		'remap_file_pages')
			return 216
			;;
		'getdents64')
			return 217
			;;
		'set_tid_address')
			return 218
			;;
		'restart_syscall')
			return 219
			;;
		'semtimedop')
			return 220
			;;
		'fadvise64')
			return 221
			;;
		'timer_create')
			return 222
			;;
		'timer_settime')
			return 223
			;;
		'timer_gettime')
			return 224
			;;
		'timer_getoverrun')
			return 225
			;;
		'timer_delete')
			return 226
			;;
		'clock_settime')
			return 227
			;;
		'clock_gettime')
			return 228
			;;
		'clock_getres')
			return 229
			;;
		'clock_nanosleep')
			return 230
			;;
		'exit_group')
			return 231
			;;
		'epoll_wait')
			return 232
			;;
		'epoll_ctl')
			return 233
			;;
		'tgkill')
			return 234
			;;
		'utimes')
			return 235
			;;
		'vserver')
			return 236
			;;
		'mbind')
			return 237
			;;
		'set_mempolicy')
			return 238
			;;
		'get_mempolicy')
			return 239
			;;
		'mq_open')
			return 240
			;;
		'mq_unlink')
			return 241
			;;
		'mq_timedsend')
			return 242
			;;
		'mq_timedreceive')
			return 243
			;;
		'mq_notify')
			return 244
			;;
		'mq_getsetattr')
			return 245
			;;
		'kexec_load')
			return 246
			;;
		'waitid')
			return 247
			;;
		'add_key')
			return 248
			;;
		'request_key')
			return 249
			;;
		'keyctl')
			return 250
			;;
		'ioprio_set')
			return 251
			;;
		'ioprio_get')
			return 252
			;;
		'inotify_init')
			return 253
			;;
		'inotify_add_watch')
			return 254
			;;
		'inotify_rm_watch')
			return 255
			;;
		'migrate_pages')
			return 256
			;;
		'openat')
			return 257
			;;
		'mkdirat')
			return 258
			;;
		'mknodat')
			return 259
			;;
		'fchownat')
			return 260
			;;
		'futimesat')
			return 261
			;;
		'newfstatat')
			return 262
			;;
		'unlinkat')
			return 263
			;;
		'renameat')
			return 264
			;;
		'linkat')
			return 265
			;;
		'symlinkat')
			return 266
			;;
		'readlinkat')
			return 267
			;;
		'fchmodat')
			return 268
			;;
		'faccessat')
			return 269
			;;
		'pselect6')
			return 270
			;;
		'ppoll')
			return 271
			;;
		'unshare')
			return 272
			;;
		'set_robust_list')
			return 273
			;;
		'get_robust_list')
			return 274
			;;
		'splice')
			return 275
			;;
		'tee')
			return 276
			;;
		'sync_file_range')
			return 277
			;;
		'vmsplice')
			return 278
			;;
		'move_pages')
			return 279
			;;
		'utimensat')
			return 280
			;;
		'epoll_pwait')
			return 281
			;;
		'signalfd')
			return 282
			;;
		'timerfd_create')
			return 283
			;;
		'eventfd')
			return 284
			;;
		'fallocate')
			return 285
			;;
		'timerfd_settime')
			return 286
			;;
		'timerfd_gettime')
			return 287
			;;
		'accept4')
			return 288
			;;
		'signalfd4')
			return 289
			;;
		'eventfd2')
			return 290
			;;
		'epoll_create1')
			return 291
			;;
		'dup3')
			return 292
			;;
		'pipe2')
			return 293
			;;
		'inotify_init1')
			return 294
			;;
		'preadv')
			return 295
			;;
		'pwritev')
			return 296
			;;
		'rt_tgsigqueueinfo')
			return 297
			;;
		'perf_event_open')
			return 298
			;;
		'recvmmsg')
			return 299
			;;
		'fanotify_init')
			return 300
			;;
		'fanotify_mark')
			return 301
			;;
		'prlimit64')
			return 302
			;;
		'name_to_handle_at')
			return 303
			;;
		'open_by_handle_at')
			return 304
			;;
		'clock_adjtime')
			return 305
			;;
		'syncfs')
			return 306
			;;
		'sendmmsg')
			return 307
			;;
		'set_ns')
			return 308
			;;
		'get_cpu')
			return 309
			;;
		'process_vm_readv')
			return 310
			;;
		'process_vm_writev')
			return 311
			;;
	esac
	return 1000
}

OUTFILE=
STRACE_ARGS=
SYSCALLS=
SYS_NUM_WRITTEN=0

#Argument handling (required option -o <outfile> first, then all remaining arguments as input for strace)
while getopts ":ho:" opt
do
	case $opt in
		o)
			OUTFILE=$OPTARG
			shift $((OPTIND-1))
			;;
		h)
			usage
			;;
		\?)
			usage
			;;
		:)
			usage
			;;
	esac
done

if [ $# -eq 0 ]
then
	usage
fi

while [ $# -ne 0 ]
do
	if [ -z "$STRACE_ARGS" ]
	then
		STRACE_ARGS="$1"
	else
		STRACE_ARGS="$STRACE_ARGS $1"
	fi

	shift
done

#Generate the strace, strip everything but the syscall name and recode the syscall names to a sequence of syscall numbers
strace $STRACE_ARGS 2> $OUTFILE.strace
cat $OUTFILE.strace | cut -d "(" -f 1 > $OUTFILE.tmp

SYSCALLS=(`cat $OUTFILE.tmp`)

for (( i=0; i < ${#SYSCALLS[@]}; i++))
do
	get_syscall_index ${SYSCALLS[$i]}
	ANS=$?
	if [ $ANS -ne 1000 ]
	then
		if [ $SYS_NUM_WRITTEN -eq 0 ]
		then
			echo -n "$ANS" > $OUTFILE
			SYS_NUM_WRITTEN=1
		else
			echo -n ",$ANS" >> $OUTFILE
		fi
	fi
done

rm -f $OUTFILE.strace $OUTFILE.tmp
