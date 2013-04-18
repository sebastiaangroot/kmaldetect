#define SYSCALL_NAME_S 64
#define STRACE_S 2048
struct syscall_collection
{
	unsigned int pid;
	unsigned char syscalls[STRACE_S][SYSCALL_NAME_S];
};
