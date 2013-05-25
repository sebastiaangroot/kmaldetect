#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include "kmaldetect.h"

#include <pwd.h>
#include <sched.h>

#define NETLINK_MALDETECT 24
#define MAX_PAYLOAD 1024
#define SYSACCOUNT	"maldetect"

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int set_rr_scheduler(void)
{
	struct sched_param param;
	param.sched_priority = sched_get_priority_max(SCHED_RR);
	if (sched_setscheduler(0, SCHED_RR, &param) != 0)
	{
		return -1;
	}

	return 0;
}

int drop_privileges(void)
{
	struct passwd *user_info = getpwnam(SYSACCOUNT);
	if (setgid(user_info->pw_gid) != 0 || setuid(user_info->pw_uid) != 0)
	{
		return 0;
	}

	return 1;
}

int main(void)
{
	//Check if we're running as root
	if (getuid() != 0)
	{
		fprintf(stderr, "This application needs to be run as root.\n");
		exit(1);
	}

	//Set the scheduler to the soft-realtime round robin scheduler
	if (set_rr_scheduler() != 0)
	{
		fprintf(stderr, "Failed to change the scheduler.\n");
		exit(1);
	}

	//We only needed to be root to change the scheduler. Drop privileges
	if (!drop_privileges())
	{
		fprintf(stderr, "Failed to drop privileges. Is system account \"%s\" available?\n", SYSACCOUNT);
		exit(1);
	}

	int doonce = 0;
	sock_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_MALDETECT);

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();

	bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;

	nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	strcpy(NLMSG_DATA(nlh), "maldetect-syn");
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("Sending message to kernel\n");
	sendmsg(sock_fd, &msg, 0);

	printf("Waiting for message from kernel\n");
	
	while (1)
	{
		recvmsg(sock_fd, &msg, 0);
		printf("Received message: %s\n", (char *)NLMSG_DATA(nlh));
		if (!doonce)
		{
			msg.msg_name = (void *)&dest_addr;
			msg.msg_namelen = sizeof(dest_addr);
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			sendmsg(sock_fd, &msg, 0);
			doonce = 1;
		}
	}

	return 0;
}
