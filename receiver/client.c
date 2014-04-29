/*
 * This is the entry point for the KMaldetect Receiver. It initializes the application and then starts listening to the KMaldetect LKM.
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include "maldetect.h"
#include "util.h"
#include "mm.h"

#include <pwd.h>
#include <sched.h>

/*
* - Check if we're root
* - Set our scheduler to the soft-realtime round robin scheduler
* - Set our uid and gid to that of user maldetect
* - Initiate the first 64KB block of memory to store syscall data
* - Prepare our netlink socket for listening to our kernel module
* - Send the message "maldetect-syn" and wait for the message "kmaldetect-ack"
* - Keep listening for mesages that send a SYSCALL struct, and upon receiving them, store them using the mm.c's functions
* */
extern int block_lim;
int main(void)
{
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	int sock_fd;
	struct msghdr msg;
	block_lim = 4;

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
	if (drop_privileges() != 0)
	{
		fprintf(stderr, "Failed to drop privileges. Is system account \"%s\" available?\n", SYSACCOUNT);
		exit(1);
	}

	if (mm_init() != 0)
	{
		fprintf(stderr, "Failed to initialize the memory manager.\n");
		exit(1);
	}

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

	recvmsg(sock_fd, &msg, 0);
	printf("Received message: %s\n", (char *)NLMSG_DATA(nlh));
	memset(NLMSG_DATA(nlh), 0, strlen((char *)NLMSG_DATA(nlh)));

	while (1)
	{
		recvmsg(sock_fd, &msg, 0);
		SYSCALL *data = (SYSCALL *)NLMSG_DATA(nlh);
		printf("%i,%lu,%i\n", data->sys_id, data->inode, data->pid);
		store_syscall(data);
		memset(NLMSG_DATA(nlh), 0, sizeof(SYSCALL));
	}

	return 0;
}

