/*
 * The netlink interface for the KMaldetect LKM. It contains init and exit functions for the interface, as well as several receive and send functions.
 *
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include "kmaldetect.h"
#include "hooks.h"

#define NETLINK_MALDETECT 24

DEFINE_MUTEX(maldetect_nl_mutex);
static struct sock *nl_sk;
pid_t maldetect_userspace_pid;

/* Exported send_syscall function to pass syscall information to the userspace application */
int maldetect_nl_send_syscall(SYSCALL *msg)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	int res;
	if (NULL == (skb = alloc_skb(NLMSG_SPACE(sizeof(SYSCALL)), GFP_ATOMIC)))
	{
		printk(KERN_WARNING "[kmaldetect] Failed to allocate memory for skb\n");
		return -1;
	}

	nlh = (struct nlmsghdr *)skb_put(skb, NLMSG_SPACE(sizeof(SYSCALL)));
	nlh->nlmsg_type = 0;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(SYSCALL));
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_seq = 0;
	memset(NLMSG_DATA(nlh) + sizeof(SYSCALL), 0, NLMSG_SPACE(sizeof(SYSCALL)) - NLMSG_LENGTH(sizeof(SYSCALL)));
	memcpy(NLMSG_DATA(nlh), msg, sizeof(SYSCALL));
	mutex_lock(&maldetect_nl_mutex);
	res = netlink_unicast(nl_sk, skb, maldetect_userspace_pid, 1);
	mutex_unlock(&maldetect_nl_mutex);
	return 0;
}

/* Initial setup of a connection with the userspace application. todo: create an error-recovery method for the connection  */
static void recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	pid_t pid;
	struct sk_buff *skb_out;
	int msg_size;
	char *msg = "kmaldetect-ack";
	int res;

	mutex_lock(&maldetect_nl_mutex);
	msg_size = strlen(msg);
	nlh = nlmsg_hdr(skb);

	if (strncmp((char *)nlmsg_data(nlh), "maldetect-syn", strlen("maldetect-syn")) != 0)
	{
		printk(KERN_WARNING "[kmaldetect] Received invalid maldetect-syn message: %s\n", (char *)nlmsg_data(nlh));
		mutex_unlock(&maldetect_nl_mutex);
		return;
	}

	printk(KERN_INFO "[kmaldetect] Received maldetect-syn\n");
	if ((pid = nlh->nlmsg_pid) <= 0)
	{
		printk(KERN_WARNING "[kmaldetect] Received invalid PID from maldetect-syn message: %i\n", pid);
		mutex_unlock(&maldetect_nl_mutex);
		return;
	}

	skb_out = nlmsg_new(msg_size, 0);
	if (!skb_out)
	{
		printk(KERN_WARNING "[kmaldetect] Failed to allocate new skb\n");
		mutex_unlock(&maldetect_nl_mutex);
		return;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	strncpy(nlmsg_data(nlh), msg, msg_size);
	nlmsg_end(skb_out, nlh);

	res = nlmsg_unicast(nl_sk, skb_out, pid);
	if (res != 0)
	{
		printk(KERN_WARNING "[kmaldetect] Failed to send kmaldetect-ack message to %i\n", pid);
		mutex_unlock(&maldetect_nl_mutex);
		return;
	}

	maldetect_userspace_pid = pid;

	mutex_unlock(&maldetect_nl_mutex);
	printk(KERN_INFO "[kmaldetect] Set ulevel pid to %i\n", maldetect_userspace_pid);
}

/* Exported init-function for the netlink interface */
void maldetect_nl_init(void)
{
	maldetect_userspace_pid = -1;
	nl_sk = netlink_kernel_create(&init_net, NETLINK_MALDETECT, 0, recv_msg, NULL, THIS_MODULE);

	if (!nl_sk)
	{
		printk(KERN_WARNING "%s: failed to create nl socket\n", __FUNCTION__);
	}

	printk(KERN_INFO "[kmaldetect] Created socket\n");
}

void maldetect_nl_close(void)
{
	mutex_lock(&maldetect_nl_mutex);
	netlink_kernel_release(nl_sk);
	mutex_unlock(&maldetect_nl_mutex);
}
