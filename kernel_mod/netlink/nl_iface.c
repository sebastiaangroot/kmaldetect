#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include "kmaldetect.h"

#define NETLINK_MALDETECT 24

DEFINE_MUTEX(maldetect_nl_mutex);
struct sock *nl_sk;
int userspace_pid;

/* Exported send_syscall function to pass syscall information to the userspace application */
int maldetect_nl_send_syscall(SYSCALL data)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	int msg_size;
	int res;

	if (userspace_pid <= 0)
	{
		return 0;
	}

	//msg_size = sizeof(data);
	msg_size = strlen("test");
	skb_out = nlmsg_new(msg_size, 0);
	if (!skb_out)
	{
		printk(KERN_WARNING "[kmaldetect] Failed to allocate new skb\n");
		return 0;
	}
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	//memcpy(nlmsg_data(nlh), &data, msg_size);
	strncpy(nlmsg_data(nlh), "test", msg_size);

	mutex_lock(&maldetect_nl_mutex);
	res = nlmsg_unicast(nl_sk, skb_out, userspace_pid);
	mutex_unlock(&maldetect_nl_mutex);
	
	if (!res)
	{
		printk(KERN_WARNING "[kmaldetect] Failed to send syscall message to maldetect userspace application\n");
		return 0;
	}
	return 1;
}

/* Once we've established connection with the userspace application, we do nothing with incomming traffic */
static void recv_msg_dummy(struct sk_buff *skb)
{
	SYSCALL data;
	int res;

	data.sys_id = 5;
	data.inode = 6;
	data.pid = 7;
	data.mloc = 8;

	printk("Trying to send a syscall message\n");
	res = maldetect_nl_send_syscall(data);
}

/* Initial setup of a connection with the userspace application. todo: create an error-recovery method for the connection  */
static void recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int pid;
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
	res = nlmsg_unicast(nl_sk, skb_out, pid);
	if (res != 0)
	{
		printk(KERN_WARNING "[kmaldetect] Failed to send kmaldetect-ack message to %i\n", pid);
		mutex_unlock(&maldetect_nl_mutex);
		return;
	}

	userspace_pid = pid;
	netlink_kernel_release(nl_sk);
	nl_sk = netlink_kernel_create(&init_net, NETLINK_MALDETECT, 0, recv_msg_dummy, NULL, THIS_MODULE);
	mutex_unlock(&maldetect_nl_mutex);
	printk(KERN_INFO "Set ulevel pid to %i\n", userspace_pid);
}

/* Exported init-function for the netlink interface */
void maldetect_nl_init(void)
{
	userspace_pid = -1;
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
