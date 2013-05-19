#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/wait.h>
#include <net/net_namespace.h>

struct sock *nl_sk = NULL;

void netlink_test(void)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	int err;
	u32 pid;

	nl_sk = netlink_kernel_create(&init_net, NETLINK_GENERIC, NULL, NULL, NULL, THIS_MODULE);

	skb = skb_recv_datagram(nl_sk, 0, 0, &err);

	nlh = (struct nlmsghdr *)skb->data;
	printk("Received message\n");

	pid = nlh->nlmsg_pid;
}

static int __init nettest_start(void)
{
	printk("Started...\n");
	netlink_test();
	return 0;
}

static void __exit nettest_stop(void)
{
	printk("Stopped...\n");
}

module_init(nettest_start);
module_exit(nettest_stop);
