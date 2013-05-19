#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>

static struct sock *nettest_sock;
DEFINE_MUTEX(nettest_mutex);

static void nettest_parse(struct sk_buff *skb)
{
	printk("I received something!\n");
	skb = skb;
}

static void nettest_receive(struct sk_buff *skb)
{
	mutex_lock(&nettest_mutex);
	nettest_parse(skb);
	mutex_unlock(&nettest_mutex);
}

static int __init nettest_start(void)
{
	printk("Working\n");

	nettest_sock = netlink_kernel_create(&init_net, NETLINK_GENERIC, 0, nettest_receive, NULL, THIS_MODULE);

	return 0;
}

static void __exit nettest_end(void)
{
	printk("Exited\n");
}

module_init(nettest_start);
module_exit(nettest_end);
