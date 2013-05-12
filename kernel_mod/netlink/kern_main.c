#include <linux/module.h>
#include <linux/kernel.h>

#define NETLINK_TEST 17

static unsigned int user_pid = -1;
struct sock *nl_sk = NULL;

int netlinktest_createsock(void)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	int err;
	unsigned int pid;

	nl_sk = netlink_kernel_create(NETLINK_TEST, NULL); //Second argument is the message receiving function, not used here


}

static int __init mod_start(void)
{
	printk(KERN_INFO "netlinktest loaded\n");
	if (netlinktest_createsock() != 0)
	{
		return -1;
	}

	return 0;
}

static void __exit mod_end(void)
{
	printk(KERN_INFO "netlinktest exiting\n");
}

module_init(mod_start);
module_exit(mod_end);
