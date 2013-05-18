static struct sock *netlink_sock;

DEFINE_MUTEX(maldetect_recv_mutex);

static void maldetect_msg_recv_skb(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;

	int len;
	int err;

	nlh = nlmsg_hdr(skb);
	len = skb->len;

	while(NLMSG_OK(nlh, len))
	{
		err = audit_
	}
}

static void maldetect_msg_recv(struct sk_buff *skb)
{
	mutex_lock(&maldetect_recv_mutex);
	maldetect_receive_skb(skb);
	mutex_unlock(&maldetect_recv_mutex);
}

static int netlink_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = maldetect_msg_recv,
	};

	netlink_sock = netlink_kernel_create(&init_net, NETLINK_AUDIT, &cfg);
	if (!netlink_sock)
	{
		printk(KERN_INFO "Error initiating netlink socket.\n");
		return 0;
	}

	netlink_sock->sk_sndtimeo = MAX_SCHEDULE_TIMEOUT;

}
