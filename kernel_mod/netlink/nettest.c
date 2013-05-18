#include "nliface.h"
#include "common.h"

static struct *sock maldetect_sock;
static u32 maldetect_userlevel_pid;
DEFINE_MUTEX(maldetect_sock_mutex);

struct sk_buff *maldetect_make_reply(int pid, int seq, int type, int done,
				 int multi, void *payload, int size)
{
	struct sk_buff	*skb;
	struct nlmsghdr	*nlh;
	void		*data;
	int		flags = multi ? NLM_F_MULTI : 0;
	int		t     = done  ? NLMSG_DONE  : type;

	skb = nlmsg_new(size, GFP_KERNEL);
	if (!skb)
		return NULL;

	nlh	= NLMSG_NEW(skb, pid, seq, t, size, flags);
	data	= NLMSG_DATA(nlh);
	memcpy(data, payload, size);
	return skb;

nlmsg_failure:			/* Used by NLMSG_NEW */
	if (skb)
		kfree_skb(skb);
	return NULL;
}

void maldetect_send_syscall(struct syscall_info data)
{
	struct sk_buff *skb;
	struct task_struct *tsk;
	struct nlmsghdr *nlh;
	
}

static int maldetect_send_synack_thread(void *arg)
{
	struct maldetect_synack_reply *reply = (struct maldetect_synack_reply *)arg;
	
	mutex_lock(&maldetect_sock_mutex);
	mutex_unlock(&maldetect_sock_mutex);
	
	netlink_unicast(maldetect_sock, reply->skb, reply->pid, 0);
	kfree(reply);
	return 0;
}

void maldetect_send_synack(int pid, int seq)
{
	struct sk_buff *skb;
	struct task_struct *tsk;
	struct nlmsghdr *nlh;
	void *data;
	struct maldetect_synack_reply *reply = kmalloc(sizeof(struct maldetect_synack_reply), GFP_KERNEL);
	if (!reply)
	{
		return;
	}
	
	skb = maldetect_make_reply(pid, seq, MALDETECT_SYNACK, 0, 0, reply, sizeof(struct maldetect_synack_reply));
	
	if (!skb)
	{
		kfree(reply);
		return;
	}

	reply->pid = pid;
	reply->skb = skb;
	
	tsk = kthread_run(maldetect_send_reply_thread, reply, "maldetect_synack");
	if (!IS_ERR(tsk))
	{
		return;
	}
	
	kfree_skb(skb);
	kfree(reply);
}

static void maldetect_receive_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	u32 pid, seq;
	u16 msg_type;
	
	pid = NETLINK_CREDS(skb)->pid;
	seq = nlh->nlmsg_seq;
	msg_type = nlh->nlmsg_type;
	
	switch (msg_type)
	{
		case MALDETECT_SYN:
			maldetect_send_synack(NETLINK_CB(skb).pid, seq);
		case MALDETECT_ACK:
			maldetect_userlevel_pid = pid;
	}
}

static void audit_receive_skb(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int len;
	
	nlh = nlmsg_hdr(skb)
	len = skb->len;
	
	while (NLMSG_OK(nlh, len))
	{
		maldetect_receive_msg(skb, nlh);
		nlh = NLMSG_NEXT(nlh, len);
	}
}

static void maldetect_receive(struct sk_buff *skb)
{
	mutex_lock(&maldetect_sock_mutex);
	maldetect_receive_skb(skb);
	mutex_unlock(&maldetect_sock_mutex);
}

static int maldetect_netlink_init(void)
{
	maldetect_userlevel_pid = 0;
	maldetect_sock = netlink_kernel_create(&init_net, NETLINK_KOBJECT_UEVENT, 0, maldetect_receive, NULL, THIS_MODULE);
	skb_queue_head_init(&maldetect_skb_queue);
	skb_queue_head_init(&maldetect_skb_hold_queue);
	
	return 0;
}