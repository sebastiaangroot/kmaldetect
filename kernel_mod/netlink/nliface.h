#ifndef NLIFACE_H
#define NLIFACE_H

#define MALDETECT_SYN		0
#define MALDETECT_SYNACK	1
#define MALDETECT_ACK		2
#define MALDETECT_SYSINFO	3

struct maldetect_synack_reply
{
	struct sk_buff *skb;
	u32 pid;
};

#endif