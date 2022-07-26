
typedef struct {
        u32 guest_addr;
        u32 host_addr;
        u8 host_if;
} config_t;

typedef struct {
        u16 begin;
        u16 end;
} port_range_t;

#define MAX_RANGE_COUNT 8

enum {
	SYS_REJECT = 0,
	SYS_PROCEED,
	SYS_RETRY
};

#define	EEXIST		17	/* File exists */

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/

#define AF_INET		2	/* Internet IP Protocol 	*/

#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7

#define TCP_H_LEN	(sizeof(struct tcphdr))
#define UDP_H_LEN	(sizeof(struct udphdr))
#define IP_H_LEN	(sizeof(struct iphdr))

#define ETH_TOTAL_H_LEN	(sizeof(struct ethhdr))
#define IP_TOTAL_H_LEN	(ETH_TOTAL_H_LEN + IP_H_LEN)
#define TCP_TOTAL_H_LEN	(IP_TOTAL_H_LEN + TCP_H_LEN)
#define UDP_TOTAL_H_LEN	(IP_TOTAL_H_LEN + UDP_H_LEN)

#define IP_CSUM_OFFSET	(ETH_TOTAL_H_LEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFFSET	(IP_TOTAL_H_LEN + offsetof(struct tcphdr, check))
#define UDP_CSUM_OFFSET	(IP_TOTAL_H_LEN + offsetof(struct udphdr, check))

#define IS_PSEUDO 0x10

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

enum {
	USER_HOST,
	USER_GUEST,
	USER_MAX
};

typedef struct {
	u32 daddr;
	u16 sport;
	u16 dport;
} key_est_t;

typedef struct {
	u32 raddr; /* real server address(used for IPVS) */
	u16 rport; /* real server port(used for IPVS) */
	u16 user;
} val_est_t;

typedef struct {
	u16 sport;
} key_lst_t;

typedef struct {
	u16 refs[USER_MAX];
} val_lst_t;

typedef struct {
	__be16	source;
	__be16	dest;
} tcphdr_min_t;

typedef struct {
	__be16	source;
	__be16	dest;
} udphdr_min_t;

enum log_ops {
	LOG_OPS_CONN,
	LOG_OPS_LISTEN
};

enum log_event {
	LOG_EVENT_CONFLICT,
	LOG_EVENT_MAP_ERROR,
};

typedef struct {
	u8 user;	/* trigered by CVM or container. 0 for CVM and 1
			 * for container.
			 */
	u8 proto;	/* protocol number (UDP or TCP) */
	u8 ops;		/* 0 for connect, 1 for listen */
	u8 event;	/* 0 for conflict. */
	u32 saddr;	/* local ip addr in network bit order */
	u32 daddr;	/* remote ip addr in network bit order */
	u16 sport;	/* local port in network bit order */
	u16 dport;	/* remote port in network bit order */
} log_t;

#define SKB_DATA_END_PTR(skb)	((void *)(long)skb->data_end)
#define SKB_DATA_PTR(skb)	((void *)(long)skb->data)
#define SKB_INVALID_IP(skb)	\
	(SKB_DATA_PTR(skb) + IP_TOTAL_H_LEN > SKB_DATA_END_PTR(skb))
#define SKB_HDR_IP(skb)		\
	(SKB_DATA_PTR(skb) + ETH_TOTAL_H_LEN)

/* Change network bytes order u32 to network bytes order u16 */
static __always_inline u16 be32tobe16(u32 p)
{
	return *((u16 *)&p + 1);
}

static __always_inline u16 le32tobe16(u32 p)
{
	return bpf_htons((u16)p);
}

static __always_inline u8 get_ip_header_len(struct iphdr *ip)
{
	u8 len = (((u8 *)ip)[0] & 0xF0) * 4;
	return len > IP_H_LEN ? len: IP_H_LEN;
}

static __always_inline bool is_ip_frag(struct iphdr *ip)
{
	return ip->frag_off & bpf_htons(0x3FFF);
}

static __always_inline bool is_init_ns(void *sk)
{
	return bpf_get_netns_cookie(sk) == bpf_get_netns_cookie(NULL);
}

static inline void *try_pull_ip_hdr(struct __sk_buff *skb)
{
	if (SKB_INVALID_IP(skb)) {
		bpf_skb_pull_data(skb, IP_TOTAL_H_LEN);
		if (SKB_INVALID_IP(skb))
			return NULL;
	}
	return SKB_HDR_IP(skb);
}

static inline void *load_l4_hdr(struct __sk_buff *skb, struct iphdr *ip,
			        void *dst, u32 len)
{
	u32 offset, iplen;
	void *l4;

	iplen = get_ip_header_len(ip);
	offset = ETH_TOTAL_H_LEN + MAX(iplen, IP_H_LEN);
	l4 = SKB_DATA_PTR(skb) + offset;

	if (l4 + len > SKB_DATA_END_PTR(skb)) {
		if (bpf_skb_load_bytes(skb, offset, dst, len))
			return NULL;
		return dst;
	}
	return l4;
}

static inline void compute_addr_csum(struct __sk_buff *skb, u32 offset,
				     u32 old_ip, u32 new_ip)
{
	bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, old_ip, new_ip,
			    sizeof(new_ip));
	bpf_l4_csum_replace(skb, offset, old_ip, new_ip,
			    IS_PSEUDO | sizeof(new_ip));
}
