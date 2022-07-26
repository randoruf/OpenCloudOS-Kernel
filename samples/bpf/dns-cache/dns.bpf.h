#ifndef __DNS_BPF_H
#define __DNS_BPF_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define ETH_ALEN         6
#define ETH_P_IP         0x0800 
#define IP_LEN_MSK       0x0F

#define TC_ACT_UNSPEC    (-1)
#define TC_ACT_OK        (0)
#define TC_ACT_SHOT      (2)
#define TC_ACT_STOLEN    (4)
#define TC_ACT_QUEUED    (5)
#define TC_ACT_REDIRECT  (7)
#define TC_ACT_TRAP      (8)

#define OK               (0)
#define EFULL            (-7)

/* dns macro */

#define DNS_PORT     	  53
#define DNS_QUERY         0		/* opcode */
#define DNS_REPLY         1

#define DNS_NORMAL        0x00
#define DNS_COMPRESSED    0xc0
#define DNS_RESERVED      0x80
#define DNS_EXTEND        0x40
#define DNS_FLAG_MASK     0xc0

#define DNS_CLS_TCPIP     1
#define DNS_TYPE_IPV4     1
#define DNS_TYPE_CNAME    5
#define DNS_TYPE_SOA      6
#define DNS_TYPE_IPV6     28

#define DNS_STANDARD      0
#define MAX_QUERIES_LIMIT 1
#define MAX_ANSWER_LIMIT  50     /* max answer information count */
#define MAX_AUTH_LIMIT    50     /* max authorization information count */

#define DNS_ATTR_LEN      4
#define MAX_UDP_LEN       500    /* max udp length  */
#define MAX_NAME_LEN      100    /* max dns name length */
#define NS_IN_SECS        1000000000

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

struct dnshdr {
	u16 id;           /* unique id */
	u16 flags;
	u16 qcount;       /* queries information count*/
	u16 rcount;       /* answer information count */
	u16 acount;       /* authorization information count */
	u16 ecount;       /* additional information count */
};

#define IPV4_OFF     	  (sizeof(struct ethhdr))
#define UDP_OFF      	  (IPV4_OFF + sizeof(struct iphdr))
#define DNS_OFF      	  (UDP_OFF + sizeof(struct udphdr))
#define DATA_OFF     	  (DNS_OFF + sizeof(struct dnshdr))

#define ETH_OF(member)    (offsetof(struct ethhdr, member))
#define IPV4_OF(member)   (IPV4_OFF + offsetof(struct iphdr, member))
#define UDP_OF(member)    (UDP_OFF + offsetof(struct udphdr, member))
#define DNS_OF(member)    (DNS_OFF + offsetof(struct dnshdr, member))

#define DNS_RECODE_SHIFT  0
#define DNS_RA_SHIFT      7
#define DNS_RD_SHIFT      8
#define DNS_TC_SHIFT      9
#define DNS_AA_SHIFT      10
#define DNS_OPCODE_SHIFT  11
#define DNS_QR_SHIFT      15

#define DNS_QR_MASK       (1 << DNS_QR_SHIFT)
#define DNS_OPCODE_MASK   (0xf << DNS_OPCODE_SHIFT)

#define DNS_RA            (1 <<  DNS_RA_SHIFT)
#define DNS_QR(qr)        (qr << DNS_QR_SHIFT)
#define DNS_RECODE(code)  (code << DNS_RECODE_SHIFT)
#define DNS_OPCODE(flags) ((flags >> DNS_OPCODE_SHIFT) & 0xf)

/* UDP pseudo header */
struct pudphdr{
	u32  saddr;
	u32  daddr;
	u8   zero;
	u8   proto;
	u16  length;
};

typedef struct dns_stat {
	u32 total;                       /* total queries */
	u32 cache_hit;                   /* cache hit */
	u32 cache_miss;                  /* cache miss */
	u32 cache_full;                  /* cache full */
	u32 queries_limit;               /* exceeded the default maximum count of query */
	u32 answer_limit;                /* exceeded the default maximum count of answer */
	u32 auth_limit;                  /* exceeded the default maximum count of auth */
	u32 additional_limit;            /* exceeded the default maximum count of additional */
	u32 store_failed;                /* unable to store cache */
	u32 parse_failed;                /* parse error */
	u32 redirect_failed;             /* redirect failed */
	u32 nonstandard;                 /* non-standard dns frame */
	u32 key_overflow;                /* insufficient key buffer space */
	u32 value_overflow;              /* insufficient value buffer space */
} stat_t;

static __always_inline int dns_name_length(struct __sk_buff * skb, u64 off)
{
	int ret;
	uint8_t byte;
	int size;

	ret = bpf_skb_load_bytes(skb, off, &byte, 1);
	if (unlikely(ret < 0))
		return -1;

	switch(byte & DNS_FLAG_MASK) {
	case DNS_COMPRESSED:
		size = 2; // compression frame only uses 2 bytes
		break;
	case DNS_NORMAL: // compute the size of name
		for (size = 1; size < MAX_NAME_LEN; size++) {
			ret = bpf_skb_load_bytes(skb, off + size, &byte, 1);
			if (unlikely(ret < 0))
				return -1;

			if (unlikely(byte == 0)) {
				size++;
				break;
			}
		}
		break;
	case DNS_EXTEND: // not support
	case DNS_RESERVED:
	default:
		size = 0;
		break;
	}

	return size;
}

static __always_inline int dns_section_ttl(struct __sk_buff * skb, u64 off, u32 *ttl)
{
	int ret;
	u16 length;
	int nameoff;

	nameoff = dns_name_length(skb, off);
	if (unlikely(nameoff <= 0))
		return -1;

	ret = bpf_skb_load_bytes(skb, off + nameoff + 4, ttl, 4);
	if (unlikely(ret < 0))
		return -1;

	ret = bpf_skb_load_bytes(skb, off + nameoff + 8, &length, 2);
	if (unlikely(ret < 0))
		return -1;

	*ttl = bpf_ntohl(*ttl);
	length = bpf_ntohs(length);

	return off + nameoff + 10 + length;
}

static __always_inline int dns_replace_ttl(struct __sk_buff * skb, u64 off, u32 ttl)
{
	int ret;
	u16 length;
	int nameoff;

	ttl = bpf_htonl(ttl);
	nameoff = dns_name_length(skb, off);
	if (unlikely(nameoff <= 0))
		return -1;

	ret = bpf_skb_store_bytes(skb, off + nameoff + 4, &ttl, 4, 1);
	if (unlikely(ret < 0))
		return -1;

	ret = bpf_skb_load_bytes(skb, off + nameoff + 8, &length, 2);
	if (unlikely(ret < 0))
		return -1;

	length = bpf_ntohs(length);
	return off + length + nameoff + 10;
}

static __always_inline int dns_load_section(struct __sk_buff * skb, u64 off, u8 *bytes, u64 max)
{
	int i;
	volatile u64 size;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	data = data + off;
	/* read dns name section */
	for (size = 0; size < max; size++) {
		if (data + size + sizeof(u8) > data_end)
			return -1;

		bytes[size]  = *(u8 *)(data + size);
		if (unlikely(bytes[size] == 0)) {
			size++;
			break;
		}
	}

	/* read dns class+type section */
	for (i = 0; size < max && i < DNS_ATTR_LEN; size++) {
		if (data + size + sizeof(u8) > data_end)
			return -1;

		bytes[size]  = *(u8 *)(data + size);
		i++;
	}

	/* dns too long */
	if (unlikely(size >= max))
		return -1;

	return size;
}

static __always_inline int dns_load_playload(struct __sk_buff * skb, u64 off, u8 *bytes, u64 max)
{
	volatile u64 size;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (unlikely(skb->len - off > max))
		return -1;

	data = data + off;
	for (size = 0; size < max; size++) {
		if (data + size + sizeof(u8) > data_end)
			break;
		bytes[size] = *(u8 *)(data + size);
	}

	/* dns too long */
	if (unlikely(size >= max))
		return -1;

	return size;
}

#endif
