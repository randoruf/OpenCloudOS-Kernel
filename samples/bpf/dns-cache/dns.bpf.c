#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "dns.map.h"
#include "dns.bpf.h"

#undef DNS_CACHE_RECLAIM
#undef DNS_PLAYLOAD_FAST_COPY

/*
 * The temporary variable of percpu is used to store
 * the key of the current DNS
 */

struct bpf_map_def SEC("maps") percpu_global_key = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(dkey_t),
	.max_entries = 1,
};

/*
 * The temporary variable of percpu is used to store
 * the value of the current DNS
 */

struct bpf_map_def SEC("maps") percpu_global_val = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(cache_t),
	.max_entries = 1,
};

/*
 * The map is used to store the configration of the prog
 */

struct bpf_map_def SEC("maps") dns_config = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(config_t),
	.max_entries = 1,
};

/*
 * The map is used to store the status of the prog
 */

struct bpf_map_def SEC("maps") dns_stat = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(stat_t),
	.max_entries = 1,
};

/*
 * The map is used to store the cache of the dns
 */

struct bpf_map_def SEC("maps") dns_cache = {
#ifdef DNS_CACHE_RECLAIM
	.type = BPF_MAP_TYPE_LRU_HASH,
#else
	.type = BPF_MAP_TYPE_HASH,
#endif
	.key_size = sizeof(dkey_t),
	.value_size = sizeof(cache_t),
	.max_entries = CACHE_COUNT,
};

/*
 * Find the smallest TTL field in DNS.
 */

static __always_inline u32 dns_load_minttl(struct __sk_buff *skb, u64 off, stat_t *stat)
{
	u64 i;
	int ret, pos;
	u32 minttl, ttl;
	u16 rcount, acount;

	ret = bpf_skb_load_bytes(skb, DNS_OF(rcount), &rcount, 2);
	if (unlikely(ret < 0))
		return 0;

	ret = bpf_skb_load_bytes(skb, DNS_OF(acount), &acount, 2);
	if (unlikely(ret < 0))
		return 0;

	pos = off;
	minttl = 0xffff;
	/* find the smallest ttl in answer*/
	for (i = 0; i < MAX_ANSWER_LIMIT && i < bpf_ntohs(rcount); i++) {
		pos = dns_section_ttl(skb, pos, &ttl);
		if (unlikely(pos < 0)) {
			stat->parse_failed++;
			return 0;
		}

		if (minttl > ttl)
			minttl = ttl;
	}

	if (unlikely(i == MAX_ANSWER_LIMIT)) {
		stat->answer_limit++;
		return 0;
	}

	/* find the smallest ttl in auth */
	for (i = 0; i < MAX_AUTH_LIMIT && i < bpf_ntohs(acount); i++) {
		pos = dns_section_ttl(skb, pos, &ttl);
		if (unlikely(pos < 0)) {
			stat->parse_failed++;
			return 0;
		}

		if (minttl > ttl)
			minttl = ttl;
	}

	if (unlikely(i == MAX_AUTH_LIMIT)) {
		stat->auth_limit++;
		return 0;
	}

	return minttl;
}

/*
 * Replace the TTL value in DNS message with the specified TTL.
 */

static __always_inline u32 dns_update_ttl(struct __sk_buff *skb, u64 off, u32 ttl)
{
	u64 i;
	int ret, pos;
	u16 rcount, acount;

	/* load dns answer count in playload */
	ret = bpf_skb_load_bytes(skb, DNS_OF(rcount), &rcount, 2);
	if (unlikely(ret < 0))
		return -1;

	/* load dns auth count in playload */
	ret = bpf_skb_load_bytes(skb, DNS_OF(acount), &acount, 2);
	if (unlikely(ret < 0))
		return -1;

	pos = off;

	/* process dns ansers section*/
	for (i = 0; i < MAX_ANSWER_LIMIT && i < bpf_ntohs(rcount); i++) {
		pos = dns_replace_ttl(skb, pos, ttl);
		if (unlikely(pos < 0))
			return -1;
	}

	/* process dns auth section */
	for (i = 0; i < MAX_AUTH_LIMIT && i < bpf_ntohs(acount); i++) {
		pos = dns_replace_ttl(skb, pos, ttl);
		if (unlikely(pos < 0))
			return -1;
	}

	return 0;
}

/*
 * Generate DNS response message.
 */

static __always_inline int dns_fill_reponse(struct __sk_buff *skb, u8 keylen, cache_t *c)
{
	u64 ns;
	u32 ttl = 0;
	struct dnshdr *hdr;

	hdr = (struct dnshdr *)(skb->data + DNS_OFF);
	if ((long)(hdr + 1) > skb->data_end)
		return TC_ACT_UNSPEC;

	/* restore count to playload */
	hdr->flags = c->flags;
	hdr->rcount = c->rcount;
	hdr->acount = c->acount;

	/* fill reply data */
#ifdef DNS_PLAYLOAD_FAST_COPY
	bpf_skb_change_tail (skb, skb->len + CACHE_VALUE_LEN, 0);
	bpf_skb_store_bytes(skb, skb->len - CACHE_VALUE_LEN, c->playload, CACHE_VALUE_LEN, 1);
#else
	int i;

	bpf_skb_change_tail (skb, skb->len + c->length, 0);
	for (i = 0; i < c->length && i < CACHE_VALUE_LEN; i++) {
		bpf_skb_store_bytes(skb, skb->len - c->length + i, c->playload + i, 1, 1);
	}
#endif

	/* update new ttl */
	ns = bpf_ktime_get_ns() / NS_IN_SECS;
	if (likely(c->expire > ns))
		ttl = c->expire - ns;

	if (dns_update_ttl(skb, DATA_OFF + keylen, ttl) < 0)
		return TC_ACT_UNSPEC;

	return TC_ACT_REDIRECT;
}

/*
 * Save the DNS response message into hash map.
 */

static __always_inline int dns_store_cache(struct __sk_buff *skb, dkey_t *k, stat_t *stat)
{
	int ret;
	u64 map_flags = BPF_NOEXIST;
	cache_t *c = GET_MAP_POINTER(&percpu_global_val, TC_ACT_UNSPEC);

	__builtin_memset(c, 0, sizeof(cache_t));
	if (bpf_map_lookup_elem(&dns_cache, k) != NULL)
		return TC_ACT_UNSPEC; /* exists, give up or use map_flags = BPF_EXIST? */

	/* find the smallest ttl in playload */
	c->expire = dns_load_minttl(skb, DATA_OFF + k->length, stat);
	if (unlikely(c->expire <= 0))
		return TC_ACT_UNSPEC;

	/* load playload to cache struct */
	ret = dns_load_playload(skb, DATA_OFF + k->length, c->playload, CACHE_VALUE_LEN);
	if (unlikely(ret < 0)) {
		stat->value_overflow++;
		return TC_ACT_UNSPEC;
	}

	/* calculate expiration time */
	c->length = ret;
	c->expire += bpf_ktime_get_ns() / NS_IN_SECS;

	/* save the count in playload to cache */
	bpf_skb_load_bytes(skb, DNS_OF(flags), &c->flags, 2);
	bpf_skb_load_bytes(skb, DNS_OF(rcount), &c->rcount, 2);
	bpf_skb_load_bytes(skb, DNS_OF(acount), &c->acount, 2);

	/* saved into hashmap */
	ret = bpf_map_update_elem(&dns_cache, k, c, map_flags);
	switch (ret) {
	case OK:
		break;
	case EFULL:
		stat->cache_full++;
		break;
	default:
		stat->store_failed++;
		break;
	}

	return TC_ACT_UNSPEC;
}

/*
 * Find the DNS response message from hash map.
 */

static __always_inline cache_t * dns_find_cache(struct __sk_buff *skb, dkey_t *k, stat_t *stat)
{
	u32 ttl;
	cache_t * c;

	/* find cache from hashmap */
	c = bpf_map_lookup_elem(&dns_cache, k);
	if (unlikely(c == NULL)) {
		stat->cache_miss++;
		return NULL;
	}

	ttl = bpf_ktime_get_ns() / NS_IN_SECS;

	/* ttl timeout, delete it */
	if (unlikely(ttl >= c->expire)) {
		bpf_map_delete_elem(&dns_cache, k);
		return NULL;
	}
	stat->cache_hit++;

	return c;
}

/*
 * Handle the DNS message.
 */

static __always_inline int dns_may_handle(struct __sk_buff *skb)
{
	int ret;
	cache_t * c = NULL;
	u16 flags, qcount, ecount;
	stat_t *stat = GET_MAP_POINTER(&dns_stat, TC_ACT_UNSPEC);
	dkey_t *k = GET_MAP_POINTER(&percpu_global_key, TC_ACT_UNSPEC);
	config_t *config = GET_MAP_POINTER(&dns_config, TC_ACT_UNSPEC);

	__builtin_memset(k, 0, sizeof(dkey_t));
	ret = bpf_skb_load_bytes(skb, DNS_OF(flags), &flags, 2);
	if (unlikely(ret < 0))
		return TC_ACT_UNSPEC;

	flags = bpf_ntohs(flags);
	/* process standard only */
	if (unlikely(DNS_OPCODE(flags) != DNS_STANDARD)) {
		stat->nonstandard++;
		PUT_MAP_POINTER(&dns_stat, stat);
		return TC_ACT_UNSPEC;
	}

	/* read dns queries count */
	bpf_skb_load_bytes(skb, DNS_OF(qcount), &qcount, 2);
	if (unlikely(bpf_ntohs(qcount) > MAX_QUERIES_LIMIT)) {
		stat->queries_limit++;
		PUT_MAP_POINTER(&dns_stat, stat);
		return TC_ACT_UNSPEC;
	}

	/* no caching with additional information */
	bpf_skb_load_bytes(skb, DNS_OF(ecount), &ecount, 2);
	if (unlikely(bpf_ntohs(ecount) > 0)) {
		stat->additional_limit++;
		PUT_MAP_POINTER(&dns_stat, stat);
		return TC_ACT_UNSPEC;
	}

	/* load the dns queries section */
	ret = dns_load_section(skb, DATA_OFF, k->playload, CACHE_KEY_LEN);
	if (unlikely(ret < 0)) {
		stat->key_overflow++;
		PUT_MAP_POINTER(&dns_stat, stat);
		return TC_ACT_UNSPEC;
	}
	k->length = ret;

	/* dns handle */
	switch(flags & DNS_QR_MASK) {
	case DNS_QR(DNS_QUERY):
		/* isolate dns results from different dns servers */

		if (config->isolate)
			bpf_skb_load_bytes(skb, IPV4_OF(daddr), &k->dns_server, sizeof(u32));

		c = dns_find_cache(skb, k, stat);
		stat->total++;
		break;
	case DNS_QR(DNS_REPLY):
		/* isolate dns results from different dns servers */

		if (config->isolate)
			bpf_skb_load_bytes(skb, IPV4_OF(saddr), &k->dns_server, sizeof(u32));

		ret = dns_store_cache(skb, k, stat);
		break;
	default:
		break;
	}

	PUT_MAP_POINTER(&dns_stat, stat);

	/* no cache found */
	if (c == NULL)
		return TC_ACT_UNSPEC;

	return dns_fill_reponse(skb, k->length, c);
}

/*
 * Fill UDP header into DNS response message.
 */

static __always_inline int udp_send(struct __sk_buff *skb)
{
	u16 data;
	int i = 0;
	u8 last = 0;
	u32 csum = 0;
	struct udphdr *hdr;
	struct pudphdr puhdr = {};
	u32 len = skb->len - UDP_OFF;

	hdr = (struct udphdr *)(skb->data + UDP_OFF);
	if ((long)(hdr + 1) > skb->data_end)
		return TC_ACT_SHOT;

	hdr->check = 0;
	hdr->dest ^= hdr->source;
	hdr->source ^= hdr->dest;
	hdr->dest ^= hdr->source;
	hdr->len = bpf_htons(len);

	/* create UDP pseudo header */
	puhdr.length = hdr->len;
	bpf_skb_load_bytes(skb, IPV4_OF(daddr), &puhdr.saddr, sizeof(puhdr.saddr));
	bpf_skb_load_bytes(skb, IPV4_OF(saddr), &puhdr.daddr, sizeof(puhdr.daddr));
	bpf_skb_load_bytes(skb, IPV4_OF(protocol), &puhdr.proto, sizeof(puhdr.proto));

	/* calculate UDP check sum */
	for (i = 0; i < sizeof(struct pudphdr); i += 2) {
		csum += *(u16 *)(((u8 *)&puhdr) + i);
	}

	for (i = 0; i < len && i < MAX_UDP_LEN; i += 2) {
		bpf_skb_load_bytes(skb, UDP_OFF + i, &data, 2);
		csum += data;
	}

	if (len % 2)
		bpf_skb_load_bytes(skb, skb->len - 1, &last, 1);

	csum += last;
	hdr->check = (u16)(~((csum >> 16) + (csum & 0xffff)));

	return TC_ACT_REDIRECT;
}

/*
 * Handle UDP message.
 */

static __always_inline int udp_recv(struct __sk_buff *skb)
{
	int ret;
	u16 dport, sport;

	ret = bpf_skb_load_bytes(skb, UDP_OF(dest), &dport, 2);
	if (unlikely(ret < 0))
		return TC_ACT_UNSPEC;

	ret = bpf_skb_load_bytes(skb, UDP_OF(source), &sport, 2);
	if (unlikely(ret < 0))
		return TC_ACT_UNSPEC;

	sport = bpf_ntohs(sport);
	dport = bpf_ntohs(dport);
	if (likely(dport != DNS_PORT && sport != DNS_PORT))
		return TC_ACT_UNSPEC; /* non-dns, return */

	/* convert non-linear data to linear data */
	bpf_skb_pull_data(skb, skb->len);

	ret = dns_may_handle(skb);
	return ret == TC_ACT_REDIRECT? udp_send(skb): TC_ACT_UNSPEC;
}

/*
 * Fill IPv4 header into DNS response message.
 */

static __always_inline int ipv4_send(struct __sk_buff *skb)
{
	u16 oldlen;
	struct iphdr *hdr;

	hdr = (struct iphdr *)(skb->data + IPV4_OFF);
	if ((long)(hdr + 1) > skb->data_end)
		return TC_ACT_SHOT;

	oldlen = hdr->tot_len;
	hdr->daddr ^= hdr->saddr;
	hdr->saddr ^= hdr->daddr;
	hdr->daddr ^= hdr->saddr;
	hdr->tot_len = bpf_htons(skb->len - IPV4_OFF);
	bpf_l3_csum_replace(skb, IPV4_OF(check), oldlen, hdr->tot_len, sizeof(oldlen));

	return TC_ACT_REDIRECT;
}

/*
 * Handle IPv4 message.
 */

static __always_inline int ipv4_recv(struct __sk_buff *skb)
{
	u8 len;
	int ret;
	u8 proto;

	ret = bpf_skb_load_bytes(skb, IPV4_OFF, &len, 1);
	if (unlikely(ret < 0))
		return TC_ACT_UNSPEC;

	len = (len & IP_LEN_MSK) * 4;
	if (len != sizeof(struct iphdr))
		return TC_ACT_UNSPEC;

	ret = bpf_skb_load_bytes(skb, IPV4_OF(protocol), &proto, 1);
	if (unlikely(ret < 0))
		return TC_ACT_UNSPEC;

	switch (proto) {
	case IPPROTO_UDP:
		ret = udp_recv(skb);
		break;
	default:
		ret = TC_ACT_UNSPEC;
		break;
	};

	return ret != TC_ACT_REDIRECT? ret: ipv4_send(skb);
}

/*
 * Fill ethernet header into DNS response message.
 */

static __always_inline int dev_xmit(struct __sk_buff *skb)
{
	int ret;
	struct ethhdr *hdr;
	char h_mac[ETH_ALEN];
	stat_t *stat = GET_MAP_POINTER(&dns_stat, TC_ACT_SHOT);

	hdr = (struct ethhdr *)(long)(skb->data);
	if (skb->data + sizeof(*hdr) > skb->data_end)
		return TC_ACT_SHOT;

	__builtin_memcpy(h_mac, hdr->h_dest, ETH_ALEN);
	__builtin_memcpy(hdr->h_dest, hdr->h_source, ETH_ALEN);
	__builtin_memcpy(hdr->h_source, h_mac, ETH_ALEN);

	ret = bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
	if (ret != 0) {
		stat->redirect_failed++;
		PUT_MAP_POINTER(&dns_stat, stat);
	}

	return TC_ACT_STOLEN;
}

/*
 * Handle network data.
 */

static __always_inline int netif_rx(struct __sk_buff *skb)
{
	int ret;
	u16 proto;

	ret = bpf_skb_load_bytes(skb, ETH_OF(h_proto), &proto, 2);
	if (unlikely(ret < 0))
		return TC_ACT_UNSPEC;

	proto = bpf_htons(proto);
	if (unlikely(proto != ETH_P_IP))
		return TC_ACT_UNSPEC; /* non-ipv4 return */

	ret = ipv4_recv(skb);
	return ret == TC_ACT_REDIRECT? dev_xmit(skb): ret;
}

SEC("classifier")
int dns_egress(struct __sk_buff *skb)
{
	return netif_rx(skb);
}

SEC("classifier")
int dns_ingress (struct __sk_buff *skb)
{
	return netif_rx(skb);
}

char _license[] SEC("license") = "GPL";
