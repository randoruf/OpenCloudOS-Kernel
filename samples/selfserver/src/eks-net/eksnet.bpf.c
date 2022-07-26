#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "eksnet.bpf.h"

#define MAX_EST_COUNT	102400
#define MAX_LST_COUNT	10240

/* map for host TCP establish connect */
struct bpf_map_def SEC("maps") m_tcp_est = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(key_est_t),
	.value_size = sizeof(val_est_t),
	.max_entries = MAX_EST_COUNT,
};

/* map for host TCP local ports that are binded */
struct bpf_map_def SEC("maps") m_tcp_lst = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(key_lst_t),
	.value_size = sizeof(val_lst_t),
	.max_entries = MAX_LST_COUNT,
};

struct bpf_map_def SEC("maps") m_udp_lst = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(key_lst_t),
	.value_size = sizeof(val_lst_t),
	.max_entries = 65536,
};

struct bpf_map_def SEC("maps") m_config = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(config_t),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") m_event = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = 1024,
};

#define GET_CONFIG(err)	({						\
	int key = 0;							\
	config_t *config = bpf_map_lookup_elem(&m_config, &key);	\
	if (!config)							\
		return err;						\
	config;								\
})

#define PERF_OUTPUT(ctx, data)						\
	bpf_printk("EKS network failed: user:%d, proto:%d, ops:%d\n",	\
		   data.user, data.proto, data.ops);			\
	bpf_printk("EKS network failed: event:%d, sport:%d, dport:%d\n",\
		   data.event, data.sport, data.dport)

port_range_t tcp_range[MAX_RANGE_COUNT] = { };

static __always_inline bool tcp_in_range(u16 port)
{
	int i = 0;
        for(; i < ARRAY_SIZE(tcp_range) && tcp_range[i].end; i++)
                if (tcp_range[i].begin <= port &&
                    tcp_range[i].end >= port)
                        return true;
        return false;
}

static __always_inline bool has_user(u16 *refs)
{
	return refs[0] || refs[1];
}

static __always_inline
val_lst_t *find_or_init_lst(struct bpf_map_def *map, key_lst_t *key)
{
	val_lst_t *lst = bpf_map_lookup_elem(map, key);
	if (!lst) {
		val_lst_t init_lst = { };
		bpf_map_update_elem(map, key, &init_lst,
				    BPF_NOEXIST);
		lst = bpf_map_lookup_elem(map, key);
	} else {
		if (!has_user(lst->refs))
			return NULL;
	}
	return lst;
}

/* check if sock should be ignored. If the binded local ip address doesn't
 * belong to host and slave, and is not IP_ANY, just ignore it.
 * 
 * The sock should be ignored on return True.
 */
static __always_inline bool sockops_check(struct bpf_sock_ops *skops)
{
	config_t *config = GET_CONFIG(0);
	return skops->local_ip4 && skops->local_ip4 != config->host_addr &&
	       skops->local_ip4 != config->guest_addr;
}

/* check if sock should be ignored. If the binded local ip address doesn't
 * belong to host and slave, and is not IP_ANY, just ignore it.
 * 
 * The sock should be ignored on return True.
 */
static __always_inline bool sock_check(struct bpf_sock *sk)
{
	config_t *config = GET_CONFIG(0);
	return sk->src_ip4 && sk->src_ip4 != config->host_addr &&
	       sk->src_ip4 != config->guest_addr;
}

static __always_inline int do_udp_bind(struct bpf_sock *sk, int user)
{
	key_lst_t key = {
		.sport = le32tobe16(sk->src_port)
	};
	val_lst_t *binded;

	if (sk->protocol != IPPROTO_UDP)
		return SYS_PROCEED;

	binded = find_or_init_lst(&m_udp_lst, &key);
	if (!binded)
		goto on_rej;

	if (binded->refs[!user])
		goto on_rej;

	binded->refs[user] += 1;
	return SYS_PROCEED;

on_rej:;
	log_t log = {
		.ops = LOG_OPS_LISTEN,
		.sport = sk->src_port,
		.proto = IPPROTO_UDP,
		.user = user,
	};
	PERF_OUTPUT(sk, log);

	return SYS_REJECT;
}

/* UDP port bind (ip v4) eBPF program */
SEC("cgroup/post_bind4")
int eksnet_udp_bind(struct bpf_sock *sk)
{
	return do_udp_bind(sk, is_init_ns(sk) ? USER_HOST: USER_GUEST);
}

/* UDP port autobind (v4 && v6) eBPF program */
SEC("cgroup/post_autobind")
int eksnet_udp_ab(struct bpf_sock *sk)
{
	/* handle only ipv4, ignore other family */
	if (sk->family != AF_INET)
		return SYS_PROCEED;
	return do_udp_bind(sk, is_init_ns(sk) ? USER_HOST: USER_GUEST);
}

/* UDP socket release (v4 && v6) eBPF program. */
SEC("cgroup/udp_unhash")
int eksnet_udp_unhash(struct bpf_sock *sk)
{
	key_lst_t lst_key = {
		.sport = le32tobe16(sk->src_port)
	};
	val_lst_t *lst;
	int user;

	/* handle only ipv4, ignore other family */
	if (sk->family != AF_INET)
		return 0;

	user = is_init_ns(sk) ? USER_HOST: USER_GUEST;
	lst = bpf_map_lookup_elem(&m_udp_lst, &lst_key);
	if (!lst || !lst->refs[user])
		return 0;
	lst->refs[user] -= 1;
	if (lst->refs[user])
		return 0;

	bpf_map_delete_elem(&m_udp_lst, &lst_key);
	return 0;
}

static __always_inline void do_tcp_release(key_est_t *key, int user)
{
	if (key->daddr) {
		val_est_t *ested = bpf_map_lookup_elem(&m_tcp_est, key);
		if (!ested || ested->user != user)
			return;
		if (ested->raddr) {
			key_est_t ipvs_key = {
				.sport = key->sport,
				.dport = ested->rport,
				.daddr = ested->raddr
			};
			bpf_map_delete_elem(&m_tcp_est, &ipvs_key);
		}
		bpf_map_delete_elem(&m_tcp_est, key);
	} else {
		val_lst_t *lst;
		lst = bpf_map_lookup_elem(&m_tcp_lst, &key->sport);
		if (!lst || lst->refs[!user])
			return;

		lst->refs[!!user] -= 1;
		if (!has_user(lst->refs))
			bpf_map_delete_elem(&m_tcp_lst, &key->sport);
	}
}

/* TCP socket release (v4 && v6) for timewait case. */
SEC("cgroup/tw_close")
int eksnet_tw_close(struct bpf_sock *sk)
{
	/* handle only ipv4, ignore other family */
	if (sk->family != AF_INET || sock_check(sk))
		return 0;

	/* In fact, sk->dst_port is not u32 network byte order.
	 * It can be considered part network byte order, as
	 * (u16)sk->dst_port is network byte order.
	 * 
	 * This is different from skops->remote_port, which is total
	 * u64 network byte order.
	 * 
	 * Therefore, htons((u16)sk->dst_port) is the same as
	 * htonl(skops->remote_port).
	 */
	key_est_t key = {
		.sport = le32tobe16(sk->src_port),
		.dport = sk->dst_port,
		.daddr = sk->dst_ip4
	};
	do_tcp_release(&key, is_init_ns(sk) ? USER_HOST: USER_GUEST);
	return 0;
}

static __always_inline void do_tcp_ops(struct bpf_sock_ops *skops,
				       int user)
{
	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		goto do_connect;
	case BPF_SOCK_OPS_STATE_CB:
		if (skops->args[1] == BPF_TCP_CLOSE)
			goto do_release;
		break;
	case BPF_SOCK_OPS_TCP_LISTEN_CB:
		goto do_listen;
	}
	return;

do_release:
	if (sockops_check(skops) || !tcp_in_range(skops->local_port))
		return;
	key_est_t rls_key = {
		.sport = le32tobe16(skops->local_port),
		.daddr = skops->remote_ip4,
		.dport = be32tobe16(skops->remote_port)
	};
	do_tcp_release(&rls_key, user);
	return;

do_connect:
	if (sockops_check(skops) || !tcp_in_range(skops->local_port))
		return;

	key_est_t key = {
		.sport = le32tobe16(skops->local_port),
		.daddr = skops->remote_ip4,
		.dport = be32tobe16(skops->remote_port)
	};
	skops->reply = SOCK_OPS_RET_REJECT;

	val_est_t val = {.user = user};
	int ret = bpf_map_update_elem(&m_tcp_est, &key, &val,
				      BPF_NOEXIST);
	if (ret) {
		log_t log = {
			.event = ret == -EEXIST ? LOG_EVENT_CONFLICT: LOG_EVENT_MAP_ERROR,
			.dport = bpf_ntohl(skops->remote_port),
			.daddr = skops->remote_ip4,
			.sport = skops->local_port,
			.saddr = skops->local_ip4,
			.proto = IPPROTO_TCP,
			.ops = LOG_OPS_CONN,
			.user = user,
		};
		PERF_OUTPUT(skops, log);
		return;
	}

	bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG | BPF_SOCK_OPS_TW_CLOSE_FLAG);
	skops->reply = SOCK_OPS_RET_OK;
	return;

do_listen:
	if (sockops_check(skops) || !tcp_in_range(skops->local_port))
		return;

	key_lst_t lst_key = {
		.sport = le32tobe16(skops->local_port),
	};
	val_lst_t *lst;

	skops->reply = SOCK_OPS_RET_REJECT;
	lst = find_or_init_lst(&m_tcp_lst, &lst_key);
	if (!lst)
		goto lst_rej;

	if (lst->refs[!user])
		goto lst_rej;
	lst->refs[!!user] += 1;

	bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
	skops->reply = SOCK_OPS_RET_OK;
	return;

lst_rej:;
	log_t log = {
		.dport = bpf_ntohl(skops->remote_port),
		.daddr = skops->remote_ip4,
		.sport = skops->local_port,
		.saddr = skops->local_ip4,
		.proto = IPPROTO_TCP,
		.ops = LOG_OPS_LISTEN,
		.user = user,
	};
	PERF_OUTPUT(skops, log);
}

/* TCP socket ops (v4 && v6) eBPF program */
SEC("sockops")
int eksnet_tcp_ops(struct bpf_sock_ops *skops)
{
	/* handle only ipv4, ignore other family */
	if (skops->family != AF_INET)
		return 1;
	do_tcp_ops(skops, is_init_ns(skops) ? USER_HOST: USER_GUEST);
	return 1;
}

SEC("classifier")
int eksnet_ingress(struct __sk_buff *skb)
{
	struct ethhdr *eth;
	struct iphdr *ip;
	config_t *config;
	u32 offset;

	if (!(ip = try_pull_ip_hdr(skb)) ||
	    (eth = SKB_DATA_PTR(skb))->h_proto != bpf_htons(ETH_P_IP) ||
	    is_ip_frag(ip))
		goto out;

	switch (ip->protocol) {
	case IPPROTO_TCP: {
		tcphdr_min_t _tcp, *tcp;
		tcp = load_l4_hdr(skb, ip, &_tcp, sizeof(tcphdr_min_t));
		if (!tcp)
			goto out;

		key_est_t key = {
			.dport = tcp->source,
			.daddr = ip->saddr,
			.sport = tcp->dest
		};
		val_est_t *ested = bpf_map_lookup_elem(&m_tcp_est, &key);
		if (ested) {
			if (ested->user == USER_HOST) {
				offset = TCP_CSUM_OFFSET;
				goto do_dnat;
			}
			break;
		}

		val_lst_t *lsted = bpf_map_lookup_elem(&m_tcp_lst,
						       &key.sport);
		if (lsted && lsted->refs[USER_HOST]) {
			offset = TCP_CSUM_OFFSET;
			goto do_dnat;
		}
		break;
	}
	case IPPROTO_UDP: {
		udphdr_min_t _udp, *udp;
		udp = load_l4_hdr(skb, ip, &_udp, sizeof(udphdr_min_t));
		if (!udp)
			goto out;

		key_lst_t key = {
			.sport = udp->dest
		};
		val_lst_t *binded = bpf_map_lookup_elem(&m_udp_lst, &key);
		if (binded && binded->refs[USER_HOST]) {
			offset = UDP_CSUM_OFFSET;
			goto do_dnat;
		}
		break;
	}
	default:
		break;
	}
out:
	return TC_ACT_UNSPEC;

do_dnat:
	config = GET_CONFIG(0);
	u32 old_ip = ip->daddr;
	ip->daddr = config->host_addr;

	compute_addr_csum(skb, offset, old_ip, config->host_addr);
	return TC_ACT_UNSPEC;
}

SEC("classifier")
int eksnet_egress(struct __sk_buff *skb)
{
	struct ethhdr *eth;
	struct iphdr *ip;
	config_t *config;
	u32 offset;

	if (!(ip = try_pull_ip_hdr(skb)) ||
	    (eth = SKB_DATA_PTR(skb))->h_proto != bpf_htons(ETH_P_IP) ||
	    is_ip_frag(ip))
		goto out;

	switch (ip->protocol) {
	case IPPROTO_TCP:
		offset = TCP_CSUM_OFFSET;
		goto do_snat;
	case IPPROTO_UDP:
		offset = UDP_CSUM_OFFSET;
		goto do_snat;
	}
out:
	return TC_ACT_UNSPEC;

do_snat:
	config = GET_CONFIG(0);

	/* dest addr is host addr, means this is a packet from container
	 * to host (CVM). change it's dest mac to the ipvlan's mac.
	 */
	if (ip->daddr == config->host_addr) {
		__builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
		return bpf_redirect(config->host_if, BPF_F_INGRESS);
	}

	/* Don't do nat is this is a packet from host to container, or
	 * this packet is not sended by host.
	 */
	if (ip->daddr == config->guest_addr ||
	    ip->saddr != config->host_addr)
		return TC_ACT_UNSPEC;

	u32 old_ip = ip->saddr;
	ip->saddr = config->guest_addr;

	compute_addr_csum(skb, offset, old_ip, config->guest_addr);
	return TC_ACT_UNSPEC;
}

#define _(x) ({						\
	typeof(x) tmp;					\
	bpf_probe_read((void *)&tmp, sizeof(x), &(x));	\
	tmp;						\
})

SEC("kprobe/ip_vs_conn_new")
int eksnet_ipvs(struct pt_regs *ctx)
{
	const union nf_inet_addr *daddr, *caddr, *vaddr;
	config_t *config;
	struct ip_vs_conn_param *cp;
	__be16 dport;

	daddr = (void *)PT_REGS_PARM3(ctx);
	cp = (void *)PT_REGS_PARM1(ctx);
	dport = PT_REGS_PARM4(ctx);

	caddr = _(cp->caddr);
	if (!caddr)
		goto out;

	u32 cip = _(caddr->ip);
	config = GET_CONFIG(0);
	if (cip != config->host_addr && cip != config->guest_addr)
		goto out;

	u16 cport = _(cp->cport);
	if (!tcp_in_range(bpf_ntohs(cport)))
		goto out;

	vaddr = _(cp->vaddr);
	if (!vaddr)
		goto out;

	u16 vport = _(cp->vport);
	u32 vip = _(vaddr->ip);

	key_est_t origin = {
		.daddr = vip,
		.dport = vport,
		.sport = cport
	};

	val_est_t *val = bpf_map_lookup_elem(&m_tcp_est, &origin);
	/* !val means this connect is not traced; val->raddr means that
	 * IPVS is already considered.
	 */
	if (!val || val->raddr)
		goto out;

	val->raddr = _(daddr->ip);
	val->rport = dport;

	val_est_t ipvs_val = {.user = val->user};
	key_est_t reply = {
		.daddr = val->raddr,
		.dport = val->rport,
		.sport = cport
	};
	bpf_map_update_elem(&m_tcp_est, &reply, &ipvs_val, BPF_NOEXIST);
out:
	return 0;
}

char _license[] SEC("license") = "GPL";
