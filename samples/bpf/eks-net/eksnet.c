#include <net_utils.h>
#include <arg_parse.h>
#include "eksnet.h"
#include "eksnet.skel.h"

static char *nic, *cgroup, ipref[16], epref[16];
static int cgroup_fd;
struct eksnet *obj;


static arg_config_t prog_config = {
	.name = "eksnet",
	.summary = "eks network redirect program",
	.desc = ""
};

#define FOR_EACH_CG(func)	\
	func(udp_bind);		\
	func(udp_ab);		\
	func(udp_unhash);	\
	func(tw_close);		\
	func(tcp_ops);

static void do_cleanup(int code)
{
	int atype;

	tc_detach(nic, epref, false);
	tc_detach(nic, ipref, true);

#define CG_DETACH(name)							\
atype = bpf_program__get_expected_attach_type(obj->progs.eksnet_##name);	\
bpf_prog_detach2(bpf_program__fd(obj->progs.eksnet_##name),		\
		 cgroup_fd, atype)

	FOR_EACH_CG(CG_DETACH);
	eksnet__detach(obj);
	eksnet__destroy(obj);

	printf("CFT Network exited\n");
	exit(0);
}

static int parse_range(port_range_t range[], char *str)
{
	int begin, end, i = 0;
	char *cur = str;
	
	for (; cur && i < MAX_RANGE_COUNT; i++) {
		if (sscanf(cur, "%d-%d", &begin, &end) == 2) {
			range[i].begin = begin;
			range[i].end = end;
		} else if(sscanf(cur, "%d", &begin) == 1) {
			range[i].begin = begin;
			range[i].end = begin;
		} else {
			return -EINVAL;
		}
		cur = strchr(cur, ',');
		if (cur && *cur)
			cur++;
	}

	if (i == MAX_RANGE_COUNT)
		return -EINVAL;

	return 0;
}

int main(int argc, char *argv[])
{
	port_range_t tcp_range[MAX_RANGE_COUNT] = {};
	int ret, atype, opt, max_entries = 0;
	bool no_prealloc = false;
	int cgroup_version = 0;
	char *port = NULL;
	u32 host, guest;

	option_item_t opts[] = {
		{
			.lname = "guest", .sname = 'g', .type = OPTION_IPV4,
			.dest = &guest, .required = true,
			.desc = "guest (pod) ip address"
		},
		{
			.lname = "host", .sname = 'h', .type = OPTION_IPV4,
			.dest = &host, .required = true,
			.desc = "host ip address"
		},
		{
			.lname = "nic", .sname = 'i', .type = OPTION_STRING,
			.dest = &nic, .required = true,
			.desc = "nic that used, such as eth0"
		},
		{
			.lname = "cgroup", .sname = 'v', .type = OPTION_INT,
			.dest = &cgroup_version,
			.desc = "cgroup version, 1 or 2"
		},
		{
			.lname = "max", .sname = 'm', .type = OPTION_INT,
			.dest = &max_entries,
			.desc = "max entries length"
		},
		{
			.lname = "no_prealloc", .sname = 'n', .type = OPTION_BOOL,
			.dest = &no_prealloc,
			.desc = "no_prealloc for the tcp map"
		},
		{
			.lname = "port", .sname = 'p', .type = OPTION_STRING,
			.dest = &port,
			.desc = "port range that should be trace, such as "
				"7777,8000-9000,9999,62550-64000"
		},
		{
			.lname = "help", .type = OPTION_HELP,
			.desc = "show help info"
		},
	};

	if (parse_args(argc, argv, &prog_config, opts, ARRAY_SIZE(opts)))
		goto err;

	cgroup = cgroup_version != 2 ? "/sys/fs/cgroup/pids/" :
				       "/sys/fs/cgroup/";

	if (port && parse_range(tcp_range, port)) {
		printf("port range format error\n");
		goto err;
	}

	if ((cgroup_fd = open(cgroup, S_IREAD)) < 0) {
		printf("failed to open cgroup\n");
		goto err;
	}
	obj = eksnet__open();

	if (no_prealloc)
		bpf_map__set_map_flags(obj->maps.m_tcp_est, BPF_F_NO_PREALLOC);
	if (max_entries)
		bpf_map__set_max_entries(obj->maps.m_tcp_est, max_entries);

	if (eksnet__load(obj)) {
		printf("failed to load eBPF\n");
		goto err;
	}

	//memcpy(obj->bss->tcp_range, tcp_range, sizeof(tcp_range));

	config_t config = {
		.host_if = if_nametoindex(nic),
		.guest_addr = guest,
		.host_addr = host
	};
	int key = 0;
	bpf_map_update_elem(bpf_map__fd(obj->maps.m_config), &key,
			    &config, 0);

#define CG_ATTACH(name)							\
atype = bpf_program__get_expected_attach_type(obj->progs.eksnet_##name);	\
ret = bpf_prog_attach(bpf_program__fd(obj->progs.eksnet_##name),		\
		      cgroup_fd,					\
		      atype,						\
		      BPF_F_ALLOW_MULTI);				\
if (ret) {								\
	printf("failed to attach cgroup\n");				\
	goto err;							\
}

	/* attach cgroup programs */
	FOR_EACH_CG(CG_ATTACH);

	/* attach kprobe for ip_vs_conn_new */
	if (kprobe_exist("ip_vs_conn_new"))
		bpf_program__attach(obj->progs.eksnet_ipvs);
	else
		printf("IPVS not enabled, ignoring it...\n");

	/* attach TC programs */
	if (tc_attach(obj->progs.eksnet_ingress, nic, ipref, true) ||
	    tc_attach(obj->progs.eksnet_egress, nic, epref, false)) {
		printf("failed to attach TC\n");
		goto err;
	}

	signal(SIGTERM, do_cleanup);
	signal(SIGINT, do_cleanup);

	printf("EKS Network started\n");
	while (true)
		sleep(60);
	return 0;
err:
	return -1;
}
