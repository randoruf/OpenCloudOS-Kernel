#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <uapi/linux/if_link.h>
#include <sys/time.h>
#include <time.h>

#include "dns.map.h"
#include "dns.skel.h"

static char *nic, tx_pref[16], rx_pref[16];

static int usage(const char *prog)
{
	fprintf(stderr, "usage: %s [OPTS] IFACE\n\n"
		"OPTS:\n"
		"    -m N         map N entries\n"
		"    -l N         ulimit in N kbytes\n"
		"    -i           dns isolate\n"
		"    -h           help\n", prog);

	return 0;
}

static inline int do_exec(char *cmd, char *output)
{
	char buf[128];
	FILE *f = popen(cmd, "r");

	while (fgets(buf, sizeof(buf) - 1, f) != NULL) {
		if (!output)
			continue;
		strcat(output + strlen(output), buf);
	}

	return pclose(f);
}

static inline int tc_attach(struct bpf_program *prog, char *nic,
			    char *pref, bool ingress)
{
	char *filter;
	char cmd[1024], path_pin[256] = "/sys/fs/bpf/tmp/";

	strcat(path_pin, bpf_program__name(prog));
	if (bpf_program__pin(prog, path_pin)) {
		printf("failed to pin mark\n");
		return -1;
	}

	filter = ingress ? "ingress": "egress";
	snprintf(cmd, sizeof(cmd), "((tc qdisc show dev %s | grep clsact > /dev/null) || "
		"tc qdisc add dev %s clsact) && "
		"tc filter add dev %s %s bpf direct-action object-pinned %s;"
		"rm %s", nic, nic, nic, filter, path_pin, path_pin);
	system(cmd);

	sprintf(cmd, "tc filter show dev %s %s | grep dns_ | "
		"tail -n 1 | awk '{print $5}'", nic, filter);

	/* get the filter entry that we added. 'pref' of it can be used
	 * to delete it later.
	 */
	return do_exec(cmd, pref);
}

static inline void tc_detach(char *nic, char *pref, bool ingress)
{
	char cmd[128], *filter;

	filter = ingress ? "ingress": "egress";
	snprintf(cmd, sizeof(cmd) - 1, "tc filter delete dev %s %s pref %s",
		nic, filter, pref);

	do_exec(cmd, NULL);
}

static void signal_handler(int sig)
{
	tc_detach(nic, tx_pref, false);
	tc_detach(nic, rx_pref, true);
	exit(0);
}

int main(int argc, char *argv[])
{
	int opt;
	int err = 0;
	int key = 0;
	struct dns *obj;
	const char *name;
	int max_entries = 0;
	config_t config = {
		.isolate = 0,
	};

	struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	name = basename(argv[0]);
	while ((opt = getopt(argc, argv, "ihm:l:")) != -1) {
		switch (opt) {
		case 'm':
			max_entries = atoi(optarg);
			break;
		case 'i':
			config.isolate = 1;
			break;
		case 'l':
			limit.rlim_cur = atoi(optarg);
			limit.rlim_max = atoi(optarg);
			break;
		case 'h':
			return usage(name);
		default:
			return usage(name);
		}
	}

	if (optind == argc) {
		return usage(name);
	}

	/* kbytes to bytes */
	if (limit.rlim_cur != RLIM_INFINITY) {
		limit.rlim_cur *= 1024;
		limit.rlim_max *= 1024;
	}

	if(setrlimit(RLIMIT_MEMLOCK, &limit) < 0) {
		printf ("set limit failed\n");
		return 0;
	}

	obj = dns__open();
	if (obj == NULL) {
		printf ("Open bpf object failed\n");
		return -1;
	}

	err = dns__load(obj);
	if(err != 0) {
		printf ("Load bpf object failed\n");
		goto out;
	}

	if (max_entries > 0)
		bpf_map__set_max_entries(obj->maps.dns_cache, max_entries);

	bpf_map_update_elem(bpf_map__fd(obj->maps.dns_config), &key,
		&config, 0);

	nic = argv[optind];
	if (tc_attach(obj->progs.dns_egress, nic, tx_pref, false)){
		printf ("Attach to tc failed\n");
		goto out;
	}

	if (tc_attach(obj->progs.dns_ingress, nic, rx_pref, true)){
		tc_detach(nic, tx_pref, false);
		printf ("Attach to tc failed\n");
		goto out;
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	while (true) {
		sleep (60);
	}

out:
	dns__destroy(obj);
	return 0;
}
