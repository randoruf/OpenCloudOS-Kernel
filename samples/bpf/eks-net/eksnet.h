#include <unistd.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <bpf/bpf.h>

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

static inline int do_exec(char *cmd, char *output)
{
	FILE *f = popen(cmd, "r");
	char buf[128];
	int status;

	while (fgets(buf, sizeof(buf) - 1, f) != NULL) {
		if (!output)
			continue;
		strcat(output + strlen(output), buf);
	}

	status = pclose(f);
	return WEXITSTATUS(status);
}

static inline int simple_exec(char *cmd)
{
	return do_exec(cmd, NULL);
}

static inline int tc_attach(struct bpf_program *prog, char *nic,
			    char *pref, bool ingress)
{
	char cmd[256], path_pin[256] = "/sys/fs/bpf/tmp/", *filter;
	int ret;

	strcat(path_pin, bpf_program__name(prog));
	if (bpf_program__pin(prog, path_pin)) {
		printf("failed to pin mark\n");
		goto err;
	}

	filter = ingress ? "ingress": "egress";
	sprintf(cmd, "((tc qdisc show dev %s | grep clsact > /dev/null) || "
		"tc qdisc add dev %s clsact) && "
		"tc filter add dev %s %s bpf da object-pinned %s;"
		"rm %s",
		nic, nic, nic, filter, path_pin, path_pin);
	ret = system(cmd);

	sprintf(cmd, "tc filter show dev %s %s | grep eks_ |"
		" tail -n 1 | awk '{print $5}'",
		nic, filter);

	/* get the filter entry that we added. 'pref' of it can be used
	 * to delete it later.
	 */
	return do_exec(cmd, pref);
err:
	return -1;
}

static inline void tc_detach(char *nic, char *pref, bool ingress)
{
	char cmd[128], *filter;
	filter = ingress ? "ingress": "egress";
	snprintf(cmd, sizeof(cmd) - 1,
		 "tc filter delete dev %s %s pref %s",
		 nic, filter,
		 pref);
	simple_exec(cmd);
}

static inline bool kprobe_exist(char *name)
{
	char cmd[128];
	snprintf(cmd, sizeof(cmd) - 1,
		 "cat /sys/kernel/debug/tracing/available_filter_functions | grep %s",
		 name);
	return simple_exec(cmd) == 0;
}
