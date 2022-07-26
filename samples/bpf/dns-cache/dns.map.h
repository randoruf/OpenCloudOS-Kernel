#ifndef __DNS_MAP_H
#define __DNS_MAP_H

#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define CACHE_KEY_LEN     500    /* max dns queries length */
#define CACHE_VALUE_LEN   1000   /* max dns answer length */
#define CACHE_COUNT       10000

#define GET_MAP_POINTER(c_map, err) ({             \
	int key = 0;                                   \
	void *stat = bpf_map_lookup_elem(c_map, &key); \
	if (!stat)                                     \
		return err;                                \
	stat;                                          \
})

#define PUT_MAP_POINTER(c_map, c) ({                      \
	int key = 0;                                          \
	(void) bpf_map_update_elem(c_map, &key, c, BPF_EXIST);\
})

typedef struct dns_config {
	u32 isolate;
} config_t;

typedef struct dns_key {
	u8  length;
	u32 dns_server;
	u8  playload[CACHE_KEY_LEN];      /* dns queries payload */
} dkey_t;

typedef struct dns_cache {
	u64  expire;                     /* time in seconds */
	u16  rcount;       				 /* answer information count */
	u16  acount;       				 /* authorization information count */
	u32  length;
	u16  flags;
	u8   playload[CACHE_VALUE_LEN];  /* dns reply payload */
} cache_t;

#endif
