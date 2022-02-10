// SPDX-License-Identifier: GPL-2.0-only
/*
 * memory management for dmemfs
 *
 * Authors:
 *   Chen Zhuo	     <sagazchen@tencent.com>
 */
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/cpuset.h>
#include <linux/nodemask.h>
#include <linux/topology.h>
#include <linux/dmem.h>
#include <linux/debugfs.h>
#include <linux/notifier.h>

/*
 * There are two kinds of page in dmem management:
 * - nature page, it's the CPU's page size, i.e, 4K on x86
 *
 * - dmem page, it's the unit size used by dmem itself to manage all
 *     registered memory. It's set by dmem_alloc_init()
 */
struct dmem_region {
	/* original registered memory region */
	phys_addr_t reserved_start_addr;
	phys_addr_t reserved_end_addr;

	/* memory region aligned to dmem page */
	phys_addr_t dpage_start_pfn;
	phys_addr_t dpage_end_pfn;

	/*
	 * avoid memory allocation if the dmem region is small enough
	 */
	unsigned long static_bitmap;
	unsigned long *bitmap;
	u64 next_free_pos;
	struct list_head node;

	unsigned long static_error_bitmap;
	unsigned long *error_bitmap;
};

/*
 * statically define number of regions to avoid allocating memory
 * dynamically from memblock as slab is not available at that time
 */
#define DMEM_REGION_PAGES	2
#define INIT_REGION_NUM							\
	((DMEM_REGION_PAGES << PAGE_SHIFT) / sizeof(struct dmem_region))

static struct dmem_region static_regions[INIT_REGION_NUM];

struct dmem_node {
	unsigned long total_dpages;
	unsigned long free_dpages;

	/* fallback list for allocation */
	int nodelist[MAX_NUMNODES];
	struct list_head regions;
};

struct dmem_pool {
	struct mutex lock;

	unsigned long region_num;
	unsigned long registered_pages;
	unsigned long unaligned_pages;

	/* shift bits of dmem page */
	unsigned long dpage_shift;

	unsigned long total_dpages;
	unsigned long free_dpages;

	/*
	 * increased when allocator is initialized,
	 * stop it being destroyed when someone is
	 * still using it
	 */
	u64 user_count;
	struct dmem_node nodes[MAX_NUMNODES];
};

static struct dmem_pool dmem_pool = {
	.lock = __MUTEX_INITIALIZER(dmem_pool.lock),
};

#define for_each_dmem_node(_dnode)					\
	for (_dnode = dmem_pool.nodes;					\
		_dnode < dmem_pool.nodes + ARRAY_SIZE(dmem_pool.nodes);	\
		_dnode++)

void __init dmem_init(void)
{
	struct dmem_node *dnode;

	pr_info("dmem: pre-defined region: %ld\n", INIT_REGION_NUM);

	for_each_dmem_node(dnode)
		INIT_LIST_HEAD(&dnode->regions);
}

/*
 * register the memory region to dmem pool as freed memory, the region
 * should be properly aligned to PAGE_SIZE at least
 *
 * it's safe to be out of dmem_pool's lock as it's used at the very
 * beginning of system boot
 */
int dmem_region_register(int node, phys_addr_t start, phys_addr_t end)
{
	struct dmem_region *dregion;

	pr_info("dmem: register region [%#llx - %#llx] on node %d.\n",
		(unsigned long long)start, (unsigned long long)end, node);

	if (unlikely(dmem_pool.region_num >= INIT_REGION_NUM)) {
		pr_err("dmem: region is not sufficient.\n");
		return -ENOMEM;
	}

	dregion = &static_regions[dmem_pool.region_num++];
	dregion->reserved_start_addr = start;
	dregion->reserved_end_addr = end;

	list_add_tail(&dregion->node, &dmem_pool.nodes[node].regions);
	dmem_pool.registered_pages += __phys_to_pfn(end) -
					__phys_to_pfn(start);
	return 0;
}
