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

#define CREATE_TRACE_POINTS
#include <trace/events/dmem.h>
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

#define DMEM_PAGE_SIZE		(1UL << dmem_pool.dpage_shift)
#define DMEM_PAGE_UP(x)		phys_to_dpage(((x) + DMEM_PAGE_SIZE - 1))
#define DMEM_PAGE_DOWN(x)	phys_to_dpage(x)

#define dpage_to_phys(_dpage)						\
	((_dpage) << dmem_pool.dpage_shift)
#define phys_to_dpage(_addr)						\
	((_addr) >> dmem_pool.dpage_shift)

#define dpage_to_pfn(_dpage)						\
	(__phys_to_pfn(dpage_to_phys(_dpage)))
#define pfn_to_dpage(_pfn)						\
	(phys_to_dpage(__pfn_to_phys(_pfn)))

#define dnode_to_nid(_dnode)						\
	((_dnode) - dmem_pool.nodes)
#define nid_to_dnode(nid)						\
	(&dmem_pool.nodes[nid])

#define for_each_dmem_node(_dnode)					\
	for (_dnode = dmem_pool.nodes;					\
		_dnode < dmem_pool.nodes + ARRAY_SIZE(dmem_pool.nodes);	\
		_dnode++)

#define for_each_dmem_region(_dnode, _dregion) 			\
	list_for_each_entry(_dregion, &(_dnode)->regions, node)

static inline int *dmem_nodelist(int nid)
{
	return nid_to_dnode(nid)->nodelist;
}

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

#ifdef CONFIG_DMEM_DEBUG_FS
struct debugfs_entry {
	const char *name;
	unsigned long offset;
};

#define DMEM_POOL_OFFSET(x)	offsetof(struct dmem_pool, x)
#define DMEM_POOL_ENTRY(x)	{__stringify(x), DMEM_POOL_OFFSET(x)}

#define DMEM_NODE_OFFSET(x)	offsetof(struct dmem_node, x)
#define DMEM_NODE_ENTRY(x)	{__stringify(x), DMEM_NODE_OFFSET(x)}

static struct debugfs_entry dmem_pool_entries[] = {
	DMEM_POOL_ENTRY(region_num),
	DMEM_POOL_ENTRY(registered_pages),
	DMEM_POOL_ENTRY(unaligned_pages),
	DMEM_POOL_ENTRY(dpage_shift),
	DMEM_POOL_ENTRY(total_dpages),
	DMEM_POOL_ENTRY(free_dpages),
};

static struct debugfs_entry dmem_node_entries[] = {
	DMEM_NODE_ENTRY(total_dpages),
	DMEM_NODE_ENTRY(free_dpages),
};

static int dmem_entry_get(void *offset, u64 *val)
{
	*val = *(u64 *)offset;
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(dmem_fops, dmem_entry_get, NULL, "%llu\n");

static int dmemfs_init_debugfs_node(struct dmem_node *dnode,
				    struct dentry *parent)
{
	struct dentry *node_dir;
	char dir_name[32];
	int i, ret = -EEXIST;

	snprintf(dir_name, sizeof(dir_name), "node%ld",
		 dnode - dmem_pool.nodes);
	node_dir = debugfs_create_dir(dir_name, parent);
	if (!node_dir)
		return ret;

	for (i = 0; i < ARRAY_SIZE(dmem_node_entries); i++)
		if (!debugfs_create_file(dmem_node_entries[i].name, 0444,
		   node_dir, (void *)dnode + dmem_node_entries[i].offset,
		   &dmem_fops))
			return ret;
	return 0;
}

static int dmemfs_init_debugfs(void)
{
	struct dentry *dmem_debugfs_dir;
	struct dmem_node *dnode;
	int i, ret = -EEXIST;

	dmem_debugfs_dir = debugfs_create_dir("dmem", NULL);
	if (!dmem_debugfs_dir)
		return ret;

	for (i = 0; i < ARRAY_SIZE(dmem_pool_entries); i++)
		if (!debugfs_create_file(dmem_pool_entries[i].name, 0444,
		   dmem_debugfs_dir,
		   (void *)&dmem_pool + dmem_pool_entries[i].offset,
		   &dmem_fops))
			goto exit;

	for_each_dmem_node(dnode) {
		/*
		 * do not create debugfs files for the node
		 * where no memory is available
		 */
		if (list_empty(&dnode->regions))
			continue;

		if (dmemfs_init_debugfs_node(dnode, dmem_debugfs_dir))
			goto exit;
	}

	return 0;
exit:
	debugfs_remove_recursive(dmem_debugfs_dir);
	return ret;
}

#else
static int dmemfs_init_debugfs(void)
{
	return 0;
}
#endif

#define PENALTY_FOR_DMEM_SHARED_NODE		(1)

static int dmem_nodeload[MAX_NUMNODES] __initdata;

/* Evaluate penalty for each dmem node */
static int __init dmem_evaluate_node(int local, int node)
{
	int penalty;

	/* Use the distance array to find the distance */
	penalty = node_distance(local, node);

	/* Penalize nodes under us ("prefer the next node") */
	penalty += (node < local);

	/* Give preference to headless and unused nodes */
	if (!cpumask_empty(cpumask_of_node(node)))
		penalty += PENALTY_FOR_NODE_WITH_CPUS;

	/* Penalize dmem-node shared with kernel */
	if (node_state(node, N_MEMORY))
		penalty += PENALTY_FOR_DMEM_SHARED_NODE;

	/* Slight preference for less loaded node */
	penalty *= (nr_online_nodes * MAX_NUMNODES);

	penalty += dmem_nodeload[node];

	return penalty;
}

static int __init find_next_dmem_node(int local, nodemask_t *used_nodes)
{
	struct dmem_node *dnode;
	int node, best_node = NUMA_NO_NODE;
	int penalty, min_penalty = INT_MAX;

	/* Invalid node is not suitable to call node_distance */
	if (!node_state(local, N_POSSIBLE))
		return NUMA_NO_NODE;

	/* Use the local node if we haven't already */
	if (!node_isset(local, *used_nodes)) {
		node_set(local, *used_nodes);
		return local;
	}

	for_each_dmem_node(dnode) {
		if (list_empty(&dnode->regions))
			continue;

		node = dnode_to_nid(dnode);

		/* Don't want a node to appear more than once */
		if (node_isset(node, *used_nodes))
			continue;

		penalty = dmem_evaluate_node(local, node);

		if (penalty < min_penalty) {
			min_penalty = penalty;
			best_node = node;
		}
	}

	if (best_node >= 0)
		node_set(best_node, *used_nodes);

	return best_node;
}

static int __init dmem_node_init(struct dmem_node *dnode)
{
	int *nodelist;
	nodemask_t used_nodes;
	int local, node, prev;
	int load;
	int i = 0;

	nodelist = dnode->nodelist;
	nodes_clear(used_nodes);
	local = dnode_to_nid(dnode);
	prev = local;
	load = nr_online_nodes;

	while ((node = find_next_dmem_node(local, &used_nodes)) >= 0) {
		/*
		 * We don't want to pressure a particular node.
		 * So adding penalty to the first node in same
		 * distance group to make it round-robin.
		 */
		if (node_distance(local, node) != node_distance(local, prev))
			dmem_nodeload[node] = load;

		nodelist[i++] = prev = node;
		load--;
	}

	return 0;
}

static void __init dmem_region_uinit(struct dmem_region *dregion)
{
	unsigned long nr_pages, size, *bitmap = dregion->error_bitmap;

	if (!bitmap)
		return;

	nr_pages = __phys_to_pfn(dregion->reserved_end_addr)
		- __phys_to_pfn(dregion->reserved_start_addr);

	WARN_ON(!nr_pages);

	size = BITS_TO_LONGS(nr_pages) * sizeof(long);
	if (size > sizeof(dregion->static_bitmap))
		kfree(bitmap);
	dregion->error_bitmap = NULL;
}

/*
 * we only stop allocator to use the reserved page and do not
 * reture pages back if anything goes wrong
 */
static void __init dmem_uinit(void)
{
	struct dmem_region *dregion, *dr;
	struct dmem_node *dnode;

	for_each_dmem_node(dnode) {
		dnode->nodelist[0] = NUMA_NO_NODE;
		list_for_each_entry_safe(dregion, dr, &dnode->regions, node) {
			dmem_region_uinit(dregion);
			dregion->reserved_start_addr =
				dregion->reserved_end_addr = 0;
			list_del(&dregion->node);
		}
	}

	dmem_pool.region_num = 0;
	dmem_pool.registered_pages = 0;
}

static int __init dmem_region_init(struct dmem_region *dregion)
{
	unsigned long *bitmap, size, nr_pages;

	nr_pages = __phys_to_pfn(dregion->reserved_end_addr)
		- __phys_to_pfn(dregion->reserved_start_addr);

	size = BITS_TO_LONGS(nr_pages) * sizeof(long);
	if (size <= sizeof(dregion->static_error_bitmap)) {
		bitmap = &dregion->static_error_bitmap;
	} else {
		bitmap = kzalloc(size, GFP_KERNEL);
		if (!bitmap)
			return -ENOMEM;
	}
	dregion->error_bitmap = bitmap;
	return 0;
}

/*
 * dmem memory is not 'struct page' backend, i.e, the kernel threats
 * it as invalid pfn
 */
static int __init dmem_check_region(struct dmem_region *dregion)
{
	unsigned long pfn;

	for (pfn = __phys_to_pfn(dregion->reserved_start_addr);
	      pfn < __phys_to_pfn(dregion->reserved_end_addr); pfn++) {
		if (!WARN_ON(pfn_valid(pfn)))
			continue;

		pr_err("dmem: check pfn %#lx failed, its memory was not properly reserved\n",
			pfn);
		return -EINVAL;
	}

	return 0;
}

static int __init dmem_late_init(void)
{
	struct dmem_region *dregion;
	struct dmem_node *dnode;
	int ret;

	for_each_dmem_node(dnode) {
		dmem_node_init(dnode);

		for_each_dmem_region(dnode, dregion) {
			ret = dmem_region_init(dregion);
			if (ret)
				goto exit;
			ret = dmem_check_region(dregion);
			if (ret)
				goto exit;
		}
	}

	return dmemfs_init_debugfs();
exit:
	dmem_uinit();
	return ret;
}
late_initcall(dmem_late_init);

static int dmem_alloc_region_init(struct dmem_region *dregion,
				  unsigned long *dpages)
{
	unsigned long start, end, *bitmap, size;

	start = DMEM_PAGE_UP(dregion->reserved_start_addr);
	end = DMEM_PAGE_DOWN(dregion->reserved_end_addr);

	*dpages = end - start;
	if (!*dpages)
		return 0;

	size = BITS_TO_LONGS(*dpages) * sizeof(long);
	if (size <= sizeof(dregion->static_bitmap))
		bitmap = &dregion->static_bitmap;
	else {
		bitmap = kzalloc(size, GFP_KERNEL);
		if (!bitmap)
			return -ENOMEM;
	}

	dregion->bitmap = bitmap;
	dregion->next_free_pos = 0;
	dregion->dpage_start_pfn = start;
	dregion->dpage_end_pfn = end;

	dmem_pool.unaligned_pages += __phys_to_pfn((dpage_to_phys(start)
		- dregion->reserved_start_addr));
	dmem_pool.unaligned_pages += __phys_to_pfn(dregion->reserved_end_addr
		- dpage_to_phys(end));
	return 0;
}

static bool dmem_dpage_is_error(struct dmem_region *dregion, phys_addr_t dpage)
{
	unsigned long valid_pages;
	unsigned long pos_pfn, pos_offset;
	unsigned long pages_per_dpage = DMEM_PAGE_SIZE >> PAGE_SHIFT;
	phys_addr_t reserved_start_pfn;

	reserved_start_pfn = __phys_to_pfn(dregion->reserved_start_addr);
	valid_pages = dpage_to_pfn(dregion->dpage_end_pfn) - reserved_start_pfn;

	pos_offset = dpage_to_pfn(dpage) - reserved_start_pfn;
	pos_pfn = find_next_bit(dregion->error_bitmap, valid_pages, pos_offset);
	if (pos_pfn < pos_offset + pages_per_dpage)
		return true;
	return false;
}

static unsigned long
dmem_alloc_bitmap_clear(struct dmem_region *dregion, phys_addr_t dpage,
			unsigned int dpages_nr)
{
	u64 pos = dpage - dregion->dpage_start_pfn;
	unsigned int i;
	unsigned long err_num = 0;

	for (i = 0; i < dpages_nr; i++) {
		if (dmem_dpage_is_error(dregion, dpage + i)) {
			WARN_ON(!test_bit(pos + i, dregion->bitmap));
			err_num++;
		} else {
			WARN_ON(!__test_and_clear_bit(pos + i,
						      dregion->bitmap));
		}
	}
	return err_num;
}

/* set or clear corresponding bit on allocation bitmap based on error bitmap */
static unsigned long dregion_alloc_bitmap_set_clear(struct dmem_region *dregion,
						    bool set)
{
	unsigned long pos_pfn, pos_offset;
	unsigned long valid_pages, mce_dpages = 0;
	phys_addr_t dpage, reserved_start_pfn;

	reserved_start_pfn = __phys_to_pfn(dregion->reserved_start_addr);

	valid_pages = dpage_to_pfn(dregion->dpage_end_pfn) - reserved_start_pfn;
	pos_offset = dpage_to_pfn(dregion->dpage_start_pfn)
		- reserved_start_pfn;
try_set:
	pos_pfn = find_next_bit(dregion->error_bitmap, valid_pages, pos_offset);

	if (pos_pfn >= valid_pages)
		return mce_dpages;
	mce_dpages++;
	dpage = pfn_to_dpage(pos_pfn + reserved_start_pfn);
	if (set)
		WARN_ON(__test_and_set_bit(dpage - dregion->dpage_start_pfn,
					   dregion->bitmap));
	else
		WARN_ON(!__test_and_clear_bit(dpage - dregion->dpage_start_pfn,
					      dregion->bitmap));
	pos_offset = dpage_to_pfn(dpage + 1) - reserved_start_pfn;
	goto try_set;
}

static void dmem_uinit_check_alloc_bitmap(struct dmem_region *dregion)
{
	unsigned long dpages, size;

	dregion_alloc_bitmap_set_clear(dregion, false);

	dpages = dregion->dpage_end_pfn - dregion->dpage_start_pfn;
	size = BITS_TO_LONGS(dpages) * sizeof(long);
	WARN_ON(!bitmap_empty(dregion->bitmap, size * BITS_PER_BYTE));
}

static void dmem_alloc_region_uinit(struct dmem_region *dregion)
{
	unsigned long dpages, size, *bitmap = dregion->bitmap;

	if (!bitmap)
		return;

	dpages = dregion->dpage_end_pfn - dregion->dpage_start_pfn;
	WARN_ON(!dpages);

	dmem_uinit_check_alloc_bitmap(dregion);

	size = BITS_TO_LONGS(dpages) * sizeof(long);
	if (size > sizeof(dregion->static_bitmap))
		kfree(bitmap);
	dregion->bitmap = NULL;
}

static void __dmem_alloc_uinit(void)
{
	struct dmem_node *dnode;
	struct dmem_region *dregion;

	if (!dmem_pool.dpage_shift)
		return;

	dmem_pool.unaligned_pages = 0;

	for_each_dmem_node(dnode) {
		for_each_dmem_region(dnode, dregion)
			dmem_alloc_region_uinit(dregion);

		dnode->total_dpages = dnode->free_dpages = 0;
	}

	dmem_pool.dpage_shift = 0;
	dmem_pool.total_dpages = dmem_pool.free_dpages = 0;
}

static void dnode_count_free_dpages(struct dmem_node *dnode, long dpages)
{
	dnode->free_dpages += dpages;
	dmem_pool.free_dpages += dpages;
}

/*
 * uninitialize dmem allocator
 *
 * all dpages should be freed before calling it
 */
void dmem_alloc_uinit(void)
{
	mutex_lock(&dmem_pool.lock);
	if (!--dmem_pool.user_count)
		__dmem_alloc_uinit();
	mutex_unlock(&dmem_pool.lock);
}
EXPORT_SYMBOL(dmem_alloc_uinit);

/*
 * initialize dmem allocator
 *   @dpage_shift: the shift bits of dmem page size used to manange
 *      dmem memory, it should be CPU's nature page size at least
 *
 * Note: the page size the allocator used isn't the same thing with
 *       the alignment used to reserve dmem memory
 */
int dmem_alloc_init(unsigned long dpage_shift)
{
	struct dmem_node *dnode;
	struct dmem_region *dregion;
	unsigned long dpages;
	int ret = 0;

	if (dpage_shift < PAGE_SHIFT)
		return -EINVAL;

	mutex_lock(&dmem_pool.lock);

	trace_dmem_alloc_init(dpage_shift);

	if (dmem_pool.dpage_shift) {
		/*
		 * double init on the same page size is okay
		 * to make the unit tests happy
		 */
		if (dmem_pool.dpage_shift != dpage_shift)
			ret = -EBUSY;

		goto exit;
	}

	dmem_pool.dpage_shift = dpage_shift;

	for_each_dmem_node(dnode) {
		for_each_dmem_region(dnode, dregion) {
			ret = dmem_alloc_region_init(dregion, &dpages);
			if (ret < 0) {
				__dmem_alloc_uinit();
				goto exit;
			}

			dnode_count_free_dpages(dnode, dpages);
		}
		dnode->total_dpages = dnode->free_dpages;
	}

	dmem_pool.total_dpages = dmem_pool.free_dpages;

	if (dmem_pool.unaligned_pages && !ret)
		pr_warn("dmem: %llu pages are wasted due to alignment\n",
			(unsigned long long)dmem_pool.unaligned_pages);
exit:
	if (!ret)
		dmem_pool.user_count++;

	mutex_unlock(&dmem_pool.lock);
	return ret;
}
EXPORT_SYMBOL(dmem_alloc_init);

static phys_addr_t
dmem_alloc_region_page(struct dmem_region *dregion, unsigned int try_max,
		       unsigned int *result_nr)
{
	unsigned long pos, dpages;
	unsigned int i;

	/* no dpage is available in this region */
	if (!dregion->bitmap)
		return 0;

	dpages = dregion->dpage_end_pfn - dregion->dpage_start_pfn;

	/* no free page in this region */
	if (dregion->next_free_pos >= dpages)
		return 0;

	pos = find_next_zero_bit(dregion->bitmap, dpages,
				 dregion->next_free_pos);
	if (pos >= dpages) {
		dregion->next_free_pos = pos;
		return 0;
	}

	__set_bit(pos, dregion->bitmap);

	/* do not go beyond the region */
	try_max = min(try_max, (unsigned int)(dpages - pos - 1));
	for (i = 1; i < try_max; i++)
		if (__test_and_set_bit(pos + i, dregion->bitmap))
			break;

	*result_nr = i;
	dregion->next_free_pos = pos + *result_nr;
	return dpage_to_phys(dregion->dpage_start_pfn + pos);
}

/*
 * allocate dmem pages from the nodelist
 *
 *   @nodelist: dmem_node's nodelist
 *   @nodemask: nodemask for filtering the dmem nodelist
 *   @try_max: try to allocate @try_max dpages if possible
 *   @result_nr: allocated dpage number returned to the caller
 *
 * return the physical address of the first dpage allocated from dmem
 * pool, or 0 on failure. The allocated dpage number is filled into
 * @result_nr
 */
static phys_addr_t
dmem_alloc_pages_from_nodelist(int *nodelist, nodemask_t *nodemask,
			       unsigned int try_max, unsigned int *result_nr)
{
	struct dmem_node *dnode;
	struct dmem_region *dregion;
	phys_addr_t addr = 0;
	int node, i;
	unsigned int local_result_nr;

	WARN_ON(try_max > 1 && !result_nr);

	if (!result_nr)
		result_nr = &local_result_nr;

	*result_nr = 0;

	for (i = 0; !addr && i < ARRAY_SIZE(dnode->nodelist); i++) {
		node = nodelist[i];

		if (nodemask && !node_isset(node, *nodemask))
			continue;

		mutex_lock(&dmem_pool.lock);

		WARN_ON(!dmem_pool.dpage_shift);

		dnode = &dmem_pool.nodes[node];
		for_each_dmem_region(dnode, dregion) {
			addr = dmem_alloc_region_page(dregion, try_max,
						      result_nr);
			if (addr) {
				dnode_count_free_dpages(dnode,
							-(long)(*result_nr));
				break;
			}
		}

		trace_dmem_alloc_pages_node(addr, node, try_max, *result_nr);
		mutex_unlock(&dmem_pool.lock);
	}
	return addr;
}

/*
 * allocate a dmem page from the dmem pool and try to allocate more
 * continuous dpages if @try_max is not less than 1
 *
 *   @nid: the NUMA node the dmem page got from
 *   @nodemask: nodemask for filtering the dmem nodelist
 *   @try_max: try to allocate @try_max dpages if possible
 *   @result_nr: allocated dpage number returned to the caller
 *
 * return the physical address of the first dpage allocated from dmem
 * pool, or 0 on failure. The allocated dpage number is filled into
 * @result_nr
 */
phys_addr_t
dmem_alloc_pages_nodemask(int nid, nodemask_t *nodemask, unsigned int try_max,
			  unsigned int *result_nr)
{
	int *nodelist;

	if (nid >= sizeof(ARRAY_SIZE(dmem_pool.nodes)))
		return 0;

	nodelist = dmem_nodelist(nid);
	return dmem_alloc_pages_from_nodelist(nodelist, nodemask,
					      try_max, result_nr);
}
EXPORT_SYMBOL(dmem_alloc_pages_nodemask);

/* Return a nodelist indicated for current node representing a mempolicy */
static int *policy_nodelist(struct mempolicy *policy)
{
	int nd = numa_node_id();

	switch (policy->mode) {
	case MPOL_PREFERRED:
		if (!(policy->flags & MPOL_F_LOCAL))
			nd = policy->v.preferred_node;
		break;
	case MPOL_BIND:
		if (unlikely(!node_isset(nd, policy->v.nodes)))
			nd = first_node(policy->v.nodes);
		break;
	default:
		WARN_ON(1);
	}
	return dmem_nodelist(nd);
}

static nodemask_t *dmem_policy_nodemask(struct mempolicy *policy)
{
	if (unlikely(policy->mode == MPOL_BIND) &&
			cpuset_nodemask_valid_mems_allowed(&policy->v.nodes))
		return &policy->v.nodes;

	return NULL;
}

static void
get_mempolicy_nlist_and_nmask(struct mempolicy *pol,
			      struct vm_area_struct *vma, unsigned long addr,
			      int **nl, nodemask_t **nmask)
{
	if (pol->mode == MPOL_INTERLEAVE) {
		unsigned int nid;

		/*
		 * we use dpage_shift to interleave numa nodes although
		 * multiple dpages may be allocated
		 */
		nid = interleave_nid(pol, vma, addr, dmem_pool.dpage_shift);
		*nl = dmem_nodelist(nid);
		*nmask = NULL;
	} else {
		*nl = policy_nodelist(pol);
		*nmask = dmem_policy_nodemask(pol);
	}
}

/*
 * dmem_alloc_pages_vma - Allocate pages for a VMA.
 *
 *   @vma:  Pointer to VMA or NULL if not available.
 *   @addr: Virtual Address of the allocation. Must be inside the VMA.
 *   @try_max: try to allocate @try_max dpages if possible
 *   @result_nr: allocated dpage number returned to the caller
 *
 * This function allocates pages from dmem pool and applies a NUMA policy
 * associated with the VMA.
 *
 * Return the physical address of the first dpage allocated from dmem
 * pool, or 0 on failure. The allocated dpage number is filled into
 * @result_nr
 */
phys_addr_t
dmem_alloc_pages_vma(struct vm_area_struct *vma, unsigned long addr,
		     unsigned int try_max, unsigned int *result_nr)
{
	phys_addr_t phys_addr;
	struct mempolicy *pol;
	int *nl;
	nodemask_t *nmask;
	unsigned int cpuset_mems_cookie;

retry_cpuset:
	pol = get_vma_policy(vma, addr);
	cpuset_mems_cookie = read_mems_allowed_begin();

	get_mempolicy_nlist_and_nmask(pol, vma, addr, &nl, &nmask);
	mpol_cond_put(pol);

	phys_addr = dmem_alloc_pages_from_nodelist(nl, nmask, try_max,
						   result_nr);
	if (unlikely(!phys_addr && read_mems_allowed_retry(cpuset_mems_cookie)))
		goto retry_cpuset;

	return phys_addr;
}
EXPORT_SYMBOL(dmem_alloc_pages_vma);

/*
 * Don't need to call it in a lock.
 * This function uses the reserved addresses those are initially registered
 * and will not be modified at run time.
 */
static struct dmem_region *find_dmem_region(phys_addr_t phys_addr,
					    struct dmem_node **pdnode)
{
	struct dmem_node *dnode;
	struct dmem_region *dregion;

	for_each_dmem_node(dnode)
		for_each_dmem_region(dnode, dregion) {
			if (dregion->reserved_start_addr > phys_addr)
				continue;
			if (dregion->reserved_end_addr <= phys_addr)
				continue;

			*pdnode = dnode;
			return dregion;
		}

	return NULL;
}

/*
 * free dmem page to the dmem pool
 *   @addr: the physical addree will be freed
 *   @dpage_nr: the number of dpage to be freed
 */
void dmem_free_pages(phys_addr_t addr, unsigned int dpages_nr)
{
	struct dmem_region *dregion;
	struct dmem_node *pdnode = NULL;
	phys_addr_t dpage = phys_to_dpage(addr);
	u64 pos;
	unsigned long err_dpages;

	mutex_lock(&dmem_pool.lock);

	trace_dmem_free_pages(addr, dpages_nr);
	WARN_ON(!dmem_pool.dpage_shift);

	dregion = find_dmem_region(addr, &pdnode);
	WARN_ON(!dregion || !dregion->bitmap || !pdnode);

	pos = dpage - dregion->dpage_start_pfn;
	dregion->next_free_pos = min(dregion->next_free_pos, pos);

	/* it is not possible to span multiple regions */
	WARN_ON(dpage + dpages_nr - 1 >= dregion->dpage_end_pfn);

	err_dpages = dmem_alloc_bitmap_clear(dregion, dpage, dpages_nr);

	dnode_count_free_dpages(pdnode, dpages_nr - err_dpages);
	mutex_unlock(&dmem_pool.lock);
}
EXPORT_SYMBOL(dmem_free_pages);
