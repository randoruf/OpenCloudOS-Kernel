// SPDX-License-Identifier: GPL-2.0-only
/*
 * Support reserved memory for dmem.
 * As dmem_reserve_init will adjust memblock to reserve memory
 * for dmem, we could save a vast amount of memory for 'struct page'.
 *
 * Authors:
 *   Chen Zhuo	     <sagazchen@tencent.com>
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/memblock.h>
#include <linux/log2.h>
#include <linux/dmem.h>

struct dmem_param {
	phys_addr_t base;
	phys_addr_t size;
	phys_addr_t align;
	/*
	 * If set to 1, dmem_param specified requested memory for kernel,
	 * otherwise for dmem.
	 */
	bool resv_kernel;
};

static struct dmem_param dmem_param __initdata;

/* Check dmem param defined by user to match dmem align */
static int __init check_dmem_param(bool resv_kernel, phys_addr_t base,
				   phys_addr_t size, phys_addr_t align)
{
	phys_addr_t min_align = 1UL << SECTION_SIZE_BITS;

	if (!align)
		align = min_align;

	/*
	 * the reserved region should be aligned to memory section
	 * at least
	 */
	if (align < min_align) {
		pr_warn("dmem: 'align' should be %#llx at least to be aligned to memory section.\n",
			min_align);
		return -EINVAL;
	}

	if (!is_power_of_2(align)) {
		pr_warn("dmem: 'align' should be power of 2.\n");
		return -EINVAL;
	}

	if (base & (align - 1)) {
		pr_warn("dmem: 'addr' is unaligned to 'align' in dmem=\n");
		return -EINVAL;
	}

	if (size & (align - 1)) {
		pr_warn("dmem: 'size' is unaligned to 'align' in dmem=\n");
		return -EINVAL;
	}

	if (base >= base + size) {
		pr_warn("dmem: 'addr + size' overflow in dmem=\n");
		return -EINVAL;
	}

	if (resv_kernel && base) {
		pr_warn("dmem: take a certain base address for kernel is illegal\n");
		return -EINVAL;
	}

	dmem_param.base = base;
	dmem_param.size = size;
	dmem_param.align = align;
	dmem_param.resv_kernel = resv_kernel;

	pr_info("dmem: parameter: base address %#llx size %#llx align %#llx resv_kernel %d\n",
		(unsigned long long)base, (unsigned long long)size,
		(unsigned long long)align, resv_kernel);
	return 0;
}

static int __init parse_dmem(char *p)
{
	phys_addr_t base, size, align;
	char *oldp;
	bool resv_kernel = false;

	if (!p)
		return -EINVAL;

	base = align = 0;

	if (*p == '!') {
		resv_kernel = true;
		p++;
	}

	oldp = p;
	size = memparse(p, &p);
	if (oldp == p)
		return -EINVAL;

	if (!size) {
		pr_warn("dmem: 'size' of 0 defined in dmem=, or {invalid} param\n");
		return -EINVAL;
	}

	while (*p) {
		phys_addr_t *pvalue;

		switch (*p) {
		case '@':
			pvalue = &base;
			break;
		case ':':
			pvalue = &align;
			break;
		default:
			pr_warn("dmem: unknown indicator: %c in dmem=\n", *p);
			return -EINVAL;
		}

		/*
		 * Some attribute had been specified multiple times.
		 * This is not allowed.
		 */
		if (*pvalue)
			return -EINVAL;

		oldp = ++p;
		*pvalue = memparse(p, &p);
		if (oldp == p)
			return -EINVAL;

		if (*pvalue == 0) {
			pr_warn("dmem: 'addr' or 'align' should not be set to 0\n");
			return -EINVAL;
		}
	}

	return check_dmem_param(resv_kernel, base, size, align);
}

early_param("dmem", parse_dmem);

/*
 * We wanna remove a memory range from memblock.memory thoroughly.
 * As isolating memblock.memory in memblock_remove needs to double
 * the array of memblock_region, allocated memory for new array maybe
 * locate in the memory range which we wanna to remove.
 *	So, conflict.
 * To resolve this conflict, here reserve this memory range firstly.
 * While reserving this memory range, isolating memory.reserved will allocate
 * memory excluded from memory range which to be removed. So following
 * double array in memblock_remove can't observe this reserved range.
 */
static void __init dmem_remove_memblock(phys_addr_t base, phys_addr_t size)
{
	memblock_reserve(base, size);
	memblock_remove(base, size);
	memblock_free(base, size);
}

static u64 node_req_mem[MAX_NUMNODES] __initdata;

/* Reserve certain size of memory for dmem in each numa node */
static void __init dmem_reserve_size(phys_addr_t size, phys_addr_t align,
		bool resv_kernel)
{
	phys_addr_t start, end;
	u64 i;
	int nid;

	/* Calculate available free memory on each node */
	for_each_free_mem_range(i, NUMA_NO_NODE, MEMBLOCK_NONE, &start,
				&end, &nid)
		node_req_mem[nid] += end - start;

	/* Calculate memory size needed to reserve on each node for dmem */
	for (i = 0; i < MAX_NUMNODES; i++) {
		node_req_mem[i] = ALIGN(node_req_mem[i], align);

		if (!resv_kernel) {
			node_req_mem[i] = min(size, node_req_mem[i]);
			continue;
		}

		/* leave dmem_param.size memory for kernel */
		if (node_req_mem[i] > size)
			node_req_mem[i] = node_req_mem[i] - size;
		else
			node_req_mem[i] = 0;
	}

retry:
	for_each_free_mem_range_reverse(i, NUMA_NO_NODE, MEMBLOCK_NONE,
					&start, &end, &nid) {
		/* Well, we have got enough memory for this node. */
		if (!node_req_mem[nid])
			continue;

		start = round_up(start, align);
		end = round_down(end, align);
		/* Skip memblock_region which is too small */
		if (start >= end)
			continue;

		/* Towards memory block at higher address */
		start = end - min((end - start), node_req_mem[nid]);

		/*
		 * do not have enough resource to save the region, skip it
		 * from now on
		 */
		if (dmem_region_register(nid, start, end) < 0)
			break;

		dmem_remove_memblock(start, end - start);

		node_req_mem[nid] -= end - start;

		/* We have dropped a memblock, so re-walk it. */
		goto retry;
	}

	for (i = 0; i < MAX_NUMNODES; i++) {
		if (!node_req_mem[i])
			continue;

		pr_info("dmem: %#llx size of memory is not reserved on node %lld due to misaligned regions.\n",
			(unsigned long long)size, i);
	}

}

/* Reserve [base, base + size) for dmem. */
static void __init
dmem_reserve_region(phys_addr_t base, phys_addr_t size, phys_addr_t align)
{
	phys_addr_t start, end;
	phys_addr_t p_start, p_end;
	u64 i;
	int nid;

	p_start = base;
	p_end = base + size;

retry:
	for_each_free_mem_range_reverse(i, NUMA_NO_NODE, MEMBLOCK_NONE,
					&start, &end, &nid) {
		/* Find region located in user defined range. */
		if (start >= p_end || end <= p_start)
			continue;

		start = round_up(max(start, p_start), align);
		end = round_down(min(end, p_end), align);
		if (start >= end)
			continue;

		if (dmem_region_register(nid, start, end) < 0)
			break;

		dmem_remove_memblock(start, end - start);

		size -= end - start;
		if (!size)
			return;

		/* We have dropped a memblock, so re-walk it. */
		goto retry;
	}

	pr_info("dmem: %#llx size of memory is not reserved for dmem due to holes and misaligned regions in [%#llx, %#llx].\n",
		(unsigned long long)size, (unsigned long long)base,
		(unsigned long long)(base + size));
}

/* Reserve memory for dmem */
int __init dmem_reserve_init(void)
{
	phys_addr_t base, size, align;
	bool resv_kernel;

	dmem_init();

	base = dmem_param.base;
	size = dmem_param.size;
	align = dmem_param.align;
	resv_kernel = dmem_param.resv_kernel;

	/* Dmem param had not been enabled. */
	if (size == 0)
		return 0;

	if (base)
		dmem_reserve_region(base, size, align);
	else
		dmem_reserve_size(size, align, resv_kernel);

	return 0;
}
