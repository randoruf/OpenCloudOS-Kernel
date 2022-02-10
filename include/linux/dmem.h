/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_DMEM_H
#define _LINUX_DMEM_H

#ifdef CONFIG_DMEM
int dmem_reserve_init(void);
void dmem_init(void);
int dmem_region_register(int node, phys_addr_t start, phys_addr_t end);
int dmem_alloc_init(unsigned long dpage_shift);
void dmem_alloc_uinit(void);

#else
static inline int dmem_reserve_init(void)
{
	return 0;
}
#endif
#endif	/* _LINUX_DMEM_H */
