/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM dmem

#if !defined(_TRACE_DMEM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_DMEM_H

#include <linux/tracepoint.h>

TRACE_EVENT(dmem_alloc_init,
	TP_PROTO(unsigned long dpage_shift),
	TP_ARGS(dpage_shift),

	TP_STRUCT__entry(
		__field(unsigned long, dpage_shift)
	),

	TP_fast_assign(
		__entry->dpage_shift = dpage_shift;
	),

	TP_printk("dpage_shift %lu", __entry->dpage_shift)
);

TRACE_EVENT(dmem_alloc_pages_node,
	TP_PROTO(phys_addr_t addr, int node, int try_max, int result_nr),
	TP_ARGS(addr, node, try_max, result_nr),

	TP_STRUCT__entry(
		__field(phys_addr_t, addr)
		__field(int, node)
		__field(int, try_max)
		__field(int, result_nr)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->node = node;
		__entry->try_max = try_max;
		__entry->result_nr = result_nr;
	),

	TP_printk("addr %#lx node %d try_max %d result_nr %d",
		  (unsigned long)__entry->addr, __entry->node,
		  __entry->try_max, __entry->result_nr)
);

TRACE_EVENT(dmem_free_pages,
	TP_PROTO(phys_addr_t addr, int dpages_nr),
	TP_ARGS(addr, dpages_nr),

	TP_STRUCT__entry(
		__field(phys_addr_t, addr)
		__field(int, dpages_nr)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->dpages_nr = dpages_nr;
	),

	TP_printk("addr %#lx dpages_nr %d", (unsigned long)__entry->addr,
		  __entry->dpages_nr)
);
#endif

/* This part must be outside protection */
#include <trace/define_trace.h>
