/* SPDX-License-Identifier: GPL-2.0 */
/**
 * trace.h - DesignWare Support
 *
 * Copyright (C)
 *
 * Author: Xiao Guangrong <xiaoguangrong@tencent.com>
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM dmemfs

#if !defined(_TRACE_DMEMFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_DMEMFS_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(dmemfs_radix_tree_class,
	TP_PROTO(unsigned long index, void *rentry),
	TP_ARGS(index, rentry),

	TP_STRUCT__entry(
		__field(unsigned long,	index)
		__field(void *, rentry)
	),

	TP_fast_assign(
		__entry->index = index;
		__entry->rentry = rentry;
	),

	TP_printk("index %lu entry %#lx", __entry->index,
		  (unsigned long)__entry->rentry)
);

DEFINE_EVENT(dmemfs_radix_tree_class, dmemfs_radix_tree_insert,
	TP_PROTO(unsigned long index, void *rentry),
	TP_ARGS(index, rentry)
);

DEFINE_EVENT(dmemfs_radix_tree_class, dmemfs_radix_tree_delete,
	TP_PROTO(unsigned long index, void *rentry),
	TP_ARGS(index, rentry)
);
#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
