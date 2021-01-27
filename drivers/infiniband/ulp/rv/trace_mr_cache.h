/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 */
#if !defined(__RV_TRACE_MR_CACHE_H) || defined(TRACE_HEADER_MULTI_READ)
#define __RV_TRACE_MR_CACHE_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rv_mr_cache

DECLARE_EVENT_CLASS(/* rv_mr_cache */
	rv_mr_cache_template,
	TP_PROTO(unsigned long addr, unsigned long len, int acc),
	TP_ARGS(addr, len, acc),
	TP_STRUCT__entry(/* entry */
		__field(unsigned long, addr)
		__field(unsigned long, len)
		__field(int, acc)
	),
	TP_fast_assign(/* assign */
		__entry->addr = addr;
		__entry->len = len;
		__entry->acc = acc;
	),
	TP_printk(/* print */
		"addr 0x%lx, len %lu acc %d",
		__entry->addr,
		__entry->len,
		__entry->acc
	)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_insert,
	TP_PROTO(unsigned long addr, unsigned long len, int acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_search_enter,
	TP_PROTO(unsigned long addr, unsigned long len, int acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_search_mrc,
	TP_PROTO(unsigned long addr, unsigned long len, int acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_remove,
	TP_PROTO(unsigned long addr, unsigned long len, int acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_evict_evict,
	TP_PROTO(unsigned long addr, unsigned long len, int acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_evict_keep,
	TP_PROTO(unsigned long addr, unsigned long len, int acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_notifier,
	TP_PROTO(unsigned long addr, unsigned long len, int acc),
	TP_ARGS(addr, len, acc)
);

TRACE_EVENT(/* event */
	rv_mr_cache_cache_full,
	TP_PROTO(unsigned long max, unsigned long total, unsigned long cur),
	TP_ARGS(max, total, cur),
	TP_STRUCT__entry(/* entry */
		__field(unsigned long, max)
		__field(unsigned long, total)
		__field(unsigned long, cur)
	),
	TP_fast_assign(/* assign */
		__entry->max = max;
		__entry->total = total;
		__entry->cur = cur;
	),
	TP_printk(/* print */
		"Cache Full max %lu, total %lu, cur %lu",
		__entry->max,
		__entry->total,
		__entry->cur
	)
);

TRACE_EVENT(/* event */
	rv_mr_cache_deinit,
	TP_PROTO(unsigned long addr, unsigned long len, int acc, int cnt),
	TP_ARGS(addr, len, acc, cnt),
	TP_STRUCT__entry(/* entry */
		__field(unsigned long, addr)
		__field(unsigned long, len)
		__field(int, acc)
		__field(int, cnt)
	),
	TP_fast_assign(/* assign */
		__entry->addr = addr;
		__entry->len = len;
		__entry->acc = acc;
		__entry->cnt = cnt;
	),
	TP_printk(/* print */
		"addr 0x%lx, len %lu, acc %d refcnt %d",
		__entry->addr,
		__entry->len,
		__entry->acc,
		__entry->cnt
	)
);

DECLARE_EVENT_CLASS(/* rv_mr_cache_wq */
	rv_mr_cache_wq_template,
	TP_PROTO(const char *wq_name),
	TP_ARGS(wq_name),
	TP_STRUCT__entry(/* entry */
		__string(name, wq_name)
	),
	TP_fast_assign(/* assign */
		__assign_str(name, wq_name);
	),
	TP_printk(/* print */
		"Workqueue %s",
		__get_str(name)
	)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_wq_template, rv_mr_cache_wq_alloc,
	TP_PROTO(const char *wq_name),
	TP_ARGS(wq_name)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_wq_template, rv_mr_cache_wq_destroy,
	TP_PROTO(const char *wq_name),
	TP_ARGS(wq_name)
);

TRACE_EVENT(/* event */
	rv_mr_cache_cache_evict,
	TP_PROTO(u64 cleared, u64 target, u64 total_size),
	TP_ARGS(cleared, target, total_size),
	TP_STRUCT__entry(/* entry */
		__field(u64, cleared)
		__field(u64, target)
		__field(u64, total_size)
	),
	TP_fast_assign(/* assign */
		__entry->cleared = cleared;
		__entry->target = target;
		__entry->total_size = total_size;
	),
	TP_printk(/* print */
		"cleared 0x%llx target 0x%llx total_size 0x%llx",
		__entry->cleared,
		__entry->target,
		__entry->total_size
	)
);

#endif /* __RV_TRACE_MR_CACHE_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_mr_cache
#include <trace/define_trace.h>
