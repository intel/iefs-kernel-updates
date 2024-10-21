/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 - 2021 Intel Corporation.
 */
#if !defined(__RV_TRACE_MR_CACHE_H) || defined(TRACE_HEADER_MULTI_READ)
#define __RV_TRACE_MR_CACHE_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rv_mr_cache

DECLARE_EVENT_CLASS(/* msg */
	rv_mrc_msg_template,
	TP_PROTO(const char *msg, u64 d1, u64 d2, u64 d3),
	TP_ARGS(msg, d1, d2, d3),
	TP_STRUCT__entry(/* entry */
		__string(msg, msg)
		__field(u64, d1)
		__field(u64, d2)
		__field(u64, d3)
	),
	TP_fast_assign(/* assign */
		__assign_str(msg, msg);
		__entry->d1 = d1;
		__entry->d2 = d2;
		__entry->d3 = d3;
	),
	TP_printk(/* print */
		" %s: 0x%llx 0x%llx 0x%llx",
		__get_str(msg),
		__entry->d1,
		__entry->d2,
		__entry->d3
	)
);

DEFINE_EVENT(/* event */
	rv_mrc_msg_template, rv_mrc_msg_insert,
	TP_PROTO(const char *msg, u64 d1, u64 d2, u64 d3),
	TP_ARGS(msg, d1, d2, d3)
);

DEFINE_EVENT(/* event */
	rv_mrc_msg_template, rv_mrc_msg_doit_evict,
	TP_PROTO(const char *msg, u64 d1, u64 d2, u64 d3),
	TP_ARGS(msg, d1, d2, d3)
);

DEFINE_EVENT(/* event */
	rv_mrc_msg_template, rv_mrc_msg_deinit,
	TP_PROTO(const char *msg, u64 d1, u64 d2, u64 d3),
	TP_ARGS(msg, d1, d2, d3)
);

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
DEFINE_EVENT(/* event */
	rv_mrc_msg_template, rv_mrc_msg_gpu_evict,
	TP_PROTO(const char *msg, u64 d1, u64 d2, u64 d3),
	TP_ARGS(msg, d1, d2, d3)
);
#endif

DECLARE_EVENT_CLASS(/* rv_mr_cache */
	rv_mr_cache_template,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc),
	TP_STRUCT__entry(/* entry */
		__field(u64, addr)
		__field(u64, len)
		__field(u32, acc)
	),
	TP_fast_assign(/* assign */
		__entry->addr = addr;
		__entry->len = len;
		__entry->acc = acc;
	),
	TP_printk(/* print */
		"addr 0x%llx, len %llu acc 0x%x",
		__entry->addr,
		__entry->len,
		__entry->acc
	)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_insert,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_search_enter,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_search_mrce,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_evict_mrce,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_evict_evict,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_evict_range,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_evict_keep,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_notifier,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_deinit,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc)
);

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_gpu_evict,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc)
);
#endif

DEFINE_EVENT(/* event */
	rv_mr_cache_template, rv_mr_cache_doit_evict,
	TP_PROTO(u64 addr, u64 len, u32 acc),
	TP_ARGS(addr, len, acc)
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

DECLARE_EVENT_CLASS(/* rv_mr_cache */
	rv_mrc_evd_template,
	TP_PROTO(u64 clr_bytes, u32 clr_count, u64 tgt_bytes, u32 tgt_count),
	TP_ARGS(clr_bytes, clr_count, tgt_bytes, tgt_count),
	TP_STRUCT__entry(/* entry */
		__field(u64, clr_bytes)
		__field(u32, clr_count)
		__field(u64, tgt_bytes)
		__field(u32, tgt_count)
	),
	TP_fast_assign(/* assign */
		__entry->clr_bytes = clr_bytes;
		__entry->clr_count = clr_count;
		__entry->tgt_bytes = tgt_bytes;
		__entry->tgt_count = tgt_count;
	),
	TP_printk(/* print */
		"Cleared 0x%llx %u target %llx %u",
		__entry->clr_bytes,
		__entry->clr_count,
		__entry->tgt_bytes,
		__entry->tgt_count
	)
);

DEFINE_EVENT(/* event */
	rv_mrc_evd_template, rv_mrc_evd_evict,
	TP_PROTO(u64 clr_bytes, u32 clr_count, u64 tgt_bytes, u32 tgt_count),
	TP_ARGS(clr_bytes, clr_count, tgt_bytes, tgt_count)
);

#endif /* __RV_TRACE_MR_CACHE_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_mr_cache
#include <trace/define_trace.h>
