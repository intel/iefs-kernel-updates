/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2021 Intel Corporation.
 */
#if !defined(__RV_TRACE_GPU_H) || defined(TRACE_HEADER_MULTI_READ)
#define __RV_TRACE_GPU_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rv_gpu

DECLARE_EVENT_CLASS(/* gmr */
	rv_gdr_msg_template,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2),
	TP_STRUCT__entry(/* entry */
		__field(int, inx)
		__string(msg, msg)
		__field(u64, d1)
		__field(u64, d2)
	),
	TP_fast_assign(/* assign */
		__entry->inx = inx;
		__assign_str(msg, msg);
		__entry->d1 = d1;
		__entry->d2 = d2;
	),
	TP_printk(/* print */
		"rv_inx %d: %s 0x%llx %llx",
		__entry->inx,
		__get_str(msg),
		__entry->d1,
		__entry->d2
	)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_munmap,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_munmap_skip,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_put_pages,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_mrce_remove,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_deinit,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_free_callback,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_create_gmr,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_do_pin,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_do_mmap,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_pin_mmap,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_mmap,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_reg_mem,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_gdr_msg_template, rv_gdr_msg_map_verbs_mr,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DECLARE_EVENT_CLASS(/* gmr */
	rv_gdr_mr_template,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc),
	TP_STRUCT__entry(/* entry */
		__field(int, inx)
		__field(u64, addr)
		__field(u64, len)
		__field(u32, acc)
	),
	TP_fast_assign(/* assign */
		__entry->inx = inx;
		__entry->addr = addr;
		__entry->len = len;
		__entry->acc = acc;
	),
	TP_printk(/* print */
		"inx %d addr 0x%llx len %llu acc 0x%x",
		__entry->inx,
		__entry->addr,
		 __entry->len,
		 __entry->acc
	)
);

DEFINE_EVENT(/* event */
	rv_gdr_mr_template, rv_gdr_mr_release,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_gdr_mr_template, rv_gdr_mr_put_pages,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_gdr_mr_template, rv_gdr_mr_mrce_remove,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_gdr_mr_template, rv_gdr_mr_free_callback,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_gdr_mr_template, rv_gdr_mr_create,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_gdr_mr_template, rv_gdr_mr_do_pin,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_gdr_mr_template, rv_gdr_mr_pin_mmap,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_gdr_mr_template, rv_gdr_mr_munmap_unpin,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_gdr_mr_template, rv_gdr_mr_mmap,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_gdr_mr_template, rv_gdr_mr_reg_mem,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_gdr_mr_template, rv_gdr_mr_map_verbs_mr,
	TP_PROTO(int inx, u64 addr, u64 len, u32 acc),
	TP_ARGS(inx, addr, len, acc)
);

#endif /* __RV_TRACE_GPU_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_gpu
#include <trace/define_trace.h>
