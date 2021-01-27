/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 */
#if !defined(__RV_TRACE_MISC_H) || defined(TRACE_HEADER_MULTI_READ)
#define __RV_TRACE_MISC_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rv_misc

DECLARE_EVENT_CLASS(/* msg */
	rv_msg_template,
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
		"inx %u: %s 0x%llx 0x%llx",
		__entry->inx,
		__get_str(msg),
		__entry->d1,
		__entry->d2
	)
);

DEFINE_EVENT(/* event */
	rv_msg_template, rv_msg_err_qp,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);
#endif /* __RV_TRACE_MISC_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_misc
#include <trace/define_trace.h>
