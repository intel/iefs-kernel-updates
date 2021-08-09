/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 - 2021 Intel Corporation.
 */
#if !defined(__RV_TRACE_MR_H) || defined(TRACE_HEADER_MULTI_READ)
#define __RV_TRACE_MR_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rv_mr

#define MR_INFO_PRN "addr 0x%llx len 0x%llx acc 0x%x lkey 0x%x rkey 0x%x " \
		    "iova 0x%llx pd_usecnt %u"

#ifdef NVIDIA_GPU_DIRECT
DECLARE_EVENT_CLASS(/* msg */
	rv_mr_msg_template,
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
	rv_mr_msg_template, rv_mr_msg_kern_reg_mem,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);

DEFINE_EVENT(/* event */
	rv_mr_msg_template, rv_mr_msg_user_gpu_reg_mem,
	TP_PROTO(int inx, const char *msg, u64 d1, u64 d2),
	TP_ARGS(inx, msg, d1, d2)
);
#endif

DECLARE_EVENT_CLASS(/* mr */
	rv_mr_template,
	TP_PROTO(u8 mode, u64 addr, u64 len, u32 acc),
	TP_ARGS(mode, addr, len, acc),
	TP_STRUCT__entry(/* entry */
		__field(u8, mode)
		__field(u64, addr)
		__field(u64, len)
		__field(u32, acc)
	),
	TP_fast_assign(/* assign */
		__entry->mode = mode;
		__entry->addr = addr;
		__entry->len = len;
		__entry->acc = acc;
	),
	TP_printk(/* print */
		"mode 0x%x addr 0x%llx, len %llu acc 0x%x",
		__entry->mode,
		__entry->addr,
		__entry->len,
		__entry->acc
	)
);

DEFINE_EVENT(/* event */
	rv_mr_template, rv_mr_reg,
	TP_PROTO(u8 mode, u64 addr, u64 len, u32 acc),
	TP_ARGS(mode, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_template, rv_mr_dereg,
	TP_PROTO(u8 mode, u64 addr, u64 len, u32 acc),
	TP_ARGS(mode, addr, len, acc)
);

#ifdef NVIDIA_GPU_DIRECT
DEFINE_EVENT(/* event */
	rv_mr_template, rv_mr_kern_reg_mem,
	TP_PROTO(u8 mode, u64 addr, u64 len, u32 acc),
	TP_ARGS(mode, addr, len, acc)
);

DEFINE_EVENT(/* event */
	rv_mr_template, rv_mr_user_gpu_reg_mem,
	TP_PROTO(u8 mode, u64 addr, u64 len, u32 acc),
	TP_ARGS(mode, addr, len, acc)
);
#endif

TRACE_EVENT(/* event */
	rv_mr_umem,
	TP_PROTO(u64 addr, u64 len, int nmap),
	TP_ARGS(addr, len, nmap),
	TP_STRUCT__entry(/* entry */
		__field(u64, addr)
		__field(u64, len)
		__field(int, nmap)
	),
	TP_fast_assign(/* assign */
		__entry->addr = addr;
		__entry->len = len;
		__entry->nmap = nmap;
	),
	TP_printk(/* print */
		"addr 0x%llx, len 0x%llx, nmap %d",
		__entry->addr,
		__entry->len,
		__entry->nmap
	)
);

DECLARE_EVENT_CLASS(/* mr_info */
	rv_mr_info_template,
	TP_PROTO(u64 addr, u64 len, u32 acc, u32 lkey,
		 u32 rkey, u64 iova, u32 pd_usecnt),
	TP_ARGS(addr, len, acc, lkey, rkey, iova, pd_usecnt),
	TP_STRUCT__entry(/* entry */
		__field(u64, addr)
		__field(u64, len)
		__field(u32, acc)
		__field(u32, lkey)
		__field(u32, rkey)
		__field(u64, iova)
		__field(u32, cnt)
	),
	TP_fast_assign(/* assign */
		__entry->addr = addr;
		__entry->len = len;
		__entry->acc = acc;
		__entry->lkey = lkey;
		__entry->rkey = rkey;
		__entry->iova = iova;
		__entry->cnt = pd_usecnt;
	),
	TP_printk(/* print */
		MR_INFO_PRN,
		__entry->addr,
		__entry->len,
		__entry->acc,
		__entry->lkey,
		__entry->rkey,
		__entry->iova,
		__entry->cnt
	)
);

DEFINE_EVENT(/* event */
	rv_mr_info_template, rv_mr_info_reg,
	TP_PROTO(u64 addr, u64 len, u32 acc, u32 lkey,
		 u32 rkey, u64 iova, u32 pd_usecnt),
	TP_ARGS(addr, len, acc, lkey, rkey, iova, pd_usecnt)
);

DEFINE_EVENT(/* event */
	rv_mr_info_template, rv_mr_info_kern_reg,
	TP_PROTO(u64 addr, u64 len, u32 acc, u32 lkey,
		 u32 rkey, u64 iova, u32 pd_usecnt),
	TP_ARGS(addr, len, acc, lkey, rkey, iova, pd_usecnt)
);

DEFINE_EVENT(/* event */
	rv_mr_info_template, rv_mr_info_dereg,
	TP_PROTO(u64 addr, u64 len, u32 acc, u32 lkey,
		 u32 rkey, u64 iova, u32 pd_usecnt),
	TP_ARGS(addr, len, acc, lkey, rkey, iova, pd_usecnt)
);

#endif /* __RV_TRACE_MR_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_mr
#include <trace/define_trace.h>
