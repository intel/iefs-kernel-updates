/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 - 2021 Intel Corporation.
 */
#if !defined(__RV_TRACE_RDMA_H) || defined(TRACE_HEADER_MULTI_READ)
#define __RV_TRACE_RDMA_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>
#include "rv.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rv_rdma

#define RV_PEND_WRITE_PRN "user_inx %d sconn %pK pend_wr %pK loc_addr 0x%llx" \
			  " rkey 0x%x rem_addr 0x%llx len 0x%llx immed 0x%x" \
			  " wr_id 0x%llx qpn 0x%x"

#define RV_SCONN_RECV_PRN "sconn %pK index %u qp 0x%x conn %pK flags 0x%x " \
			  " state %u immed 0x%x"

#define RV_EVENT_PRN "type 0x%x status 0x%x immed 0x%x wr_id 0x%llx " \
		     "conn_handle 0x%llx len 0x%x"

DECLARE_EVENT_CLASS(/* pend_write */
	rv_pend_write_template,
	TP_PROTO(struct rv_pend_write *pend_wr),
	TP_ARGS(pend_wr),
	TP_STRUCT__entry(/* entry */
		__field(int, user_inx)
		__field(struct rv_sconn *, sconn)
		__field(void *, pend_wr)
		__field(u64, loc_addr)
		__field(u32, rkey)
		__field(u64, rem_addr)
		__field(u64, len)
		__field(u32, immed)
		__field(u32, qpn)
		__field(u64, wr_id)
	),
	TP_fast_assign(/* assign */
		__entry->pend_wr = pend_wr;
		__entry->user_inx = pend_wr->user_index;
		__entry->sconn = pend_wr->sconn;
		__entry->loc_addr = pend_wr->loc_addr;
		__entry->rkey = pend_wr->rkey;
		__entry->rem_addr = pend_wr->rem_addr;
		__entry->len = pend_wr->length;
		__entry->immed = pend_wr->immed;
		__entry->wr_id = pend_wr->wr_id;
		__entry->qpn = __entry->sconn->qp->qp_num;
	),
	TP_printk(/* print */
		RV_PEND_WRITE_PRN,
		__entry->user_inx,
		__entry->sconn,
		__entry->pend_wr,
		__entry->loc_addr,
		__entry->rkey,
		__entry->rem_addr,
		__entry->len,
		__entry->immed,
		__entry->wr_id,
		__entry->qpn
	)
);

DEFINE_EVENT(/* event */
	rv_pend_write_template, rv_pend_write_post,
	TP_PROTO(struct rv_pend_write *pend_wr),
	TP_ARGS(pend_wr)
);

DEFINE_EVENT(/* event */
	rv_pend_write_template, rv_pend_write_done,
	TP_PROTO(struct rv_pend_write *pend_wr),
	TP_ARGS(pend_wr)
);

DECLARE_EVENT_CLASS(/* recv */
	rv_sconn_recv_template,
	TP_PROTO(void *ptr, u8 index, u32 qp_num, void *conn, u32 flags,
		 u32 state, u32 immed),
	TP_ARGS(ptr, index, qp_num, conn, flags, state, immed),
	TP_STRUCT__entry(/* entry */
		__field(void *, ptr)
		__field(u8, index)
		__field(u32, qp_num)
		__field(void *, conn)
		__field(u32, flags)
		__field(u32, state)
		__field(u32, immed)
	),
	TP_fast_assign(/* assign */
		__entry->ptr = ptr;
		__entry->index = index;
		__entry->qp_num = qp_num;
		__entry->conn = conn;
		__entry->flags = flags;
		__entry->state = state;
		__entry->immed = immed;
	),
	TP_printk(/* print */
		 RV_SCONN_RECV_PRN,
		__entry->ptr,
		__entry->index,
		__entry->qp_num,
		__entry->conn,
		__entry->flags,
		__entry->state,
		__entry->immed
	)
);

DEFINE_EVENT(/* event */
	rv_sconn_recv_template, rv_sconn_recv_done,
	TP_PROTO(void *ptr, u8 index, u32 qp_num, void *conn, u32 flags,
		 u32 state, u32 immed),
	TP_ARGS(ptr, index, qp_num, conn, flags, state, immed)
);

DEFINE_EVENT(/* event */
	rv_sconn_recv_template, rv_sconn_recv_post,
	TP_PROTO(void *ptr, u8 index, u32 qp_num, void *conn, u32 flags,
		 u32 state, u32 immed),
	TP_ARGS(ptr, index, qp_num, conn, flags, state, immed)
);

DEFINE_EVENT(/* event */
	rv_sconn_recv_template, rv_sconn_hb_done,
	TP_PROTO(void *ptr, u8 index, u32 qp_num, void *conn, u32 flags,
		 u32 state, u32 immed),
	TP_ARGS(ptr, index, qp_num, conn, flags, state, immed)
);

DEFINE_EVENT(/* event */
	rv_sconn_recv_template, rv_sconn_hb_post,
	TP_PROTO(void *ptr, u8 index, u32 qp_num, void *conn, u32 flags,
		 u32 state, u32 immed),
	TP_ARGS(ptr, index, qp_num, conn, flags, state, immed)
);

DECLARE_EVENT_CLASS(/* event */
	rv_event_template,
	TP_PROTO(u8 type, u8 status, u32 immed, u64 wr_id, u64 conn_handle,
		 u32 len),
	TP_ARGS(type, status, immed, wr_id, conn_handle, len),
	TP_STRUCT__entry(/* entry */
		__field(u8, type)
		__field(u8, status)
		__field(u32, immed)
		__field(u64, wr_id)
		__field(u64, conn_handle)
		__field(u32, len)
	),
	TP_fast_assign(/* assign */
		__entry->type = type;
		__entry->status = status;
		__entry->immed = immed;
		__entry->wr_id = wr_id;
		__entry->conn_handle = conn_handle;
		__entry->len = len;
	),
	TP_printk(/* print */
		RV_EVENT_PRN,
		__entry->type,
		__entry->status,
		__entry->immed,
		__entry->wr_id,
		__entry->conn_handle,
		__entry->len
	)
);

DEFINE_EVENT(/* event */
	rv_event_template, rv_event_write_done,
	TP_PROTO(u8 type, u8 status, u32 immed, u64 wr_id, u64 conn_handle,
		 u32 len),
	TP_ARGS(type, status, immed, wr_id, conn_handle, len)
);

DEFINE_EVENT(/* event */
	rv_event_template, rv_event_post,
	TP_PROTO(u8 type, u8 status, u32 immed, u64 wr_id, u64 conn_handle,
		 u32 len),
	TP_ARGS(type, status, immed, wr_id, conn_handle, len)
);

DEFINE_EVENT(/* event */
	rv_event_template, rv_event_recv_write,
	TP_PROTO(u8 type, u8 status, u32 immed, u64 wr_id, u64 conn_handle,
		 u32 len),
	TP_ARGS(type, status, immed, wr_id, conn_handle, len)
);

DECLARE_EVENT_CLASS(/* wc */
	rv_wc_template,
	TP_PROTO(struct ib_wc *wc),
	TP_ARGS(wc),
	TP_STRUCT__entry(/* entry */
		__field(u64, wr_id)
		__field(enum ib_wc_status, status)
		__field(enum ib_wc_opcode, opcode)
		__field(u32, byte_len)
		__field(u32, imm_data)
		__field(u32, qpn)
	),
	TP_fast_assign(/* assign */
		__entry->wr_id = wc->wr_id;
		__entry->status = wc->status;
		__entry->opcode = wc->opcode;
		__entry->byte_len = wc->byte_len;
		__entry->imm_data = be32_to_cpu(wc->ex.imm_data);
		__entry->qpn = wc->qp->qp_num;
	),
	TP_printk(/* print */
		"wr_id 0x%llx status 0x%x opcode 0x%x byte_len 0x%x immed 0x%x qpn 0x%x",
		__entry->wr_id,
		__entry->status,
		__entry->opcode,
		__entry->byte_len,
		__entry->imm_data,
		__entry->qpn
	)
);

DEFINE_EVENT(/* event */
	rv_wc_template, rv_wc_recv_done,
	TP_PROTO(struct ib_wc *wc),
	TP_ARGS(wc)
);

DEFINE_EVENT(/* event */
	rv_wc_template, rv_wc_write_done,
	TP_PROTO(struct ib_wc *wc),
	TP_ARGS(wc)
);

DEFINE_EVENT(/* event */
	rv_wc_template, rv_wc_hb_done,
	TP_PROTO(struct ib_wc *wc),
	TP_ARGS(wc)
);

DEFINE_EVENT(/* event */
	rv_wc_template, rv_wc_reg_mr_done,
	TP_PROTO(struct ib_wc *wc),
	TP_ARGS(wc)
);

DEFINE_EVENT(/* event */
	rv_wc_template, rv_wc_inv_rkey_done,
	TP_PROTO(struct ib_wc *wc),
	TP_ARGS(wc)
);

DEFINE_EVENT(/* event */
	rv_wc_template, rv_wc_fr_inv_rkey_done,
	TP_PROTO(struct ib_wc *wc),
	TP_ARGS(wc)
);

DEFINE_EVENT(/* event */
	rv_wc_template, rv_wc_fr_inv_rkey_done_unsignaled,
	TP_PROTO(struct ib_wc *wc),
	TP_ARGS(wc)
);

#endif /* __RV_TRACE_RDMA_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_rdma
#include <trace/define_trace.h>
