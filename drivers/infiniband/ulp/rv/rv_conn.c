// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 - 2021 Intel Corporation.
 */

#define DRAIN_TIMEOUT 20 /* in seconds */
#define NO_ERR_TO_ERR /* handle drivers which lack ERR->ERR state transition */
#undef USE_IB_DRAIN /* use ib_drain_qp without timeout handling */

#include <rdma/ib_marshall.h>
#include <linux/nospec.h>

#include "rv.h"
#include "trace.h"

static int rv_resolve_ip(struct rv_sconn *sconn);
static int rv_err_qp(struct ib_qp *qp);
static int rv_create_qp(int rv_inx, struct rv_sconn *sconn,
			struct rv_job_dev *jdev);
static void rv_destroy_qp(struct rv_sconn *sconn);
static int rv_sconn_can_reconn(struct rv_sconn *sconn);
static void rv_sconn_timeout_func(struct timer_list *timer);
static void rv_sconn_timeout_work(struct work_struct *work);
static void rv_sconn_delay_func(struct timer_list *timer);
static void rv_sconn_delay_work(struct work_struct *work);
static void rv_sconn_hb_func(struct timer_list *timer);
static void rv_sconn_hb_work(struct work_struct *work);
static void rv_hb_done(struct ib_cq *cq, struct ib_wc *wc);
static void rv_sconn_enter_disconnecting(struct rv_sconn *sconn,
					 const char *reason,
					 const char *add_reason);
static void rv_sconn_done_disconnecting(struct rv_sconn *sconn);
#ifdef RV_ENABLE_DRAIN_TIMEOUT
static void rv_sconn_drain_timeout_func(struct timer_list *timer);
#endif

static int rv_cm_handler(struct ib_cm_id *id, const struct ib_cm_event *evt);
static void rv_send_req(struct rv_sconn *sconn);
static void rv_qp_event(struct ib_event *event, void *context);
static void rv_cq_event(struct ib_event *event, void *context);

static void rv_sconn_free_primary_path(struct rv_sconn *sconn)
{
	kfree(sconn->primary_path);
	sconn->primary_path = NULL;
}

#ifdef RV_ENABLE_DUP_SQ_CQE_CHECK
void rv_sconn_free_first_done_wr(struct rv_sconn *sconn)
{
	struct rv_pend_write *p;

	p = list_first_entry(&sconn->done_wr_list, struct rv_pend_write,
			     done_wr_entry);
	list_del(&p->done_wr_entry);
	kfree(p);
}

static void rv_sconn_free_done_wr(struct rv_sconn *sconn)
{
	unsigned long flags;

	spin_lock_irqsave(&sconn->drain_lock, flags);
	while (!list_empty(&sconn->done_wr_list))
		rv_sconn_free_first_done_wr(sconn);
	sconn->done_wr_count = 0;
	spin_unlock_irqrestore(&sconn->drain_lock, flags);
}
#endif

/*
 * cleanup a rv_sconn - a careful dance to shutdown all sconn activity
 * rv_conn.kref is already 0, all sconn QP/resolve/CM callbacks
 * will test sconn->parent->kref and return without starting new work
 * also CM listener callback won't accept new REQ for rv_conn
 * after rdma_addr_cancel - no resolver cb in flight nor scheduled
 * after ib_destroy_cm_id - CM will ensure no callbacks active
 * after rv_destroy_qp - QP empty/drained, no more QP events, no more CQEs
 */
static void rv_sconn_deinit(struct rv_sconn *sconn)
{
	trace_rv_sconn_deinit(sconn, sconn->index,
			      sconn->qp ? sconn->qp->qp_num : 0,
			      sconn->parent, sconn->flags, (u32)sconn->state,
			      sconn->cm_id, sconn->resolver_retry_left);

#ifdef RV_ENABLE_DRAIN_TIMEOUT
	del_timer_sync(&sconn->drain_timer);
#endif
	del_timer_sync(&sconn->conn_timer);
	del_timer_sync(&sconn->delay_timer);
	del_timer_sync(&sconn->hb_timer);

	if (sconn->state == RV_RESOLVING)
		rdma_addr_cancel(&sconn->dev_addr);

	if (sconn->cm_id) {
		ib_destroy_cm_id(sconn->cm_id);
		sconn->cm_id = NULL;
	}

#ifdef RV_ENABLE_DUP_SQ_CQE_CHECK
	rv_sconn_free_done_wr(sconn);
#endif
	rv_destroy_qp(sconn);

	rv_sconn_free_primary_path(sconn);
}

#ifdef DRAIN_WQ
/*
 * We flush wq2 to ensure all prior QP drain/destroy workitems items
 * (especially those for sconn's in our conn) are done before
 * we free the conn.  This avoids late RQ CQEs from dereferencing sconn
 * after it has been freed.
 */
static void rv_handle_free_conn(struct work_struct *work)
{
	struct rv_conn *conn = container_of(work, struct rv_conn, free_work);

	trace_rv_conn_release(conn, conn->rem_addr, conn->ah.is_global,
			      conn->ah.dlid,
			      be64_to_cpu(*((__be64 *)&conn->ah.grh.dgid[0])),
			      be64_to_cpu(*((__be64 *)&conn->ah.grh.dgid[8])),
			      conn->num_conn, conn->next,
			      conn->jdev, kref_read(&conn->kref));
	rv_flush_work2();
	kfree_rcu(conn, rcu);
}
#endif

static void rv_conn_release(struct rv_conn *conn)
{
	int i;

	trace_rv_conn_release(conn, conn->rem_addr, conn->ah.is_global,
			      conn->ah.dlid,
			      be64_to_cpu(*((__be64 *)&conn->ah.grh.dgid[0])),
			      be64_to_cpu(*((__be64 *)&conn->ah.grh.dgid[8])),
			      conn->num_conn, conn->next,
			      conn->jdev, kref_read(&conn->kref));

	mutex_lock(&conn->jdev->conn_list_mutex);
	list_del_rcu(&conn->conn_entry);
	mutex_unlock(&conn->jdev->conn_list_mutex);

	for (i = 0; i < conn->num_conn; i++)
		rv_sconn_deinit(&conn->sconn_arr[i]);
	rv_job_dev_put(conn->jdev);
#ifdef DRAIN_WQ
	rv_queue_work3(&conn->free_work);
#else
	kfree_rcu(conn, rcu);
#endif
}

/*
 * Since this function may be called from rv_cm_handler(), we can't call
 * rv_conn_release() directly to destroy the cm_id (and wait on cm handler
 * mutex).
 * Instead, put the cleanup on a workqueue thread.
 */
static void rv_conn_schedule_release(struct kref *kref)
{
	struct rv_conn *conn = container_of(kref, struct rv_conn, kref);

	rv_queue_work(&conn->put_work);
}

void rv_conn_put(struct rv_conn *conn)
{
	kref_put(&conn->kref, rv_conn_schedule_release);
}

/* return 0 if successful get, return -ENXIO if object going away */
int rv_conn_get_check(struct rv_conn *conn)
{
	return kref_get_unless_zero(&conn->kref) ? 0 : -ENXIO;
}

void rv_conn_get(struct rv_conn *conn)
{
	kref_get(&conn->kref);
}

/* we can get away with a quick read of state without the mutex */
static int rv_sconn_connected(struct rv_sconn *sconn)
{
	switch (sconn->state) {
	case RV_CONNECTED:
		return 1;
	case RV_ERROR:
		return -EIO;
	default:
		return test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags);
	}
}

static int rv_conn_connected(struct rv_conn *conn)
{
	int i;
	int ret;

	for (i = 0; i < conn->num_conn; i++) {
		ret = rv_sconn_connected(&conn->sconn_arr[i]);
		if (ret <= 0)
			return ret;
	}
	return 1;
}

/*
 * Returns 1 if gid1 > gid 2
 * Returns 0 if the same
 * Returns -1 if gid1 < gid2
 */
int cmp_gid(const void *gid1, const void *gid2)
{
	u64 *subn1, *subn2, *ifid1, *ifid2;

	subn1 = (u64 *)gid1;
	ifid1 = (u64 *)gid1 + 1;

	subn2 = (u64 *)gid2;
	ifid2 = (u64 *)gid2 + 1;

	if (*subn1 != *subn2) {
		if (*subn1 > *subn2)
			return 1;
		else
			return -1;
	}
	if (*ifid1 > *ifid2)
		return 1;
	else if (*ifid2 > *ifid1)
		return -1;
	else
		return 0;
}

/* in microseconds */
static u64 rv_sconn_time_elapsed(struct rv_sconn *sconn)
{
	return ktime_us_delta(ktime_get(), sconn->start_time);
}

/*
 * LID is 10 characters + \0
 * IPv4 is 15 + \0
 * IPv6 is 39 + \0
 */
#define RV_MAX_ADDR_STR 40

static char *show_gid(char *buf, size_t size, const u8 *gid)
{
	if (ipv6_addr_v4mapped((struct in6_addr *)gid))
		snprintf(buf, size, "%pI4", &gid[12]);
	else
		snprintf(buf, size, "%pI6", gid);
	return buf;
}

static char *show_rem_addr(char *buf, size_t size, struct rv_sconn *sconn)
{
	struct rv_conn *conn = sconn->parent;

	if (!conn->ah.is_global)
		snprintf(buf, size, "LID 0x%x", conn->ah.dlid);
	else
		show_gid(buf, size, conn->ah.grh.dgid);
	return buf;
}

static const char *get_device_name(struct rv_sconn *sconn)
{
	struct ib_device *ib_dev = sconn->parent->jdev->dev->ib_dev;

	if (ib_dev)
		return ib_dev->name;
	else
		return "unknown";
}

/*
 * Move to the new state and handle basic transition activities
 *
 * rv_sconn.mutex must be held
 * reason - used in log messages for transitions out of RV_CONNECTED
 *	or to RV_ERROR
 */
static void rv_sconn_set_state(struct rv_sconn *sconn, enum rv_sconn_state new,
			       const char *reason, const char *add_reason,
			       bool quiet)
{
	enum rv_sconn_state old = sconn->state;
	char buf[RV_MAX_ADDR_STR];

	/* some log messages for major transitions */
	if (old == RV_CONNECTED && new != RV_CONNECTED && !quiet)
		rv_conn_err(sconn,
			    "Conn Lost to %s via %s: sconn inx %u qp %u: %s%s\n",
			    show_rem_addr(buf, sizeof(buf), sconn),
			    get_device_name(sconn), sconn->index,
			    sconn->qp ? sconn->qp->qp_num : 0,
			    reason, add_reason);
	if (old != RV_CONNECTED && new == RV_CONNECTED &&
	    test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags) && !quiet)
		rv_conn_err(sconn,
			    "Reconnected to %s via %s: sconn index %u qp %u\n",
			    show_rem_addr(buf, sizeof(buf), sconn),
			    get_device_name(sconn), sconn->index,
			    sconn->qp ? sconn->qp->qp_num : 0);
	else if (old != RV_ERROR && new == RV_ERROR && !quiet) {
		if (test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags))
			rv_conn_err(sconn,
				    "Unable to Reconn to %s via %s: sconn %u qp %u: %s%s\n",
				    show_rem_addr(buf, sizeof(buf), sconn),
				    get_device_name(sconn), sconn->index,
				    sconn->qp ? sconn->qp->qp_num : 0,
				    reason, add_reason);
		else
			rv_conn_err(sconn,
				    "Unable to Connect to %s via %s: sconn %u qp %u: %s%s\n",
				    show_rem_addr(buf, sizeof(buf), sconn),
				    get_device_name(sconn), sconn->index,
				    sconn->qp ? sconn->qp->qp_num : 0,
				    reason, add_reason);
	}

	/*
	 * process exit from old state
	 * elapsed time measured for success or failure
	 */
	if (old == RV_WAITING && new != RV_WAITING) {
		if (test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags)) {
			u64 elapsed = rv_sconn_time_elapsed(sconn);

			sconn->stats.rewait_time += elapsed;
			if (elapsed > sconn->stats.max_rewait_time)
				sconn->stats.max_rewait_time = elapsed;
		} else {
			sconn->stats.wait_time = rv_sconn_time_elapsed(sconn);
		}
	} else if (old == RV_RESOLVING && new != RV_RESOLVING) {
		if (test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags)) {
			u64 elapsed = rv_sconn_time_elapsed(sconn);

			sconn->stats.reresolve_time += elapsed;
			if (elapsed > sconn->stats.max_reresolve_time)
				sconn->stats.max_reresolve_time = elapsed;
		} else {
			sconn->stats.resolve_time =
				rv_sconn_time_elapsed(sconn);
		}
	} else if (old == RV_CONNECTING && new != RV_CONNECTING) {
		if (test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags)) {
			u64 elapsed = rv_sconn_time_elapsed(sconn);

			sconn->stats.reconnect_time += elapsed;
			if (elapsed > sconn->stats.max_reconnect_time)
				sconn->stats.max_reconnect_time = elapsed;
		} else {
			sconn->stats.connect_time =
				rv_sconn_time_elapsed(sconn);
		}
	} else if (old == RV_CONNECTED && new != RV_CONNECTED) {
		del_timer_sync(&sconn->hb_timer);
		sconn->stats.connected_time += rv_sconn_time_elapsed(sconn);
		if (new != RV_ERROR) {
			/* reconnect starts on 1st exit from CONNECTED */
			sconn->conn_timer.expires = jiffies +
				       sconn->parent->jdev->reconnect_timeout *
				       HZ;
			add_timer(&sconn->conn_timer);
		}
#ifdef RV_ENABLE_DRAIN_TIMEOUT
	} else if (old == RV_DISCONNECTING && new != RV_DISCONNECTING) {
		del_timer_sync(&sconn->drain_timer);
#endif
	}

	/* process entry to new state */
	if (old != RV_WAITING && new == RV_WAITING) {
		sconn->start_time = ktime_get();
	} else if (old != RV_RESOLVING && new == RV_RESOLVING) {
		sconn->start_time = ktime_get();
	} else if (old != RV_CONNECTING && new == RV_CONNECTING) {
		sconn->start_time = ktime_get();
	} else if (old != RV_CONNECTED && new == RV_CONNECTED) {
		if (test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags))
			sconn->stats.conn_recovery++;
		sconn->start_time = ktime_get();
		set_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags);
		del_timer_sync(&sconn->conn_timer);
	} else if (old != RV_DELAY && new == RV_DELAY) {
		sconn->delay_timer.expires = jiffies + RV_RECONNECT_DELAY;
		add_timer(&sconn->delay_timer);
	} else if (old != RV_ERROR && new == RV_ERROR) {
		del_timer_sync(&sconn->hb_timer);
		del_timer_sync(&sconn->conn_timer);
		del_timer_sync(&sconn->delay_timer);
		if (sconn->qp) {
			/* this will trigger the QP to self drain */
			rv_err_qp(sconn->qp);
			set_bit(RV_SCONN_DRAINING, &sconn->flags);
		}
	}

	sconn->state = new;
	trace_rv_sconn_set_state(sconn, sconn->index,
				 sconn->qp ? sconn->qp->qp_num : 0,
				 sconn->parent, sconn->flags,
				 (u32)sconn->state, sconn->cm_id,
				 sconn->resolver_retry_left);
}

static int rv_sconn_move_qp_to_rtr(struct rv_sconn *sconn, u32 *psn)
{
	struct ib_qp_attr qp_attr;
	int attr_mask = 0;
	int ret;

	/* move QP to INIT */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_INIT;
	ret = ib_cm_init_qp_attr(sconn->cm_id, &qp_attr, &attr_mask);
	if (ret) {
		rv_conn_err(sconn, "Failed to init qp_attr for INIT: %d\n",
			    ret);
		return ret;
	}
	trace_rv_msg_qp_rtr(sconn, sconn->index, "pkey_index + sconn",
			    (u64)qp_attr.pkey_index, (u64)sconn);
	ret = ib_modify_qp(sconn->qp, &qp_attr, attr_mask);
	if (ret) {
		rv_conn_err(sconn, "Failed to move qp %u into INIT: %d\n",
			    sconn->qp ? sconn->qp->qp_num : 0,  ret);
		return ret;
	}

	/* move QP to RTR */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_RTR;
	ret = ib_cm_init_qp_attr(sconn->cm_id, &qp_attr, &attr_mask);
	if (ret) {
		rv_conn_err(sconn, "Failed to init qp_attr for RTR: %d\n", ret);
		return ret;
	}
	if (psn) {
		*psn = get_random_u32() & 0xffffff;
		qp_attr.rq_psn = *psn;
	}
	trace_rv_msg_qp_rtr(sconn, sconn->index, "dlid | dqp_num, mtu | rq_psn",
			    (u64)(qp_attr.ah_attr.ib.dlid |
				  ((u64)qp_attr.dest_qp_num) << 32),
			    (u64)(qp_attr.path_mtu |
				  ((u64)qp_attr.rq_psn) << 32));
	ret = ib_modify_qp(sconn->qp, &qp_attr, attr_mask);
	if (ret) {
		rv_conn_err(sconn, "Failed to move qp %u into RTR: %d\n",
			    sconn->qp ? sconn->qp->qp_num : 0,  ret);
		return ret;
	}

	/* post recv WQEs */
	ret = rv_drv_prepost_recv(sconn);
	if (ret)
		rv_conn_err(sconn, "Failed to prepost qp %u recv WQEs: %d\n",
			    sconn->qp ? sconn->qp->qp_num : 0,  ret);

	return ret;
}

static int rv_sconn_move_qp_to_rts(struct rv_sconn *sconn)
{
	struct ib_qp_attr qp_attr;
	int attr_mask;
	int ret;

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_RTS;
	ret = ib_cm_init_qp_attr(sconn->cm_id, &qp_attr, &attr_mask);
	if (ret) {
		rv_conn_err(sconn, "Failed to init qp_attr for RTS: %d\n", ret);
		return ret;
	}
	ret = ib_modify_qp(sconn->qp, &qp_attr, attr_mask);
	if (ret) {
		rv_conn_err(sconn, "Failed to move qp %u into RTS: %d\n",
			    sconn->qp ? sconn->qp->qp_num : 0,  ret);
		return ret;
	}
	return ret;
}

/*
 * validate REP basics
 * - private_data format and version
 *	rev must always be an exact version we support
 *	reject rev 0 & 1, only support rev 2
 * - SRQ
 */
static int rv_check_rep_basics(struct rv_sconn *sconn,
			       const struct ib_cm_rep_event_param *param,
			       struct rv_rep_priv_data *rep_priv)
{
	if (rep_priv->magic != RV_PRIVATE_DATA_MAGIC) {
		rv_conn_err(sconn,
			    "Inval CM REP recv: magic 0x%llx expected 0x%llx\n",
			    rep_priv->magic, RV_PRIVATE_DATA_MAGIC);
		return -EINVAL;
	}
	if (rep_priv->ver != RV_PRIVATE_DATA_VER) {
		rv_conn_err(sconn,
			    "Invalid CM REP recv: rv version %d expected %d\n",
			    rep_priv->ver, RV_PRIVATE_DATA_VER);
		return -EINVAL;
	}
	if (param->srq) {
		rv_conn_err(sconn, "Invalid srq %d\n", param->srq);
		return -EINVAL;
	}

	return 0;
}

/*
 * Client side inbound CM REP handler
 * caller must hold a rv_conn reference and the sconn->mutex
 * This func does not release that ref
 */
static void rv_cm_rep_handler(struct rv_sconn *sconn,
			      const struct ib_cm_rep_event_param *param,
			      const void *priv)
{
	int ret;
	struct rv_job_dev *jdev = sconn->parent->jdev;
	struct rv_rep_priv_data *rep_priv = (struct rv_rep_priv_data *)priv;
	const char *reason;
	struct rv_rej_priv_data rej_priv = {
		.magic = RV_PRIVATE_DATA_MAGIC,
		.ver = RV_PRIVATE_DATA_VER,
		.reason = RV_REJ_REASON_LOCAL_ERR,
		.recoverable = 0,
	};

	if (rv_check_rep_basics(sconn, param, rep_priv)) {
		reason = "invalid REP";
		rej_priv.reason = RV_REJ_REASON_INVALID_REP;
		goto rej;
	}

	if (sconn->state != RV_CONNECTING) {
		reason = "unexpected REP";
		rej_priv.reason = RV_REJ_REASON_ERROR;
		goto rej;
	}

	if (rv_sconn_move_qp_to_rtr(sconn, NULL))
		goto err;

	if (rv_sconn_move_qp_to_rts(sconn))
		goto err;

	ret = ib_send_cm_rtu(sconn->cm_id, NULL, 0);
	if (ret) {
		rv_conn_err(sconn, "Failed to send cm RTU: %d\n", ret);
		goto err;
	}
	sconn->stats.rtu_sent++;
	trace_rv_msg_cm_rep_handler(sconn, sconn->index, "Sending RTU", 0,
				    (u64)sconn);
	if (jdev->hb_interval) {
		sconn->hb_timer.expires = jiffies +
					  msecs_to_jiffies(jdev->hb_interval);
		add_timer(&sconn->hb_timer);
	}
	rv_sconn_set_state(sconn, RV_CONNECTED, "", "", false);
	return;

err:
	/* do not try to retry/recover for fundamental QP errors */
	if (!ib_send_cm_rej(sconn->cm_id, IB_CM_REJ_INSUFFICIENT_RESP_RESOURCES,
			    NULL, 0, &rej_priv, sizeof(rej_priv))) {
		u64 val = (u64)IB_CM_REJ_INSUFFICIENT_RESP_RESOURCES;

		sconn->stats.rej_sent++;
		trace_rv_msg_cm_rep_handler(sconn, sconn->index,
					    "Sending REJ reason",
					    val, (u64)sconn);
	}
	rv_sconn_set_state(sconn, RV_ERROR, "local error handling REP", "",
			   false);
	return;

rej:
	if (!ib_send_cm_rej(sconn->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
			    NULL, 0, &rej_priv, sizeof(rej_priv))) {
		sconn->stats.rej_sent++;
		trace_rv_msg_cm_rep_handler(sconn, sconn->index,
					    "Sending REJ reason",
					(u64)IB_CM_REJ_CONSUMER_DEFINED,
					(u64)sconn);
	}
	rv_sconn_set_state(sconn, RV_ERROR, reason, "", false);
}

/*
 * validate REQ basics
 * - private_data format and version
 *	reject rev 0 & 1
 *	accept >=2, assume future versions will be forward compatible
 * - QP type and APM
 */
static int rv_check_req_basics(struct ib_cm_id *id,
			       const struct ib_cm_req_event_param *param,
			       struct rv_req_priv_data *req_priv)
{
	if (req_priv->magic != RV_PRIVATE_DATA_MAGIC) {
		rv_cm_err(id,
			  "Inval CM REQ recv: magic 0x%llx expected 0x%llx\n",
			  req_priv->magic, RV_PRIVATE_DATA_MAGIC);
		return -EINVAL;
	}
	if (req_priv->ver < RV_PRIVATE_DATA_VER) {
		rv_cm_err(id,
			  "Invalid CM REQ recv: rv version %d expected %d\n",
			  req_priv->ver, RV_PRIVATE_DATA_VER);
		return -EINVAL;
	}

	if (param->qp_type != IB_QPT_RC || param->srq) {
		rv_cm_err(id,
			  "Invalid qp_type 0x%x or srq %d\n",
			  param->qp_type, param->srq);
		return -EINVAL;
	}

	if (param->alternate_path) {
		rv_cm_err(id,
			  "Invalid CM REQ recv: alt path not allowed\n");
		return -EINVAL;
	}

	return 0;
}

/* validate REQ primary_path against sconn->conn->ah from create_conn */
static int rv_sconn_req_check_ah(const struct rv_sconn *sconn,
				 const struct sa_path_rec *path)
{
	struct rv_conn *conn = sconn->parent;
	int ret = -EINVAL;

#define RV_CHECK(f1, f2) (path->f1 != conn->ah.f2)
#define RV_CHECK_BE32(f1, f2) (be32_to_cpu(path->f1) != conn->ah.f2)
#define RV_REPORT(f1, f2, text, format) \
		rv_conn_err(sconn, "CM REQ inconsistent " text " " format \
			    " with create_conn " format "\n", \
			    path->f1, conn->ah.f2)

	if (RV_CHECK(sl, sl))
		RV_REPORT(sl, sl, "SL", "%u");
	else if (conn->ah.is_global &&
		 RV_CHECK(traffic_class, grh.traffic_class))
		RV_REPORT(traffic_class, grh.traffic_class, "traffic_class",
			  "%u");
	else if (conn->ah.is_global &&
		 RV_CHECK_BE32(flow_label, grh.flow_label))
		RV_REPORT(flow_label, grh.flow_label, "flow_label", "0x%x");
		/* for RoCE hop_limit overridden by resolver */
	else if (conn->ah.is_global && !rv_jdev_protocol_roce(conn->jdev) &&
		 RV_CHECK(hop_limit, grh.hop_limit))
		RV_REPORT(hop_limit, grh.hop_limit, "hop_limit", "%u");
	else if (RV_CHECK(rate, static_rate))
		RV_REPORT(rate, static_rate, "rate", "%u");
#undef RV_CHECK
#undef RV_CHECK_BE32
#undef RV_REPORT
	else
		ret = 0;
	return ret;
}

/* validate REQ primary_path against sconn->path from cm_connect */
static int rv_sconn_req_check_path(const struct rv_sconn *sconn,
				   const struct sa_path_rec *path)
{
	int ret = -EINVAL;

#define RV_CHECK(field) (path->field != sconn->path.field)
#define RV_REPORT(field, text, format) \
		     rv_conn_err(sconn, "CM REQ inconsistent " text " " format \
				 " with connect " format "\n", \
				 path->field, sconn->path.field)
	if (RV_CHECK(pkey))
		RV_REPORT(pkey, "pkey", "0x%x");
	else if (RV_CHECK(mtu))
		RV_REPORT(mtu, "mtu", "%u");
	else if (RV_CHECK(sl))
		RV_REPORT(sl, "SL", "%u");
	else if (RV_CHECK(traffic_class))
		RV_REPORT(traffic_class, "traffic_class", "%u");
	else if (RV_CHECK(flow_label))
		RV_REPORT(flow_label, "flow_label", "0x%x");
	else if (RV_CHECK(rate))
		RV_REPORT(rate, "rate", "%u");
		/* for RoCE hop_limit overridden by resolver */
	else if (!rv_jdev_protocol_roce(sconn->parent->jdev) &&
		 RV_CHECK(hop_limit))
		RV_REPORT(hop_limit, "hop_limit", "%u");
	else if (path->packet_life_time < sconn->path.packet_life_time)
		RV_REPORT(packet_life_time, "packet_life_time", "%u");
#undef RV_CHECK
#undef RV_REPORT
	else
		ret = 0;
	return ret;
}

/*
 * caller must hold a rv_conn reference and sconn->mutex.
 * This func does not release the ref nor mutex
 * The private data version must be <= version in REQ and reflect a
 * version both client and listener support.
 * We currently only support version 2.
 */
static void rv_send_rep(struct rv_sconn *sconn,
			const struct ib_cm_req_event_param *param, u32 psn)
{
	struct ib_cm_rep_param rep;
	struct rv_rep_priv_data rep_priv = {
			.magic = RV_PRIVATE_DATA_MAGIC,
			.ver = RV_PRIVATE_DATA_VER,
		};
	int ret;
	struct rv_rej_priv_data rej_priv = {
		.magic = RV_PRIVATE_DATA_MAGIC,
		.ver = RV_PRIVATE_DATA_VER,
		.reason = RV_REJ_REASON_LOCAL_ERR,
		.recoverable = 0,
	};

	memset(&rep, 0, sizeof(rep));
	rep.qp_num = sconn->qp->qp_num;
	rep.rnr_retry_count = min_t(unsigned int, 7, param->rnr_retry_count);
	rep.flow_control = 1;
	rep.failover_accepted = 0;
	rep.srq = !!(sconn->qp->srq);
	rep.responder_resources = 0;
	rep.initiator_depth = 0;
	rep.starting_psn = psn;

	rep.private_data = &rep_priv;
	rep.private_data_len = sizeof(rep_priv);

	ret = ib_send_cm_rep(sconn->cm_id, &rep);
	if (ret) {
		rv_conn_err(sconn, "Failed to send CM REP: %d\n", ret);
		goto err;
	}
	sconn->stats.rep_sent++;
	trace_rv_msg_cm_req_handler(sconn, sconn->index, "Sending REP", 0,
				    (u64)sconn);
	rv_sconn_set_state(sconn, RV_CONNECTING, "", "", false);
	return;

err:
	if (!ib_send_cm_rej(sconn->cm_id, IB_CM_REJ_INSUFFICIENT_RESP_RESOURCES,
			    NULL, 0, &rej_priv, sizeof(rej_priv))) {
		u64 val =  (u64)IB_CM_REJ_INSUFFICIENT_RESP_RESOURCES;

		sconn->stats.rej_sent++;
		trace_rv_msg_cm_req_handler(sconn, sconn->index,
					    "Sending REJ reason",
					    val, (u64)sconn);
	}
	rv_sconn_set_state(sconn, RV_ERROR, "local error sending REP", "",
			   false);
}

/*
 * Server side inbound CM REQ handler
 * special cases:
 *	if RV_CONNECTING - RTU got lost and remote trying again alraedy
 *	if RV_CONNECTED - remote figured out connection is down 1st
 * return:
 *	0 - sconn has taken ownership of the cm_id
 *	<0 - CM should destroy the id
 * rv_find_sconn_from_req validates REQ against jdev:
 *	job key, local port, local device, sconn index,
 *	remote address (dgid or dlid), hb_interval
 * For valid REQs, we establish a new IB CM handler for subsequent CM events
 */
static int rv_cm_req_handler(struct ib_cm_id *id,
			     const struct ib_cm_req_event_param *param,
			     void *priv)
{
	struct rv_req_priv_data *req_priv = (struct rv_req_priv_data *)priv;
	struct rv_sconn *sconn = NULL;
	u32 psn;
	struct rv_rej_priv_data rej_priv = {
		.magic = RV_PRIVATE_DATA_MAGIC,
		.ver = RV_PRIVATE_DATA_VER,
		.reason = RV_REJ_REASON_LOCAL_ERR,
		.recoverable = 0,
	};

	if (rv_check_req_basics(id, param, req_priv)) {
		rej_priv.reason = RV_REJ_REASON_INVALID_REQ;
		goto rej;
	}

	sconn = rv_find_sconn_from_req(id, param, req_priv);
	if (!sconn) {
		rej_priv.reason = RV_REJ_REASON_NOT_FOUND;
		rv_cm_err(id, "Could not find conn for the request\n");
		goto rej;
	}

	mutex_lock(&sconn->mutex);

	sconn->stats.cm_evt_cnt[IB_CM_REQ_RECEIVED]++;
	trace_rv_sconn_req_handler(sconn, sconn->index,
				   sconn->qp ? sconn->qp->qp_num : 0,
				   sconn->parent, sconn->flags,
				   (u32)sconn->state, id,
				   sconn->resolver_retry_left);

	if (rv_sconn_req_check_ah(sconn, param->primary_path)) {
		rej_priv.reason = RV_REJ_REASON_MISMATCH;
		goto rej;
	}
	if (sconn->path.dlid &&
	    rv_sconn_req_check_path(sconn, param->primary_path)) {
		rej_priv.reason = RV_REJ_REASON_MISMATCH;
		goto rej;
	}

	switch (sconn->state) {
	case RV_WAITING:
		break;
	case RV_ERROR:
		rej_priv.reason = RV_REJ_REASON_ERROR;
		goto rej;
	case RV_CONNECTING:
	case RV_CONNECTED:
		if (rv_sconn_can_reconn(sconn)) {
			rej_priv.recoverable = 1;
			rej_priv.reason = RV_REJ_REASON_CONNECTING;
			rv_sconn_enter_disconnecting(sconn,
						     "remote reconnecting", "");
		}
		goto rej;
	case RV_DISCONNECTING:
		rej_priv.recoverable = 1;
		rej_priv.reason = RV_REJ_REASON_DISCONNECTING;
		goto rej;
	default:
		rej_priv.reason = RV_REJ_REASON_NOT_LISTENER;
		goto rej;
	}
	if (!sconn->qp)
		goto rej;

	sconn->cm_id = id;
	id->context = sconn;

	id->cm_handler = rv_cm_handler;
	if (rv_sconn_move_qp_to_rtr(sconn, &psn))
		goto err;

	rv_send_rep(sconn, param, psn);
	mutex_unlock(&sconn->mutex);
	rv_conn_put(sconn->parent);
	return 0;

err:
	if (!ib_send_cm_rej(id, IB_CM_REJ_INSUFFICIENT_RESP_RESOURCES, NULL, 0,
			    &rej_priv, sizeof(rej_priv))) {
		u64 val =  (u64)IB_CM_REJ_INSUFFICIENT_RESP_RESOURCES;

		sconn->stats.rej_sent++;
		trace_rv_msg_cm_req_handler(sconn, sconn->index,
					    "Sending REJ reason",
					    val, (u64)sconn);
	}
	rv_sconn_set_state(sconn, RV_ERROR, "local error handling REQ", "",
			   false);
	mutex_unlock(&sconn->mutex);
	rv_conn_put(sconn->parent);
	return 0;

rej:
	if (!ib_send_cm_rej(id, IB_CM_REJ_CONSUMER_DEFINED, NULL, 0,
			    &rej_priv, sizeof(rej_priv))) {
		if (sconn)
			sconn->stats.rej_sent++;
		trace_rv_msg_cm_req_handler(sconn, sconn ? sconn->index : 0,
					    "Sending REJ reason",
					    (u64)IB_CM_REJ_CONSUMER_DEFINED,
					    (u64)sconn);
	}
	if (sconn) {
		mutex_unlock(&sconn->mutex);
		rv_conn_put(sconn->parent);
	}
	return -EINVAL;
}

/* must hold sconn->mutex */
static int rv_sconn_can_reconn(struct rv_sconn *sconn)
{
	return test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags) &&
	       sconn->parent->jdev->reconnect_timeout &&
	       rv_job_dev_has_users(sconn->parent->jdev);
}

/*
 * Post a WR, rv_drain_done will handle when SQ is empty
 * caller must hold a reference and QP must be in QPS_ERR
 * an additional reference is established on behalf of the WR's CQ callback
 */
static int rv_start_drain_sq(struct rv_sconn *sconn)
{
	struct ib_rdma_wr swr = {
		.wr = {
			.wr_cqe	= &sconn->sdrain_cqe,
			.opcode	= IB_WR_RDMA_WRITE,
		},
	};
	int ret;

	rv_conn_get(sconn->parent);
	ret = ib_post_send(sconn->qp, &swr.wr, NULL);
	if (ret) {
		rv_conn_err(sconn, "failed to drain send queue: post %d\n",
			    ret);
		rv_conn_put(sconn->parent);
	}
	return ret;
}

/*
 * Post a WR, rv_drain_done will handle when RQ is empty
 * caller must hold a reference and QP must be in QPS_ERR
 * an additional reference is established on behalf of the WR's CQ callback
 */
static int rv_start_drain_rq(struct rv_sconn *sconn)
{
	struct ib_recv_wr rwr = {
		.wr_cqe	= &sconn->rdrain_cqe,
	};
	int ret;

	rv_conn_get(sconn->parent);
	ret = ib_post_recv(sconn->qp, &rwr, NULL);
	if (ret) {
		rv_conn_err(sconn, "failed to drain recv queue: post %d\n",
			    ret);
		rv_conn_put(sconn->parent);
	}
	return ret;
}

/* in soft IRQ context, a reference held on our behalf */
static void rv_rq_drain_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct rv_sconn *sconn = container_of(wc->wr_cqe,
					      struct rv_sconn, rdrain_cqe);

	/*
	 * We test RV_SCONN_DRAINING bit here only because it is possible
	 * that this drain completion handler could come after the drain_timer
	 * has expired. In that case, the drain timer handler and/or the
	 * drain_work could have cleared this bit, and released the rv_conn
	 * object. It should be reminded that other race conditions are still
	 * possible.
	 */
	if (test_bit(RV_SCONN_DRAINING, &sconn->flags)) {
		set_bit(RV_SCONN_RQ_DRAINED, &sconn->flags);
		trace_rv_sconn_rq_drain_done(sconn, sconn->index,
					     sconn->qp ? sconn->qp->qp_num : 0,
					     sconn->parent, sconn->flags,
					     (u32)sconn->state, sconn->cm_id,
					     sconn->resolver_retry_left);
		if (test_bit(RV_SCONN_SQ_DRAINED, &sconn->flags)) {
#ifdef RV_ENABLE_DRAIN_TIMEOUT
			del_timer_sync(&sconn->drain_timer);
#endif
			rv_queue_work(&sconn->drain_work);
			return;
		}
		rv_conn_put(sconn->parent);
	}
}

/* in soft IRQ context, a reference held on our behalf */
static void rv_sq_drain_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct rv_sconn *sconn = container_of(wc->wr_cqe,
					      struct rv_sconn, sdrain_cqe);

	/*
	 * We test RV_SCONN_DRAINING bit here only because it is possible
	 * that this drain completion handler could come after the drain_timer
	 * has expired. In that case, the drain timer handler and/or the
	 * drain_work could have cleared this bit, and released the rv_conn
	 * object. It should be reminded that other race conditions are still
	 * possible.
	 */
	if (test_bit(RV_SCONN_DRAINING, &sconn->flags)) {
		set_bit(RV_SCONN_SQ_DRAINED, &sconn->flags);
		trace_rv_sconn_sq_drain_done(sconn, sconn->index,
					     sconn->qp ? sconn->qp->qp_num : 0,
					     sconn->parent, sconn->flags,
					     (u32)sconn->state, sconn->cm_id,
					     sconn->resolver_retry_left);
		if (test_bit(RV_SCONN_RQ_DRAINED, &sconn->flags)) {
#ifdef RV_ENABLE_DRAIN_TIMEOUT
			del_timer_sync(&sconn->drain_timer);
#endif
			rv_queue_work(&sconn->drain_work);
			return;
		}
		rv_conn_put(sconn->parent);
	}
}

#ifdef RV_ENABLE_DRAIN_TIMEOUT
/*
 * timeout exhausted on a drain CQE callback
 * a rv_conn reference is held by the outstanding RQ and SQ drains
 * we assume we have waited long enough that CQE callback is not coming
 * and will not race with this func
 */
static void rv_sconn_drain_timeout_func(struct timer_list *timer)
{
	struct rv_sconn *sconn = container_of(timer, struct rv_sconn,
					      drain_timer);

	if (!sconn->parent)
		return;
	if (!test_bit(RV_SCONN_SQ_DRAINED, &sconn->flags) &&
	    !test_bit(RV_SCONN_RQ_DRAINED, &sconn->flags))
		rv_conn_put(sconn->parent);

	if (!test_bit(RV_SCONN_RQ_DRAINED, &sconn->flags)) {
		set_bit(RV_SCONN_RQ_DRAINED, &sconn->flags);
		rv_conn_dbg(sconn,
			    "drain recv queue sconn index %u qp %u conn %p\n",
			    sconn->index, sconn->qp ? sconn->qp->qp_num : 0,
			    sconn->parent);
	}
	if (!test_bit(RV_SCONN_SQ_DRAINED, &sconn->flags)) {
		set_bit(RV_SCONN_SQ_DRAINED, &sconn->flags);
		rv_conn_dbg(sconn,
			    "drain send queue sconn index %u qp %u conn %p\n",
			    sconn->index, sconn->qp ? sconn->qp->qp_num : 0,
			    sconn->parent);
	}
	rv_queue_work(&sconn->drain_work);
}
#endif

/*
 * must hold sconn->mutex and have a reference
 * If QP is in QPS_RESET, nothing to do
 * drain_lock makes sure no recv WQEs get reposted after our drain WQE
 */
static void rv_sconn_enter_disconnecting(struct rv_sconn *sconn,
					 const char *reason,
					 const char *add_reason)
{
	unsigned long flags;
	int ret;

	rv_sconn_set_state(sconn, RV_DISCONNECTING, reason, add_reason, false);

	ret = rv_err_qp(sconn->qp);
	if (ret == 1) {
		rv_sconn_done_disconnecting(sconn);
		return;
	} else if (ret) {
		goto fail;
	}

	spin_lock_irqsave(&sconn->drain_lock, flags);
	set_bit(RV_SCONN_DRAINING, &sconn->flags);
#ifdef RV_ENABLE_DRAIN_TIMEOUT
	sconn->drain_timer.expires = jiffies + DRAIN_TIMEOUT * HZ;
	add_timer(&sconn->drain_timer);
#endif

	ret = rv_start_drain_rq(sconn);
	ret |= rv_start_drain_sq(sconn);
	spin_unlock_irqrestore(&sconn->drain_lock, flags);
	if (!ret)
		return;
fail:
	trace_rv_msg_enter_disconnect(sconn, sconn->index,
				      "Unable to move QP to error", 0, 0);
	rv_sconn_set_state(sconn, RV_ERROR, "unable to drain QP", "", false);
}

struct rv_dest_cm_work_item {
	struct work_struct destroy_work;
	struct rv_sconn *sconn;
	struct ib_cm_id *cm_id;
	struct ib_qp *qp;
};

/*
 * destroy the CM_ID and the QP
 * Once ib_destroy_cm_id returns, all CM callbacks are done
 * Any WQEs/CQEs in flight must be drained before this handler is scheduled
 */
static void rv_handle_destroy_qp_cm(struct work_struct *work)
{
	struct rv_dest_cm_work_item *item = container_of(work,
				struct rv_dest_cm_work_item, destroy_work);

	ib_destroy_cm_id(item->cm_id);

	ib_destroy_qp(item->qp);

	rv_conn_put(item->sconn->parent);
	kfree(item);
}

/*
 * must hold sconn->mutex
 * QP is now drained and no longer posting recv nor sends
 * We start fresh with a new QP and cm_id.  This lets CM do its own
 * timewait handling and avoids any stale packets arriving on our new QP.
 * To conform to lock heirarchy, schedule actual destroy in WQ
 * since can't destroy cm_id while holding sconn->mutex nor in CM callback.
 */
static void rv_sconn_done_disconnecting(struct rv_sconn *sconn)
{
	struct rv_dest_cm_work_item *item;
	struct rv_job_dev *jdev = sconn->parent->jdev;
	int ret;
	struct ib_cm_id *id;

	trace_rv_sconn_done_discon(sconn, sconn->index,
				   sconn->qp ? sconn->qp->qp_num : 0,
				   sconn->parent, sconn->flags,
				   (u32)sconn->state, sconn->cm_id,
				   sconn->resolver_retry_left);

#ifdef RV_ENABLE_DUP_SQ_CQE_CHECK
	rv_sconn_free_done_wr(sconn);
#endif

	item = kzalloc(sizeof(*item), GFP_KERNEL);
	if (!item)
		goto fail;
	rv_conn_get(sconn->parent);
	INIT_WORK(&item->destroy_work, rv_handle_destroy_qp_cm);
	item->sconn = sconn;
	item->cm_id = sconn->cm_id;
	sconn->cm_id = NULL;
	item->qp = sconn->qp;
	sconn->qp = NULL;
	rv_queue_work(&item->destroy_work);

	clear_bit(RV_SCONN_DRAINING, &sconn->flags);
	clear_bit(RV_SCONN_RQ_DRAINED, &sconn->flags);
	clear_bit(RV_SCONN_SQ_DRAINED, &sconn->flags);

	ret = rv_create_qp(RV_INVALID, sconn, jdev);
	if (ret) {
		rv_conn_err(sconn, "Failed to re-create qp: %d\n", ret);
		goto fail;
	}

	if (test_bit(RV_SCONN_SERVER, &sconn->flags)) {
		rv_sconn_set_state(sconn, RV_WAITING, "", "", false);
		return;
	}

	id = ib_create_cm_id(jdev->dev->ib_dev, rv_cm_handler, sconn);
	if (IS_ERR(id)) {
		rv_conn_err(sconn, "Create CM ID failed\n");
		goto fail;
	}
	sconn->cm_id = id;
	rv_sconn_set_state(sconn, RV_DELAY, "", "", false);
	return;

fail:
	rv_sconn_set_state(sconn, RV_ERROR, "local error disconnecting", "",
			   false);
}

/* only allowed in RV_DISCONNECTING or RV_ERROR */
static void rv_sconn_drain_work(struct work_struct *work)
{
	struct rv_sconn *sconn = container_of(work, struct rv_sconn,
					      drain_work);

	mutex_lock(&sconn->mutex);
	if (sconn->state == RV_DISCONNECTING)
		rv_sconn_done_disconnecting(sconn);
	else
		WARN_ON(sconn->state != RV_ERROR);
	mutex_unlock(&sconn->mutex);

	rv_conn_put(sconn->parent);
}

static const char * const rv_rej_reason_strs[] = {
	[RV_REJ_REASON_NONE]		= "",
	[RV_REJ_REASON_INVALID_REQ]	= " Invalid RV REQ",
	[RV_REJ_REASON_INVALID_REP]	= " Invalid RV REP",
	[RV_REJ_REASON_NOT_FOUND]	= " No Matching Conn",
	[RV_REJ_REASON_MISMATCH]	= " Mismatched Params or Path",
	[RV_REJ_REASON_LOCAL_ERR]	= " Remote Node Error",
	[RV_REJ_REASON_ERROR]		= " Conn already In Error",
	[RV_REJ_REASON_CONNECTING]	= " Preparing to Reconnect",
	[RV_REJ_REASON_DISCONNECTING]	= " Disconnecting",
	[RV_REJ_REASON_NOT_LISTENER]	= " Not Listener",
	[RV_REJ_REASON_CONN_TIMEOUT]	= " Conn Timeout",
};

static const char *rv_rej_reason_str(u8 reason)
{
	size_t index = reason;

	if (index < ARRAY_SIZE(rv_rej_reason_strs) &&
	    rv_rej_reason_strs[index])
		return rv_rej_reason_strs[index];
	else
		return " Unknown";
}

/*
 * Check REJ private data to determine if remote side is recoverable
 * Also returns additional RV reason text (with leading space or "")
 * - private_data format and version
 *	rev must always be an exact version we support
 *	ignore rev 0 & 1, only support rev 2
 * Assumes a REJ without additional information is not recoverable, if peer
 * is same rev, that will be true.
 */
static u8 rv_rej_is_recoverable(struct rv_sconn *sconn, void *priv,
				const char **add_reason)
{
	struct rv_rej_priv_data *rej_priv = (struct rv_rej_priv_data *)priv;

	*add_reason = "";
	if (!rej_priv->magic)
		goto nopriv;
	if (rej_priv->magic != RV_PRIVATE_DATA_MAGIC) {
		rv_conn_err(sconn,
			    "Inval CM REJ recv: magic 0x%llx expected 0x%llx\n",
			    rej_priv->magic, RV_PRIVATE_DATA_MAGIC);
		goto nopriv;
	}
	if (rej_priv->ver != RV_PRIVATE_DATA_VER) {
		rv_conn_err(sconn,
			    "Invalid CM REJ recv: rv version %d expected %d\n",
			    rej_priv->ver, RV_PRIVATE_DATA_VER);
		goto nopriv;
	}
	*add_reason = rv_rej_reason_str(rej_priv->reason);

	return rej_priv->recoverable;

nopriv:
	*add_reason = rv_rej_reason_str(RV_REJ_REASON_NONE);
	return 0;
}

static const char * const rv_dreq_reason_strs[] = {
	[RV_DREQ_REASON_NONE]		= "",
	[RV_DREQ_REASON_CLOSE]		= " Job Exited",
	[RV_DREQ_REASON_RTU_UNEXP]	= " Unexpected RTU",
	[RV_DREQ_REASON_LOCAL_ERR]	= " Remote Node Error",
	[RV_DREQ_REASON_QP_ERR]		= " Remote QP Error",
	[RV_DREQ_REASON_CQ_ERR]		= " Remote CQ Error",
	[RV_DREQ_REASON_CONN_TIMEOUT]	= " Conn Timeout",
};

static const char *rv_dreq_reason_str(u8 reason)
{
	size_t index = reason;

	if (index < ARRAY_SIZE(rv_dreq_reason_strs) &&
	    rv_dreq_reason_strs[index])
		return rv_dreq_reason_strs[index];
	else
		return " Unknown";
}

/*
 * Check DREQ private data to determine if remote side is recoverable
 * Also returns additional RV reason text (with leading space or "")
 * - private_data format and version
 *	rev must always be an exact version we support
 *	ignore rev 0 & 1, only support rev 2
 * Assumes a DREQ without additional information is a file close, if peer
 * is same rev, that will be true.  Otherwise we don't attempt recovery.
 */
static u8 rv_dreq_is_recoverable(struct rv_sconn *sconn, void *priv,
				 const char **add_reason, bool *is_close)
{
	struct rv_dreq_priv_data *dreq_priv = (struct rv_dreq_priv_data *)priv;

	*add_reason = "";
	*is_close = false;
	if (!dreq_priv->magic)
		goto nopriv;
	if (dreq_priv->magic != RV_PRIVATE_DATA_MAGIC) {
		rv_conn_err(sconn,
			    "Inval CM DREQ recv: magic 0x%llx expected 0x%llx\n",
			    dreq_priv->magic, RV_PRIVATE_DATA_MAGIC);
		goto nopriv;
	}
	if (dreq_priv->ver != RV_PRIVATE_DATA_VER) {
		rv_conn_err(sconn,
			    "Invalid CM DREQ recv: rv version %d expected %d\n",
			    dreq_priv->ver, RV_PRIVATE_DATA_VER);
		goto nopriv;
	}

	*add_reason = rv_dreq_reason_str(dreq_priv->reason);
	*is_close = (dreq_priv->reason == RV_DREQ_REASON_CLOSE);
	return dreq_priv->recoverable;

nopriv:
	*add_reason = rv_dreq_reason_str(RV_DREQ_REASON_CLOSE);
	*is_close = 1;
	return 0;
}

/*
 * rv_cm_handler - The client Callback frunction from IB CM
 * @cm_id: Handle for connection manager
 * @event: The event it caught
 * Be reminded that we can not destroy cm_id in this thread.
 */
static int rv_cm_handler(struct ib_cm_id *id, const struct ib_cm_event *evt)
{
	struct rv_sconn *sconn = id->context;
	int recover;
	const char *add_reason;
	bool is_close;
	struct rv_dreq_priv_data dreq_priv = {
		.magic = RV_PRIVATE_DATA_MAGIC,
		.ver = RV_PRIVATE_DATA_VER,
		.reason = RV_DREQ_REASON_RTU_UNEXP,
		.recoverable = 0,
	};

	trace_rv_cm_event_handler((u32)evt->event, id, sconn);
	if (!sconn || !sconn->parent)
		return 0;
	if (rv_conn_get_check(sconn->parent))
		return 0;
	trace_rv_sconn_cm_handler(sconn, sconn->index,
				  sconn->qp ? sconn->qp->qp_num : 0,
				  sconn->parent, sconn->flags,
				  (u32)sconn->state, sconn->cm_id,
				  sconn->resolver_retry_left);

	mutex_lock(&sconn->mutex);
	sconn->stats.cm_evt_cnt[min(evt->event, RV_CM_EVENT_UNEXP)]++;

	if (sconn->cm_id != id)
		goto unlock;

	switch (evt->event) {
	case IB_CM_REP_RECEIVED:
		rv_cm_rep_handler(sconn, &evt->param.rep_rcvd,
				  evt->private_data);
		break;
	case IB_CM_RTU_RECEIVED:
	case IB_CM_USER_ESTABLISHED:
		if (sconn->state != RV_CONNECTING) {
			/*
			 * QP error could be received before RTU. In that case,
			 * the state will be set to RV_DISCONNECTING.
			 */
			if (sconn->state == RV_DISCONNECTING)
				break;
			if (!ib_send_cm_dreq(id, &dreq_priv,
					     sizeof(dreq_priv))) {
				sconn->stats.dreq_sent++;
				trace_rv_msg_cm_handler(sconn, sconn->index,
							"Sending DREQ", 0,
							(u64)sconn);
			}
			rv_sconn_set_state(sconn, RV_ERROR, "unexpected RTU",
					   "", false);
		} else if (rv_sconn_move_qp_to_rts(sconn)) {
			/*
			 * If the qp has been put into ERR state due to an
			 * invalid first data packet received from the remote
			 * node, try to recover the connection.
			 */
			if (rv_query_qp_state(sconn->qp) == IB_QPS_ERR &&
			    rv_sconn_can_reconn(sconn))
				dreq_priv.recoverable = 1;
			if (!ib_send_cm_dreq(id, &dreq_priv,
					     sizeof(dreq_priv))) {
				sconn->stats.dreq_sent++;
				trace_rv_msg_cm_handler(sconn,
							sconn->index,
							"Sending DREQ",
							0, (u64)sconn);
			}

			if (dreq_priv.recoverable)
				rv_sconn_enter_disconnecting(sconn, "QP in ERR",
							     "");
			else
				rv_sconn_set_state(sconn, RV_ERROR,
						   "local error handling RTU",
						   "", false);
		} else {
			rv_sconn_set_state(sconn, RV_CONNECTED, "", "", false);
		}
		break;

	case IB_CM_REQ_ERROR:
		trace_rv_msg_cm_handler(sconn, sconn->index,
					"Sending CM REQ failed, send_status",
					(u64)evt->param.send_status,
					(u64)sconn);
		if (sconn->state == RV_CONNECTING && rv_sconn_can_reconn(sconn))
			rv_sconn_enter_disconnecting(sconn, "no REQ response",
						     "");
		else
			rv_sconn_set_state(sconn, RV_ERROR, "no REQ response",
					   "", false);
		break;
	case IB_CM_REP_ERROR:
		trace_rv_msg_cm_handler(sconn, sconn->index,
					"Sending CM REP failed, send_status",
					(u64)evt->param.send_status,
					(u64)sconn);
		if (sconn->state == RV_CONNECTING && rv_sconn_can_reconn(sconn))
			rv_sconn_enter_disconnecting(sconn, "no REP response",
						     "");
		else
			rv_sconn_set_state(sconn, RV_ERROR, "no REP response",
					   "", false);
		break;
	case IB_CM_REJ_RECEIVED:
		trace_rv_msg_cm_handler(sconn, sconn->index,
					"CM REJ received reason",
					(u64)evt->param.rej_rcvd.reason,
					(u64)sconn);
		recover = rv_rej_is_recoverable(sconn, evt->private_data,
						&add_reason);
		if (sconn->state == RV_CONNECTING && recover &&
		    rv_sconn_can_reconn(sconn)) {
			rv_sconn_enter_disconnecting(sconn, "received REJ",
						     add_reason);
		} else {
			/*
			 * When both nodes are disconnecting, it is possible to
			 * receive a REJ event from the ib_cm module from the
			 * remote node when the peer's cm_id is destroyed. In
			 * this case REJ private data is not used and no
			 * recoverable info is communicated.
			 */
			if (sconn->state != RV_DISCONNECTING ||
			    !rv_sconn_can_reconn(sconn))
				rv_sconn_set_state(sconn, RV_ERROR,
						   "received REJ",
						   add_reason, false);
		}
		break;
	case IB_CM_DREQ_RECEIVED:
		if (!ib_send_cm_drep(id, NULL, 0)) {
			sconn->stats.drep_sent++;
			trace_rv_msg_cm_handler(sconn, sconn->index,
						"Sending DREP", 0, (u64)sconn);
		}

		if (sconn->state == RV_DISCONNECTING)
			break;
		recover = rv_dreq_is_recoverable(sconn, evt->private_data,
						 &add_reason, &is_close);
		if (sconn->state == RV_CONNECTED ||
		    sconn->state == RV_CONNECTING) {
			if (recover && rv_sconn_can_reconn(sconn))
				rv_sconn_enter_disconnecting(sconn,
							     "received DREQ",
							     add_reason);
			else
				rv_sconn_set_state(sconn, RV_ERROR,
						   "received DREQ", add_reason,
						   is_close);
		} else {
			rv_sconn_set_state(sconn, RV_ERROR,
					   "received DREQ", add_reason, false);
		}
		break;

	case IB_CM_TIMEWAIT_EXIT:
		break;
	case IB_CM_MRA_RECEIVED:
		break;
	case IB_CM_DREQ_ERROR:
	case IB_CM_DREP_RECEIVED:
		break;

	case IB_CM_REQ_RECEIVED:
	case IB_CM_LAP_ERROR:
	case IB_CM_LAP_RECEIVED:
	case IB_CM_APR_RECEIVED:
		break;
	case IB_CM_SIDR_REQ_ERROR:
	case IB_CM_SIDR_REQ_RECEIVED:
	case IB_CM_SIDR_REP_RECEIVED:
		break;
	default:
		rv_conn_err(sconn, "Unhandled CM event %d\n", evt->event);
		WARN_ON(1);
		rv_sconn_set_state(sconn, RV_ERROR, "invalid CM event",
				   "", false);
		break;
	}

unlock:
	mutex_unlock(&sconn->mutex);

	rv_conn_put(sconn->parent);

	return 0;
}

/*
 * rv_cm_server_handler - The server callback function from IB CM
 * @cm_id: Handle for connection manager. This is an newly created cm_id
 *	For the new connection, which is different from the original
 *	listener cm_id.
 * @event: The event it caught
 * It only handles incoming REQs. All other events should go to rv_cm_handler
 */
static int rv_cm_server_handler(struct ib_cm_id *id,
				const struct ib_cm_event *evt)
{
	int ret = 0;

	trace_rv_cm_event_server_handler((u32)evt->event, id, NULL);
	switch (evt->event) {
	case IB_CM_REQ_RECEIVED:
		ret = rv_cm_req_handler(id, &evt->param.req_rcvd,
					evt->private_data);
		break;
	default:
		rv_cm_err(id, "Unhandled CM event %d\n", evt->event);
		WARN_ON(1);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int rv_conn_cmp_params(int rv_inx, const struct rv_conn *conn,
			      const struct rv_conn_create_params_in *param)
{
	if (param->rem_addr != conn->rem_addr) {
		trace_rv_msg_cmp_params(rv_inx,
					"rem_addr differ, skipping",
					(u64)param->rem_addr,
					(u64)conn->rem_addr);
		return 1;
	}

	if (param->ah.is_global != conn->ah.is_global) {
		trace_rv_msg_cmp_params(rv_inx,
					"Global flags differ, skipping",
					(u64)param->ah.is_global,
					(u64)conn->ah.is_global);
		return 1;
	}

	if (param->ah.is_global) {
		if (cmp_gid(&param->ah.grh.dgid[0],
			    &conn->ah.grh.dgid[0]) == 0) {
			trace_rv_msg_cmp_params(rv_inx,
						"Gid's are matching",
						*(u64 *)&param->ah.grh.dgid[8],
						*(u64 *)&conn->ah.grh.dgid[8]);
			return 0;
		}
		trace_rv_msg_cmp_params(rv_inx, "Gid's do not match",
					*(u64 *)&param->ah.grh.dgid[8],
					*(u64 *)&conn->ah.grh.dgid[8]);
		return 1;

	} else {
		if (param->ah.dlid == conn->ah.dlid) {
			trace_rv_msg_cmp_params(rv_inx, "Found matching dlid",
						(u64)param->ah.dlid,
						(u64)conn->ah.dlid);
			return 0;
		}
		trace_rv_msg_cmp_params(rv_inx, "DLID not matching",
					(u64)param->ah.dlid,
					(u64)conn->ah.dlid);
		return 1;
	}
}

/*
 * Search the list for the GID or DLID in the AH
 * Caller must hold rv_user.mutex
 */
static struct rv_conn *
user_conn_exist(struct rv_user *rv, struct rv_conn_create_params_in *param)
{
	struct rv_conn *conn;

	XA_STATE(xas, &rv->conn_xa, 0);

	xas_for_each(&xas, conn, UINT_MAX) {
		trace_rv_msg_conn_exist(rv->inx, "Conn found in list",
					(u64)conn, 0);
		if (!rv_conn_cmp_params(rv->inx, conn, param))
			return conn;
	}

	return NULL;
}

struct rv_cq_event_work_item {
	struct work_struct cq_event_work;
	struct rv_sconn *sconn;
	struct ib_event event;
};

/*
 * CQ Async event callback worker
 * Must make sure the CQs are still relevant as they could have changed
 */
static void rv_cq_event_work(struct work_struct *work)
{
	struct rv_cq_event_work_item *item = container_of(work,
				struct rv_cq_event_work_item, cq_event_work);
	struct rv_sconn *sconn = item->sconn;
	struct rv_dreq_priv_data dreq_priv = {
		.magic = RV_PRIVATE_DATA_MAGIC,
		.ver = RV_PRIVATE_DATA_VER,
		.reason = RV_DREQ_REASON_CQ_ERR,
		.recoverable = 0,
	};

	trace_rv_sconn_cq_event(sconn, sconn->index,
				sconn->qp ? sconn->qp->qp_num : 0,
				sconn->parent, sconn->flags,
				(u32)sconn->state, sconn->cm_id,
				sconn->resolver_retry_left);

	mutex_lock(&sconn->mutex);
	if (sconn->send_cq != item->event.element.cq &&
	    sconn->recv_cq != item->event.element.cq)
		goto unlock;

	switch (item->event.event) {
	case IB_EVENT_CQ_ERR:
		if (!ib_send_cm_dreq(sconn->cm_id, &dreq_priv,
				     sizeof(dreq_priv))) {
			sconn->stats.dreq_sent++;
			trace_rv_msg_cq_event(sconn, sconn->index,
					      "Sending DREQ", 0, (u64)sconn);
		}
		rv_sconn_set_state(sconn, RV_ERROR, "CQ error", "", false);
		break;
	default:
		break;
	}
unlock:
	mutex_unlock(&sconn->mutex);
	rv_conn_put(sconn->parent);
	kfree(item);
}

/*
 * CQ Async Event
 * Non-premptable, so real work in WQ
 */
static void rv_cq_event(struct ib_event *event, void *context)
{
	struct rv_sconn *sconn = (struct rv_sconn *)context;
	struct rv_cq_event_work_item *item;
	char *cq_text;

	if (!sconn || !sconn->parent)
		return;
	if (rv_conn_get_check(sconn->parent))
		return;
	if (sconn->send_cq == event->element.cq)
		cq_text = "Send";
	else if (sconn->recv_cq == event->element.cq)
		cq_text = "Recv";
	else
		cq_text = "Unkn";

	rv_conn_err(sconn,
		    "%s CQ Event received: %s: sconn index %u qp %u\n",
		    cq_text, ib_event_msg(event->event), sconn->index,
		    event->element.qp->qp_num);

	item = kzalloc(sizeof(*item), GFP_ATOMIC);
	if (!item)
		goto fail;
	INIT_WORK(&item->cq_event_work, rv_cq_event_work);
	item->sconn = sconn;
	item->event = *event;
	rv_queue_work(&item->cq_event_work);
	return;

fail:
	rv_conn_err(sconn,
		    "No mem for %s CQ Evt: %s: sconn index %u qp %u conn %p\n",
		    cq_text, ib_event_msg(event->event), sconn->index,
		    event->element.qp->qp_num, sconn->parent);
	rv_conn_put(sconn->parent);
}

struct rv_qp_event_work_item {
	struct work_struct qp_event_work;
	struct rv_sconn *sconn;
	struct ib_event event;
};

/*
 * QP Async event callback worker
 * Must make sure the QP is still relevant as it could have changed
 * unfortnately only get LID_CHANGE, PORT_ERR, PORT_ACTIVE
 * GID_CHANGE, at device level, but likely to get QP event soon after
 */
static void rv_qp_event_work(struct work_struct *work)
{
	struct rv_qp_event_work_item *item = container_of(work,
				struct rv_qp_event_work_item, qp_event_work);
	struct rv_sconn *sconn = item->sconn;
	struct rv_dreq_priv_data dreq_priv = {
		.magic = RV_PRIVATE_DATA_MAGIC,
		.ver = RV_PRIVATE_DATA_VER,
		.reason = RV_DREQ_REASON_QP_ERR,
		.recoverable = 0,
	};

	trace_rv_sconn_qp_event(sconn, sconn->index,
				sconn->qp ? sconn->qp->qp_num : 0,
				sconn->parent, sconn->flags,
				(u32)sconn->state, sconn->cm_id,
				sconn->resolver_retry_left);

	mutex_lock(&sconn->mutex);
	if (sconn->qp != item->event.element.qp)
		goto unlock;

	switch (item->event.event) {
	case IB_EVENT_PATH_MIG:
		if (sconn->state == RV_CONNECTED)
			ib_cm_notify(sconn->cm_id, item->event.event);
		break;
	case IB_EVENT_COMM_EST:
		if (sconn->state == RV_CONNECTING)
			ib_cm_notify(sconn->cm_id, item->event.event);
		break;
	case IB_EVENT_QP_FATAL:
	case IB_EVENT_QP_REQ_ERR:
	case IB_EVENT_QP_ACCESS_ERR:
		if (sconn->state == RV_DISCONNECTING ||
		    ((sconn->state == RV_CONNECTED ||
		      sconn->state == RV_CONNECTING) &&
		     rv_sconn_can_reconn(sconn)))
			dreq_priv.recoverable = 1;
		if (!ib_send_cm_dreq(sconn->cm_id, &dreq_priv,
				     sizeof(dreq_priv))) {
			sconn->stats.dreq_sent++;
			trace_rv_msg_qp_event(sconn, sconn->index,
					      "Sending DREQ", 0, (u64)sconn);
		}
		if (sconn->state != RV_DISCONNECTING) {
			if (dreq_priv.recoverable)
				rv_sconn_enter_disconnecting(sconn, "QP error",
							     "");
			else
				rv_sconn_set_state(sconn, RV_ERROR, "QP error",
						   "", false);
		}
		break;
	default:
		break;
	}
unlock:
	mutex_unlock(&sconn->mutex);
	rv_conn_put(sconn->parent);
	kfree(item);
}

/*
 * QP Async Event
 * Non-premptable, so real work in WQ
 */
static void rv_qp_event(struct ib_event *event, void *context)
{
	struct rv_sconn *sconn = (struct rv_sconn *)context;
	struct rv_qp_event_work_item *item;

	if (!sconn || !sconn->parent)
		return;
	if (rv_conn_get_check(sconn->parent))
		return;

	rv_conn_err(sconn,
		    "QP Event received: %s: sconn index %u qp %u\n",
		    ib_event_msg(event->event), sconn->index,
		    event->element.qp->qp_num);

	item = kzalloc(sizeof(*item), GFP_ATOMIC);
	if (!item)
		goto fail;
	INIT_WORK(&item->qp_event_work, rv_qp_event_work);
	item->sconn = sconn;
	item->event = *event;
	rv_queue_work(&item->qp_event_work);
	return;

fail:
	rv_conn_err(sconn,
		    "No mem for QP Event: %s: sconn index %u qp %u conn %p\n",
		    ib_event_msg(event->event), sconn->index,
		    event->element.qp->qp_num, sconn->parent);
	rv_conn_put(sconn->parent);
}

/*
 * shared rv_conn QP create and re-create
 * Allocate 2 extra WQEs and CQEs in each direction so room for error
 * recovery drain and drain in release.
 * In rare case of release during error recovery may need both.
 * Plus one for heartbeat
 * mlx5 driver requires recv_sge>0, even though we expect no data
 * Returns:
 *	0 on success
 *	-ENOSPC - QP from device too small
 *		(note can't be -ENOXIO since that means device removed
 *	error from ib_create_qp
 */
static int rv_create_qp(int rv_inx, struct rv_sconn *sconn,
			struct rv_job_dev *jdev)
{
	int ret = 0;
	struct ib_qp_init_attr qp_attr;
	int alloced_s_cq = 0;
	int alloced_r_cq = 0;
	u32 qp_depth;

	qp_depth = jdev->qp_depth + 3;

	if (!sconn->send_cq) {
		sconn->send_cq = ib_alloc_cq(jdev->dev->ib_dev, sconn,
					     qp_depth, 0, IB_POLL_SOFTIRQ);
		if (IS_ERR(sconn->send_cq)) {
			ret = PTR_ERR(sconn->send_cq);
			rv_err(rv_inx, "Creating send cq failed %d\n", ret);
			goto bail_out;
		}
		sconn->send_cq->event_handler = rv_cq_event;
		alloced_s_cq = 1;
	}

	if (!sconn->recv_cq) {
		sconn->recv_cq = ib_alloc_cq(jdev->dev->ib_dev, sconn,
					     qp_depth, 0, IB_POLL_SOFTIRQ);
		if (IS_ERR(sconn->recv_cq)) {
			ret = PTR_ERR(sconn->recv_cq);
			rv_err(rv_inx, "Creating recv cq failed %d\n", ret);
			goto bail_s_cq;
		}
		sconn->recv_cq->event_handler = rv_cq_event;
		alloced_r_cq = 1;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.event_handler = rv_qp_event;
	qp_attr.qp_context = sconn;
	qp_attr.cap.max_send_wr = qp_depth;
	qp_attr.cap.max_recv_wr = qp_depth;
	qp_attr.cap.max_recv_sge = 1;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_attr.qp_type = IB_QPT_RC;
	qp_attr.send_cq = sconn->send_cq;
	qp_attr.recv_cq = sconn->recv_cq;

	sconn->qp = ib_create_qp(jdev->pd, &qp_attr);
	if (IS_ERR(sconn->qp)) {
		ret = PTR_ERR(sconn->qp);
		sconn->qp = NULL;
		goto bail_r_cq;
	}
	if (qp_attr.cap.max_recv_wr < qp_depth ||
	    qp_attr.cap.max_send_wr < qp_depth) {
		ret = -ENOSPC;
		goto bail_qp;
	}
#ifdef RV_ENABLE_DUP_SQ_CQE_CHECK
	sconn->max_send_wr = qp_attr.cap.max_send_wr;
#endif

	return 0;

bail_qp:
	ib_destroy_qp(sconn->qp);
	sconn->qp = NULL;
bail_r_cq:
	if (alloced_r_cq) {
		ib_free_cq(sconn->recv_cq);
		sconn->recv_cq = NULL;
	}
bail_s_cq:
	if (alloced_r_cq) {
		ib_free_cq(sconn->send_cq);
		sconn->send_cq = NULL;
	}
bail_out:

	return ret;
}

#ifndef USE_IB_DRAIN
struct rv_drain_cqe {
	struct ib_cqe cqe;
	struct completion done;
};

static void rv_drain_qp_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct rv_drain_cqe *cqe = container_of(wc->wr_cqe,
						struct rv_drain_cqe, cqe);

	complete(&cqe->done);
}
#endif

int rv_query_qp_state(struct ib_qp *qp)
{
	struct ib_qp_attr attr;
	struct ib_qp_init_attr qp_init_attr;
	int ret;

	ret = ib_query_qp(qp, &attr, IB_QP_STATE, &qp_init_attr);
	if (ret) {
		rv_err(RV_INVALID, "failed to query qp %u: %d\n",
		       qp->qp_num, ret);
		return ret;
	}
	trace_rv_conn_msg_query_qp_state(RV_INVALID, "qp_state",
					 (u64)qp->qp_num,
					 (u64)attr.qp_state);

	return attr.qp_state;
}

/*
 * If QP is not in reset state, move it to error state.
 *
 * Return:  0  - Success;
 *	    1 - QP in RESET
 *	    <0 - Failure.
 */
#ifdef NO_ERR_TO_ERR
/*
 * ERR->ERR transition can fail, could have raced with async event
 * so check state again if ib_modify_qp fails
 */
#endif
static int rv_err_qp(struct ib_qp *qp)
{
	struct ib_qp_attr attr;
	int ret;
#ifdef NO_ERR_TO_ERR
	struct ib_qp_init_attr qp_init_attr;
	int ret2;
#endif

	ret = rv_query_qp_state(qp);
	if (ret < 0)
		return ret;

	if (ret == IB_QPS_RESET)
		return 1;

	if (ret == IB_QPS_ERR)
		return 0;

	attr.qp_state = IB_QPS_ERR;
	ret = ib_modify_qp(qp, &attr, IB_QP_STATE);
#ifdef NO_ERR_TO_ERR
	if (!ret)
		return ret;

	ret2 = ib_query_qp(qp, &attr, IB_QP_STATE, &qp_init_attr);
	if (!ret2 && attr.qp_state == IB_QPS_ERR)
		return 0;

	rv_err(RV_INVALID,
	       "failed to put qp %u into error state: %d now in 0x%x\n",
	       qp->qp_num, ret, attr.qp_state);
#endif

	return ret;
}

#ifndef USE_IB_DRAIN
/* Post a WR and block until its completion is reaped for the SQ.*/
static void rv_drain_sq(struct ib_qp *qp)
{
	struct rv_drain_cqe *sdrain;
	struct ib_rdma_wr swr = {
		.wr = {
			.next = NULL,
			.opcode	= IB_WR_RDMA_WRITE,
		},
	};
	int ret;

	ret = rv_err_qp(qp);
	if (ret)
		return;

	sdrain = kzalloc(sizeof(*sdrain), GFP_KERNEL);
	if (!sdrain)
		return;
	swr.wr.wr_cqe = &sdrain->cqe;
	sdrain->cqe.done = rv_drain_qp_done;
	init_completion(&sdrain->done);

	ret = ib_post_send(qp, &swr.wr, NULL);
	if (ret) {
		rv_err(RV_INVALID, "failed to drain send queue: post %d\n",
		       ret);
		/* XXX leaks sdrain, but have potential CQE cb */
		return;
	}

	if (!wait_for_completion_timeout(&sdrain->done, DRAIN_TIMEOUT * HZ))
		rv_dbg(RV_INVALID, "timeout to drain send queue qp %u\n",
		       qp->qp_num);
		/* XXX leak instead of leaving future CQE cb hazzard */
	else
		kfree(sdrain);
}

/* Post a WR and block until its completion is reaped for the RQ. */
static void rv_drain_rq(struct ib_qp *qp)
{
	struct rv_drain_cqe *rdrain;
	struct ib_recv_wr rwr = {};
	int ret;

	ret = rv_err_qp(qp);
	if (ret)
		return;

	rdrain = kzalloc(sizeof(*rdrain), GFP_KERNEL);
	if (!rdrain)
		return;
	rwr.wr_cqe = &rdrain->cqe;
	rdrain->cqe.done = rv_drain_qp_done;
	init_completion(&rdrain->done);

	ret = ib_post_recv(qp, &rwr, NULL);
	if (ret) {
		rv_err(RV_INVALID, "failed to drain recv queue: post %d\n",
		       ret);
		/* XXX leaks rdrain, but have potential CQE cb */
		return;
	}

	if (!wait_for_completion_timeout(&rdrain->done, DRAIN_TIMEOUT * HZ))
		rv_dbg(RV_INVALID, "timeout to drain recv queue qp %u\n",
		       qp->qp_num);
		/* XXX leak instead of leaving future CQE cb hazzard */
	else
		kfree(rdrain);
}

/* synchronous drain of QP, preempts */
static void rv_drain_qp(struct ib_qp *qp)
{
	rv_drain_sq(qp);
	if (!qp->srq)
		rv_drain_rq(qp);
}
#endif /* USE_IB_DRAIN */

#ifdef DRAIN_WQ
struct rv_dest_qp_work_item {
	struct work_struct destroy_work;
	struct ib_qp *qp;
	struct ib_cq *send_cq;
	struct ib_cq *recv_cq;
};

/* only used if QP needs to be drained */
static void rv_handle_destroy_qp(struct work_struct *work)
{
	struct rv_dest_qp_work_item *item = container_of(work,
				struct rv_dest_qp_work_item, destroy_work);

	trace_rv_msg_destroy_qp(NULL, RV_INVALID, "destroy qp",
				item->qp ? (u64)item->qp->qp_num : 0, 0);
	if (item->qp) {
#ifdef USE_IB_DRAIN
		ib_drain_qp(item->qp);
#else
		rv_drain_qp(item->qp);
#endif
		ib_destroy_qp(item->qp);
	}
	if (item->recv_cq)
		ib_free_cq(item->recv_cq);

	if (item->send_cq)
		ib_free_cq(item->send_cq);
	kfree(item);
}
#endif

/*
 * destroy QP and CQs, cannot hold sconn->mutex
 * Drain the qp before destroying it to avoid the race between QP destroy
 * and completion handler. Timeout protects against CQ issues.
 */
static void rv_destroy_qp(struct rv_sconn *sconn)
{
	int qps = -1;
#ifdef DRAIN_WQ
	struct rv_dest_qp_work_item *item;
#endif

	if (sconn->qp)
		qps = rv_query_qp_state(sconn->qp);
#ifdef DRAIN_WQ
	if (qps >= 0 && qps != IB_QPS_RESET) {
		item = kzalloc(sizeof(*item), GFP_KERNEL);
		if (item) {
			trace_rv_msg_destroy_qp(sconn, sconn->index,
						"queue destroy qp",
						(u64)sconn->qp->qp_num,
						(u64)sconn);
			INIT_WORK(&item->destroy_work, rv_handle_destroy_qp);
			item->qp = sconn->qp;
			item->recv_cq = sconn->recv_cq;
			item->send_cq = sconn->send_cq;
			sconn->qp = NULL;
			sconn->recv_cq = NULL;
			sconn->send_cq = NULL;

			rv_queue_work2(&item->destroy_work);
			return;
		}
	}
#endif
	trace_rv_msg_destroy_qp(sconn, sconn->index, "destroy qp",
				sconn->qp ? (u64)sconn->qp->qp_num : 0,
				(u64)sconn);
	if (sconn->qp) {
		if (qps >= 0 && qps != IB_QPS_RESET)
#ifdef USE_IB_DRAIN
			ib_drain_qp(sconn->qp);
#else
			rv_drain_qp(sconn->qp);
#endif
		ib_destroy_qp(sconn->qp);
		sconn->qp = NULL;
	}

	if (sconn->recv_cq) {
		ib_free_cq(sconn->recv_cq);
		sconn->recv_cq = NULL;
	}

	if (sconn->send_cq) {
		ib_free_cq(sconn->send_cq);
		sconn->send_cq = NULL;
	}
}

/*
 * only for use by rv_conn_alloc
 * others use rv_conn_get_alloc or rv_conn_get
 * must be called with jdev->conn_list_mutex held
 * We create QP now to make sure we can create it before going further.
 * Otherwise we really don't need it until REQ handler on server or
 * connect on client.
 */
static int rv_sconn_init(struct rv_user *rv, struct rv_sconn *sconn,
			 struct rv_conn_create_params_in *param,
			 struct rv_conn *parent, u8 index)
{
	struct rv_job_dev *jdev = rv->jdev;
	int ret;

	sconn->index = index;
	sconn->parent = parent;

	mutex_init(&sconn->mutex);

	spin_lock_init(&sconn->drain_lock);

	INIT_WORK(&sconn->drain_work, rv_sconn_drain_work);
#ifdef RV_ENABLE_DRAIN_TIMEOUT
	timer_setup(&sconn->drain_timer, rv_sconn_drain_timeout_func, 0);
#endif
#ifdef RV_ENABLE_DUP_SQ_CQE_CHECK
	INIT_LIST_HEAD(&sconn->done_wr_list);
#endif

	timer_setup(&sconn->conn_timer, rv_sconn_timeout_func, 0);
	INIT_WORK(&sconn->timer_work, rv_sconn_timeout_work);

	timer_setup(&sconn->delay_timer, rv_sconn_delay_func, 0);
	INIT_WORK(&sconn->delay_work, rv_sconn_delay_work);

	timer_setup(&sconn->hb_timer, rv_sconn_hb_func, 0);
	INIT_WORK(&sconn->hb_work, rv_sconn_hb_work);

	sconn->cqe.done = rv_recv_done;
	sconn->rdrain_cqe.done = rv_rq_drain_done;
	sconn->sdrain_cqe.done = rv_sq_drain_done;
	sconn->hb_cqe.done = rv_hb_done;

	if (param->ah.is_global ?
	    memcmp(jdev->loc_gid, param->ah.grh.dgid, sizeof(jdev->loc_gid)) < 0
	    : jdev->loc_addr < param->rem_addr)
		set_bit(RV_SCONN_SERVER, &sconn->flags);

	ret = rv_create_qp(rv->inx, sconn, jdev);
	if (ret) {
		rv_err(rv->inx, "Failed to create qp: %d\n", ret);
		goto bail;
	}

	if (test_bit(RV_SCONN_SERVER, &sconn->flags)) {
		if (!jdev->listener) {
			jdev->listener = rv_listener_get_alloc(jdev->dev,
							       jdev->service_id,
							  rv_cm_server_handler);
			if (!jdev->listener) {
				rv_err(rv->inx,
				       "Failed to get/allocate listener\n");
				goto bail_qp;
			}
		}
		sconn->state = RV_WAITING;
		sconn->start_time = ktime_get();
	} else {
		sconn->state = RV_INIT;
	}
	atomic_set(&sconn->stats.outstand_send_write, 0);
	atomic64_set(&sconn->stats.send_write_cqe, 0);
	atomic64_set(&sconn->stats.send_write_cqe_fail, 0);
	atomic64_set(&sconn->stats.recv_write_cqe, 0);
	atomic64_set(&sconn->stats.recv_write_bytes, 0);
	atomic64_set(&sconn->stats.recv_cqe_fail, 0);
	atomic64_set(&sconn->stats.send_hb_cqe, 0);
	atomic64_set(&sconn->stats.send_hb_cqe_fail, 0);
	atomic64_set(&sconn->stats.recv_hb_cqe, 0);
	trace_rv_sconn_init(sconn, sconn->index, sconn->qp->qp_num,
			    sconn->parent, sconn->flags, (u32)sconn->state,
			    sconn->cm_id, sconn->resolver_retry_left);
	return 0;

bail_qp:
	rv_destroy_qp(sconn);
bail:
	return -ENOMEM;
}

static void rv_handle_conn_put(struct work_struct *work)
{
	struct rv_conn *conn = container_of(work, struct rv_conn, put_work);

	rv_conn_release(conn);
}

/*
 * only for use by rv_conn_get_alloc
 * others use rv_conn_get_alloc or rv_conn_get
 * must be called with jdev->conn_list_mutex held
 */
static struct rv_conn *rv_conn_alloc(struct rv_user *rv,
				     struct rv_conn_create_params_in *param)
{
	struct rv_conn *conn;
	struct rv_job_dev *jdev = rv->jdev;
	int i;

	conn = kzalloc(sizeof(*conn) +
		       sizeof(conn->sconn_arr[0]) * jdev->num_conn,
		       GFP_KERNEL);
	if (!conn)
		return NULL;

	conn->num_conn = jdev->num_conn;
	rv_job_dev_get(jdev);
	conn->jdev = jdev;
	memcpy(&conn->ah, &param->ah, sizeof(struct ib_uverbs_ah_attr));
	conn->rem_addr = (u64)param->rem_addr;

	kref_init(&conn->kref);
	INIT_WORK(&conn->put_work, rv_handle_conn_put);
#ifdef DRAIN_WQ
	INIT_WORK(&conn->free_work, rv_handle_free_conn);
#endif

	spin_lock_init(&conn->next_lock);
	for (i = 0; i < conn->num_conn; i++) {
		if (rv_sconn_init(rv, &conn->sconn_arr[i], param, conn, i))
			goto bail_conn;
	}
	trace_rv_conn_alloc(conn, conn->rem_addr, conn->ah.is_global,
			    conn->ah.dlid,
			    be64_to_cpu(*((__be64 *)&conn->ah.grh.dgid[0])),
			    be64_to_cpu(*((__be64 *)&conn->ah.grh.dgid[8])),
			    conn->num_conn, conn->next,
			    conn->jdev, kref_read(&conn->kref));

	return conn;

bail_conn:
	for (--i; i >= 0; i--)
		rv_sconn_deinit(&conn->sconn_arr[i]);
	rv_job_dev_put(jdev);
	kfree(conn);
	return NULL;
}

/*
 * get a reference to the matching rv_conn.  Allocate an rv_conn if no
 * match found.  kref_get_unless_zero avoids race w/ release removing from list
 */
static struct rv_conn *rv_conn_get_alloc(struct rv_user *rv,
					 struct rv_conn_create_params_in *param)
{
	struct rv_conn *conn;
	struct rv_job_dev *jdev = rv->jdev;

	mutex_lock(&jdev->conn_list_mutex);
	rcu_read_lock();
	list_for_each_entry_rcu(conn, &jdev->conn_list, conn_entry) {
		if (rv_conn_cmp_params(rv->inx, conn, param))
			continue;
		if (!kref_get_unless_zero(&conn->kref))
			continue;
		rcu_read_unlock();
		goto done;
	}
	rcu_read_unlock();
	conn = rv_conn_alloc(rv, param);
	if (!conn)
		goto done;
	list_add_rcu(&conn->conn_entry, &jdev->conn_list);
done:
	mutex_unlock(&jdev->conn_list_mutex);
	return conn;
}

/* validate conn_create against jdev->ah */
static int rv_jdev_check_create_ah(int rv_inx, const struct rv_job_dev *jdev,
				   const struct rv_conn_create_params_in *param)
{
	if (!param->ah.dlid && !rv_jdev_protocol_roce(jdev)) {
		rv_err(rv_inx, "create_conn: DLID must be non-zero\n");
		return -EINVAL;
	}
	if (param->ah.is_global &&
	    jdev->loc_gid_index != param->ah.grh.sgid_index) {
		rv_err(rv_inx, "create_conn: incorrect sgid_index\n");
		return -EINVAL;
	}
	if (jdev->port_num != param->ah.port_num) {
		rv_err(rv_inx, "create_conn: port or sgid_index\n");
		return -EINVAL;
	}
	if (param->ah.is_global ?
	    !memcmp(jdev->loc_gid, param->ah.grh.dgid, sizeof(jdev->loc_gid))
	    : jdev->loc_addr == param->rem_addr) {
		rv_err(rv_inx, "create_conn: loopback not allowed\n");
		return -EINVAL;
	}
	return 0;
}

/*
 * validate conn_create ah against conn->ah
 * Assumes caller has used rv_jdev_check_create_ah and
 * assumes conn_get_alloc matched on rem_addr, is_global and (dgid or dlid).
 * Confirms the rest of ah is consistent
 */
static int rv_conn_create_check_ah(int rv_inx, const struct rv_conn *conn,
				   const struct ib_uverbs_ah_attr *ah)
{
	int ret = -EEXIST;

#define RV_CHECK(field) (ah->field != conn->ah.field)
#define RV_REPORT(field, text, format) \
		     rv_err(rv_inx, "create_conn: inconsistent " text " " \
			    format " with other processes " format "\n", \
			    ah->field, conn->ah.field)
	if (RV_CHECK(dlid))
		RV_REPORT(dlid, "DLID", "0x%x");
	else if (RV_CHECK(src_path_bits))
		RV_REPORT(src_path_bits, "src_path_bits", "0x%x");
	else if (RV_CHECK(sl))
		RV_REPORT(sl, "SL", "%u");
	else if (conn->ah.is_global && RV_CHECK(grh.traffic_class))
		RV_REPORT(grh.traffic_class, "traffic_class", "%u");
	else if (conn->ah.is_global && RV_CHECK(grh.flow_label))
		RV_REPORT(grh.flow_label, "flow_label", "0x%x");
	else if (RV_CHECK(static_rate))
		RV_REPORT(static_rate, "rate", "%u");
	else if (conn->ah.is_global && RV_CHECK(grh.hop_limit))
		RV_REPORT(grh.hop_limit, "hop_limit", "%u");
	else
		ret = 0;
#undef RV_CHECK
#undef RV_REPORT

	return ret;
}

int doit_conn_create(struct rv_user *rv, unsigned long arg)
{
	struct rv_conn_create_params param;
	struct rv_conn *conn;
	struct rv_job_dev *jdev;
	int ret = 0;
	u32 id;

	if (copy_from_user(&param.in, (void __user *)arg, sizeof(param.in)))
		return -EFAULT;
	trace_rv_conn_create_req(/* trace */
		param.in.rem_addr, param.in.ah.is_global,
		param.in.ah.grh.sgid_index, param.in.ah.port_num,
		param.in.ah.dlid,
		be64_to_cpu(*((__be64 *)&param.in.ah.grh.dgid[0])),
		be64_to_cpu(*((__be64 *)&param.in.ah.grh.dgid[8])));

	mutex_lock(&rv->mutex);
	if (rv->state != RV_USER_ATTACHED) {
		ret = (rv->state == RV_USER_WAS_ATTACHED) ? -ENXIO : -EINVAL;
		goto bail_unlock;
	}
	if (rv->rdma_mode != RV_RDMA_MODE_KERNEL) {
		ret = -EINVAL;
		goto bail_unlock;
	}

	jdev = rv->jdev;
	trace_rv_jdev_conn_create(jdev, jdev->dev_name, jdev->num_conn,
				  jdev->index_bits, jdev->loc_gid_index,
				  jdev->loc_addr, jdev->job_key_len,
				  jdev->job_key, jdev->service_id,
				  jdev->q_depth, jdev->user_array_next,
				  kref_read(&jdev->kref));
	ret = rv_jdev_check_create_ah(rv->inx, jdev, &param.in);
	if (ret)
		goto bail_unlock;

	conn = user_conn_exist(rv, &param.in);
	if (conn) {
		trace_rv_msg_conn_create(rv->inx, "User_conn exists",
					 (u64)conn, 0);
		ret = -EBUSY;
		goto bail_unlock;
	}

	conn = rv_conn_get_alloc(rv, &param.in);
	if (!conn) {
		rv_err(rv->inx, "Failed to get/allocate conn\n");
		ret = -ENOMEM;
		goto bail_unlock;
	}
	trace_rv_conn_create(conn, conn->rem_addr, conn->ah.is_global,
			     conn->ah.dlid,
			     be64_to_cpu(*((__be64 *)&conn->ah.grh.dgid[0])),
			     be64_to_cpu(*((__be64 *)&conn->ah.grh.dgid[8])),
			     conn->num_conn, conn->next,
			     conn->jdev, kref_read(&conn->kref));
	ret = rv_conn_create_check_ah(rv->inx, conn, &param.in.ah);
	if (ret)
		goto bail_put;

	ret = xa_alloc(&rv->conn_xa, &id, conn, XA_LIMIT(1, UINT_MAX),
		       GFP_KERNEL);
	if (ret)
		goto bail_put;

	param.out.handle = (u64)id;
	param.out.conn_handle = (u64)conn;
	ret = copy_to_user((void __user *)arg, &param.out, sizeof(param.out));
	if (ret) {
		ret = -EFAULT;
		goto bail_xa;
	}

	trace_rv_msg_uconn_create(rv->inx, "rv_user create uconn", (u64)conn,
				  0);
	mutex_unlock(&rv->mutex);

	return 0;

bail_xa:
	xa_erase(&rv->conn_xa, id);
bail_put:
	rv_conn_put(conn);
bail_unlock:
	mutex_unlock(&rv->mutex);
	return ret;
}

/*
 * Address Resolver callback.
 * there is a slight chance the device bounced and changed mode
 * from RoCE to IB or iWARP.  However then the gids we have
 * are wrong anyway. So just let resolver struggle and hit retry limit
 * instead of trying to redo rdma_protocol_roce(), etc.
 * PSM will fail in this case anyway and close.
 */
static void rv_resolve_ip_cb(int status, struct sockaddr *src_addr,
			     struct rdma_dev_addr *addr, void *context)
{
	struct rv_sconn *sconn = (struct rv_sconn *)context;

	if (!sconn || !sconn->parent)
		return;
	if (rv_conn_get_check(sconn->parent))
		return;

	mutex_lock(&sconn->mutex);
	trace_rv_sconn_resolve_cb(sconn, sconn->index,
				  sconn->qp ? sconn->qp->qp_num : 0,
				  sconn->parent, sconn->flags,
				  (u32)sconn->state, sconn->cm_id,
				  sconn->resolver_retry_left);
	if (sconn->state != RV_RESOLVING)
		goto unlock;

	if (status) {
		rv_conn_err(sconn, "failed to resolve_ip status %d\n", status);
		goto retry;
	}
	if (addr != &sconn->dev_addr) {
		rv_conn_err(sconn, "wrong dev_addr in callback\n");
		goto fail;
	}
	if (addr->sgid_attr != sconn->parent->jdev->sgid_attr) {
		rv_conn_err(sconn, "wrong sgid_attr in callback\n");
		goto fail;
	}
	sconn->primary_path->roce.route_resolved = true;
	sa_path_set_dmac(sconn->primary_path, addr->dst_dev_addr);
	sconn->primary_path->hop_limit = addr->hoplimit;

	rv_send_req(sconn);
unlock:
	mutex_unlock(&sconn->mutex);
	rv_conn_put(sconn->parent);
	return;

retry:
	if (sconn->resolver_retry_left) {
		sconn->resolver_retry_left--;
		if (!rv_resolve_ip(sconn)) {
			mutex_unlock(&sconn->mutex);
			rv_conn_put(sconn->parent);
			return;
		}
	}
	if (rv_sconn_can_reconn(sconn))
		rv_sconn_set_state(sconn, RV_DELAY, "", "", false);
fail:
	if (test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags))
		sconn->stats.reresolve_fail++;
	else
		sconn->stats.resolve_fail++;
	rv_sconn_free_primary_path(sconn);
	if (sconn->state != RV_DELAY)
		rv_sconn_set_state(sconn, RV_ERROR,
				   "unable to resolve address", "", false);
	mutex_unlock(&sconn->mutex);
	rv_conn_put(sconn->parent);
}

/*
 * Algorithm based on roce_resolve_route_from_path
 * Caller must hold a rv_conn reference. This func does not release that ref
 * Caller holds mutex and has validated sconn->state, caller will release mutex
 */
static int rv_resolve_ip(struct rv_sconn *sconn)
{
	union {
		struct sockaddr     _sockaddr;
		struct sockaddr_in  _sockaddr_in;
		struct sockaddr_in6 _sockaddr_in6;
	} src_addr, dst_addr;

	if (test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags))
		sconn->stats.reresolve++;
	else
		sconn->stats.resolve++;
	/*
	 * To avoid a upstream compiling warning by using the
	 * largest field in a union.
	 */
	rdma_gid2ip((struct sockaddr *)&src_addr._sockaddr_in6,
		    &sconn->primary_path->sgid);
	rdma_gid2ip((struct sockaddr *)&dst_addr._sockaddr_in6,
		    &sconn->primary_path->dgid);

	if (src_addr._sockaddr.sa_family != dst_addr._sockaddr.sa_family)
		return -EINVAL;

	memset(&sconn->dev_addr, 0, sizeof(sconn->dev_addr));
	sconn->dev_addr.net = &init_net; /* manditory, but will not be used */
	sconn->dev_addr.sgid_attr = sconn->parent->jdev->sgid_attr;

	return rdma_resolve_ip(&src_addr._sockaddr, &dst_addr._sockaddr,
				&sconn->dev_addr, RV_RESOLVER_TIMEOUT,
				rv_resolve_ip_cb, true, sconn);
}

/*
 * Gets connection establishment ball rolling
 * After this everything proceeds via callbacks or timeouts.
 * Caller must hold a rv_conn reference. This func does not release that ref.
 * Caller holds mutex and has validated sconn->state, caller will release mutex
 * For IB/OPA, no need to resolve IP to dmac, so move to next step.
 */
static void rv_resolve_path(struct rv_sconn *sconn)
{
	int ret;
	struct rv_job_dev *jdev = sconn->parent->jdev;

	rv_sconn_set_state(sconn, RV_RESOLVING, "", "", false);

	sconn->resolver_retry_left = RV_RESOLVER_RETRY;

	trace_rv_sconn_resolve(sconn, sconn->index, sconn->qp->qp_num,
			       sconn->parent, sconn->flags, (u32)sconn->state,
			       sconn->cm_id, sconn->resolver_retry_left);
	sconn->primary_path = kzalloc(sizeof(*sconn->primary_path), GFP_KERNEL);
	if (!sconn->primary_path)
		goto err;

	/* this sets record type to IB or OPA, fix up below for RoCE */
	ib_copy_path_rec_from_user(sconn->primary_path, &sconn->path);
	sconn->primary_path->service_id = cpu_to_be64(jdev->service_id);

	if (rv_jdev_protocol_roce(jdev)) {
		sconn->primary_path->rec_type =
			sa_conv_gid_to_pathrec_type(jdev->sgid_attr->gid_type);
		if (unlikely(!sa_path_is_roce(sconn->primary_path)))
			goto err;
		ret = rv_resolve_ip(sconn);
		if (ret)
			goto err;
		return;
	}
	rv_send_req(sconn);
	return;

err:
	if (test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags))
		sconn->stats.reresolve_fail++;
	else
		sconn->stats.resolve_fail++;
	rv_sconn_free_primary_path(sconn);
	rv_sconn_set_state(sconn, RV_ERROR, "local error resolving address",
			   "", false);
}

/* caller must hold a rv_conn reference. This func does not release that ref */
static void rv_send_req(struct rv_sconn *sconn)
{
	struct rv_job_dev *jdev = sconn->parent->jdev;
	struct ib_cm_req_param req;
	struct rv_req_priv_data req_priv = {
			.magic = RV_PRIVATE_DATA_MAGIC,
			.ver = RV_PRIVATE_DATA_VER,
		};
	int ret;

	memset(&req, 0, sizeof(req));
	req.ppath_sgid_attr = jdev->sgid_attr;
	req.flow_control = 1;
	req.retry_count = 7;
	req.responder_resources = 0;
	req.rnr_retry_count = 7;
	req.max_cm_retries = 15;
	req.primary_path = sconn->primary_path;
	req.service_id = req.primary_path->service_id;
	req.initiator_depth = 0;
	req.remote_cm_response_timeout = 17;
	req.local_cm_response_timeout = 17;
	req.qp_num = sconn->qp->qp_num;
	req.qp_type = sconn->qp->qp_type;
	req.srq = !!(sconn->qp->srq);
	req.starting_psn = get_random_u32() & 0xffffff;

	req.private_data = &req_priv;
	req.private_data_len = sizeof(req_priv);
	req_priv.index = sconn->index;
	req_priv.job_key_len = jdev->job_key_len;
	memcpy(req_priv.job_key, jdev->job_key, sizeof(req_priv.job_key));
	req_priv.uid = jdev->uid;
	trace_rv_msg_send_req(sconn, sconn->index,
			      "sending rec_type | route_resolved, dmac",
			      (u64)(req.primary_path->rec_type |
			      (((u64)req.primary_path->roce.route_resolved) <<
			       31)),
			      (u64)(req.primary_path->roce.dmac[0] |
			      ((u64)req.primary_path->roce.dmac[1]) << 8 |
			      ((u64)req.primary_path->roce.dmac[2]) << 16 |
			      ((u64)req.primary_path->roce.dmac[3]) << 24 |
			      ((u64)req.primary_path->roce.dmac[4]) << 32 |
			      ((u64)req.primary_path->roce.dmac[5]) << 40));

	ret = ib_send_cm_req(sconn->cm_id, &req);
	rv_sconn_free_primary_path(sconn);
	if (!ret) {
		sconn->stats.req_sent++;
		trace_rv_msg_send_req(sconn, sconn->index, "Sending REQ", 0,
				      (u64)sconn);
		rv_sconn_set_state(sconn, RV_CONNECTING, "", "", false);
	} else {
		rv_conn_err(sconn, "Failed to send cm req. %d\n", ret);
		rv_sconn_set_state(sconn, RV_ERROR, "local error sending REQ",
				   "", false);
	}
}

/*
 * called on work queue with rv_conn reference held on our behalf
 * if in CONNECTING:
 *	IB CM listener could have a rep outstanding, REJ cancels it,
 *	or we could have sent or gotten RTU and raced with CM cb.
 *	Tell IB CM to send REJ and DREQ, it will sort things out for us.
 * if already in CONNECTED do nothing, we got in just under the timelimit.
 */
static void rv_sconn_timeout_work(struct work_struct *work)
{
	struct rv_sconn *sconn = container_of(work, struct rv_sconn,
					      timer_work);
	struct rv_rej_priv_data rej_priv = {
		.magic = RV_PRIVATE_DATA_MAGIC,
		.ver = RV_PRIVATE_DATA_VER,
		.reason = RV_REJ_REASON_CONN_TIMEOUT,
		.recoverable = 0,
	};
	struct rv_dreq_priv_data dreq_priv = {
		.magic = RV_PRIVATE_DATA_MAGIC,
		.ver = RV_PRIVATE_DATA_VER,
		.reason = RV_DREQ_REASON_CONN_TIMEOUT,
		.recoverable = 0,
	};

	mutex_lock(&sconn->mutex);
	trace_rv_sconn_timeout_work(sconn, sconn->index,
				    sconn->qp ? sconn->qp->qp_num : 0,
				    sconn->parent, sconn->flags,
				    (u32)sconn->state, sconn->cm_id,
				    sconn->resolver_retry_left);
	switch (sconn->state) {
	case RV_RESOLVING:
		rv_sconn_free_primary_path(sconn);
		rdma_addr_cancel(&sconn->dev_addr);
		rv_sconn_set_state(sconn, RV_ERROR, "connection timeout", "",
				   false);
		break;
	case RV_CONNECTING:
		if (!ib_send_cm_rej(sconn->cm_id, IB_CM_REJ_TIMEOUT, NULL, 0,
				    &rej_priv, sizeof(rej_priv))) {
			sconn->stats.rej_sent++;
			trace_rv_msg_sconn_timeout_work(sconn, sconn->index,
							"Sending REJ reason",
							(u64)IB_CM_REJ_TIMEOUT,
							(u64)sconn);
		}
		if (!ib_send_cm_dreq(sconn->cm_id, &dreq_priv,
				     sizeof(dreq_priv))) {
			sconn->stats.dreq_sent++;
			trace_rv_msg_sconn_timeout_work(sconn, sconn->index,
							"Sending DREQ", 0,
							(u64)sconn);
		}
		fallthrough;
	case RV_WAITING:
	case RV_DISCONNECTING:
	case RV_DELAY:
		rv_sconn_set_state(sconn, RV_ERROR, "connection timeout", "",
				   false);
		break;
	case RV_CONNECTED:
		break;
	case RV_INIT:
	case RV_ERROR:
	default:
		break;
	}
	mutex_unlock(&sconn->mutex);

	rv_conn_put(sconn->parent);
}

/* called at SOFT IRQ,  so real work in WQ */
static void rv_sconn_timeout_func(struct timer_list *timer)
{
	struct rv_sconn *sconn = container_of(timer, struct rv_sconn,
					      conn_timer);

	if (!sconn->parent)
		return;
	if (rv_conn_get_check(sconn->parent))
		return;
	rv_queue_work(&sconn->timer_work);
}

/* called on work queue with rv_conn reference held on our behalf */
static void rv_sconn_delay_work(struct work_struct *work)
{
	struct rv_sconn *sconn = container_of(work, struct rv_sconn,
					      delay_work);

	mutex_lock(&sconn->mutex);
	trace_rv_sconn_delay_work(sconn, sconn->index,
				  sconn->qp ? sconn->qp->qp_num : 0,
				  sconn->parent, sconn->flags,
				  (u32)sconn->state, sconn->cm_id,
				  sconn->resolver_retry_left);
	if (sconn->state == RV_DELAY)
		rv_resolve_path(sconn);
	mutex_unlock(&sconn->mutex);

	rv_conn_put(sconn->parent);
}

/* called at SOFT IRQ,  so real work in WQ */
static void rv_sconn_delay_func(struct timer_list *timer)
{
	struct rv_sconn *sconn = container_of(timer, struct rv_sconn,
					      delay_timer);

	if (!sconn->parent)
		return;
	if (rv_conn_get_check(sconn->parent))
		return;
	rv_queue_work(&sconn->delay_work);
}

/*
 * validate cm_connect path against sconn->path
 */
static int rv_sconn_connect_check_path(int rv_inx, const struct rv_sconn *sconn,
				       const struct ib_user_path_rec *path)
{
	char buf1[RV_MAX_ADDR_STR];
	char buf2[RV_MAX_ADDR_STR];
	int ret = -EEXIST;

#define RV_CHECK(field) (path->field != sconn->path.field)
#define RV_REPORT(field, text, format) \
		     rv_err(rv_inx, "connect: inconsistent " text " " format \
			    " with other processes " format "\n", \
			    path->field, sconn->path.field)

	if (RV_CHECK(dlid))
		RV_REPORT(dlid, "DLID", "0x%x");
	else if (cmp_gid(path->dgid, sconn->path.dgid))
		rv_err(rv_inx,
		       "connect: inconsistent dest %s with other proc %s\n",
		       show_gid(buf1, sizeof(buf1), path->dgid),
		       show_gid(buf2, sizeof(buf2), sconn->path.dgid));
	else if (RV_CHECK(slid))
		RV_REPORT(slid, "SLID", "0x%x");
	else if (cmp_gid(path->sgid, sconn->path.sgid))
		rv_err(rv_inx,
		       "connect: inconsistent src %s with other processes %s\n",
		       show_gid(buf1, sizeof(buf1), path->sgid),
		       show_gid(buf2, sizeof(buf2), sconn->path.sgid));
	else if (RV_CHECK(pkey))
		RV_REPORT(pkey, "pkey", "0x%x");
	else if (RV_CHECK(mtu))
		RV_REPORT(pkey, "mtu", "%u");
	else if (RV_CHECK(sl))
		RV_REPORT(sl, "SL", "%u");
	else if (RV_CHECK(traffic_class))
		RV_REPORT(traffic_class, "traffic_class", "%u");
	else if (RV_CHECK(flow_label))
		RV_REPORT(flow_label, "flow_label", "0x%x");
	else if (RV_CHECK(rate))
		RV_REPORT(rate, "rate", "%u");
	else if (RV_CHECK(hop_limit))
		RV_REPORT(hop_limit, "hop_limit", "%u");
	else if (RV_CHECK(packet_life_time))
		RV_REPORT(packet_life_time, "packet_life_time", "%u");
#undef RV_CHECK
#undef RV_REPORT
	else
		ret = 0;
	return ret;
}

/*
 * start connection and wait for client side to complete
 * caller must hold a rv_conn reference. This func does not release that ref
 * We use sconn->path.dlid to identify the 1st connect call for the given sconn
 * On subsequent calls we only need to check params match existing.
 */
static int rv_sconn_connect(int rv_inx, struct rv_sconn *sconn,
			    struct rv_conn_connect_params_in *params)
{
	struct rv_job_dev *jdev = sconn->parent->jdev;
	int ret = 0;
	struct ib_cm_id *id;

	mutex_lock(&sconn->mutex);

	if (!sconn->path.dlid)
		sconn->path = params->path;

	if (sconn->state != RV_INIT) {
		ret = rv_sconn_connect_check_path(rv_inx, sconn,
						  &params->path);
		mutex_unlock(&sconn->mutex);
		return ret;
	}

	sconn->path = params->path;

	id = ib_create_cm_id(jdev->dev->ib_dev, rv_cm_handler, sconn);
	if (IS_ERR(id)) {
		rv_err(rv_inx, "Create CM ID failed\n");
		rv_sconn_set_state(sconn, RV_ERROR,
				   "local error preparing client", "", false);
		mutex_unlock(&sconn->mutex);
		return PTR_ERR(id);
	}
	sconn->cm_id = id;

	rv_resolve_path(sconn);
	mutex_unlock(&sconn->mutex);
	return ret;
}

/*
 * validate rv_user supplied path is consistent with conn->ah from create_conn
 * sgid already checked against jdev in caller
 */
static int rv_conn_connect_check_ah(int rv_inx, const struct rv_conn *conn,
				    const struct ib_user_path_rec *path)
{
	char buf1[RV_MAX_ADDR_STR];
	char buf2[RV_MAX_ADDR_STR];
	int ret = -EINVAL;

#define RV_CHECK(f1, f2) (path->f1 != conn->ah.f2)
#define RV_CHECK_BE32(f1, f2) (be32_to_cpu(path->f1) != conn->ah.f2)
#define RV_REPORT(f1, f2, text, format) \
		     rv_err(rv_inx, "connect: inconsistent " text " " \
			    format " with create_conn " format "\n", \
			    path->f1, conn->ah.f2)
	if (be16_to_cpu(path->dlid) != conn->ah.dlid)
		rv_err(rv_inx,
		       "connect: inconsistent DLID 0x%x with create_conn 0x%x\n",
		       be16_to_cpu(path->dlid), conn->ah.dlid);
	else if (conn->ah.is_global &&
		 cmp_gid(conn->ah.grh.dgid, path->dgid))
		rv_err(rv_inx,
		       "connect: inconsistent dest %s with other proc %s\n",
		       show_gid(buf1, sizeof(buf1), path->dgid),
		       show_gid(buf2, sizeof(buf2), conn->ah.grh.dgid));
	else if (RV_CHECK(sl, sl))
		RV_REPORT(sl, sl, "SL", "%u");
	else if (conn->ah.is_global &&
		 RV_CHECK(traffic_class, grh.traffic_class))
		RV_REPORT(traffic_class, grh.traffic_class, "traffic_class",
			  "%u");
	else if (conn->ah.is_global &&
		 RV_CHECK_BE32(flow_label, grh.flow_label))
		RV_REPORT(flow_label, grh.flow_label, "flow_label", "0x%x");
	else if (conn->ah.is_global && RV_CHECK(hop_limit, grh.hop_limit))
		RV_REPORT(hop_limit, grh.hop_limit, "hop_limit", "%u");
	else if (RV_CHECK(rate, static_rate))
		RV_REPORT(rate, static_rate, "rate", "%u");
	else
		ret = 0;
#undef RV_CHECK
#undef RV_CHECK_BE32
#undef RV_REPORT
	return ret;
}

static int rv_conn_connect(int rv_inx, struct rv_conn *conn,
			   struct rv_conn_connect_params_in *params)
{
	int i;
	int ret;

	trace_rv_conn_connect(conn, conn->rem_addr, conn->ah.is_global,
			      conn->ah.dlid,
			      be64_to_cpu(*((__be64 *)&conn->ah.grh.dgid[0])),
			      be64_to_cpu(*((__be64 *)&conn->ah.grh.dgid[8])),
			      conn->num_conn, conn->next,
			      conn->jdev, kref_read(&conn->kref));

	ret = rv_conn_connect_check_ah(rv_inx, conn, &params->path);
	if (ret)
		return ret;

	for (i = 0; i < conn->num_conn; i++) {
		ret = rv_sconn_connect(rv_inx, &conn->sconn_arr[i], params);
		if (ret)
			return ret;
	}
	return 0;
}

/* validate connect against jdev->ah */
static int rv_jdev_check_connect_path(int rv_inx, const struct rv_job_dev *jdev,
				      const struct ib_user_path_rec *path)
{
	char buf1[RV_MAX_ADDR_STR];
	char buf2[RV_MAX_ADDR_STR];

	if (cmp_gid(path->sgid, jdev->loc_gid)) {
		rv_err(rv_inx, "connect: inconsistent src %s with attach %s\n",
		       show_gid(buf1, sizeof(buf1), path->sgid),
		       show_gid(buf2, sizeof(buf2), jdev->loc_gid));
		return -EINVAL;
	}
	return 0;
}

/*
 * PSM gurantees that both sides have created their connection prior to
 * either trying to connect it.
 */
int doit_conn_connect(struct rv_user *rv, unsigned long arg)
{
	struct rv_conn_connect_params_in params;
	struct rv_conn *conn;
	int ret = 0;

	if (copy_from_user(&params, (void __user *)arg, sizeof(params)))
		return -EFAULT;

	mutex_lock(&rv->mutex);
	if (rv->state != RV_USER_ATTACHED) {
		ret = (rv->state == RV_USER_WAS_ATTACHED) ? -ENXIO : -EINVAL;
		goto unlock;
	}
	if (rv->rdma_mode != RV_RDMA_MODE_KERNEL) {
		ret = -EINVAL;
		goto unlock;
	}
	ret = rv_jdev_check_connect_path(rv->inx, rv->jdev, &params.path);
	if (ret)
		goto unlock;
	conn = user_conn_find(rv, params.handle);
	if (!conn) {
		rv_err(rv->inx, "connect: No connection found\n");
		ret = -EINVAL;
		goto unlock;
	}
	trace_rv_msg_uconn_connect(rv->inx, "rv_user connect", (u64)conn, 0);

	ret = rv_conn_connect(rv->inx, conn, &params);
	if (ret) {
		rv_err(rv->inx, "Failed to connect to server: %d\n", ret);
		xa_erase(&rv->conn_xa, params.handle);
		rv_conn_put(conn);
	}
unlock:
	mutex_unlock(&rv->mutex);

	return ret;
}

int doit_conn_connected(struct rv_user *rv, unsigned long arg)
{
	struct rv_conn_connected_params_in params;
	struct rv_conn *conn;
	int ret = 0;

	if (copy_from_user(&params, (void __user *)arg, sizeof(params)))
		return -EFAULT;

	mutex_lock(&rv->mutex);
	conn = user_conn_find(rv, params.handle);
	if (!conn) {
		rv_err(rv->inx, "connect: No connection found\n");
		ret = -EINVAL;
		goto unlock;
	}

	ret = rv_conn_connected(conn);
unlock:
	mutex_unlock(&rv->mutex);

	return ret;
}

int doit_conn_get_conn_count(struct rv_user *rv, unsigned long arg)
{
	struct rv_conn_get_conn_count_params params;
	struct rv_conn *conn;
	struct rv_sconn *sconn;
	int ret = 0;
	u8 index;

	if (copy_from_user(&params.in, (void __user *)arg, sizeof(params.in)))
		return -EFAULT;

	mutex_lock(&rv->mutex);
	if (rv->state != RV_USER_ATTACHED) {
		ret = (rv->state == RV_USER_WAS_ATTACHED) ? -ENXIO : -EINVAL;
		goto unlock;
	}
	if (rv->rdma_mode != RV_RDMA_MODE_KERNEL) {
		ret = -EINVAL;
		goto unlock;
	}

	conn = user_conn_find(rv, params.in.handle);
	if (!conn) {
		rv_err(rv->inx, "get_conn_count: No connection found\n");
		ret = -EINVAL;
		goto unlock;
	}
	if (params.in.index >= conn->num_conn) {
		rv_err(rv->inx, "get_conn_count: Invalid index: %d\n",
		       params.in.index);
		ret = -EINVAL;
		goto unlock;
	}
	index = array_index_nospec(params.in.index, conn->num_conn);

	sconn = &conn->sconn_arr[index];

	mutex_lock(&sconn->mutex);
	if (sconn->state == RV_ERROR)
		ret = -EIO;
	else
		params.out.count = sconn->stats.conn_recovery +
				   (test_bit(RV_SCONN_WAS_CONNECTED,
					     &sconn->flags) ? 1 : 0);
	mutex_unlock(&sconn->mutex);
	if (ret)
		goto unlock;

	if (copy_to_user((void __user *)arg, &params.out, sizeof(params.out)))
		ret = -EFAULT;
unlock:
	mutex_unlock(&rv->mutex);

	return ret;
}

static void rv_sconn_add_stats(struct rv_sconn *sconn,
			       struct rv_conn_get_stats_params *params)
{
	mutex_lock(&sconn->mutex);
	params->out.num_conn++;
	if (test_bit(RV_SCONN_SERVER, &sconn->flags))
		params->out.flags |= RV_CONN_STAT_FLAG_SERVER;
	else
		params->out.flags |= RV_CONN_STAT_FLAG_CLIENT;
	if (!test_bit(RV_SCONN_WAS_CONNECTED, &sconn->flags))
		params->out.flags &= ~RV_CONN_STAT_FLAG_WAS_CONNECTED;

#define RV_ADD_CM_EVT_STAT(sconn, params, s, evt) \
	((params)->out.s += (sconn)->stats.cm_evt_cnt[evt])

#define RV_ADD_STAT(sconn, params, s) \
	((params)->out.s += (sconn)->stats.s)

#define RV_ADD_ATOMIC_STAT(sconn, params, s) \
	((params)->out.s += atomic_read(&(sconn)->stats.s))

#define RV_ADD_ATOMIC64_STAT(sconn, params, s) \
	((params)->out.s += atomic64_read(&(sconn)->stats.s))

#define RV_MAX_STAT(sconn, params, s) \
	((params)->out.s = max((params)->out.s, (sconn)->stats.s))

	RV_ADD_CM_EVT_STAT(sconn, params, req_error, IB_CM_REQ_ERROR);
	RV_ADD_CM_EVT_STAT(sconn, params, rep_error, IB_CM_REP_ERROR);
	RV_ADD_CM_EVT_STAT(sconn, params, rep_recv, IB_CM_REP_RECEIVED);
	RV_ADD_CM_EVT_STAT(sconn, params, rtu_recv, IB_CM_RTU_RECEIVED);
	RV_ADD_CM_EVT_STAT(sconn, params, established, IB_CM_USER_ESTABLISHED);
	RV_ADD_CM_EVT_STAT(sconn, params, dreq_error, IB_CM_DREQ_ERROR);
	RV_ADD_CM_EVT_STAT(sconn, params, dreq_recv, IB_CM_DREQ_RECEIVED);
	RV_ADD_CM_EVT_STAT(sconn, params, drep_recv, IB_CM_DREP_RECEIVED);
	RV_ADD_CM_EVT_STAT(sconn, params, timewait, IB_CM_TIMEWAIT_EXIT);
	RV_ADD_CM_EVT_STAT(sconn, params, mra_recv, IB_CM_MRA_RECEIVED);
	RV_ADD_CM_EVT_STAT(sconn, params, rej_recv, IB_CM_REJ_RECEIVED);
	RV_ADD_CM_EVT_STAT(sconn, params, lap_error, IB_CM_LAP_ERROR);
	RV_ADD_CM_EVT_STAT(sconn, params, lap_recv, IB_CM_LAP_RECEIVED);
	RV_ADD_CM_EVT_STAT(sconn, params, apr_recv, IB_CM_APR_RECEIVED);
	RV_ADD_CM_EVT_STAT(sconn, params, unexp_event, RV_CM_EVENT_UNEXP);

	RV_ADD_STAT(sconn, params, req_sent);
	RV_ADD_STAT(sconn, params, rep_sent);
	RV_ADD_STAT(sconn, params, rtu_sent);
	RV_ADD_STAT(sconn, params, rej_sent);
	RV_ADD_STAT(sconn, params, dreq_sent);
	RV_ADD_STAT(sconn, params, drep_sent);

	RV_MAX_STAT(sconn, params, wait_time);
	RV_MAX_STAT(sconn, params, resolve_time);
	RV_MAX_STAT(sconn, params, connect_time);
	RV_MAX_STAT(sconn, params, connected_time);
	RV_ADD_STAT(sconn, params, resolve);
	RV_ADD_STAT(sconn, params, resolve_fail);
	RV_ADD_STAT(sconn, params, conn_recovery);
	RV_MAX_STAT(sconn, params, rewait_time);
	RV_MAX_STAT(sconn, params, reresolve_time);
	RV_MAX_STAT(sconn, params, reconnect_time);
	RV_MAX_STAT(sconn, params, max_rewait_time);
	RV_MAX_STAT(sconn, params, max_reresolve_time);
	RV_MAX_STAT(sconn, params, max_reconnect_time);
	RV_ADD_STAT(sconn, params, reresolve);
	RV_ADD_STAT(sconn, params, reresolve_fail);
	RV_ADD_STAT(sconn, params, post_write);
	RV_ADD_STAT(sconn, params, post_write_fail);
	RV_ADD_STAT(sconn, params, post_write_bytes);
	RV_ADD_STAT(sconn, params, post_hb);
	RV_ADD_STAT(sconn, params, post_hb_fail);

	RV_ADD_ATOMIC_STAT(sconn, params, outstand_send_write);
	RV_ADD_ATOMIC64_STAT(sconn, params, send_write_cqe);
	RV_ADD_ATOMIC64_STAT(sconn, params, send_write_cqe_fail);
	RV_ADD_ATOMIC64_STAT(sconn, params, recv_write_cqe);
	RV_ADD_ATOMIC64_STAT(sconn, params, recv_write_bytes);
	RV_ADD_ATOMIC64_STAT(sconn, params, recv_cqe_fail);
	RV_ADD_ATOMIC64_STAT(sconn, params, send_hb_cqe);
	RV_ADD_ATOMIC64_STAT(sconn, params, send_hb_cqe_fail);
	RV_ADD_ATOMIC64_STAT(sconn, params, recv_hb_cqe);
#undef RV_ADD_CM_EVT_STAT
#undef RV_ADD_STAT
#undef RV_ADD_ATOMIC_STAT
#undef RV_ADD_ATOMIC64_STAT
#undef RV_MAX_STAT
	mutex_unlock(&sconn->mutex);
}

/* add up all the stats for sconns in given conn */
static void rv_conn_add_stats(struct rv_conn *conn,
			      struct rv_conn_get_stats_params *params)
{
	int i;

	for (i = 0; i < conn->num_conn; i++)
		rv_sconn_add_stats(&conn->sconn_arr[i], params);
}

int doit_conn_get_stats(struct rv_user *rv, unsigned long arg)
{
	struct rv_conn_get_stats_params params;
	struct rv_conn *conn;
	int ret = 0;
	u8 index;

	if (copy_from_user(&params.in, (void __user *)arg, sizeof(params.in)))
		return -EFAULT;

	mutex_lock(&rv->mutex);
	if (rv->state != RV_USER_ATTACHED) {
		ret = (rv->state == RV_USER_WAS_ATTACHED) ? -ENXIO : -EINVAL;
		goto unlock;
	}
	if (rv->rdma_mode != RV_RDMA_MODE_KERNEL) {
		ret = -EINVAL;
		goto unlock;
	}

	if (params.in.handle) {
		conn = user_conn_find(rv, params.in.handle);
		if (!conn) {
			rv_err(rv->inx,
			       "conn_get_stats: No connection found\n");
			ret = -EINVAL;
			goto unlock;
		}
		index = params.in.index;

		memset(&params, 0, sizeof(params));
		params.out.flags = RV_CONN_STAT_FLAG_WAS_CONNECTED;
		params.out.index = index;

		if (index == RV_CONN_STATS_AGGREGATE) {
			rv_conn_add_stats(conn, &params);
		} else if (index >= conn->num_conn) {
			ret = -EINVAL;
			goto unlock;
		} else {
			index = array_index_nospec(index, conn->num_conn);
			rv_sconn_add_stats(&conn->sconn_arr[index], &params);
		}
	} else {
		XA_STATE(xas, &rv->conn_xa, 0);

		memset(&params, 0, sizeof(params));
		params.out.flags = RV_CONN_STAT_FLAG_WAS_CONNECTED;
		params.out.index =  RV_CONN_STATS_AGGREGATE;

		xas_for_each(&xas, conn, UINT_MAX)
			rv_conn_add_stats(conn, &params);
	}

	if (copy_to_user((void __user *)arg, &params.out, sizeof(params.out)))
		ret = -EFAULT;
unlock:
	mutex_unlock(&rv->mutex);

	return ret;
}

/*
 * We have a rv_conn reference for the heartbeat cqe
 * We let QP Async Event callback handle the errors for us.
 * Note: rv_conn_put can put rv_job_dev and trigger whole job cleanup
 */
static void rv_hb_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct rv_sconn *sconn = container_of(wc->wr_cqe,
					      struct rv_sconn, hb_cqe);

	trace_rv_wc_hb_done((u64)sconn, wc->status, wc->opcode, wc->byte_len,
			    0);
	trace_rv_sconn_hb_done(sconn, sconn->index,
			       sconn->qp ? sconn->qp->qp_num : 0,
			       sconn->parent, sconn->flags,
			       (u32)sconn->state, 0);

	if (wc->status) {
		rv_report_cqe_error(cq, wc, sconn, "Heartbeat");
		atomic64_inc(&sconn->stats.send_hb_cqe_fail);
	} else {
		struct rv_job_dev *jdev = sconn->parent->jdev;

		WARN_ON(wc->qp != sconn->qp);
		atomic64_inc(&sconn->stats.send_hb_cqe);
		sconn->hb_timer.expires = jiffies +
					  msecs_to_jiffies(jdev->hb_interval);
		add_timer(&sconn->hb_timer);
	}

	rv_conn_put(sconn->parent);
}

/*
 * issue HB WQE as needed.
 * if there has been activity, no need for a new HB packet
 * called on work queue with rv_conn reference held on our behalf
 */
static void rv_sconn_hb_work(struct work_struct *work)
{
	struct rv_sconn *sconn = container_of(work, struct rv_sconn, hb_work);
	struct ib_send_wr swr = {
			.opcode	= IB_WR_SEND,
			.wr_cqe	= &sconn->hb_cqe,
			.send_flags = IB_SEND_SIGNALED,
	};
	u64 old_act_count;
	int ret;

	mutex_lock(&sconn->mutex);

	if (sconn->state != RV_CONNECTED)
		goto unlock;

	old_act_count =  sconn->act_count;
	sconn->act_count = sconn->stats.post_write +
			   atomic64_read(&sconn->stats.recv_write_cqe) +
			   atomic64_read(&sconn->stats.recv_hb_cqe);
	if (sconn->act_count > old_act_count) {
		struct rv_job_dev *jdev = sconn->parent->jdev;

		sconn->hb_timer.expires = jiffies +
					  msecs_to_jiffies(jdev->hb_interval);
		add_timer(&sconn->hb_timer);
		goto unlock;
	}

	trace_rv_sconn_hb_post(sconn, sconn->index, sconn->qp->qp_num,
			       sconn->parent, sconn->flags,
			       (u32)sconn->state, 0);
	rv_conn_get(sconn->parent);
	ret = ib_post_send(sconn->qp, &swr, NULL);
	if (ret) {
		sconn->stats.post_hb_fail++;
		rv_conn_err(sconn, "failed to send hb: post %d\n", ret);
		rv_conn_put(sconn->parent);
	} else {
		sconn->stats.post_hb++;
	}

unlock:
	mutex_unlock(&sconn->mutex);

	rv_conn_put(sconn->parent);
}

/* called at SOFT IRQ,  so real work in WQ */
static void rv_sconn_hb_func(struct timer_list *timer)
{
	struct rv_sconn *sconn = container_of(timer, struct rv_sconn, hb_timer);

	if (!sconn->parent)
		return;
	if (rv_conn_get_check(sconn->parent))
		return;
	rv_queue_work(&sconn->hb_work);
}

static void rv_listener_release(struct kref *kref)
{
	struct rv_listener *listener =
		container_of(kref, struct rv_listener, kref);
	struct rv_device *dev = listener->dev;
	unsigned long flags;

	spin_lock_irqsave(&dev->listener_lock, flags);
	list_del(&listener->listener_entry);
	spin_unlock_irqrestore(&dev->listener_lock, flags);

	ib_destroy_cm_id(listener->cm_id);

	rv_device_put(dev);
	kfree(listener);
}

void rv_listener_put(struct rv_listener *listener)
{
	trace_rv_listener_put(listener->dev->ib_dev->name,
			      be64_to_cpu(listener->cm_id->service_id),
			      kref_read(&listener->kref));
	kref_put(&listener->kref, rv_listener_release);
}

/*
 * only for use by rv_listener_get_alloc
 * all others must use rv_listener_get_alloc or rv_listener_get
 */
static struct rv_listener *rv_listener_alloc(struct rv_device *dev,
					     u64 service_id,
					     ib_cm_handler handler)
{
	struct rv_listener *listener;
	int ret;

	listener = kzalloc(sizeof(*listener), GFP_KERNEL);
	if (!listener)
		return NULL;

	listener->cm_id = ib_create_cm_id(dev->ib_dev, handler, listener);
	if (IS_ERR(listener->cm_id)) {
		rv_ptr_err("listener", listener, "Failed to create CM ID\n");
		goto err_free;
	}

#ifdef IB_CM_LISTEN_WITHOUT_MASK
	ret = ib_cm_listen(listener->cm_id, cpu_to_be64(service_id));
#else
	ret = ib_cm_listen(listener->cm_id, cpu_to_be64(service_id), 0);
#endif
	if (ret) {
		rv_ptr_err("listener", listener, "CM listen failed: %d\n", ret);
		goto err_cm;
	}
	rv_device_get(dev);
	listener->dev = dev;

	kref_init(&listener->kref);

	return listener;
err_cm:
	ib_destroy_cm_id(listener->cm_id);
err_free:
	kfree(listener);

	return NULL;
}

struct rv_listener *rv_listener_get_alloc(struct rv_device *dev, u64 service_id,
					  ib_cm_handler handler)
{
	unsigned long flags;
	struct rv_listener *entry = NULL;
	__be64 sid = cpu_to_be64(service_id);

	mutex_lock(&dev->listener_mutex);
	spin_lock_irqsave(&dev->listener_lock, flags);
	list_for_each_entry(entry, &dev->listener_list, listener_entry) {
		if (sid == entry->cm_id->service_id) {
			if (!kref_get_unless_zero(&entry->kref))
				continue;
			goto done;
		}
	}
	spin_unlock_irqrestore(&dev->listener_lock, flags);
	entry = rv_listener_alloc(dev, service_id, handler);
	if (!entry)
		goto unlock_mutex;
	trace_rv_listener_get(dev->ib_dev->name, service_id,
			      kref_read(&entry->kref));
	spin_lock_irqsave(&dev->listener_lock, flags);
	list_add(&entry->listener_entry, &dev->listener_list);

done:
	spin_unlock_irqrestore(&dev->listener_lock, flags);
unlock_mutex:
	mutex_unlock(&dev->listener_mutex);
	return entry;
}
