// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 Intel Corporation.
 */

#ifdef NVIDIA_GPU_DIRECT
#include "gpu.h"
#endif

#include "rv.h"
#include "trace.h"

unsigned int enable_user_mr;

module_param(enable_user_mr, uint, 0444);
MODULE_PARM_DESC(enable_user_mr, "Enable user mode MR caching");

static void rv_handle_user_mrs_put(struct work_struct *work);

#ifdef RV_REG_MR_PD_UOBJECT
/* XXX - should be in rv_job_dev */
struct mutex mr_pd_uobject_lock;
#endif

static bool rv_cache_mrc_filter(struct rv_mr_cached *mrc, unsigned long addr,
				unsigned long len, unsigned int acc);
static void rv_cache_mrc_get(struct rv_mr_cache *cache,
			     void *arg, struct rv_mr_cached *mrc);
static int rv_cache_mrc_put(struct rv_mr_cache *cache,
			    void *arg, struct rv_mr_cached *mrc);
static int rv_cache_mrc_invalidate(struct rv_mr_cache *cache,
				   void *arg, struct rv_mr_cached *mrc);
static int rv_cache_mrc_evict(struct rv_mr_cache *cache,
			      void *arg, struct rv_mr_cached *mrc,
			      void *evict_arg, bool *stop);

static const struct rv_mr_cache_ops rv_cache_ops = {
	.filter = rv_cache_mrc_filter,
	.get = rv_cache_mrc_get,
	.put = rv_cache_mrc_put,
	.invalidate = rv_cache_mrc_invalidate,
	.evict = rv_cache_mrc_evict
};

static struct ib_uverbs_file *get_ufile(struct rv_mem_params_in *minfo,
					struct fd *fd, int inx)
{
	struct fd f;
	struct file *filp;
	struct ib_uverbs_file *file;

	/* fd to "struct fd" */
	f = fdget(minfo->cmd_fd_int);

	/* "struct fd" to "struct file *" */
	filp = f.file;
	if (!filp) {
		rv_err(inx, "could not get file ptr from cmd_fd_int:%d\n",
		       minfo->cmd_fd_int);
		goto bail;
	}

	/* "struct file "* to "struct ib_uverbs_file *" */
	file = filp->private_data;
	if (!file) {
		rv_err(inx, "could not get file from file ptr cmd_fd_int:%d\n",
		       minfo->cmd_fd_int);
		goto bail;
	}

	memcpy(fd, &f, sizeof(f));
	return file;
bail:
	fdput(f);
	return NULL;
}

#ifdef RV_REG_MR_DISCRETE
/* never actually called, but just in case */
static void rv_reg_mr_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct rv_user_mrs *umrs = container_of(wc->wr_cqe,
					  struct rv_user_mrs, req_cqe);
	/*enum ib_wc_status status = wc->status;*/

	trace_rv_wc_reg_mr_done((u64)umrs, wc->status, wc->opcode,
				wc->byte_len, wc->ex.imm_data);
	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		rv_err(umrs->rv_inx, "reg_mr request failed\n");
	} else if (unlikely(wc->opcode != IB_WC_REG_MR)) {
		rv_err(umrs->rv_inx, "Recv bad opcode\n");
		/*status = IB_WC_LOC_QP_OP_ERR;*/
	}

	/* Set the completion status */
	/*umrs->status = status;*/
	/*complete(&umrs->done);*/
}

static void rv_inv_rkey_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct rv_user_mrs *umrs = container_of(wc->wr_cqe, struct rv_user_mrs,
						dummy_cqe);
	enum ib_wc_status status = wc->status;

	trace_rv_wc_inv_rkey_done((u64)umrs, wc->status, wc->opcode,
				  wc->byte_len, wc->ex.imm_data);
	if (unlikely(wc->status != IB_WC_SUCCESS))
		rv_err(umrs->rv_inx, "inv_rkey request failed\n");
	/* We are receiving opcode IB_WC_RECV (0x800) */

	/* Set the completion status */
	umrs->status = status;
	complete(&umrs->done);
}
#endif /*RV_REG_MR_DISCRETE*/

#ifdef RV_REG_MR_DISCRETE
static int rv_inv_rkey(struct rv_user_mrs *umrs, u32 rkey)
{
	struct ib_send_wr wr;
	const struct ib_send_wr *bad_send_wr;

	umrs->dummy_cqe.done = rv_inv_rkey_done;
	wr.wr_cqe = &umrs->dummy_cqe;
	wr.opcode = IB_WR_LOCAL_INV;
	wr.next = NULL;
	wr.num_sge = 0;
	wr.send_flags = IB_SEND_SIGNALED;
	wr.ex.invalidate_rkey = rkey;

	return ib_post_send(umrs->qp, &wr, &bad_send_wr);
}

static int rv_send_reg_mr_req(struct rv_user_mrs *umrs, struct mr_info *mr,
			      struct rv_mem_params_in *minfo)
{
	int ret;
	struct ib_reg_wr wr;
	const struct ib_send_wr *bad_send_wr;

	memset(&wr, 0, sizeof(wr));
	init_completion(&umrs->done);
	umrs->status = IB_WC_SUCCESS;
	wr.wr.next = NULL;
	wr.wr.opcode = IB_WR_REG_MR;
	wr.wr.wr_cqe = &umrs->req_cqe;
	wr.wr.num_sge = 0;
	/*
	 * No send_completion event will be reported, which makes
	 * rv_reg_mr_done() useless.
	 */
	wr.wr.send_flags = 0;
	wr.mr = mr->ib_mr;
	wr.key = mr->ib_mr->rkey;
	wr.access = minfo->access & ~IBV_ACCESS_KERNEL;

	ret = ib_post_send(umrs->qp, &wr.wr, &bad_send_wr);
	if (unlikely(ret)) {
		rv_err(umrs->rv_inx, "Failed to send REG_MR req: %d\n", ret);
		return ret;
	}
	/*
	 * we get no completion for the REG_MR.
	 * On irdma (CVL), the send queue tail will not be advanced and we can
	 * send a LOCAL_INV request to get a completion event and reap the
	 * WQEs.
	 */
	ret = rv_inv_rkey(umrs, umrs->dummy_mr->rkey);
	if (unlikely(ret)) {
		rv_err(umrs->rv_inx, "Failed to send LOCAL_INV req: %d\n",
		       ret);
		return ret;
	}

	/* Wait for completion */
	ret = wait_for_completion_interruptible(&umrs->done);
	if (ret < 0) {
		rv_err(umrs->rv_inx, "Failed to wait for completion: %d", ret);
		ret = -EINTR;
	}
	if (umrs->status != IB_WC_SUCCESS) {
		rv_err(umrs->rv_inx, "REG_MR request failed: status 0x%x\n",
		       umrs->status);
		ret = -EFAULT;
	}

	return ret;
}
#endif /*RV_REG_MR_DISCRETE*/

#ifndef RV_REG_MR_PD_UOBJECT
static int rv_kern_reg_mem(struct rv_user_mrs *umrs,
			   struct rv_mem_params_in *minfo,
			   struct mr_info *mr)
{
	int ret = 0;
	unsigned int offset;
	int num;

	/* sanity check */
	if (!umrs->jdev)
		return -EINVAL;
	/* Set the kernel pd */
	mr->ib_pd = umrs->jdev->pd;
	/* For ucontext, only device and closing fields are relevant */
	mr->ucontext.device = umrs->jdev->pd->device;

	/*
	 * Pin and map the user buffer.
	 * XXX for GPU filter out IBV_ACCESS_IS_GPU_ADDR
	 */
	mr->umem = ib_umem_get(&mr->ucontext, (unsigned long)minfo->addr,
			       minfo->length,
			       minfo->access & ~IBV_ACCESS_KERNEL, 0);
	if (IS_ERR(mr->umem)) {
		rv_err(umrs->rv_inx, "Failed to get umem: %p\n", mr->umem);
		return -EFAULT;
	}
	trace_rv_mr_umem(mr->umem->address, mr->umem->length, mr->umem->nmap);

	/* Allocate a kernel mr */
	mr->ib_mr = ib_alloc_mr(umrs->jdev->pd, IB_MR_TYPE_MEM_REG,
				mr->umem->nmap);
	if (IS_ERR(mr->ib_mr)) {
		rv_err(umrs->rv_inx, "Failed to alloc kernel mr: %p\n",
		       mr->ib_mr);
		ret = -EFAULT;
		goto bail_umem;
	}

	/* Bind the kernel mr with the mapped user buffer */
	offset = mr->umem->address & (PAGE_SIZE - 1);
	num = ib_map_mr_sg(mr->ib_mr, mr->umem->sg_head.sgl,
			   mr->umem->nmap, &offset, PAGE_SIZE);
	if (num <= 0) {
		rv_err(umrs->rv_inx, "Failed to map mr_sg: %d\n", num);
		ret = -EFAULT;
		goto bail_mr;
	}
	/*
	 * XXX core/rw.c uses ib_map_mr_sg then builds a wqe to IB_WR_REG_MR
	 * ib_map_mr_sg says:  After this completes successfully, the
	 * memory region is ready for registration.
	 */

	/* Send the REG_MR request */
#ifdef RV_REG_MR_DISCRETE
	ret = rv_send_reg_mr_req(umrs, mr, minfo);
#endif
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to send REG_MR request: %d\n",
		       ret);
		goto bail_mr;
	}
	trace_rv_mr_info_kern_reg((unsigned long)minfo->addr,
				  minfo->length, minfo->access,
				  mr->ib_mr->lkey, mr->ib_mr->rkey,
				  mr->ib_mr->iova,
				  atomic_read(&mr->ib_pd->usecnt));
	return 0;
bail_mr:
	ib_dereg_mr(mr->ib_mr);
bail_umem:
	ib_umem_release(mr->umem);

	return ret;
}
#endif /* RV_REG_MR_PD_UOBJECT*/

/* caller must hold rv->mutex */
static int rv_drv_api_reg_mem(struct rv_user *rv,
			      struct rv_mem_params_in *minfo,
			      struct mr_info *mr)
{
	struct ib_pd *ib_pd;
#ifdef RV_REG_MR_PD_UOBJECT
	struct ib_pd *ib_pd_save = NULL;
#endif
	struct ib_mr *ib_mr;
	struct ib_uverbs_file *ufile;
#ifdef UVERBS_ATTR_BUNDLE_NO_UDATA
	struct ib_udata udata;
#else
	struct uverbs_attr_bundle attrs;
#endif
	int srcu_key;
	int ret = 0;

	mr->ib_mr = NULL;
	mr->ib_pd = NULL;

#ifdef NVIDIA_GPU_DIRECT
	if (minfo->access & IBV_ACCESS_IS_GPU_ADDR) {
		/* address is a gpu address - call into nvidia code */
		ret = get_gpu_pages((u64)minfo->addr, minfo->length,
				    &mr->page_table, NULL, mr);
				/* XXX s/NULL/gdrdrv_get_pages_free_callback */
		if (ret) {
			rv_err(rv->inx, "get_gpu_pages failed\n");
			return ret;
		}
		return -1;
	}
#endif /* NVIDIA_GPU_DIRECT */

	/*
	 * Check if the buffer is for kernel use. It should be noted that
	 * the ibv_pd_handle value "0" is a valid user space pd handle.
	 */
#ifdef RV_REG_MR_DISCRETE
	if (minfo->access & IBV_ACCESS_KERNEL)
		return rv_kern_reg_mem(rv->umrs, minfo, mr);
#endif
	/*
	 * we allow registering user MRs even when RDMA mode KERNEL.
	 * so must use rv_ib_dev() to access ib_dev.
	 */
#ifdef UVERBS_ATTR_BUNDLE_NO_UDATA
	memset(&udata, 0, sizeof(udata));
#else
	memset(&attrs, 0, sizeof(attrs));
#endif
	ufile = get_ufile(minfo, &mr->fd, rv->inx);
	if (!ufile)
		return -EFAULT;
	srcu_key = srcu_read_lock(&ufile->device->disassociate_srcu);
#ifdef UVERBS_ATTR_BUNDLE_NO_UDATA
	udata.inlen = minfo->ulen;
	if (minfo->ulen)
		udata.inbuf = minfo->udata;
	ib_pd = uobj_get_obj_read(pd, UVERBS_OBJECT_PD, minfo->ibv_pd_handle,
				  ufile);
#else
	attrs.ufile = ufile;
	attrs.driver_udata.inlen = minfo->ulen;
	if (minfo->ulen)
		attrs.driver_udata.inbuf = minfo->udata;

	ib_pd = uobj_get_obj_read(pd, UVERBS_OBJECT_PD, minfo->ibv_pd_handle,
				  &attrs);
#endif
	if (!ib_pd) {
		ret = -EINVAL;
		rv_err(rv->inx,
		       "could not get pd with fd:%d pd_handle:0x%x\n",
		       minfo->cmd_fd_int, minfo->ibv_pd_handle);
		goto out_unlock;
	}
#ifdef RV_REG_MR_PD_UOBJECT
	ib_pd_save = ib_pd;
#endif
	/*
	 * XXX this pd check is only use of rv required here, need rv for
	 * mode USER where umrs won't have a dev.
	 *
	 * for RV_REG_MR_PD_UOBJECT with kernel MR, don't need this,
	 * using jdev pd
	 */
	if (ib_pd->device != rv_ib_dev(rv)) {
		ret = -EINVAL;
		rv_err(rv->inx,
		       "mismatched devs: owner dev %p(%s) pd dev %p(%s)\n",
		       rv_ib_dev(rv),
		       rv_ib_dev(rv)->name,
		       ib_pd->device, ib_pd->device->name);
		goto err_put;
	}
#ifdef RV_REG_MR_PD_UOBJECT
	if (minfo->access & IBV_ACCESS_KERNEL) {
		/* sanity check */
		if (rv->rdma_mode != RV_RDMA_MODE_KERNEL || !rv->jdev) {
			rv_err(rv->inx, "kenel access in USER mode\n");
			ret = -EINVAL;
			goto err_put;
		}
		/*
		 * using minfo->addr as virt will be an issue for QP sharing
		 *
		 * pd->uobject - really not used in irdma, maybe put canned info
		 * in our rv->jdev->pd?
		 */
		mutex_lock(&mr_pd_uobject_lock);
		rv->jdev->pd->uobject = ib_pd->uobject;
		ib_pd = rv->jdev->pd;
	}
#endif

	/*
	 * XXX for GPU filter out IBV_ACCESS_IS_GPU_ADDR
	 *
	 * UVERBS_ATTR_BUNDLE_NO_UDATA is only applicable to SLES 15.1, which
	 * does not have HAVE_IB_DEVICE_OPS defined.
	 */
#ifdef HAVE_IB_DEVICE_OPS
	ib_mr = ib_pd->device->ops.reg_user_mr(ib_pd, (u64)minfo->addr,
					       minfo->length,
					       (u64)minfo->addr, minfo->access,
					       &attrs.driver_udata);
#else
	ib_mr = ib_pd->device->reg_user_mr(ib_pd, (u64)minfo->addr,
					   minfo->length,
					   (u64)minfo->addr, minfo->access,
#ifdef UVERBS_ATTR_BUNDLE_NO_UDATA
					   &udata);
#else
					   &attrs.driver_udata);
#endif
#endif
#ifdef RV_REG_MR_PD_UOBJECT
	if (minfo->access & IBV_ACCESS_KERNEL) {
		ib_pd->uobject = NULL;
		/* device->dereg_mr does not need the uobject */
		mutex_unlock(&mr_pd_uobject_lock);
	}
#endif
	if (IS_ERR(ib_mr)) {
		rv_err(rv->inx, "reg_user_mr failed\n");
		ret = PTR_ERR(mr);
		goto err_put;
	}

	ib_mr->device  = ib_pd->device;
	ib_mr->pd      = ib_pd;
	ib_mr->dm      = NULL;
	atomic_inc(&ib_pd->usecnt);
	trace_rv_mr_info_reg((unsigned long)minfo->addr,
			     minfo->length, minfo->access,
			     ib_mr->lkey, ib_mr->rkey, ib_mr->iova,
			     atomic_read(&ib_pd->usecnt));

	mr->ib_mr = ib_mr;
	mr->ib_pd = ib_pd;

err_put:
#ifdef RV_REG_MR_PD_UOBJECT
	uobj_put_obj_read(ib_pd_save);
#else
	uobj_put_obj_read(ib_pd);
#endif
out_unlock:
	srcu_read_unlock(&ufile->device->disassociate_srcu, srcu_key);
	return ret;
}

/*
 * This was created to be used in the event we want to skip releasing
 * ib_pd until after eviction; but it is dereg_mr that is causing the
 * issue during eviction.
 */
#ifdef NVIDIA_GPU_DIRECT
static int __rv_drv_api_dereg_mem(struct ib_device *ib_dev,
				  struct ib_mr *ib_mr, struct ib_pd *ib_pd,
				  struct fd *fd, void *addr, u64 length,
				  unsigned int access)
#else
static int __rv_drv_api_dereg_mem(struct ib_device *ib_dev,
				  struct ib_mr *ib_mr, struct ib_pd *ib_pd,
				  struct fd *fd)
#endif
{
	int ret;
#ifdef DEREG_MR_HAS_UDATA
	struct ib_udata udata;
#endif

#ifdef NVIDIA_GPU_DIRECT
	if (access & IBV_ACCESS_IS_GPU_ADDR) {
		rv_err(RV_INVALID, "fill in code here\n");
		return -1;
	}
#endif /* NVIDIA_GPU_DIRECT */

	if (!ib_mr)
		return 0;

#ifdef HAVE_IB_DEVICE_OPS
#ifdef DEREG_MR_HAS_UDATA
	memset(&udata, 0, sizeof(udata));
	ret = ib_dev->ops.dereg_mr(ib_mr, &udata);
#else
	ret = ib_dev->ops.dereg_mr(ib_mr);
#endif
#else
	ret = ib_dev->dereg_mr(ib_mr);
#endif
	if (ret)
		rv_err(RV_INVALID, "dereg_mr failed\n");

	if (ib_pd) {
		atomic_dec(&ib_pd->usecnt);
		fdput(*fd);
	}

	return ret;
}

#ifdef NVIDIA_GPU_DIRECT
int rv_drv_api_dereg_mem(struct mr_info *mr, void *addr, u64 length,
			 unsigned int access)
#else
int rv_drv_api_dereg_mem(struct mr_info *mr)
#endif
{
	int ret;
#ifdef NVIDIA_GPU_DIRECT

	trace_rv_mr_info_dereg(addr, length, access,
			       mr->ib_mr->lkey, mr->ib_mr->rkey,
			       mr->ib_mr->iova,
			       atomic_read(&mr->ib_pd->usecnt));
#else
	struct rv_mr_cached *mrc = container_of(mr, struct rv_mr_cached, mr);

	trace_rv_mr_info_dereg(mrc->addr, mrc->len, mrc->access,
			       mr->ib_mr->lkey, mr->ib_mr->rkey,
			       mr->ib_mr->iova,
			       atomic_read(&mr->ib_pd->usecnt));
#endif

#ifndef RV_REG_MR_PD_UOBJECT
	/* Check if we are dealing with kernel mr */
	if (mr->umem) {	 /* kernel MR */
		ret = ib_dereg_mr(mr->ib_mr);
		ib_umem_release(mr->umem);
		mr->umem = NULL;
	} else
#endif
	{
#ifdef NVIDIA_GPU_DIRECT
		ret = __rv_drv_api_dereg_mem(mr->ib_pd->device,
					     mr->ib_mr, mr->ib_pd, &mr->fd,
					     addr, length, access);
#else
		ret = __rv_drv_api_dereg_mem(mr->ib_pd->device,
					     mr->ib_mr, mr->ib_pd, &mr->fd);
#endif
	}
	if (!ret) {
		mr->ib_mr = NULL;
		mr->ib_pd = NULL;
	}
	return ret;
}

#ifdef RV_REG_MR_DISCRETE
static void rv_user_mrs_cq_event(struct ib_event *event, void *context)
{
	struct rv_user_mrs *umrs = (struct rv_user_mrs *)context;

	rv_err(umrs->rv_inx, "CQ Event 0x%x received\n", event->event);
}

static void rv_user_mrs_rc_qp_event(struct ib_event *event, void *context)
{
	struct rv_user_mrs *umrs = (struct rv_user_mrs *)context;

	rv_err(umrs->rv_inx, "QP Event 0x%x received\n", event->event);
}
#endif

#ifdef RV_REG_MR_DISCRETE
static void rv_user_mrs_destroy_rc_qp(struct rv_user_mrs *umrs)
{
	if (umrs->qp) {
		trace_rv_msg_destroy_rc_qp(umrs->rv_inx, umrs->jdev,
					   "Destroy kernel MRs rc qp",
					   (u64)umrs->qp->qp_num, 0);
		ib_destroy_qp(umrs->qp);
		umrs->qp = NULL;
	}

	if (umrs->recv_cq) {
		ib_free_cq(umrs->recv_cq);
		umrs->recv_cq = NULL;
	}

	if (umrs->send_cq) {
		ib_free_cq(umrs->send_cq);
		umrs->send_cq = NULL;
	}
}
#endif

#ifdef RV_REG_MR_DISCRETE
/*
 * local RC QP exclusively for REG_MR WQEs
 *
 * 1 QP per rv_user (in rv_user_mrs), no more than 1 REG_MR WQE outstanding
 * at a time
 */
static int rv_create_rc_qp(struct rv_user_mrs *umrs)
{
	struct ib_qp_init_attr init_attr;
	struct ib_qp_attr attr;
	int attr_mask = 0;
	int ret;
	struct ib_port_attr port_attr;
	union ib_gid gid;

	/* sanity check */
	if (!umrs->jdev)
		return -EINVAL;
	ret = ib_query_port(umrs->jdev->dev->ib_dev, umrs->jdev->port_num,
			    &port_attr);
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to query port: %d\n", ret);
		goto fail;
	}

	ret = rdma_query_gid(umrs->jdev->dev->ib_dev, umrs->jdev->port_num, 0,
			     &gid);
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to query gid: %d\n", ret);
		goto fail;
	}

	umrs->send_cq = ib_alloc_cq(umrs->jdev->dev->ib_dev, umrs, 10, 0,
				    IB_POLL_SOFTIRQ);
	if (IS_ERR(umrs->send_cq)) {
		rv_err(umrs->rv_inx, "Creating send cq failed\n");
		ret = -ENOMEM;
		goto fail;
	}
	umrs->send_cq.event_handler = rv_user_mrs_cq_event;

	umrs->recv_cq = ib_alloc_cq(umrs->jdev->dev->ib_dev, umrs, 10, 0,
				    IB_POLL_SOFTIRQ);
	if (IS_ERR(umrs->recv_cq)) {
		rv_err(umrs->rv_inx, "Creating recv cq failed\n");
		ret = -ENOMEM;
		goto fail;
	}
	umrs->recv_cq.event_handler = rv_user_mrs_cq_event;

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.event_handler = rv_user_mrs_rc_qp_event;
	init_attr.qp_context = umrs;
	init_attr.cap.max_send_wr = 400;
	init_attr.cap.max_recv_wr = 10;
	/* Setting max_recv_sge to 0 will fail on mlx5 */
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_sge = 1;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = umrs->send_cq;
	init_attr.recv_cq = umrs->recv_cq;

	umrs->qp = ib_create_qp(umrs->jdev->pd, &init_attr);
	if (IS_ERR(umrs->qp)) {
		ret = PTR_ERR(umrs->qp);
		rv_err(umrs->rv_inx, "Failed to create qp: 0x%x\n", ret);
		goto fail;
	}

	memset(&attr, 0, sizeof(attr));
	attr.port_num = umrs->jdev->port_num;
	attr.pkey_index = 0;
	attr.qp_state = IB_QPS_INIT;
	attr.qp_access_flags = IB_ACCESS_LOCAL_WRITE;
	attr_mask = IB_QP_STATE | IB_QP_PKEY_INDEX | IB_QP_PORT |
		    IB_QP_ACCESS_FLAGS;
	ret = ib_modify_qp(umrs->qp, &attr, attr_mask);
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to move qp into INIT: %d\n", ret);
		goto fail;
	}

	attr.qp_state = IB_QPS_RTR;
	memset(&attr.ah_attr, 0, sizeof(attr.ah_attr));
	attr.ah_attr.port_num = umrs->jdev->port_num;
	if (rdma_port_get_link_layer(umrs->jdev->dev->ib_dev,
				     umrs->jdev->port_num)
	    != IB_LINK_LAYER_ETHERNET) {
		attr.ah_attr.type = RDMA_AH_ATTR_TYPE_IB;
		attr.ah_attr.ib.src_path_bits = 0;
		attr.ah_attr.ib.dlid = port_attr.lid;
	} else {
		attr.ah_attr.ah_flags |= IB_AH_GRH;
		attr.ah_attr.type = RDMA_AH_ATTR_TYPE_ROCE;
		attr.ah_attr.grh.dgid = gid;
		attr.ah_attr.grh.sgid_index = 0;
		attr.ah_attr.grh.hop_limit = 0xFF;
	}
	attr.path_mtu = port_attr.active_mtu;
	attr.dest_qp_num = umrs->qp->qp_num;
	attr.rq_psn = 0;
	attr.max_dest_rd_atomic = 0;
	attr.min_rnr_timer = 14;
	attr_mask = IB_QP_STATE | IB_QP_AV | IB_QP_PATH_MTU |
		    IB_QP_DEST_QPN | IB_QP_RQ_PSN | IB_QP_MIN_RNR_TIMER |
		    IB_QP_MAX_DEST_RD_ATOMIC;
	ret = ib_modify_qp(umrs->qp, &attr, attr_mask);
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to move qp into RTR: %d\n", ret);
		goto fail;
	}

	attr.qp_state = IB_QPS_RTS;
	attr.sq_psn = 0;
	attr.max_rd_atomic = 0;
	attr.retry_cnt = 0;
	attr.rnr_retry = 0;
	attr.timeout = 14;
	attr_mask = IB_QP_STATE | IB_QP_SQ_PSN | IB_QP_MAX_QP_RD_ATOMIC |
		    IB_QP_RETRY_CNT | IB_QP_RNR_RETRY | IB_QP_TIMEOUT;
	ret = ib_modify_qp(umrs->qp, &attr, attr_mask);
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to move qp into RTS: %d\n", ret);
		goto fail;
	}
	trace_rv_msg_create_rc_qp(umrs->rv_inx, umrs->jdev, "RC qp is in RTS",
				  (u64)umrs->qp->qp_num, 0);
	return 0;
fail:
	rv_user_mrs_destroy_rc_qp(umrs);

	return ret;
}
#endif

/*
 * no need for rv->mutex, only rv_inx, rdma_mode and jdev are used.
 * however ok to hold rv->mutex
 */
struct rv_user_mrs *rv_user_mrs_alloc(struct rv_user *rv, u32 cache_size)
{
	int ret;
	struct rv_user_mrs *umrs;

	umrs = kzalloc(sizeof(*umrs), GFP_KERNEL);
	if (!umrs)
		return ERR_PTR(-ENOMEM);

	/*
	 * XXX May need to save current->mm earlier in device open and pass that
	 * instead
	 */
	umrs->rv_inx = rv->inx;
	ret =  rv_mr_cache_init(rv->inx, &umrs->cache, &rv_cache_ops, NULL,
				current->mm, cache_size);
	if (ret)
		goto bail_free;

	if (rv->rdma_mode == RV_RDMA_MODE_KERNEL) {
		/*
		 * for mode KERNEL the user_mrs object may survive past the
		 * rv_user close, so we need our own jdev reference to dereg
		 * MRs while outstanding send IOs complete.
		 * For mode USER, the MRs are using the user's pd
		 * and rv_user will free all MRs during close
		 *
		 * the jdev->pd we will use for MRs and QP needs ref to jdev
		 */
		rv_job_dev_get(rv->jdev);
		umrs->jdev = rv->jdev;
#ifdef RV_REG_MR_DISCRETE
		umrs->req_cqe.done = rv_reg_mr_done;
		/* Create the rc qp */
		ret = rv_create_rc_qp(umrs);
		if (ret) {
			rv_err(rv->inx, "Failed to create rc qp\n");
			goto fail;
		}
		umrs->dummy_cqe.done = rv_inv_rkey_done;
		umrs->dummy_mr = ib_alloc_mr(umrs->jdev->pd,
					     IB_MR_TYPE_MEM_REG, 5);
		if (ret) {
			rv_err(rv->inx, "Failed to alloc dummy mr\n");
			goto fail_qp;
		}
#endif
	}
	kref_init(&umrs->kref); /* refcount now 1 */
	INIT_WORK(&umrs->put_work, rv_handle_user_mrs_put);
	trace_rv_user_mrs_alloc(umrs->rv_inx, umrs->jdev,
				umrs->cache.total_size, umrs->cache.max_size,
				kref_read(&umrs->kref));

	return umrs;

#ifdef RV_REG_MR_DISCRETE
fail_qp:
	rv_user_mrs_destroy_rc_qp(umrs);
fail:	/* only get here for mode KERNEL */
	rv_mr_cache_deinit(rv->inx, &umrs->cache);
	rv_job_dev_put(umrs->jdev);
#endif
bail_free:
	kfree(umrs);
	return ERR_PTR(ret);
}

static void rv_user_mrs_release(struct rv_user_mrs *umrs)
{
	trace_rv_user_mrs_release(umrs->rv_inx, umrs->jdev,
				  umrs->cache.total_size, umrs->cache.max_size,
				  kref_read(&umrs->kref));
#ifdef RV_REG_MR_DISCRETE
	if (umrs->dummy_mr)
		ib_dereg_mr(umrs->dummy_mr);
	rv_user_mrs_destroy_rc_qp(umrs);
#endif
	rv_mr_cache_deinit(umrs->rv_inx, &umrs->cache);
	if (umrs->jdev)
		rv_job_dev_put(umrs->jdev);
	kfree(umrs);
}

static void rv_handle_user_mrs_put(struct work_struct *work)
{
	struct rv_user_mrs *umrs = container_of(work, struct rv_user_mrs,
						put_work);

	rv_user_mrs_release(umrs);
}

static void rv_user_mrs_schedule_release(struct kref *kref)
{
	struct rv_user_mrs *umrs = container_of(kref, struct rv_user_mrs, kref);

	/*
	 * Since this function may be called from rv_write_done(),
	 * we can't call rv_user_mrs_release() directly to
	 * destroy it's rc QP and rv_mr_cache_deinit (and wait for completion)
	 * Instead, put the cleanup on a workqueue thread.
	 */
	rv_queue_work(&umrs->put_work);
}

void rv_user_mrs_get(struct rv_user_mrs *umrs)
{
	kref_get(&umrs->kref);
}

void rv_user_mrs_put(struct rv_user_mrs *umrs)
{
	kref_put(&umrs->kref, rv_user_mrs_schedule_release);
}

int doit_reg_mem(struct rv_user *rv, unsigned long arg)
{
	struct rv_mem_params mparams;
	struct rv_mr_cached *mrc;
	int ret;
	struct rv_user_mrs *umrs = rv->umrs;

	if (copy_from_user(&mparams, (void __user *)arg, sizeof(mparams)))
		return -EFAULT;

	if (!enable_user_mr && !(mparams.in.access & IBV_ACCESS_KERNEL))
		return -EINVAL;

	/*
	 * rv->mutex protects use of umrs QP for REG_MR, also
	 * protects between rb_search and rb_insert vs races with other
	 * doit_reg_mem and doit_dereg_mem calls
	 */
	mutex_lock(&rv->mutex);
	if (!rv->attached) {
		ret = rv->was_attached ? -ENXIO : -EINVAL;
		goto bail_unlock;
	}
	if (rv->rdma_mode != RV_RDMA_MODE_KERNEL &&
	    (mparams.in.access & IBV_ACCESS_KERNEL)) {
		ret = -EINVAL;
		goto bail_unlock;
	}

	trace_rv_mr_reg(rv->rdma_mode, (unsigned long)mparams.in.addr,
			mparams.in.length, mparams.in.access);
	/* get reference,  if found update hit stats */
	mrc = rv_mr_cache_search_get(&umrs->cache,
				     (unsigned long)mparams.in.addr,
				     mparams.in.length, mparams.in.access,
				     true);
	if (mrc)
		goto cont;

	/* create a new mrc for rb tree */
	mrc = kzalloc(sizeof(*mrc), GFP_KERNEL);
	if (!mrc) {
		ret = -ENOMEM;
		umrs->stats.failed++;
		goto bail_unlock;
	}

	/* register using verbs callback */
	ret = rv_drv_api_reg_mem(rv, &mparams.in, &mrc->mr);
	if (ret) {
		umrs->stats.failed++;
		goto bail_free;
	}
	mrc->addr = (unsigned long)mparams.in.addr;
	mrc->len = mparams.in.length;
	mrc->access = mparams.in.access;

	ret = rv_mr_cache_insert(&umrs->cache, mrc);
	if (ret)
		goto bail_dereg;

cont:
	/* return the mr handle, lkey & rkey */
	mparams.out.mr_handle = (uint64_t)mrc;
	mparams.out.iova = mrc->mr.ib_mr->iova;
	mparams.out.lkey = mrc->mr.ib_mr->lkey;
	mparams.out.rkey = mrc->mr.ib_mr->rkey;

	if (copy_to_user((void __user *)arg, &mparams, sizeof(mparams))) {
		ret = -EFAULT;
		goto bail_put;
	}

	mutex_unlock(&rv->mutex);

	return 0;

bail_dereg:
#ifdef NVIDIA_GPU_DIRECT
	BUG_ON(1); /* XXX Dereg call is not right */
	if (rv_drv_api_dereg_mem(&mrc->mr, NULL, 0, 0))
#else
	if (rv_drv_api_dereg_mem(&mrc->mr))
#endif
		rv_err(rv->inx, "dereg_mem failed during cleanup\n");
bail_free:
	kfree(mrc);
bail_unlock:
	mutex_unlock(&rv->mutex);
	return ret;

bail_put:
	rv_mr_cache_put(&umrs->cache, mrc);
	mutex_unlock(&rv->mutex);
	return ret;
}

int doit_dereg_mem(struct rv_user *rv, unsigned long arg)
{
	struct rv_mr_cached *mrc;
	struct rv_dereg_params_in dparams;
	int ret = -EINVAL;

	if (copy_from_user(&dparams, (void __user *)arg, sizeof(dparams)))
		return -EFAULT;

	/* rv->mutex protects possible race with doit_reg_mem */
	mutex_lock(&rv->mutex);
	if (!rv->attached) {
		ret = rv->was_attached ? -ENXIO : -EINVAL;
		goto bail_unlock;
	}

	mrc = rv_mr_cache_search_put(&rv->umrs->cache,
				     (unsigned long)dparams.addr,
				     dparams.length, dparams.access);
	if (!mrc)
		goto bail_unlock;

	mutex_unlock(&rv->mutex);
	trace_rv_mr_dereg(rv->rdma_mode, (unsigned long)dparams.addr,
			  dparams.length, dparams.access);

	return 0;

bail_unlock:
	mutex_unlock(&rv->mutex);
	return ret;
}

/* called with cache->lock */
static bool rv_cache_mrc_filter(struct rv_mr_cached *mrc, unsigned long addr,
				unsigned long len, unsigned int acc)
{
	return (bool)(mrc->addr == addr) &&
		   (bool)(mrc->len == len) &&
		   (bool)(mrc->access == acc);
}

/* called with cache->lock */
static void rv_cache_mrc_get(struct rv_mr_cache *cache,
			     void *arg, struct rv_mr_cached *mrc)
{
	int refcount;

	refcount = atomic_inc_return(&mrc->refcount);
	if (refcount == 1) {
		cache->stats.inuse++;
		cache->stats.inuse_bytes += mrc->len;
	}
	rv_mr_cache_update_stats_max(cache, refcount);
}

/* called with cache->lock */
static int rv_cache_mrc_put(struct rv_mr_cache *cache,
			    void *arg, struct rv_mr_cached *mrc)
{
	int refcount;

	refcount = atomic_dec_return(&mrc->refcount);
	if (!refcount) {
		cache->stats.inuse--;
		cache->stats.inuse_bytes -= mrc->len;
	}
	return refcount;
}

/* called with cache->lock */
static int rv_cache_mrc_invalidate(struct rv_mr_cache *cache,
				   void *arg, struct rv_mr_cached *mrc)
{
	if (!atomic_read(&mrc->refcount))
		return 1;
	return 0;
}

/*
 * Return 1 if the mrc can be evicted from the cache
 *
 * Called with cache->lock
 */
static int rv_cache_mrc_evict(struct rv_mr_cache *cache,
			      void *arg, struct rv_mr_cached *mrc,
			      void *evict_arg, bool *stop)
{
	struct evict_data *evict_data = evict_arg;

	/* is this mrc still being used? */
	if (atomic_read(&mrc->refcount))
		return 0; /* keep this mrc */

	/* this mrc will be evicted, add its size to our count */
	evict_data->cleared += mrc->len;

	/* have enough MB bytes been cleared? */
	if (evict_data->cleared >= evict_data->target)
		*stop = true;

	return 1; /* remove this mrc */
}

void rv_mr_init(void)
{
#ifdef RV_REG_MR_PD_UOBJECT
	mutex_init(&mr_pd_uobject_lock);
#endif
}
