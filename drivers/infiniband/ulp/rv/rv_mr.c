// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 - 2021 Intel Corporation.
 */

#include "rv.h"
#include "trace.h"

#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
#include <rdma/ib_cache.h>
#endif
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
#include "gpu.h"
#include "gdr_ops.h"
#endif

unsigned int enable_user_mr = 1;

module_param(enable_user_mr, uint, 0444);
MODULE_PARM_DESC(enable_user_mr, "Enable user mode MR caching");

#ifdef RV_REG_MR_DISCRETE
static unsigned int fr_batch_size = RV_FR_POOL_BATCH_SIZE;
module_param(fr_batch_size, uint, 0444);
MODULE_PARM_DESC(fr_batch_size,
		 "FR pool batch allocation size (0 to disable FR pool");

static unsigned int fr_page_list_len = RV_MAX_PAGE_LIST_LEN;
module_param(fr_page_list_len, uint, 0444);
MODULE_PARM_DESC(fr_page_list_len,
		 "FR pool batch page list size");

static unsigned int fr_pool_wm_lo = RV_FR_POOL_WM_LO;
module_param(fr_pool_wm_lo, uint, 0444);
MODULE_PARM_DESC(fr_pool_wm_lo, "FR pool lower watermark");
#endif

/*
 * Default PSM limit is (TF_NFLOWS(32) + num_send_rdma(128)) * window_rv(128K)
 * So ideal CPU MR cache is > 20MB, however PSM can survive with less
 */
static unsigned int mr_cache_size = 256; /* this is MB */

module_param(mr_cache_size, uint, 0444);
MODULE_PARM_DESC(mr_cache_size, "Size of mr cache (in MB)");

/*
 * Default PSM limit is (TF_NFLOWS(32) + num_send_rdma(128)) * window_rv(2M)
 * So ideal CPU MR cache is > 320MB, however PSM can survive with less
 */
static unsigned int mr_cache_size_gpu = 1024; /* this is MB */

module_param(mr_cache_size_gpu, uint, 0444);
MODULE_PARM_DESC(mr_cache_size_gpu, "Size of mr cache for GPU jobs (in MB)");

#define RV_RC_QP_MAX_SEND_WR	400
#define RV_RC_QP_INV_LIMIT	(RV_RC_QP_MAX_SEND_WR - 40)
#define RV_RC_QP_INV_THRESHOLD	(RV_RC_QP_INV_LIMIT >> 2)

static void rv_handle_user_mrs_put(struct work_struct *work);
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
static int rv_create_rc_qp(struct rv_user_mrs *umrs,
			   struct ib_qp **qp, struct ib_pd *pd,
			   struct rv_device *dev, u8 port_num,
			   u16 gid_index);
#endif

#ifdef RV_REG_MR_DISCRETE
static struct rv_fr_desc *rv_fr_pool_get(struct rv_fr_pool *pool);
static void rv_fr_pool_put(struct rv_fr_desc *desc);
#endif

static bool rv_cache_mrce_filter(struct rv_mr_cache_entry *mrce, u64 addr,
				 u64 len, u32 acc);
static void rv_cache_mrce_remove(struct rv_mr_cache *cache,
				 void *context, struct rv_mr_cache_entry *mrce,
				 int is_invalidate);

static const struct rv_mr_cache_ops rv_cache_ops = {
	.filter = rv_cache_mrce_filter,
	.remove = rv_cache_mrce_remove
};

/* given an rv, find the proper ib_dev to use when registering user MRs */
static inline struct ib_device *rv_ib_dev(struct rv_user *rv)
{
	struct rv_device *dev = rv->rdma_mode == RV_RDMA_MODE_USER ? rv->dev :
				rv->jdev->dev;

	return dev->ib_dev;
}

/* Refer to ib_uverbs_open_xrcd() in drivers/infiniband/core/uverbs_cmd.c for any updates */
static struct ib_uverbs_file *get_ufile(struct rv_mem_params_in *minfo,
					struct fd *fd, int inx)
{
	struct fd f;
	struct file *filp;
	struct ib_uverbs_file *file;

	/* fd to "struct fd" */
	f = fdget(minfo->cmd_fd_int);

	/* "struct fd" to "struct file *" */
#ifdef HAVE_FD_FILE
	if (fd_empty(f))
		filp = NULL;
	else
		filp = fd_file(f);
#else
	filp = f.file;
#endif
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

#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
/*
 * This function will be called either:
 * - IB_SEND_SIGNALED is set in wr.send_flags;
 * - The reg_mr request fails.
 * In new CVL software (since 09/2020), the no-completion event for REG_MEM
 * WR has been fixed and the LOCAL_INV WR is no longer required. As a result,
 * the dummy_mr is no longer required, either. However, to maintain backward
 * compatibility with older CVL software, we will keep the dummy_mr for the
 * short-term.
 * Note that the rv->mutex should be held when calling any of the functions
 * to send either REG_MEM or LOCAL_INV WR to the RC QPs due to the fact that
 * umrs->status and umrs->done could be re-used between requests.
 */
static void rv_reg_mr_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct rv_user_mrs *umrs = container_of(wc->wr_cqe,
					  struct rv_user_mrs, req_cqe);
	enum ib_wc_status status = wc->status;

	trace_rv_wc_reg_mr_done(wc);
	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		rv_err(umrs->rv_inx,
		       "reg_mr failed: st 0x%x op 0x%x len %u imm 0x%x\n",
		       wc->status, wc->opcode, wc->byte_len, wc->ex.imm_data);
	} else if (unlikely(wc->opcode != IB_WC_REG_MR)) {
		rv_err(umrs->rv_inx, "Recv bad opcode 0x%x (exp 0x%x)\n",
		       wc->opcode, IB_WC_REG_MR);
		status = IB_WC_LOC_QP_OP_ERR;
	}

	/* Set the completion status */
	umrs->status = status;
	complete(&umrs->done);
}

static void rv_fr_inv_rkey_done_unsignaled(struct ib_cq *cq, struct ib_wc *wc)
{
	trace_rv_wc_fr_inv_rkey_done_unsignaled(wc);
	/* Do nothing */
}

static void rv_fr_inv_rkey_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct rv_fr_pool *pool = container_of(wc->wr_cqe, struct rv_fr_pool,
					       cqe);

	trace_rv_wc_fr_inv_rkey_done(wc);
	/*
	 * The cqe callback is requested once for every RV_RC_QP_INV_THRESHOLD
	 * LOCAL_INV WRs.
	 */
	if (atomic_read(&pool->inv_cnt) >= RV_RC_QP_INV_THRESHOLD)
		atomic_sub(RV_RC_QP_INV_THRESHOLD, &pool->inv_cnt);

	complete(&pool->done);
}

static int rv_fr_inv_rkey(struct rv_fr_pool *pool, struct ib_qp *qp, u32 rkey,
			  bool signaled)
{
	struct ib_send_wr wr;
	const struct ib_send_wr *bad_send_wr;

	pool->cqe.done = signaled ? rv_fr_inv_rkey_done :
			 rv_fr_inv_rkey_done_unsignaled;
	wr.wr_cqe = &pool->cqe;
	wr.opcode = IB_WR_LOCAL_INV;
	wr.next = NULL;
	wr.num_sge = 0;
	wr.send_flags = signaled ? IB_SEND_SIGNALED : 0;
	wr.ex.invalidate_rkey = rkey;

	return ib_post_send(qp, &wr, &bad_send_wr);
}

static void rv_inv_rkey_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct rv_user_mrs *umrs = container_of(wc->wr_cqe, struct rv_user_mrs,
						dummy_cqe);
	trace_rv_wc_inv_rkey_done(wc);
	if (unlikely(wc->status != IB_WC_SUCCESS))
		rv_err(umrs->rv_inx,
		       "inv_rkey failed: st 0x%x op 0x%x len %u imm 0x%x\n",
		       wc->status, wc->opcode, wc->byte_len, wc->ex.imm_data);
	/* We are receiving opcode IB_WC_RECV (0x800) */

	/* Set the completion status */
	umrs->status = wc->status;
	complete(&umrs->done);
}

static int rv_inv_rkey(struct rv_user_mrs *umrs, struct ib_qp *qp, u32 rkey,
		       bool signaled)
{
	struct ib_send_wr wr;
	const struct ib_send_wr *bad_send_wr;

	umrs->dummy_cqe.done = rv_inv_rkey_done;
	wr.wr_cqe = &umrs->dummy_cqe;
	wr.opcode = IB_WR_LOCAL_INV;
	wr.next = NULL;
	wr.num_sge = 0;
	wr.send_flags = signaled ? IB_SEND_SIGNALED : 0;
	wr.ex.invalidate_rkey = rkey;

	return ib_post_send(qp, &wr, &bad_send_wr);
}

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
/* Called from gdr free_callback */
int rv_inv_gdr_rkey(struct rv_user_mrs *umrs, u32 access, u32 rkey)
{
	struct rv_user *rv = umrs->rv;
	int ret;

	mutex_lock(&rv->mutex);
	reinit_completion(&umrs->done);
	umrs->status = IB_WC_SUCCESS;
	if ((access & IBV_ACCESS_KERNEL) && umrs->qp)
		ret = rv_inv_rkey(umrs, umrs->qp, rkey, true);
	else if (!(access & IBV_ACCESS_KERNEL) && umrs->user_qp)
		ret = rv_inv_rkey(umrs, umrs->user_qp, rkey, true);
	else
		ret = -EINVAL;
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to send LOCAL_INV req: %d\n",
		       ret);
		goto unlock;
	}

	/* Wait for completion */
	ret = wait_for_completion_interruptible(&umrs->done);
	if (ret < 0) {
		rv_err(umrs->rv_inx, "Failed to wait for completion: %d", ret);
		ret = -EINTR;
	}
	if (umrs->status != IB_WC_SUCCESS) {
		rv_err(umrs->rv_inx, "LOCAL_INV request failed: status 0x%x\n",
		       umrs->status);
		ret = -EFAULT;
	}
unlock:
	mutex_unlock(&rv->mutex);
	return ret;
}
#endif /* NVIDIA_GPU_DIRECT || INTEL_GPU_DIRECT */

static int rv_send_reg_mr_req(struct rv_user_mrs *umrs, struct ib_qp *qp,
			      struct mr_info *mr,
			      struct rv_mem_params_in *minfo,
			      struct ib_mr *dummy_mr)
{
	int ret;
	struct ib_reg_wr wr;
	const struct ib_send_wr *bad_send_wr;

	memset(&wr, 0, sizeof(wr));
	reinit_completion(&umrs->done);
	umrs->status = IB_WC_SUCCESS;
	wr.wr.next = NULL;
	wr.wr.opcode = IB_WR_REG_MR;
	wr.wr.wr_cqe = &umrs->req_cqe;
	wr.wr.num_sge = 0;
	/*
	 * No send_completion event will be reported, which makes
	 * rv_reg_mr_done() useless.
	 */
	wr.wr.send_flags = dummy_mr? 0 : IB_SEND_SIGNALED;
	wr.mr = mr->ib_mr;
	wr.key = mr->ib_mr->rkey;
	wr.access = minfo->access & ~IBV_ACCESS_RV;

	ret = ib_post_send(qp, &wr.wr, &bad_send_wr);
	if (unlikely(ret)) {
		rv_err(umrs->rv_inx, "Failed to send REG_MR req: %d qp %u\n",
		       ret, qp->qp_num);
		return ret;
	}
	if (dummy_mr) {
		/*
		 * we get no completion for the REG_MR.
		 * On irdma (CVL), the send queue tail will not be advanced and
		 * we can send a LOCAL_INV request to get a completion event
		 * and reap the WQEs.
		 */
		ret = rv_inv_rkey(umrs, qp, dummy_mr->rkey, true);
		if (unlikely(ret)) {
			rv_err(umrs->rv_inx,
			       "Failed to send LOCAL_INV req: %d\n",
			       ret);
			return ret;
		}
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

static int rv_kern_reg_mem(struct rv_user_mrs *umrs,
			   struct rv_mem_params_in *minfo,
			   struct mr_info *mr)
{
	int ret = 0;
#ifdef RV_REG_MR_DISCRETE
	unsigned int offset;
	struct rv_fr_desc *d = NULL;
#ifdef IB_UMEM_GET_WITH_UDATA
	struct uverbs_attr_bundle attrs;
#endif
#endif
	int num;

	/* sanity check */
	if (!umrs->jdev)
		return -EINVAL;
	/* Set the kernel pd */
	mr->ib_pd = umrs->jdev->pd;
	/* For ucontext, only device and closing fields are relevant */
	mr->ucontext.device = mr->ib_pd->device;

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (minfo->access & IBV_ACCESS_IS_GPU_ADDR) {
		/* GPU memory already pinned, need to create MR and map it */
		num = rv_gdr_map_verbs_mr(umrs->rv_inx, mr, minfo);
		trace_rv_mr_kern_reg_mem(umrs->rv->rdma_mode, minfo->addr,
					 minfo->length, minfo->access);
		trace_rv_mr_msg_kern_reg_mem(umrs->rv_inx, "num ", num, 0);
		if (num < 0) {
			rv_err(umrs->rv_inx, "Failed to map GPU mr: %d\n", num);
			return num;
		}
		WARN_ON(!num); /* XXX drop this */
		goto cont;
	}

#endif
#ifdef RV_REG_MR_DISCRETE
	/*
	 * Pin and map the user buffer.
	 */
#ifdef IB_UMEM_GET_WITH_UDATA
	memset(&attrs, 0, sizeof(attrs));
	attrs.context = &mr->ucontext;
	mr->umem = ib_umem_get(&attrs.driver_udata, minfo->addr,
			       minfo->length,
#ifdef IB_UMEM_GET_WITH_UDATA_DMASYNC
			       minfo->access & ~IBV_ACCESS_RV, 0);
#else
			       minfo->access & ~IBV_ACCESS_RV);
#endif
#elif defined(IB_UMEM_GET_WITH_DEVICE)
	mr->umem = ib_umem_get(mr->ib_pd->device, minfo->addr,
			       minfo->length,
			       minfo->access & ~IBV_ACCESS_RV);
#else
	mr->umem = ib_umem_get(&mr->ucontext, minfo->addr,
			       minfo->length,
			       minfo->access & ~IBV_ACCESS_RV, 0);
#endif
	if (IS_ERR(mr->umem)) {
		rv_err(umrs->rv_inx, "Failed to get umem: %ld\n",
		       PTR_ERR(mr->umem));
		ret = -EFAULT;
		goto bail_clean_mr;
	}
#ifndef IB_UMEM_HAS_NO_NMAP
	trace_rv_mr_umem(mr->umem->address, mr->umem->length, mr->umem->nmap);
#else
	trace_rv_mr_umem(mr->umem->address, mr->umem->length,
			 mr->umem->sgt_append.sgt.nents);
#endif

	/*
	 * Allocate a kernel mr.
	 * The maximum number of sg entries should be passed instead of the
	 * current sg entries. In RHEL 8.1, mr->umem->nmap is set to the
	 * number of pages in the given buffer. However, in RHEL 8.3, it
	 * is set to the number of sg entries for the given buffer (<= number
	 * of pages in the given buffer). Otherwise, ib_map_mr_sg() may
	 * terminate prematurely on an irdma device.
	 */
	if (umrs->pool &&
	    umrs->pool->max_page_list_len >= ib_umem_num_pages(mr->umem)) {
		d = rv_fr_pool_get(umrs->pool);
		if (d) {
			mr->ib_mr = d->mr;
			mr->desc = d;
		}
	}
	if (!mr->ib_mr) {
		mr->ib_mr = ib_alloc_mr(mr->ib_pd, IB_MR_TYPE_MEM_REG,
					ib_umem_num_pages(mr->umem));
		if (IS_ERR(mr->ib_mr)) {
			rv_err(umrs->rv_inx, "Failed to alloc kernel mr: %ld\n",
			       PTR_ERR(mr->ib_mr));
			ret = -EFAULT;	/* XXX - error code??? ENOMEM? */
			goto bail_umem;
		}
	}

	/* Bind the kernel mr with the mapped user buffer */
	offset = ib_umem_offset(mr->umem);
#ifndef IB_UMEM_HAS_NO_NMAP
	num = ib_map_mr_sg(mr->ib_mr, mr->umem->sg_head.sgl,
			   mr->umem->nmap, &offset, PAGE_SIZE);
	if (num <= 0 || num < mr->umem->nmap) {
#else
	num = ib_map_mr_sg(mr->ib_mr, mr->umem->sgt_append.sgt.sgl,
			   mr->umem->sgt_append.sgt.nents, &offset, PAGE_SIZE);
	if (num <= 0 || num < mr->umem->sgt_append.sgt.nents) {
#endif
		rv_err(umrs->rv_inx, "Failed to map mr_sg: %d\n", num);
		ret = -EFAULT;
		goto bail_mr;
	}
#endif
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
cont:
#endif
	/*
	 * XXX core/rw.c uses ib_map_mr_sg then builds a wqe to IB_WR_REG_MR
	 * ib_map_mr_sg says:  After this completes successfully, the
	 * memory region is ready for registration.
	 */

	/* Send the REG_MR request */
	ret = rv_send_reg_mr_req(umrs, umrs->qp, mr, minfo, umrs->dummy_mr);
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to send REG_MR request: %d\n",
		       ret);
		goto bail_mr;
	}
	trace_rv_mr_info_kern_reg(minfo->addr,
				  minfo->length, minfo->access,
				  mr->ib_mr->lkey, mr->ib_mr->rkey,
				  mr->ib_mr->iova,
				  atomic_read(&mr->ib_pd->usecnt));
	return 0;
bail_mr:
#ifdef RV_REG_MR_DISCRETE
	if (d)
		rv_fr_pool_put(d);
	else
#endif
		ib_dereg_mr(mr->ib_mr);
#ifdef RV_REG_MR_DISCRETE
bail_umem:
	if (mr->umem)
		ib_umem_release(mr->umem);
bail_clean_mr:
#endif
	mr->ib_mr = NULL;
	mr->umem = NULL;
	mr->ucontext.device = NULL;
	mr->ib_pd = NULL;
	return ret;
}
#endif /*RV_REG_MR_DISCRETE || NVIDIA_GPU_DIRECT  || INTEL_GPU_DIRECT*/

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
/* caller must hold rv->mutex */
static int rv_user_gpu_reg_mem(u8 rdma_mode, struct ib_pd *ib_pd,
			       struct rv_user_mrs *umrs,
			       struct rv_mem_params_in *minfo,
			       struct mr_info *mr)
{
	int ret = 0;
	int num;
	struct rv_device *dev;
	u8 port_num;
	u16 gid_index;

	// the umrs comes from rv->umrs that is inited during attach.
	if (rdma_mode == RV_RDMA_MODE_KERNEL) {
		dev = umrs->jdev->dev;
		port_num = umrs->jdev->port_num;
		gid_index = umrs->jdev->loc_gid_index;
	} else {
		dev = umrs->dev;
		port_num = umrs->port_num;
		gid_index = umrs->loc_gid_index;
	}
	/* sanity check */
	if (!dev || !port_num)
		return -EINVAL;
	if (!umrs->user_qp) {
		ret = rv_create_rc_qp(umrs, &umrs->user_qp, ib_pd,
				      dev, port_num, gid_index);
		if (ret)
			return ret;
	}
	if (!umrs->user_dummy_mr) {
		umrs->user_dummy_mr = ib_alloc_mr(ib_pd,
						  IB_MR_TYPE_MEM_REG, 5);
		if (ret) {
			rv_err(umrs->rv_inx,
			       "Failed to alloc user dummy mr\n");
			return ret;
		}
	}
	/* Set the kernel pd */
	mr->ib_pd = ib_pd;
	/* For ucontext, only device and closing fields are relevant */
	mr->ucontext.device = mr->ib_pd->device;

	/* GPU memory already pinned, need to create MR and map it */
	num = rv_gdr_map_verbs_mr(umrs->rv_inx, mr, minfo);
	trace_rv_mr_user_gpu_reg_mem(umrs->rv->rdma_mode, minfo->addr,
				     minfo->length, minfo->access);
	trace_rv_mr_msg_user_gpu_reg_mem(umrs->rv_inx, "num ", num, 0);
	if (num < 0) {
		rv_err(umrs->rv_inx, "Failed to map GPU mr: %d\n", num);
		return num;
	}
	WARN_ON(!num); /* XXX drop this */
	/* Send the REG_MR request */
	ret = rv_send_reg_mr_req(umrs, umrs->user_qp, mr, minfo,
				 umrs->user_dummy_mr);
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to send REG_MR request: %d\n",
		       ret);
		goto bail_mr;
	}
	trace_rv_mr_info_kern_reg(minfo->addr,
				  minfo->length, minfo->access,
				  mr->ib_mr->lkey, mr->ib_mr->rkey,
				  mr->ib_mr->iova,
				  atomic_read(&mr->ib_pd->usecnt));
	return 0;
bail_mr:
	ib_dereg_mr(mr->ib_mr);
	mr->ib_mr = NULL;
	mr->umem = NULL;
	mr->ucontext.device = NULL;
	mr->ib_pd = NULL;
	return ret;
}
#endif /* NVIDIA_GPU_DIRECT || INTEL_GPU_DIRECT */

/* caller must hold rv->mutex */
int rv_drv_api_reg_mem(struct rv_user *rv,
		       struct rv_mem_params_in *minfo,
		       struct mr_info *mr)
{
	struct ib_pd *ib_pd;
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

	/*
	 * Check if the buffer is for kernel use. It should be noted that
	 * the ibv_pd_handle value "0" is a valid user space pd handle.
	 */
#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (RV_ACC_CHECK(minfo->access))
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
		rv_err(rv->inx, "could not get pd with fd:%d pd_handle:0x%x\n",
		       minfo->cmd_fd_int, minfo->ibv_pd_handle);
		goto out_unlock;
	}
	/*
	 * XXX this pd check is only use of rv required here, need rv for
	 * mode USER where umrs won't have a dev.
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

	/*
	 * UVERBS_ATTR_BUNDLE_NO_UDATA is only applicable to SLES 15.1, which
	 * does not have HAVE_IB_DEVICE_OPS defined.
	 */

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (minfo->access & IBV_ACCESS_IS_GPU_ADDR) {
		ret = rv_user_gpu_reg_mem(rv->rdma_mode, ib_pd, rv->umrs,
					  minfo, mr);
		if (ret)
			ib_mr = ERR_PTR(ret);
		else
			ib_mr = mr->ib_mr;
	} else {
#endif
#ifdef HAVE_IB_DEVICE_OPS
	ib_mr = ib_pd->device->ops.reg_user_mr(ib_pd, minfo->addr,
					       minfo->length,
					       minfo->addr,
					       minfo->access & ~IBV_ACCESS_RV,
					       &attrs.driver_udata);
#else
	ib_mr = ib_pd->device->reg_user_mr(ib_pd, minfo->addr, minfo->length,
					   minfo->addr,
					   minfo->access & ~IBV_ACCESS_RV,
#ifdef UVERBS_ATTR_BUNDLE_NO_UDATA
					   &udata);
#else
					   &attrs.driver_udata);
#endif
#endif
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	}
#endif
	if (IS_ERR(ib_mr)) {
		rv_err(rv->inx,
		       "reg_user_mr failed: add 0x%llx l 0x%llx acc 0x%x\n",
		       minfo->addr, minfo->length, minfo->access);
		ret = PTR_ERR(ib_mr);
		goto err_put;
	}
	/* A hardware driver may not set the iova field */
	if (!ib_mr->iova)
		ib_mr->iova = minfo->addr;

	ib_mr->device  = ib_pd->device;
	ib_mr->pd      = ib_pd;
	ib_mr->dm      = NULL;
	atomic_inc(&ib_pd->usecnt);
	trace_rv_mr_info_reg(minfo->addr, minfo->length, minfo->access,
			     ib_mr->lkey, ib_mr->rkey, ib_mr->iova,
			     atomic_read(&ib_pd->usecnt));

	mr->ib_mr = ib_mr;
	mr->ib_pd = ib_pd;

err_put:
	uobj_put_obj_read(ib_pd);
out_unlock:
	srcu_read_unlock(&ufile->device->disassociate_srcu, srcu_key);
	if (ret)
		fdput(mr->fd);
	return ret;
}

/*
 * This was created to be used in the event we want to skip releasing
 * ib_pd until after eviction; but it is dereg_mr that is causing the
 * issue during eviction.
 */
static int __rv_drv_api_dereg_mem(struct ib_device *ib_dev, struct ib_mr *ib_mr,
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
				  struct ib_pd *ib_pd, struct fd *fd,
				  u32 is_gpu)
#else
				  struct ib_pd *ib_pd, struct fd *fd)
#endif
{
	int ret;
#ifdef DEREG_MR_HAS_UDATA
	struct ib_udata udata;
#endif

	if (!ib_mr)
		return 0;

	/*
	 * Clear the iova in case that the hw driver keeps an mr cache and
	 * does not set this field to avoid stale iova when the mr is re-used.
	 */
	ib_mr->iova = 0;

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (is_gpu) {
		ret = ib_dereg_mr(ib_mr);
	} else {
#endif
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
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	}
#endif
	if (ret)
		rv_err(RV_INVALID, "dereg_mr failed\n");

	if (ib_pd) {
		atomic_dec(&ib_pd->usecnt);
		fdput(*fd);
	}

	return ret;
}

int rv_drv_api_dereg_mem(struct mr_info *mr)
{
	int ret = 0;
	struct rv_mr_cached *mrc = container_of(mr, struct rv_mr_cached, mr);

	trace_rv_mr_info_dereg(mrc->entry.addr, mrc->entry.len,
			       mrc->entry.access,
			       mr->ib_mr->lkey, mr->ib_mr->rkey,
			       mr->ib_mr->iova,
			       atomic_read(&mr->ib_pd->usecnt));

	/* Check if we are dealing with kernel mr */
#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (mr->umem || RV_ACC_CHECK(mrc->entry.access)) {
#ifdef RV_REG_MR_DISCRETE
		if (mr->desc) {
			rv_fr_pool_put(mr->desc);
			mr->desc = NULL;
		} else {
#endif
			ret = ib_dereg_mr(mr->ib_mr);
#ifdef RV_REG_MR_DISCRETE
		}
#endif
		if (mr->umem) {
			ib_umem_release(mr->umem);
			mr->umem = NULL;
		}
	} else
#endif
	{
		ret = __rv_drv_api_dereg_mem(mr->ib_pd->device,
					     mr->ib_mr, mr->ib_pd, &mr->fd
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
					     , mrc->entry.access & IBV_ACCESS_IS_GPU_ADDR
#endif
					     );
	}
	if (!ret) {
		mr->ib_mr = NULL;
		mr->ib_pd = NULL;
	}
	return ret;
}

#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
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

static void rv_user_mrs_destroy_rc_qp(struct rv_user_mrs *umrs)
{
	int qps;

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (umrs->user_qp) {
		struct rv_device *dev = umrs->dev ?
			umrs->dev : umrs->jdev->dev;

		trace_rv_msg_destroy_rc_qp(umrs->rv_inx, dev->ib_dev->name,
					   "Destroy user MRs rc qp",
					   (u64)umrs->user_qp->qp_num, 0);
		qps = rv_query_qp_state(umrs->user_qp);
		if (qps >= 0 && qps != IB_QPS_RESET)
			ib_drain_qp(umrs->user_qp);
		ib_destroy_qp(umrs->user_qp);
		umrs->user_qp = NULL;
	}
#endif

	if (umrs->qp) {
		trace_rv_msg_destroy_rc_qp(umrs->rv_inx, umrs->jdev->dev->ib_dev->name,
					   "Destroy kernel MRs rc qp",
					   (u64)umrs->qp->qp_num, 0);
		qps = rv_query_qp_state(umrs->qp);
		if (qps >= 0 && qps != IB_QPS_RESET)
			ib_drain_qp(umrs->qp);
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

/*
 * local RC QP exclusively for REG_MR WQEs
 *
 * 1 QP per rv_user (in rv_user_mrs), no more than 1 REG_MR WQE outstanding
 * at a time
 */
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
/* additional umrs->user_qp for GPU MRs in user pd for user space QP DMA */
#endif
static int rv_create_rc_qp(struct rv_user_mrs *umrs,
			   struct ib_qp **qp, struct ib_pd *pd,
			   struct rv_device *dev, u8 port_num,
			   u16 gid_index)
{
	struct ib_qp_init_attr init_attr;
	struct ib_qp_attr attr;
	int attr_mask = 0;
	int ret;
	struct ib_port_attr port_attr;
	union ib_gid gid;
	int created_send_cq = 0;
	int created_recv_cq = 0;

        trace_rv_create_rc_qp_req(umrs->rv_inx, dev->ib_dev->name, port_num, gid_index);
	ret = ib_query_port(dev->ib_dev, port_num, &port_attr);
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to query port: %d\n", ret);
		goto fail;
	}

	ret = rdma_query_gid(dev->ib_dev, port_num, gid_index, &gid);
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to query gid: %d\n", ret);
		goto fail;
	}

	if (!umrs->send_cq) {
		umrs->send_cq = ib_alloc_cq_any(dev->ib_dev, umrs, 10,
						IB_POLL_WORKQUEUE);
		if (IS_ERR(umrs->send_cq)) {
			rv_err(umrs->rv_inx, "Creating send cq failed\n");
			umrs->send_cq = NULL;
			ret = -ENOMEM;
			goto fail;
		}
		created_send_cq = 1;
		umrs->send_cq->event_handler = rv_user_mrs_cq_event;
	}

	if (!umrs->recv_cq) {
		umrs->recv_cq = ib_alloc_cq_any(dev->ib_dev, umrs, 10,
						IB_POLL_WORKQUEUE);
		if (IS_ERR(umrs->recv_cq)) {
			rv_err(umrs->rv_inx, "Creating recv cq failed\n");
			umrs->recv_cq = NULL;
			ret = -ENOMEM;
			goto fail;
		}
		created_recv_cq = 1;
		umrs->recv_cq->event_handler = rv_user_mrs_cq_event;
	}

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.event_handler = rv_user_mrs_rc_qp_event;
	init_attr.qp_context = umrs;
	init_attr.cap.max_send_wr = RV_RC_QP_MAX_SEND_WR;
	init_attr.cap.max_recv_wr = 10;
	/* Setting max_recv_sge to 0 will fail on mlx5 */
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_sge = 1;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = umrs->send_cq;
	init_attr.recv_cq = umrs->recv_cq;

	*qp = ib_create_qp(pd, &init_attr);
	if (IS_ERR(*qp)) {
		ret = PTR_ERR(*qp);
		*qp = NULL;
		rv_err(umrs->rv_inx, "Failed to create qp: 0x%x\n", ret);
		goto fail;
	}

	memset(&attr, 0, sizeof(attr));
	attr.port_num = port_num;
	attr.pkey_index = 0;
	attr.qp_state = IB_QPS_INIT;
	attr.qp_access_flags = IB_ACCESS_LOCAL_WRITE;
	attr_mask = IB_QP_STATE | IB_QP_PKEY_INDEX | IB_QP_PORT |
		    IB_QP_ACCESS_FLAGS;
	ret = ib_modify_qp(*qp, &attr, attr_mask);
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to move qp into INIT: %d\n", ret);
		goto fail;
	}

	attr.qp_state = IB_QPS_RTR;
	memset(&attr.ah_attr, 0, sizeof(attr.ah_attr));
	attr.ah_attr.port_num = port_num;
	if (rdma_protocol_roce(dev->ib_dev, port_num)) {
		attr.ah_attr.ah_flags |= IB_AH_GRH;
		attr.ah_attr.type = RDMA_AH_ATTR_TYPE_ROCE;
		attr.ah_attr.grh.dgid = gid;
		attr.ah_attr.grh.sgid_index = gid_index;
		attr.ah_attr.grh.hop_limit = 0xFF;
	} else {
		attr.ah_attr.type = RDMA_AH_ATTR_TYPE_IB;
		attr.ah_attr.ib.src_path_bits = 0;
		attr.ah_attr.ib.dlid = port_attr.lid;
	}
	attr.path_mtu = port_attr.active_mtu;
	attr.dest_qp_num = (*qp)->qp_num;
	attr.rq_psn = 0;
	attr.max_dest_rd_atomic = 0;
	attr.min_rnr_timer = 14;
	attr_mask = IB_QP_STATE | IB_QP_AV | IB_QP_PATH_MTU |
		    IB_QP_DEST_QPN | IB_QP_RQ_PSN | IB_QP_MIN_RNR_TIMER |
		    IB_QP_MAX_DEST_RD_ATOMIC;
	ret = ib_modify_qp(*qp, &attr, attr_mask);
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
	ret = ib_modify_qp(*qp, &attr, attr_mask);
	if (ret) {
		rv_err(umrs->rv_inx, "Failed to move qp into RTS: %d\n", ret);
		goto fail;
	}
	trace_rv_msg_create_rc_qp(umrs->rv_inx, dev->ib_dev->name, "RC qp is in RTS",
				  (u64)(*qp)->qp_num, 0);
	return 0;
fail:
	if (*qp) {
		trace_rv_msg_destroy_rc_qp(umrs->rv_inx, dev->ib_dev->name,
					   "Destroy kernel MRs rc qp",
					   (u64)(*qp)->qp_num, 0);
		ib_destroy_qp(*qp);
		*qp = NULL;
	}
	if (created_recv_cq) {
		ib_free_cq(umrs->recv_cq);
		umrs->recv_cq = NULL;
	}
	if (created_send_cq) {
		ib_free_cq(umrs->send_cq);
		umrs->send_cq = NULL;
	}

	return ret;
}
#endif /* RV_REG_MR_DISCRETE || NVIDIA_GPU_DIRECT || INTEL_GPU_DIRECT */

#ifdef RV_REG_MR_DISCRETE

static void rv_destroy_fr_list(struct list_head *list)
{
	struct rv_fr_desc *d;

	while (!list_empty(list)) {
		d = list_first_entry(list, typeof(*d), entry);
		list_del(&d->entry);
		if (d->mr)
			ib_dereg_mr(d->mr);
		kfree(d);
	}
}

static void rv_empty_fr_pool(struct rv_fr_pool *pool)
{
	if (!pool)
		return;

	cancel_work_sync(&pool->alloc_work);
	mutex_lock(&pool->lock);
	rv_destroy_fr_list(&pool->free_list);
	/*
	 * We should not have any entry on the used_list/put_list.
	 * Nevertheless, try to free if any.
	 */
	rv_destroy_fr_list(&pool->used_list);
	rv_destroy_fr_list(&pool->put_list);
	pool->put_cnt = 0;
	mutex_unlock(&pool->lock);
}

static void rv_destroy_fr_pool(struct rv_user_mrs *umrs)
{
	kfree(umrs->pool);
	umrs->pool = NULL;
}

static int rv_fr_desc_batch_alloc(struct rv_fr_pool *pool, unsigned int num)
{
	int i;
	struct rv_fr_desc **desc;
	struct ib_mr *mr;
	int ret = 0;

	trace_rv_fr_add_pool(pool, num);
	desc = kzalloc(sizeof(*desc) * num, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;
	for (i = 0; i < num; i++) {
		desc[i] = kzalloc(sizeof(struct rv_fr_desc), GFP_KERNEL);
		if (!desc[i]) {
			ret = -ENOMEM;
			goto free_desc;
		}
		mr = ib_alloc_mr(pool->umrs->jdev->pd, IB_MR_TYPE_MEM_REG,
				 pool->max_page_list_len);
		if (IS_ERR(mr)) {
			ret = PTR_ERR(mr);
			rv_err(pool->umrs->rv_inx,
			       "fr: ib_alloc_mr() failed: %d.\n",
			       ret);
			goto free_desc;
		}
		desc[i]->mr = mr;
		desc[i]->pool = pool;
		desc[i]->is_new = true;
	}

	/* Now add the allocated descriptors to the pool */
	for (i = 0; i < num; i++)
		list_add_tail(&desc[i]->entry, &pool->free_list);
	pool->size += num;
	pool->free_size += num;

	goto out;

free_desc:
	/* Free any allocated resources */
	for (; i >= 0; i--) {
		if (desc[i]) {
			if (desc[i]->mr)
				ib_dereg_mr(desc[i]->mr);
			kfree(desc[i]);
		}
	}

out:
	kfree(desc);
	return ret;
}

/* The caller must hold the pool->lock */
static void rv_fr_clean_desc(struct rv_fr_desc *desc)
{
	struct rv_fr_pool *pool = desc->pool;
	int ret;
	int cnt;

	/*
	 * Invalidate rkey first. It should be reminded that it is always
	 * possible that we may overrun the qp's send queue, especially when
	 * the umrs is being torn down, where a large number of MRs are removed
	 * from the cache one after another. Consequently, we should wait
	 * for completion if too many LOCAL_INV WRs are posted.
	 */
	cnt = atomic_read(&pool->inv_cnt);
	if (cnt > 0 && !(cnt % RV_RC_QP_INV_THRESHOLD)) {
		reinit_completion(&pool->done);
		ret = rv_fr_inv_rkey(pool, pool->umrs->qp, desc->mr->rkey,
				     true);
		if (!ret) {
			if (atomic_inc_return(&pool->inv_cnt) >=
				RV_RC_QP_INV_LIMIT)
				wait_for_completion_interruptible(&pool->done);
		} else {
			rv_dbg(pool->umrs->rv_inx,
			       "Failed to send LOCAL_INV for rkey 0x%x: %d\n",
			       desc->mr->rkey, ret);
		}
	} else {
		ret = rv_fr_inv_rkey(pool, pool->umrs->qp, desc->mr->rkey,
				     false);
		if (!ret)
			atomic_inc(&pool->inv_cnt);
		else
			rv_dbg(pool->umrs->rv_inx,
			       "Failed to send LOCAL_INV for rkey 0x%x: %d\n",
			       desc->mr->rkey, ret);
	}
}

static void rv_fr_pool_work(struct work_struct *work)
{
	struct rv_fr_pool *pool = container_of(work, struct rv_fr_pool,
						alloc_work);
	struct rv_fr_desc *d;
	unsigned int num;

	/* process the put_list first */
	mutex_lock(&pool->lock);
	do {
		d = list_first_entry_or_null(&pool->put_list,
					     typeof(*d), entry);
		if (d) {
			if (!pool->umrs->is_down &&
			    pool->free_size < fr_batch_size) {
				rv_fr_clean_desc(d);
				list_move_tail(&d->entry, &pool->free_list);
				pool->free_size++;
			} else {
				list_del(&d->entry);
				ib_dereg_mr(d->mr);
				kfree(d);
			}
			pool->put_cnt--;
		}
	} while (d);
	/*
	 * Add to bring us just beyond the low water value
	 *
	 * We should rarely get here!
	 */
	if (pool->free_size <= fr_pool_wm_lo) {
		num = fr_pool_wm_lo - pool->free_size + 1;
		rv_fr_desc_batch_alloc(pool, num);
	}
	trace_rv_fr_pool_work(pool);
	mutex_unlock(&pool->lock);
}

static struct rv_fr_pool *rv_create_fr_pool(struct rv_user_mrs *umrs,
					    u32 page_list_len)
{
	struct rv_fr_pool *pool;
	int ret = -ENOMEM;

	/* One way to disable FR pool */
	if (fr_batch_size == 0)
		return NULL;
	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		goto err;
	/* Use the user input if available */
	pool->max_page_list_len = page_list_len ?
				  page_list_len : fr_page_list_len;
	pool->umrs = umrs;
	INIT_WORK(&pool->alloc_work, rv_fr_pool_work);
	mutex_init(&pool->lock);
	INIT_LIST_HEAD(&pool->free_list);
	INIT_LIST_HEAD(&pool->used_list);
	INIT_LIST_HEAD(&pool->put_list);
	pool->put_cnt = 0;
	atomic_set(&pool->inv_cnt, 0);
	init_completion(&pool->done);

	ret = rv_fr_desc_batch_alloc(pool, fr_batch_size);
	if (ret)
		goto destroy_pool;
	trace_rv_create_fr_pool(pool);
out:
	return pool;

destroy_pool:
	rv_destroy_fr_pool(umrs);

err:
	pool = NULL;
	goto out;
}

static struct rv_fr_desc *rv_fr_pool_get(struct rv_fr_pool *pool)
{
	struct rv_fr_desc *d = NULL;

	if (!pool)
		goto exit;

	/*
	 * If the descriptors have been consumed below the low watermark,
	 * schedule the batch alloc work. Schedule the alloc work only
	 * occasionally to avoid rapid-fire scheduling.
	 */
	mutex_lock(&pool->lock);
	if (pool->free_size <= fr_pool_wm_lo) {
		if (pool->free_size == fr_pool_wm_lo ||
		    pool->wait_cnt >= fr_pool_wm_lo) {
			rv_queue_work(&pool->alloc_work);
			pool->wait_cnt = 0;
		} else {
			pool->wait_cnt++;
		}
	}

	if (!list_empty(&pool->free_list)) {
		d = list_first_entry(&pool->free_list, typeof(*d), entry);
		list_move_tail(&d->entry, &pool->used_list);
		pool->free_size--;

		/* Increment the rkey for re-use */
		if (!d->is_new) {
			u32 rkey;

			rkey = ib_inc_rkey(d->mr->rkey);
			ib_update_fast_reg_key(d->mr, rkey);
		}
	}
	trace_rv_fr_pool_get(pool);
	mutex_unlock(&pool->lock);
exit:
	return d;
}

static void rv_fr_pool_put(struct rv_fr_desc *desc)
{
	struct rv_fr_pool *pool = desc->pool;

	mutex_lock(&pool->lock);
	/* Move to the put list */
	desc->is_new = false;
	list_move_tail(&desc->entry, &pool->put_list);
	pool->put_cnt++;

	/* Don't keep too many entries on the put list */
	if (pool->put_cnt >= fr_pool_wm_lo) {
		rv_queue_work(&pool->alloc_work);
		pool->wait_cnt = 0;
	}
	trace_rv_fr_pool_put(pool);
	mutex_unlock(&pool->lock);
}
#endif /* RV_REG_MR_DISCRETE */

/* Cannot hold rv->mutex */
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
struct rv_user_mrs *rv_user_mrs_alloc(struct rv_user *rv, u32 cache_size,
				      u8 gpu, u32 gpu_cache_size)
#else
struct rv_user_mrs *rv_user_mrs_alloc(struct rv_user *rv, u32 cache_size,
				      u8 gpu)
#endif
{
	int ret;
	struct rv_user_mrs *umrs;

	umrs = kzalloc(sizeof(*umrs), GFP_KERNEL);
	if (!umrs)
		return ERR_PTR(-ENOMEM);

	umrs->rv_inx = rv->inx;
	if ((gpu & RV_RDMA_MODE_UPSIZE_CPU) && !cache_size)
		cache_size = mr_cache_size_gpu;
	if (!cache_size)
		cache_size = mr_cache_size;
	umrs->tgid = get_pid(task_tgid(current));
	ret = rv_mr_cache_init(rv->inx, 'c', &umrs->cache, &rv_cache_ops, umrs,
			       current->mm, cache_size, 0);
	if (ret)
		goto bail_free;
	kref_init(&umrs->kref); /* refcount now 1 */
	INIT_WORK(&umrs->put_work, rv_handle_user_mrs_put);
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	ret = rv_gdr_init(rv->inx, &umrs->gdrdata, gpu, gpu_cache_size);
	if (ret)
		goto bail_deinit;
	umrs->rv = rv;
#endif
#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	init_completion(&umrs->done);
#endif
	return umrs;

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
bail_deinit:
	rv_mr_cache_deinit(umrs->rv_inx, &umrs->cache);
#endif
bail_free:
	put_pid(umrs->tgid);
	kfree(umrs);
	return ERR_PTR(ret);
}

/* called with rv->mutex */
#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
int rv_user_mrs_attach(struct rv_user *rv, u32 page_list_len)
#else
void rv_user_mrs_attach(struct rv_user *rv, u32 page_list_len)
#endif
{
	struct rv_user_mrs *umrs = rv->umrs;
#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	int ret;
#endif

#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	/*
	 * Always set the req_cqe.done to avoid crash.
	 * When a REG_MR wr fails, the RDMA device will return the completion
	 * event, regardless if the wr.send_flags is set (IB_SEND_SIGNALED) or not.
	 */
	umrs->req_cqe.done = rv_reg_mr_done;
#endif
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
#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
		/* Create the rc qp */
		ret = rv_create_rc_qp(umrs, &umrs->qp,  umrs->jdev->pd,
				      umrs->jdev->dev, umrs->jdev->port_num,
				      umrs->jdev->loc_gid_index);
		if (ret) {
			rv_err(rv->inx, "Failed to create rc qp\n");
			goto fail;
		}
		umrs->dummy_cqe.done = rv_inv_rkey_done;
		umrs->dummy_mr = ib_alloc_mr(umrs->jdev->pd,
					     IB_MR_TYPE_MEM_REG, 5);
		if (IS_ERR(umrs->dummy_mr)) {
			rv_err(rv->inx, "Failed to alloc dummy mr: %ld\n",
			       PTR_ERR(umrs->dummy_mr));
			ret = PTR_ERR(umrs->dummy_mr);
			goto fail_qp;
		}
#ifdef RV_REG_MR_DISCRETE
		umrs->pool = rv_create_fr_pool(umrs, page_list_len);
#endif
#endif
	}
	trace_rv_user_mrs_attach(umrs->rv_inx, umrs->jdev,
				 umrs->cache.total_size, umrs->cache.max_size,
				 kref_read(&umrs->kref));
#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	return 0;

fail_qp:
	rv_user_mrs_destroy_rc_qp(umrs);
fail:	/* only get here for mode KERNEL */
	rv_job_dev_put(umrs->jdev);
	umrs->jdev = NULL;
	return ret;
#endif
}

/* can preempt */
static void rv_user_mrs_release(struct rv_user_mrs *umrs)
{
	trace_rv_user_mrs_release(umrs->rv_inx, umrs->jdev,
				  umrs->cache.total_size, umrs->cache.max_size,
				  kref_read(&umrs->kref));
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (umrs->user_dummy_mr)
		ib_dereg_mr(umrs->user_dummy_mr);
#endif
#ifdef RV_REG_MR_DISCRETE
	umrs->is_down = true;
#endif
#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (umrs->dummy_mr)
		ib_dereg_mr(umrs->dummy_mr);
#endif
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	rv_gdr_deinit(umrs->rv_inx, &umrs->gdrdata);
#endif
	rv_mr_cache_deinit(umrs->rv_inx, &umrs->cache);
#ifdef RV_REG_MR_DISCRETE
	/* The fr pool must be destroyed after the cache */
	rv_empty_fr_pool(umrs->pool);
#endif
#if defined(RV_REG_MR_DISCRETE) || defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	rv_user_mrs_destroy_rc_qp(umrs);
#endif
#ifdef RV_REG_MR_DISCRETE
	rv_destroy_fr_pool(umrs);
#endif
	if (umrs->jdev)
		rv_job_dev_put(umrs->jdev);
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (umrs->dev)
		rv_device_put(umrs->dev);
#endif
	put_pid(umrs->tgid);
	kfree(umrs);
}

static void rv_user_mrs_release_kref(struct kref *kref)
{
	struct rv_user_mrs *umrs = container_of(kref, struct rv_user_mrs, kref);

	rv_user_mrs_release(umrs);
}

static void rv_handle_user_mrs_put(struct work_struct *work)
{
	struct rv_user_mrs *umrs = container_of(work, struct rv_user_mrs,
						put_work);

	rv_user_mrs_release(umrs);
}

/*
 * Since this function may be called from rv_write_done(),
 * we can't call rv_user_mrs_release() directly to destroy it's rc QP and
 * rv_mr_cache_deinit (and wait for completion).
 * Instead, we put the cleanup on a workqueue thread.  This can happen if
 * the wait for IOs done in detach_all is interrupted so that rv_write_done
 * ends up releasing the final reference.
 */
static void rv_user_mrs_schedule_release(struct kref *kref)
{
	struct rv_user_mrs *umrs = container_of(kref, struct rv_user_mrs, kref);

	rv_queue_work(&umrs->put_work);
}

void rv_user_mrs_get(struct rv_user_mrs *umrs)
{
	kref_get(&umrs->kref);
}

/* non-preemptible and preemptible versions */
void rv_user_mrs_put(struct rv_user_mrs *umrs)
{
	kref_put(&umrs->kref, rv_user_mrs_schedule_release);
}

void rv_user_mrs_put_preemptible(struct rv_user_mrs *umrs)
{
	kref_put(&umrs->kref, rv_user_mrs_release_kref);
}

static u64 rv_round_req_mem(struct rv_mem_params *mparams)
{
	u64 offset;

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (mparams->in.access & IBV_ACCESS_IS_GPU_ADDR) {
		offset = mparams->in.addr & (GPU_PAGE_SIZE - 1);
		mparams->in.addr  = mparams->in.addr & GPU_PAGE_MASK;
		mparams->in.length = ALIGN(mparams->in.length + offset, GPU_PAGE_SIZE);
	} else {
#endif
		offset = mparams->in.addr & (PAGE_SIZE - 1);
		mparams->in.addr  = mparams->in.addr & PAGE_MASK;
		mparams->in.length = ALIGN(mparams->in.length + offset, PAGE_SIZE);
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	}
#endif
	return offset;
}

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
int doit_reg_mem(struct file *fp, struct rv_user *rv, unsigned long arg, u32 rev)
#else
int doit_reg_mem(struct rv_user *rv, unsigned long arg, u32 rev)
#endif
{
	struct rv_mem_params mparams;
	struct rv_mr_cache_entry *mrce;
	struct rv_mr_cached *mrc;
	int ret;
	struct rv_user_mrs *umrs = rv->umrs;
	struct rv_device *dev;
	u64 offset = 0;
	u64 addr_in;

	if (rev <= RV_ABI_VERSION(1, 1)) {
		/* smaller input structure */
		if (copy_from_user(&mparams.in, (void __user *)arg,
				   sizeof(struct rv_mem_params_r1_in)))
			return -EFAULT;
	} else if (rev <= RV_ABI_VERSION(1, 4)) {
		/* smaller input structure */
		if (copy_from_user(&mparams.in, (void __user *)arg,
				   sizeof(struct rv_mem_params_r4_in)))
			return -EFAULT;
	} else {
		if (copy_from_user(&mparams.in, (void __user *)arg,
				   sizeof(mparams.in)))
			return -EFAULT;
	}

	if (!enable_user_mr && !(mparams.in.access & IBV_ACCESS_KERNEL))
		return -EINVAL;

	/*
	 * rv->mutex protects use of umrs QP for REG_MR, also
	 * protects between rb_search and rb_insert vs races with other
	 * doit_reg_mem and doit_dereg_mem calls
	 */
	mutex_lock(&rv->mutex);
	if (rv->state != RV_USER_ATTACHED) {
		ret = (rv->state == RV_USER_WAS_ATTACHED) ? -ENXIO : -EINVAL;
		goto bail_unlock;
	}
	umrs = rv->umrs;
	if (!umrs || umrs->tgid != task_tgid(current) || !current->mm) {
		ret = -EINVAL;
		goto bail_unlock;
	}
	if (rv->rdma_mode != RV_RDMA_MODE_KERNEL &&
	    (mparams.in.access & IBV_ACCESS_KERNEL)) {
		ret = -EINVAL;
		goto bail_unlock;
	}

	/* Round down address and round up length */
	trace_rv_mr_reg(rv->rdma_mode, mparams.in.addr,
			mparams.in.length, mparams.in.access);
	addr_in = mparams.in.addr;
	offset = rv_round_req_mem(&mparams);

	dev = rv->rdma_mode == RV_RDMA_MODE_USER ? rv->dev :
		rv->jdev->dev;
	if (dev->max_fast_reg_page_list_len &&
	    ((mparams.in.access & IBV_ACCESS_KERNEL)
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	      || (mparams.in.access & IBV_ACCESS_IS_GPU_ADDR)
#endif
	    ) && mparams.in.length >
			(((u64)dev->max_fast_reg_page_list_len) <<
				PAGE_SHIFT)) {
		rv_err(rv->inx, "Requested MR length 0x%llx > limit 0x%llx\n",
		       mparams.in.length,
		       ((u64)dev->max_fast_reg_page_list_len) << PAGE_SHIFT);
		ret = -EINVAL;
		goto bail_unlock;
	}

	trace_rv_mr_reg(rv->rdma_mode, mparams.in.addr,
			mparams.in.length, mparams.in.access);
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (mparams.in.access & IBV_ACCESS_IS_GPU_ADDR) {
#ifdef INTEL_GPU_DIRECT
		if (rev <= RV_ABI_VERSION(1, 4)) {
			/*
			 * lacks alloc_id and base_addr, which are needed for
			 * I-GPU caching
			 */
			ret = -EINVAL;
			goto bail_unlock;
		}
		if (mparams.in.addr < mparams.in.base_addr) {
			rv_err(rv->inx, "addr 0x%llx < base_addr 0x%llx\n",
			       mparams.in.addr, mparams.in.base_addr);
			ret = -EINVAL;
			goto bail_unlock;
		}
#endif
		ret = rv_ioctl_gpu_reg_mem(fp, rv, &umrs->gdrdata, &mparams);
		/* Need to take care of any offset for iova */
		if (!ret) {
			mparams.out.iova += offset;
			if (copy_to_user((void __user *)arg, &mparams.out,
					 sizeof(mparams.out)))
				ret = -EFAULT;
		}
		goto bail_unlock;
	}
#endif
	/* get reference,  if found update hit stats */
	mrce = rv_mr_cache_search_get(&umrs->cache, mparams.in.addr,
				      mparams.in.length, mparams.in.access,
				      true, true);
	WARN_ON(IS_ERR(mrce));
	if (mrce) {
		mrc = container_of(mrce, struct rv_mr_cached, entry);
		/*
		 * The request memory (addr, addr + length -1) may be only
		 * a subregion in the existing mrce. Therefore, we need
		 * to calculate the offset.
		 */
		offset = addr_in - mrce->addr;
		goto cont;
	}

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
	rv_mr_cache_entry_init(&mrc->entry, mparams.in.addr, mparams.in.length,
			       mparams.in.access);
	ret = rv_mr_cache_insert(&umrs->cache, &mrc->entry);
	if (ret)
		goto bail_dereg;

cont:
	/* return the mr handle, lkey & rkey */
	mparams.out.mr_handle = (uint64_t)mrc;
	mparams.out.iova = mrc->mr.ib_mr->iova + offset;
	mparams.out.lkey = mrc->mr.ib_mr->lkey;
	mparams.out.rkey = mrc->mr.ib_mr->rkey;

	if (copy_to_user((void __user *)arg, &mparams.out,
			 sizeof(mparams.out))) {
		ret = -EFAULT;
		goto bail_put;
	}

	mutex_unlock(&rv->mutex);

	return 0;

bail_dereg:
	if (rv_drv_api_dereg_mem(&mrc->mr))
		rv_err(rv->inx, "dereg_mem failed during cleanup\n");
bail_free:
	kfree(mrc);
bail_unlock:
	mutex_unlock(&rv->mutex);
	return ret;

bail_put:
	rv_mr_cache_put(&umrs->cache, &mrc->entry, true);
	mutex_unlock(&rv->mutex);
	return ret;
}

int doit_dereg_mem(struct rv_user *rv, unsigned long arg)
{
	struct rv_mr_cache_entry *mrce;
	struct rv_dereg_params_in dparams;
	int ret = -EINVAL;
	struct rv_user_mrs *umrs;

	if (copy_from_user(&dparams, (void __user *)arg, sizeof(dparams)))
		return -EFAULT;

	/* rv->mutex protects possible race with doit_reg_mem */
	mutex_lock(&rv->mutex);
	if (rv->state != RV_USER_ATTACHED) {
		ret = (rv->state == RV_USER_WAS_ATTACHED) ? -ENXIO : -EINVAL;
		goto bail_unlock;
	}
	umrs = rv->umrs;
	if (!umrs || umrs->tgid != task_tgid(current) || !current->mm) {
		ret = -EINVAL;
		goto bail_unlock;
	}
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (dparams.access & IBV_ACCESS_IS_GPU_ADDR) {
		ret = rv_ioctl_gpu_dereg_mem(&umrs->gdrdata, &dparams);
		if (ret)
			goto bail_unlock;
		goto done;
	}
#endif

	mrce = rv_mr_cache_search_put(&umrs->cache, dparams.addr, dparams.length, dparams.access,
				      (struct rv_mr_cached *)dparams.mr_handle);
	if (IS_ERR(mrce))
		goto bail_unlock;

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
done:
#endif
	mutex_unlock(&rv->mutex);
	trace_rv_mr_dereg(rv->rdma_mode, dparams.addr,
			  dparams.length, dparams.access);

	return 0;

bail_unlock:
	mutex_unlock(&rv->mutex);
	return ret;
}

/*
 *	RV_IOCTL_EVICT, a request to evict a cached MR.
 */
int doit_evict(struct file *fp, struct rv_user *rv, unsigned long arg)
{
	struct rv_evict_params params;
	int ret = -EINVAL;
	struct rv_user_mrs *umrs;
	struct evict_out out;

	if (copy_from_user(&params.in, (void __user *)arg, sizeof(params.in)))
		return -EFAULT;

	/* rv->mutex protects possible race with doit_reg_mem */
	mutex_lock(&rv->mutex);
	if (rv->state != RV_USER_ATTACHED) {
		ret = (rv->state == RV_USER_WAS_ATTACHED) ? -ENXIO : -EINVAL;
		goto bail_unlock;
	}
	umrs = rv->umrs;
	if (!umrs || umrs->tgid != task_tgid(current) || !current->mm) {
		ret = -EINVAL;
		goto bail_unlock;
	}
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if ((params.in.type == RV_EVICT_TYPE_SEARCH_EXACT &&
	     params.in.search.access & IBV_ACCESS_IS_GPU_ADDR) ||
	    params.in.type ==  RV_EVICT_TYPE_GPU_SEARCH_RANGE ||
	    params.in.type ==  RV_EVICT_TYPE_GPU_AMOUNT) {
		/* we'll need to release rv->mutex, so get umrs reference */
		rv_user_mrs_get(rv->umrs);
		mutex_unlock(&rv->mutex);
		ret = rv_ioctl_gpu_evict(&umrs->gdrdata, &params);
		rv_user_mrs_put_preemptible(rv->umrs);
		if (ret)
			return ret;
		if (copy_to_user((void __user *)arg, &params.out,
				 sizeof(params.out)))
			ret = -EFAULT;
		return ret;
	} else
#endif
	if (params.in.type == RV_EVICT_TYPE_SEARCH_EXACT) {
		trace_rv_mr_cache_doit_evict(params.in.search.addr,
					     params.in.search.length,
					     params.in.search.access);
		ret = rv_mr_cache_evict_exact(&umrs->cache,
					      params.in.search.addr,
					      params.in.search.length,
					      params.in.search.access);
		if (ret) {
			trace_rv_mrc_msg_doit_evict("Evict exact failed: ret",
						    (u64)ret, 0, 0);
			goto bail_unlock;
		}
		params.out.bytes = params.in.search.length;
		params.out.count = 1;
		trace_rv_mrc_msg_doit_evict("Evict exact: bytes, count",
					    params.out.bytes,
					    params.out.count, 0);
	} else if (params.in.type == RV_EVICT_TYPE_SEARCH_RANGE) {
		trace_rv_mr_cache_doit_evict(params.in.search.addr,
					     params.in.search.length, 0);
		ret = rv_mr_cache_evict_range(&umrs->cache,
					      params.in.search.addr,
					      params.in.search.length,
					      &out);
		if (ret) {
			trace_rv_mrc_msg_doit_evict("Evict range failed: ret",
						    (u64)ret, 0, 0);
			goto bail_unlock;
		}
		params.out.bytes = out.bytes;
		params.out.count = out.count;
		trace_rv_mrc_msg_doit_evict("Evict range: bytes, count",
					    params.out.bytes,
					    params.out.count, 0);
	} else if (params.in.type == RV_EVICT_TYPE_AMOUNT) {
		trace_rv_mrc_msg_doit_evict("Evict amount: bytes, count",
					    params.out.bytes,
					    params.out.count, 0);
		ret = rv_mr_cache_evict_amount(&umrs->cache,
					       params.in.amount.bytes,
					       params.in.amount.count,
					       &out);
		if (ret) {
			trace_rv_mrc_msg_doit_evict("Evict amount failed: ret",
						    (u64)ret, 0, 0);
			goto bail_unlock;
		}
		params.out.bytes = out.bytes;
		params.out.count = out.count;
		trace_rv_mrc_msg_doit_evict("Evict amount: bytes, count",
					    params.out.bytes,
					    params.out.count, 0);
	} else {
		ret = -EINVAL;
		goto bail_unlock;
	}
	mutex_unlock(&rv->mutex);
	if (copy_to_user((void __user *)arg, &params.out, sizeof(params.out)))
		ret = -EFAULT;

	return ret;

bail_unlock:
	mutex_unlock(&rv->mutex);
	return ret;
}

/* called with cache->lock */
static bool rv_cache_mrce_filter(struct rv_mr_cache_entry *mrce, u64 addr,
				 u64 len, u32 acc)
{
	/* Allow subregion match */
	return mrce->addr <= addr &&
	       (mrce->addr + mrce->len) >= (addr + len) &&
	       mrce->access == acc;
}

/*
 * Called without cache->lock
 */
static void rv_cache_mrce_remove(struct rv_mr_cache *cache,
				 void *context, struct rv_mr_cache_entry *mrce,
				 int is_invalidate)
{
	struct rv_mr_cached *mrc = container_of(mrce, struct rv_mr_cached,
						entry);

	rv_drv_api_dereg_mem(&mrc->mr);
	kfree(mrc);
}

void rv_mr_init(void)
{
#ifdef RV_REG_MR_DISCRETE
	if (fr_batch_size > 0 && fr_batch_size < RV_FR_POOL_BATCH_SIZE_MIN)
		fr_batch_size = RV_FR_POOL_BATCH_SIZE_MIN;
	if (fr_pool_wm_lo == 0 || fr_pool_wm_lo > fr_batch_size)
		fr_pool_wm_lo = fr_batch_size >> 2;
#endif
}
