// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 - 2021 Intel Corporation.
 *
 * This file includes code obtained from: https://github.com/NVIDIA/gdrcopy/
 * under the following copyright and license.
 *
 * Copyright (c) 2014, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */
#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/aio.h>
#include <linux/bitmap.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/sched/mm.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/slab.h>

#include <rdma/ib.h>

#include "rv.h"
#include "gpu.h"
#include "trace.h"

/*
 * Default PSM limit is (TF_NFLOWS(32) + num_send_rdma(128)) * window_rv(2M)
 * So ideal GPU cache is > 320MB, however PSM can survive with less
 * Real limit here is GPU BAR space and GPU memory size
 */
unsigned int gpu_rdma_cache_size = 1024; /* this is MB */
module_param(gpu_rdma_cache_size, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(gpu_rdma_cache_size, "Size of gpu pin/mr (including RDMA) cache (in MB)");

/* when PSM is not using large window_sz RDMA, we can get by w/ smaller cache */
unsigned int gpu_cache_size = 256; /* this is MB */
module_param(gpu_cache_size, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(gpu_cache_size, "Size of gpu pin/mr cache (in MB)");

/**
 * struct gdr_mr - describes a gpu buffer and it's pinned and mmaped state.
 * A given gdr_mr can be mmap'ed for gdrcpy or registered for RDMA or both.
 * The gdr_mr in either case is tracked in a single gdrdata.cache per open.
 *
 * @mrc: The rv_mr_cache entry information and optional verbs RDMA MR
 *	mrc.mr is protected by gdrdata.mr_lock.
 * @host_addr: if not NULL, it is the host address mapping of this gpu buffer.
 *	protected by gdrdata.mr_lock
 * @mr_handle: a pseudo-random number used by this driver's mmap_handler to
 *	identify this gmr.  Used as a confirmation mmap is working on the
 *	expected gmr. Immutable.
 * @page_table: The GPU buf's NVidia page table with pinned pages
 *	Except in midst of create or destroy always has list of pinned pages, so
 *	page_table is essentally immutable and does not need gdrdata.mr_lock.
 * #ipc_handle: IPC handle for dma_buf (intel GPU)
 * @ref_cnt: A reference count on this structure.
 * @gd: The gdrdata and GPU cache this gdr_mr is part of (set NULL during
 *	destroy once we reach point gd and gd->mr_lock no longer are needed)
 *	otherwise immutable.
 * @lock: protects free_callback access to gd and changes to gd->refcount for
 *	this gdr_mr
 *
 * gdrdata.mr_lock's main goal is to protect against free_callback races with
 * ioctl's.  As such this is held during all cache calls which might call
 * ops->remove as well as all initialization of gdr_mr.mrc.mr and
 * gdr_mr.host_addr.  free_callback's wait for gdr_mr.mrc.entry.refcount == 0
 * also prevents races on using the verbs MR.
 *
 * gdr_mr.ref_cnt <= 2
 *	1 ref_cnt for entry on GPU cache (or while creating for insert)
 *	1 ref_cnt for potential free_callback
 *	cache entry usage for IOs tracked with gdr_mr.mrc_entry.refcount
 * The verbs MR and mmap'ing are not taken away until on path to destroy
 *	NIC MR is always taken away when remove from cache.
 *	The mmap and put_pages are attempted on cache remove, but may be
 *	deferred to free_callback if called in non-user context.
 *	Unpinning GPU pages may also be deferred to free_callback
 *	if put_pages races with free.
 *	The free_callback may occur after deinit so we need to allow a gdr_mr
 *	to exist in this state after gdrdata and gpu_data is gone.
 * To handle the potential for a free_callback after cache deinit, the
 * gdr_mr.gd is set to NULL when removing the gdr_mr from the cache.  The
 * gdr_mr.lock protects this operation.  If a check of gdr_mr.gd returns
 * NULL (within gdr_mr.lock), the function checking can be assured the
 * gdr_mr is no longer in the cache and no longer has an MR or mmap.
 */
struct gdr_mr {
	struct rv_mr_cached mrc;
	spinlock_t lock; /* see above */
	struct rv_gdrdata *gd;	/* valid until removed from cache */

	u64 host_addr;		/* for mmap */
	u32 mr_handle;		/* for mmap */

#ifdef NVIDIA_GPU_DIRECT
	nvidia_p2p_page_table_t *page_table;
#elif defined(INTEL_GPU_DIRECT)
	u32 ipc_handle;
	struct dma_buf *dbuf;
	struct dma_buf_attachment *dat;
	struct sg_table *sg_table;
	u64 alloc_id;
#endif
	struct kref ref_cnt;
	int rv_inx;
};

static inline void gdr_mr_put(struct gdr_mr *gmr);
static inline void gdr_mr_get(struct gdr_mr *gmr);
static void gdr_mr_put_gd(struct gdr_mr *gmr);
static void gdr_cache_mrce_remove(struct rv_mr_cache *cache, void *context,
				  struct rv_mr_cache_entry *mrce,
				  int is_invalidate);

#ifdef NVIDIA_GPU_DIRECT
static void gdr_mr_put_pages(struct gdr_mr *gmr);
static void gdrdrv_get_pages_free_callback(void *data);

static int pin_gpu_buf(struct gdr_mr *gmr)
{
	int ret;

	gdr_mr_get(gmr);	/* 2nd ref for free_callback */
	ret = get_gpu_pages(gmr->mrc.entry.addr, gmr->mrc.entry.len,
			    &gmr->page_table, gdrdrv_get_pages_free_callback,
			    gmr);
	trace_rv_gdr_msg_pin_gpu_buf(gmr->rv_inx, "page_table, mm",
				     (u64)gmr->page_table, (u64)current->mm);
	if (ret) {
		trace_rv_gdr_msg_pin_gpu_buf(gmr->rv_inx,
					     "failed to pin pages: size, ret",
					     gmr->mrc.entry.len, (u64)ret);
		/*
		 * Occasionally the page_table may be set. In this case, we
		 * should ignore and reset the pointer to avoid trigger
		 * WARN_ON during cleanup.
		 */
		gmr->page_table = NULL;
		/*
		 * nVidia doc says nvidia_p2p_get_pages returns -EINVAL for
		 * bad arg.  However may return -EINVAL if not enough GPU BAR
		 */
		if (ret == -EINVAL)
			ret = -ENOMEM;
		gdr_mr_put(gmr); /* free_callback's ref */
		gmr->gd->stats.failed_pin++;
		return ret;
	}
	trace_rv_gdr_msg_pin_gpu_buf(gmr->rv_inx, "entries, pages",
				     gmr->page_table->entries,
				     (u64)gmr->page_table->pages);

#ifdef NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE
	if (!NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE(gmr->page_table)) {
		rv_err(gmr->rv_inx,
		       "get_pages incompatible page table version\n");
		ret = -EOPNOTSUPP;
		gmr->gd->stats.failed_pin++;
		goto bail_unpin;
	}
#endif
	/*
	 * nVidia defines 4K and 128K possible page sizes, but sample code
	 * assumes 64K
	 */
	if (gmr->page_table->page_size != NVIDIA_P2P_PAGE_SIZE_64KB) {
		rv_err(gmr->rv_inx, "get_pages unexpected page size %d\n",
		       gmr->page_table->page_size);
		ret = -EOPNOTSUPP;
		gmr->gd->stats.failed_pin++;
		goto bail_unpin;
	}
	return 0;

bail_unpin:
	/* The following will call gdr_mr_put() once */
	mutex_unlock(&gmr->gd->mr_lock);
	gdr_mr_put_pages(gmr);
	mutex_lock(&gmr->gd->mr_lock);
	return ret;
}

#define pin_gpu_buf_mmap(gmr) pin_gpu_buf(gmr)
#define pin_gpu_buf_mr(gmr) pin_gpu_buf(gmr)

#elif defined(INTEL_GPU_DIRECT)
static int gpu_buf_get(struct gdr_mr *gmr)
{
	gmr->dbuf = dma_buf_get(gmr->ipc_handle);
	if (IS_ERR(gmr->dbuf)) {
		rv_err(gmr->rv_inx,
		       "Failed to get dma_buf: ipc_handle %u ret %p (%ld)\n",
		       gmr->ipc_handle, gmr->dbuf, PTR_ERR(gmr->dbuf));
		gmr->dbuf = NULL;
		gmr->gd->stats.failed_pin++;
		return -EINVAL;
	}
	return 0;
}

#define pin_gpu_buf_mmap(gmr) gpu_buf_get(gmr)

static void
rv_dmabuf_unsupported_move_notify(struct dma_buf_attachment *attach)
{
	struct gdr_mr *gmr = attach->importer_priv;

	rv_err(gmr->rv_inx,
	       "Invalidate callback should not be called when memory is pinned\n");
}

static struct dma_buf_attach_ops rv_dmabuf_attach_pinned_ops = {
	.allow_peer2peer = true,
	.move_notify = rv_dmabuf_unsupported_move_notify,
};

/* Promote mmap pin to mr pin */
static int pin_gpu_buf_promote(struct gdr_mr *gmr)
{
	int ret = 0;

	gmr->dat = dma_buf_dynamic_attach(gmr->dbuf,
					  gmr->gd->ib_dev->dma_device,
					  &rv_dmabuf_attach_pinned_ops, gmr);
	if (IS_ERR(gmr->dat)) {
		rv_err(gmr->rv_inx,
		       "Failed to attach dma_buf: %p (ipc %u) ret %ld\n",
		       gmr->dbuf, gmr->ipc_handle, PTR_ERR(gmr->dat));
		gmr->dat = NULL;
		ret = -EINVAL;
		goto pin_out;
	}

	dma_resv_lock(gmr->dat->dmabuf->resv, NULL);
	ret = dma_buf_pin(gmr->dat);
	if (ret) {
		rv_err(gmr->rv_inx, "Failed to pin dma_buf (ipc %u): %d\n",
		       gmr->ipc_handle, ret);
		goto dbuf_detach;
	}

	gmr->sg_table = dma_buf_map_attachment(gmr->dat, DMA_BIDIRECTIONAL);
	if (IS_ERR(gmr->sg_table)) {
		rv_err(gmr->rv_inx,
		       "Failed to map attach for dbuf %p (ipc %u), ret %ld\n",
		       gmr->dbuf, gmr->ipc_handle, PTR_ERR(gmr->sg_table));
		gmr->sg_table = NULL;
		ret = -EFAULT;
		goto dbuf_unpin;
	}
	dma_resv_unlock(gmr->dat->dmabuf->resv);

	return ret;

dbuf_unpin:
	dma_buf_unpin(gmr->dat);
dbuf_detach:
	dma_resv_unlock(gmr->dat->dmabuf->resv);
	dma_buf_detach(gmr->dbuf, gmr->dat);
	gmr->dat = NULL;
pin_out:
	gmr->gd->stats.failed_pin++;
	return ret;
}

static int pin_gpu_buf_mr(struct gdr_mr *gmr)
{
	int ret;

	ret = gpu_buf_get(gmr);
	if (ret)
		return ret;
	ret = pin_gpu_buf_promote(gmr);
	if (ret) {
		/* Release the dma-buf */
		dma_buf_put(gmr->dbuf);
		gmr->dbuf = NULL;
	}
	return ret;
}
#endif /* INTEl_GPU_DIRECT */

/**
 * gdrdrv_munmap() - unmap a pinned gpu page from process's address space.
 * @gmr: - the gpu buf being unmapped.
 *
 * Unmap host_addr from the user's address space.
 * gmr->host_addr must be non-NULL
 *
 * This could be called during process exit after a user-mode SEGFAULT.
 * Under this circumstance, we must not call vm_munmap(), otherwise the kernel
 * will segfault and panic.  Any fatal signal sets PF_EXITING and then removes
 * current->mm.  We test both since current->mm is needed for vm_mmap and
 * if EXITING is set mm is probably gone or soon will be
 *
 * If we are called in a non-process context, such as during NIC remove_one
 * we do nothing and let free_callback call this and hopefully cleanup.
 * Worst case, the remove_one of segfault will be fatal and linux will
 * vm_munmap as part of process exit.
 */
static inline void gdrdrv_munmap(struct gdr_mr *gmr)
{
	int unmap_ret = 0;

	trace_rv_gdr_msg_munmap(gmr->rv_inx, "mm, flags", (u64)current->mm,
				current->flags);
	if (current->mm && !(current->flags & PF_EXITING)) {
		unmap_ret = vm_munmap(gmr->host_addr, gmr->mrc.entry.len);
		WARN_ON(unmap_ret);
		gmr->host_addr = 0;
	} else {
		trace_rv_gdr_msg_munmap_skip(gmr->rv_inx, "skipped gmr, mm",
					     (u64)gmr, (u64)current->mm);
	}
}

/*
 * When ref_cnt hits zero it implies gdr_mr is no longer in cache
 * and no future free_callbacks coming
 */
static inline void mr_release(struct kref *kref)
{
	struct gdr_mr *gmr;

	gmr = container_of(kref, struct gdr_mr, ref_cnt);
	WARN_ON(gmr->gd); /* XXX drop this */
	WARN_ON(!RB_EMPTY_NODE(&gmr->mrc.entry.node));	/* XXX drop this */
	WARN_ON(gmr->mrc.entry.user_refcount);/* XXX drop this */
	WARN_ON(gmr->mrc.entry.refcount);	/* XXX drop this */
	WARN_ON(gmr->host_addr && current->mm);	/* XXX drop this */
	WARN_ON(gmr->mrc.mr.ib_mr);	/* XXX drop this */
#ifdef NVIDIA_GPU_DIRECT
	WARN_ON(gmr->page_table);	/* XXX drop this */
	trace_rv_gdr_mr_release(gmr->rv_inx, gmr->mrc.entry.addr,
				gmr->mrc.entry.len, gmr->mrc.entry.access);
#else
	trace_rv_gdr_mr_release(gmr->rv_inx, gmr->mrc.entry.addr,
				gmr->mrc.entry.len, gmr->alloc_id,
				gmr->mrc.entry.access, gmr->ipc_handle);
#endif
	kfree(gmr);
}

static inline void
gdr_mr_get(struct gdr_mr *gmr)
{
	kref_get(&gmr->ref_cnt);
}

static inline void
gdr_mr_put(struct gdr_mr *gmr)
{
	kref_put(&gmr->ref_cnt, mr_release);
}

/**
 * handle_to_offset() - convert a 32-bit number to a vm_mmap() offset argument.
 * @handle: an unsigned 32 bit psuedo random value.
 *
 * The 32 bit psuedo-random handle value is used to uniquely label a
 * struct gdr_mr, for use by this driver's mmap handler.
 *
 * This shifts left the 32-bit handle value to a "page-aligned" value that
 * can be passed as the offset argument to vm_mmap().  The vm_mmap()
 * function then shifts its offset argument 12 bits to the right
 * before assigning to the vm_pgoff member of the vm_area struct
 * that is passed to the mmap handler.
 *
 * This way, the vm_pgoff member contains the original 32-bit handle
 * value.
 *
 * Return: A value that can be passed as an offset into a vm_mmap() call.
 */
static inline off_t
handle_to_offset(u32 handle)
{
	return (off_t)handle << PAGE_SHIFT;
}

/* convert a vm_pgoff value to a 32-bit handle */
static inline u32
handle_from_vm_pgoff(unsigned long pgoff)
{
	return (u32)pgoff;
}

/* Generate a pseudo-random handle value, to be used during mmap operations. */
static inline u32
get_random_handle(void)
{
	return (u32)get_cycles();
}

static bool gdr_cache_mrce_filter(struct rv_mr_cache_entry *mrce, u64 addr,
				  u64 len, u32 acc)
{
	//return (bool)(mrc->addr == addr);
	return mrce->addr == addr && mrce->len == len && mrce->access == acc;
}

#ifdef NVIDIA_GPU_DIRECT
/*
 * no locks held.  Nvidia driver solves put_pages vs free_callback races
 * so we can safely clear gdr_mr.page_table when put_pages returns success
 */
static void gdr_mr_put_pages(struct gdr_mr *gmr)
{
	struct rv_gdrdata *gd = gmr->gd;
	int ret;

	/*
	 * put_pages requires the user's mm and tgid, otherwise it is a noop
	 * but silently returns success. During some cleanup cases this is
	 * called in a different context, in which case we must skip the
	 * put_pages and depend on the free_callback
	 */
	if (gd->tgid != task_tgid(current) || !current->mm)
		return;

	trace_rv_gdr_mr_put_pages(gmr->rv_inx, gmr->mrc.entry.addr,
				  gmr->mrc.entry.len, gmr->mrc.entry.access);
	/*
	 * can race with free_callback. nvidia_p2p_put_pages() returns:
	 * 0 - put_pages won race, pages unpinned, no future free_callback
	 * -EINVAL - free_callback won race and will unpin pages
	 * other - unknown errors
	 */
	ret = nvidia_p2p_put_pages(0, 0, gmr->mrc.entry.addr, gmr->page_table);
	trace_rv_gdr_msg_put_pages(gmr->rv_inx, "ret, mm", ret,
				   (u64)current->mm);
	if (!ret) {
		gmr->page_table = NULL;
		gdr_mr_put(gmr);	/* for callback */
	}
}
#endif /* NVIDIA_GPU_DIRECT */

/* break reference from gdr_mr to parent gd */
static void gdr_mr_put_gd(struct gdr_mr *gmr)
{
	struct rv_gdrdata *gd;
	unsigned long flags;

	spin_lock_irqsave(&gmr->lock, flags);
	gd = gmr->gd;
	gmr->gd = NULL;
	atomic_dec(&gd->refcount);
	spin_unlock_irqrestore(&gmr->lock, flags);
}

#ifdef INTEL_GPU_DIRECT
struct gdr_remove_gmr_work_item {
	struct work_struct remove_gmr_work;
	struct gdr_mr *gmr;
};

/* no harm if hold gd->mr_lock, but not needed as
 * the gmr and gmr->mr should have no more references to it and is on
 * the path to destruction.  Note on INTEL_GPU_DIRECT gmr only ever
 * has one reference and the gdr_invalidate which preceeded the mrce_remove
 * confirmed no more mrc references and took it off MR cache so can't be
 * found to add any other references.
 */
static void gdr_remove_gmr(struct gdr_mr *gmr)
{
	if (gmr->mrc.mr.ib_mr) {
		rv_drv_api_dereg_mem(&gmr->mrc.mr);
		/* unlikely to fail, forced to leak MR if dereg fails */
		memset(&gmr->mrc.mr, 0, sizeof(gmr->mrc.mr));
	}
	if (gmr->sg_table) {
		dma_buf_unmap_attachment(gmr->dat, gmr->sg_table,
					 DMA_BIDIRECTIONAL);
		gmr->sg_table = NULL;
	}
	if (gmr->dat) {
		dma_buf_unpin(gmr->dat);
		dma_buf_detach(gmr->dbuf, gmr->dat);
		gmr->dat = NULL;
	}
	if (gmr->dbuf) {
		dma_buf_put(gmr->dbuf);
		gmr->dbuf = NULL;
	}
	gdr_mr_put_gd(gmr);
	gdr_mr_put(gmr);	/* for cache */
}

/* worker for removing MR */
static void gdr_handle_remove_gmr(struct work_struct *work)
{

	struct gdr_remove_gmr_work_item *item =  container_of(work,
			struct gdr_remove_gmr_work_item, remove_gmr_work);
	gdr_remove_gmr(item->gmr);
	kfree(item);
}
#endif /* INTEL_GPU_DIRECT */

/* by the time this is called, the entry is off the cache and will not
 * be accessed by new cache searches nor future deinit.
 * This function can be called from two paths:
 * - from deinit (file close).
 * - from free_callback.
 * - from cache eviction (cache full or explicit evict ioctl).
 * Caller must hold gd->mr_lock as this protects our freeing of gdr_mr.mrc.mr
 * and gdr_mr.host_addr from races with free_callback.
 *
 * When called within free_callback, is_invalidate==1 and we avoid
 * calling put_pages as this causes a WARN_ON in nvidia code.
 *
 * For other callers, free_callback can race with this and we expect
 * put_pages to handle such races.
 */
static void gdr_cache_mrce_remove(struct rv_mr_cache *cache, void *context,
				  struct rv_mr_cache_entry *mrce,
				  int is_invalidate)
{
	struct gdr_mr *gmr = container_of(mrce, struct gdr_mr, mrc.entry);
	struct rv_gdrdata *gd = (struct rv_gdrdata *)context;

#ifdef INTEL_GPU_DIRECT
	struct gdr_remove_gmr_work_item *item;

	trace_rv_gdr_mr_mrce_remove(gmr->rv_inx, mrce->addr, mrce->len,
				    gmr->alloc_id, mrce->access,
				    gmr->ipc_handle);
#else
	trace_rv_gdr_mr_mrce_remove(gmr->rv_inx, mrce->addr, mrce->len,
				    mrce->access);
#endif
	trace_rv_gdr_msg_mrce_remove(gmr->rv_inx, "gmr, is_invalidate",
				     (u64)gmr, is_invalidate);
	WARN_ON(!RB_EMPTY_NODE(&mrce->node));	/* XXX drop this */
	WARN_ON(mrce->user_refcount);	/* XXX drop this */
	WARN_ON(mrce->refcount);	/* XXX drop this */
	WARN_ON(gd != gmr->gd);	/* XXX drop this */
	WARN_ON(gd->map_this_mr == gmr);	/* XXX drop this */
	trace_rv_gdr_msg_mrce_remove(gmr->rv_inx, "gmr, gd->refcount", (u64)gmr,
				     atomic_read(&gd->refcount));

#ifdef NVIDIA_GPU_DIRECT
	if (gmr->mrc.mr.ib_mr) {
		rv_drv_api_dereg_mem(&gmr->mrc.mr);
		/* unlikely to fail, forced to leak MR if dereg fails */
		memset(&gmr->mrc.mr, 0, sizeof(gmr->mrc.mr));
	}
	if (gmr->host_addr)
		gdrdrv_munmap(gmr);
	if (!is_invalidate && gmr->page_table) {
		mutex_unlock(&gd->mr_lock);
		gdr_mr_put_pages(gmr);
		mutex_lock(&gd->mr_lock);
	}
	gdr_mr_put_gd(gmr);
	gdr_mr_put(gmr);	/* for cache */
#elif defined(INTEL_GPU_DIRECT)
	/* must do munmap in process context */
	if (gmr->host_addr)
		gdrdrv_munmap(gmr);
	item = kzalloc(sizeof(*item), GFP_KERNEL);
	if (item) {
		INIT_WORK(&item->remove_gmr_work, gdr_handle_remove_gmr);
		item->gmr = gmr;
		rv_queue_work(&item->remove_gmr_work);
	} else {
		gdr_remove_gmr(gmr);
	}
#endif
}

static struct rv_mr_cache_ops gdr_cache_ops = {
	.filter = gdr_cache_mrce_filter,
	.remove = gdr_cache_mrce_remove,
};

int rv_gdr_init(int rv_inx, struct rv_gdrdata *gd, u8 gpu, u32 cache_size)
{
	int ret;

	gd->rv_inx = rv_inx;
	atomic_set(&gd->ioctl_busy_flag, 0);
	mutex_init(&gd->mr_lock);
	atomic_set(&gd->refcount, 0);
	memset(&gd->stats, 0, sizeof(gd->stats));
	if (!(gpu & RV_RDMA_MODE_GPU))
		return 0;
	gd->tgid = get_pid(task_tgid(current));
	if ((gpu & RV_RDMA_MODE_UPSIZE_GPU) && !cache_size)
		cache_size = gpu_rdma_cache_size;
	if (!cache_size)
		cache_size = gpu_cache_size;

	ret = rv_mr_cache_init(rv_inx, 'g', &gd->cache, &gdr_cache_ops, gd,
			       NULL, cache_size, 1);
	if (ret) {
		put_pid(gd->tgid);
		gd->tgid = NULL;
	}
	return ret;
}

/*
 * when GPUDirect RDMA is in use, this is called only after all IOs are done
 * so rv_mr_cache_deinit will be able to evict all entries.
 * deinit when part of a close can depend on file close to cleanup mm
 * but when part of a remove_one user may still have open.
 * In the rare case where detach_all is interrupted, this may wait for
 * those MRs to release their references to gdrdata.
 */
void rv_gdr_deinit(int rv_inx, struct rv_gdrdata *gd)
{
	unsigned long sleep_time = msecs_to_jiffies(1);

	if (rv_gdr_enabled(gd)) {
		mutex_lock(&gd->mr_lock);
		rv_mr_cache_deinit(rv_inx, &gd->cache);
		mutex_unlock(&gd->mr_lock);

		trace_rv_gdr_msg_deinit(gd->rv_inx, "wait for gd, refcount",
					(u64)gd, atomic_read(&gd->refcount));
		while (atomic_read(&gd->refcount))
			schedule_timeout_interruptible(sleep_time);

		WARN_ON(gd->map_this_mr);
		trace_rv_gdr_msg_deinit(gd->rv_inx,
					"done wait for gd, refcount",
					(u64)gd, atomic_read(&gd->refcount));
		put_pid(gd->tgid);
		gd->tgid = NULL;
	}
}

/* Invalidate a GPU MR cache entry.
 * If the entry still has an IO in flight, it is marked as "freeing" and the
 * lkey/rkey is invalidated so the IO will fail quickly as no one cares about
 * the IO anymore. In this case -EBUSY is returned.
 *
 * Otherwise, the usual case, we simply remove it from the MR cache,
 * and 0 is returned.
 *
 * caller must hold gd->mr_lock
 */
static int gdr_invalidate(struct rv_gdrdata *gd, struct gdr_mr *gmr)
{
	struct rv_user_mrs *umrs;

#ifdef INTEL_GPU_DIRECT
	trace_rv_gdr_mr_invalidate(gmr->rv_inx, gmr->mrc.entry.addr,
				      gmr->mrc.entry.len, gmr->alloc_id,
				      gmr->mrc.entry.access, gmr->ipc_handle);
#else
	trace_rv_gdr_mr_invalidate(gmr->rv_inx, gmr->mrc.entry.addr,
				      gmr->mrc.entry.len,
				      gmr->mrc.entry.access);
#endif
	if (rv_mr_cache_freeing_mrce(&gd->cache, &gmr->mrc.entry)) {
		if (gmr->mrc.mr.ib_mr) {
			umrs = container_of(gd, struct rv_user_mrs, gdrdata);
			rv_inv_gdr_rkey(umrs, gmr->mrc.entry.access,
					gmr->mrc.mr.ib_mr->rkey);
			gd->stats.inval_mr++;
		}
		return -EBUSY;
	}

	(void)rv_mr_cache_evict_mrce(&gd->cache, &gmr->mrc.entry, 1);
#ifdef NVIDIA_GPU_DIRECT
	/* the callback still has a reference to gmr, so gmr is valid */
	WARN_ON(gmr->host_addr);
	WARN_ON(gmr->mrc.mr.ib_mr);	/* XXX drop this */
#else
	/* gmr will have been freed, gmr ref count is never >1 */
#endif
	return 0;
}

#ifdef NVIDIA_GPU_DIRECT
/**
 * gdrdrv_get_pages_free_callback() - Callback handler for unpinning a GPU buf.
 * @data: - A pointer to a struct gdr_mr describing the gpu buf being freed.
 *
 * This is a callback function that the Nvidia driver calls when
 * a user frees a GPU buffer that has been pinned. This function waits for
 * IOs to complete, removes the gdr_mr from tha cache, unmaps and
 * unpins the gpu buffer.
 *
 * The GPU buffer can ALSO be unmmapped and unpinned through eviction (in ioctl)
 * or close (cache deinit) in which case gdr_cache_mrce_remove is called
 * and may race with this routine.
 *
 * Ultimately, the nvidia_p2p_put_pages() function determines which code
 * path wins this race.  If nvidia_p2p_put_pages() "wins", then
 * this callback function will not be called for that GPU buffer.  If this
 * callback handler "wins", then nvidia_p2p_put_pages() will fail with an
 * -EINVAL error code.
 *
 * In some situations, such as an app segfault or a device removal, the
 * gdr_cache_mrce_remove may be called in a non-user context, in which case
 * vm_munmap and nvidia_p2p_put_pages cannot be called.  In this case, the
 * remove will break the association with gdrdata, free the verbs MR and depend
 * on this callback to vm_munmap and free the pages.
 * In this case mr_lock is not needed by this callback (and is not available).
 *
 * To prevent deadlocks, nvidia_p2p_put_pages cannot be called while
 * holding any locks this might acquire (such as gdrdata.mr_lock).
 *
 * nvidia_p2p_put_pages solves races with free_callback, so once we
 * get here we know gdr_cache_mrce_remove will not be freeing gdr_mr.page_table.
 *
 * gdr_mr.page_table SHOULD NEVER be NULL when this function is entered.
 * If that happens, it indicates a bug either in this driver, or in
 * the NVidia driver.  But out of a sense of parania, we WARN on this
 * case, and call free_gpu_page_table() ONLY when this pointer is NOT
 * NULL.
 *
 * Typically nvidia caller will have set current->mm
 */
static void gdrdrv_get_pages_free_callback(void *data)
{
	struct gdr_mr *gmr = data;
	struct rv_gdrdata *gd;
	unsigned long flags;

	/* Sanity Check */
	if (!gmr || !gmr->page_table)
		return;

	trace_rv_gdr_mr_free_callback(gmr->rv_inx, gmr->mrc.entry.addr,
				      gmr->mrc.entry.len,
				      gmr->mrc.entry.access);
	trace_rv_gdr_msg_free_callback(gmr->rv_inx, "gmr, mm", (u64)gmr,
				       (u64)current->mm);
	spin_lock_irqsave(&gmr->lock, flags);
	gd = gmr->gd;
	if (gd) {
		atomic_inc(&gd->refcount);
		spin_unlock_irqrestore(&gmr->lock, flags);
		/*
		 * If the MR is still being referenced, invalidate the
		 * lkey/rkey and keep the MR.
		 */
		mutex_lock(&gd->mr_lock);
		if (gdr_invalidate(gd, gmr) )
			goto free_exit;
	} else {
		spin_unlock_irqrestore(&gmr->lock, flags);
	}
	WARN_ON(!RB_EMPTY_NODE(&gmr->mrc.entry.node)); /* XXX drop this */
free_exit:
	if (gmr->host_addr)
		gdrdrv_munmap(gmr);
	WARN_ON(!gmr->page_table);
	if (gmr->page_table) {
		free_gpu_page_table(gmr->page_table);
		gmr->page_table = NULL;
	}
	if (gd) {
		mutex_unlock(&gd->mr_lock);
		atomic_dec(&gd->refcount);
	}
	gdr_mr_put(gmr); /* for callback */
}
#endif /* NVIDIA_GPU_DIRECT */

/**
 * create_gmr() - create a new GPU memory region
 * @gd: A pointer to the rv_gdrdata for this open file descriptor.
 * @gpu_buf_addr: GPU buffer start address
 * @gpu_buf_size: GPU buffer size
 *
 * kref_init() intializes the reference count on this gdr_mr
 * to 1.  This is treated as the "cache mr_ref()" for this
 * gdr_mr.
 *
 * Return:
 * Pointer to the new gmr if successful. NULL otherwise.
 */
static struct gdr_mr *create_gmr(struct rv_gdrdata *gd,
				 u64 gpu_buf_addr, u64 gpu_buf_size,
#ifdef NVIDIA_GPU_DIRECT
				 u32 access)
#else
				 u32 access, u32 ipc_handle, u64 alloc_id)
#endif
{
	struct gdr_mr *gmr;

	gmr = kzalloc(sizeof(*gmr), GFP_KERNEL);
	if (!gmr)
		return gmr;

	rv_mr_cache_entry_init(&gmr->mrc.entry, gpu_buf_addr, gpu_buf_size,
			       access);
#ifdef INTEL_GPU_DIRECT
	gmr->ipc_handle = ipc_handle;
	gmr->alloc_id = alloc_id;
#endif
	spin_lock_init(&gmr->lock);
	atomic_inc(&gd->refcount);
	gmr->gd = gd;
	gmr->rv_inx = gd->rv_inx;
	gmr->mr_handle = get_random_handle();
	gmr->host_addr = 0;
#ifdef NVIDIA_GPU_DIRECT
	gmr->page_table = NULL;
#endif
	kref_init(&gmr->ref_cnt);
#ifdef INTEL_GPU_DIRECT
	trace_rv_gdr_mr_create(gmr->rv_inx, gpu_buf_addr, gpu_buf_size,
			       alloc_id, access, ipc_handle);
#else
	trace_rv_gdr_mr_create(gmr->rv_inx, gpu_buf_addr, gpu_buf_size, access);
#endif
	trace_rv_gdr_msg_create_gmr(gmr->rv_inx, "gmr, gd->refcount", (u64)gmr,
				    atomic_read(&gd->refcount));

	return gmr;
}

/**
 * pin a gpu buffer
 *
 * allocate and pin a gdr_mr for GPU memory.
 *
 * Return:
 * gdr_mr ptr - success, have mrc->entry.refcount and gmr->entry.ref_cnt
 * other - unable to pin the gpu buffer
 *	-ENOMEM for BAR or other resource exhaustions
 * called with gd->mr_lock
 */
static struct gdr_mr *
do_pin_gpu_buf(struct rv_gdrdata *gd,
	       u64 gpu_buf_addr, u64 gpu_buf_size, u32 access,
#ifdef NVIDIA_GPU_DIRECT
	       bool is_mmap)
#else
	       u32 ipc_handle, u64 alloc_id, bool is_mmap)
#endif
{
	struct gdr_mr *gmr;
	int ret = 0;

#ifdef NVIDIA_GPU_DIRECT
	gmr = create_gmr(gd, gpu_buf_addr, gpu_buf_size, access);
#else
	gmr = create_gmr(gd, gpu_buf_addr, gpu_buf_size, access, ipc_handle,
			 alloc_id);
#endif
	if (!gmr)
		return ERR_PTR(-ENOMEM);
#ifdef INTEL_GPU_DIRECT
	trace_rv_gdr_mr_do_pin(gmr->rv_inx, gpu_buf_addr, gpu_buf_size,
			       alloc_id, access, ipc_handle);
#else
	trace_rv_gdr_mr_do_pin(gmr->rv_inx, gpu_buf_addr, gpu_buf_size, access);
#endif

	if (is_mmap)
		ret = pin_gpu_buf_mmap(gmr);
	else
		ret = pin_gpu_buf_mr(gmr);
	if (ret) {
		trace_rv_gdr_msg_do_pin(gd->rv_inx,
					"failed to pin gpu pages: size, ret",
					gpu_buf_size, (u64)ret);
		rv_mr_cache_entry_deinit(&gmr->mrc.entry);
		gdr_mr_put_gd(gmr);
		gdr_mr_put(gmr);
		return ERR_PTR(ret);
	} else {
		return gmr;
	}
}

/*
 * caller holds gdrdata.mr_lock and has a reference for gdr_mr and a
 * gdr_mr.mrc.entry.refcount
 * ioctl_busy_lock protects against races with mmap calls for other ioctls.
 * For Nvidia GPU, gdr_mr.mrc.entry.refcount will hold off free_callback until
 * we and our caller are done, so it won't free gdr_mr.page_table until we are
 * done (and we release our gdr_mr.mrc.entry.refcount).
 */
static int
do_mmap_gpu_buf(struct file *fp, struct gdr_mr *gmr)
{
	struct rv_gdrdata *gd = gmr->gd;
	unsigned long virtual;
	int ret;

	WARN_ON(gd->map_this_mr);
	gd->map_this_mr = gmr;

	mutex_unlock(&gd->mr_lock);

	virtual = vm_mmap(fp, 0, gmr->mrc.entry.len, PROT_READ | PROT_WRITE,
			  MAP_SHARED, handle_to_offset(gmr->mr_handle));

	mutex_lock(&gd->mr_lock);

	gd->map_this_mr = NULL;
#ifdef NVIDIA_GPU_DIRECT
	WARN_ON(!gmr->page_table);
#endif

	if (IS_ERR((void *)virtual)) {
		ret = PTR_ERR((void *)virtual);
		rv_err(gmr->rv_inx, "mmap failed %d\n", ret);
		gd->stats.failed_mmap++;
		return ret;
	}

	WARN_ON(gmr->host_addr);
	gmr->host_addr = virtual;
	trace_rv_gdr_msg_do_mmap(gmr->rv_inx, "gmr, host_addr", (u64)gmr,
				 gmr->host_addr);
	return 0;
}

/**
 * fetch_user_query_ioctl_params - fetch and validate arguments.
 * @arg
 * @query_params
 *
 * Fetch from user space the query parameter block and validate its content.
 *
 * Return:
 * 0 on success
 * -EFAULT on bad parameter block address
 * -EINVAL on invalid content of parameter block
 */
int
fetch_user_query_ioctl_params(unsigned long arg, int rev,
			      struct rv_gpu_mem_params *query_params)
{
	if (rev <= RV_GPU_ABI_VER_MINOR_0) {
		/* smaller structure w/o alloc_id */
		if (copy_from_user(&query_params->in,
				   (struct rv_gpu_mem_params __user *)arg,
				   sizeof(struct rv_gpu_mem_params_r0_in)))
			return -EFAULT;
	} else {
		if (copy_from_user(&query_params->in,
				   (struct rv_gpu_mem_params __user *)arg,
				   sizeof(query_params->in)))
			return -EFAULT;
	}
	if ((!query_params->in.gpu_buf_size) ||
	    !(query_params->in.access & IBV_ACCESS_IS_GPU_ADDR) ||
#ifdef NVIDIA_GPU_DIRECT
	    (query_params->in.gpu_buf_addr & ~GPU_PAGE_MASK) ||
	    (query_params->in.gpu_buf_size & ~GPU_PAGE_MASK))
#else
	    (rev <= RV_GPU_ABI_VER_MINOR_0) ||	/* lacks alloc_id */
	    !(query_params->in.ipc_handle))
#endif
		return -EINVAL;

	return 0;
}

/**
 * rv_ioctl_gpu_buf_pin_mmap() - process the RV_IOCTL_GDR_GPU_PIN_MMAP
 * @fp: A pointer to the open file structure for this file.
 * @gd: A pointer to the rv_gdrdata structure for this file.
 * @arg: A pointer to the struct rv_gpu_mem_params argument.
 *
 * This function handles ioctl() requests to pin and mmap a gpu buffer.
 * mmap buffers are short lived, so we immediately put our mrce->refcount
 * and expect PSM/app to not free them while gdrcopy is in progress.
 *
 * Check the cache for the desired gpu buffer
 * If it isn't found, then pin and mmap it, and insert in cache.
 *
 * Must release gdrdata.mr_lock during vm_mmap, so ioctl_busy lock prevents
 * races with other ioctl calls.
 *
 * A free_callback can race and set freeing flag for our gdr_mr in which
 * case for a new gdr_mr, insert will fail and we cleanup our gdr_mr and then
 * free_callback can proceed.  For a cache hit, our put of mrce->refcount
 * can allow free_callback to cleanup the gdr_mr immediately after we are done.
 *
 * On success, return to the user the user host address of this mapping.
 * The "fast path" in this code is when the gpu buffer is already found
 * in the cache.  We want this case to run with minimal overhead.
 *
 * We require access to specify at least IBV_ACCESS_IS_GPU_ADDR, this way
 * RV_IOCTL_EVICT can use that flag in access to identify requests for
 * exact match GPU pin (or verbs MR) evictions (essentially an unpin call)
 *
 * Return:
 * 0 - success,
 * -EFAULT - The copy_from_user() or copy_to_user() function failed,
 * -EINVAL - The gpu buffer described is not properly aligned,
 * -EINVAL - The operation requested was not valid,
 * -ENOENT - An unpin was requested, but the desired gpu buffer was not found,
 */
int
rv_ioctl_gpu_buf_pin_mmap(struct file *fp, struct rv_gdrdata *gd,
			  unsigned long arg, int rev)
{
	struct rv_gpu_mem_params query_params;
	struct gdr_mr *gmr = NULL;
	int ret = 0;
	struct rv_mr_cache_entry *mrce;

	if (!rv_gdr_enabled(gd))
		return -EINVAL;
	if (gd->tgid != task_tgid(current) || !current->mm)
		return -EINVAL;
	if (atomic_cmpxchg(&gd->ioctl_busy_flag, 0, 1))
		return -EINVAL;
	ret = fetch_user_query_ioctl_params(arg, rev, &query_params);
	if (ret)
		goto done;

	mutex_lock(&gd->mr_lock);
	/* callers gpu buffer will be page aligned and multiple of pages */
	mrce = rv_mr_cache_search_get(&gd->cache,
				      query_params.in.gpu_buf_addr,
				      query_params.in.gpu_buf_size,
				      query_params.in.access,
#ifdef INTEL_GPU_DIRECT
				      false, true);
#else
				      true, true);
#endif
	if (IS_ERR(mrce)) {
		ret = PTR_ERR(mrce);
		goto unlock;
	}
	if (mrce) {
		gmr = container_of(mrce, struct gdr_mr, mrc.entry);
		WARN_ON(mrce->len < query_params.in.gpu_buf_size);
#ifdef INTEL_GPU_DIRECT
		if (gmr->alloc_id != query_params.in.alloc_id) {
			/* we still have gd->mr_lock so mrce won't go away */
			rv_mr_cache_entry_put(&gd->cache, mrce);
			gdr_invalidate(gd, gmr);
			goto dopin;
		}
		rv_mr_cache_inc_hit(&gd->cache);	// was a real hit
#endif
		if (!gmr->host_addr) {
			/* This will release and reaqcuire mr_lock */
			ret = do_mmap_gpu_buf(fp, gmr);
			if (ret)
				goto done_put;
			WARN_ON(!gmr->mrc.mr.ib_mr);
			gd->stats.hit_add_mmap++;
			rv_mr_cache_entry_promote(&gd->cache, mrce);
		} else {
			gd->stats.hit_mmap++;
		}
		goto skip_pin_mmap;
	}
#ifdef INTEL_GPU_DIRECT
dopin:
#endif
	gmr = do_pin_gpu_buf(gd, query_params.in.gpu_buf_addr,
			     query_params.in.gpu_buf_size,
			     query_params.in.access,
#ifdef NVIDIA_GPU_DIRECT
			     true);
#else
			     query_params.in.ipc_handle,
			     query_params.in.alloc_id, true);
#endif
	if (IS_ERR(gmr)) {
		/* if unable to pin (out of BAR) let PSM evict and retry */
		ret = PTR_ERR(gmr);
		goto unlock;
	}

	/* This will release and reaqcuire mr_lock */
	ret = do_mmap_gpu_buf(fp, gmr);
	if (ret)
		goto bail_unpin;
	gmr->mrc.entry.type = RV_MRCE_TYPE_MMAP;
	/* If evict, this may release and reaqcuire mr_lock while put_pages */
	ret = rv_mr_cache_insert(&gd->cache, &gmr->mrc.entry);
	if (ret) {
		rv_err(gd->rv_inx, "failed to insert gdr cache %d\n", ret);
		goto bail_unmmap;
	}
skip_pin_mmap:
	query_params.out.host_buf_addr = gmr->host_addr;
#ifdef NVIDIA_GPU_DIRECT
	query_params.out.phys_addr = gmr->page_table->pages[0]->physical_address;
#else
	query_params.out.phys_addr = 0;
#endif
	if (copy_to_user((struct hfi_gdr_query_params __user *)arg,
			 &query_params.out,
			 sizeof(query_params.out)))
		ret = -EFAULT;
done_put:
#ifdef NVIDIA_GPU_DIRECT
	trace_rv_gdr_mr_pin_mmap(gmr->rv_inx, gmr->mrc.entry.addr,
				 gmr->mrc.entry.len, gmr->mrc.entry.access);
#else
	trace_rv_gdr_mr_pin_mmap(gmr->rv_inx, gmr->mrc.entry.addr,
				 gmr->mrc.entry.len, gmr->alloc_id,
				 gmr->mrc.entry.access, gmr->ipc_handle);
#endif
	rv_mr_cache_put(&gd->cache, &gmr->mrc.entry, true);
unlock:
	mutex_unlock(&gd->mr_lock);
done:
	WARN_ON(atomic_read(&gd->ioctl_busy_flag) != 1);
	atomic_set(&gd->ioctl_busy_flag, 0);
	return ret;

bail_unmmap:
bail_unpin:
	rv_err(gd->rv_inx, "fail pin: gmr %p\n", gmr);
	/* not in cache yet so can't call rv_mr_cache_put */
	rv_mr_cache_entry_deinit(&gmr->mrc.entry);
	/* remove checks more than needed, but ok */
	gdr_cache_mrce_remove(&gd->cache, gd, &gmr->mrc.entry, 0);
	goto unlock;
}

/*
 * rv_ioctl_gpu_evict() - GPU specific part of RV_IOCTL_EVICT
 * @gd: A pointer to the rv_gdrdata structure for this file.
 * @params: params from the ioctl, caller will copy_to_user
 *
 * This function handles the ioctl() request to unpin and unmap a gpu buffer.
 *
 * Return:
 * 0 - success,
 * -EINVAL - The operation requested was not valid,
 * -ENOENT - No entry was evicted from cache
 */
int rv_ioctl_gpu_evict(struct rv_gdrdata *gd, struct rv_evict_params *params)
{
	int ret = 0;
	struct evict_out out;

	if (!rv_gdr_enabled(gd))
		return -EINVAL;
	if (gd->tgid != task_tgid(current) || !current->mm)
		return -EINVAL;
	if (atomic_cmpxchg(&gd->ioctl_busy_flag, 0, 1))
		return -EINVAL;

	mutex_lock(&gd->mr_lock);
	if (params->in.type == RV_EVICT_TYPE_SEARCH_EXACT) {
		trace_rv_mr_cache_gpu_evict(params->in.search.addr,
					    params->in.search.length,
					    params->in.search.access);
		ret = rv_mr_cache_evict_exact(&gd->cache,
					      params->in.search.addr,
					      params->in.search.length,
					      params->in.search.access);
		if (ret) {
			trace_rv_mrc_msg_gpu_evict("Evict exact failed: ret",
						   (u64)ret, 0, 0);
			goto bail_unlock;
		}
		params->out.bytes = params->in.search.length;
		params->out.count = 1;
		trace_rv_mrc_msg_gpu_evict("Evict exact: bytes, count",
					   params->out.bytes,
					   params->out.count, 0);
	} else if (params->in.type == RV_EVICT_TYPE_GPU_SEARCH_RANGE) {
		trace_rv_mr_cache_gpu_evict(params->in.search.addr,
					    params->in.search.length,
					    0);
		ret = rv_mr_cache_evict_range(&gd->cache,
					      params->in.search.addr,
					      params->in.search.length,
					      &out);
		if (ret) {
			trace_rv_mrc_msg_gpu_evict("Evict range failed: ret",
						   (u64)ret, 0, 0);
			goto bail_unlock;
		}
		params->out.bytes = out.bytes;
		params->out.count = out.count;
		trace_rv_mrc_msg_gpu_evict("Evict range: bytes, count",
					   params->out.bytes,
					   params->out.count, 0);
	} else if (params->in.type == RV_EVICT_TYPE_GPU_AMOUNT) {
		trace_rv_mrc_msg_gpu_evict("Evict amount: bytes, count",
					   params->in.amount.bytes,
					   params->in.amount.count, 0);
		ret = rv_mr_cache_evict_amount(&gd->cache,
					       params->in.amount.bytes,
					       params->in.amount.count,
					       &out);
		if (ret) {
			trace_rv_mrc_msg_gpu_evict("Evict amount failed: ret",
						   (u64)ret, 0, 0);
			goto bail_unlock;
		}
		params->out.bytes = out.bytes;
		params->out.count = out.count;
		trace_rv_mrc_msg_gpu_evict("Evict amount: bytes, count",
					   params->out.bytes,
					   params->out.count, 0);
	} else {
		ret = -EINVAL;
	}
bail_unlock:
	mutex_unlock(&gd->mr_lock);
	WARN_ON(atomic_read(&gd->ioctl_busy_flag) != 1);
	atomic_set(&gd->ioctl_busy_flag, 0);
	return ret;
}

#ifdef NVIDIA_GPU_DIRECT
/**
 * gdr_mmap_phys_mem_wcomb()
 * @vma: A pointer to a vm_area_struct for physical memory segment to be mmaped.
 * @vaddr: A virtual address to mmap a physical memory segment.
 * @paddr: The physical address of the physical memory segment.
 * @size: The size of the physical memory segment.
 *
 * This function remaps a contiguous physical memory region into the user's
 * address space.  THe mapping is in write combining mode.
 *
 * Return:
 * 0 - success,
 * -EAGAIN - the mmap request failed
 */
static int gdr_mmap_phys_mem_wcomb(struct vm_area_struct *vma,
				   unsigned long vaddr,
				   unsigned long paddr,
				   size_t size)
{
	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	if (io_remap_pfn_range(vma, vaddr, PHYS_PFN(paddr), size,
			       vma->vm_page_prot))
		return -EAGAIN;
	return 0;
}

static int gdr_mmap(struct gdr_mr *gmr, struct vm_area_struct *vma)
{
	int ret = 0;
	size_t size = vma->vm_end - vma->vm_start;
	int p = 0;
	unsigned long vaddr, prev_page_paddr;
	int phys_contiguous = 1;

	WARN_ON(!gmr->page_table); /* XXX - drop this */

	/* check for physically contiguous IO range */
	vaddr = vma->vm_start;
	prev_page_paddr = gmr->page_table->pages[0]->physical_address;
	for (p = 1; p < gmr->page_table->entries; ++p) {
		struct nvidia_p2p_page *page = gmr->page_table->pages[p];
		unsigned long page_paddr = page->physical_address;
		if (prev_page_paddr + NV_GPU_PAGE_SIZE != page_paddr) {
			phys_contiguous = 0;
			break;
		}
		prev_page_paddr = page_paddr;
	}

	if (phys_contiguous) {
		size_t len = min(size,
				 NV_GPU_PAGE_SIZE * gmr->page_table->entries);
		unsigned long page0_paddr =
			gmr->page_table->pages[0]->physical_address;
		ret = gdr_mmap_phys_mem_wcomb(vma, vaddr, page0_paddr, len);
		if (ret)
			goto out;

	} else {
		/*
		 * If not contiguous, map individual GPU pages separately.
		 * In this case, write-combining performance can be really
		 * bad, not sure why.
		 */
		p = 0;
		while (size && p < gmr->page_table->entries) {
			struct nvidia_p2p_page *page =
						gmr->page_table->pages[p];
			unsigned long page_paddr = page->physical_address;
			size_t len = min(NV_GPU_PAGE_SIZE, size);

			ret = gdr_mmap_phys_mem_wcomb(vma, vaddr, page_paddr,
						      len);
			if (ret)
				goto out;

			vaddr += len;
			size -= len;
			++p;
		}
	}

out:
	return ret;
}
#elif defined(INTEL_GPU_DIRECT)
static int gdr_mmap(struct gdr_mr *gmr, struct vm_area_struct *vma)
{
	return dma_buf_mmap(gmr->dbuf, vma, 0);
}
#endif /* NVIDIA_GPU_DIRECT */

/**
 * rv_gdr_mmap() - This driver's mmap handler for GPU ops.
 * @filep: A pointer to the open file structure for this file.
 * @vma: A pointer to the vma_area struct.
 *
 * This driver's mmap handler is normally invoked through this driver's
 * ioctl handler when it is mmapping a pinned GPU buffer into the user's
 * address space.
 *
 * This driver's mmap handler COULD also be called by the user calling
 * the mmap() system call.  This is not a valid case for this driver,
 * and that mmap() system call will fail.
 *
 * Return:
 * 0 - success,
 * -EINVAL - The requested gpu buffer description is invalid
 */
int rv_gdr_mmap(struct file *filep, struct rv_gdrdata *gd,
		struct vm_area_struct *vma)
{
	int ret = 0;
	struct gdr_mr *gmr;

	if (!rv_gdr_enabled(gd))
		return -EINVAL;
	if (gd->tgid != task_tgid(current) || !current->mm)
		return -EINVAL;

	mutex_lock(&gd->mr_lock);

	gmr = gd->map_this_mr;
	if (!gmr) {	/* direct user call of mmap */
		rv_err(gd->rv_inx, "direct user mmap call for GPU\n");
		ret = -EINVAL;
		goto out;
	}

	if (gmr->mr_handle != handle_from_vm_pgoff(vma->vm_pgoff)) {
		rv_err(gd->rv_inx,
		       "direct user mmap call for GPU, wrong offset\n");
		ret = -EINVAL;
		goto out;
	}
#ifdef NVIDIA_GPU_DIRECT
	if (gmr->mrc.entry.freeing) /* XXX - drop this */
		rv_err(gmr->rv_inx, "mmap race with free_callback\n");
	trace_rv_gdr_mr_mmap(gmr->rv_inx, gmr->mrc.entry.addr,
			     gmr->mrc.entry.len, gmr->mrc.entry.access);
#else
	if (gmr->mrc.entry.freeing) /* XXX - drop this */
		rv_err(gmr->rv_inx, "mmap race with invalidate\n");
	trace_rv_gdr_mr_mmap(gmr->rv_inx, gmr->mrc.entry.addr,
			     gmr->mrc.entry.len, gmr->alloc_id,
			     gmr->mrc.entry.access, gmr->ipc_handle);
#endif
	trace_rv_gdr_msg_mmap(gmr->rv_inx, "gmr, freeing", (u64)gmr,
			      gmr->mrc.entry.freeing);

	ret = gdr_mmap(gmr, vma);

out:
	mutex_unlock(&gd->mr_lock);

	return ret;
}

/**
 * rv_ioctl_gpu_reg_mem() - process the reg_mem for GPU address
 */
int
rv_ioctl_gpu_reg_mem(struct file *fp, struct rv_user *rv, struct rv_gdrdata *gd,
		     struct rv_mem_params *mparams)
{
	struct gdr_mr *gmr = NULL;
	int ret = 0;
	struct rv_mr_cache_entry *mrce;

#ifdef INTEL_GPU_DIRECT
	if (!mparams->in.ipc_handle) {
		rv_err(rv->inx, "No ipc_handle for reg gpu mr\n");
		return -EINVAL;
	}
#endif
	if (!rv_gdr_enabled(gd))
		return -EINVAL;
	if (gd->tgid != task_tgid(current) || !current->mm)
		return -EINVAL;
	if (atomic_cmpxchg(&gd->ioctl_busy_flag, 0, 1))
		return -EINVAL;

	mutex_lock(&gd->mr_lock);
	mrce = rv_mr_cache_search_get(&gd->cache, mparams->in.addr,
				      mparams->in.length, mparams->in.access,
#ifdef INTEL_GPU_DIRECT
				      false, true);
#else
				      true, true);
#endif
	if (IS_ERR(mrce)) {
		ret = PTR_ERR(mrce);
		goto unlock;
	}
	if (mrce) {
		gmr = container_of(mrce, struct gdr_mr, mrc.entry);
		WARN_ON(mrce->len < mparams->in.length);
#ifdef INTEL_GPU_DIRECT
		if (gmr->alloc_id != mparams->in.alloc_id) {
			/* we still have gd->mr_lock so mrce won't go away */
			rv_mr_cache_entry_put(&gd->cache, mrce);
			gdr_invalidate(gd, gmr);
			goto dopin;
		}
		rv_mr_cache_inc_hit(&gd->cache);	// was a real hit
#endif
		if (!gmr->mrc.mr.ib_mr) {
#ifdef INTEL_GPU_DIRECT
			/*
			 * For dma_buf, the mmap pin and mr pin are different.
			 * Therefore, more actions are required before the
			 * cache entry can be used.
			 */
			ret = pin_gpu_buf_promote(gmr);
			if (ret) {
				gd->stats.failed_reg++;
				goto bail_put;
			}
#endif
			ret = rv_drv_api_reg_mem(rv, &mparams->in,
						 &gmr->mrc.mr);
			if (ret) {
				gd->stats.failed_reg++;
				goto bail_put;	/* keep mmap entry */
			}
#ifdef INTEL_GPU_DIRECT
			trace_rv_gdr_mr_reg_mem(gmr->rv_inx, mparams->in.addr,
						mparams->in.length,
						mparams->in.alloc_id,
						mparams->in.access,
						mparams->in.ipc_handle);
#else
			trace_rv_gdr_mr_reg_mem(gmr->rv_inx, mparams->in.addr,
						mparams->in.length,
						mparams->in.access);
#endif
			trace_rv_gdr_msg_reg_mem(gmr->rv_inx, "gmr, iova",
						 (u64)gmr,
						 gmr->mrc.mr.ib_mr->iova);
			WARN_ON(!gmr->host_addr);
			gd->stats.hit_add_reg++;
			rv_mr_cache_entry_promote(&gd->cache, mrce);
		} else {
			gd->stats.hit_reg++;
		}
		goto skip_pin_reg;
	}
#ifdef INTEL_GPU_DIRECT
dopin:
#endif
	gmr = do_pin_gpu_buf(gd, mparams->in.addr, mparams->in.length,
#ifdef NVIDIA_GPU_DIRECT
			     mparams->in.access,
#else
			     mparams->in.access, mparams->in.ipc_handle,
			     mparams->in.alloc_id,
#endif
			     false);
	if (IS_ERR(gmr)) {
		/* if unable to pin (out of BAR) let PSM evict and retry */
		ret = PTR_ERR(gmr);
		goto unlock;
	}
	ret = rv_drv_api_reg_mem(rv, &mparams->in, &gmr->mrc.mr);
	if (ret) {
		WARN_ON(gmr->mrc.mr.ib_mr); /* XXX drop this */
		gd->stats.failed_reg++;
		goto bail_unpin;
	}
	gmr->mrc.entry.type = RV_MRCE_TYPE_REG;
#ifdef INTEL_GPU_DIRECT
	trace_rv_gdr_mr_reg_mem(gmr->rv_inx, mparams->in.addr,
				mparams->in.length, mparams->in.alloc_id,
				mparams->in.access, mparams->in.ipc_handle);
#else
	trace_rv_gdr_mr_reg_mem(gmr->rv_inx, mparams->in.addr,
				mparams->in.length, mparams->in.access);
#endif
	trace_rv_gdr_msg_reg_mem(gmr->rv_inx, "gmr, iova",
				 (u64)gmr, gmr->mrc.mr.ib_mr->iova);
	/* If need to evict, this will release and reaqcuire mr_lock */
	ret = rv_mr_cache_insert(&gd->cache, &gmr->mrc.entry);
	if (ret) {
		rv_err(rv->inx, "failed to insert gdr cache %d\n", ret);
		goto bail_dereg;
	}
skip_pin_reg:
	mparams->out.mr_handle = (uint64_t)gmr;
	mparams->out.iova = gmr->mrc.mr.ib_mr->iova;
	mparams->out.lkey = gmr->mrc.mr.ib_mr->lkey;
	mparams->out.rkey = gmr->mrc.mr.ib_mr->rkey;
unlock:
	mutex_unlock(&gd->mr_lock);
	WARN_ON(atomic_read(&gd->ioctl_busy_flag) != 1);
	atomic_set(&gd->ioctl_busy_flag, 0);
	return ret;

bail_dereg:
bail_unpin:
	rv_err(rv->inx, "fail reg: gmr %p\n", gmr);
	/* not in cache yet so can't call rv_mr_cache_put */
	rv_mr_cache_entry_deinit(&gmr->mrc.entry);
	/* remove checks more than needed, but ok */
	gdr_cache_mrce_remove(&gd->cache, gd, &gmr->mrc.entry, 0);
	goto unlock;

bail_put:
	rv_err(rv->inx, "put on failed reg: gmr %p\n", gmr);
	rv_mr_cache_put(&gd->cache, &gmr->mrc.entry, true);
	goto unlock;
}

/**
 * rv_ioctl_gpu_dereg_mem() - process the dereg_mem for GPU address
 */
int
rv_ioctl_gpu_dereg_mem(struct rv_gdrdata *gd,
		       struct rv_dereg_params_in *dparams)
{
	int ret = 0;
	struct rv_mr_cache_entry *mrce;

	if (!rv_gdr_enabled(gd))
		return -EINVAL;
	if (gd->tgid != task_tgid(current) || !current->mm)
		return -EINVAL;
	if (atomic_cmpxchg(&gd->ioctl_busy_flag, 0, 1))
		return -EINVAL;

	mutex_lock(&gd->mr_lock);
	mrce = rv_mr_cache_search_put(&gd->cache, dparams->addr,
				      dparams->length, dparams->access);
	if (!mrce)
		ret = -EINVAL;
	mutex_unlock(&gd->mr_lock);
	WARN_ON(atomic_read(&gd->ioctl_busy_flag) != 1);
	atomic_set(&gd->ioctl_busy_flag, 0);
	return ret;
}

/**
 * rv_gdr_map_verbs_mr
 *
 * Return:
 * >0 - success, number of sgl mapped
 * -EINVAL - The requested gpu buffer description is invalid
 *  caller holds gd->mr_lock
 */
int rv_gdr_map_verbs_mr(int rv_inx, struct mr_info *mr,
			struct rv_mem_params_in *minfo)
{
	int ret = 0;
	struct gdr_mr *gmr = container_of(mr, struct gdr_mr, mrc.mr);
	struct scatterlist *sgl;	/* list */
	unsigned int nents = 0;
	unsigned int offset;
	int num;
	struct scatterlist *sg;		/* iterator for sgl */
	int i;
	u64 addr;
	u64 tlen;
	unsigned int len;
	u32 max_sg;
#ifdef INTEL_GPU_DIRECT
	u64 start, end;
	struct scatterlist *dsg; /* sg from dma_buf */
#endif

	if (!rv_gdr_enabled(gmr->gd))
		return -EINVAL;
	if (gmr->gd->tgid != task_tgid(current) || !current->mm)
		return -EINVAL;

#ifdef INTEL_GPU_DIRECT
	trace_rv_gdr_mr_map_verbs_mr(rv_inx, gmr->mrc.entry.addr,
				     gmr->mrc.entry.len, gmr->alloc_id,
				     gmr->mrc.entry.access, gmr->ipc_handle);
	if (gmr->mrc.entry.freeing) /* XXX - drop this */
		rv_err(gmr->rv_inx, "reg_mr race with invalidate\n");
#else
	trace_rv_gdr_mr_map_verbs_mr(rv_inx, gmr->mrc.entry.addr,
				     gmr->mrc.entry.len,
				     gmr->mrc.entry.access);
	if (gmr->mrc.entry.freeing) /* XXX - drop this */
		rv_err(gmr->rv_inx, "reg_mr race with free_callback\n");
#endif
	trace_rv_gdr_msg_map_verbs_mr(rv_inx, "gmr, freeing", (u64)gmr,
				      gmr->mrc.entry.freeing);
#ifdef NVIDIA_GPU_DIRECT
	WARN_ON(!gmr->page_table); /* XXX - drop this */

	nents = gmr->page_table->entries;
#elif defined(INTEL_GPU_DIRECT)
	nents = gmr->sg_table->nents;
#endif
	if (!nents)
		return -EINVAL;

	/* Allocate a kernel verbs mr */
#ifdef NVIDIA_GPU_DIRECT
	max_sg = nents * (GPU_PAGE_SIZE >> PAGE_SHIFT);
#else
	start = ALIGN_DOWN(minfo->addr, GPU_PAGE_SIZE);
	end = ALIGN(minfo->addr + minfo->length, GPU_PAGE_SIZE);
	max_sg = (end - start) >>  PAGE_SHIFT;
#endif
	mr->ib_mr = ib_alloc_mr(mr->ib_pd, IB_MR_TYPE_MEM_REG, max_sg);
	if (IS_ERR(mr->ib_mr)) {
		rv_err(rv_inx, "Failed to alloc kernel verbs mr: %ld\n",
		       PTR_ERR(mr->ib_mr));
		ret = PTR_ERR(mr->ib_mr);
		mr->ib_mr = NULL;
		return ret;
	}

	offset = minfo->addr & (GPU_PAGE_SIZE - 1);
	/* build a scatterlist, page_link is empty and offset==0 for each */
	/* we are doing peer2peer DMA, so we shouldn't need to map in IOMMU */
	sgl = kmalloc_array(nents, sizeof(struct scatterlist), GFP_KERNEL);
	if (!sgl) {
		ret = -ENOMEM;
		goto bail_mr;
	}
	sg_init_table(sgl, nents);
	tlen = minfo->length + offset;
#ifdef INTEL_GPU_DIRECT
	dsg = gmr->sg_table->sgl;
#endif
	for_each_sg(sgl, sg, nents, i) {
#ifdef NVIDIA_GPU_DIRECT
		addr = gmr->page_table->pages[i]->physical_address;
#else
		addr = sg_dma_address(dsg);
#endif
		trace_rv_gdr_msg_map_verbs_mr(rv_inx, "i, physical_address", i,
					      addr);
		sg_dma_address(sg) = addr;
#ifdef NVIDIA_GPU_DIRECT
		len = tlen > GPU_PAGE_SIZE ?
			GPU_PAGE_SIZE : (unsigned int)tlen;
#else
		len = sg_dma_len(dsg) > tlen ? tlen : sg_dma_len(dsg);
#endif
		sg->length = len;
		sg_dma_len(sg) = len;
		tlen -= len;
		if (!tlen) {
			i++;
			break;
		}
#ifdef INTEL_GPU_DIRECT
		dsg = sg_next(dsg);
#endif
	}
	nents = i;

	trace_rv_gdr_msg_map_verbs_mr(rv_inx, "offset, page_size", offset,
				      PAGE_SIZE);
	num = ib_map_mr_sg(mr->ib_mr, sgl, nents, &offset, PAGE_SIZE);
	kfree(sgl);
	if (num < (int)nents) {
		rv_err(rv_inx, "Failed to map GPU gmr: %d %d\n", num, nents);
		if (num < 0)
			ret = num; /* what error code does driver return? */
		else
			ret = -EINVAL;	/* driver misbehaved */
		goto bail_mr;
	}
	return num;

bail_mr:
	ib_dereg_mr(mr->ib_mr);
	mr->ib_mr = NULL;
	return ret;
}

/* for RDMA WQE handling */
/* Could return an ERROR for GPU if MR is stale ("freeing") */
struct rv_mr_cache_entry *rv_gdr_search_get(struct rv_gdrdata *gd,
					    struct rv_post_write_params *params)
{
	struct rv_mr_cache_entry *mrce;

	if (!rv_gdr_enabled(gd))
		return NULL;
	if (gd->tgid != task_tgid(current) || !current->mm)
		return NULL;
	mutex_lock(&gd->mr_lock);
	mrce = rv_mr_cache_search_get(&gd->cache,
				      params->in.loc_mr_addr,
				      params->in.loc_mr_length,
				      params->in.loc_mr_access,
				      false, false);
	mutex_unlock(&gd->mr_lock);
	return mrce;
}

/* for RDMA CQE handling */
void rv_gdr_cache_put(struct rv_gdrdata *gd, struct rv_mr_cache_entry *mrce)
{
	rv_mr_cache_put(&gd->cache, mrce, false);
}
