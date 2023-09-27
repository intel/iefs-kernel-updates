/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 - 2022 Intel Corporation.
 */

#ifndef _RV_GDR_OPS_H
#define _RV_GDR_OPS_H

/*
 * For GPU Direct and GPU Direct Copy (GDR Copy) there is an additional
 * GPU MR cache.  This tracks GPU pages which have been locked and
 * registered as a verbs MR for GPU Direct RDMA
 * or mapped into CPU virtual for GPU Direct Copy.
 * cache - actual cache of GPU memory regions.
 *	A process's use of GPU is indicated by cache.max_size > 0
 *	The cache itself will track all GPU memory pinned and hold all
 *	the active struct gpu_mr.
 * tgid - The task_tgid of the process which the cache was created for is
 *	retained. nvidia_p2p_put_pages misbehaves when called under a
 *	different context.  So it's required to check this before deciding to
 *	call put_pages.  Immutable.
 * ioctl_busy_flag - limit exactly 1 ioctl in flight but don't use
 *	a lock.  This is necessary (as opposed to a mutex such as rv_user.mutex)
 *	since we can't hold locks while calling vm_mmap or nvidia_p2p_put_pages.
 *	PSM is single threaded, so this is just a security/safety-net feature
 *	and we can simply fail any ioctl calls attempted while this is set.
 * map_this_mr - the GPU memory region which is in the process of being
 *	pinned and mapped, used during vm_mmap.  This is another reason only
 *	1 ioctl can be allowed at a time.
 * mr_lock - protects gdrdata.map_this_mr, gdrdata.stats, gdr_mr.mr,
 *	and gdr_mr.host_addr.
 *	This especially needs to be held during calls which create/modify/free
 *	these fields, including cache calls which may call ops->remove
 *	(which happens outside cache.lock). The protection here is for
 *	races between ioctls (which may also call ops->remove) and free_callback
 *	which can also call cache functions and ops->remove.
 *	While ioctl_busy_flag prevents concurrent ioctl's and avoids races
 *	for search/create/insert creating duplicate MRs, once GPU pages have
 *	been pinned via get_pages, a free_callback could occur (in theory).
 *	Note gdr_mr.page_table is not protected by mr_lock, but instead it's
 *	access is carefully sequenced to avoid races on destruction so
 *	it can be treated as essentially immutable.
 *	FYI, an alternative could be a mutex per gdr_mr and then this could
 *	be a spin_lock to just protect map_this_mr.  However given PSM design
 *	there is limited benefit for that added complexity and memory.
 * refcount - counts the number of gdr_mr's (or in progress free_callbacks)
 *	holding references to gdrdata.  The gdrdata deinit must wait for this to
 *	be 0 before freeing itself.  This does not include the rv_user_mrs
 *	reference.
 *
 * The ioctl_busy_flag is used to ensure that only one thread
 * at a time is executing in GPU ioctl() handlers.  Any thread that enters a
 * GPU ioctl() handler while it is "busy", will receive an -EINVAL error code.
 * This means there is no concurrent execution of most GPU ioctls.
 * This is acceptable because the primary user of this driver is PSM,
 * and the core of PSM is single-threaded.
 *
 * map_this_mr is used as a way to efficiently communicate across
 * the vm_mmap() function call in do_pin_and_mmap_gpu_buf() to this
 * driver's mmap handler function (rv_gdr_mmap()). It holds a pointer to a
 * gdr_mr struct that describes the GPU buffer that is to be mmapped
 * into the process's user virtual address space.  This is validated against
 * the mr_handle which we get through vm_mmap as a pgoff value.  The validation
 * ensures the mmap is from this driver as opposed to a direct user space
 * call to vm_mmap.
 * Stats:
 *	failed_pin - cache miss and failed to pin GPU pages
 *	failed_reg - failed to register MR (can be hit without MR or miss)
 *	failed_mmap - failed to mmap (can be hit without mmap or miss)
 *	hit_reg - cache hit registering an MR
 *	hit_add_reg - the gmr has already been mmapped and it is found in the
 *			cache when trying to register a Verbs MR.
 *	hit_mmap - cache hit on mmap
 *	hit_add_mmap - the gmr has already been registered as a Verbs MR, and
 *			it is found in the cache when trying to mmap it.
 *	inval_mr - number of times an MR is invalidated by the free_callback
 *	           when it still has references.
 * stats are protected by mr_lock
 * hit = hit_reg + hit_add_reg + hit_mmap + hit_add_mmap
 * miss = miss_reg + miss_mmap
 * failed_* is not included in hit nor miss counts
 */
struct rv_gdrdata {
	atomic_t ioctl_busy_flag;
	struct rv_mr_cache cache;
	struct pid *tgid;
	void *map_this_mr;
	struct mutex mr_lock;
	atomic_t refcount;
	int rv_inx;
#ifdef INTEL_GPU_DIRECT
	struct ib_device *ib_dev;
#endif
	struct {
		u64 hit_reg;
		u64 hit_add_reg;
		u64 hit_mmap;
		u64 hit_add_mmap;
		u64 failed_pin;
		u64 failed_reg;
		u64 failed_mmap;
		u64 inval_mr;
	} stats;
};

int rv_gdr_init(int rv_inx, struct rv_gdrdata *gd, u8 gpu, u32 cache_size);
void rv_gdr_deinit(int rv_inx, struct rv_gdrdata *gd);
int rv_ioctl_gpu_buf_pin_mmap(struct file *fp, struct rv_gdrdata *gd,
			      unsigned long arg, int rev);
int rv_ioctl_gpu_evict(struct rv_gdrdata *gd, struct rv_evict_params *params);
int rv_gdr_mmap(struct file *fp, struct rv_gdrdata *gd,
		struct vm_area_struct *vma);
struct rv_user;
int rv_ioctl_gpu_reg_mem(struct file *fp, struct rv_user *rv,
			 struct rv_gdrdata *gd, struct rv_mem_params *mparams);
int rv_ioctl_gpu_dereg_mem(struct rv_gdrdata *gd,
			   struct rv_dereg_params_in *dparams);
struct mr_info;
int rv_gdr_map_verbs_mr(int rv_inx, struct mr_info *mr,
			struct rv_mem_params_in *minfo);

/* for RDMA WQE/CQE handling */
struct rv_mr_cache_entry *rv_gdr_search_get(struct rv_gdrdata *gd,
					    struct rv_post_write_params *params
					    );
void rv_gdr_cache_put(struct rv_gdrdata *gd, struct rv_mr_cache_entry *mrce);

static inline bool rv_gdr_enabled(struct rv_gdrdata *gd)
{
	return !!gd->cache.max_size;
}

#endif /* _RV_GDR_OPS_H */
