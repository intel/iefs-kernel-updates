// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 - 2021 Intel Corporation.
 */

#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/scatterlist.h>
#include <linux/debugfs.h>
#include <linux/interval_tree_generic.h>

#include <rdma/ib_user_sa.h>

#include "rv.h"
#include "trace.h"

static void handle_remove(struct work_struct *work);
static void do_remove(struct rv_mr_cache *cache, struct list_head *del_list,
		      int is_invalidate);
static u32 rv_mr_cache_evict_bytes(struct rv_mr_cache *cache, u64 bytes);
static int mmu_notifier_range_start(struct mmu_notifier *,
				    const struct mmu_notifier_range *);
static struct rv_mr_cache_entry *rv_mr_cache_search(struct rv_mr_cache *cache,
						    u64 addr, u64 len, u32 acc);
static void rv_update_mrc_stats_insert(struct rv_mr_cache *cache,
				       struct rv_mr_cache_entry *mrce);
static void rv_update_mrc_stats_remove(struct rv_mr_cache *cache,
				       struct rv_mr_cache_entry *mrce,
				       int is_invalidate);
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
static void rv_mr_cache_update_stats_max_use(struct rv_mr_cache *cache,
					     u32 refcount, u8 type);
#else
static void rv_mr_cache_update_stats_max_use(struct rv_mr_cache *cache,
					     u32 refcount);
#endif
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
static void rv_mr_cache_update_stats_max_insert(struct rv_mr_cache *cache,
						u8 type);
#else
static void rv_mr_cache_update_stats_max_insert(struct rv_mr_cache *cache);
#endif

static u64 rv_gdr_roundup(struct rv_mr_cache *cache, u64 len)
{
	/*
	 * Based on tests, for each pin request to Nvidia GPUDirect driver,
	 * the BAR1 memory used (reported by nvidia-smi -q) =
	 * round_up(len, 2 MB) and the total BAR1 memory used = 8 +
	 * sum(BAR memory used for each pin request).
	 */
#define GDR_MEM_MIN_SIZE  BIT(21)

	return cache->is_gdr ? round_up(len, GDR_MEM_MIN_SIZE) : len;
}

#ifndef MMU_NOTIFIER_RANGE_START_USES_MMU_NOTIFIER_RANGE
static void compat_mmu_notifier_range_start(struct mmu_notifier *mn,
					    struct mm_struct *mm,
					    unsigned long start,
					    unsigned long end)
{
	struct mmu_notifier_range r = {
		.mm = mm,
		.start = start,
		.end = end,
	};

	(void)mmu_notifier_range_start(mn, &r);
}
#endif

static const struct mmu_notifier_ops mn_opts = {
#if 0 /* XXX - look into if this should be used or not and in what distro */
	.flags = MMU_INVALIDATE_DOES_NOT_BLOCK,
#endif
#ifdef MMU_NOTIFIER_RANGE_START_USES_MMU_NOTIFIER_RANGE
	.invalidate_range_start = mmu_notifier_range_start,
#else
	.invalidate_range_start = compat_mmu_notifier_range_start,
#endif
};

static u64 mrce_start(struct rv_mr_cache_entry *mrce)
{
	return mrce->addr;
}

static u64 mrce_last(struct rv_mr_cache_entry *mrce)
{
	return mrce->addr + mrce->len - 1;
}

INTERVAL_TREE_DEFINE(struct rv_mr_cache_entry, node, u64, __last,
		     mrce_start, mrce_last, static, rv_int_rb);

static void rv_mr_cache_rb_remove(struct rv_mr_cache *cache,
				  struct rv_mr_cache_entry *mrce,
				  int is_invalidate)
{
	rv_int_rb_remove(mrce, &cache->root);
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	RB_CLEAR_NODE(&mrce->node);
#endif
	rv_update_mrc_stats_remove(cache, mrce, is_invalidate);
}

/*
 * MMU notifier callback
 *
 * If the address range overlaps an MR which is in use (refcount>0)
 * we refuse to remove it.  Otherwise we remove it from the MR cache
 * by getting it off the LRU list and RB-tree and schedule the
 * MR deregistration.
 */
static int mmu_notifier_range_start(struct mmu_notifier *mn,
				    const struct mmu_notifier_range *range)
{
	struct rv_mr_cache *cache = container_of(mn, struct rv_mr_cache, mn);
#ifdef NO_RB_ROOT_CACHE
	struct rb_root *root = &cache->root;
#else
	struct rb_root_cached *root = &cache->root;
#endif
	struct rv_mr_cache_entry *mrce, *ptr = NULL;
	unsigned long flags;
	bool added = false;

	spin_lock_irqsave(&cache->lock, flags);
	for (mrce = rv_int_rb_iter_first(root, range->start, range->end - 1);
	     mrce; mrce = ptr) {
		ptr = rv_int_rb_iter_next(mrce, range->start, range->end - 1);
		if (!mrce->refcount) {
			trace_rv_mr_cache_notifier(mrce->addr, mrce->len,
						   mrce->access);
			rv_mr_cache_rb_remove(cache, mrce, 1);
			list_move(&mrce->list, &cache->del_list);
			added = true;
		}
	}
	spin_unlock_irqrestore(&cache->lock, flags);

	if (added)
		queue_work(cache->wq, &cache->del_work);
	return 0;
}

#define GDR_MEM_STARTUP (8 * 1024 * 1024)

/* MR deregistration is done on a per rv_user work queue.  */
int rv_mr_cache_init(int rv_inx, char cache_id, struct rv_mr_cache *cache,
		     const struct rv_mr_cache_ops *ops, void *context,
		     struct mm_struct *mm, u32 cache_size, int is_gdr)
{
	char wq_name[25];
	int ret = 0;

	if (! cache_size)
		return -EINVAL;
	if (mm) {
		sprintf(wq_name, "rv-%c%d\n", cache_id, rv_inx);
		cache->wq = alloc_workqueue(wq_name,
					    WQ_SYSFS | WQ_HIGHPRI |
					    WQ_CPU_INTENSIVE |
					    WQ_MEM_RECLAIM,
					    RV_RB_MAX_ACTIVE_WQ_ENTRIES);
		if (!cache->wq)
			return -ENOMEM;
		trace_rv_mr_cache_wq_alloc(wq_name);
	}

#ifdef NO_RB_ROOT_CACHE
	cache->root = RB_ROOT;
#else
	cache->root = RB_ROOT_CACHED;
#endif
	cache->ops = ops;
	cache->context = context;

	INIT_HLIST_NODE(&cache->mn.hlist);
	spin_lock_init(&cache->lock);

	cache->mn.ops = &mn_opts;
	cache->mm = mm;

	INIT_WORK(&cache->del_work, handle_remove);
	INIT_LIST_HEAD(&cache->del_list);
	INIT_LIST_HEAD(&cache->lru_list);

	cache->max_size = (u64)cache_size * 1024 * 1024;
	cache->is_gdr = is_gdr;
	/*
	 * For Nvidia GPUDirect, we have a 8 MB startup cost for BAR1 memory
	 * used. For simplicity, set it here instead of adding it after the
	 * first entry is inserted into the cache.
	 */
	if (is_gdr)
		cache->total_size = GDR_MEM_STARTUP;
	if (mm) {
		ret = mmu_notifier_register(&cache->mn, cache->mm);
		if (ret)
			goto bail_wq;
	}

	return ret;

bail_wq:
	if (cache->wq) {
		destroy_workqueue(cache->wq);
		cache->wq = NULL;
	}
	return ret;
}

/* All remaining entries in the cache are deregistered */
void rv_mr_cache_deinit(int rv_inx, struct rv_mr_cache *cache)
{
	struct rv_mr_cache_entry *mrce;
	struct rb_node *node;
	unsigned long flags;
	struct list_head del_list;

	if (cache->mm)
		mmu_notifier_unregister(&cache->mn, cache->mm);

	INIT_LIST_HEAD(&del_list);

	spin_lock_irqsave(&cache->lock, flags);
#ifdef NO_RB_ROOT_CACHE
	while ((node = rb_first(&cache->root))) {
#else
	while ((node = rb_first_cached(&cache->root))) {
#endif
		mrce = rb_entry(node, struct rv_mr_cache_entry, node);
		trace_rv_mr_cache_deinit(mrce->addr, mrce->len, mrce->access);
		trace_rv_mrc_msg_deinit("inx, refcount", rv_inx,
					mrce->refcount, 0);
#ifdef NO_RB_ROOT_CACHE
		rb_erase(node, &cache->root);
#else
		rb_erase_cached(node, &cache->root);
#endif
		RB_CLEAR_NODE(node);
		rv_update_mrc_stats_remove(cache, mrce, 1);
		list_move(&mrce->list, &del_list);
		mrce->refcount -= mrce->user_refcount;
		mrce->user_refcount = 0;
		WARN_ON(mrce->refcount);
	}
	if (cache->is_gdr)
		cache->total_size -= GDR_MEM_STARTUP;
	WARN_ON(cache->total_size);

	spin_unlock_irqrestore(&cache->lock, flags);

	do_remove(cache, &del_list, 0);

	if (cache->wq) {
		char wq_name[25];

		sprintf(wq_name, "rv-%d\n", rv_inx);
		trace_rv_mr_cache_wq_destroy(wq_name);
		flush_workqueue(cache->wq);
		destroy_workqueue(cache->wq);
	}
	cache->wq = NULL;
	cache->mm = NULL;
}

void rv_mr_cache_entry_init(struct rv_mr_cache_entry *mrce,
			    u64 addr, u64 len, u32 access)
{
	mrce->addr = addr;
	mrce->len = len;
	mrce->access = access;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	mrce->freeing = 0;
	mrce->type = RV_MRCE_TYPE_REG; /* GPU callers will change */
#endif
	mrce->refcount = 1;
	mrce->user_refcount = 1;
	RB_CLEAR_NODE(&mrce->node);
	INIT_LIST_HEAD(&mrce->list);
}

/*
 * only needed for cleanup when init an entry and never add to cache
 * no need for cache->lock, as only caller has pointer to mrce
 */
void rv_mr_cache_entry_deinit(struct rv_mr_cache_entry *mrce)
{
	mrce->user_refcount--;
	mrce->refcount--;
}

/* called with cache->lock */
static void rv_mr_cache_mrce_get(struct rv_mr_cache *cache,
				 struct rv_mr_cache_entry *mrce,
				 bool for_user)
{
	u32 refcount;

	refcount = ++mrce->refcount;
	if (refcount == 1) {
		u64 len = rv_gdr_roundup(cache, mrce->len);

		cache->stats.inuse++;
		cache->stats.inuse_bytes += len;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
		cache->stats.inuse_a[mrce->type]++;
		cache->stats.inuse_bytes_a[mrce->type] += len;
#endif
	}
	if (for_user)
		mrce->user_refcount++;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	rv_mr_cache_update_stats_max_use(cache, refcount, mrce->type);
#else
	rv_mr_cache_update_stats_max_use(cache, refcount);
#endif
}

/* called with cache->lock */
static u32 rv_mr_cache_mrce_put(struct rv_mr_cache *cache,
				struct rv_mr_cache_entry *mrce, bool for_user)
{
	int refcount;

	if (for_user)
		mrce->user_refcount--;
	refcount = --mrce->refcount;
	if (!refcount) {
		u64 len = rv_gdr_roundup(cache, mrce->len);
		cache->stats.inuse--;
		cache->stats.inuse_bytes -= len;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
		cache->stats.inuse_a[mrce->type]--;
		cache->stats.inuse_bytes_a[mrce->type] -= len;
#endif
	}
	return refcount;
}

#ifdef INTEL_GPU_DIRECT
void rv_mr_cache_entry_put(struct rv_mr_cache *cache,
				struct rv_mr_cache_entry *mrce)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	rv_mr_cache_mrce_put(cache, mrce, true);
	spin_unlock_irqrestore(&cache->lock, flags);
}
#endif /* INTEL_GPU_DIRECT */

/*
 * Return 1 if the mrce can be evicted from the cache
 *
 * Called with cache->lock
 */
static int rv_mr_cache_mrce_evict(struct rv_mr_cache *cache,
				  struct rv_mr_cache_entry *mrce,
				  struct evict_data *evict_data, bool *stop)
{
	/* is this mrce still being used? */
	if (mrce->refcount)
		return 0; /* keep this mrce */

	/* this mrce will be evicted, add its size to our count */
	evict_data->cleared_bytes += rv_gdr_roundup(cache, mrce->len);
	evict_data->cleared_count++;

	/* have enough bytes been cleared? */
	if (evict_data->cleared_bytes >= evict_data->target_bytes &&
	    evict_data->cleared_count >= evict_data->target_count)
		*stop = true;

	return 1; /* remove this mrce */
}

/*
 * update max stats after increasing inuse and/or refcount
 * called with cache->lock
 */
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
static void rv_mr_cache_update_stats_max_use(struct rv_mr_cache *cache,
					     u32 refcount, u8 type)
#else
static void rv_mr_cache_update_stats_max_use(struct rv_mr_cache *cache,
					     u32 refcount)
#endif
{
	if (refcount > cache->stats.max_refcount)
		cache->stats.max_refcount = refcount;
	if (cache->stats.inuse > cache->stats.max_inuse)
		cache->stats.max_inuse = cache->stats.inuse;
	if (cache->stats.inuse_bytes > cache->stats.max_inuse_bytes)
		cache->stats.max_inuse_bytes = cache->stats.inuse_bytes;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (refcount > cache->stats.max_refcount_a[type])
		cache->stats.max_refcount_a[type] = refcount;
	if (cache->stats.inuse_a[type] > cache->stats.max_inuse_a[type])
		cache->stats.max_inuse_a[type] = cache->stats.inuse_a[type];
	if (cache->stats.inuse_bytes_a[type] >
	    cache->stats.max_inuse_bytes_a[type])
		cache->stats.max_inuse_bytes_a[type] =
					cache->stats.inuse_bytes_a[type];
#endif
}

/*
 * update max stats after increasing count/total_size when inserting an entry
 * called with cache->lock
 */
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
static void rv_mr_cache_update_stats_max_insert(struct rv_mr_cache *cache,
						u8 type)
#else
static void rv_mr_cache_update_stats_max_insert(struct rv_mr_cache *cache)
#endif
{
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	rv_mr_cache_update_stats_max_use(cache, 1, type);
#else
	rv_mr_cache_update_stats_max_use(cache, 1);
#endif
	if (cache->stats.count > cache->stats.max_count)
		cache->stats.max_count = cache->stats.count;
	if (cache->total_size > cache->stats.max_cache_size)
		cache->stats.max_cache_size = cache->total_size;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (cache->stats.count_a[type] > cache->stats.max_count_a[type])
		cache->stats.max_count_a[type] = cache->stats.count_a[type];
	if (cache->stats.total_size_a[type] >
					cache->stats.max_cache_size_a[type])
		cache->stats.max_cache_size_a[type] =
					cache->stats.total_size_a[type];
#endif
}

/* gets a reference to mrce on behalf of caller */
int rv_mr_cache_insert(struct rv_mr_cache *cache,
		       struct rv_mr_cache_entry *mrce)
{
	struct rv_mr_cache_entry *existing;
	unsigned long flags;
	u64 new_len, evict_len;
	int ret = 0;

again:
	trace_rv_mr_cache_insert(mrce->addr, mrce->len, mrce->access);

	spin_lock_irqsave(&cache->lock, flags);
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	if (mrce->freeing) {
		ret = -ENOENT;
		goto unlock;
	}
#endif
	existing = rv_mr_cache_search(cache, mrce->addr, mrce->len,
				      mrce->access);
	if (existing) {
		ret = -EINVAL;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
		if (existing->freeing)
			ret = -EBUSY;
#endif
		goto unlock;
	}
	new_len = cache->total_size + rv_gdr_roundup(cache, mrce->len);
	if (new_len > cache->max_size) {
		spin_unlock_irqrestore(&cache->lock, flags);

		trace_rv_mrc_msg_insert("Cache full: max, total, cur",
					cache->max_size, cache->total_size,
					mrce->len);

		evict_len = new_len - cache->max_size;
		if (rv_mr_cache_evict_bytes(cache, evict_len) >= evict_len)
			goto again;
		else
			goto cache_full;
	}

	rv_int_rb_insert(mrce, &cache->root);
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	WARN_ON(RB_EMPTY_NODE(&mrce->node));
#endif
	INIT_LIST_HEAD(&mrce->list);

	WARN_ON(mrce->user_refcount != 1);/* XXX delete later */
	WARN_ON(mrce->refcount != 1);/* XXX delete line later */
	rv_update_mrc_stats_insert(cache, mrce);
unlock:
	spin_unlock_irqrestore(&cache->lock, flags);
	return ret;

cache_full:
	spin_lock_irqsave(&cache->lock, flags);
	cache->stats.full++;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	cache->stats.full_a[mrce->type]++;
#endif
	spin_unlock_irqrestore(&cache->lock, flags);
	return -ENOMEM;
}

/* Caller must hold cache->lock */
static struct rv_mr_cache_entry *rv_mr_cache_search(struct rv_mr_cache *cache,
						    u64 addr, u64 len, u32 acc)
{
	struct rv_mr_cache_entry *mrce = NULL;

	trace_rv_mr_cache_search_enter(addr, len, acc);

	if (!cache->ops->filter) {
		mrce = rv_int_rb_iter_first(&cache->root, addr,
					    (addr + len) - 1);
		if (mrce)
			trace_rv_mr_cache_search_mrce(mrce->addr, mrce->len,
						      mrce->access);
	} else {
		for (mrce = rv_int_rb_iter_first(&cache->root, addr,
						 (addr + len) - 1);
		     mrce;
		     mrce = rv_int_rb_iter_next(mrce, addr, (addr + len) - 1)) {
			trace_rv_mr_cache_search_mrce(mrce->addr, mrce->len,
						      mrce->access);
			if (cache->ops->filter(mrce, addr, len, acc))
				return mrce;
		}
	}
	return mrce;
}

/*
 * look for a cache hit.  If get a hit, make sure removed from LRU list.
 *
 * return:
 *     NULL - Not found;
 *     A valid cache entry pointer;
 *     -ENOENT - The buffer is being freed (only for GPU).
 */

struct rv_mr_cache_entry *rv_mr_cache_search_get(struct rv_mr_cache *cache,
						 u64 addr, u64 len, u32 acc,
						 bool update_hit, bool for_user)
{
	unsigned long flags;
	struct rv_mr_cache_entry *mrce;

	spin_lock_irqsave(&cache->lock, flags);
	mrce =  rv_mr_cache_search(cache, addr, len, acc);
	if (mrce) {
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
		if (mrce->freeing) {
			cache->stats.freeing++;
			mrce = ERR_PTR(-ENOENT);
			goto unlock;
		}
#endif
		rv_mr_cache_mrce_get(cache, mrce, for_user);
		if (update_hit)
			cache->stats.hit++;
		list_del_init(&mrce->list);
	}
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
unlock:
#endif
	spin_unlock_irqrestore(&cache->lock, flags);

	return mrce;
}

/*
 * release a cache reference by address (always for_user).
 * This is called from user ioctl, so we must make sure they don't
 * dereg twice yielding a negative refcount.
 * The released entry goes on our LRU list to prioritize evictions.
 */
struct rv_mr_cache_entry *rv_mr_cache_search_put(struct rv_mr_cache *cache,
						 u64 addr, u64 len, u32 acc)
{
	unsigned long flags;
	struct rv_mr_cache_entry *mrce;

	spin_lock_irqsave(&cache->lock, flags);
	mrce =  rv_mr_cache_search(cache, addr, len, acc);
	if (mrce) {
		if (!mrce->user_refcount) {
			mrce = NULL;
			goto unlock;
		}
		if (!rv_mr_cache_mrce_put(cache, mrce, true))
			list_add(&mrce->list, &cache->lru_list);
	}
unlock:
	spin_unlock_irqrestore(&cache->lock, flags);

	return mrce;
}

/* Simple release, the entry goes on our LRU list to prioritize evictions. */
void rv_mr_cache_put(struct rv_mr_cache *cache, struct rv_mr_cache_entry *mrce,
		     bool for_user)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	if (!rv_mr_cache_mrce_put(cache, mrce, for_user))
		list_add(&mrce->list, &cache->lru_list);
	spin_unlock_irqrestore(&cache->lock, flags);
}

/*
 * evict a cache entry by exact match (always for_user).
 * This is called from user ioctl
 */
int rv_mr_cache_evict_exact(struct rv_mr_cache *cache,
			    u64 addr, u64 len, u32 acc)
{
	unsigned long flags;
	struct rv_mr_cache_entry *mrce;
	int ret = -ENOENT;

	spin_lock_irqsave(&cache->lock, flags);
	mrce =  rv_mr_cache_search(cache, addr, len, acc);
	if (mrce) {
		if (mrce->refcount) {
			ret = -EBUSY;
			goto unlock;
		}
		trace_rv_mr_cache_evict_evict(mrce->addr, mrce->len,
					      mrce->access);
		rv_mr_cache_rb_remove(cache, mrce, 0);
		list_del_init(&mrce->list); /* remove from LRU list */
		spin_unlock_irqrestore(&cache->lock, flags);
		cache->ops->remove(cache, cache->context, mrce, 0);
		return 0;
	}
unlock:
	spin_unlock_irqrestore(&cache->lock, flags);
	return ret;
}

int rv_mr_cache_evict_range(struct rv_mr_cache *cache,
			    u64 addr, u64 len, struct evict_out *out)
{
#ifdef NO_RB_ROOT_CACHE
	struct rb_root *root = &cache->root;
#else
	struct rb_root_cached *root = &cache->root;
#endif
	struct rv_mr_cache_entry *mrce, *ptr = NULL;
	unsigned long flags;
	struct list_head del_list;

	INIT_LIST_HEAD(&del_list);

	spin_lock_irqsave(&cache->lock, flags);
	for (mrce = rv_int_rb_iter_first(root, addr, addr + len - 1);
	     mrce; mrce = ptr) {
		ptr = rv_int_rb_iter_next(mrce, addr, addr + len - 1);
		if (!mrce->refcount) {
			trace_rv_mr_cache_evict_range(mrce->addr, mrce->len,
						      mrce->access);
			out->bytes += rv_gdr_roundup(cache, mrce->len);
			out->count++;
			rv_mr_cache_rb_remove(cache, mrce, 0);
			list_move(&mrce->list, &del_list);
		}
	}
	spin_unlock_irqrestore(&cache->lock, flags);

	do_remove(cache, &del_list, 0);
	return 0;
}

/*
 * evict entries from the cache, least recently used first.
 * We evict until we reach the goal or LRU_list is empty. Evicted
 * entries are removed from the cache and deregistered.
 */
static void rv_mr_cache_evict(struct rv_mr_cache *cache,
			      struct evict_data *evict_data)
{
	struct rv_mr_cache_entry *mrce, *temp;
	struct list_head del_list;
	unsigned long flags;
	bool stop = false;

	INIT_LIST_HEAD(&del_list);

	spin_lock_irqsave(&cache->lock, flags);
	trace_rv_mrc_evd_evict(evict_data->cleared_bytes,
			       evict_data->cleared_count,
			       evict_data->target_bytes,
			       evict_data->target_count);
	list_for_each_entry_safe_reverse(mrce, temp, &cache->lru_list, list) {
		if (rv_mr_cache_mrce_evict(cache, mrce, evict_data, &stop)) {
			trace_rv_mr_cache_evict_evict(mrce->addr, mrce->len,
						      mrce->access);
			rv_mr_cache_rb_remove(cache, mrce, 0);
			list_move(&mrce->list, &del_list);
		} else {
			trace_rv_mr_cache_evict_keep(mrce->addr, mrce->len,
						     mrce->access);
		}
		if (stop)
			break;
	}
	trace_rv_mrc_evd_evict(evict_data->cleared_bytes,
			       evict_data->cleared_count,
			       evict_data->target_bytes,
			       evict_data->target_count);
	spin_unlock_irqrestore(&cache->lock, flags);

	do_remove(cache, &del_list, 0);
}

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
/*
 * It is up to the caller to ensure that rv_mr_cache_evict_mrce
 * does not race with the ops->remove which may be called
 * outside rv_mr_cache.lock due to a GPU free_callback or mmu invalidate
 * notifier matching 'mrce' or cache eviction to make space for an insert
 * or to deinit the cache.
 * Also beware, that if removal is in progress prior to calling this (such as
 * a remove on a schedule queue), this can return success but the ops->remove
 * may be in progress or scheduled to be called in future.
 *
 * is_invalidate - how to count stats 0=eviction, 1=invalidation removal,
 *		also passed to ops->remove
 */
int rv_mr_cache_evict_mrce(struct rv_mr_cache *cache,
			   struct rv_mr_cache_entry *mrce,
			   int is_invalidate)
{
	unsigned long flags;

	/* Validity of cache and mrce pointers has been checked by caller. */
	spin_lock_irqsave(&cache->lock, flags);
	if (RB_EMPTY_NODE(&mrce->node)) { /* nothing to do */
		spin_unlock_irqrestore(&cache->lock, flags);
		return 0;
	}
	if (mrce->refcount) {
		spin_unlock_irqrestore(&cache->lock, flags);
		return -EBUSY;
	}
	trace_rv_mr_cache_evict_mrce(mrce->addr, mrce->len, mrce->access);
	rv_mr_cache_rb_remove(cache, mrce, is_invalidate);
	list_del_init(&mrce->list); /* remove from LRU list */
	spin_unlock_irqrestore(&cache->lock, flags);
	cache->ops->remove(cache, cache->context, mrce, is_invalidate);
	return 0;
}

/*
 * Mark mrce as in process of being freed.
 * Typically caller will want to then call rv_mr_cache_evict_mrce while
 * holding proper locks to avoid races between free_callback and other cache
 * callers.
 * By setting freeing flag we prevent future cache hits.
 */
int rv_mr_cache_freeing_mrce(struct rv_mr_cache *cache,
			     struct rv_mr_cache_entry *mrce)
{
	unsigned long flags;
	int ret = 0;

	/* Validity of cache and mrce pointers has been checked by caller. */
	spin_lock_irqsave(&cache->lock, flags);
	mrce->freeing = 1;

	if (mrce->refcount)
		ret = -EBUSY;
	spin_unlock_irqrestore(&cache->lock, flags);

	return ret;
}

#ifdef INTEL_GPU_DIRECT
void rv_mr_cache_inc_hit(struct rv_mr_cache *cache)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	cache->stats.hit++;
	spin_unlock_irqrestore(&cache->lock, flags);
}
#endif /* INTEL_GPU_DIRECT */
#endif /* NVIDIA_GPU_DIRECT || INTEL_GPU_DIRECT */

/*
 * Call the remove function for the given cache and the list.  This
 * is expected to be called with a delete list extracted from cache.
 * The caller does NOT need the cache->lock.
 */
static void do_remove(struct rv_mr_cache *cache, struct list_head *del_list,
		      int is_invalidate)
{
	struct rv_mr_cache_entry *mrce;

	while (!list_empty(del_list)) {
		mrce = list_first_entry(del_list, struct rv_mr_cache_entry, list);
		list_del(&mrce->list);
		cache->ops->remove(cache, cache->context, mrce, is_invalidate);
	}
}

/*
 * Work queue function to remove all nodes that have been queued up to
 * be removed.	The key feature is that mm->mmap_lock is not being held
 * and the remove callback can sleep while taking it, if needed.
 * This is only used by MMU notifier invalidation of MRs, so it
 * assumes it can pass is_invalidate=1 to do_remove.
 */
static void handle_remove(struct work_struct *work)
{
	struct rv_mr_cache *cache = container_of(work, struct rv_mr_cache,
						 del_work);
	struct list_head del_list;
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	list_replace_init(&cache->del_list, &del_list);
	spin_unlock_irqrestore(&cache->lock, flags);

	do_remove(cache, &del_list, 1);
}

static u32 rv_mr_cache_evict_bytes(struct rv_mr_cache *cache, u64 bytes)
{
	struct evict_data evict_data;

	evict_data.cleared_bytes = 0;
	evict_data.target_bytes = bytes;
	evict_data.cleared_count = 0;
	evict_data.target_count = 0;
	rv_mr_cache_evict(cache, &evict_data);
	return evict_data.cleared_bytes;
}

int rv_mr_cache_evict_amount(struct rv_mr_cache *cache,
			     u64 bytes, u32 count, struct evict_out *out)
{
	struct evict_data evict_data;

	evict_data.cleared_bytes = 0;
	evict_data.target_bytes = bytes;
	evict_data.cleared_count = 0;
	evict_data.target_count = count;
	rv_mr_cache_evict(cache, &evict_data);
	if (!evict_data.cleared_bytes && !evict_data.cleared_count)
		return -ENOENT;
	out->bytes = evict_data.cleared_bytes;
	out->count = evict_data.cleared_count;
	return 0;
}

static void rv_update_mrc_stats_insert(struct rv_mr_cache *cache,
				       struct rv_mr_cache_entry *mrce)
{
	u64 len = rv_gdr_roundup(cache, mrce->len);

	cache->stats.miss++;
	cache->stats.inuse++;
	cache->stats.inuse_bytes += len;
	cache->total_size += len;
	cache->stats.count++;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	cache->stats.miss_a[mrce->type]++;
	cache->stats.inuse_a[mrce->type]++;
	cache->stats.inuse_bytes_a[mrce->type] += len;
	cache->stats.total_size_a[mrce->type] += len;
	cache->stats.count_a[mrce->type]++;
	rv_mr_cache_update_stats_max_insert(cache, mrce->type);
#else
	rv_mr_cache_update_stats_max_insert(cache);
#endif
}

static void rv_update_mrc_stats_remove(struct rv_mr_cache *cache,
				       struct rv_mr_cache_entry *mrce,
				       int is_invalidate)
{
	u64 len = rv_gdr_roundup(cache, mrce->len);

	cache->total_size -= len;
	cache->stats.count--;
	if (is_invalidate)
		cache->stats.remove++;
	else
		cache->stats.evict++;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	cache->stats.total_size_a[mrce->type] -= len;
	cache->stats.count_a[mrce->type]--;
	if (is_invalidate)
		cache->stats.remove_a[mrce->type]++;
	else
		cache->stats.evict_a[mrce->type]++;
#endif
}

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
/*
 * promote from current rv_mrce_type to RV_MRCE_TYPE_BOTH
 * caller must have a mrce->refcount reference
 */
void rv_mr_cache_entry_promote(struct rv_mr_cache *cache,
			       struct rv_mr_cache_entry *mrce)
{
	unsigned long flags;
	u64 len = rv_gdr_roundup(cache, mrce->len);

	spin_lock_irqsave(&cache->lock, flags);

	WARN_ON(mrce->type == RV_MRCE_TYPE_BOTH);  /* XXX drop this */
	WARN_ON(!mrce->refcount); /* XXX drop this */
	cache->stats.total_size_a[mrce->type] -= len;
	cache->stats.count_a[mrce->type]--;
	cache->stats.inuse_a[mrce->type]--;
	cache->stats.inuse_bytes_a[mrce->type] -= len;

	mrce->type = RV_MRCE_TYPE_BOTH;

	cache->stats.total_size_a[RV_MRCE_TYPE_BOTH] += len;
	cache->stats.count_a[RV_MRCE_TYPE_BOTH]++;
	cache->stats.inuse_a[RV_MRCE_TYPE_BOTH]++;
	cache->stats.inuse_bytes_a[RV_MRCE_TYPE_BOTH] += len;

	rv_mr_cache_update_stats_max_insert(cache, RV_MRCE_TYPE_BOTH);

	spin_unlock_irqrestore(&cache->lock, flags);
}

/*
 * rv_mr_cache_first() - Return the first node in the MR cache red/black tree.
 * @cache: - A pointer to the root/control structure of a red/black tree.
 *
 * This function layers on top of the Linux interval red/black tree
 * implementation.
 *
 * If the tree is NOT empty, then return a pointer to the first node in
 * that tree.  Otherwise return NULL.
 *
 * Return: A pointer to the first node in the tree, or NULL if tree is empty.
 */
struct rv_mr_cache_entry *rv_mr_cache_first(struct rv_mr_cache *cache)
{
	struct rv_mr_cache_entry *mrce = NULL;
	struct rb_node *node;
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
#ifdef NO_RB_ROOT_CACHE
	node = rb_first(&cache->root);
#else
	node = rb_first_cached(&cache->root);
#endif
	if (node)
		mrce = rb_entry(node, struct rv_mr_cache_entry, node);
	spin_unlock_irqrestore(&cache->lock, flags);

	return mrce;
}
#endif
