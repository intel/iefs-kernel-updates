// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 Intel Corporation.
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

unsigned int mr_cache_size = MAX_RB_SIZE;

module_param(mr_cache_size, uint, 0444);
MODULE_PARM_DESC(mr_cache_size, "Size of mr cache (in MB)");


static void handle_remove(struct work_struct *work);
static void do_remove(struct rv_mr_cache *cache, struct list_head *del_list);
static u32 rv_cache_evict(struct rv_mr_cache *cache, unsigned long mbytes);
static int mmu_notifier_range_start(struct mmu_notifier *,
				    const struct mmu_notifier_range *);
static struct rv_mr_cached *rv_mr_cache_search(struct rv_mr_cache *cache,
					       unsigned long addr,
					       unsigned long len,
					       unsigned int acc);
static void rv_update_mrc_stats_add(struct rv_mr_cache *cache,
				    struct rv_mr_cached *mrc);
static void rv_update_mrc_stats_remove(struct rv_mr_cache *cache,
				       struct rv_mr_cached *mrc);

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

static unsigned long mrc_start(struct rv_mr_cached *mrc)
{
	return mrc->addr;
}

static unsigned long mrc_last(struct rv_mr_cached *mrc)
{
	return mrc->addr + mrc->len - 1;
}

INTERVAL_TREE_DEFINE(struct rv_mr_cached, node, unsigned long, __last,
		     mrc_start, mrc_last, static, rv_int_rb);

static int mmu_notifier_range_start(struct mmu_notifier *mn,
				    const struct mmu_notifier_range *range)
{
	struct rv_mr_cache *cache = container_of(mn, struct rv_mr_cache, mn);
#ifdef NO_RB_ROOT_CACHE
	struct rb_root *root = &cache->root;
#else
	struct rb_root_cached *root = &cache->root;
#endif
	struct rv_mr_cached *mrc, *ptr = NULL;
	unsigned long flags;
	bool added = false;

	spin_lock_irqsave(&cache->lock, flags);
	for (mrc = rv_int_rb_iter_first(root, range->start, range->end - 1);
	     mrc; mrc = ptr) {
		/* Guard against node removal. */
		ptr = rv_int_rb_iter_next(mrc, range->start, range->end - 1);
		/*
		 * NOTE: mimic hfi1 by making this call to invalidate. In other
		 * words, do not remove the node unless the refcount is 0!!!
		 */
		if (cache->ops->invalidate(cache, cache->ops_arg, mrc)) {
			trace_rv_mr_cache_notifier(mrc->addr, mrc->len,
						   mrc->access);
			rv_int_rb_remove(mrc, root);
			/* move from LRU list to delete list */
			list_move(&mrc->list, &cache->del_list);
			cache->stats.remove++;
			rv_update_mrc_stats_remove(cache, mrc);
			added = true;
			/*
			 * perform dereg_mem in do_remove or else you have
			 * issues in ib_umem_release
			 */
		}
	}
	spin_unlock_irqrestore(&cache->lock, flags);

	if (added)
		queue_work(cache->wq, &cache->del_work);
	return 0;
}

int rv_mr_cache_init(int rv_inx, struct rv_mr_cache *cache,
		     const struct rv_mr_cache_ops *ops, void *priv,
		     struct mm_struct *mm, u32 cache_size)
{
	char wq_name[25];	/* allow for up to 2^64 value for rv_inx */
	int ret = 0;

	/*
	 * XXX: We used a our own work queue in hfi but we may be able to get
	 * by with the system default go ahead and create one for now.
	 */
	sprintf(wq_name, "rv-%d\n", rv_inx);
	cache->wq = alloc_workqueue(wq_name,
				    WQ_SYSFS | WQ_HIGHPRI | WQ_CPU_INTENSIVE
					| WQ_MEM_RECLAIM,
				    RV_RB_MAX_ACTIVE_WQ_ENTRIES);
	if (!cache->wq)
		return -ENOMEM;

	trace_rv_mr_cache_wq_alloc(wq_name);
#ifdef NO_RB_ROOT_CACHE
	cache->root = RB_ROOT;
#else
	cache->root = RB_ROOT_CACHED;
#endif
	cache->ops = ops;
	cache->ops_arg = priv;

	INIT_HLIST_NODE(&cache->mn.hlist);
	spin_lock_init(&cache->lock);

	cache->mn.ops = &mn_opts;
	cache->mm = mm;

	INIT_WORK(&cache->del_work, handle_remove);
	INIT_LIST_HEAD(&cache->del_list);
	INIT_LIST_HEAD(&cache->lru_list);

	if (cache_size)
		cache->max_size = (unsigned long)cache_size * 1024 * 1024;
	else
		cache->max_size = (unsigned long)mr_cache_size * 1024 * 1024;

	if (mm) {
		ret = mmu_notifier_register(&cache->mn, cache->mm);
		if (ret) {
			destroy_workqueue(cache->wq);
			cache->wq = NULL;
		}
	}

	return ret;
}

void rv_mr_cache_deinit(int rv_inx, struct rv_mr_cache *cache)
{
	struct rv_mr_cached *mrc;
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
		mrc = rb_entry(node, struct rv_mr_cached, node);
		trace_rv_mr_cache_deinit(mrc->addr, mrc->len, mrc->access,
					 atomic_read(&mrc->refcount));
#ifdef NO_RB_ROOT_CACHE
		rb_erase(node, &cache->root);
#else
		rb_erase_cached(node, &cache->root);
#endif
		/* move from LRU list to delete list */
		list_move(&mrc->list, &del_list);
		cache->stats.remove++;
		rv_update_mrc_stats_remove(cache, mrc);
		/*
		 * perform dereg_mem in do_remove or else you have issues in
		 * ib_umem_release.
		 */
	}
	WARN_ON(cache->total_size);

	spin_unlock_irqrestore(&cache->lock, flags);

	/* remove any we queued for delete above */
	do_remove(cache, &del_list);

	/* XXX destroy above after flush to ensure nothing gets added */
	if (cache->wq) {
		char wq_name[25];

		sprintf(wq_name, "rv-%d\n", rv_inx);
		trace_rv_mr_cache_wq_destroy(wq_name);
		/* Flush the workqueue first */
		flush_workqueue(cache->wq);
		destroy_workqueue(cache->wq);
	}
	cache->wq = NULL;
	cache->mm = NULL;
}

/* called with cache->lock */
void rv_mr_cache_update_stats_max(struct rv_mr_cache *cache, int refcount)
{
	if ((u32)refcount > cache->stats.max_refcount)
		cache->stats.max_refcount = (u32)refcount;
	if (cache->stats.inuse > cache->stats.max_inuse)
		cache->stats.max_inuse = cache->stats.inuse;
	if (cache->stats.inuse_bytes > cache->stats.max_inuse_bytes)
		cache->stats.max_inuse_bytes = cache->stats.inuse_bytes;
	if (cache->stats.count > cache->stats.max_count)
		cache->stats.max_count = cache->stats.count;
	if (cache->total_size > cache->stats.max_cache_size)
		cache->stats.max_cache_size = cache->total_size;
}

/* gets a reference to mrc on behalf of caller */
int rv_mr_cache_insert(struct rv_mr_cache *cache,
		       struct rv_mr_cached *mrc)
{
	struct rv_mr_cached *existing;
	unsigned long flags;
	unsigned long new_len, evict_len;
	int ret = 0;

again:
	trace_rv_mr_cache_insert(mrc->addr, mrc->len, mrc->access);

	spin_lock_irqsave(&cache->lock, flags);
	existing = rv_mr_cache_search(cache, mrc->addr, mrc->len, mrc->access);
	if (existing) {
		ret = -EINVAL;
		goto unlock;
	}
	new_len = cache->total_size + mrc->len;
	if (new_len > cache->max_size) {
		spin_unlock_irqrestore(&cache->lock, flags);

		trace_rv_mr_cache_cache_full(cache->max_size, cache->total_size,
					     mrc->len);

		evict_len = new_len - cache->max_size;
		if (rv_cache_evict(cache, evict_len) >= evict_len)
			goto again;
		spin_lock_irqsave(&cache->lock, flags);
		cache->stats.full++;
		spin_unlock_irqrestore(&cache->lock, flags);
		return -ENOMEM;
	}

	rv_int_rb_insert(mrc, &cache->root);
	INIT_LIST_HEAD(&mrc->list);

	cache->ops->get(cache, cache->ops_arg, mrc);
	cache->stats.miss++;
	rv_update_mrc_stats_add(cache, mrc);
unlock:
	spin_unlock_irqrestore(&cache->lock, flags);
	return ret;
}

/* Caller must hold cache->lock */
static struct rv_mr_cached *rv_mr_cache_search(struct rv_mr_cache *cache,
					       unsigned long addr,
					       unsigned long len,
					       unsigned int acc)
{
	struct rv_mr_cached *mrc = NULL;

	trace_rv_mr_cache_search_enter(addr, len, acc);

	if (!cache->ops->filter) {
		mrc = rv_int_rb_iter_first(&cache->root, addr,
					   (addr + len) - 1);
		if (mrc)
			trace_rv_mr_cache_search_mrc(mrc->addr, mrc->len,
						     mrc->access);
	} else {
		for (mrc = rv_int_rb_iter_first(&cache->root, addr,
						(addr + len) - 1);
		     mrc;
		     mrc = rv_int_rb_iter_next(mrc, addr, (addr + len) - 1)) {
			trace_rv_mr_cache_search_mrc(mrc->addr, mrc->len,
						     mrc->access);
			if (cache->ops->filter(mrc, addr, len, acc))
				return mrc;
		}
	}
	return mrc;
}

struct rv_mr_cached *rv_mr_cache_search_get(struct rv_mr_cache *cache,
					    unsigned long addr,
					    unsigned long len, unsigned int acc,
					    bool update_hit)
{
	unsigned long flags;
	struct rv_mr_cached *mrc;

	spin_lock_irqsave(&cache->lock, flags);
	mrc =  rv_mr_cache_search(cache, addr, len, acc);
	if (mrc) {
		cache->ops->get(cache, cache->ops_arg, mrc);
		if (update_hit)
			cache->stats.hit++;
		/* If it is on lru_list, remove it */
		list_del_init(&mrc->list);
	}
	spin_unlock_irqrestore(&cache->lock, flags);

	return mrc;
}

struct rv_mr_cached *rv_mr_cache_search_put(struct rv_mr_cache *cache,
					    unsigned long addr,
					    unsigned long len, unsigned int acc)
{
	unsigned long flags;
	struct rv_mr_cached *mrc;

	spin_lock_irqsave(&cache->lock, flags);
	mrc =  rv_mr_cache_search(cache, addr, len, acc);
	if (mrc) {
		/* do the inc/dec before releasing lock */
		/* Make sure that refcount will not become negative */
		if (!atomic_read(&mrc->refcount)) {
			mrc = NULL;
			goto unlock;
		}
		if (!cache->ops->put(cache, cache->ops_arg, mrc))
			list_add(&mrc->list, &cache->lru_list);
	}
unlock:
	spin_unlock_irqrestore(&cache->lock, flags);

	return mrc;
}

void rv_mr_cache_put(struct rv_mr_cache *cache, struct rv_mr_cached *mrc)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	if (!cache->ops->put(cache, cache->ops_arg, mrc))
		list_add(&mrc->list, &cache->lru_list);
	spin_unlock_irqrestore(&cache->lock, flags);
}

void rv_mr_cache_evict(struct rv_mr_cache *cache, void *evict_arg)
{
	struct rv_mr_cached *mrc, *temp;
	struct list_head del_list;
	unsigned long flags;
	bool stop = false;

	INIT_LIST_HEAD(&del_list);

	spin_lock_irqsave(&cache->lock, flags);
	list_for_each_entry_safe_reverse(mrc, temp, &cache->lru_list, list) {
		/*
		 * XXX Evict handler should not be what decides to stop
		 * XXX Evict handler needs to take in the access flags as
		 * well!
		 */
		if (cache->ops->evict(cache, cache->ops_arg, mrc, evict_arg,
				      &stop)) {
			trace_rv_mr_cache_evict_evict(mrc->addr, mrc->len,
						      mrc->access);
			rv_int_rb_remove(mrc, &cache->root);
			/* move from LRU list to delete list */
			list_move(&mrc->list, &del_list);
			cache->stats.evict++;
			rv_update_mrc_stats_remove(cache, mrc);
		} else {
			trace_rv_mr_cache_evict_keep(mrc->addr, mrc->len,
						     mrc->access);
		}
		if (stop)
			break;
	}
	spin_unlock_irqrestore(&cache->lock, flags);

	do_remove(cache, &del_list);
}

#ifdef NVIDIA_GPU_DIRECT
/*
 * It is up to the caller to ensure that this function does not race with the
 * mmu invalidate notifier which may be calling the users remove callback on
 * 'mrc'.
 */
/* XXX - only used for gdp_ops.c, risk in that assumes refcount is 1 */
void rv_mr_cache_remove(struct rv_mr_cache *cache, struct rv_mr_cached *mrc)
{
	unsigned long flags;

	/* Validity of cache and mrc pointers has been checked by caller. */
	spin_lock_irqsave(&cache->lock, flags);
	trace_rv_mr_cache_remove(mrc->addr, mrc->len, mrc->access);
	rv_int_rb_remove(mrc, &cache->root);
	list_del_init(&mrc->list); /* remove from LRU list */
	if (cache->ops->put(cache, cache->ops_arg, mrc))
		WARN_ON(1);
	cache->stats.remove++;
	rv_update_mrc_stats_remove(cache, mrc);
	spin_unlock_irqrestore(&cache->lock, flags);

}
#endif

/*
 * Call the remove function for the given cache and the list.  This
 * is expected to be called with a delete list extracted from cache.
 * The caller should not be holding the cache->lock.
 */
static void do_remove(struct rv_mr_cache *cache, struct list_head *del_list)
{
	struct rv_mr_cached *mrc;

	while (!list_empty(del_list)) {
		mrc = list_first_entry(del_list, struct rv_mr_cached, list);
		list_del(&mrc->list);
#ifdef NVIDIA_GPU_DIRECT
		rv_drv_api_dereg_mem(&mrc->mr, (void *)mrc->addr, mrc->len,
				     mrc->access);
#else
		rv_drv_api_dereg_mem(&mrc->mr);
#endif
		kfree(mrc);
	}
}

/*
 * Work queue function to remove all nodes that have been queued up to
 * be removed.	The key feature is that mm->mmap_lock is not being held
 * and the remove callback can sleep while taking it, if needed.
 */
static void handle_remove(struct work_struct *work)
{
	struct rv_mr_cache *cache = container_of(work, struct rv_mr_cache,
						 del_work);
	struct list_head del_list;
	unsigned long flags;

	/* remove anything that is queued to get removed */
	spin_lock_irqsave(&cache->lock, flags);
	list_replace_init(&cache->del_list, &del_list);
	spin_unlock_irqrestore(&cache->lock, flags);

	do_remove(cache, &del_list);
}

static u32 rv_cache_evict(struct rv_mr_cache *cache, unsigned long mbytes)
{
	struct evict_data evict_data;

	evict_data.cleared = 0;
	evict_data.target = mbytes;
	trace_rv_mr_cache_cache_evict(evict_data.cleared, evict_data.target,
				      cache->total_size);
	rv_mr_cache_evict(cache, &evict_data);
	trace_rv_mr_cache_cache_evict(evict_data.cleared, evict_data.target,
				      cache->total_size);
	return evict_data.cleared;
}

static void rv_update_mrc_stats_add(struct rv_mr_cache *cache,
				    struct rv_mr_cached *mrc)
{
	cache->total_size += mrc->len;
	cache->stats.count++;
	rv_mr_cache_update_stats_max(cache, atomic_read(&mrc->refcount));
}

static void rv_update_mrc_stats_remove(struct rv_mr_cache *cache,
				       struct rv_mr_cached *mrc)
{
	cache->total_size -= mrc->len;
	cache->stats.count--;
}

#ifdef NVIDIA_GPU_DIRECT
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
struct rv_mr_cached *rv_mr_cache_first(struct rv_mr_cache *cache)
{
	struct rv_mr_cached *mrc = NULL;
	struct rb_node *node;
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
#ifdef NO_RB_ROOT_CACHE
	node = rb_first(&cache->root);
#else
	node = rb_first_cached(&cache->root);
#endif
	if (node)
		mrc = rb_entry(node, struct rv_mr_cached, node);
	spin_unlock_irqrestore(&cache->lock, flags);

	return mrc;
}
#endif
