/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 - 2021 Intel Corporation.
 */

#ifndef __RV_MR_CACHE_H__
#define __RV_MR_CACHE_H__

#define RV_REG_MR_DISCRETE       /* discrete QP with REG_MR WQE */

#include <linux/types.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/mmu_notifier.h>
#include <linux/interval_tree_generic.h>

#include "compat.h"

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
#include "gpu.h"
#endif

#define RV_RB_MAX_ACTIVE_WQ_ENTRIES 5

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
enum rv_mrce_type {
	RV_MRCE_TYPE_REG =	0,
	RV_MRCE_TYPE_MMAP =	1,
	RV_MRCE_TYPE_BOTH =	2,
	RV_MRCE_TYPE_COUNT =	3	/* number of types */
};
#endif

/*
 * The MR cache holds registered MRs and tracks reference counts for each.
 * Entries with a refcount==0 may remain in the cache and on an lru_list.
 * If the MMU notifier indicates pages would like to be freed, the entry
 * will be removed from the cache if it's refcount==0.  Otherwise there
 * are IOs in flight (app should not free memory for buffers with IOs in flight)
 * and the MMU notifier is not allowed to free the pages.
 * If a new cache entry is needed (cache miss), entries will be evicted, oldest
 * to newest based on the lru_list, until there is space for the new entry.
 *
 * max_size - limit allowed for total_size in bytes, immutable
 * is_gdr - is the cache a GPUDirect cache (1 or 0)?
 * context - owner context for all ops calls, immutable
 * mn - MMU notifier
 * lock - protects the RB-tree, lru_list, del_list, total_size, and stats
 *	  also protects some fields in rv_mr_cache_entry (node, refcount,
 *	  user_refcount, list)
 * root - an RB-tree with an interval based lookup
 * total_size - current bytes in the cache
 * ops - owner callbacks for major cache events
 * mm - for MMU notifier
 * lru_list - ordered list, most recently used to least recently used
 * del_work, del_list, wq - handle deletes on a work queue
 *
 * Statistics:
 *	max_cache_size - max bytes in the cache
 *	count - Current number of MRs in the cache
 *	max_count - Maximum of count
 *	inuse - Current number of MRs with refcount > 0
 *	max_inuse - Maximum of inuse
 *	inuse_bytes - number of bytes with refcount > 0
 *	max_inuse_bytes - of inuse_bytes
 *	max_refcount - Maximum of refcount for any MR
 *	hit - Cache hit
 *	miss - Cache miss and added
 *	full - Cache miss and can't add since full
 *	evict - Removed due to lack of cache space
 *	remove - Refcount==0 & remove by mmu notifier event
 */
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
/*
 * freeing - Cache hit on GPU entry being freed, failure return
 *
 * Statistics also tracked per rv_mrce_type.  For simplicity, these extra stats
 * are tracked for all caches, but only reported against GPU cache
 * because the CPU MR cache will have RV_MRCE_TYPE_REG for all entries.
 * To keep stats tracking simpler, search_get always adds a reference
 * and then promote may change the type.  Worse case this can result in
 * 1 extra max_reference or max_inuse reported for the "non-BOTH" types.
 * In practice the max_inuse and max_reference for TYPE_MMAP will be 1
 * and for TYPE_REG it may be 1 more than desired if "highest reference" was
 * part of a promotion to TYPE_BOTH.
 */
#endif
struct rv_mr_cache {
	u64 max_size;
	int is_gdr;
	void *context;
	struct mmu_notifier mn;
	spinlock_t lock; /* See above */
#ifdef NO_RB_ROOT_CACHE
	struct rb_root root;
#else
	struct rb_root_cached root;
#endif
	u64 total_size;
	const struct rv_mr_cache_ops *ops;
	struct mm_struct *mm;
	struct list_head lru_list;
	struct work_struct del_work;
	struct list_head del_list;
	struct workqueue_struct *wq;

	struct {
		u64 max_cache_size;
		u32 count;
		u32 max_count;
		u32 inuse;
		u32 max_inuse;
		u64 inuse_bytes;
		u64 max_inuse_bytes;
		u32 max_refcount;
		u64 hit;
		u64 miss;
		u64 full;
		u64 evict;
		u64 remove;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
		u64 freeing; /* only occurs for GPU cache */
		u64 total_size_a[RV_MRCE_TYPE_COUNT];
		u64 max_cache_size_a[RV_MRCE_TYPE_COUNT];
		u32 count_a[RV_MRCE_TYPE_COUNT];
		u32 max_count_a[RV_MRCE_TYPE_COUNT];
		u32 inuse_a[RV_MRCE_TYPE_COUNT];
		u32 max_inuse_a[RV_MRCE_TYPE_COUNT];
		u32 max_refcount_a[RV_MRCE_TYPE_COUNT];
		u64 inuse_bytes_a[RV_MRCE_TYPE_COUNT];
		u64 max_inuse_bytes_a[RV_MRCE_TYPE_COUNT];
		u64 miss_a[RV_MRCE_TYPE_COUNT];
		u64 full_a[RV_MRCE_TYPE_COUNT];
		u64 remove_a[RV_MRCE_TYPE_COUNT];
		u64 evict_a[RV_MRCE_TYPE_COUNT];
#endif
	} stats;
};

/*
 * an entry in the MR cache RB-tree
 *
 * We track two reference counts:
 * refcount - total references, MRs held for user and IOs in flight
 * user_refcount - references held for users.  Subset of refcount.
 *		  used to allow cleanup of user references on close.
 *
 * addr, len, access, __last - immutable
 * node, refcount, user_refcount - protected by rv_mr_cache.lock
 * list - when used for lru_list add/remove is protected by rv_mr_cache.lock
 * list - not protected during final entry ops->removal (after out of cache)
 */
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
/*
 * freeing - This is used for GPU MRs to indicate that GPU wants to free
 *	     pages, so we don't want to add any new references and are
 *	     waiting for completion when refcount hits 0.
 *	     protected by rv_mr_cache.lock. Only set for GPU cache's MRs.
 */
/*
 * type - indicates type of MR.  CPU MRs are always RV_MRCE_TYPE_REG however
 *	  GPU MR can start as RV_MRCE_TYPE_REG or RV_MRCE_TYPE_MMAP and may
 *	  progress to RV_MRCE_TYPE_BOTH.  The mrce will never regress from
 *	  BOTH back to the other types.  The type is solely used for stats
 *	  and is protected by the rv_mr_cache.lock.  Having this type
 *	  avoids the need for rv_mr_cache_put to get higher level mutex's
 *	  to determine the MR type by inspection of host_addr and ib_mr.
 */
#endif
struct rv_mr_cache_entry {
	u64 addr;
	u64 len;
	u32 access;
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
	u8 freeing;
	u8 type;
#endif
	u64 __last;
	u32 refcount;
	u32 user_refcount;
	struct rb_node node;
	struct list_head list;
};

/*
 * evict operation argument
 * cleared - count evicted so far in bytes
 * target - target count to evict in bytes
 */
struct evict_data {
	u64 cleared_bytes;
	u64 target_bytes;
	u32 cleared_count;
	u32 target_count;
};

struct evict_out {
	u64 bytes;
	u32 count;
};

/* callbacks for each major cache event */
struct rv_mr_cache_ops {
	bool (*filter)(struct rv_mr_cache_entry *mrce, u64 addr, u64 len,
		       u32 acc);
	void (*remove)(struct rv_mr_cache *cache,
		       void *context, struct rv_mr_cache_entry *mrce,
		       int is_invalidate);
};

int rv_mr_cache_insert(struct rv_mr_cache *cache,
		       struct rv_mr_cache_entry *mrce);

int rv_mr_cache_evict_exact(struct rv_mr_cache *cache,
			    u64 addr, u64 len, u32 acc);
int rv_mr_cache_evict_range(struct rv_mr_cache *cache,
			    u64 addr, u64 len, struct evict_out *out);
int rv_mr_cache_evict_amount(struct rv_mr_cache *cache,
			     u64 bytes, u32 count, struct evict_out *out);
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
int rv_mr_cache_evict_mrce(struct rv_mr_cache *cache,
			   struct rv_mr_cache_entry *mrce,
			   int is_invalidate);
#ifdef INTEL_GPU_DIRECT
void rv_mr_cache_inc_hit(struct rv_mr_cache *cache);
void rv_mr_cache_entry_put(struct rv_mr_cache *cache,
				struct rv_mr_cache_entry *mrce);
#endif
#endif

struct rv_mr_cache_entry *rv_mr_cache_search_get(struct rv_mr_cache *cache,
						 u64 addr, u64 len, u32 acc,
						 bool update_hit,
						 bool for_user);
struct rv_mr_cache_entry *rv_mr_cache_search_put(struct rv_mr_cache *cache,
						 u64 addr, u64 len, u32 acc);
void rv_mr_cache_put(struct rv_mr_cache *cache, struct rv_mr_cache_entry *mrce,
		     bool for_user);

int rv_mr_cache_init(int rv_inx, char cache_id, struct rv_mr_cache *cache,
		     const struct rv_mr_cache_ops *ops, void *context,
		     struct mm_struct *mm, u32 cache_size, int is_gdr);
void rv_mr_cache_deinit(int rv_inx, struct rv_mr_cache *cache);

void rv_mr_cache_entry_init(struct rv_mr_cache_entry *mrce,
			    u64 addr, u64 len, u32 access);
void rv_mr_cache_entry_deinit(struct rv_mr_cache_entry *mrce);


#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
void rv_mr_cache_entry_promote(struct rv_mr_cache *cache,
			       struct rv_mr_cache_entry *mrce);
struct rv_mr_cache_entry *rv_mr_cache_first(struct rv_mr_cache *cache);
#endif

#endif /* __RV_MR_CACHE_H__ */
