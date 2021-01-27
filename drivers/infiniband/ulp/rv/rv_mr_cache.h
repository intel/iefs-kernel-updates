/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 */

#ifndef __RV_MR_CACHE_H__
#define __RV_MR_CACHE_H__

/*
 * right now we have 2 implementations of kernel MR registration
 * RV_REG_MR_PD_UOBJECT currently works best
 * Exactly 1 must be defined
 */
#undef RV_REG_MR_DISCRETE       /* discrete QP with REG_MR WQE */
#define RV_REG_MR_PD_UOBJECT	/* fill in pd->uobject during reg_mr */

#include <linux/types.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/mmu_notifier.h>
#include <linux/interval_tree_generic.h>

#include "compat.h"

#ifdef NVIDIA_GPU_DIRECT
#include "gpu.h"
#endif

#define MAX_RB_SIZE 256 /* This is MB */
#define RV_RB_MAX_ACTIVE_WQ_ENTRIES 5 /* XXX: Find a better value */

struct rv_mr_cache {
	unsigned long max_size; /* limit allowed for total_size, immutable */
	void *ops_arg;	/* owner context for all ops calls, immutable */
	struct mmu_notifier mn;
	spinlock_t lock;	/* protect the RB tree and stats */
#ifdef NO_RB_ROOT_CACHE
	struct rb_root root;
#else
	struct rb_root_cached root;
#endif
	unsigned long total_size; /* current bytes in the cache */
	const struct rv_mr_cache_ops *ops;
	struct mm_struct *mm;
	struct list_head lru_list;
	struct work_struct del_work;
	struct list_head del_list;
	struct workqueue_struct *wq;

	/* Statistics */
	struct {
		u64 max_cache_size; /* max bytes in the cache */
		u32 count;	/* Current number of MRs in the cache */
		u32 max_count;	/* Maximum of count */
		u32 inuse;	/* Current number of MRs with refcount > 0 */
		u32 max_inuse;	/* Maximum of inuse */
		u64 inuse_bytes;/* Current number of bytes with refcount > 0 */
		u64 max_inuse_bytes;/* Maximum of inuse_bytes */
		u32 max_refcount; /* Maximum of refcount for any MR */
		u64 hit;	/* Cache hit */
		u64 miss;	/* Cache miss and added */
		u64 full;	/* Cache miss and can't add since full */
		u64 evict;	/* Removed due to lack of cache space */
		u64 remove;	/* Refcount==0 & remove by mmu notifier event */
	} stats;
};

struct mr_info { /* XXX Rename to rv_mr_info this needs to go somewhere else not RB related */
	struct ib_mr *ib_mr;
	struct ib_pd *ib_pd; /* converted from user version */
	struct fd fd; /* converted from user provided cmd_fd */
#ifndef RV_REG_MR_PD_UOBJECT
	/* For registering kernel mr */
	struct ib_ucontext ucontext;
	struct ib_umem *umem;
#endif
#ifdef NVIDIA_GPU_DIRECT
	nvidia_p2p_page_table_t *page_table;
#endif
};

struct rv_mr_cached {
	struct mr_info mr; /*non-rb tree related info */
	unsigned long addr;
	unsigned long len;
	unsigned int access;
	unsigned long __last;
	atomic_t refcount;
	struct rb_node node;
	struct list_head list;
};

struct rv_mr_cache_ops {
	bool (*filter)(struct rv_mr_cached *mrc, unsigned long addr,
		       unsigned long len, unsigned int acc);
	void (*get)(struct rv_mr_cache *cache,
		    void *ops_arg, struct rv_mr_cached *mrc);
	int (*put)(struct rv_mr_cache *cache,
		   void *ops_arg, struct rv_mr_cached *mrc);
	int (*invalidate)(struct rv_mr_cache *cache,
			  void *ops_arg, struct rv_mr_cached *mrc);
	int (*evict)(struct rv_mr_cache *cache,
		     void *ops_arg, struct rv_mr_cached *mrc,
		     void *evict_arg, bool *stop);
};

void rv_mr_cache_update_stats_max(struct rv_mr_cache *cache,
				  int refcount);

int rv_mr_cache_insert(struct rv_mr_cache *cache, struct rv_mr_cached *mrc);

void rv_mr_cache_evict(struct rv_mr_cache *cache, void *evict_arg);
#ifdef NVIDIA_GPU_DIRECT
void rv_mr_cache_remove(struct rv_mr_cache *cache, struct rv_mr_cached *mrc);
#endif

struct rv_mr_cached *rv_mr_cache_search_get(struct rv_mr_cache *cache,
					    unsigned long addr,
					    unsigned long len, unsigned int acc,
					    bool update_hit);
struct rv_mr_cached *rv_mr_cache_search_put(struct rv_mr_cache *cache,
					    unsigned long addr,
					    unsigned long len, unsigned int acc);
void rv_mr_cache_put(struct rv_mr_cache *cache, struct rv_mr_cached *mrc);

int rv_mr_cache_init(int rv_inx, struct rv_mr_cache *cache,
		     const struct rv_mr_cache_ops *ops, void *priv,
		     struct mm_struct *mm, u32 cache_size);
void rv_mr_cache_deinit(int rv_inx, struct rv_mr_cache *cache);

/* evict operation argument */
struct evict_data {
	unsigned long cleared;    /* (in MB) count evicted so far */
	unsigned long target;     /* (in MB) target count to evict */
};

#ifdef NVIDIA_GPU_DIRECT
struct rv_mr_cached *rv_mr_cache_first(struct rv_mr_cache *cache);
#endif

#endif /* __RV_MR_CACHE_H__ */
