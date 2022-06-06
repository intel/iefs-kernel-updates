/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 - 2021 Intel Corporation.
 */
#ifndef __RV_USER_IOCTL_H__
#define __RV_USER_IOCTL_H__
#include <rdma/rdma_user_ioctl.h>
#include <rdma/ib_user_sa.h>
#include <rdma/ib_user_verbs.h>

/* Checking /Documentation/userspace-api/ioctl/ioctl-number.rst */
#define RV_MAGIC RDMA_IOCTL_MAGIC
#define RV_FILE_NAME "/dev/rv"

/*
 * Handles are opaque to application; they are meaningful only to the
 * RV driver
 */

/* this version of ABI */
#define RV_ABI_VER_MAJOR 1
#define RV_ABI_VER_MINOR 1

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
/* this version of GPU ABI */
#define RV_GPU_ABI_VER_MAJOR 1
#define RV_GPU_ABI_VER_MINOR 0
#endif
/* define capability flags here */
#define RV_CAP_USER_MR (1UL << 0) /* registering MR for user PD allowed */
#define RV_CAP_EVICT   (1UL << 1) /* RV_IOCTL_EVICT */
#ifdef NVIDIA_GPU_DIRECT
/*
 * Bit-63 is being used instead of the LSB that is available since
 * RV_CAP_GPU_DIRECT will only be used in an out of tree driver.
 */
#define RV_CAP_GPU_DIRECT (1UL << 63) /* GPU Direct RDMA support */
#endif

struct rv_query_params_out {
		/* ABI version */
	__u16 major_rev;
	__u16 minor_rev;
#ifdef NVIDIA_GPU_DIRECT
	__u16 gpu_major_rev;
	__u16 gpu_minor_rev;
#else
	__u32 pad;
#endif
	__aligned_u64 capability;
	__aligned_u64 resv2[6];
};

#define RV_IOCTL_QUERY _IOR(RV_MAGIC, 0xFC, struct rv_query_params_out)

/* Mode for use of rv module by PSM */
#define RV_RDMA_MODE_USER 0	/* user MR caching only */
#define RV_RDMA_MODE_KERNEL 1	/* + kernel RC QPs with kernel MR caching */
#ifdef NVIDIA_GPU_DIRECT
#define RV_RDMA_MODE_GPU_ONLY 2 /* Only for GPU access */
#define RV_RDMA_MODE_MAX 2
#define RV_RDMA_MODE_MASK 0x3
#else
#define RV_RDMA_MODE_MAX 1
#define RV_RDMA_MODE_MASK 1
#endif

/*
 * there are two configurable sizes for the cache, when PSM is using a
 * larger window size due to GPU, it selects the upsized cache
 */
#define RV_RDMA_MODE_UPSIZE_CPU 0x20 /* upsize CPU cache */
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
#define RV_RDMA_MODE_UPSIZE_GPU 0x40 /* upsize GPU cache */
#define RV_RDMA_MODE_GPU	0x80 /* PSM will pin/mmap/register GPU memory */
#endif

#define RV_MAX_DEV_NAME_LEN IB_DEVICE_NAME_MAX
#define RV_MAX_NUM_CONN 16
#define RV_MAX_INDEX_BITS 12
#define RV_MAX_JOB_KEY_LEN 16
#define RV_MAX_CQ_ENTRIES 10000

/*
 * mr_cache_size is in MBs and if 0 will use module param as default
 * num_conn - number of QPs between each pair of nodes
 * loc_addr - used to select client/listen vs rem_addr when !ah.is_global
 *	otherwise ah.grh.dgid is compared to loc_gid
 * index_bits - num high bits of immed data with rv index
 * loc_gid_index - SGID for client connections
 * loc_gid[16] - to double check gid_index unchanged and compare to ah.grh.dgid
 * job_key[RV_MAX_JOB_KEY_LEN] = unique uuid per job
 * job_key_len - len, if 0 matches jobs with len==0 only
 * q_depth - size of QP and per QP CQs
 * reconnect_timeout - in seconds from loss to restoration
 * hb_interval - in milliseconds between heartbeats
 */
#ifdef NVIDIA_GPU_DIRECT
/* gpu_cache_size is in MBs and if 0 will use module param as default */
#endif
struct rv_attach_params_in {
	char dev_name[RV_MAX_DEV_NAME_LEN];
	__u32 mr_cache_size;
	__u8 rdma_mode;

	/* additional information for RV_RDMA_MODE_KERNEL */
	__u8 port_num;
	__u8 num_conn;
#ifdef NVIDIA_GPU_DIRECT
	/* XXX we have 1 byte here if needed */
#endif
	__u32 loc_addr;
	__u8 index_bits;
#ifdef NVIDIA_GPU_DIRECT
	/* XXX we have 1 byte here if needed */
#endif
	__u16 loc_gid_index;
	__u8 loc_gid[16];
	__u8 job_key[RV_MAX_JOB_KEY_LEN];
	__u8 job_key_len;
#ifdef NVIDIA_GPU_DIRECT
	/* XXX we have 3 more bytes here */
	__u32 gpu_cache_size;
#endif
	__aligned_u64 service_id;
	__aligned_u64 context;
	__u32 cq_entries;
	__u32 q_depth;
	__u32 reconnect_timeout;
	__u32 hb_interval;
};

/*
 * rv_index - unique within job on given NIC
 * mr_cache_size - in MBs
 * q_depth - size of QP and per QP CQs
 * reconnect_timeout - value being used
 */
struct rv_attach_params_out {
	__u32 rv_index;
	__u32 mr_cache_size;
	__u32 q_depth;
	__u32 reconnect_timeout;
};

#ifdef NVIDIA_GPU_DIRECT
/*
 * returned only when attach with RV_RDMA_MODE_GPU.  To keep ABI interop
 * sizeof(rv_attach_params_out_gpu) must be <= sizeof(rv_attach_params_in)
 *
 * rv_index - unique within job on given NIC
 * mr_cache_size - in MBs
 * q_depth - size of QP and per QP CQs
 * reconnect_timeout - value being used
 * gpu_cache_size - in MBs
 */
struct rv_attach_params_out_gpu {
	__u32 rv_index;
	__u32 mr_cache_size;
	__u32 q_depth;
	__u32 reconnect_timeout;
	__u32 gpu_cache_size;
};
#endif

struct rv_attach_params {
	union {
		struct rv_attach_params_in in;
		struct rv_attach_params_out out;
#ifdef NVIDIA_GPU_DIRECT
		struct rv_attach_params_out_gpu out_gpu;
#endif
	};
};

#define RV_IOCTL_ATTACH		_IOWR(RV_MAGIC, 0xF1, struct rv_attach_params)

/* The buffer is used to register a kernel mr */
#define IBV_ACCESS_KERNEL 0x80000000

/*
 * ibv_pd_handle - user space appl allocated pd
 * ulen - driver_udata inlen
 * *udata - driver_updata inbuf
 */
struct rv_mem_params_in {
	__u32 ibv_pd_handle;
	__u32 cmd_fd_int;
	__aligned_u64 addr;
	__aligned_u64 length;
	__u32 access;
	size_t ulen;
	void *udata;
};

struct rv_mem_params_out {
	__aligned_u64 mr_handle;
	__aligned_u64 iova;
	__u32 lkey;
	__u32 rkey;
};

struct rv_mem_params {
	union {
		struct rv_mem_params_in in;
		struct rv_mem_params_out out;
	};
};

#define RV_IOCTL_REG_MEM	_IOWR(RV_MAGIC, 0xF3, struct rv_mem_params)

struct rv_dereg_params_in {
	__aligned_u64 mr_handle;
	__aligned_u64 addr;
	__aligned_u64 length;
	__u32 access;
};

#define RV_IOCTL_DEREG_MEM	_IOW(RV_MAGIC, 0xF4, struct rv_dereg_params_in)

/*
 * The caller can evict:
 *	- a specific MR (exact, including access),
 *	- all MRs in an address range (access ignored)
 *	- evict an amount from the cache.  When evicting an amount, MRs
 *	  are evicted until >= bytes and >= count has been evicted
 * evict will not affect MRs which have a reference from an IO or
 * a REG_MEM call which has not had a cooresponding DEREG_MEM.
 */
#define RV_EVICT_TYPE_SEARCH_EXACT 1
#define RV_EVICT_TYPE_SEARCH_RANGE 2
#define RV_EVICT_TYPE_AMOUNT 3
#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)
#define RV_EVICT_TYPE_GPU_SEARCH_RANGE 65
#define RV_EVICT_TYPE_GPU_AMOUNT 66
#endif

struct rv_evict_params_in {
	__u8 type;
	__u8 pad[7];
	union {
		struct {
			__aligned_u64 addr;
			__aligned_u64 length;
			__u32 access;
		} search;
		struct {
			__aligned_u64 bytes;
			__u32 count;
		} amount;
	};
};

struct rv_evict_params_out {
	__aligned_u64 bytes;
	__u32 count;
};

struct rv_evict_params {
	union {
		struct rv_evict_params_in in;
		struct rv_evict_params_out out;
	};
};

#define RV_IOCTL_EVICT _IOWR(RV_MAGIC, 0xF6, struct rv_evict_params)

/*
 * MR cache statistics are as follows:
 *   cache_size - Current memory in the cache in bytes
 *   max_cache_size - Maximum of cache_size in bytes
 *   limit_cache_size - Maximum allowed cache_size in MB
 *   count - Current number of MRs in the cache
 *   max_count - Maximum of count
 *   inuse - Current number of MRs in the cache with refcount > 0
 *   max_inuse - Maximum of inuse
 *   inuse_bytes - Current number of bytes in cache for MRs with refcount > 0
 *   max_inuse_bytes - Maximum of inuse_bytes
 *   max_refcount - Maximum of refcount for an MR
 *   Event counts:
 *      hit - Cache hit
 *      miss - Cache miss and added
 *      full - Cache miss but can't add since full
 *      failed - Cache miss but can't add since reg_mr failed
 *	remove - Refcount == 0 and removed by mmu notifier event or cache deinit
 *      evict - Removed from cache due to lack of cache space
 *   Number of valid IOCTL_REG_MEM calls = hit+miss+full+failed
 *      (counts omit some EINVAL and EFAULT REG_MEM use cases)
 */

struct rv_cache_stats_params_out {
	__aligned_u64 cache_size;
	__aligned_u64 max_cache_size;
	__u32 limit_cache_size;
	__u32 count;
	__u32 max_count;
	__u32 inuse;
	__u32 max_inuse;
	__aligned_u64 inuse_bytes;
	__aligned_u64 max_inuse_bytes;
	__u32 max_refcount;
	__aligned_u64 hit;
	__aligned_u64 miss;
	__aligned_u64 full;
	__aligned_u64 failed;
	__aligned_u64 remove;
	__aligned_u64 evict;
};

#define RV_IOCTL_GET_CACHE_STATS _IOR(RV_MAGIC, 0xF7, \
				      struct rv_cache_stats_params_out)

/*
 * The create provides an ah_attr.  Field use is as follows:
 * sanity checked with attach:
 *	grh.sgid_index, port_num
 *	possibly in future: src_path_bits
 * identify QPs which can be shared
 *	rem_addr, ah.is_global, grh.dgid or dlid
 *	possibly in future: sl, traffic_class, flow_label, maybe static_rate
 * sanity checked with connect path:
 *	dlid, grh.dgid
 *	could check: sl
 *	don't want to check: static_rate (could negotiate down in path)
 * validated with inbound REQ
 *	port_num, grh.dgid or dlid
 * Not used: hop_limit (locally resolve)
 * rem_addr - used to select client/listen vs loc_addr when !ah.is_global
 *	otherwise ah.grh.dgid is compared to loc_gid
 */
struct rv_conn_create_params_in {
	struct ib_uverbs_ah_attr ah;
	__u32 rem_addr;
	__aligned_u64 context;
};

/*
 * handle - rv_user_conn for future conn/discon calls
 * conn_handle - rv_conn for completions only
 */
struct rv_conn_create_params_out {
	__aligned_u64 handle;
	__aligned_u64 conn_handle;
};

struct rv_conn_create_params {
	union {
		struct rv_conn_create_params_in in;
		struct rv_conn_create_params_out out;
	};
};

#define RV_IOCTL_CONN_CREATE	_IOWR(RV_MAGIC, 0xF8, \
				      struct rv_conn_create_params)

struct rv_conn_connect_params_in {
	__aligned_u64 handle;
	struct ib_user_path_rec path;
};

#define RV_IOCTL_CONN_CONNECT	_IOW(RV_MAGIC, 0xF9, \
				     struct rv_conn_connect_params_in)

struct rv_conn_connected_params_in {
	__aligned_u64 handle;
};

#define RV_IOCTL_CONN_CONNECTED	_IOW(RV_MAGIC, 0xFA, \
				     struct rv_conn_connected_params_in)

/*
 * get connection count for a specific sconn
 * returns:
 *	0 - count returned
 *	EIO - connection lost and unrecoverable
 *	EINVAL - invalid handle and/or index
 * A 32b count is sufficient to handle constant RV reconnects, with a
 * 100ms delay between each established connection, for up to 13 years.
 */
struct rv_conn_get_conn_count_params_in {
	__aligned_u64 handle;
	__u8 index;
};

/* we return count as an output parameter (vs ioctl ret) so can use full 32b */
struct rv_conn_get_conn_count_params_out {
	__u32 count;
};

struct rv_conn_get_conn_count_params {
	union {
		struct rv_conn_get_conn_count_params_in in;
		struct rv_conn_get_conn_count_params_out out;
	};
};

#define RV_IOCTL_CONN_GET_CONN_COUNT	_IOWR(RV_MAGIC, 0xFF, \
					   struct rv_conn_get_conn_count_params)

/* index to get agg of sconn in given conn */
#define RV_CONN_STATS_AGGREGATE 255

/*
 * handle - if 0, aggregate of all rv's sconn returned
 * index - ignored if !handle, otherwise specific sconn index
 */
struct rv_conn_get_stats_params_in {
	__aligned_u64 handle;
	__u8 index;
};

/*
 * flags can be combined when get aggregate results
 * so separate bits for client vs server
 */
#define RV_CONN_STAT_FLAG_SERVER 0x01
#define RV_CONN_STAT_FLAG_CLIENT 0x02
#define RV_CONN_STAT_FLAG_WAS_CONNECTED 0x04

/*
 * index - mimics input value
 * flags
 * num_conn - total QPs included
 * CM events
 *	req_error - IB_CM_REQ_ERROR
 *	req_recv - IB_CM_REQ_RECEIVED
 *	rep_error - IB_CM_REP_ERROR
 *	rep_recv - IB_CM_REP_RECEIVED
 *	rtu_recv - IB_CM_RTU_RECEIVED
 *	established - IB_CM_USER_ESTABLISHED - via ib_cm_notify
 *	dreq_error - IB_CM_DREQ_ERROR
 *	dreq_recv - IB_CM_DREQ_RECEIVED
 *	drep_recv - IB_CM_DREP_RECEIVED
 *	timewait - IB_CM_TIMEWAIT_EXIT
 *	mra_recv - IB_CM_MRA_RECEIVED
 *	rej_recv - IB_CM_REJ_RECEIVED
 *	lap_error - IB_CM_LAP_ERROR
 *	lap_recv - IB_CM_LAP_RECEIVED
 *	apr_recv - IB_CM_APR_RECEIVED
 *	unexp_event - SIDR and any others
 * outbound CM messages
 *	req_sent - CM REQ
 *	rep_sent - CM REP
 *	rtu_sent - CM RTU
 *	rej_sent - CM REJ
 *	dreq_sent - CM DREQ
 *	drep_sent - CM DREP
 *	(re)connect time does not include wait nor resolver time
 *	wait_time - microseconds for initial connect
 *	resolve_time - microseconds for initial connect
 *	connect_time - microseconds for initial connect
 *	connected_time - microseconds were connected
 *	resolve - attempts at resolving
 *	resolve_fail - hard failures
 *	conn_recovery - # times recovered connection
 *	rewait_time - microseconds for connect recovery
 *	reresolve_time - microseconds for connect recovery
 *	reconnect_time - microseconds for connect recovery
 *	max_rewait_time - microseconds for connect recovery
 *	max_reresolve_time - microseconds for connect recovery
 *	max_reconnect_time - microseconds for connect recovery
 *	reresolve - attempts at resolving
 *	reresolve_fail - hard failures
 *	post_write - successful post_rdma_write
 *	post_write_fail - failed at time of posting
 *	post_write_bytes - for successful post
 *	outstand_send_write - sent RDMA Write waiting for CQE
 *	send_write_cqe - successful sent RDMA Write CQE
 *	send_write_cqe_fail - sent RDMA Write CQE with bad status
 *	recv_write_cqe - successful recv RDMA Write CQE
 *	recv_write_bytes - successful recv RDMA Write
 *	recv_cqe_fail - recv CQE with bad status
 *	post_hb - successful post of heartbeat
 *	post_hb_fail - failed at time of posting
 *	send_hb_cqe - successful sent heartbeat CQE
 *	send_hb_cqe_fail - sent heartbeat CQE with bad status
 *	recv_hb_cqe - successful recv heartbeat CQE
 */
struct rv_conn_get_stats_params_out {
	__u8 index;
	__u8 flags;
	__u32 num_conn;

	/* CM events */
	__u32 req_error;
	__u32 req_recv;
	__u32 rep_error;
	__u32 rep_recv;
	__u32 rtu_recv;
	__u32 established;
	__u32 dreq_error;
	__u32 dreq_recv;
	__u32 drep_recv;
	__u32 timewait;
	__u32 mra_recv;
	__u32 rej_recv;
	__u32 lap_error;
	__u32 lap_recv;
	__u32 apr_recv;
	__u32 unexp_event;

	/* outbound CM messages */
	__u32 req_sent;
	__u32 rep_sent;
	__u32 rtu_sent;
	__u32 rej_sent;
	__u32 dreq_sent;
	__u32 drep_sent;
	__aligned_u64 wait_time;
	__aligned_u64 resolve_time;
	__aligned_u64 connect_time;
	__aligned_u64 connected_time;
	__u32 resolve;
	__u32 resolve_fail;
	__u32 conn_recovery;
	__aligned_u64 rewait_time;
	__aligned_u64 reresolve_time;
	__aligned_u64 reconnect_time;
	__aligned_u64 max_rewait_time;
	__aligned_u64 max_reresolve_time;
	__aligned_u64 max_reconnect_time;
	__u32 reresolve;
	__u32 reresolve_fail;

	__aligned_u64 post_write;
	__aligned_u64 post_write_fail;
	__aligned_u64 post_write_bytes;
	__u32 outstand_send_write;
	__aligned_u64 send_write_cqe;
	__aligned_u64 send_write_cqe_fail;

	__aligned_u64 recv_write_cqe;
	__aligned_u64 recv_write_bytes;
	__aligned_u64 recv_cqe_fail;

	__aligned_u64 post_hb;
	__aligned_u64 post_hb_fail;
	__aligned_u64 send_hb_cqe;
	__aligned_u64 send_hb_cqe_fail;
	__aligned_u64 recv_hb_cqe;
};

struct rv_conn_get_stats_params {
	union {
		struct rv_conn_get_stats_params_in in;
		struct rv_conn_get_stats_params_out out;
	};
};

#define RV_IOCTL_CONN_GET_STATS	_IOWR(RV_MAGIC, 0xFD, \
				      struct rv_conn_get_stats_params)

/*
 * send_write_cqe - successful sent RDMA Write CQE
 * send_write_cqe_fail - sent RDMA Write CQE with bad status
 * send_write_bytes - for successful send
 * recv_write_cqe - successful recv RDMA Write CQE
 * recv_write_cqe_fail - recv RDMA Write CQE with bad status
 * recv_write_bytes - successful recv RDMA Write
 */
struct rv_event_stats_params_out {
	__aligned_u64 send_write_cqe;
	__aligned_u64 send_write_cqe_fail;
	__aligned_u64 send_write_bytes;

	__aligned_u64 recv_write_cqe;
	__aligned_u64 recv_write_cqe_fail;
	__aligned_u64 recv_write_bytes;
};

#define RV_IOCTL_GET_EVENT_STATS _IOR(RV_MAGIC, 0xFE, \
				      struct rv_event_stats_params_out)

#if defined(NVIDIA_GPU_DIRECT) || defined(INTEL_GPU_DIRECT)

#ifndef IBV_ACCESS_IS_GPU_ADDR
#define IBV_ACCESS_IS_GPU_ADDR 0x10000000
#endif

struct rv_gpu_mem_params { /* maps to hfi1_gdr_query_params */
	union {
		struct {
			__aligned_u64 gpu_buf_size;
			__aligned_u64 gpu_buf_addr;
			__u32 access;
		} in;
		struct {
			__aligned_u64 host_buf_addr;
			__aligned_u64 phys_addr;
		} out;
	};
};

#define RV_IOCTL_GPU_PIN_MMAP _IOWR(RV_MAGIC, 0xF5, struct rv_gpu_mem_params)

/*
 * GPU MR cache statistics are as follows:
 *   cache_size - Current memory in the cache in bytes
 *   max_cache_size - Maximum of cache_size in bytes
 *   limit_cache_size - Maximum allowed cache_size in MB
 *   count - Current number of MRs in the cache
 *   max_count - Maximum of count
 *   inuse - Current number of MRs in the cache with refcount > 0
 *   max_inuse - Maximum of inuse
 *   inuse_bytes - Current number of bytes in cache for MRs with refcount > 0
 *   max_inuse_bytes - Maximum of inuse_bytes
 *   max_refcount - Maximum of refcount for an MR
 *   The above are also counted for:
 *	reg - gdr_mr's just used for verbs MR
 *	mmap - gdr_mr's just used for mmap
 *	both - gdr_mr's used for both
 *	X = X_reg + X_mmap + X_both
 *   Event counts:
 *	hit - Cache hit
 *	miss - Cache miss and added
 *	full - Cache miss but can't add since full
 *	full_reg - Cache miss registering MR but can't add since full
 *	full_mmap - Cache miss on mmap but can't add since full,
 *		full = full_reg + full_mmap
 *	failed_pin - cache miss and failed to pin GPU pages
 *	failed_reg - failed to register MR (can be hit without MR or miss)
 *	failed_mmap - failed to mmap (can be hit without mmap or miss)
 *	hit_reg - cache hit registering an MR
 *	hit_add_reg - cache hit on pinned pages registering an MR, created MR
 *	hit_mmap - cache hit on mmap
 *	hit_add_mmap - cache hit on pinned pages on mmap, mmap'ed pages
 *	miss_reg - cache miss on registering an MR
 *	miss_mmap - cache miss on mmap
 *	remove - Refcount == 0 and removed by mmu notifier event or cache deinit
 *		reg, mmap and both subsets
 *	evict - Removed from cache due to lack of cache space
 *		reg, mmap and both subsets
 *   Number of valid calls to IOCTL_REG_MEM for GPU memory + IOCTL_GPU_PIN_MMAP
 *		= hit + miss + full + failed*
 *	(counts omit some EINVAL and EFAULT REG_MEM and PIN_MMAP use cases)
 *	hit = hit_reg + hit_add_reg + hit_mmap + hit_add_mmap
 *	miss = miss_reg + miss_mmap
 * For simplicity, a few GPU specific IO stats are included here:
 *	post_write - total successful post_rdma_write (CPU & GPU)
 *	post_write_bytes - total successful post_rdma_write (CPU & GPU)
 *	gpu_post_write - successful post_rdma_write for GPU source address
 *	gpu_post_write_bytes - for successful post for GPU source address
 */

struct rv_gpu_cache_stats_params_out {
	__aligned_u64 cache_size;
	__aligned_u64 cache_size_reg;
	__aligned_u64 cache_size_mmap;
	__aligned_u64 cache_size_both;
	__aligned_u64 max_cache_size;
	__aligned_u64 max_cache_size_reg;
	__aligned_u64 max_cache_size_mmap;
	__aligned_u64 max_cache_size_both;
	__u32 limit_cache_size;
	__u32 count;
	__u32 count_reg;
	__u32 count_mmap;
	__u32 count_both;
	__u32 max_count;
	__u32 max_count_reg;
	__u32 max_count_mmap;
	__u32 max_count_both;
	__u32 inuse;
	__u32 inuse_reg;
	__u32 inuse_mmap;
	__u32 inuse_both;
	__u32 max_inuse;
	__u32 max_inuse_reg;
	__u32 max_inuse_mmap;
	__u32 max_inuse_both;
	__u32 max_refcount;
	__u32 max_refcount_reg;
	__u32 max_refcount_mmap;
	__u32 max_refcount_both;
	__u32 pad;
	__aligned_u64 inuse_bytes;
	__aligned_u64 inuse_bytes_reg;
	__aligned_u64 inuse_bytes_mmap;
	__aligned_u64 inuse_bytes_both;
	__aligned_u64 max_inuse_bytes;
	__aligned_u64 max_inuse_bytes_reg;
	__aligned_u64 max_inuse_bytes_mmap;
	__aligned_u64 max_inuse_bytes_both;
	__aligned_u64 hit;
	__aligned_u64 hit_reg;
	__aligned_u64 hit_add_reg;
	__aligned_u64 hit_mmap;
	__aligned_u64 hit_add_mmap;
	__aligned_u64 miss;
	__aligned_u64 miss_reg;
	__aligned_u64 miss_mmap;
	__aligned_u64 full;
	__aligned_u64 full_reg;
	__aligned_u64 full_mmap;
	__aligned_u64 failed_pin;
	__aligned_u64 failed_reg;
	__aligned_u64 failed_mmap;
	__aligned_u64 remove;
	__aligned_u64 remove_reg;
	__aligned_u64 remove_mmap;
	__aligned_u64 remove_both;
	__aligned_u64 evict;
	__aligned_u64 evict_reg;
	__aligned_u64 evict_mmap;
	__aligned_u64 evict_both;
	__aligned_u64 inval_mr;
	__aligned_u64 post_write;
	__aligned_u64 post_write_bytes;
	__aligned_u64 gpu_post_write;
	__aligned_u64 gpu_post_write_bytes;
};

#define RV_IOCTL_GPU_GET_CACHE_STATS _IOR(RV_MAGIC, 0xEF, \
				      struct rv_gpu_cache_stats_params_out)

#endif /* NVIDIA_GPU_DIRECT*/

/*
 * handle - from create_conn
 * application source buffer and a kernel lkey for it
 *	loc_addr
 *	loc_mr_handle
 * local MR - selected by 3-tuple (addr, len, access)
 *	loc_mr_addr
 *	loc_mr_length
 *	loc_mr_access
 * remote application dest buffer and a kernel rkey for it
 *	rem_addr
 *	rkey
 * length
 * wr_id - application context, included in RV SQ completion events
 * immed
 */
struct rv_post_write_params_in {
	__aligned_u64 handle;
	__aligned_u64 loc_addr;
	__aligned_u64 loc_mr_handle;
	__aligned_u64 loc_mr_addr;
	__aligned_u64 loc_mr_length;
	__u32 loc_mr_access;
	__u32 rkey;
	__aligned_u64 rem_addr;
	__aligned_u64 length;
	__aligned_u64 wr_id;
	__u32 immed;
};

struct rv_post_write_params_out {
	__u8 sconn_index;
	__u32 conn_count;
};

struct rv_post_write_params {
	union {
		struct rv_post_write_params_in in;
		struct rv_post_write_params_out out;
	};
};

#define RV_IOCTL_POST_RDMA_WR_IMMED _IOWR(RV_MAGIC, 0xFB, \
					  struct rv_post_write_params)

enum rv_event_type {
	RV_WC_RDMA_WRITE,		/* send RDMA Write CQE */
	RV_WC_RECV_RDMA_WITH_IMM,	/* recv RDMA Write w/immed CQE */
};

/*
 * events placed on ring buffer for delivery to user space.
 * Carefully sized to be a multiple of 64 bytes for cache alignment.
 * Must pack to get good field alignment and desired 64B overall size
 * Unlike verbs, all rv_event fields are defined even when
 * rv_event.wc.status != IB_WC_SUCCESS. Only sent writes can report bad status.
 * event_type - enum rv_event_type
 * wc - send or recv work completions
 *	status - ib_wc_status
 *	resv1 - alignment
 *	imm_data - for RV_WC_RECV_RDMA_WITH_IMM only
 *	wr_id - PSM wr_id for RV_WC_RDMA_WRITE only
 *	conn_handle - conn handle. For efficiency in completion processing, this
 *		handle is the rv_conn handle, not the rv_user_conn.
 *		Main use is sanity checks.  On Recv PSM must use imm_data to
 *		efficiently identify source.
 *	byte_len - unlike verbs API, this is always valid
 *	resv2 - alignment
 * cache_align -  not used, but forces overall struct to 64B size
 */
struct rv_event {
	__u8		event_type;
	union {
		struct {
			__u8		status;
			__u16	resv1;
			__u32	imm_data;
			__aligned_u64	wr_id;
			__aligned_u64	conn_handle;
			__u32	byte_len;
			__u32	resv2;
		} __attribute__((__packed__)) wc;
		struct {
			__u8 pad[7];
			uint64_t pad2[7];
		} __attribute__((__packed__)) cache_align;
	};
} __attribute__((__packed__));

/*
 * head - consumer removes here
 * tail - producer adds here
 * overflow_cnt - number of times producer overflowed ring and discarded
 * pad - 64B cache alignment for entries
 */
struct rv_ring_header {
	volatile __u32 head;
	volatile __u32 tail;
	volatile __u64 overflow_cnt;
	__aligned_u64 pad[6];
	struct rv_event entries[];
};

#define RV_RING_ALLOC_LEN(num_entries) \
	((__u32)(((num_entries) * sizeof(struct rv_event)) + \
	       sizeof(struct rv_ring_header)))

#endif /* __RV_USER_IOCTL_H__ */
