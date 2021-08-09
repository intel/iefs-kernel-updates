/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 */
#if !defined(COMPAT_COMMON_H)
#define COMPAT_COMMON_H

#include <linux/socket.h>
#include <net/ipv6.h>
#include <net/ip.h>
#include <linux/netdevice.h>
#include <linux/if_link.h>
#include <uapi/rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <linux/timer.h>
#ifdef HAVE_XARRAY
#include <linux/xarray.h>
#else
#include <linux/idr.h>
#endif

#include <rdma/ib_hdrs.h>
#include <linux/kref.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/cdev.h>

#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/uverbs_std_types.h>

#define UVERBS_MODULE_NAME ib_uverbs
#include <rdma/uverbs_named_ioctl.h>

#if !defined(RB_ROOT_CACHED)
#define rb_root_cached			rb_root
#define RB_ROOT_CACHED			RB_ROOT
#define rb_erase_cached(node, root)	rb_erase(node, root)
#define rb_first_cached(root)		rb_first(root)
#endif

#ifndef HAVE_ENUM_IB_UVERBS_ADVISE_MR_ADVICE
enum ib_uverbs_advise_mr_advice {
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH,
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE,
};
#endif

#ifndef HAVE_FALLTHROUGH
#define fallthrough                    do {} while (0)
#endif

#ifndef HAVE_IB_DEVICE_OPS

struct iw_cm_id;
struct iw_cm_conn_param;
struct uverbs_attr_bundle;
struct ib_flow_action_attrs_esp;
struct ib_dm_mr_attr;
struct ib_dm_alloc_attr;
struct ib_counters_read_attr;
struct rdma_netdev_alloc_params;
struct rdma_restrack_entry;

/**
 * struct ib_device_ops - InfiniBand device operations
 * This structure defines all the InfiniBand device operations, providers will
 * need to define the supported operations, otherwise they will be set to null.
 */
struct ib_device_ops {
#ifdef POST_HAS_CONST
	int (*post_send)(struct ib_qp *qp, const struct ib_send_wr *send_wr,
			 const struct ib_send_wr **bad_send_wr);
	int (*post_recv)(struct ib_qp *qp, const struct ib_recv_wr *recv_wr,
			 const struct ib_recv_wr **bad_recv_wr);
#else
	int (*post_send)(struct ib_qp *qp, struct ib_send_wr *send_wr,
			 struct ib_send_wr **bad_send_wr);
	int (*post_recv)(struct ib_qp *qp, struct ib_recv_wr *recv_wr,
			 struct ib_recv_wr **bad_recv_wr);
#endif
	void (*drain_rq)(struct ib_qp *qp);
	void (*drain_sq)(struct ib_qp *qp);
	int (*poll_cq)(struct ib_cq *cq, int num_entries, struct ib_wc *wc);
	int (*peek_cq)(struct ib_cq *cq, int wc_cnt);
	int (*req_notify_cq)(struct ib_cq *cq, enum ib_cq_notify_flags flags);
	int (*req_ncomp_notif)(struct ib_cq *cq, int wc_cnt);
#ifdef POST_HAS_CONST
	int (*post_srq_recv)(struct ib_srq *srq,
			     const struct ib_recv_wr *recv_wr,
			     const struct ib_recv_wr **bad_recv_wr);
#else
	int (*post_srq_recv)(struct ib_srq *srq,
			     struct ib_recv_wr *recv_wr,
			     struct ib_recv_wr **bad_recv_wr);
#endif
	int (*process_mad)(struct ib_device *device, int process_mad_flags,
			   u8 port_num, const struct ib_wc *in_wc,
			   const struct ib_grh *in_grh,
			   const struct ib_mad_hdr *in_mad, size_t in_mad_size,
			   struct ib_mad_hdr *out_mad, size_t *out_mad_size,
			   u16 *out_mad_pkey_index);
	int (*query_device)(struct ib_device *device,
			    struct ib_device_attr *device_attr,
			    struct ib_udata *udata);
	int (*modify_device)(struct ib_device *device, int device_modify_mask,
			     struct ib_device_modify *device_modify);
#ifdef GET_DEV_FW_STR_HAS_LEN
	void (*get_dev_fw_str)(struct ib_device *device, char *str,
			       size_t str_len);
#else
	void (*get_dev_fw_str)(struct ib_device *device, char *str);
#endif
#ifdef HAVE_GET_VECTOR_AFFINITY
	const struct cpumask *(*get_vector_affinity)(struct ib_device *ibdev,
						     int comp_vector);
#endif
	int (*query_port)(struct ib_device *device, u8 port_num,
			  struct ib_port_attr *port_attr);
	int (*modify_port)(struct ib_device *device, u8 port_num,
			   int port_modify_mask,
			   struct ib_port_modify *port_modify);
	/**
	 * The following mandatory functions are used only at device
	 * registration.  Keep functions such as these at the end of this
	 * structure to avoid cache line misses when accessing struct ib_device
	 * in fast paths.
	 */
	int (*get_port_immutable)(struct ib_device *device, u8 port_num,
				  struct ib_port_immutable *immutable);
	enum rdma_link_layer (*get_link_layer)(struct ib_device *device,
					       u8 port_num);
	/**
	 * When calling get_netdev, the HW vendor's driver should return the
	 * net device of device @device at port @port_num or NULL if such
	 * a net device doesn't exist. The vendor driver should call dev_hold
	 * on this net device. The HW vendor's device driver must guarantee
	 * that this function returns NULL before the net device has finished
	 * NETDEV_UNREGISTER state.
	 */
	struct net_device *(*get_netdev)(struct ib_device *device, u8 port_num);
	/**
	 * rdma netdev operation
	 *
	 * Driver implementing alloc_rdma_netdev or rdma_netdev_get_params
	 * must return -EOPNOTSUPP if it doesn't support the specified type.
	 */
#ifdef HAVE_ALLOC_RDMA_NETDEV
	struct net_device *(*alloc_rdma_netdev)(
		struct ib_device *device, u8 port_num, enum rdma_netdev_t type,
		const char *name, unsigned char name_assign_type,
		void (*setup)(struct net_device *));
#endif

#ifdef HAVE_RDMA_NETDEV_GET_PARAMS
	int (*rdma_netdev_get_params)(struct ib_device *device, u8 port_num,
				      enum rdma_netdev_t type,
				      struct rdma_netdev_alloc_params *params);
#endif
	/**
	 * query_gid should be return GID value for @device, when @port_num
	 * link layer is either IB or iWarp. It is no-op if @port_num port
	 * is RoCE link layer.
	 */
	int (*query_gid)(struct ib_device *device, u8 port_num, int index,
			 union ib_gid *gid);
	/**
	 * When calling add_gid, the HW vendor's driver should add the gid
	 * of device of port at gid index available at @attr. Meta-info of
	 * that gid (for example, the network device related to this gid) is
	 * available at @attr. @context allows the HW vendor driver to store
	 * extra information together with a GID entry. The HW vendor driver may
	 * allocate memory to contain this information and store it in @context
	 * when a new GID entry is written to. Params are consistent until the
	 * next call of add_gid or delete_gid. The function should return 0 on
	 * success or error otherwise. The function could be called
	 * concurrently for different ports. This function is only called when
	 * roce_gid_table is used.
	 */
#ifdef HAVE_IB_GID_ATTR
#ifdef ADD_GID_HAS_GID
	int (*add_gid)(const union ib_gid *gid,
		       const struct ib_gid_attr *attr,
		       void **context);
#else
	int (*add_gid)(const struct ib_gid_attr *attr, void **context);
#endif
#else
	int (*add_gid)(struct ib_device *device, u8 port_num,
		       unsigned int index, const union ib_gid *gid,
		       const struct ib_gid_attr *attr, void **context);
#endif
	/**
	 * When calling del_gid, the HW vendor's driver should delete the
	 * gid of device @device at gid index gid_index of port port_num
	 * available in @attr.
	 * Upon the deletion of a GID entry, the HW vendor must free any
	 * allocated memory. The caller will clear @context afterwards.
	 * This function is only called when roce_gid_table is used.
	 */
#ifdef HAVE_IB_GID_ATTR
	int (*del_gid)(const struct ib_gid_attr *attr, void **context);
#else
	int  (*del_gid)(struct ib_device *device, u8 port_num,
			unsigned int index,
			void **context);
#endif
	int (*query_pkey)(struct ib_device *device, u8 port_num, u16 index,
			  u16 *pkey);
#ifdef ALLOC_UCONTEXT_RETURNS_INT
	int (*alloc_ucontext)(struct ib_ucontext *context,
			      struct ib_udata *udata);
#else
	struct ib_ucontext *(*alloc_ucontext)(struct ib_device *ibdev,
					      struct ib_udata *udata);
#endif
#ifdef DEALLOC_UCONTEXT_RETURNS_VOID
	void (*dealloc_ucontext)(struct ib_ucontext *context);
#else
	int (*dealloc_ucontext)(struct ib_ucontext *context);
#endif
	int (*mmap)(struct ib_ucontext *context, struct vm_area_struct *vma);
	void (*disassociate_ucontext)(struct ib_ucontext *ibcontext);
#ifdef ALLOC_PD_RETURN_INT
	int (*alloc_pd)(struct ib_pd *pd, struct ib_udata *udata);
#else
	struct ib_pd *(*alloc_pd)(struct ib_device *ibdev,
				  struct ib_ucontext *context,
				  struct ib_udata *udata);
#endif
#ifdef DEALLOC_PD_HAS_UDATA
	void (*dealloc_pd)(struct ib_pd *pd, struct ib_udata *udata);
#else
	int (*dealloc_pd)(struct ib_pd *pd);
#endif
#ifdef CREATE_AH_HAS_INIT_ATTR
	int (*create_ah)(struct ib_ah *ah, struct rdma_ah_init_attr *attr,
			 struct ib_udata *udata);
#elif defined(CREATE_AH_RETURNS_INT)
	int (*create_ah)(struct ib_ah *ah, struct rdma_ah_attr *ah_attr,
			 u32 flags, struct ib_udata *udata);
#elif defined(CREATE_AH_HAS_FLAGS)
	struct ib_ah *(*create_ah)(struct ib_pd *pd,
				   struct rdma_ah_attr *ah_attr,
				   u32 create_flags,
				   struct ib_udata *udata);
#elif defined(CREATE_AH_HAS_UDATA)
	struct ib_ah *(*create_ah)(struct ib_pd *pd,
				   struct rdma_ah_attr *ah_attr,
				   struct ib_udata *udata);
#else
	struct ib_ah *(*create_ah)(struct ib_pd *pd,
				   struct rdma_ah_attr *ah_attr);
#endif
	int (*modify_ah)(struct ib_ah *ah, struct rdma_ah_attr *ah_attr);
	int (*query_ah)(struct ib_ah *ah, struct rdma_ah_attr *ah_attr);
#ifdef DESTROY_AH_RETURNS_VOID
	void (*destroy_ah)(struct ib_ah *ah, u32 flags);
#elif defined(DESTROY_AH_HAS_FLAGS)
	int (*destroy_ah)(struct ib_ah *ah, u32 flags);
#else
	int (*destroy_ah)(struct ib_ah *ah);
#endif
#ifdef CREATE_SRQ_RETURNS_INT
	int (*create_srq)(struct ib_srq *srq,
			  struct ib_srq_init_attr *srq_init_attr,
			  struct ib_udata *udata);
#else
	struct ib_srq *(*create_srq)(struct ib_pd *ibpd,
				     struct ib_srq_init_attr *srq_init_attr,
		 		     struct ib_udata *udata);
#endif
	int (*modify_srq)(struct ib_srq *srq, struct ib_srq_attr *srq_attr,
			  enum ib_srq_attr_mask srq_attr_mask,
			  struct ib_udata *udata);
	int (*query_srq)(struct ib_srq *srq, struct ib_srq_attr *srq_attr);
#ifdef DESTROY_SRQ_HAS_UDATA
	void (*destroy_srq)(struct ib_srq *srq, struct ib_udata *udata);
#else
	int (*destroy_srq)(struct ib_srq *srq);
#endif
	struct ib_qp *(*create_qp)(struct ib_pd *pd,
				   struct ib_qp_init_attr *qp_init_attr,
				   struct ib_udata *udata);
	int (*modify_qp)(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
			 int qp_attr_mask, struct ib_udata *udata);
	int (*query_qp)(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
			int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr);
#ifdef DESTROY_QP_HAS_UDATA
	int (*destroy_qp)(struct ib_qp *qp, struct ib_udata *udata);
#else
	int (*destroy_qp)(struct ib_qp *qp);
#endif
#ifdef CREATE_CQ_LACKS_CONTEXT
	struct ib_cq *(*create_cq)(struct ib_device *device,
				   const struct ib_cq_init_attr *attr,
				   struct ib_udata *udata);
#else
	struct ib_cq *(*create_cq)(struct ib_device *device,
				   const struct ib_cq_init_attr *attr,
				   struct ib_ucontext *context,
				   struct ib_udata *udata);
#endif
	int (*modify_cq)(struct ib_cq *cq, u16 cq_count, u16 cq_period);
#ifdef DESTROY_CQ_HAS_UDATA
	int (*destroy_cq)(struct ib_cq *cq, struct ib_udata *udata);
#else
	int (*destroy_cq)(struct ib_cq *cq);
#endif
	int (*resize_cq)(struct ib_cq *cq, int cqe, struct ib_udata *udata);
	struct ib_mr *(*get_dma_mr)(struct ib_pd *pd, int mr_access_flags);
	struct ib_mr *(*reg_user_mr)(struct ib_pd *pd, u64 start, u64 length,
				     u64 virt_addr, int mr_access_flags,
				     struct ib_udata *udata);
	int (*rereg_user_mr)(struct ib_mr *mr, int flags, u64 start, u64 length,
			     u64 virt_addr, int mr_access_flags,
			     struct ib_pd *pd, struct ib_udata *udata);
#ifdef DEREG_MR_HAS_UDATA
	int (*dereg_mr)(struct ib_mr *mr, struct ib_udata *udata);
#else
	int (*dereg_mr)(struct ib_mr *mr);
#endif
#ifdef ALLOC_MR_HAS_UDATA
	struct ib_mr *(*alloc_mr)(struct ib_pd *pd, enum ib_mr_type mr_type,
				  u32 max_num_sg, struct ib_udata *udata);
#else
	struct ib_mr *(*alloc_mr)(struct ib_pd *pd, enum ib_mr_type mr_type,
				  u32 max_num_sg);
#endif
	int (*advise_mr)(struct ib_pd *pd,
			 enum ib_uverbs_advise_mr_advice advice, u32 flags,
			 struct ib_sge *sg_list, u32 num_sge,
			 struct uverbs_attr_bundle *attrs);
	int (*map_mr_sg)(struct ib_mr *mr, struct scatterlist *sg, int sg_nents,
			 unsigned int *sg_offset);
	int (*check_mr_status)(struct ib_mr *mr, u32 check_mask,
			       struct ib_mr_status *mr_status);
	struct ib_mw *(*alloc_mw)(struct ib_pd *pd, enum ib_mw_type type,
				  struct ib_udata *udata);
	int (*dealloc_mw)(struct ib_mw *mw);
	struct ib_fmr *(*alloc_fmr)(struct ib_pd *pd, int mr_access_flags,
				    struct ib_fmr_attr *fmr_attr);
	int (*map_phys_fmr)(struct ib_fmr *fmr, u64 *page_list, int list_len,
			    u64 iova);
	int (*unmap_fmr)(struct list_head *fmr_list);
	int (*dealloc_fmr)(struct ib_fmr *fmr);
	int (*attach_mcast)(struct ib_qp *qp, union ib_gid *gid, u16 lid);
	int (*detach_mcast)(struct ib_qp *qp, union ib_gid *gid, u16 lid);
#ifdef HAVE_ALLOC_XRCD
	struct ib_xrcd *(*alloc_xrcd)(struct ib_device *device,
				      struct ib_udata *udata);
#ifdef DEALLOC_XRCD_HAS_UDATA
	int (*dealloc_xrcd)(struct ib_xrcd *xrcd, struct ib_udata *udata);
#else
	int (*dealloc_xrcd)(struct ib_xrcd *xrcd);
#endif
#endif
#ifdef CREATE_FLOW_HAS_UDATA
	struct ib_flow *(*create_flow)(struct ib_qp *qp,
				       struct ib_flow_attr *flow_attr,
				       int domain, struct ib_udata *udata);
#else
	struct ib_flow *(*create_flow)(struct ib_qp *qp,
				       struct ib_flow_attr *flow_attr,
				       int domain);
#endif
	int (*destroy_flow)(struct ib_flow *flow_id);
	struct ib_flow_action *(*create_flow_action_esp)(
		struct ib_device *device,
		const struct ib_flow_action_attrs_esp *attr,
		struct uverbs_attr_bundle *attrs);
	int (*destroy_flow_action)(struct ib_flow_action *action);
	int (*modify_flow_action_esp)(
		struct ib_flow_action *action,
		const struct ib_flow_action_attrs_esp *attr,
		struct uverbs_attr_bundle *attrs);
	int (*set_vf_link_state)(struct ib_device *device, int vf, u8 port,
				 int state);
	int (*get_vf_config)(struct ib_device *device, int vf, u8 port,
			     struct ifla_vf_info *ivf);
	int (*get_vf_stats)(struct ib_device *device, int vf, u8 port,
			    struct ifla_vf_stats *stats);
	int (*set_vf_guid)(struct ib_device *device, int vf, u8 port, u64 guid,
			   int type);
	struct ib_wq *(*create_wq)(struct ib_pd *pd,
				   struct ib_wq_init_attr *init_attr,
				   struct ib_udata *udata);
#ifdef DESTROY_WQ_HAS_UDATA
	int (*destroy_wq)(struct ib_wq *wq, struct ib_udata *udata);
#else
	int (*destroy_wq)(struct ib_wq *wq);
#endif
	int (*modify_wq)(struct ib_wq *wq, struct ib_wq_attr *attr,
			 u32 wq_attr_mask, struct ib_udata *udata);
	struct ib_rwq_ind_table *(*create_rwq_ind_table)(
		struct ib_device *device,
		struct ib_rwq_ind_table_init_attr *init_attr,
		struct ib_udata *udata);
	int (*destroy_rwq_ind_table)(struct ib_rwq_ind_table *wq_ind_table);
	struct ib_dm *(*alloc_dm)(struct ib_device *device,
				  struct ib_ucontext *context,
				  struct ib_dm_alloc_attr *attr,
				  struct uverbs_attr_bundle *attrs);
	int (*dealloc_dm)(struct ib_dm *dm, struct uverbs_attr_bundle *attrs);
	struct ib_mr *(*reg_dm_mr)(struct ib_pd *pd, struct ib_dm *dm,
				   struct ib_dm_mr_attr *attr,
				   struct uverbs_attr_bundle *attrs);
	struct ib_counters *(*create_counters)(
		struct ib_device *device, struct uverbs_attr_bundle *attrs);
	int (*destroy_counters)(struct ib_counters *counters);
	int (*read_counters)(struct ib_counters *counters,
			     struct ib_counters_read_attr *counters_read_attr,
			     struct uverbs_attr_bundle *attrs);
	/**
	 * alloc_hw_stats - Allocate a struct rdma_hw_stats and fill in the
	 *   driver initialized data.  The struct is kfree()'ed by the sysfs
	 *   core when the device is removed.  A lifespan of -1 in the return
	 *   struct tells the core to set a default lifespan.
	 */
	struct rdma_hw_stats *(*alloc_hw_stats)(struct ib_device *device,
						u8 port_num);
	/**
	 * get_hw_stats - Fill in the counter value(s) in the stats struct.
	 * @index - The index in the value array we wish to have updated, or
	 *   num_counters if we want all stats updated
	 * Return codes -
	 *   < 0 - Error, no counters updated
	 *   index - Updated the single counter pointed to by index
	 *   num_counters - Updated all counters (will reset the timestamp
	 *     and prevent further calls for lifespan milliseconds)
	 * Drivers are allowed to update all counters in leiu of just the
	 *   one given in index at their option
	 */
	int (*get_hw_stats)(struct ib_device *device,
			    struct rdma_hw_stats *stats, u8 port, int index);
	/*
	 * This function is called once for each port when a ib device is
	 * registered.
	 */
	int (*init_port)(struct ib_device *device, u8 port_num,
			 struct kobject *port_sysfs);
	/**
	 * Allows rdma drivers to add their own restrack attributes.
	 */
	int (*fill_res_entry)(struct sk_buff *msg,
			      struct rdma_restrack_entry *entry);

	/* Device lifecycle callbacks */
	/*
	 * Called after the device becomes registered, before clients are
	 * attached
	 */
	int (*enable_driver)(struct ib_device *dev);
	/*
	 * This is called as part of ib_dealloc_device().
	 */
	void (*dealloc_driver)(struct ib_device *dev);

	/* iWarp CM callbacks */
	void (*iw_add_ref)(struct ib_qp *qp);
	void (*iw_rem_ref)(struct ib_qp *qp);
	struct ib_qp *(*iw_get_qp)(struct ib_device *device, int qpn);
	int (*iw_connect)(struct iw_cm_id *cm_id,
			  struct iw_cm_conn_param *conn_param);
	int (*iw_accept)(struct iw_cm_id *cm_id,
			 struct iw_cm_conn_param *conn_param);
	int (*iw_reject)(struct iw_cm_id *cm_id, const void *pdata,
			 u8 pdata_len);
	int (*iw_create_listen)(struct iw_cm_id *cm_id, int backlog);
	int (*iw_destroy_listen)(struct iw_cm_id *cm_id);

};
#endif

#ifndef HAVE_MMU_NOTIFIER_RANGE
struct mmu_notifier_range {
	struct mm_struct *mm;
	unsigned long start;
	unsigned long end;
};
#endif

#ifndef UVERBS_IDR_ANY_OBJECT
#define UVERBS_IDR_ANY_OBJECT 0xFFFF
#endif

/* From: drivers/infiniband/core/uverbs.h */

struct ib_uverbs_device {
	atomic_t				refcount;
	int					num_comp_vectors;
	struct completion			comp;
	struct device				dev;
	/* First group for device attributes, NULL terminated array */
	const struct attribute_group		*groups[2];
	struct ib_device	__rcu	       *ib_dev;
	int					devnum;
	struct cdev			        cdev;
	struct rb_root				xrcd_tree;
	struct mutex				xrcd_tree_mutex;
	struct srcu_struct			disassociate_srcu;
	struct mutex				lists_mutex; /* protect lists */
	struct list_head			uverbs_file_list;
#ifndef UVERBS_DEVICE_NO_EVENTS_FILE_LIST
	struct list_head			uverbs_events_file_list;
#endif
	struct uverbs_api			*uapi;
};

struct ib_uverbs_event_queue {
	spinlock_t				lock;
	int					is_closed;
	wait_queue_head_t			poll_wait;
	struct fasync_struct		       *async_queue;
	struct list_head			event_list;
};

#ifndef HAVE_NEW_UVERBS_ASYNC_EVENT_FILE
struct ib_uverbs_async_event_file {
	struct ib_uverbs_event_queue		ev_queue;
	struct ib_uverbs_file		       *uverbs_file;
	struct kref				ref;
	struct list_head			list;
};
#else
struct ib_uverbs_async_event_file {
	struct ib_uobject                       uobj;
	struct ib_uverbs_event_queue            ev_queue;
	struct ib_event_handler                 event_handler;
};
#endif

struct ib_uverbs_file {
	struct kref				ref;
	struct ib_uverbs_device		       *device;
	struct mutex				ucontext_lock;
	/*
	 * ucontext must be accessed via ib_uverbs_get_ucontext() or with
	 * ucontext_lock held
	 */
	struct ib_ucontext		       *ucontext;
#ifndef UVERBS_FILE_NO_EVENT_HANDLER
	struct ib_event_handler			event_handler;
#endif
#ifdef UVERBS_FILE_HAS_DEFAULT_ASYNC_FILE
	struct ib_uverbs_async_event_file       *default_async_file;
#else
	struct ib_uverbs_async_event_file       *async_file;
#endif
	struct list_head			list;

	/*
	 * To access the uobjects list hw_destroy_rwsem must be held for write
	 * OR hw_destroy_rwsem held for read AND uobjects_lock held.
	 * hw_destroy_rwsem should be called across any destruction of the HW
	 * object of an associated uobject.
	 */
	struct rw_semaphore	hw_destroy_rwsem;
	spinlock_t		uobjects_lock;
	struct list_head	uobjects;

	struct mutex umap_lock;
	struct list_head umaps;
#ifndef UVERBS_FILE_NO_DISASSOCIATE_PAGE
	struct page *disassociate_page;
#endif

#ifdef UVERBS_FILE_HAVE_CMD_MASK
	u64 uverbs_cmd_mask;
	u64 uverbs_ex_cmd_mask;

#endif

#ifdef UVERBS_FILE_HAVE_XARRAY_IDR
	struct xarray		idr;
#else
	struct idr		idr;
#endif
	/* spinlock protects write access to idr */
#ifndef UVERBS_FILE_NO_IDR_LOCK
	spinlock_t		idr_lock;
#endif
};

/* NOTE THIS PART EXTRACTED FROM rdma_core.h */
#ifndef UVERBS_API_NO_WRITE_METHOD
struct uverbs_api_write_method {
	int (*handler)(struct uverbs_attr_bundle *attrs);
	u8 disabled:1;
	u8 is_ex:1;
	u8 has_udata:1;
	u8 has_resp:1;
	u8 req_size;
	u8 resp_size;
};
#endif

/*
 * Original source file:
 * include/rdma/uverbs_std_types.h: rhel 7.9/8.1/8.2/8.3/8.4, sles 15.2/15.3
 * drivers/infiniband/core/rdma_core.h: sles15.1,
 */
#ifdef NO_UVERBS_API_OBJECT
struct uverbs_api_object {
	const struct uverbs_obj_type *type_attrs;
	const struct uverbs_obj_type_class *type_class;
};
#endif

/* From drivers/infiniband/core/rdma_core.h */
struct uverbs_api {
	/* radix tree contains struct uverbs_api_* pointers */
	struct radix_tree_root radix;
	enum rdma_driver_id driver_id;

#ifndef UVERBS_API_NO_WRITE_METHOD
	unsigned int num_write;
	unsigned int num_write_ex;
	struct uverbs_api_write_method notsupp_method;
	const struct uverbs_api_write_method **write_methods;
	const struct uverbs_api_write_method **write_ex_methods;
#endif
};

/*
 * Get an uverbs_api_object that corresponds to the given object_id.
 * Note:
 * -ENOMSG means that any object is allowed to match during lookup.
 */
static inline const struct uverbs_api_object *
uapi_get_object(struct uverbs_api *uapi, u16 object_id)
{
    const struct uverbs_api_object *res;

    if (object_id == UVERBS_IDR_ANY_OBJECT)
        return ERR_PTR(-ENOMSG);

    res = radix_tree_lookup(&uapi->radix, uapi_key_obj(object_id));
    if (!res)
        return ERR_PTR(-ENOENT);

    return res;
}

struct ib_uobject *rdma_lookup_get_uobject(const struct uverbs_api_object *obj,
                                           struct ib_uverbs_file *ufile, s64 id,
#ifndef RDMA_LOOKUP_GET_UOBJECT_HAVE_ATTR
                                           enum rdma_lookup_mode mode);
#else
					   enum rdma_lookup_mode mode,
					   struct uverbs_attr_bundle *attrs);
#endif

void rdma_lookup_put_uobject(struct ib_uobject *uobj,
                             enum rdma_lookup_mode mode);

#ifndef HAVE_XARRAY
struct xarray {
	struct idr table;
	spinlock_t lock;
};

typedef unsigned __bitwise xa_mark_t;
#define XA_PRESENT		((__force xa_mark_t)8U)

struct xa_limit {
	u32 max;
	u32 min;
};

#define XA_LIMIT(_min, _max) (struct xa_limit) { .min = _min, .max = _max }

#define xa_limit_32b    XA_LIMIT(0, UINT_MAX)

int xa_alloc_irq(struct xarray *xa, u32 *id, void *entry,
		 struct xa_limit limit, gfp_t gfp);

#undef xa_lock_irq
#undef xa_unlock_irq
#undef xa_lock_irqsave
#undef xa_unlock_irqrestore
#define xa_lock_irq(xa)		spin_lock_irq(&(xa)->lock)
#define xa_unlock_irq(xa)	spin_unlock_irq(&(xa)->lock)
#define xa_lock_irqsave(xa, flags)	spin_lock_irqsave(&(xa)->lock, flags)
#define xa_unlock_irqrestore(xa, flags)	spin_unlock_irqrestore(&(xa)->lock, flags)
#undef xa_alloc
#define xa_alloc(xa, id, entry, limit, gfp) xa_alloc_irq(xa, id, entry, limit, gfp)

#define XA_FLAGS_ALLOC 0
#define XA_FLAGS_LOCK_IRQ 0
#ifndef IDR_INIT_HAVE_NONAME
#define XARRAY_INIT(name, flags) {		\
	.lock = __SPIN_LOCK_UNLOCKED(name.lock),\
	.table = IDR_INIT(name.table)		\
}
#else
#define XARRAY_INIT(name, flags) {		\
	.lock = __SPIN_LOCK_UNLOCKED(name.lock),\
	.table = IDR_INIT			\
}
#endif

#define DEFINE_XARRAY_FLAGS(name, flags)	\
	struct xarray name = XARRAY_INIT(name, flags)

static inline void xa_init(struct xarray *xa)
{
	idr_init(&xa->table);
	spin_lock_init(&xa->lock);
}

#undef xa_init_flags
#define xa_init_flags(xa, flags) xa_init(xa)

struct xa_state {
	struct xarray *xa;
	unsigned int index;
};

#undef XA_STATE
#define XA_STATE(name, array, index)		\
	struct xa_state name = { .xa = array };			\

/* subtle differences in locking, but rv uses rv->lock to protect so ok */
#undef xas_for_each
#define xas_for_each(xas, entry, max)		\
	idr_for_each_entry(&(xas)->xa->table, entry, ((xas)->index))

static inline void *xas_store(struct xa_state *xas, void *entry)
{
	void *old_entry;

	spin_lock(&xas->xa->lock);
	if (entry == NULL) {
#ifdef IDR_REMOVE_NO_RETURN
		old_entry = idr_find(&xas->xa->table, xas->index);
		idr_remove(&xas->xa->table, xas->index);
#else
		old_entry = idr_remove(&xas->xa->table, xas->index);
#endif
	} else {
		old_entry = idr_replace(&xas->xa->table, entry, xas->index);
	}
	spin_unlock(&xas->xa->lock);
	return old_entry;
}

static inline int xa_insert(struct xarray *xa, unsigned long index,
			    void *entry, gfp_t gfp)
{
	int rc;

	spin_lock(&xa->lock);
	rc = idr_alloc(&xa->table, entry, index, index + 1, gfp);
	spin_unlock(&xa->lock);
	return rc;
}

static inline void *xa_erase(struct xarray *xa, unsigned long index)
{
	spin_lock(&xa->lock);
	idr_remove(&xa->table, index);
	spin_unlock(&xa->lock);
	return NULL;
}

static inline void *xa_load(struct xarray *xa, unsigned long index)
{
	void *p;

	rcu_read_lock();
	p = idr_find(&xa->table, index);
	rcu_read_unlock();
	return p;
}

static inline void *xa_find(struct xarray *xa, unsigned long *index,
			    unsigned long max, xa_mark_t filter)
{
	return idr_get_next(&xa->table, (int *)index);
}

static inline void xa_destroy(struct xarray *xa)
{
	idr_destroy(&xa->table);
}

#define __xa_erase(xa, index) idr_remove(&(xa)->table, index)

#define xa_for_each(xa, id, entry)	\
	for (id = 0;			\
	     ((entry) = idr_get_next(&(xa)->table, (int *)&(id))) != NULL; \
	     ++id)

#endif  /* !defined(HAVE_XARRAY) */

#endif /* !defined(COMPAT_COMMON_H) */
