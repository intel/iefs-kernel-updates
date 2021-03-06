/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 */
#if !defined(RH83_COMPAT_H)
#define RH83_COMPAT_H

#define CREATE_AH_HAS_UDATA
#define HAVE_ALLOC_RDMA_NETDEV
#define CREATE_FLOW_HAS_UDATA
#define HAVE_IB_GID_ATTR
#define ADD_GID_HAS_GID
#define HAVE_RDMA_NETDEV_GET_PARAMS
#define HAVE_ENUM_IB_UVERBS_ADVISE_MR_ADVICE
#define HAVE_IB_DEVICE_OPS
#define POST_HAS_CONST
#define CREATE_AH_HAS_FLAGS
#define DESTROY_AH_HAS_FLAGS
#define DEALLOC_PD_HAS_UDATA
#define DESTROY_CQ_HAS_UDATA
#define DESTROY_QP_HAS_UDATA
#define DEREG_MR_HAS_UDATA
#define ALLOC_MR_HAS_UDATA
#define RDMA_LOOKUP_GET_UOBJECT_HAVE_ATTR
#define HAVE_MMU_NOTIFIER_RANGE
#define UVERBS_DEVICE_NO_EVENTS_FILE_LIST
#define HAVE_NEW_UVERBS_ASYNC_EVENT_FILE
#define UVERBS_FILE_HAVE_XARRAY_IDR
#define UVERBS_FILE_NO_IDR_LOCK
#define HAVE_ATOMIC_FETCH_ADD_UNLESS
#define TYPE_CLASS_NO_NEEDS_KFREE_RCU
#define HAVE_XARRAY

#include "compat_common.h"

#endif /* RH83_COMPAT_H */
