/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 */
#if !defined(RH82_COMPAT_H)
#define RH82_COMPAT_H

/*
 * The reason that we add this header here is to have
 * the define LINUX_EFI_MOK_VARIABLE_TABLE_GUID that came
 * with the 4.18.0-193.28.1.el8_2 update, which also
 * renamed __atomic_add_unless as atomic_fetch_add_unless, so
 * that we can support both RHEL 8.2 GA and the latest kernel
 * update.
 */
#include <linux/efi.h>

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
#define HAVE_XARRAY
#ifdef LINUX_EFI_MOK_VARIABLE_TABLE_GUID
#define HAVE_ATOMIC_FETCH_ADD_UNLESS
#endif
#define IB_UMEM_GET_WITH_UDATA
#define IB_UMEM_GET_WITH_UDATA_DMASYNC

#include "compat_common.h"

#endif /* RH82_COMPAT_H */
