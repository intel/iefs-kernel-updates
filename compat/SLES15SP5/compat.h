/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2022 Intel Corporation.
 */
#if !defined(SLES15SP5_COMPAT_H)
#define SLES15SP5_COMPAT_H

#define HAVE_FALLTHROUGH
#define HAVE_ENUM_IB_UVERBS_ADVISE_MR_ADVICE
#define IB_CLIENT_ADD_RETURN_INT
#define HAVE_IB_DEVICE_OPS
#define DEREG_MR_HAS_UDATA
#define HAVE_MMU_NOTIFIER_RANGE
#define MMU_NOTIFIER_RANGE_START_USES_MMU_NOTIFIER_RANGE
#define UVERBS_DEVICE_NO_EVENTS_FILE_LIST
#define HAVE_NEW_UVERBS_ASYNC_EVENT_FILE
#define UVERBS_FILE_NO_EVENT_HANDLER
#define UVERBS_FILE_HAS_DEFAULT_ASYNC_FILE
#define UVERBS_FILE_HAVE_XARRAY_IDR
#define UVERBS_FILE_NO_IDR_LOCK
#define RDMA_LOOKUP_GET_UOBJECT_HAVE_ATTR
#define HAVE_ATOMIC_FETCH_ADD_UNLESS
#define TYPE_CLASS_NO_NEEDS_KFREE_RCU
#define HAVE_XARRAY
#define IB_UMEM_GET_WITH_DEVICE
#define IB_UMEM_HAS_NO_NMAP

#include "compat_common.h"

#endif /* SLES15SP5_COMPAT_H */