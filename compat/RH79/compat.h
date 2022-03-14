/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2021 Intel Corporation.
 */
#if !defined(RH79_COMPAT_H)
#define RH79_COMPAT_H

#define CREATE_AH_HAS_UDATA
#define HAVE_IB_GID_ATTR
#define POST_HAS_CONST
#define CREATE_FLOW_HAS_UDATA
#define HAVE_ALLOC_RDMA_NETDEV
#define HAVE_RDMA_NETDEV_GET_PARAMS
#define HAVE_NEW_UVERBS_ASYNC_EVENT_FILE
#define UVERBS_FILE_NO_DISASSOCIATE_PAGE
#undef	CONFIG_EVENT_TRACING
#define IDR_REMOVE_NO_RETURN

#include "compat_common.h"

#endif /* RH79_COMPAT_H */
