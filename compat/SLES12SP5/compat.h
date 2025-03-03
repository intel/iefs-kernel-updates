/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 */
#if !defined(SLES12SP5_COMPAT_H)
#define SLES12SP5_COMPAT_H

#define CREATE_AH_HAS_UDATA
#define HAVE_ALLOC_RDMA_NETDEV
#define POST_HAS_CONST
#define CREATE_FLOW_HAS_UDATA
#define HAVE_IB_GID_ATTR
#define HAVE_RDMA_NETDEV_GET_PARAMS
#define NO_RB_ROOT_CACHE

#include "compat_common.h"

#endif //SLES12SP5_COMPAT
