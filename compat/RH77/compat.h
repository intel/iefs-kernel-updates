/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 */
#if !defined(RH77_COMPAT_H)
#define RH77_COMPAT_H

#define HAVE_IB_GID_ATTR
#define POST_HAS_CONST
#define CREATE_FLOW_HAS_UDATA
#define CREATE_AH_HAS_UDATA
#define HAVE_ALLOC_RDMA_NETDEV
#define HAVE_RDMA_NETDEV_GET_PARAMS

#include "compat_common.h"

#endif //RH77_COMPAT
