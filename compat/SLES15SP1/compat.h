/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 */
#if !defined(SLES15SP1_COMPAT_H)
#define SLES15SP1_COMPAT_H

#define CREATE_AH_HAS_UDATA
#define HAVE_ALLOC_RDMA_NETDEV
#define POST_HAS_CONST
#define HAVE_IB_GID_ATTR
#define CREATE_FLOW_HAS_UDATA
#define HAVE_RDMA_NETDEV_GET_PARAMS
#define NO_RB_ROOT_CACHE
#define UVERBS_FILE_NO_DISASSOCIATE_PAGE
#define UVERBS_FILE_HAVE_CMD_MASK
#define UVERBS_API_NO_WRITE_METHOD
#define UVERBS_ATTR_BUNDLE_NO_UDATA
#define NO_UVERBS_API_OBJECT

#include "compat_common.h"

#endif /* SLES15SP1_COMPAT_H */
