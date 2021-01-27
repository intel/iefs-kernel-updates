// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 Intel Corporation.
 */

#include <linux/pci.h>
#include <linux/types.h>
#include <linux/module.h>
#include "gpu.h"

unsigned long gpu_cache_size = 256;
module_param(gpu_cache_size, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(gpu_cache_size, "Send and receive side GPU buffers cache size limit (in MB)");

int pin_gpu_pages(unsigned long vaddr, unsigned long len,
		  struct nvidia_p2p_page_table **page_table_ptr,
		  void (*free_callback)(void *data), void *data)
{
	int ret;
	struct nvidia_p2p_page_table *page_table;

	ret = get_gpu_pages(vaddr, len, page_table_ptr, free_callback, data);
	if (!ret) {
		page_table = *page_table_ptr;
		/* Current code supports only 64KB GPU memory page size */
		if (page_table->page_size != NVIDIA_P2P_PAGE_SIZE_64KB) {
			put_gpu_pages(vaddr, page_table);
			return -EOPNOTSUPP;
		}
#ifdef NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE
		if (!NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE(page_table)) {
			put_gpu_pages(vaddr, page_table);
			return -EOPNOTSUPP;
		}
#endif
	}
	return ret;
}
