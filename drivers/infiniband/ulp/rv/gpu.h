/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 */

#ifndef _GPU_H
#define _GPU_H

#ifdef NVIDIA_GPU_DIRECT
#include "nv-p2p.h"

#define NV_GPU_PAGE_SHIFT 16
#define NV_GPU_PAGE_SIZE BIT(NV_GPU_PAGE_SHIFT)
#define NV_GPU_PAGE_MASK (~(NV_GPU_PAGE_SIZE - 1))

#define GPU_PAGE_TO_PFN(page) (page->physical_address >> NV_GPU_PAGE_SHIFT)

#define GPU_PAGE_SIZE NV_GPU_PAGE_SIZE
#define GPU_PAGE_MASK NV_GPU_PAGE_MASK

static inline void put_gpu_pages(u64 vaddr,
				 struct nvidia_p2p_page_table *page_table)
{
	nvidia_p2p_put_pages(0, 0, vaddr, page_table);
}

static inline int get_gpu_pages(u64 vaddr, u64 len,
				struct nvidia_p2p_page_table **page_table_ptr,
				void (*free_callback)(void *data), void *data)
{
	/* start address must be GPU page aligned */
	len += vaddr & ~NV_GPU_PAGE_MASK;
	vaddr &= NV_GPU_PAGE_MASK;

	return nvidia_p2p_get_pages(0, 0, vaddr, len, page_table_ptr,
				    free_callback, data);
}

static inline void free_gpu_page_table(struct nvidia_p2p_page_table *page_table)
{
	nvidia_p2p_free_page_table(page_table);
}

static inline int num_user_pages_gpu(u64 addr, u64 len)
{
	const u64 spage = addr & NV_GPU_PAGE_MASK;
	const u64 epage = (addr + len - 1) & NV_GPU_PAGE_MASK;

	return 1 + ((epage - spage) >> NV_GPU_PAGE_SHIFT);
}
#elif defined(INTEL_GPU_DIRECT)
#include <linux/dma-buf.h>
#include <linux/dma-resv.h>

#ifdef MODULE_IMPORT_NS_DMA_BUF_FOR_INTEL_GPU_DIRECT
MODULE_IMPORT_NS(DMA_BUF);
#endif

#define INTEL_GPU_PAGE_SHIFT 12
#define INTEL_GPU_PAGE_SIZE BIT(INTEL_GPU_PAGE_SHIFT)
#define INTEL_GPU_PAGE_MASK (~(INTEL_GPU_PAGE_SIZE - 1))

#define GPU_PAGE_SIZE INTEL_GPU_PAGE_SIZE
#define GPU_PAGE_MASK INTEL_GPU_PAGE_MASK

#endif /* NVIDIA_GPU_DIRECT else INTEL_GPU_DIRECT */

#endif /* _GPU_H */
