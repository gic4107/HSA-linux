/*
 * Copyright 2014 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Andrew Lewycky
 *          Oded Gabbay
 */

/*
 * radeon_kfd.h defines the private interface between the
 * AMD kernel graphics drivers and the AMD radeon KFD.
 */

#ifndef RADEON_KFD_H_INCLUDED
#define RADEON_KFD_H_INCLUDED

#include <linux/types.h>
struct pci_dev;

#define KFD_INTERFACE_VERSION 1

struct kfd_dev;
struct kgd_dev;

struct kgd_mem;

enum kgd_memory_pool {
	KGD_POOL_SYSTEM_CACHEABLE = 1,
	KGD_POOL_SYSTEM_WRITECOMBINE = 2,
	KGD_POOL_FRAMEBUFFER = 3,
};

struct kgd2kfd_shared_resources {
	void __iomem *mmio_registers; /* Mapped pointer to GFX MMIO registers. */

	unsigned int compute_vmid_bitmap; /* Bit n == 1 means VMID n is available for KFD. */

	unsigned int first_compute_pipe; /* Compute pipes are counted starting from MEC0/pipe0 as 0. */
	unsigned int compute_pipe_count; /* Number of MEC pipes available for KFD. */

	phys_addr_t doorbell_physical_address; /* Base address of doorbell aperture. */
	size_t doorbell_aperture_size; /* Size in bytes of doorbell aperture. */
	size_t doorbell_start_offset; /* Number of bytes at start of aperture reserved for KGD. */
};

struct kgd2kfd_calls {
	void (*exit)(void);
	struct kfd_dev* (*probe)(struct kgd_dev* kgd, struct pci_dev* pdev);
	bool (*device_init)(struct kfd_dev* kfd, const struct kgd2kfd_shared_resources* gpu_resources);
	void (*device_exit)(struct kfd_dev* kfd);
	void (*interrupt)(struct kfd_dev* kfd, const void *ih_ring_entry);
	void (*suspend)(struct kfd_dev* kfd);
	int (*resume)(struct kfd_dev* kfd);
};

struct kfd2kgd_calls {
	/* Memory management. */
	int (*allocate_mem)(struct kgd_dev *kgd, size_t size, size_t alignment, enum kgd_memory_pool pool, struct kgd_mem **memory_handle);
	void (*free_mem)(struct kgd_dev *kgd, struct kgd_mem *memory_handle);

	int (*gpumap_mem)(struct kgd_dev *kgd, struct kgd_mem *mem, uint64_t *vmid0_address);
	void (*ungpumap_mem)(struct kgd_dev *kgd, struct kgd_mem *mem);

	int (*kmap_mem)(struct kgd_dev *kgd, struct kgd_mem *mem, void **ptr);
	void (*unkmap_mem)(struct kgd_dev *kgd, struct kgd_mem *mem);

	uint64_t (*get_vmem_size)(struct kgd_dev *kgd);
	uint64_t (*get_gpu_clock_counter)(struct kgd_dev *kgd);

	/* SRBM_GFX_CNTL mutex */
	void (*lock_srbm_gfx_cntl)(struct kgd_dev *kgd);
	void (*unlock_srbm_gfx_cntl)(struct kgd_dev *kgd);

	/* GRBM_GFX_INDEX mutex */
	void (*lock_grbm_gfx_idx)(struct kgd_dev *kgd);
	void (*unlock_grbm_gfx_idx)(struct kgd_dev *kgd);
};

bool kgd2kfd_init(unsigned interface_version,
		  const struct kfd2kgd_calls* f2g,
		  const struct kgd2kfd_calls** g2f);

#endif

