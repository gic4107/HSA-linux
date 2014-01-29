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
 */

#include "kfd_priv.h"

int radeon_kfd_vidmem_alloc(struct kfd_dev *kfd, size_t size, size_t alignment, enum kfd_mempool pool, kfd_mem_obj *mem_obj)
{
	return kfd2kgd->allocate_mem(kfd->kgd, size, alignment, (enum kgd_memory_pool)pool, (struct kgd_mem **)mem_obj);
}

void radeon_kfd_vidmem_free(struct kfd_dev *kfd, kfd_mem_obj mem_obj)
{
	kfd2kgd->free_mem(kfd->kgd, (struct kgd_mem *)mem_obj);
}

int radeon_kfd_vidmem_gpumap(struct kfd_dev *kfd, kfd_mem_obj mem_obj, uint64_t *vmid0_address)
{
	return kfd2kgd->gpumap_mem(kfd->kgd, (struct kgd_mem *)mem_obj, vmid0_address);
}

void radeon_kfd_vidmem_ungpumap(struct kfd_dev *kfd, kfd_mem_obj mem_obj)
{
	kfd2kgd->ungpumap_mem(kfd->kgd, (struct kgd_mem *)mem_obj);
}

int radeon_kfd_vidmem_kmap(struct kfd_dev *kfd, kfd_mem_obj mem_obj, void **ptr)
{
	return kfd2kgd->kmap_mem(kfd->kgd, (struct kgd_mem *)mem_obj, ptr);
}

void radeon_kfd_vidmem_unkmap(struct kfd_dev *kfd, kfd_mem_obj mem_obj)
{
	kfd2kgd->unkmap_mem(kfd->kgd, (struct kgd_mem *)mem_obj);
}
