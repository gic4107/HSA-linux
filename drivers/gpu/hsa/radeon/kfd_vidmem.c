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

#include <linux/slab.h>
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

int radeon_kfd_process_create_vm(struct kfd_dev *kfd, void **vm)
{
	BUG_ON(kfd == NULL);
	BUG_ON(vm == NULL);

	return kfd2kgd->create_process_vm(kfd->kgd, (void **) vm);
}

void radeon_kfd_process_destroy_vm(struct kfd_dev *kfd, void *vm)
{
	BUG_ON(kfd == NULL);
	BUG_ON(vm == NULL);

	kfd2kgd->destroy_process_vm(kfd->kgd, vm);
}

uint64_t radeon_kfd_process_get_pd(void *vm)
{
	BUG_ON(vm == NULL);

	return kfd2kgd->get_process_page_dir(vm);
}

int radeon_kfd_process_gpuvm_alloc(struct kfd_dev *kfd, uint64_t va, size_t size, void *vm, void **mem_obj)
{

	BUG_ON(kfd == NULL);
	BUG_ON(vm == NULL);
	BUG_ON(mem_obj == NULL);

	return kfd2kgd->create_process_gpumem(kfd->kgd, va, size, vm, (struct kgd_mem **) mem_obj);

}

void radeon_kfd_process_gpuvm_free(struct kfd_dev *kfd, void *mem_obj)
{
	BUG_ON(kfd == NULL);
	BUG_ON(mem_obj == NULL);

	kfd2kgd->destroy_process_gpumem(kfd->kgd, mem_obj);
}

int radeon_kfd_vidmem_alloc_map(struct kfd_dev *kfd, kfd_mem_obj *mem_obj, void **ptr, uint64_t *vmid0_address, size_t size)
{
	int retval;
	retval = radeon_kfd_vidmem_alloc(kfd, size, PAGE_SIZE, KFD_MEMPOOL_SYSTEM_WRITECOMBINE, mem_obj);
	if (retval != 0)
		goto fail_vidmem_alloc;

	retval = radeon_kfd_vidmem_kmap(kfd, *mem_obj, ptr);
	if (retval != 0)
		goto fail_vidmem_kmap;

	retval = radeon_kfd_vidmem_gpumap(kfd, *mem_obj, vmid0_address);
	if (retval != 0)
		goto fail_vidmem_gpumap;

	return 0;

fail_vidmem_gpumap:
	radeon_kfd_vidmem_unkmap(kfd, *mem_obj);
fail_vidmem_kmap:
	radeon_kfd_vidmem_free(kfd, *mem_obj);
fail_vidmem_alloc:
	return retval;
}

void radeon_kfd_vidmem_free_unmap(struct kfd_dev *kfd, kfd_mem_obj mem_obj)
{
	radeon_kfd_vidmem_ungpumap(kfd, mem_obj);
	radeon_kfd_vidmem_unkmap(kfd, mem_obj);
	radeon_kfd_vidmem_free(kfd, mem_obj);
}
