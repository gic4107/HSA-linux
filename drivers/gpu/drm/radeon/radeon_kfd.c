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

#include <linux/module.h>
#include <linux/radeon_kfd.h>
#include <drm/drmP.h>
#include "radeon.h"

struct kgd_mem {
	struct radeon_bo *bo;
	u32 domain;
	struct radeon_bo_va *bo_va;
};

static int allocate_mem(struct kgd_dev *kgd, size_t size, size_t alignment, enum kgd_memory_pool pool, struct kgd_mem **memory_handle);
static void free_mem(struct kgd_dev *kgd, struct kgd_mem *memory_handle);

static int gpumap_mem(struct kgd_dev *kgd, struct kgd_mem *mem, uint64_t *vmid0_address);
static void ungpumap_mem(struct kgd_dev *kgd, struct kgd_mem *mem);

static int kmap_mem(struct kgd_dev *kgd, struct kgd_mem *mem, void **ptr);
static void unkmap_mem(struct kgd_dev *kgd, struct kgd_mem *mem);

static int create_process_vm(struct kgd_dev *kgd, void **vm);
static void destroy_process_vm(struct kgd_dev *kgd, void *vm);

static int create_process_gpumem(struct kgd_dev *kgd, uint64_t va, size_t size, void *vm, struct kgd_mem **mem);
static void destroy_process_gpumem(struct kgd_dev *kgd, struct kgd_mem *mem);

static uint32_t get_process_page_dir(void *vm);

static uint64_t get_vmem_size(struct kgd_dev *kgd);
static uint64_t get_gpu_clock_counter(struct kgd_dev *kgd);

static void lock_srbm_gfx_cntl(struct kgd_dev *kgd);
static void unlock_srbm_gfx_cntl(struct kgd_dev *kgd);

static void lock_grbm_gfx_idx(struct kgd_dev *kgd);
static void unlock_grbm_gfx_idx(struct kgd_dev *kgd);

static uint32_t get_max_engine_clock_in_mhz(struct kgd_dev *kgd);


static const struct kfd2kgd_calls kfd2kgd = {
	.allocate_mem = allocate_mem,
	.free_mem = free_mem,
	.gpumap_mem = gpumap_mem,
	.ungpumap_mem = ungpumap_mem,
	.kmap_mem = kmap_mem,
	.unkmap_mem = unkmap_mem,
	.create_process_vm = create_process_vm,
	.destroy_process_vm = destroy_process_vm,
	.create_process_gpumem = create_process_gpumem,
	.destroy_process_gpumem = destroy_process_gpumem,
	.get_process_page_dir = get_process_page_dir,
	.get_vmem_size = get_vmem_size,
	.get_gpu_clock_counter = get_gpu_clock_counter,
	.lock_srbm_gfx_cntl = lock_srbm_gfx_cntl,
	.unlock_srbm_gfx_cntl = unlock_srbm_gfx_cntl,
	.lock_grbm_gfx_idx = lock_grbm_gfx_idx,
	.unlock_grbm_gfx_idx = unlock_grbm_gfx_idx,
	.get_max_engine_clock_in_mhz = get_max_engine_clock_in_mhz,
};

static const struct kgd2kfd_calls *kgd2kfd;

bool radeon_kfd_init(void)
{
	bool (*kgd2kfd_init_p)(unsigned, const struct kfd2kgd_calls*, const struct kgd2kfd_calls**);
	kgd2kfd_init_p = symbol_request(kgd2kfd_init);

	if (kgd2kfd_init_p == NULL)
		return false;

	if (!kgd2kfd_init_p(KFD_INTERFACE_VERSION, &kfd2kgd, &kgd2kfd)) {
		symbol_put(kgd2kfd_init);
		kgd2kfd = NULL;

		return false;
	}

	return true;
}

void radeon_kfd_fini(void)
{
	if (kgd2kfd) {
		kgd2kfd->exit();
		symbol_put(kgd2kfd_init);
	}
}

void radeon_kfd_device_probe(struct radeon_device *rdev)
{
	if (kgd2kfd)
		rdev->kfd = kgd2kfd->probe((struct kgd_dev *)rdev, rdev->pdev);
}

void radeon_kfd_device_init(struct radeon_device *rdev)
{
	if (rdev->kfd) {
		struct kgd2kfd_shared_resources gpu_resources = {
			.mmio_registers = rdev->rmmio,

			.compute_vmid_bitmap = 0xFF00,

			.first_compute_pipe = 1,
			.compute_pipe_count = 8 - 1,
		};

		radeon_doorbell_get_kfd_info(rdev,
					     &gpu_resources.doorbell_physical_address,
					     &gpu_resources.doorbell_aperture_size,
					     &gpu_resources.doorbell_start_offset);

		kgd2kfd->device_init(rdev->kfd, &gpu_resources);
	}
}

void radeon_kfd_device_fini(struct radeon_device *rdev)
{
	if (rdev->kfd) {
		kgd2kfd->device_exit(rdev->kfd);
		rdev->kfd = NULL;
	}
}

void radeon_kfd_interrupt(struct radeon_device *rdev, const void *ih_ring_entry)
{
	if (rdev->kfd)
		kgd2kfd->interrupt(rdev->kfd, ih_ring_entry);
}

void radeon_kfd_suspend(struct radeon_device *rdev)
{
	if (rdev->kfd)
		kgd2kfd->suspend(rdev->kfd);
}

int radeon_kfd_resume(struct radeon_device *rdev)
{
	int r = 0;

	if (rdev->kfd)
		r = kgd2kfd->resume(rdev->kfd);

	return r;
}

static u32 pool_to_domain(enum kgd_memory_pool p)
{
	switch (p) {
	case KGD_POOL_FRAMEBUFFER: return RADEON_GEM_DOMAIN_VRAM;
	default: return RADEON_GEM_DOMAIN_GTT;
	}
}

static int allocate_mem(struct kgd_dev *kgd, size_t size, size_t alignment, enum kgd_memory_pool pool, struct kgd_mem **memory_handle)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;
	struct kgd_mem *mem;
	int r;

	mem = kzalloc(sizeof(struct kgd_mem), GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	mem->domain = pool_to_domain(pool);

	r = radeon_bo_create(rdev, size, alignment, true, mem->domain, NULL, &mem->bo);
	if (r) {
		kfree(mem);
		return r;
	}

	*memory_handle = mem;
	return 0;
}

static void free_mem(struct kgd_dev *kgd, struct kgd_mem *mem)
{
	/* Assume that KFD will never free gpumapped or kmapped memory. This is not quite settled. */
	radeon_bo_unref(&mem->bo);
	kfree(mem);
}

static int gpumap_mem(struct kgd_dev *kgd, struct kgd_mem *mem, uint64_t *vmid0_address)
{
	int r;

	r = radeon_bo_reserve(mem->bo, true);
	BUG_ON(r != 0); /* ttm_bo_reserve can only fail if the buffer reservation lock is held in circumstances that would deadlock. */
	r = radeon_bo_pin(mem->bo, mem->domain, vmid0_address);
	radeon_bo_unreserve(mem->bo);

	return r;
}

static void ungpumap_mem(struct kgd_dev *kgd, struct kgd_mem *mem)
{
	int r;

	r = radeon_bo_reserve(mem->bo, true);
	BUG_ON(r != 0); /* ttm_bo_reserve can only fail if the buffer reservation lock is held in circumstances that would deadlock. */
	r = radeon_bo_unpin(mem->bo);
	BUG_ON(r != 0); /* This unpin only removed NO_EVICT placement flags and should never fail. */
	radeon_bo_unreserve(mem->bo);
}

static int kmap_mem(struct kgd_dev *kgd, struct kgd_mem *mem, void **ptr)
{
	int r;

	r = radeon_bo_reserve(mem->bo, true);
	BUG_ON(r != 0); /* ttm_bo_reserve can only fail if the buffer reservation lock is held in circumstances that would deadlock. */
	r = radeon_bo_kmap(mem->bo, ptr);
	radeon_bo_unreserve(mem->bo);

	return r;
}

static void unkmap_mem(struct kgd_dev *kgd, struct kgd_mem *mem)
{
	int r;

	r = radeon_bo_reserve(mem->bo, true);
	BUG_ON(r != 0); /* ttm_bo_reserve can only fail if the buffer reservation lock is held in circumstances that would deadlock. */
	radeon_bo_kunmap(mem->bo);
	radeon_bo_unreserve(mem->bo);
}

static uint64_t get_vmem_size(struct kgd_dev *kgd)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;
	BUG_ON(kgd == NULL);

	return rdev->mc.real_vram_size;
}

static void lock_srbm_gfx_cntl(struct kgd_dev *kgd)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;
	mutex_lock(&rdev->srbm_mutex);
}

static void unlock_srbm_gfx_cntl(struct kgd_dev *kgd)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;
	mutex_unlock(&rdev->srbm_mutex);
}


static void lock_grbm_gfx_idx(struct kgd_dev *kgd)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;
	BUG_ON(kgd == NULL);

	mutex_lock(&rdev->grbm_idx_mutex);
}

static void unlock_grbm_gfx_idx(struct kgd_dev *kgd)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;
	BUG_ON(kgd == NULL);

	mutex_unlock(&rdev->grbm_idx_mutex);
}

static uint64_t get_gpu_clock_counter(struct kgd_dev *kgd)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;

	return rdev->asic->get_gpu_clock_counter(rdev);
}

static uint32_t get_max_engine_clock_in_mhz(struct kgd_dev *kgd)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;

	/* The sclk is in quantas of 10kHz */
	return rdev->pm.dpm.dyn_state.max_clock_voltage_on_ac.sclk / 100;
}
/*
 * Creates a VM context for HSA process
 */
static int create_process_vm(struct kgd_dev *kgd, void **vm)
{
	int ret;
	struct radeon_vm *new_vm;
	struct radeon_device *rdev = (struct radeon_device *) kgd;

	BUG_ON(kgd == NULL);
	BUG_ON(vm == NULL);

	new_vm = kzalloc(sizeof(struct radeon_vm), GFP_KERNEL);
	if (new_vm == NULL)
		return -ENOMEM;

	/* Initialize the VM context */
	radeon_vm_init(rdev, new_vm);
	/* About to reference VM manager, lock must be acquired */
	mutex_lock(&rdev->vm_manager.lock);
	/* Allocate the page directory and table */
	ret = radeon_vm_alloc_pt(rdev, new_vm);
	/* Release the VM manager lock */
	mutex_unlock(&rdev->vm_manager.lock);

	if (ret != 0) {
		/* Undo everything related to the new VM context */
		radeon_vm_fini(rdev, new_vm);
		kfree(new_vm);
		new_vm = NULL;
	}

	*vm = (void *) new_vm;

	return ret;
}

/*
 * Destroys a VM context of HSA process
 */
static void destroy_process_vm(struct kgd_dev *kgd, void *vm)
{
	struct radeon_device *rdev = (struct radeon_device *) kgd;
	struct radeon_vm *rvm = (struct radeon_vm *) vm;

	BUG_ON(kgd == NULL);
	BUG_ON(vm == NULL);

	/* Release the VM context */
	radeon_vm_fini(rdev, rvm);
	kfree(vm);
}

static int create_process_gpumem(struct kgd_dev *kgd, uint64_t va, size_t size, void *vm, struct kgd_mem **mem)
{
	struct radeon_device *rdev = (struct radeon_device *) kgd;
	struct radeon_vm *rvm = (struct radeon_vm *) vm;
	int ret;
	struct radeon_bo_va *bo_va;
	struct radeon_bo *bo;

	BUG_ON(kgd == NULL);
	BUG_ON(va == 0);
	BUG_ON(size == 0);
	BUG_ON(vm == NULL);
	BUG_ON(mem == NULL);

	*mem = kzalloc(sizeof(struct kgd_mem), GFP_KERNEL);
	/* Allocate the physical memory on the GPU */
	ret = radeon_bo_create(rdev, size, PAGE_SIZE, false, RADEON_GEM_DOMAIN_VRAM, NULL, &bo);

	if (ret != 0)
		return ret;

	/* Pin bo */
	radeon_bo_reserve(bo, true);
	ret = radeon_bo_pin(bo, RADEON_GEM_DOMAIN_VRAM, NULL);
	radeon_bo_unreserve(bo);
	ret = 0;
	if (ret != 0) {
		ret = -EINVAL;
		goto err_pin;
	}

	/* Add the allocation to the VM context */
	bo_va = radeon_vm_bo_add(rdev, rvm, bo);
	if (bo_va == NULL) {
		ret = -EINVAL;
		goto err_vmadd;
	}

	/* Set virtual address for the allocation */
	ret = radeon_vm_bo_set_addr(rdev, bo_va, va, RADEON_VM_PAGE_READABLE | RADEON_VM_PAGE_WRITEABLE);
	if (ret != 0)
		goto err_vmsetaddr;

	/* About to refernce VM manager, lock must be acquired */
	mutex_lock(&rdev->vm_manager.lock);
	mutex_lock(&rvm->mutex);

	/* Update the page tables, so the GPU could start using the allocation */
	ret = radeon_vm_bo_update(rdev, rvm, bo, &bo->tbo.mem);

	mutex_unlock(&rvm->mutex);
	mutex_unlock(&rdev->vm_manager.lock);

	if (ret != 0)
		goto err_vmsetaddr;

	/* Wait for the page table update to complete. */
	radeon_fence_wait(rvm->fence, true);

	(*mem)->bo = bo;
	(*mem)->bo_va = bo_va;
	(*mem)->domain = RADEON_GEM_DOMAIN_VRAM;
	return 0;

err_vmsetaddr:
	radeon_vm_bo_rmv(rdev, bo_va);
err_vmadd:
	radeon_bo_unpin(bo);
err_pin:
	radeon_bo_unref(&bo);
	kfree(*mem);
	return ret;
}

/* Destroys the GPU allocation and frees the kgd_mem structure */
static void destroy_process_gpumem(struct kgd_dev *kgd, struct kgd_mem *mem)
{
	struct radeon_device *rdev = (struct radeon_device *) kgd;

	BUG_ON(kgd == NULL);
	BUG_ON(mem == NULL);

	radeon_vm_bo_rmv(rdev, mem->bo_va);
	radeon_bo_reserve(mem->bo, true);
	radeon_bo_unpin(mem->bo);
	radeon_bo_unreserve(mem->bo);
	radeon_bo_unref(&mem->bo);
	kfree(mem);
}

static uint32_t get_process_page_dir(void *vm)
{
	struct radeon_vm *rvm = (struct radeon_vm *) vm;

	BUG_ON(vm == NULL);

	return rvm->pd_gpu_addr >> RADEON_GPU_PAGE_SHIFT;
}
