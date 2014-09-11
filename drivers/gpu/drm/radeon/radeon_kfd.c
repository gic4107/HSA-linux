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
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <drm/drmP.h>
#include "radeon.h"
#include "cikd.h"
#include "cik_reg.h"
#include "radeon_kfd.h"

#define CIK_PIPE_PER_MEC	(4)

static const uint32_t watchRegs[MAX_WATCH_ADDRESSES * ADDRESS_WATCH_REG_MAX] = {
	TCP_WATCH0_ADDR_H, TCP_WATCH0_ADDR_L, TCP_WATCH0_CNTL,
	TCP_WATCH1_ADDR_H, TCP_WATCH1_ADDR_L, TCP_WATCH1_CNTL,
	TCP_WATCH2_ADDR_H, TCP_WATCH2_ADDR_L, TCP_WATCH2_CNTL,
	TCP_WATCH3_ADDR_H, TCP_WATCH3_ADDR_L, TCP_WATCH3_CNTL
};

struct kgd_mem {
	union {
		struct {
			struct radeon_sa_bo *sa_bo;
			uint64_t gpu_addr;
			uint32_t *ptr;
		} data1;
		struct {
			struct radeon_bo *bo;
			struct radeon_bo_va *bo_va;
		} data2;
	};
};

static int init_sa_manager(struct kgd_dev *kgd, unsigned int size);
static void fini_sa_manager(struct kgd_dev *kgd);

static int allocate_mem(struct kgd_dev *kgd, size_t size, size_t alignment,
		enum kgd_memory_pool pool, struct kgd_mem **mem);

static void free_mem(struct kgd_dev *kgd, struct kgd_mem *mem);

static uint64_t get_vmem_size(struct kgd_dev *kgd);
static uint64_t get_gpu_clock_counter(struct kgd_dev *kgd);

static uint32_t get_max_engine_clock_in_mhz(struct kgd_dev *kgd);

static int create_process_vm(struct kgd_dev *kgd, void **vm);
static void destroy_process_vm(struct kgd_dev *kgd, void *vm);

static int create_process_gpumem(struct kgd_dev *kgd, uint64_t va, size_t size, void *vm, struct kgd_mem **mem);
static void destroy_process_gpumem(struct kgd_dev *kgd, struct kgd_mem *mem);

static uint32_t get_process_page_dir(void *vm);

static int open_graphic_handle(struct kgd_dev *kgd, uint64_t va, void *vm, int fd, uint32_t handle, struct kgd_mem **mem);

/*
 * Register access functions
 */

static void kgd_program_sh_mem_settings(struct kgd_dev *kgd, uint32_t vmid,
		uint32_t sh_mem_config,	uint32_t sh_mem_ape1_base,
		uint32_t sh_mem_ape1_limit, uint32_t sh_mem_bases);

static int kgd_set_pasid_vmid_mapping(struct kgd_dev *kgd, unsigned int pasid,
					unsigned int vmid);

static int kgd_init_memory(struct kgd_dev *kgd);

static int kgd_init_pipeline(struct kgd_dev *kgd, uint32_t pipe_id,
				uint32_t hpd_size, uint64_t hpd_gpu_addr);
static int kgd_init_interrupts(struct kgd_dev *kgd, uint32_t pipe_id);
static int kgd_hqd_load(struct kgd_dev *kgd, void *mqd, uint32_t pipe_id,
			uint32_t queue_id, uint32_t __user *wptr);
static int kgd_hqd_sdma_load(struct kgd_dev *kgd, void *mqd);
static bool kgd_hqd_is_occupies(struct kgd_dev *kgd, uint64_t queue_address,
				uint32_t pipe_id, uint32_t queue_id);

static int kgd_hqd_destroy(struct kgd_dev *kgd, uint32_t reset_type,
				unsigned int timeout, uint32_t pipe_id,
				uint32_t queue_id);
static bool kgd_hqd_sdma_is_occupies(struct kgd_dev *kgd, void *mqd);
static int kgd_hqd_sdma_destroy(struct kgd_dev *kgd, void *mqd,
				unsigned int timeout);
static int kgd_init_sdma_engines(struct kgd_dev *kgd);
static int kgd_address_watch_disable(struct kgd_dev *kgd);
static int kgd_address_watch_execute(struct kgd_dev *kgd,
					unsigned int watch_point_id,
					uint32_t cntl_val,
					uint32_t addr_hi,
					uint32_t addr_lo);
static int kgd_wave_control_execute(struct kgd_dev *kgd,
					uint32_t gfx_index_val,
					uint32_t sq_cmd);
static uint32_t kgd_address_watch_get_offset(struct kgd_dev *kgd,
					unsigned int watch_point_id,
					unsigned int reg_offset);

static bool read_atc_vmid_pasid_mapping_reg_valid_field(struct kgd_dev *kgd, uint8_t vmid);
static uint16_t read_atc_vmid_pasid_mapping_reg_pasid_field(struct kgd_dev *kgd, uint8_t vmid);
static void write_vmid_invalidate_request(struct kgd_dev *kgd, uint8_t vmid);

static const struct kfd2kgd_calls kfd2kgd = {
	.init_sa_manager = init_sa_manager,
	.fini_sa_manager = fini_sa_manager,
	.allocate_mem = allocate_mem,
	.free_mem = free_mem,
	.get_vmem_size = get_vmem_size,
	.get_gpu_clock_counter = get_gpu_clock_counter,
	.get_max_engine_clock_in_mhz = get_max_engine_clock_in_mhz,
	.create_process_vm = create_process_vm,
	.destroy_process_vm = destroy_process_vm,
	.create_process_gpumem = create_process_gpumem,
	.destroy_process_gpumem = destroy_process_gpumem,
	.get_process_page_dir = get_process_page_dir,
	.open_graphic_handle = open_graphic_handle,
	.program_sh_mem_settings = kgd_program_sh_mem_settings,
	.set_pasid_vmid_mapping = kgd_set_pasid_vmid_mapping,
	.init_memory = kgd_init_memory,
	.init_pipeline = kgd_init_pipeline,
	.init_interrupts = kgd_init_interrupts,
	.init_sdma_engines = kgd_init_sdma_engines,
	.hqd_load = kgd_hqd_load,
	.hqd_sdma_load = kgd_hqd_sdma_load,
	.hqd_is_occupies = kgd_hqd_is_occupies,
	.hqd_sdma_is_occupies = kgd_hqd_sdma_is_occupies,
	.hqd_destroy = kgd_hqd_destroy,
	.hqd_sdma_destroy = kgd_hqd_sdma_destroy,
	.address_watch_disable = kgd_address_watch_disable,
	.address_watch_execute = kgd_address_watch_execute,
	.wave_control_execute = kgd_wave_control_execute,
	.address_watch_get_offset = kgd_address_watch_get_offset,
	.read_atc_vmid_pasid_mapping_reg_pasid_field = read_atc_vmid_pasid_mapping_reg_pasid_field,
	.read_atc_vmid_pasid_mapping_reg_valid_field = read_atc_vmid_pasid_mapping_reg_valid_field,
	.write_vmid_invalidate_request = write_vmid_invalidate_request
};

static const struct kgd2kfd_calls *kgd2kfd;

bool radeon_kfd_init(void)
{
	bool (*kgd2kfd_init_p)(unsigned, const struct kfd2kgd_calls*,
				const struct kgd2kfd_calls**);

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

static int init_sa_manager(struct kgd_dev *kgd, unsigned int size)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;
	int r;

	BUG_ON(kgd == NULL);

	r = radeon_sa_bo_manager_init(rdev, &rdev->kfd_bo,
				      size,
				      RADEON_GPU_PAGE_SIZE,
				      RADEON_GEM_DOMAIN_GTT,
				      RADEON_GEM_GTT_WC);

	if (r)
		return r;

	r = radeon_sa_bo_manager_start(rdev, &rdev->kfd_bo);
	if (r)
		radeon_sa_bo_manager_fini(rdev, &rdev->kfd_bo);

	return r;
}

static void fini_sa_manager(struct kgd_dev *kgd)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;

	BUG_ON(kgd == NULL);

	radeon_sa_bo_manager_suspend(rdev, &rdev->kfd_bo);
	radeon_sa_bo_manager_fini(rdev, &rdev->kfd_bo);
}

static int allocate_mem(struct kgd_dev *kgd, size_t size, size_t alignment,
		enum kgd_memory_pool pool, struct kgd_mem **mem)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;
	u32 domain;
	int r;

	BUG_ON(kgd == NULL);

	domain = pool_to_domain(pool);
	if (domain != RADEON_GEM_DOMAIN_GTT) {
		dev_err(rdev->dev,
			"Only allowed to allocate gart memory for kfd\n");
		return -EINVAL;
	}

	*mem = kmalloc(sizeof(struct kgd_mem), GFP_KERNEL);
	if ((*mem) == NULL)
		return -ENOMEM;

	r = radeon_sa_bo_new(rdev, &rdev->kfd_bo, &(*mem)->data1.sa_bo, 
				size, alignment);
	if (r) {
		dev_err(rdev->dev, "failed to get memory for kfd (%d)\n", r);
		return r;
	}

	(*mem)->data1.ptr = radeon_sa_bo_cpu_addr((*mem)->data1.sa_bo);
	(*mem)->data1.gpu_addr = radeon_sa_bo_gpu_addr((*mem)->data1.sa_bo);

	return 0;
}

static void free_mem(struct kgd_dev *kgd, struct kgd_mem *mem)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;

	BUG_ON(kgd == NULL);

	radeon_sa_bo_free(rdev, &mem->data1.sa_bo, NULL);
	kfree(mem);
}

static uint64_t get_vmem_size(struct kgd_dev *kgd)
{
	struct radeon_device *rdev = (struct radeon_device *)kgd;

	BUG_ON(kgd == NULL);

	return rdev->mc.real_vram_size;
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

	/* Initialize the VM context, allocate the page directory and zero it */
	ret = radeon_vm_init(rdev, new_vm);
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

	/* Allocate the memory on the GPU */
	ret = radeon_bo_create(rdev, size, PAGE_SIZE, false,
				RADEON_GEM_DOMAIN_VRAM,
				RADEON_GEM_NO_BACKING_STORE, NULL, &bo);

	if (ret != 0)
		return ret;

	/* Pin bo */
	radeon_bo_reserve(bo, true);
	ret = radeon_bo_pin(bo, RADEON_GEM_DOMAIN_VRAM, NULL);
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

	/* Set virtual address for the allocation, allocate PTs, if needed, and zero them */
	ret = radeon_vm_bo_set_addr(rdev, bo_va, va, RADEON_VM_PAGE_READABLE | RADEON_VM_PAGE_WRITEABLE);
	if (ret != 0)
		goto err_vmsetaddr;

	mutex_lock(&rvm->mutex);

	/* Update the page tables  */
	ret = radeon_vm_bo_update(rdev, bo_va, &bo->tbo.mem);
	/* Update the page directory */
	ret = radeon_vm_update_page_directory(rdev, rvm);

	mutex_unlock(&rvm->mutex);

	if (ret != 0)
		goto err_vmsetaddr;

	/* Wait for the page table update to complete. */
	radeon_fence_wait(rvm->fence, true);

	(*mem)->data2.bo = bo;
	(*mem)->data2.bo_va = bo_va;
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

	radeon_vm_bo_rmv(rdev, mem->data2.bo_va);
	mutex_lock(&mem->data2.bo_va->vm->mutex);
	radeon_vm_clear_freed(rdev, mem->data2.bo_va->vm);
	mutex_unlock(&mem->data2.bo_va->vm->mutex);
	radeon_bo_reserve(mem->data2.bo, true);
	radeon_bo_unpin(mem->data2.bo);
	radeon_bo_unreserve(mem->data2.bo);
	radeon_bo_unref(&mem->data2.bo);
	kfree(mem);
}

static uint32_t get_process_page_dir(void *vm)
{
	struct radeon_vm *rvm = (struct radeon_vm *) vm;

	BUG_ON(vm == NULL);

	return rvm->pd_gpu_addr >> RADEON_GPU_PAGE_SHIFT;
}

static int open_graphic_handle(struct kgd_dev *kgd, uint64_t va, void *vm, int fd, uint32_t handle, struct kgd_mem **mem)
{
	struct radeon_device *rdev = (struct radeon_device *) kgd;
	struct radeon_vm *rvm = (struct radeon_vm *) vm;
	int ret;
	struct radeon_bo_va *bo_va;
	struct radeon_bo *bo;
	struct file *filp;
	struct drm_gem_object *gem_obj;

	BUG_ON(kgd == NULL);
	BUG_ON(va == 0);
	BUG_ON(vm == NULL);
	BUG_ON(mem == NULL);

	*mem = kzalloc(sizeof(struct kgd_mem), GFP_KERNEL);
	if (!*mem)
		return -ENOMEM;

	/* Translate fd to file */
	rcu_read_lock();
	filp = fcheck(fd);
	rcu_read_unlock();

	BUG_ON(filp == NULL);

	/* Get object by handle*/
	gem_obj = drm_gem_object_lookup(rdev->ddev, filp->private_data, handle);
	BUG_ON(gem_obj == NULL);

	/* No need to increment GEM refcount*/
	drm_gem_object_unreference(gem_obj);

	bo = gem_to_radeon_bo(gem_obj);

	/* Inc TTM refcount*/
	ttm_bo_reference(&bo->tbo);

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

	mutex_lock(&rvm->mutex);

	/* Update the page tables, so the GPU could start using the allocation */
	ret = radeon_vm_bo_update(rdev, bo_va, &bo->tbo.mem);
	/* Update the page directory */
	ret = radeon_vm_update_page_directory(rdev, rvm);

	mutex_unlock(&rvm->mutex);
	if (ret != 0)
		goto err_vmsetaddr;

	/* Wait for the page table update to complete. */
	radeon_fence_wait(rvm->fence, true);

	(*mem)->data2.bo = bo;
	(*mem)->data2.bo_va = bo_va;
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

static inline struct radeon_device *get_radeon_device(struct kgd_dev *kgd)
{
	return (struct radeon_device *)kgd;
}

static void write_register(struct kgd_dev *kgd, uint32_t offset, uint32_t value)
{
	struct radeon_device *rdev = get_radeon_device(kgd);

	writel(value, (void __iomem *)(rdev->rmmio + offset));
}

static uint32_t read_register(struct kgd_dev *kgd, uint32_t offset)
{
	struct radeon_device *rdev = get_radeon_device(kgd);

	return readl((void __iomem *)(rdev->rmmio + offset));
}

static void lock_srbm(struct kgd_dev *kgd, uint32_t mec, uint32_t pipe,
			uint32_t queue, uint32_t vmid)
{
	struct radeon_device *rdev = get_radeon_device(kgd);
	uint32_t value = PIPEID(pipe) | MEID(mec) | VMID(vmid) | QUEUEID(queue);

	mutex_lock(&rdev->srbm_mutex);
	write_register(kgd, SRBM_GFX_CNTL, value);
}

static void unlock_srbm(struct kgd_dev *kgd)
{
	struct radeon_device *rdev = get_radeon_device(kgd);

	write_register(kgd, SRBM_GFX_CNTL, 0);
	mutex_unlock(&rdev->srbm_mutex);
}

static void acquire_queue(struct kgd_dev *kgd, uint32_t pipe_id,
				uint32_t queue_id)
{
	uint32_t mec = (++pipe_id / CIK_PIPE_PER_MEC) + 1;
	uint32_t pipe = (pipe_id % CIK_PIPE_PER_MEC);

	lock_srbm(kgd, mec, pipe, queue_id, 0);
}

static void release_queue(struct kgd_dev *kgd)
{
	unlock_srbm(kgd);
}

static void kgd_program_sh_mem_settings(struct kgd_dev *kgd, uint32_t vmid,
					uint32_t sh_mem_config,
					uint32_t sh_mem_ape1_base,
					uint32_t sh_mem_ape1_limit,
					uint32_t sh_mem_bases)
{
	lock_srbm(kgd, 0, 0, 0, vmid);

	write_register(kgd, SH_MEM_CONFIG, sh_mem_config);
	write_register(kgd, SH_MEM_APE1_BASE, sh_mem_ape1_base);
	write_register(kgd, SH_MEM_APE1_LIMIT, sh_mem_ape1_limit);
	write_register(kgd, SH_MEM_BASES, sh_mem_bases);

	unlock_srbm(kgd);
}

static int kgd_set_pasid_vmid_mapping(struct kgd_dev *kgd, unsigned int pasid,
					unsigned int vmid)
{
	/*
	 * We have to assume that there is no outstanding mapping.
	 * The ATC_VMID_PASID_MAPPING_UPDATE_STATUS bit could be 0
	 * because a mapping is in progress or because a mapping finished and
	 * the SW cleared it.
	 * So the protocol is to always wait & clear.
	 */
	uint32_t pasid_mapping = (pasid == 0) ? 0 : (uint32_t)pasid | 
					ATC_VMID_PASID_MAPPING_VALID_MASK;

	write_register(kgd, ATC_VMID0_PASID_MAPPING + vmid*sizeof(uint32_t),
			pasid_mapping);

	while (!(read_register(kgd, ATC_VMID_PASID_MAPPING_UPDATE_STATUS) &
								(1U << vmid)))
		cpu_relax();
	write_register(kgd, ATC_VMID_PASID_MAPPING_UPDATE_STATUS, 1U << vmid);

	return 0;
}

static int kgd_init_memory(struct kgd_dev *kgd)
{
	/*
	 * Configure apertures:
	 * LDS:         0x60000000'00000000 - 0x60000001'00000000 (4GB)
	 * Scratch:     0x60000001'00000000 - 0x60000002'00000000 (4GB)
	 * GPUVM:       0x60010000'00000000 - 0x60020000'00000000 (1TB)
	 */
	int i;
	uint32_t sh_mem_bases = PRIVATE_BASE(0x6000) | SHARED_BASE(0x6000);

	for (i = 8; i < 16; i++) {
		uint32_t sh_mem_config;

		lock_srbm(kgd, 0, 0, 0, i);

		sh_mem_config = ALIGNMENT_MODE(SH_MEM_ALIGNMENT_MODE_UNALIGNED);
		sh_mem_config |= DEFAULT_MTYPE(MTYPE_NONCACHED);

		write_register(kgd, SH_MEM_CONFIG, sh_mem_config);

		write_register(kgd, SH_MEM_BASES, sh_mem_bases);

		/* Scratch aperture is not supported for now. */
		write_register(kgd, SH_STATIC_MEM_CONFIG, 0);

		/* APE1 disabled for now. */
		write_register(kgd, SH_MEM_APE1_BASE, 1);
		write_register(kgd, SH_MEM_APE1_LIMIT, 0);

		unlock_srbm(kgd);
	}

	return 0;
}

static int kgd_init_pipeline(struct kgd_dev *kgd, uint32_t pipe_id,
				uint32_t hpd_size, uint64_t hpd_gpu_addr)
{
	uint32_t mec = (++pipe_id / CIK_PIPE_PER_MEC) + 1;
	uint32_t pipe = (pipe_id % CIK_PIPE_PER_MEC);

	lock_srbm(kgd, mec, pipe, 0, 0);
	write_register(kgd, CP_HPD_EOP_BASE_ADDR,
			lower_32_bits(hpd_gpu_addr >> 8));
	write_register(kgd, CP_HPD_EOP_BASE_ADDR_HI,
			upper_32_bits(hpd_gpu_addr >> 8));
	write_register(kgd, CP_HPD_EOP_VMID, 0);
	write_register(kgd, CP_HPD_EOP_CONTROL, hpd_size);
	unlock_srbm(kgd);

	return 0;
}

static int kgd_init_interrupts(struct kgd_dev *kgd, uint32_t pipe_id)
{
	uint32_t mec;
	uint32_t pipe;

	mec = (++pipe_id / CIK_PIPE_PER_MEC) + 1;
	pipe = (pipe_id % CIK_PIPE_PER_MEC);

	lock_srbm(kgd, mec, pipe, 0, 0);

	write_register(kgd, CPC_INT_CNTL, TIME_STAMP_INT_ENABLE);

	unlock_srbm(kgd);

	return 0;
}

static int kgd_init_sdma_engines(struct kgd_dev *kgd)
{
	uint32_t value;

	value = read_register(kgd, SDMA0_CNTL);
	value |= AUTO_CTXSW_ENABLE;
	write_register(kgd, SDMA0_CNTL, value);

	value = read_register(kgd, SDMA1_CNTL);
	value |= AUTO_CTXSW_ENABLE;
	write_register(kgd, SDMA1_CNTL, value);

	return 0;
}

static inline uint32_t get_sdma_base_addr(struct cik_sdma_rlc_registers *m)
{
	uint32_t retval;
	retval = m->sdma_engine_id * SDMA1_REGISTER_OFFSET +
			m->sdma_queue_id * KFD_CIK_SDMA_QUEUE_OFFSET;
	pr_err("kfd: sdma base address: 0x%x\n", retval);
	return retval;
}

static inline struct cik_mqd *get_mqd(void *mqd)
{
	return (struct cik_mqd *)mqd;
}

static inline struct cik_sdma_rlc_registers *get_sdma_mqd(void *mqd)
{
	return (struct cik_sdma_rlc_registers *)mqd;
}

static int kgd_hqd_load(struct kgd_dev *kgd, void *mqd, uint32_t pipe_id,
			uint32_t queue_id, uint32_t __user *wptr)
{
	uint32_t wptr_shadow, is_wptr_shadow_valid;
	struct cik_mqd *m;

	m = get_mqd(mqd);

	is_wptr_shadow_valid = !get_user(wptr_shadow, wptr);

	acquire_queue(kgd, pipe_id, queue_id);
	write_register(kgd, CP_MQD_BASE_ADDR, m->cp_mqd_base_addr_lo);
	write_register(kgd, CP_MQD_BASE_ADDR_HI, m->cp_mqd_base_addr_hi);
	write_register(kgd, CP_MQD_CONTROL, m->cp_mqd_control);

	write_register(kgd, CP_HQD_PQ_BASE, m->cp_hqd_pq_base_lo);
	write_register(kgd, CP_HQD_PQ_BASE_HI, m->cp_hqd_pq_base_hi);
	write_register(kgd, CP_HQD_PQ_CONTROL, m->cp_hqd_pq_control);

	write_register(kgd, CP_HQD_IB_CONTROL, m->cp_hqd_ib_control);
	write_register(kgd, CP_HQD_IB_BASE_ADDR, m->cp_hqd_ib_base_addr_lo);
	write_register(kgd, CP_HQD_IB_BASE_ADDR_HI, m->cp_hqd_ib_base_addr_hi);

	write_register(kgd, CP_HQD_IB_RPTR, m->cp_hqd_ib_rptr);

	write_register(kgd, CP_HQD_PERSISTENT_STATE,
			m->cp_hqd_persistent_state);
	write_register(kgd, CP_HQD_SEMA_CMD, m->cp_hqd_sema_cmd);
	write_register(kgd, CP_HQD_MSG_TYPE, m->cp_hqd_msg_type);

	write_register(kgd, CP_HQD_ATOMIC0_PREOP_LO,
			m->cp_hqd_atomic0_preop_lo);

	write_register(kgd, CP_HQD_ATOMIC0_PREOP_HI,
			m->cp_hqd_atomic0_preop_hi);

	write_register(kgd, CP_HQD_ATOMIC1_PREOP_LO,
			m->cp_hqd_atomic1_preop_lo);

	write_register(kgd, CP_HQD_ATOMIC1_PREOP_HI,
			m->cp_hqd_atomic1_preop_hi);

	write_register(kgd, CP_HQD_PQ_RPTR_REPORT_ADDR,
			m->cp_hqd_pq_rptr_report_addr_lo);

	write_register(kgd, CP_HQD_PQ_RPTR_REPORT_ADDR_HI,
			m->cp_hqd_pq_rptr_report_addr_hi);

	write_register(kgd, CP_HQD_PQ_RPTR, m->cp_hqd_pq_rptr);

	write_register(kgd, CP_HQD_PQ_WPTR_POLL_ADDR,
			m->cp_hqd_pq_wptr_poll_addr_lo);

	write_register(kgd, CP_HQD_PQ_WPTR_POLL_ADDR_HI,
			m->cp_hqd_pq_wptr_poll_addr_hi);

	write_register(kgd, CP_HQD_PQ_DOORBELL_CONTROL,
			m->cp_hqd_pq_doorbell_control);

	write_register(kgd, CP_HQD_VMID, m->cp_hqd_vmid);

	write_register(kgd, CP_HQD_QUANTUM, m->cp_hqd_quantum);

	write_register(kgd, CP_HQD_PIPE_PRIORITY, m->cp_hqd_pipe_priority);
	write_register(kgd, CP_HQD_QUEUE_PRIORITY, m->cp_hqd_queue_priority);

	write_register(kgd, CP_HQD_IQ_RPTR, m->cp_hqd_iq_rptr);

	if (is_wptr_shadow_valid)
		write_register(kgd, CP_HQD_PQ_WPTR, wptr_shadow);

	write_register(kgd, CP_HQD_ACTIVE, m->cp_hqd_active);
	release_queue(kgd);

	return 0;
}

static int kgd_hqd_sdma_load(struct kgd_dev *kgd, void *mqd)
{
	struct cik_sdma_rlc_registers *m;
	uint32_t sdma_base_addr;

	m = get_sdma_mqd(mqd);
	sdma_base_addr = get_sdma_base_addr(m);

	write_register(kgd, sdma_base_addr + SDMA0_RLC0_VIRTUAL_ADDR, m->sdma_rlc_virtual_addr);
	write_register(kgd, sdma_base_addr + SDMA0_RLC0_RB_BASE, m->sdma_rlc_rb_base);
	write_register(kgd, sdma_base_addr + SDMA0_RLC0_RB_BASE_HI, m->sdma_rlc_rb_base_hi);
	write_register(kgd, sdma_base_addr + SDMA0_RLC0_RB_RPTR_ADDR_LO, m->sdma_rlc_rb_rptr_addr_lo);
	write_register(kgd, sdma_base_addr + SDMA0_RLC0_RB_RPTR_ADDR_HI, m->sdma_rlc_rb_rptr_addr_hi);
	write_register(kgd, sdma_base_addr + SDMA0_RLC0_DOORBELL, m->sdma_rlc_doorbell);
	write_register(kgd, sdma_base_addr + SDMA0_RLC0_RB_CNTL, m->sdma_rlc_rb_cntl);

	return 0;
}

static bool kgd_hqd_is_occupies(struct kgd_dev *kgd, uint64_t queue_address,
				uint32_t pipe_id, uint32_t queue_id)
{
	uint32_t act;
	bool retval = false;
	uint32_t low, high;

	acquire_queue(kgd, pipe_id, queue_id);
	act = read_register(kgd, CP_HQD_ACTIVE);
	if (act) {
		low = lower_32_bits(queue_address >> 8);
		high = upper_32_bits(queue_address >> 8);

		if (low == read_register(kgd, CP_HQD_PQ_BASE) &&
				high == read_register(kgd, CP_HQD_PQ_BASE_HI))
			retval = true;
	}
	release_queue(kgd);
	return retval;
}

static bool kgd_hqd_sdma_is_occupies(struct kgd_dev *kgd, void *mqd)
{
	struct cik_sdma_rlc_registers *m;
	uint32_t sdma_base_addr;
	uint32_t sdma_rlc_rb_cntl;

	m = get_sdma_mqd(mqd);
	sdma_base_addr = get_sdma_base_addr(m);

	sdma_rlc_rb_cntl = read_register(kgd, sdma_base_addr + SDMA0_RLC0_RB_CNTL);

	if (sdma_rlc_rb_cntl & RB_ENABLE)
		return true;

	return false;
}

static int kgd_hqd_destroy(struct kgd_dev *kgd, uint32_t reset_type,
				unsigned int timeout, uint32_t pipe_id,
				uint32_t queue_id)
{
	uint32_t temp;

	acquire_queue(kgd, pipe_id, queue_id);
	write_register(kgd, CP_HQD_PQ_DOORBELL_CONTROL, 0);

	write_register(kgd, CP_HQD_DEQUEUE_REQUEST, reset_type);

	while (true) {
		temp = read_register(kgd, CP_HQD_ACTIVE);
		if (temp & 0x1)
			break;
		if (timeout == 0) {
			pr_err("kfd: cp queue preemption time out (%dms)\n",
				temp);
			return -ETIME;
		}
		msleep(20);
		timeout -= 20;
	}

	release_queue(kgd);
	return 0;
}

static int kgd_hqd_sdma_destroy(struct kgd_dev *kgd, void *mqd,
				unsigned int timeout)
{
	struct cik_sdma_rlc_registers *m;
	uint32_t sdma_base_addr;
	uint32_t temp;

	m = get_sdma_mqd(mqd);
	sdma_base_addr = get_sdma_base_addr(m);

	temp = read_register(kgd, sdma_base_addr + SDMA0_RLC0_RB_CNTL);
	temp = temp & ~RB_ENABLE;
	write_register(kgd, sdma_base_addr + SDMA0_RLC0_RB_CNTL, temp);

	while (true) {
		temp = read_register(kgd, sdma_base_addr +
						SDMA0_RLC0_CONTEXT_STATUS);
		if (temp & IDLE)
			break;
		if (timeout == 0)
			return -ETIME;
		msleep(20);
		timeout -= 20;
	}

	write_register(kgd, sdma_base_addr + SDMA0_RLC0_DOORBELL, 0);
	write_register(kgd, sdma_base_addr + SDMA0_RLC0_RB_RPTR, 0);
	write_register(kgd, sdma_base_addr + SDMA0_RLC0_RB_WPTR, 0);
	write_register(kgd, sdma_base_addr + SDMA0_RLC0_RB_BASE, 0);

	return 0;
}

static int kgd_address_watch_disable(struct kgd_dev *kgd)
{
	union TCP_WATCH_CNTL_BITS cntl;
	unsigned int i;

	cntl.u32All = 0;

	cntl.bitfields.valid = 0;
	cntl.bitfields.mask = ADDRESS_WATCH_REG_CNTL_DEFAULT_MASK;
	cntl.bitfields.atc = 1;

	/* Turning off this address until we set all the registers */
	for (i = 0; i < MAX_WATCH_ADDRESSES; i++)
		write_register(kgd,
				watchRegs[i * ADDRESS_WATCH_REG_MAX +
				          ADDRESS_WATCH_REG_CNTL],
				cntl.u32All);

	return 0;
}

static int kgd_address_watch_execute(struct kgd_dev *kgd,
					unsigned int watch_point_id,
					uint32_t cntl_val,
					uint32_t addr_hi,
					uint32_t addr_lo)
{
	union TCP_WATCH_CNTL_BITS cntl;

	cntl.u32All = cntl_val;

	/* Turning off this watch point until we set all the registers */
	cntl.bitfields.valid = 0;
	write_register(kgd,
			watchRegs[watch_point_id * ADDRESS_WATCH_REG_MAX +
			          ADDRESS_WATCH_REG_CNTL],
			cntl.u32All);

	write_register(kgd,
			watchRegs[watch_point_id * ADDRESS_WATCH_REG_MAX +
			          ADDRESS_WATCH_REG_ADDR_HI],
			addr_hi);

	write_register(kgd,
			watchRegs[watch_point_id * ADDRESS_WATCH_REG_MAX +
			          ADDRESS_WATCH_REG_ADDR_LO],
			addr_lo);

	/* Enable the watch point */
	cntl.bitfields.valid = 1;

	write_register(kgd,
			watchRegs[watch_point_id * ADDRESS_WATCH_REG_MAX +
			          ADDRESS_WATCH_REG_CNTL],
			cntl.u32All);

	return 0;
}

static int kgd_wave_control_execute(struct kgd_dev *kgd,
					uint32_t gfx_index_val,
					uint32_t sq_cmd)
{
	struct radeon_device *rdev = get_radeon_device(kgd);
	uint32_t data;

	mutex_lock(&rdev->grbm_idx_mutex);

	write_register(kgd, GRBM_GFX_INDEX, gfx_index_val);
	write_register(kgd, SQ_CMD, sq_cmd);

	/*  Restore the GRBM_GFX_INDEX register  */

	data = INSTANCE_BROADCAST_WRITES | SH_BROADCAST_WRITES |
		SE_BROADCAST_WRITES;

	write_register(kgd, GRBM_GFX_INDEX, data);

	mutex_unlock(&rdev->grbm_idx_mutex);

	return 0;
}

static uint32_t kgd_address_watch_get_offset(struct kgd_dev *kgd,
					unsigned int watch_point_id,
					unsigned int reg_offset)
{
	return watchRegs[watch_point_id * ADDRESS_WATCH_REG_MAX + reg_offset];
}

static bool read_atc_vmid_pasid_mapping_reg_valid_field(struct kgd_dev *kgd, uint8_t vmid)
{
	uint32_t reg;
	struct radeon_device *rdev = (struct radeon_device *) kgd;
	reg = RREG32(ATC_VMID0_PASID_MAPPING + vmid*4);
	return reg & ATC_VMID_PASID_MAPPING_VALID_MASK;
}

static uint16_t read_atc_vmid_pasid_mapping_reg_pasid_field(struct kgd_dev *kgd, uint8_t vmid)
{
	uint32_t reg;
	struct radeon_device *rdev = (struct radeon_device *) kgd;
	reg = RREG32(ATC_VMID0_PASID_MAPPING + vmid*4);
	return reg & ATC_VMID_PASID_MAPPING_PASID_MASK;
}

static void write_vmid_invalidate_request(struct kgd_dev *kgd, uint8_t vmid)
{
	struct radeon_device *rdev = (struct radeon_device *) kgd;
	return WREG32(VM_INVALIDATE_REQUEST, 1 << vmid);
}
