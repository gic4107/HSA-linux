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
#include "cikd.h"
#include <linux/fdtable.h>
#include <linux/uaccess.h>

#define CIK_PIPE_PER_MEC	(4)

struct kgd_mem {
	struct radeon_bo *bo;
	u32 domain;
	struct radeon_bo_va *bo_va;
};

struct cik_hqd_registers {
	u32 cp_mqd_base_addr;
	u32 cp_mqd_base_addr_hi;
	u32 cp_hqd_active;
	u32 cp_hqd_vmid;
	u32 cp_hqd_persistent_state;
	u32 cp_hqd_pipe_priority;
	u32 cp_hqd_queue_priority;
	u32 cp_hqd_quantum;
	u32 cp_hqd_pq_base;
	u32 cp_hqd_pq_base_hi;
	u32 cp_hqd_pq_rptr;
	u32 cp_hqd_pq_rptr_report_addr;
	u32 cp_hqd_pq_rptr_report_addr_hi;
	u32 cp_hqd_pq_wptr_poll_addr;
	u32 cp_hqd_pq_wptr_poll_addr_hi;
	u32 cp_hqd_pq_doorbell_control;
	u32 cp_hqd_pq_wptr;
	u32 cp_hqd_pq_control;
	u32 cp_hqd_ib_base_addr;
	u32 cp_hqd_ib_base_addr_hi;
	u32 cp_hqd_ib_rptr;
	u32 cp_hqd_ib_control;
	u32 cp_hqd_iq_timer;
	u32 cp_hqd_iq_rptr;
	u32 cp_hqd_dequeue_request;
	u32 cp_hqd_dma_offload;
	u32 cp_hqd_sema_cmd;
	u32 cp_hqd_msg_type;
	u32 cp_hqd_atomic0_preop_lo;
	u32 cp_hqd_atomic0_preop_hi;
	u32 cp_hqd_atomic1_preop_lo;
	u32 cp_hqd_atomic1_preop_hi;
	u32 cp_hqd_hq_scheduler0;
	u32 cp_hqd_hq_scheduler1;
	u32 cp_mqd_control;
};

struct cik_mqd {
	u32 header;
	u32 dispatch_initiator;
	u32 dimensions[3];
	u32 start_idx[3];
	u32 num_threads[3];
	u32 pipeline_stat_enable;
	u32 perf_counter_enable;
	u32 pgm[2];
	u32 tba[2];
	u32 tma[2];
	u32 pgm_rsrc[2];
	u32 vmid;
	u32 resource_limits;
	u32 static_thread_mgmt01[2];
	u32 tmp_ring_size;
	u32 static_thread_mgmt23[2];
	u32 restart[3];
	u32 thread_trace_enable;
	u32 reserved1;
	u32 user_data[16];
	u32 vgtcs_invoke_count[2];
	struct cik_hqd_registers queue_state;
	u32 dequeue_cntr;
	u32 interrupt_queue[64];
};

static int allocate_mem(struct kgd_dev *kgd, size_t size, size_t alignment,
		enum kgd_memory_pool pool, struct kgd_mem **memory_handle);

static void free_mem(struct kgd_dev *kgd, struct kgd_mem *memory_handle);

static int gpumap_mem(struct kgd_dev *kgd, struct kgd_mem *mem, uint64_t *vmid0_address);
static void ungpumap_mem(struct kgd_dev *kgd, struct kgd_mem *mem);

static int kmap_mem(struct kgd_dev *kgd, struct kgd_mem *mem, void **ptr);
static void unkmap_mem(struct kgd_dev *kgd, struct kgd_mem *mem);

static uint64_t get_vmem_size(struct kgd_dev *kgd);
static uint64_t get_gpu_clock_counter(struct kgd_dev *kgd);

static void lock_srbm_gfx_cntl(struct kgd_dev *kgd);
static void unlock_srbm_gfx_cntl(struct kgd_dev *kgd);

static void lock_grbm_gfx_idx(struct kgd_dev *kgd);
static void unlock_grbm_gfx_idx(struct kgd_dev *kgd);

static uint32_t get_max_engine_clock_in_mhz(struct kgd_dev *kgd);

/*
 * Register access functions
 */

static void kgd_program_sh_mem_settings(struct kgd_dev *kgd, uint32_t vmid, uint32_t sh_mem_config,
		uint32_t sh_mem_ape1_base, uint32_t sh_mem_ape1_limit, uint32_t sh_mem_bases);
static int kgd_set_pasid_vmid_mapping(struct kgd_dev *kgd, unsigned int pasid, unsigned int vmid);
static int kgd_init_memory(struct kgd_dev *kgd);
static int kgd_init_pipeline(struct kgd_dev *kgd, uint32_t pipe_id, uint32_t hpd_size, uint64_t hpd_gpu_addr);
static int kgd_hqd_load(struct kgd_dev *kgd, void *mqd, uint32_t pipe_id, uint32_t queue_id, uint32_t __user *wptr);
static bool kgd_hqd_is_occupies(struct kgd_dev *kgd, uint64_t queue_address, uint32_t pipe_id, uint32_t queue_id);
static int kgd_hqd_destroy(struct kgd_dev *kgd, bool is_reset, unsigned int timeout,
				uint32_t pipe_id, uint32_t queue_id);

static const struct kfd2kgd_calls kfd2kgd = {
	.allocate_mem = allocate_mem,
	.free_mem = free_mem,
	.gpumap_mem = gpumap_mem,
	.ungpumap_mem = ungpumap_mem,
	.kmap_mem = kmap_mem,
	.unkmap_mem = unkmap_mem,
	.get_vmem_size = get_vmem_size,
	.get_gpu_clock_counter = get_gpu_clock_counter,
	.lock_srbm_gfx_cntl = lock_srbm_gfx_cntl,
	.unlock_srbm_gfx_cntl = unlock_srbm_gfx_cntl,
	.lock_grbm_gfx_idx = lock_grbm_gfx_idx,
	.unlock_grbm_gfx_idx = unlock_grbm_gfx_idx,
	.get_max_engine_clock_in_mhz = get_max_engine_clock_in_mhz,
	.program_sh_mem_settings = kgd_program_sh_mem_settings,
	.set_pasid_vmid_mapping = kgd_set_pasid_vmid_mapping,
	.init_memory = kgd_init_memory,
	.init_pipeline = kgd_init_pipeline,
	.hqd_load = kgd_hqd_load,
	.hqd_is_occupies = kgd_hqd_is_occupies,
	.hqd_destroy = kgd_hqd_destroy,
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

static int allocate_mem(struct kgd_dev *kgd, size_t size, size_t alignment,
		enum kgd_memory_pool pool, struct kgd_mem **memory_handle)
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

	/*
	 * ttm_bo_reserve can only fail if the buffer reservation lock
	 * is held in circumstances that would deadlock
	 */
	BUG_ON(r != 0);
	r = radeon_bo_pin(mem->bo, mem->domain, vmid0_address);
	radeon_bo_unreserve(mem->bo);

	return r;
}

static void ungpumap_mem(struct kgd_dev *kgd, struct kgd_mem *mem)
{
	int r;

	r = radeon_bo_reserve(mem->bo, true);

	/*
	 * ttm_bo_reserve can only fail if the buffer reservation lock
	 * is held in circumstances that would deadlock
	 */
	BUG_ON(r != 0);
	r = radeon_bo_unpin(mem->bo);

	/*
	 * This unpin only removed NO_EVICT placement flags
	 * and should never fail
	 */
	BUG_ON(r != 0);
	radeon_bo_unreserve(mem->bo);
}

static int kmap_mem(struct kgd_dev *kgd, struct kgd_mem *mem, void **ptr)
{
	int r;

	r = radeon_bo_reserve(mem->bo, true);

	/*
	 * ttm_bo_reserve can only fail if the buffer reservation lock
	 * is held in circumstances that would deadlock
	 */
	BUG_ON(r != 0);
	r = radeon_bo_kmap(mem->bo, ptr);
	radeon_bo_unreserve(mem->bo);

	return r;
}

static void unkmap_mem(struct kgd_dev *kgd, struct kgd_mem *mem)
{
	int r;

	r = radeon_bo_reserve(mem->bo, true);
	/*
	 * ttm_bo_reserve can only fail if the buffer reservation lock
	 * is held in circumstances that would deadlock
	 */
	BUG_ON(r != 0);
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
 * kfd/radeon registers access interface
 */

inline uint32_t lower_32(uint64_t x)
{
	return (uint32_t)x;
}

inline uint32_t upper_32(uint64_t x)
{
	return (uint32_t)(x >> 32);
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

static void lock_srbm(struct kgd_dev *kgd, uint32_t mec, uint32_t pipe, uint32_t queue, uint32_t vmid)
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

static void acquire_queue(struct kgd_dev *kgd, uint32_t pipe_id, uint32_t queue_id)
{
	uint32_t mec = (++pipe_id / CIK_PIPE_PER_MEC) + 1;
	uint32_t pipe = (pipe_id % CIK_PIPE_PER_MEC);

	lock_srbm(kgd, mec, pipe, queue_id, 0);
}

static void release_queue(struct kgd_dev *kgd)
{
	unlock_srbm(kgd);
}

static void kgd_program_sh_mem_settings(struct kgd_dev *kgd, uint32_t vmid, uint32_t sh_mem_config,
		uint32_t sh_mem_ape1_base, uint32_t sh_mem_ape1_limit, uint32_t sh_mem_bases)
{
	lock_srbm(kgd, 0, 0, 0, vmid);

	write_register(kgd, SH_MEM_CONFIG, sh_mem_config);
	write_register(kgd, SH_MEM_APE1_BASE, sh_mem_ape1_base);
	write_register(kgd, SH_MEM_APE1_LIMIT, sh_mem_ape1_limit);
	write_register(kgd, SH_MEM_BASES, sh_mem_bases);

	unlock_srbm(kgd);
}

static int kgd_set_pasid_vmid_mapping(struct kgd_dev *kgd, unsigned int pasid, unsigned int vmid)
{
	/* We have to assume that there is no outstanding mapping.
	 * The ATC_VMID_PASID_MAPPING_UPDATE_STATUS bit could be 0 because a mapping
	 * is in progress or because a mapping finished and the SW cleared it.
	 * So the protocol is to always wait & clear.
	 */
	uint32_t pasid_mapping = (pasid == 0) ? 0 : (uint32_t)pasid | ATC_VMID_PASID_MAPPING_VALID;

	write_register(kgd, ATC_VMID0_PASID_MAPPING + vmid*sizeof(uint32_t), pasid_mapping);

	while (!(read_register(kgd, ATC_VMID_PASID_MAPPING_UPDATE_STATUS) & (1U << vmid)))
		cpu_relax();
	write_register(kgd, ATC_VMID_PASID_MAPPING_UPDATE_STATUS, 1U << vmid);

	return 0;
}

static int kgd_init_memory(struct kgd_dev *kgd)
{
	/* Configure apertures:
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

static int kgd_init_pipeline(struct kgd_dev *kgd, uint32_t pipe_id, uint32_t hpd_size, uint64_t hpd_gpu_addr)
{
	uint32_t mec = (++pipe_id / CIK_PIPE_PER_MEC) + 1;
	uint32_t pipe = (pipe_id % CIK_PIPE_PER_MEC);

	lock_srbm(kgd, mec, pipe, 0, 0);
	write_register(kgd, CP_HPD_EOP_BASE_ADDR, lower_32(hpd_gpu_addr >> 8));
	write_register(kgd, CP_HPD_EOP_BASE_ADDR_HI, upper_32(hpd_gpu_addr >> 8));
	write_register(kgd, CP_HPD_EOP_VMID, 0);
	write_register(kgd, CP_HPD_EOP_CONTROL, hpd_size);
	unlock_srbm(kgd);

	return 0;
}

static inline struct cik_mqd *get_mqd(void *mqd)
{
	return (struct cik_mqd *)mqd;
}

static int kgd_hqd_load(struct kgd_dev *kgd, void *mqd, uint32_t pipe_id, uint32_t queue_id, uint32_t __user *wptr)
{
	uint32_t wptr_shadow, is_wptr_shadow_valid;
	struct cik_mqd *m;

	m = get_mqd(mqd);

	is_wptr_shadow_valid = !get_user(wptr_shadow, wptr);

	acquire_queue(kgd, pipe_id, queue_id);
	write_register(kgd, CP_MQD_BASE_ADDR, m->queue_state.cp_mqd_base_addr);
	write_register(kgd, CP_MQD_BASE_ADDR_HI, m->queue_state.cp_mqd_base_addr_hi);
	write_register(kgd, CP_MQD_CONTROL, m->queue_state.cp_mqd_control);

	write_register(kgd, CP_HQD_PQ_BASE, m->queue_state.cp_hqd_pq_base);
	write_register(kgd, CP_HQD_PQ_BASE_HI, m->queue_state.cp_hqd_pq_base_hi);
	write_register(kgd, CP_HQD_PQ_CONTROL, m->queue_state.cp_hqd_pq_control);

	write_register(kgd, CP_HQD_IB_CONTROL, m->queue_state.cp_hqd_ib_control);
	write_register(kgd, CP_HQD_IB_BASE_ADDR, m->queue_state.cp_hqd_ib_base_addr);
	write_register(kgd, CP_HQD_IB_BASE_ADDR_HI, m->queue_state.cp_hqd_ib_base_addr_hi);

	write_register(kgd, CP_HQD_IB_RPTR, m->queue_state.cp_hqd_ib_rptr);

	write_register(kgd, CP_HQD_PERSISTENT_STATE, m->queue_state.cp_hqd_persistent_state);
	write_register(kgd, CP_HQD_SEMA_CMD, m->queue_state.cp_hqd_sema_cmd);
	write_register(kgd, CP_HQD_MSG_TYPE, m->queue_state.cp_hqd_msg_type);

	write_register(kgd, CP_HQD_ATOMIC0_PREOP_LO, m->queue_state.cp_hqd_atomic0_preop_lo);
	write_register(kgd, CP_HQD_ATOMIC0_PREOP_HI, m->queue_state.cp_hqd_atomic0_preop_hi);
	write_register(kgd, CP_HQD_ATOMIC1_PREOP_LO, m->queue_state.cp_hqd_atomic1_preop_lo);
	write_register(kgd, CP_HQD_ATOMIC1_PREOP_HI, m->queue_state.cp_hqd_atomic1_preop_hi);

	write_register(kgd, CP_HQD_PQ_RPTR_REPORT_ADDR, m->queue_state.cp_hqd_pq_rptr_report_addr);
	write_register(kgd, CP_HQD_PQ_RPTR_REPORT_ADDR_HI, m->queue_state.cp_hqd_pq_rptr_report_addr_hi);
	write_register(kgd, CP_HQD_PQ_RPTR, m->queue_state.cp_hqd_pq_rptr);

	write_register(kgd, CP_HQD_PQ_WPTR_POLL_ADDR, m->queue_state.cp_hqd_pq_wptr_poll_addr);
	write_register(kgd, CP_HQD_PQ_WPTR_POLL_ADDR_HI, m->queue_state.cp_hqd_pq_wptr_poll_addr_hi);

	write_register(kgd, CP_HQD_PQ_DOORBELL_CONTROL, m->queue_state.cp_hqd_pq_doorbell_control);

	write_register(kgd, CP_HQD_VMID, m->queue_state.cp_hqd_vmid);

	write_register(kgd, CP_HQD_QUANTUM, m->queue_state.cp_hqd_quantum);

	write_register(kgd, CP_HQD_PIPE_PRIORITY, m->queue_state.cp_hqd_pipe_priority);
	write_register(kgd, CP_HQD_QUEUE_PRIORITY, m->queue_state.cp_hqd_queue_priority);

	write_register(kgd, CP_HQD_HQ_SCHEDULER0, m->queue_state.cp_hqd_hq_scheduler0);
	write_register(kgd, CP_HQD_HQ_SCHEDULER1, m->queue_state.cp_hqd_hq_scheduler1);

	if (is_wptr_shadow_valid)
		write_register(kgd, CP_HQD_PQ_WPTR, wptr_shadow);

	write_register(kgd, CP_HQD_ACTIVE, m->queue_state.cp_hqd_active);
	release_queue(kgd);

	return 0;
}

static bool kgd_hqd_is_occupies(struct kgd_dev *kgd, uint64_t queue_address, uint32_t pipe_id, uint32_t queue_id)
{
	uint32_t act;
	bool retval = false;
	uint32_t low, high;

	acquire_queue(kgd, pipe_id, queue_id);
	act = read_register(kgd, CP_HQD_ACTIVE);
	if (act) {
		low = lower_32(queue_address >> 8);
		high = upper_32(queue_address >> 8);

		if (low == read_register(kgd, CP_HQD_PQ_BASE) &&
				high == read_register(kgd, CP_HQD_PQ_BASE_HI))
			retval = true;
	}
	release_queue(kgd);
	return retval;
}

static int kgd_hqd_destroy(struct kgd_dev *kgd, bool is_reset,
				unsigned int timeout, uint32_t pipe_id,
				uint32_t queue_id)
{
	int status = 0;
	bool sync = (timeout > 0) ? true : false;

	acquire_queue(kgd, pipe_id, queue_id);
	write_register(kgd, CP_HQD_PQ_DOORBELL_CONTROL, 0);

	if (is_reset)
		write_register(kgd, CP_HQD_DEQUEUE_REQUEST, DEQUEUE_REQUEST_RESET);
	else
		write_register(kgd, CP_HQD_DEQUEUE_REQUEST, DEQUEUE_REQUEST_DRAIN);


	while (read_register(kgd, CP_HQD_ACTIVE) != 0) {
		if (sync && timeout <= 0) {
			status = -EBUSY;
			break;
		}
		msleep(20);
		if (sync) {
			if (timeout >= 20)
				timeout -= 20;
			else
				timeout = 0;
		}
	}
	release_queue(kgd);
	return status;
}
