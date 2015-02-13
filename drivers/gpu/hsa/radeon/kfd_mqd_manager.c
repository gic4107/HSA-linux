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
 */

#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include "kfd_priv.h"
#include "kfd_mqd_manager.h"
#include "cik_mqds.h"
#include "cik_regs.h"

inline uint32_t lower_32(uint64_t x)
{
	return (uint32_t)x;
}

inline uint32_t upper_32(uint64_t x)
{
	return (uint32_t)(x >> 32);
}

inline void busy_wait(unsigned long ms)
{
	while (time_before(jiffies, ms))
		cpu_relax();
}

static inline struct cik_mqd *get_mqd(void *mqd)
{
	return (struct cik_mqd *)mqd;
}

static int init_mqd(struct mqd_manager *mm, void **mqd, kfd_mem_obj *mqd_mem_obj,
		uint64_t *gart_addr, struct queue_properties *q)
{
	uint64_t addr;
	struct cik_mqd *m;
	int retval;
	BUG_ON(!mm || !q || !mqd);

	pr_debug("kfd: In func %s\n", __func__);

	retval = 0;
	retval = radeon_kfd_vidmem_alloc_map(mm->dev, mqd_mem_obj, (void **)&m, &addr, ALIGN(sizeof(struct cik_mqd), 256));
	if (retval != 0)
		return -ENOMEM;

	memset(m, 0, ALIGN(sizeof(struct cik_mqd), 256));

	m->header = 0xC0310800;
	m->compute_pipelinestat_enable = 1;
	m->compute_static_thread_mgmt_se0 = 0xFFFFFFFF;
	m->compute_static_thread_mgmt_se1 = 0xFFFFFFFF;
	m->compute_static_thread_mgmt_se2 = 0xFFFFFFFF;
	m->compute_static_thread_mgmt_se3 = 0xFFFFFFFF;

	/*
	 * Make sure to use the last queue state saved on mqd when the cp reassigns the queue,
	 * so when queue is switched on/off (e.g over subscription or quantum timeout) the context will be consistent
	 */
	m->cp_hqd_persistent_state = DEFAULT_CP_HQD_PERSISTENT_STATE | PRELOAD_REQ;
	m->cp_hqd_quantum = QUANTUM_EN | QUANTUM_SCALE_1MS | QUANTUM_DURATION(10);

	m->cp_mqd_control             = MQD_CONTROL_PRIV_STATE_EN;
	m->cp_mqd_base_addr_lo        = lower_32(addr);
	m->cp_mqd_base_addr_hi        = upper_32(addr);

	m->cp_hqd_ib_control = DEFAULT_MIN_IB_AVAIL_SIZE | IB_ATC_EN;
	/* Although WinKFD writes this, I suspect it should not be necessary. */
	m->cp_hqd_ib_control = IB_ATC_EN | DEFAULT_MIN_IB_AVAIL_SIZE;

	m->cp_hqd_pipe_priority = 1;
	m->cp_hqd_queue_priority = 15;

	*mqd = m;
	if (gart_addr != NULL)
		*gart_addr = addr;
	retval = mm->update_mqd(mm, m, q);

	return retval;
}

static void uninit_mqd(struct mqd_manager *mm, void *mqd, kfd_mem_obj mqd_mem_obj)
{
	BUG_ON(!mm || !mqd);
	radeon_kfd_vidmem_free_unmap(mm->dev, mqd_mem_obj);
}

static int load_mqd(struct mqd_manager *mm, void *mqd)
{
	struct cik_mqd *m;
	BUG_ON(!mm || !mqd);

	m = get_mqd(mqd);
    printk("load_mqd mm=%p, mqd=%p, m=%p\n", mm, mqd, m);

	WRITE_REG(mm->dev, CP_MQD_BASE_ADDR, m->cp_mqd_base_addr_lo);
	WRITE_REG(mm->dev, CP_MQD_BASE_ADDR_HI, m->cp_mqd_base_addr_hi);
	WRITE_REG(mm->dev, CP_MQD_CONTROL, m->cp_mqd_control);

	WRITE_REG(mm->dev, CP_HQD_PQ_BASE, m->cp_hqd_pq_base_lo);
	WRITE_REG(mm->dev, CP_HQD_PQ_BASE_HI, m->cp_hqd_pq_base_hi);
	WRITE_REG(mm->dev, CP_HQD_PQ_CONTROL, m->cp_hqd_pq_control);

	WRITE_REG(mm->dev, CP_HQD_IB_CONTROL, m->cp_hqd_ib_control);
	WRITE_REG(mm->dev, CP_HQD_IB_BASE_ADDR, m->cp_hqd_ib_base_addr_lo);
	WRITE_REG(mm->dev, CP_HQD_IB_BASE_ADDR_HI, m->cp_hqd_ib_base_addr_hi);

	WRITE_REG(mm->dev, CP_HQD_IB_RPTR, m->cp_hqd_ib_rptr);

	WRITE_REG(mm->dev, CP_HQD_PERSISTENT_STATE, m->cp_hqd_persistent_state);
	WRITE_REG(mm->dev, CP_HQD_SEMA_CMD, m->cp_hqd_sema_cmd);
	WRITE_REG(mm->dev, CP_HQD_MSG_TYPE, m->cp_hqd_msg_type);

	WRITE_REG(mm->dev, CP_HQD_ATOMIC0_PREOP_LO, m->cp_hqd_atomic0_preop_lo);
	WRITE_REG(mm->dev, CP_HQD_ATOMIC0_PREOP_HI, m->cp_hqd_atomic0_preop_hi);
	WRITE_REG(mm->dev, CP_HQD_ATOMIC1_PREOP_LO, m->cp_hqd_atomic1_preop_lo);
	WRITE_REG(mm->dev, CP_HQD_ATOMIC1_PREOP_HI, m->cp_hqd_atomic1_preop_hi);

	WRITE_REG(mm->dev, CP_HQD_PQ_RPTR_REPORT_ADDR, m->cp_hqd_pq_rptr_report_addr_lo);
	WRITE_REG(mm->dev, CP_HQD_PQ_RPTR_REPORT_ADDR_HI, m->cp_hqd_pq_rptr_report_addr_hi);
	WRITE_REG(mm->dev, CP_HQD_PQ_RPTR, m->cp_hqd_pq_rptr);

	WRITE_REG(mm->dev, CP_HQD_PQ_WPTR_POLL_ADDR, m->cp_hqd_pq_wptr_poll_addr_lo);
	WRITE_REG(mm->dev, CP_HQD_PQ_WPTR_POLL_ADDR_HI, m->cp_hqd_pq_wptr_poll_addr_hi);

	WRITE_REG(mm->dev, CP_HQD_PQ_DOORBELL_CONTROL, m->cp_hqd_pq_doorbell_control);

	WRITE_REG(mm->dev, CP_HQD_VMID, m->cp_hqd_vmid);

	WRITE_REG(mm->dev, CP_HQD_QUANTUM, m->cp_hqd_quantum);

	WRITE_REG(mm->dev, CP_HQD_PIPE_PRIORITY, m->cp_hqd_pipe_priority);
	WRITE_REG(mm->dev, CP_HQD_QUEUE_PRIORITY, m->cp_hqd_queue_priority);

	WRITE_REG(mm->dev, CP_HQD_IQ_RPTR, m->cp_hqd_iq_rptr);

	WRITE_REG(mm->dev, CP_HQD_ACTIVE, m->cp_hqd_active);

	return 0;
}

static int update_mqd(struct mqd_manager *mm, void *mqd, struct queue_properties *q)
{
	struct cik_mqd *m;
	BUG_ON(!mm || !q || !mqd);

	pr_debug("kfd: In func %s\n", __func__);

	m = get_mqd(mqd);
	m->cp_hqd_pq_control = DEFAULT_RPTR_BLOCK_SIZE | DEFAULT_MIN_AVAIL_SIZE | PQ_ATC_EN;
	/* calculating queue size which is log base 2 of actual queue size -1 dwords and another -1 for ffs */
	m->cp_hqd_pq_control |= ffs(q->queue_size / sizeof(unsigned int)) - 1 - 1;
	m->cp_hqd_pq_base_lo = lower_32((uint64_t)q->queue_address >> 8);
	m->cp_hqd_pq_base_hi = upper_32((uint64_t)q->queue_address >> 8);
	m->cp_hqd_pq_rptr_report_addr_lo = lower_32((uint64_t)q->read_ptr);
	m->cp_hqd_pq_rptr_report_addr_hi = upper_32((uint64_t)q->read_ptr);
	m->cp_hqd_pq_doorbell_control = DOORBELL_EN | DOORBELL_OFFSET(q->doorbell_off);

	m->cp_hqd_vmid = q->vmid;

	if (q->format == KFD_QUEUE_FORMAT_AQL) {
		m->cp_hqd_iq_rptr = AQL_ENABLE;
		m->cp_hqd_pq_control |= NO_UPDATE_RPTR;
	}

	m->cp_hqd_active = 0;
	q->is_active = false;
	if (q->queue_size > 0 &&
			q->queue_address != 0 &&
			q->queue_percent > 0) {
		m->cp_hqd_active = 1;
		q->is_active = true;
	}

	return 0;
}

static int destroy_mqd(struct mqd_manager *mm, void *mqd, enum kfd_preempt_type type, unsigned int timeout)
{
	int status;
	uint32_t temp;
	bool sync;

	status = 0;
	BUG_ON(!mm || !mqd);

	pr_debug("kfd: In func %s\n", __func__);

	WRITE_REG(mm->dev, CP_HQD_PQ_DOORBELL_CONTROL, 0);

	if (type == KFD_PREEMPT_TYPE_WAVEFRONT_RESET)
		WRITE_REG(mm->dev, CP_HQD_DEQUEUE_REQUEST, DEQUEUE_REQUEST_RESET);
	else
		WRITE_REG(mm->dev, CP_HQD_DEQUEUE_REQUEST, DEQUEUE_REQUEST_DRAIN);

	sync = (timeout > 0);
	temp = timeout;

	while (READ_REG(mm->dev, CP_HQD_ACTIVE) != 0) {
		if (sync && timeout <= 0) {
			status = -EBUSY;
			pr_err("kfd: cp queue preemption time out (%dms)\n", temp);
			break;
		}
		busy_wait(1000);
		if (sync)
			timeout--;
	}

	return status;
}

static inline uint32_t make_srbm_gfx_cntl_mpqv(unsigned int me, unsigned int pipe, unsigned int queue, unsigned int vmid)
{
	return QUEUEID(queue) | VMID(vmid) | MEID(me) | PIPEID(pipe);
}

static inline uint32_t get_first_pipe_offset(struct mqd_manager *mm)
{
	BUG_ON(!mm);
	return mm->dev->shared_resources.first_compute_pipe;
}

static void acquire_hqd(struct mqd_manager *mm, unsigned int pipe, unsigned int queue, unsigned int vmid)
{
	unsigned int mec, pipe_in_mec;
	BUG_ON(!mm);

	radeon_kfd_lock_srbm_index(mm->dev);

	pipe_in_mec = (pipe + get_first_pipe_offset(mm)) % 4;
	mec = (pipe + get_first_pipe_offset(mm)) / 4;
	mec++;

	printk("kfd: acquire mec: %d pipe: %d queue: %d vmid: %d\n",
			mec,
			pipe_in_mec,
			queue,
			vmid);
	pr_debug("kfd: acquire mec: %d pipe: %d queue: %d vmid: %d\n",
			mec,
			pipe_in_mec,
			queue,
			vmid);

	WRITE_REG(mm->dev, SRBM_GFX_CNTL, make_srbm_gfx_cntl_mpqv(mec,
			pipe_in_mec, queue, vmid));
}

static void release_hqd(struct mqd_manager *mm)
{
	BUG_ON(!mm);
	/* Be nice to KGD, reset indexed CP registers to the GFX pipe. */
	WRITE_REG(mm->dev, SRBM_GFX_CNTL, 0);
	radeon_kfd_unlock_srbm_index(mm->dev);
}

bool is_occupied(struct mqd_manager *mm, void *mqd, struct queue_properties *q)
{
	int act;
	struct cik_mqd *m;
	uint32_t low, high;
	BUG_ON(!mm || !mqd || !q);

	m = get_mqd(mqd);

	act = READ_REG(mm->dev, CP_HQD_ACTIVE);
	if (act) {
		low = lower_32((uint64_t)q->queue_address >> 8);
		high = upper_32((uint64_t)q->queue_address >> 8);

		if (low == READ_REG(mm->dev, CP_HQD_PQ_BASE) &&
			high == READ_REG(mm->dev, CP_HQD_PQ_BASE_HI))
			return true;
	}

	return false;
}

/*
 * HIQ MQD Implementation
 */

static int init_mqd_hiq(struct mqd_manager *mm, void **mqd, kfd_mem_obj *mqd_mem_obj,
		uint64_t *gart_addr, struct queue_properties *q)
{
	uint64_t addr;
	struct cik_mqd *m;
	int retval;
	BUG_ON(!mm || !q || !mqd || !mqd_mem_obj);

	pr_debug("kfd: In func %s\n", __func__);

	retval = 0;
	retval = radeon_kfd_vidmem_alloc_map(mm->dev, mqd_mem_obj, (void **)&m, &addr, ALIGN(sizeof(struct cik_mqd), PAGE_SIZE));
	if (retval != 0)
		return -ENOMEM;

	memset(m, 0, ALIGN(sizeof(struct cik_mqd), 256));

	m->header = 0xC0310800;
	m->compute_pipelinestat_enable = 1;
	m->compute_static_thread_mgmt_se0 = 0xFFFFFFFF;
	m->compute_static_thread_mgmt_se1 = 0xFFFFFFFF;
	m->compute_static_thread_mgmt_se2 = 0xFFFFFFFF;
	m->compute_static_thread_mgmt_se3 = 0xFFFFFFFF;

	m->cp_hqd_persistent_state = DEFAULT_CP_HQD_PERSISTENT_STATE | PRELOAD_REQ;
	m->cp_hqd_quantum = QUANTUM_EN | QUANTUM_SCALE_1MS | QUANTUM_DURATION(10);

	m->cp_mqd_control             = MQD_CONTROL_PRIV_STATE_EN;
	m->cp_mqd_base_addr_lo        = lower_32(addr);
	m->cp_mqd_base_addr_hi        = upper_32(addr);

	m->cp_hqd_ib_control = DEFAULT_MIN_IB_AVAIL_SIZE;

	m->cp_hqd_pipe_priority = 1;
	m->cp_hqd_queue_priority = 15;

	*mqd = m;
	if (gart_addr)
		*gart_addr = addr;
	retval = mm->update_mqd(mm, m, q);

	return retval;
}

static int update_mqd_hiq(struct mqd_manager *mm, void *mqd, struct queue_properties *q)
{
	struct cik_mqd *m;
	BUG_ON(!mm || !q || !mqd);

	pr_debug("kfd: In func %s\n", __func__);

	m = get_mqd(mqd);
	m->cp_hqd_pq_control = DEFAULT_RPTR_BLOCK_SIZE | DEFAULT_MIN_AVAIL_SIZE | PRIV_STATE | KMD_QUEUE;
	/* calculating queue size which is log base 2 of actual queue size -1 dwords */
	m->cp_hqd_pq_control |= ffs(q->queue_size / sizeof(unsigned int)) - 1 - 1;
	m->cp_hqd_pq_base_lo = lower_32((uint64_t)q->queue_address >> 8);
	m->cp_hqd_pq_base_hi = upper_32((uint64_t)q->queue_address >> 8);
	m->cp_hqd_pq_rptr_report_addr_lo = lower_32((uint64_t)q->read_ptr);
	m->cp_hqd_pq_rptr_report_addr_hi = upper_32((uint64_t)q->read_ptr);
	m->cp_hqd_pq_doorbell_control = DOORBELL_EN | DOORBELL_OFFSET(q->doorbell_off);

	m->cp_hqd_vmid = q->vmid;

	m->cp_hqd_active = 0;
	q->is_active = false;
	if (q->queue_size > 0 &&
			q->queue_address != 0 &&
			q->queue_percent > 0) {
		m->cp_hqd_active = 1;
		q->is_active = true;
	}

	return 0;
}

/*
 * SDMA MQD Implementation
 */

struct cik_sdma_rlc_registers *get_sdma_mqd(void *mqd)
{
	struct cik_sdma_rlc_registers *m;
	BUG_ON(!mqd);
	m = (struct cik_sdma_rlc_registers *)mqd;
	return m;
}

inline uint32_t get_sdma_base_addr(struct cik_sdma_rlc_registers *m)
{
	uint32_t retval;
	retval = m->sdma_engine_id * KFD_CIK_SDMA_ENGINE_OFFSET + m->sdma_queue_id * KFD_CIK_SDMA_QUEUE_OFFSET;
	pr_err("kfd: sdma base address: 0x%x\n", retval);
	return retval;
}

static int init_mqd_sdma(struct mqd_manager *mm, void **mqd, kfd_mem_obj *mqd_mem_obj, uint64_t *gart_addr,
			    struct queue_properties *q)
{
	int retval;
	uint64_t addr;
	struct cik_sdma_rlc_registers *m;
	BUG_ON(!mm || !mqd || !mqd_mem_obj);

	retval = radeon_kfd_vidmem_alloc_map(mm->dev, mqd_mem_obj, (void **)&m, &addr, sizeof(struct cik_sdma_rlc_registers));
	if (retval != 0)
		return -ENOMEM;

	memset(m, 0, sizeof(struct cik_sdma_rlc_registers));

	*mqd = (void **)m;
	if (gart_addr)
		*gart_addr = addr;

	retval = mm->update_mqd(mm, *mqd, q);

	return retval;
}

static int load_mqd_sdma(struct mqd_manager *mm, void *mqd)
{
	struct cik_sdma_rlc_registers *m;
	uint32_t sdma_base_addr;
	BUG_ON(!mm || !mqd);

	m = get_sdma_mqd(mqd);
	sdma_base_addr = get_sdma_base_addr(m);

	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_VIRTUAL_ADDR, m->sdma_rlc_virtual_addr);
	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_RB_BASE, m->sdma_rlc_rb_base);
	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_RB_BASE_HI, m->sdma_rlc_rb_base_hi);
	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_RB_RPTR_ADDR_LO, m->sdma_rlc_rb_rptr_addr_lo);
	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_RB_RPTR_ADDR_HI, m->sdma_rlc_rb_rptr_addr_hi);
	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_DOORBELL, m->sdma_rlc_doorbell);
	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_RB_CNTL, m->sdma_rlc_rb_cntl);

	return 0;
}

static int update_mqd_sdma(struct mqd_manager *mm, void *mqd, struct queue_properties *q)
{
	struct cik_sdma_rlc_registers *m;
	BUG_ON(!mm || !mqd || !q);

	m = get_sdma_mqd(mqd);
	m->sdma_rlc_rb_cntl = RB_SIZE((ffs(q->queue_size / sizeof(unsigned int)))) | RB_VMID(q->vmid)
			| RPTR_WRITEBACK_ENABLE | RPTR_WRITEBACK_TIMER(6);
	m->sdma_rlc_rb_base = lower_32(q->queue_address >> 8);
	m->sdma_rlc_rb_base_hi = upper_32(q->queue_address >> 8);
	m->sdma_rlc_rb_rptr_addr_lo = lower_32((uint64_t)q->read_ptr);
	m->sdma_rlc_rb_rptr_addr_hi = upper_32((uint64_t)q->read_ptr);
	m->sdma_rlc_doorbell = OFFSET(q->doorbell_off) | ENABLE;
	m->sdma_rlc_virtual_addr = q->sdma_vm_addr;

	m->sdma_engine_id = q->sdma_engine_id;
	m->sdma_queue_id = q->sdma_queue_id;

	q->is_active = false;
	if (q->queue_size > 0 &&
			q->queue_address != 0 &&
			q->queue_percent > 0) {
		m->sdma_rlc_rb_cntl |= RB_ENABLE;
		q->is_active = true;
	}

	return 0;
}

/*
 * preempt type here is ignored because there is only one way to preempt sdma queue
 */
static int destroy_mqd_sdma(struct mqd_manager *mm, void *mqd, enum kfd_preempt_type type, unsigned int timeout)
{
	struct cik_sdma_rlc_registers *m;
	uint32_t sdma_base_addr;
	uint32_t temp;
	BUG_ON(!mm || !mqd);

	m = get_sdma_mqd(mqd);
	sdma_base_addr = get_sdma_base_addr(m);

	temp = READ_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_RB_CNTL);
	temp = temp & ~RB_ENABLE;
	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_RB_CNTL, temp);

	while (true) {
		temp = READ_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_CONTEXT_STATUS);
		if (temp & IDLE)
			break;
		if (timeout == 0)
			return -ETIME;
		msleep(20);
		timeout -= 20;
	}

	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_DOORBELL, 0);
	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_RB_RPTR, 0);
	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_RB_WPTR, 0);
	WRITE_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_RB_BASE, 0);

	return 0;
}

static void uninit_mqd_sdma(struct mqd_manager *mm, void *mqd, kfd_mem_obj mqd_mem_obj)
{
	BUG_ON(!mm || !mqd);
	radeon_kfd_vidmem_free_unmap(mm->dev, mqd_mem_obj);
}

/* empty stub - not used in sdma */
static void acquire_hqd_sdma(struct mqd_manager *mm, unsigned int pipe, unsigned int queue, unsigned int vmid)
{
	BUG_ON(!mm);
}

/* empty stub - not used in sdma */
static void release_hqd_sdma(struct mqd_manager *mm)
{
	BUG_ON(!mm);
}

static bool is_occupied_sdma(struct mqd_manager *mm, void *mqd, struct queue_properties *q)
{
	struct cik_sdma_rlc_registers *m;
	uint32_t sdma_base_addr;
	uint32_t sdma_rlc_rb_cntl;
	BUG_ON(!mm || !mqd);

	m = get_sdma_mqd(mqd);
	sdma_base_addr = get_sdma_base_addr(m);

	sdma_rlc_rb_cntl = READ_REG(mm->dev, sdma_base_addr + SDMA0_RLC0_RB_CNTL);

	if (sdma_rlc_rb_cntl & RB_ENABLE)
		return true;

	return false;
}

struct mqd_manager *mqd_manager_init(enum KFD_MQD_TYPE type, struct kfd_dev *dev)
{
	struct mqd_manager *mqd;
	BUG_ON(!dev);
	BUG_ON(type >= KFD_MQD_TYPE_MAX);

	pr_debug("kfd: In func %s\n", __func__);

	mqd = kzalloc(sizeof(struct mqd_manager), GFP_KERNEL);
	if (!mqd)
		return NULL;

	mqd->dev = dev;

	switch (type) {
	case KFD_MQD_TYPE_CIK_CP:
	case KFD_MQD_TYPE_CIK_COMPUTE:
		mqd->init_mqd = init_mqd;
		mqd->uninit_mqd = uninit_mqd;
		mqd->load_mqd = load_mqd;
		mqd->update_mqd = update_mqd;
		mqd->destroy_mqd = destroy_mqd;
		mqd->acquire_hqd = acquire_hqd;
		mqd->release_hqd = release_hqd;
		mqd->is_occupied = is_occupied;
		break;
	case KFD_MQD_TYPE_CIK_HIQ:
		mqd->init_mqd = init_mqd_hiq;
		mqd->uninit_mqd = uninit_mqd;
		mqd->load_mqd = load_mqd;
		mqd->update_mqd = update_mqd_hiq;
		mqd->destroy_mqd = destroy_mqd;
		mqd->acquire_hqd = acquire_hqd;
		mqd->release_hqd = release_hqd;
		mqd->is_occupied = is_occupied;
		break;
	case KFD_MQD_TYPE_CIK_SDMA:
		mqd->init_mqd = init_mqd_sdma;
		mqd->uninit_mqd = uninit_mqd_sdma;
		mqd->load_mqd = load_mqd_sdma;
		mqd->update_mqd = update_mqd_sdma;
		mqd->destroy_mqd = destroy_mqd_sdma;
		mqd->acquire_hqd = acquire_hqd_sdma;
		mqd->release_hqd = release_hqd_sdma;
		mqd->is_occupied = is_occupied_sdma;
		break;
	default:
		kfree(mqd);
		return NULL;
		break;
	}

	return mqd;
}

/* SDMA queues should be implemented here when the cp will supports them */
