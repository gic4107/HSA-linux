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

	retval = radeon_kfd_vidmem_alloc_map(
				mm->dev,
				mqd_mem_obj,
				(void **)&m,
				&addr,
				ALIGN(sizeof(struct cik_mqd), 256));

	if (retval != 0)
		return -ENOMEM;

	memset(m, 0, sizeof(struct cik_mqd));

	m->header = 0xC0310800;
	m->pipeline_stat_enable = 1;
	m->static_thread_mgmt01[0] = 0xFFFFFFFF;
	m->static_thread_mgmt01[1] = 0xFFFFFFFF;
	m->static_thread_mgmt23[0] = 0xFFFFFFFF;
	m->static_thread_mgmt23[1] = 0xFFFFFFFF;

	m->queue_state.cp_hqd_persistent_state = DEFAULT_CP_HQD_PERSISTENT_STATE;

	m->queue_state.cp_mqd_control             = MQD_CONTROL_PRIV_STATE_EN;
	m->queue_state.cp_mqd_base_addr           = lower_32(addr);
	m->queue_state.cp_mqd_base_addr_hi        = upper_32(addr);

	m->queue_state.cp_hqd_ib_control = DEFAULT_MIN_IB_AVAIL_SIZE | IB_ATC_EN;
	/* Although WinKFD writes this, I suspect it should not be necessary. */
	m->queue_state.cp_hqd_ib_control = IB_ATC_EN | DEFAULT_MIN_IB_AVAIL_SIZE;

	m->queue_state.cp_hqd_quantum = QUANTUM_EN | QUANTUM_SCALE_1MS | QUANTUM_DURATION(10);

	m->queue_state.cp_hqd_pipe_priority = 1;
	m->queue_state.cp_hqd_queue_priority = 15;

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

static int load_mqd(struct mqd_manager *mm, void *mqd, uint32_t pipe_id, uint32_t queue_id, uint32_t __user *wptr)
{
	return kfd2kgd->hqd_load(mm->dev->kgd, mqd, pipe_id, queue_id, wptr);

}

static int update_mqd(struct mqd_manager *mm, void *mqd, struct queue_properties *q)
{
	struct cik_mqd *m;

	BUG_ON(!mm || !q || !mqd);

	pr_debug("kfd: In func %s\n", __func__);

	m = get_mqd(mqd);
	m->queue_state.cp_hqd_pq_control = DEFAULT_RPTR_BLOCK_SIZE | DEFAULT_MIN_AVAIL_SIZE | PQ_ATC_EN;
	/* calculating queue size which is log base 2 of actual queue size -1 dwords and another -1 for ffs */
	m->queue_state.cp_hqd_pq_control |= ffs(q->queue_size / sizeof(unsigned int)) - 1 - 1;
	m->queue_state.cp_hqd_pq_base = lower_32((uint64_t)q->queue_address >> 8);
	m->queue_state.cp_hqd_pq_base_hi = upper_32((uint64_t)q->queue_address >> 8);
	m->queue_state.cp_hqd_pq_rptr_report_addr = lower_32((uint64_t)q->read_ptr);
	m->queue_state.cp_hqd_pq_rptr_report_addr_hi = upper_32((uint64_t)q->read_ptr);
	m->queue_state.cp_hqd_pq_doorbell_control = DOORBELL_EN | DOORBELL_OFFSET(q->doorbell_off);

	m->queue_state.cp_hqd_vmid = q->vmid;

	m->queue_state.cp_hqd_active = 0;
	q->is_active = false;
	if (q->queue_size > 0 &&
			q->queue_address != 0 &&
			q->queue_percent > 0) {
		m->queue_state.cp_hqd_active = 1;
		q->is_active = true;
	}

	return 0;
}

static int destroy_mqd(struct mqd_manager *mm, bool is_reset, unsigned int timeout, uint32_t pipe_id, uint32_t queue_id)
{
	return kfd2kgd->hqd_destroy(mm->dev->kgd, is_reset, timeout, pipe_id, queue_id);
}

bool is_occupied(struct mqd_manager *mm, uint64_t queue_address, uint32_t pipe_id, uint32_t queue_id)
{

	return kfd2kgd->hqd_is_occupies(mm->dev->kgd, queue_address, pipe_id, queue_id);

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

	retval = radeon_kfd_vidmem_alloc_map(
				mm->dev,
				mqd_mem_obj,
				(void **)&m,
				&addr,
				ALIGN(sizeof(struct cik_mqd), PAGE_SIZE));

	if (retval != 0)
		return -ENOMEM;

	memset(m, 0, sizeof(struct cik_mqd));

	m->header = 0xC0310800;
	m->pipeline_stat_enable = 1;
	m->static_thread_mgmt01[0] = 0xFFFFFFFF;
	m->static_thread_mgmt01[1] = 0xFFFFFFFF;
	m->static_thread_mgmt23[0] = 0xFFFFFFFF;
	m->static_thread_mgmt23[1] = 0xFFFFFFFF;

	m->queue_state.cp_hqd_persistent_state = DEFAULT_CP_HQD_PERSISTENT_STATE;

	m->queue_state.cp_mqd_control             = MQD_CONTROL_PRIV_STATE_EN;
	m->queue_state.cp_mqd_base_addr           = lower_32(addr);
	m->queue_state.cp_mqd_base_addr_hi        = upper_32(addr);

	m->queue_state.cp_hqd_ib_control = DEFAULT_MIN_IB_AVAIL_SIZE;

	m->queue_state.cp_hqd_quantum = QUANTUM_EN | QUANTUM_SCALE_1MS | QUANTUM_DURATION(10);

	m->queue_state.cp_hqd_pipe_priority = 1;
	m->queue_state.cp_hqd_queue_priority = 15;

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
	m->queue_state.cp_hqd_pq_control = DEFAULT_RPTR_BLOCK_SIZE | DEFAULT_MIN_AVAIL_SIZE | PRIV_STATE | KMD_QUEUE;
	/* calculating queue size which is log base 2 of actual queue size -1 dwords */
	m->queue_state.cp_hqd_pq_control |= ffs(q->queue_size / sizeof(unsigned int)) - 1 - 1;
	m->queue_state.cp_hqd_pq_base = lower_32((uint64_t)q->queue_address >> 8);
	m->queue_state.cp_hqd_pq_base_hi = upper_32((uint64_t)q->queue_address >> 8);
	m->queue_state.cp_hqd_pq_rptr_report_addr = lower_32((uint64_t)q->read_ptr);
	m->queue_state.cp_hqd_pq_rptr_report_addr_hi = upper_32((uint64_t)q->read_ptr);
	m->queue_state.cp_hqd_pq_doorbell_control = DOORBELL_EN | DOORBELL_OFFSET(q->doorbell_off);

	m->queue_state.cp_hqd_vmid = q->vmid;

	m->queue_state.cp_hqd_active = 0;
	q->is_active = false;
	if (q->queue_size > 0 &&
			q->queue_address != 0 &&
			q->queue_percent > 0) {
		m->queue_state.cp_hqd_active = 1;
		q->is_active = true;
	}

	return 0;
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
		mqd->is_occupied = is_occupied;
		break;
	case KFD_MQD_TYPE_CIK_HIQ:
		mqd->init_mqd = init_mqd_hiq;
		mqd->uninit_mqd = uninit_mqd;
		mqd->load_mqd = load_mqd;
		mqd->update_mqd = update_mqd_hiq;
		mqd->destroy_mqd = destroy_mqd;
		mqd->is_occupied = is_occupied;
		break;
	default:
		kfree(mqd);
		return NULL;
		break;
	}

	return mqd;
}

/* SDMA queues should be implemented here when the cp will supports them */
