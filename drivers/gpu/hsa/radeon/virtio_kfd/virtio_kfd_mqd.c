#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include "virtio_kfd_priv.h"

inline uint32_t lower_32(uint64_t x)
{
	return (uint32_t)x;
}

inline uint32_t upper_32(uint64_t x)
{
	return (uint32_t)(x >> 32);
}

struct cik_mqd *mqd_create(struct queue_properties *q)
{
    struct cik_mqd *m;
    int ret = 0;

    m = kzalloc(sizeof(struct cik_mqd), GFP_KERNEL);

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
	m->cp_mqd_base_addr_lo        = lower_32(m);
	m->cp_mqd_base_addr_hi        = upper_32(m);

	m->cp_hqd_ib_control = DEFAULT_MIN_IB_AVAIL_SIZE | IB_ATC_EN;
	/* Although WinKFD writes this, I suspect it should not be necessary. */
	m->cp_hqd_ib_control = IB_ATC_EN | DEFAULT_MIN_IB_AVAIL_SIZE;

	m->cp_hqd_pipe_priority = 1;
	m->cp_hqd_queue_priority = 15;

	m->cp_hqd_pq_control = DEFAULT_RPTR_BLOCK_SIZE | DEFAULT_MIN_AVAIL_SIZE | PQ_ATC_EN;
	/* calculating queue size which is log base 2 of actual queue size -1 dwords and another -1 for ffs */
	m->cp_hqd_pq_control |= ffs(q->queue_size / sizeof(unsigned int)) - 1 - 1;
	m->cp_hqd_pq_base_lo = lower_32((uint64_t)q->queue_address >> 8);
	m->cp_hqd_pq_base_hi = upper_32((uint64_t)q->queue_address >> 8);
	m->cp_hqd_pq_rptr_report_addr_lo = lower_32((uint64_t)q->read_ptr);
	m->cp_hqd_pq_rptr_report_addr_hi = upper_32((uint64_t)q->read_ptr);
//	m->cp_hqd_pq_doorbell_control = DOORBELL_EN | DOORBELL_OFFSET(q->doorbell_off);     // let host fill in

//	m->cp_hqd_vmid = q->vmid;   // let host fill in

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

    printk("mqd_create: m=%llx\n", m);

    return m;
}
