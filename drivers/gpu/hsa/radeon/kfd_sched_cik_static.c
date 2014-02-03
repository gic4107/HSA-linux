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

#include <linux/log2.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/sched.h>
#include "kfd_priv.h"
#include "kfd_scheduler.h"
#include "cik_regs.h"
#include "cik_int.h"

/* CIK CP hardware is arranged with 8 queues per pipe and 8 pipes per MEC (microengine for compute).
 * The first MEC is ME 1 with the GFX ME as ME 0.
 * We split the CP with the KGD, they take the first N pipes and we take the rest.
 */
#define CIK_QUEUES_PER_PIPE 8
#define CIK_PIPES_PER_MEC 4

#define CIK_MAX_PIPES (2 * CIK_PIPES_PER_MEC)

#define CIK_NUM_VMID 16

#define CIK_HPD_SIZE_LOG2 11
#define CIK_HPD_SIZE (1U << CIK_HPD_SIZE_LOG2)
#define CIK_HPD_ALIGNMENT 256
#define CIK_MQD_ALIGNMENT 4

#pragma pack(push, 4)

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

struct cik_mqd_padded {
	struct cik_mqd mqd;
	u8 padding[1024 - sizeof(struct cik_mqd)]; /* Pad MQD out to 1KB. (HW requires 4-byte alignment.) */
};

#pragma pack(pop)

struct cik_static_private {
	struct kfd_dev *dev;

	struct mutex mutex;

	unsigned int first_pipe;
	unsigned int num_pipes;

	unsigned long free_vmid_mask; /* unsigned long to make set/clear_bit happy */

	/* Everything below here is offset by first_pipe. E.g. bit 0 in free_queues is queue 0 in pipe first_pipe. */

	 /* Queue q on pipe p is at bit QUEUES_PER_PIPE * p + q. */
	unsigned long free_queues[DIV_ROUND_UP(CIK_MAX_PIPES * CIK_QUEUES_PER_PIPE, BITS_PER_LONG)];

	/*
	 * Dequeue waits for waves to finish so it could take a long time. We
	 * defer through an interrupt. dequeue_wait is woken when a dequeue-
	 * complete interrupt comes for that pipe.
	 */
	wait_queue_head_t dequeue_wait[CIK_MAX_PIPES];

	kfd_mem_obj hpd_mem;	/* Single allocation for HPDs for all KFD pipes. */
	kfd_mem_obj mqd_mem;	/* Single allocation for all MQDs for all KFD pipes. This is actually struct cik_mqd_padded. */
	uint64_t hpd_addr;	/* GPU address for hpd_mem. */
	uint64_t mqd_addr;	/* GPU address for mqd_mem. */
	 /* Pointer for mqd_mem.
	  * We keep this mapped because multiple processes may need to access it
	  * in parallel and this is simpler than controlling concurrent kmaps. */
	struct cik_mqd_padded *mqds;
};

struct cik_static_process {
	unsigned int vmid;
	pasid_t pasid;
};

struct cik_static_queue {
	unsigned int queue; /* + first_pipe * QUEUES_PER_PIPE */

	uint64_t mqd_addr;
	struct cik_mqd *mqd;

	void __user *pq_addr;
	void __user *rptr_address;
	doorbell_t __user *wptr_address;
	uint32_t doorbell_index;

	uint32_t queue_size_encoded; /* CP_HQD_PQ_CONTROL.QUEUE_SIZE takes the queue size as log2(size) - 3. */
};

static uint32_t lower_32(uint64_t x)
{
	return (uint32_t)x;
}

static uint32_t upper_32(uint64_t x)
{
	return (uint32_t)(x >> 32);
}

/* SRBM_GFX_CNTL provides the MEC/pipe/queue and vmid for many registers that are
 * In particular, CP_HQD_* and CP_MQD_* are instanced for each queue. CP_HPD_* are instanced for each pipe.
 * SH_MEM_* are instanced per-VMID.
 *
 * We provide queue_select, pipe_select and vmid_select helpers that should be used before accessing
 * registers from those groups. Note that these overwrite each other, e.g. after vmid_select the current
 * selected MEC/pipe/queue is undefined.
 *
 * SRBM_GFX_CNTL and the registers it indexes are shared with KGD. You must be holding the srbm_gfx_cntl
 * lock via lock_srbm_index before setting SRBM_GFX_CNTL or accessing any of the instanced registers.
 */
static uint32_t make_srbm_gfx_cntl_mpqv(unsigned int me, unsigned int pipe, unsigned int queue, unsigned int vmid)
{
	return QUEUEID(queue) | VMID(vmid) | MEID(me) | PIPEID(pipe);
}

static void pipe_select(struct cik_static_private *priv, unsigned int pipe)
{
	unsigned int pipe_in_mec = (pipe + priv->first_pipe) % CIK_PIPES_PER_MEC;
	unsigned int mec = (pipe + priv->first_pipe) / CIK_PIPES_PER_MEC;

	WRITE_REG(priv->dev, SRBM_GFX_CNTL, make_srbm_gfx_cntl_mpqv(mec+1, pipe_in_mec, 0, 0));
}

static void queue_select(struct cik_static_private *priv, unsigned int queue)
{
	unsigned int queue_in_pipe = queue % CIK_QUEUES_PER_PIPE;
	unsigned int pipe = queue / CIK_QUEUES_PER_PIPE + priv->first_pipe;
	unsigned int pipe_in_mec = pipe % CIK_PIPES_PER_MEC;
	unsigned int mec = pipe / CIK_PIPES_PER_MEC;

#if 0
	dev_err(radeon_kfd_chardev(), "queue select %d = %u/%u/%u = 0x%08x\n", queue, mec+1, pipe_in_mec, queue_in_pipe,
		make_srbm_gfx_cntl_mpqv(mec+1, pipe_in_mec, queue_in_pipe, 0));
#endif

	WRITE_REG(priv->dev, SRBM_GFX_CNTL, make_srbm_gfx_cntl_mpqv(mec+1, pipe_in_mec, queue_in_pipe, 0));
}

static void vmid_select(struct cik_static_private *priv, unsigned int vmid)
{
	WRITE_REG(priv->dev, SRBM_GFX_CNTL, make_srbm_gfx_cntl_mpqv(0, 0, 0, vmid));
}

static void lock_srbm_index(struct cik_static_private *priv)
{
	radeon_kfd_lock_srbm_index(priv->dev);
}

static void unlock_srbm_index(struct cik_static_private *priv)
{
	WRITE_REG(priv->dev, SRBM_GFX_CNTL, 0);	/* Be nice to KGD, reset indexed CP registers to the GFX pipe. */
	radeon_kfd_unlock_srbm_index(priv->dev);
}

/* One-time setup for all compute pipes. They need to be programmed with the address & size of the HPD EOP buffer. */
static void init_pipes(struct cik_static_private *priv)
{
	unsigned int i;

	lock_srbm_index(priv);

	for (i = 0; i < priv->num_pipes; i++) {
		uint64_t pipe_hpd_addr = priv->hpd_addr + i * CIK_HPD_SIZE;

		pipe_select(priv, i);

		WRITE_REG(priv->dev, CP_HPD_EOP_BASE_ADDR, lower_32(pipe_hpd_addr >> 8));
		WRITE_REG(priv->dev, CP_HPD_EOP_BASE_ADDR_HI, upper_32(pipe_hpd_addr >> 8));
		WRITE_REG(priv->dev, CP_HPD_EOP_VMID, 0);
		WRITE_REG(priv->dev, CP_HPD_EOP_CONTROL, CIK_HPD_SIZE_LOG2 - 1);
	}

	unlock_srbm_index(priv);
}

/* Program the VMID -> PASID mapping for one VMID.
 * PASID 0 is special: it means to associate no PASID with that VMID.
 * This function waits for the VMID/PASID mapping to complete.
 */
static void set_vmid_pasid_mapping(struct cik_static_private *priv, unsigned int vmid, pasid_t pasid)
{
	/* We have to assume that there is no outstanding mapping.
	 * The ATC_VMID_PASID_MAPPING_UPDATE_STATUS bit could be 0 because a mapping
	 * is in progress or because a mapping finished and the SW cleared it.
	 * So the protocol is to always wait & clear.
	 */

	uint32_t pasid_mapping = (pasid == 0) ? 0 : (uint32_t)pasid | ATC_VMID_PASID_MAPPING_VALID;

	WRITE_REG(priv->dev, ATC_VMID0_PASID_MAPPING + vmid*sizeof(uint32_t), pasid_mapping);

	while (!(READ_REG(priv->dev, ATC_VMID_PASID_MAPPING_UPDATE_STATUS) & (1U << vmid)))
		cpu_relax();
	WRITE_REG(priv->dev, ATC_VMID_PASID_MAPPING_UPDATE_STATUS, 1U << vmid);

	WRITE_REG(priv->dev, IH_VMID_0_LUT + vmid*sizeof(uint32_t), pasid);
}

static uint32_t compute_sh_mem_bases_64bit(unsigned int top_address_nybble)
{
	/* In 64-bit mode, we can only control the top 3 bits of the LDS, scratch and GPUVM apertures.
	 * The hardware fills in the remaining 59 bits according to the following pattern:
	 * LDS:		X0000000'00000000 - X0000001'00000000 (4GB)
	 * Scratch:	X0000001'00000000 - X0000002'00000000 (4GB)
	 * GPUVM:	Y0010000'00000000 - Y0020000'00000000 (1TB)
	 *
	 * (where X/Y is the configurable nybble with the low-bit 0)
	 *
	 * LDS and scratch will have the same top nybble programmed in the top 3 bits of SH_MEM_BASES.PRIVATE_BASE.
	 * GPUVM can have a different top nybble programmed in the top 3 bits of SH_MEM_BASES.SHARED_BASE.
	 * We don't bother to support different top nybbles for LDS/Scratch and GPUVM.
	 */

	BUG_ON((top_address_nybble & 1) || top_address_nybble > 0xE);

	return PRIVATE_BASE(top_address_nybble << 12) | SHARED_BASE(top_address_nybble << 12);
}

/* Initial programming for all ATS registers.
 * - enable ATS for all compute VMIDs
 * - clear the VMID/PASID mapping for all compute VMIDS
 * - program the shader core flat address settings:
 * -- 64-bit mode
 * -- unaligned access allowed
 * -- noncached (this is the only CPU-coherent mode in CIK)
 * -- APE 1 disabled
 */
static void init_ats(struct cik_static_private *priv)
{
	unsigned int i;

	/* Enable self-ringing doorbell recognition and direct the BIF to send
	 * untranslated writes to the IOMMU before comparing to the aperture.*/
	WRITE_REG(priv->dev, BIF_DOORBELL_CNTL, 0);

	WRITE_REG(priv->dev, ATC_VM_APERTURE0_CNTL, ATS_ACCESS_MODE_ALWAYS);
	WRITE_REG(priv->dev, ATC_VM_APERTURE0_CNTL2, priv->free_vmid_mask);
	WRITE_REG(priv->dev, ATC_VM_APERTURE0_LOW_ADDR, 0);
	WRITE_REG(priv->dev, ATC_VM_APERTURE0_HIGH_ADDR, 0);

	WRITE_REG(priv->dev, ATC_VM_APERTURE1_CNTL, 0);
	WRITE_REG(priv->dev, ATC_VM_APERTURE1_CNTL2, 0);
	WRITE_REG(priv->dev, ATC_VM_APERTURE1_LOW_ADDR, 0);
	WRITE_REG(priv->dev, ATC_VM_APERTURE1_HIGH_ADDR, 0);

	lock_srbm_index(priv);

	for (i = 0; i < CIK_NUM_VMID; i++) {
		if (priv->free_vmid_mask & (1U << i)) {
			uint32_t sh_mem_config;

			set_vmid_pasid_mapping(priv, i, 0);

			vmid_select(priv, i);

			sh_mem_config = ALIGNMENT_MODE(SH_MEM_ALIGNMENT_MODE_UNALIGNED);
			sh_mem_config |= DEFAULT_MTYPE(MTYPE_NONCACHED);

			WRITE_REG(priv->dev, SH_MEM_CONFIG, sh_mem_config);

			/* Configure apertures:
			 * LDS:		0x60000000'00000000 - 0x60000001'00000000 (4GB)
			 * Scratch:	0x60000001'00000000 - 0x60000002'00000000 (4GB)
			 * GPUVM:	0x60010000'00000000 - 0x60020000'00000000 (1TB)
			 */
			WRITE_REG(priv->dev, SH_MEM_BASES, compute_sh_mem_bases_64bit(6));

			/* Scratch aperture is not supported for now. */
			WRITE_REG(priv->dev, SH_STATIC_MEM_CONFIG, 0);

			/* APE1 disabled for now. */
			WRITE_REG(priv->dev, SH_MEM_APE1_BASE, 1);
			WRITE_REG(priv->dev, SH_MEM_APE1_LIMIT, 0);
		}
	}

	unlock_srbm_index(priv);
}

static void exit_ats(struct cik_static_private *priv)
{
	unsigned int i;

	for (i = 0; i < CIK_NUM_VMID; i++)
		if (priv->free_vmid_mask & (1U << i))
			set_vmid_pasid_mapping(priv, i, 0);

	WRITE_REG(priv->dev, ATC_VM_APERTURE0_CNTL, ATS_ACCESS_MODE_NEVER);
	WRITE_REG(priv->dev, ATC_VM_APERTURE0_CNTL2, 0);
}

static struct cik_static_private *kfd_scheduler_to_private(struct kfd_scheduler *scheduler)
{
	return (struct cik_static_private *)scheduler;
}

static struct cik_static_process *kfd_process_to_private(struct kfd_scheduler_process *process)
{
	return (struct cik_static_process *)process;
}

static struct cik_static_queue *kfd_queue_to_private(struct kfd_scheduler_queue *queue)
{
	return (struct cik_static_queue *)queue;
}

static int cik_static_create(struct kfd_dev *dev, struct kfd_scheduler **scheduler)
{
	struct cik_static_private *priv;
	unsigned int i;
	int err;
	void *hpdptr;

	priv = kmalloc(sizeof(*priv), GFP_KERNEL);
	if (priv == NULL)
		return -ENOMEM;

	mutex_init(&priv->mutex);

	priv->dev = dev;

	priv->first_pipe = dev->shared_resources.first_compute_pipe;
	priv->num_pipes = dev->shared_resources.compute_pipe_count;

	for (i = 0; i < priv->num_pipes * CIK_QUEUES_PER_PIPE; i++)
		__set_bit(i, priv->free_queues);

	priv->free_vmid_mask = dev->shared_resources.compute_vmid_bitmap;

	for (i = 0; i < priv->num_pipes; i++)
		init_waitqueue_head(&priv->dequeue_wait[i]);

	/*
	 * Allocate memory for the HPDs. This is hardware-owned per-pipe data.
	 * The driver never accesses this memory after zeroing it. It doesn't even have
	 * to be saved/restored on suspend/resume because it contains no data when there
	 * are no active queues.
	 */
	err = radeon_kfd_vidmem_alloc(dev,
				      CIK_HPD_SIZE * priv->num_pipes * 2,
				      PAGE_SIZE,
				      KFD_MEMPOOL_SYSTEM_WRITECOMBINE,
				      &priv->hpd_mem);
	if (err)
		goto err_hpd_alloc;

	err = radeon_kfd_vidmem_kmap(dev, priv->hpd_mem, &hpdptr);
	if (err)
		goto err_hpd_kmap;
	memset(hpdptr, 0, CIK_HPD_SIZE * priv->num_pipes);
	radeon_kfd_vidmem_unkmap(dev, priv->hpd_mem);

	/*
	 * Allocate memory for all the MQDs.
	 * These are per-queue data that is hardware owned but with driver init.
	 * The driver has to copy this data into HQD registers when a
	 * pipe is (re)activated.
	 */
	err = radeon_kfd_vidmem_alloc(dev,
				      sizeof(struct cik_mqd_padded) * priv->num_pipes * CIK_QUEUES_PER_PIPE,
				      PAGE_SIZE,
				      KFD_MEMPOOL_SYSTEM_CACHEABLE,
				      &priv->mqd_mem);
	if (err)
		goto err_mqd_alloc;
	radeon_kfd_vidmem_kmap(dev, priv->mqd_mem, (void **)&priv->mqds);
	if (err)
		goto err_mqd_kmap;

	*scheduler = (struct kfd_scheduler *)priv;

	return 0;

err_mqd_kmap:
	radeon_kfd_vidmem_free(dev, priv->mqd_mem);
err_mqd_alloc:
err_hpd_kmap:
	radeon_kfd_vidmem_free(dev, priv->hpd_mem);
err_hpd_alloc:
	mutex_destroy(&priv->mutex);
	kfree(priv);
	return err;
}

static void cik_static_destroy(struct kfd_scheduler *scheduler)
{
	struct cik_static_private *priv = kfd_scheduler_to_private(scheduler);

	radeon_kfd_vidmem_unkmap(priv->dev, priv->mqd_mem);
	radeon_kfd_vidmem_free(priv->dev, priv->mqd_mem);
	radeon_kfd_vidmem_free(priv->dev, priv->hpd_mem);

	mutex_destroy(&priv->mutex);

	kfree(priv);
}

static void
enable_interrupts(struct cik_static_private *priv)
{
	unsigned int i;

	lock_srbm_index(priv);
	for (i = 0; i < priv->num_pipes; i++) {
		pipe_select(priv, i);
		WRITE_REG(priv->dev, CPC_INT_CNTL, DEQUEUE_REQUEST_INT_ENABLE);
	}
	unlock_srbm_index(priv);
}

static void
disable_interrupts(struct cik_static_private *priv)
{
	unsigned int i;

	lock_srbm_index(priv);
	for (i = 0; i < priv->num_pipes; i++) {
		pipe_select(priv, i);
		WRITE_REG(priv->dev, CPC_INT_CNTL, 0);
	}
	unlock_srbm_index(priv);
}

static void cik_static_start(struct kfd_scheduler *scheduler)
{
	struct cik_static_private *priv = kfd_scheduler_to_private(scheduler);

	radeon_kfd_vidmem_gpumap(priv->dev, priv->hpd_mem, &priv->hpd_addr);
	radeon_kfd_vidmem_gpumap(priv->dev, priv->mqd_mem, &priv->mqd_addr);

	init_pipes(priv);
	init_ats(priv);
	enable_interrupts(priv);
}

static void cik_static_stop(struct kfd_scheduler *scheduler)
{
	struct cik_static_private *priv = kfd_scheduler_to_private(scheduler);

	exit_ats(priv);
	disable_interrupts(priv);

	radeon_kfd_vidmem_ungpumap(priv->dev, priv->hpd_mem);
	radeon_kfd_vidmem_ungpumap(priv->dev, priv->mqd_mem);
}

static bool allocate_vmid(struct cik_static_private *priv, unsigned int *vmid)
{
	bool ok = false;

	mutex_lock(&priv->mutex);

	if (priv->free_vmid_mask != 0) {
		unsigned int v = __ffs64(priv->free_vmid_mask);
		clear_bit(v, &priv->free_vmid_mask);
		*vmid = v;

		ok = true;
	}

	mutex_unlock(&priv->mutex);

	return ok;
}

static void release_vmid(struct cik_static_private *priv, unsigned int vmid)
{
	/* It's okay to race against allocate_vmid because this only adds bits to free_vmid_mask.
	 * And set_bit/clear_bit are atomic wrt each other. */
	set_bit(vmid, &priv->free_vmid_mask);
}

static void setup_vmid_for_process(struct cik_static_private *priv, struct cik_static_process *p)
{
	set_vmid_pasid_mapping(priv, p->vmid, p->pasid);

	/* SH_MEM_CONFIG and others need to be programmed differently for 32/64-bit processes. And maybe other reasons. */
}

static int
cik_static_register_process(struct kfd_scheduler *scheduler, struct kfd_process *process,
			    struct kfd_scheduler_process **scheduler_process)
{
	struct cik_static_private *priv = kfd_scheduler_to_private(scheduler);

	struct cik_static_process *hwp;

	hwp = kmalloc(sizeof(*hwp), GFP_KERNEL);
	if (hwp == NULL)
		return -ENOMEM;

	if (!allocate_vmid(priv, &hwp->vmid)) {
		kfree(hwp);
		return -ENOMEM;
	}

	hwp->pasid = process->pasid;

	setup_vmid_for_process(priv, hwp);

	*scheduler_process = (struct kfd_scheduler_process *)hwp;

	return 0;
}

static void cik_static_deregister_process(struct kfd_scheduler *scheduler, struct kfd_scheduler_process *scheduler_process)
{
	struct cik_static_private *priv = kfd_scheduler_to_private(scheduler);
	struct cik_static_process *pp = kfd_process_to_private(scheduler_process);

	release_vmid(priv, pp->vmid);
	kfree(pp);
}

static bool allocate_hqd(struct cik_static_private *priv, unsigned int *queue)
{
	bool ok = false;
	unsigned int q;

	mutex_lock(&priv->mutex);

	q = find_first_bit(priv->free_queues, priv->num_pipes * CIK_QUEUES_PER_PIPE);

	if (q != priv->num_pipes * CIK_QUEUES_PER_PIPE) {
		clear_bit(q, priv->free_queues);
		*queue = q;

		ok = true;
	}

	mutex_unlock(&priv->mutex);

	return ok;
}

static void release_hqd(struct cik_static_private *priv, unsigned int queue)
{
	/* It's okay to race against allocate_hqd because this only adds bits to free_queues.
	 * And set_bit/clear_bit are atomic wrt each other. */
	set_bit(queue, priv->free_queues);
}

static void init_mqd(const struct cik_static_queue *queue, const struct cik_static_process *process)
{
	struct cik_mqd *mqd = queue->mqd;

	memset(mqd, 0, sizeof(*mqd));

	mqd->header = 0xC0310800;
	mqd->pipeline_stat_enable = 1;
	mqd->static_thread_mgmt01[0] = 0xffffffff;
	mqd->static_thread_mgmt01[1] = 0xffffffff;
	mqd->static_thread_mgmt23[0] = 0xffffffff;
	mqd->static_thread_mgmt23[1] = 0xffffffff;

	mqd->queue_state.cp_mqd_base_addr = lower_32(queue->mqd_addr);
	mqd->queue_state.cp_mqd_base_addr_hi = upper_32(queue->mqd_addr);
	mqd->queue_state.cp_mqd_control = MQD_CONTROL_PRIV_STATE_EN;

	mqd->queue_state.cp_hqd_pq_base = lower_32((uintptr_t)queue->pq_addr >> 8);
	mqd->queue_state.cp_hqd_pq_base_hi = upper_32((uintptr_t)queue->pq_addr >> 8);
	mqd->queue_state.cp_hqd_pq_control = QUEUE_SIZE(queue->queue_size_encoded) | DEFAULT_RPTR_BLOCK_SIZE
					    | DEFAULT_MIN_AVAIL_SIZE | PQ_ATC_EN;
	mqd->queue_state.cp_hqd_pq_rptr_report_addr = lower_32((uintptr_t)queue->rptr_address);
	mqd->queue_state.cp_hqd_pq_rptr_report_addr_hi = upper_32((uintptr_t)queue->rptr_address);
	mqd->queue_state.cp_hqd_pq_doorbell_control = DOORBELL_OFFSET(queue->doorbell_index) | DOORBELL_EN;
	mqd->queue_state.cp_hqd_vmid = process->vmid;
	mqd->queue_state.cp_hqd_active = 1;

	mqd->queue_state.cp_hqd_persistent_state = DEFAULT_CP_HQD_PERSISTENT_STATE;

	/* The values for these 3 are from WinKFD. */
	mqd->queue_state.cp_hqd_quantum = QUANTUM_EN | QUANTUM_SCALE_1MS | QUANTUM_DURATION(10);
	mqd->queue_state.cp_hqd_pipe_priority = 1;
	mqd->queue_state.cp_hqd_queue_priority = 15;

	mqd->queue_state.cp_hqd_ib_control = IB_ATC_EN | DEFAULT_MIN_IB_AVAIL_SIZE;
}

/* Write the HQD registers and activate the queue.
 * Requires that SRBM_GFX_CNTL has already been programmed for the queue.
 */
static void load_hqd(struct cik_static_private *priv, struct cik_static_queue *queue)
{
	struct kfd_dev *dev = priv->dev;
	const struct cik_hqd_registers *qs = &queue->mqd->queue_state;

	WRITE_REG(dev, CP_MQD_BASE_ADDR, qs->cp_mqd_base_addr);
	WRITE_REG(dev, CP_MQD_BASE_ADDR_HI, qs->cp_mqd_base_addr_hi);
	WRITE_REG(dev, CP_MQD_CONTROL, qs->cp_mqd_control);

	WRITE_REG(dev, CP_HQD_PQ_BASE, qs->cp_hqd_pq_base);
	WRITE_REG(dev, CP_HQD_PQ_BASE_HI, qs->cp_hqd_pq_base_hi);
	WRITE_REG(dev, CP_HQD_PQ_CONTROL, qs->cp_hqd_pq_control);
	/* DOORBELL_CONTROL before WPTR because WPTR writes are dropped if DOORBELL_HIT is set. */
	WRITE_REG(dev, CP_HQD_PQ_DOORBELL_CONTROL, qs->cp_hqd_pq_doorbell_control);
	WRITE_REG(dev, CP_HQD_PQ_WPTR, qs->cp_hqd_pq_wptr);
	WRITE_REG(dev, CP_HQD_PQ_RPTR, qs->cp_hqd_pq_rptr);
	WRITE_REG(dev, CP_HQD_PQ_RPTR_REPORT_ADDR, qs->cp_hqd_pq_rptr_report_addr);
	WRITE_REG(dev, CP_HQD_PQ_RPTR_REPORT_ADDR_HI, qs->cp_hqd_pq_rptr_report_addr_hi);

	WRITE_REG(dev, CP_HQD_VMID, qs->cp_hqd_vmid);
	WRITE_REG(dev, CP_HQD_PERSISTENT_STATE, qs->cp_hqd_persistent_state);
	WRITE_REG(dev, CP_HQD_QUANTUM, qs->cp_hqd_quantum);
	WRITE_REG(dev, CP_HQD_PIPE_PRIORITY, qs->cp_hqd_pipe_priority);
	WRITE_REG(dev, CP_HQD_QUEUE_PRIORITY, qs->cp_hqd_queue_priority);

	WRITE_REG(dev, CP_HQD_IB_CONTROL, qs->cp_hqd_ib_control);
	WRITE_REG(dev, CP_HQD_IB_BASE_ADDR, qs->cp_hqd_ib_base_addr);
	WRITE_REG(dev, CP_HQD_IB_BASE_ADDR_HI, qs->cp_hqd_ib_base_addr_hi);
	WRITE_REG(dev, CP_HQD_IB_RPTR, qs->cp_hqd_ib_rptr);
	WRITE_REG(dev, CP_HQD_SEMA_CMD, qs->cp_hqd_sema_cmd);
	WRITE_REG(dev, CP_HQD_MSG_TYPE, qs->cp_hqd_msg_type);
	WRITE_REG(dev, CP_HQD_ATOMIC0_PREOP_LO, qs->cp_hqd_atomic0_preop_lo);
	WRITE_REG(dev, CP_HQD_ATOMIC0_PREOP_HI, qs->cp_hqd_atomic0_preop_hi);
	WRITE_REG(dev, CP_HQD_ATOMIC1_PREOP_LO, qs->cp_hqd_atomic1_preop_lo);
	WRITE_REG(dev, CP_HQD_ATOMIC1_PREOP_HI, qs->cp_hqd_atomic1_preop_hi);
	WRITE_REG(dev, CP_HQD_HQ_SCHEDULER0, qs->cp_hqd_hq_scheduler0);
	WRITE_REG(dev, CP_HQD_HQ_SCHEDULER1, qs->cp_hqd_hq_scheduler1);

	WRITE_REG(dev, CP_HQD_ACTIVE, 1);
}

static void activate_queue(struct cik_static_private *priv, struct cik_static_queue *queue)
{
	bool wptr_shadow_valid;
	doorbell_t wptr_shadow;

	/* Avoid sleeping while holding the SRBM lock. */
	wptr_shadow_valid = !get_user(wptr_shadow, queue->wptr_address);

	lock_srbm_index(priv);
	queue_select(priv, queue->queue);

	load_hqd(priv, queue);

	/* Doorbell and wptr are special because there is a race when reactivating a queue.
	 * Since doorbell writes to deactivated queues are ignored by hardware, the application
	 * shadows the doorbell into memory at queue->wptr_address.
	 *
	 * We want the queue to automatically resume processing as if it were always active,
	 * so we want to copy from queue->wptr_address into the wptr/doorbell.
	 *
	 * The race is that the app could write a new wptr into the doorbell before we
	 * write the shadowed wptr, resulting in an old wptr written later.
	 *
	 * The hardware solves this ignoring CP_HQD_WPTR writes after a doorbell write.
	 * So the KFD can activate the doorbell then write the shadow wptr to CP_HQD_WPTR
	 * knowing it will be ignored if the user has written a more-recent doorbell.
	 */
	if (wptr_shadow_valid)
		WRITE_REG(priv->dev, CP_HQD_PQ_WPTR, wptr_shadow);

	unlock_srbm_index(priv);

	return;
}

static bool queue_inactive(struct cik_static_private *priv, struct cik_static_queue *queue)
{
	bool inactive;

	lock_srbm_index(priv);
	queue_select(priv, queue->queue);

	inactive = (READ_REG(priv->dev, CP_HQD_ACTIVE) == 0);

	unlock_srbm_index(priv);

	return inactive;
}

static void deactivate_queue(struct cik_static_private *priv, struct cik_static_queue *queue)
{
	lock_srbm_index(priv);
	queue_select(priv, queue->queue);

	WRITE_REG(priv->dev, CP_HQD_DEQUEUE_REQUEST, DEQUEUE_REQUEST_DRAIN | DEQUEUE_INT);

	unlock_srbm_index(priv);

	wait_event(priv->dequeue_wait[queue->queue/CIK_QUEUES_PER_PIPE],
		   queue_inactive(priv, queue));
}

#define BIT_MASK_64(high, low) (((1ULL << (high)) - 1) & ~((1ULL << (low)) - 1))
#define RING_ADDRESS_BAD_BIT_MASK (~BIT_MASK_64(48, 8))
#define RWPTR_ADDRESS_BAD_BIT_MASK (~BIT_MASK_64(48, 2))

#define MAX_QUEUE_SIZE (1ULL << 32)
#define MIN_QUEUE_SIZE (1ULL << 10)

static int
cik_static_create_queue(struct kfd_scheduler *scheduler,
			struct kfd_scheduler_process *process,
			struct kfd_scheduler_queue *queue,
			void __user *ring_address,
			uint64_t ring_size,
			void __user *rptr_address,
			void __user *wptr_address,
			unsigned int doorbell)
{
	struct cik_static_private *priv = kfd_scheduler_to_private(scheduler);
	struct cik_static_process *hwp = kfd_process_to_private(process);
	struct cik_static_queue *hwq = kfd_queue_to_private(queue);

	if ((uint64_t)ring_address & RING_ADDRESS_BAD_BIT_MASK
	    || (uint64_t)rptr_address & RWPTR_ADDRESS_BAD_BIT_MASK
	    || (uint64_t)wptr_address & RWPTR_ADDRESS_BAD_BIT_MASK)
		return -EINVAL;

	if (ring_size > MAX_QUEUE_SIZE || ring_size < MIN_QUEUE_SIZE || !is_power_of_2(ring_size))
		return -EINVAL;

	if (!allocate_hqd(priv, &hwq->queue))
		return -ENOMEM;

	hwq->mqd_addr = priv->mqd_addr + sizeof(struct cik_mqd_padded) * hwq->queue;
	hwq->mqd = &priv->mqds[hwq->queue].mqd;
	hwq->pq_addr = ring_address;
	hwq->rptr_address = rptr_address;
	hwq->wptr_address = wptr_address;
	hwq->doorbell_index = doorbell;
	hwq->queue_size_encoded = ilog2(ring_size) - 3;

	init_mqd(hwq, hwp);
	activate_queue(priv, hwq);

	return 0;
}

static void
cik_static_destroy_queue(struct kfd_scheduler *scheduler, struct kfd_scheduler_queue *queue)
{
	struct cik_static_private *priv = kfd_scheduler_to_private(scheduler);
	struct cik_static_queue *hwq = kfd_queue_to_private(queue);

	deactivate_queue(priv, hwq);

	release_hqd(priv, hwq->queue);
}

static void
dequeue_int_received(struct cik_static_private *priv, uint32_t pipe_id)
{
	/* The waiting threads will check CP_HQD_ACTIVE to see whether their
	 * queue completed. */
	wake_up_all(&priv->dequeue_wait[pipe_id]);
}

/* Figure out the KFD compute pipe ID for an interrupt ring entry.
 * Returns true if it's a KFD compute pipe, false otherwise. */
static bool int_compute_pipe(const struct cik_static_private *priv,
			     const struct cik_ih_ring_entry *ih_ring_entry,
			     uint32_t *kfd_pipe)
{
	uint32_t pipe_id;

	if (ih_ring_entry->meid == 0) /* Ignore graphics interrupts - compute only. */
		return false;

	pipe_id = (ih_ring_entry->meid - 1) * CIK_PIPES_PER_MEC + ih_ring_entry->pipeid;
	if (pipe_id < priv->first_pipe)
		return false;

	pipe_id -= priv->first_pipe;

	*kfd_pipe = pipe_id;

	return true;
}

static bool
cik_static_interrupt_isr(struct kfd_scheduler *scheduler, const void *ih_ring_entry)
{
	struct cik_static_private *priv = kfd_scheduler_to_private(scheduler);
	const struct cik_ih_ring_entry *ihre = ih_ring_entry;
	uint32_t source_id = ihre->source_id;
	uint32_t pipe_id;

	/* We only care about CP interrupts here, they all come with a pipe. */
	if (!int_compute_pipe(priv, ihre, &pipe_id))
		return false;

	dev_info(radeon_kfd_chardev(), "INT(ISR): src=%02x, data=0x%x, pipe=%u, vmid=%u, pasid=%u\n",
		 ihre->source_id, ihre->data, pipe_id, ihre->vmid, ihre->pasid);

	switch (source_id) {
	case CIK_INTSRC_DEQUEUE_COMPLETE:
		dequeue_int_received(priv, pipe_id);
		return false; /* Already handled. */

	default:
		return false; /* Not interested. */
	}
}

static void
cik_static_interrupt_wq(struct kfd_scheduler *scheduler, const void *ih_ring_entry)
{
}

const struct kfd_scheduler_class radeon_kfd_cik_static_scheduler_class = {
	.name = "CIK static scheduler",
	.create = cik_static_create,
	.destroy = cik_static_destroy,
	.start = cik_static_start,
	.stop = cik_static_stop,
	.register_process = cik_static_register_process,
	.deregister_process = cik_static_deregister_process,
	.queue_size = sizeof(struct cik_static_queue),
	.create_queue = cik_static_create_queue,
	.destroy_queue = cik_static_destroy_queue,

	.interrupt_isr = cik_static_interrupt_isr,
	.interrupt_wq = cik_static_interrupt_wq,
};
