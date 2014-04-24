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

#include <linux/slab.h>
#include <linux/list.h>
#include "kfd_device_queue_manager.h"
#include "kfd_priv.h"
#include "kfd_hw_pointer_store.h"
#include "kfd_kernel_queue.h"

static inline struct process_queue_node *get_queue_by_qid(struct process_queue_manager *pqm, unsigned int qid)
{
	struct process_queue_node *pqn;
	BUG_ON(!pqm);

	list_for_each_entry(pqn, &pqm->queues, process_queue_list) {
		if (pqn->q && pqn->q->properties.queue_id == qid)
			return pqn;
		if (pqn->kq && pqn->kq->queue->properties.queue_id == qid)
			return pqn;
	}

	return NULL;
}

static int allocate_hw_pointers(struct process_queue_manager *pqm, struct queue_properties *q_properties, struct file *f,
		struct kfd_dev *dev, unsigned int qid)
{
	int retval;
	BUG_ON(!pqm || !q_properties);

	retval = 0;

	pr_debug("kfd: In func %s\n", __func__);

	/* allocates r/w pointers in lazy mode */
	if (pqm->process->read_ptr.page_mapping == NULL)
		if (hw_pointer_store_init(&pqm->process->read_ptr, KFD_HW_POINTER_STORE_TYPE_RPTR) != 0)
			return -EBUSY;
	if (pqm->process->write_ptr.page_mapping == NULL)
		if (hw_pointer_store_init(&pqm->process->write_ptr, KFD_HW_POINTER_STORE_TYPE_WPTR) != 0) {
			hw_pointer_store_destroy(&pqm->process->read_ptr);
			return -EBUSY;
		}

	q_properties->read_ptr = hw_pointer_store_create_queue(&pqm->process->read_ptr, qid, f);
	if (!q_properties->read_ptr)
		return -ENOMEM;

	q_properties->write_ptr = hw_pointer_store_create_queue(&pqm->process->write_ptr, qid, f);
	if (!q_properties->write_ptr)
		return -ENOMEM;

	q_properties->doorbell_ptr = radeon_kfd_get_doorbell(f, pqm->process, dev, qid);
	if (!q_properties->doorbell_ptr)
		return -ENOMEM;

	q_properties->doorbell_off = radeon_kfd_queue_id_to_doorbell(dev, pqm->process, qid);

	return retval;
}

static int find_available_queue_slot(struct process_queue_manager *pqm, unsigned int *qid)
{
	unsigned long found;

	BUG_ON(!pqm || !qid);

	pr_debug("kfd: in %s\n", __func__);

	found = find_first_zero_bit(pqm->queue_slot_bitmap, MAX_PROCESS_QUEUES);

	pr_debug("kfd: the new slot id %lu\n", found);

	if (found >= MAX_PROCESS_QUEUES)
		return -ENOMEM;

	set_bit(found, pqm->queue_slot_bitmap);
	*qid = found;

	return 0;
}

int pqm_init(struct process_queue_manager *pqm, struct kfd_process *p)
{
	BUG_ON(!pqm);

	INIT_LIST_HEAD(&pqm->queues);
	pqm->queue_slot_bitmap = kzalloc(DIV_ROUND_UP(MAX_PROCESS_QUEUES, BITS_PER_BYTE), GFP_KERNEL);
	if (pqm->queue_slot_bitmap == NULL)
		return -ENOMEM;
	pqm->process = p;

	return 0;
}

void pqm_uninit(struct process_queue_manager *pqm)
{
	int retval;
	struct process_queue_node *pqn, *next;
	BUG_ON(!pqm);

	pr_debug("In func %s\n", __func__);

	list_for_each_entry_safe(pqn, next, &pqm->queues, process_queue_list) {
		retval = pqm_destroy_queue(pqm,
					   (pqn->q != NULL) ? pqn->q->properties.queue_id : pqn->kq->queue->properties.queue_id);
		if (retval != 0)
			return;
	}
	kfree(pqm->queue_slot_bitmap);

	if (pqm->process->read_ptr.page_mapping)
		hw_pointer_store_destroy(&pqm->process->read_ptr);
	if (pqm->process->write_ptr.page_mapping)
		hw_pointer_store_destroy(&pqm->process->write_ptr);
}

static int create_cp_queue(struct process_queue_manager *pqm, struct kfd_dev *dev, struct queue **q,
		struct queue_properties *q_properties, struct file *f, unsigned int qid)
{
	int retval;

	retval = 0;

	/* allocate hw pointers */
	if (allocate_hw_pointers(pqm, q_properties, f, dev, qid) != 0) {
		retval = -ENOMEM;
		goto err_allocate_hw_pointers;
	}

	/* let DQM handle it*/
	q_properties->vmid = 0;
	q_properties->queue_id = qid;
	q_properties->type = KFD_QUEUE_TYPE_COMPUTE;

	retval = init_queue(q, *q_properties);
	if (retval != 0)
		goto err_init_queue;

	(*q)->device = dev;
	(*q)->process = pqm->process;

	pr_debug("kfd: PQM After init queue");

	return retval;

err_init_queue:
err_allocate_hw_pointers:
	return retval;
}

int pqm_create_queue(struct process_queue_manager *pqm,
			    struct kfd_dev *dev,
			    struct file *f,
			    struct queue_properties *properties,
			    unsigned int flags,
			    enum kfd_queue_type type,
			    unsigned int *qid)
{
	int retval;
	struct kfd_process_device *pdd;
	struct queue_properties q_properties;
	struct queue *q;
	struct process_queue_node *pqn;
	struct kernel_queue *kq;

	BUG_ON(!pqm || !dev || !properties || !qid);

	memset(&q_properties, 0, sizeof(struct queue_properties));
	memcpy(&q_properties, properties, sizeof(struct queue_properties));

	pdd = radeon_kfd_get_process_device_data(dev, pqm->process);
	BUG_ON(!pdd);

	retval = find_available_queue_slot(pqm, qid);
	if (retval != 0)
		return retval;

	if (list_empty(&pqm->queues)) {
		pdd->qpd.pqm = pqm;
		dev->dqm->register_process(dev->dqm, &pdd->qpd);
	}

	pqn = kzalloc(sizeof(struct process_queue_node), GFP_KERNEL);
	if (!pqn) {
		retval = -ENOMEM;
		goto err_allocate_pqn;
	}

	switch (type) {
	case KFD_QUEUE_TYPE_COMPUTE:
		retval = create_cp_queue(pqm, dev, &q, &q_properties, f, *qid);
		if (retval != 0)
			goto err_create_queue;
		pqn->q = q;
		pqn->kq = NULL;
		retval = dev->dqm->create_queue(dev->dqm, q, &pdd->qpd, &q->properties.vmid);
		print_queue(q);
		break;
	case KFD_QUEUE_TYPE_DIQ:
		kq = kernel_queue_init(dev, KFD_QUEUE_TYPE_DIQ);
		if (kq == NULL) {
			kernel_queue_uninit(kq);
			goto err_create_queue;
		}
		kq->queue->properties.queue_id = *qid;
		pqn->kq = kq;
		pqn->q = NULL;
		retval = dev->dqm->create_kernel_queue(dev->dqm, kq, &pdd->qpd);
		break;
	default:
		BUG();
		break;
	}

	if (retval != 0) {
		pr_err("kfd: error dqm create queue\n");
		goto err_create_queue;
	}

	pr_debug("kfd: PQM After DQM create queue\n");

	list_add(&pqn->process_queue_list, &pqm->queues);

	retval = dev->dqm->execute_queues(dev->dqm);
	if (retval != 0) {
		if (pqn->kq)
			dev->dqm->destroy_kernel_queue(dev->dqm, pqn->kq, &pdd->qpd);
		if (pqn->q)
			dev->dqm->destroy_queue(dev->dqm, &pdd->qpd, pqn->q);

		goto err_execute_runlist;
	}

	*properties = q->properties;
	pr_debug("kfd: PQM done creating queue\n");
	print_queue_properties(properties);

	return retval;

err_execute_runlist:
	list_del(&pqn->process_queue_list);
err_create_queue:
	kfree(pqn);
err_allocate_pqn:
	clear_bit(*qid, pqm->queue_slot_bitmap);
	return retval;
}

int pqm_destroy_queue(struct process_queue_manager *pqm, unsigned int qid)
{
	struct process_queue_node *pqn;
	struct kfd_process_device *pdd;
	struct device_queue_manager *dqm;
	struct kfd_dev *dev;
	int retval;

	dqm = NULL;

	BUG_ON(!pqm);
	retval = 0;

	pr_debug("kfd: In Func %s\n", __func__);

	pqn = get_queue_by_qid(pqm, qid);
	BUG_ON(!pqn);

	dev = NULL;
	if (pqn->kq)
		dev = pqn->kq->dev;
	if (pqn->q)
		dev = pqn->q->device;
	BUG_ON(!dev);

	pdd = radeon_kfd_get_process_device_data(dev, pqm->process);
	BUG_ON(!pdd);

	if (pqn->kq) {
		/* destroy kernel queue (DIQ) */
		dqm = pqn->kq->dev->dqm;
		dqm->destroy_kernel_queue(dqm, pqn->kq, &pdd->qpd);
		kernel_queue_uninit(pqn->kq);
	}

	if (pqn->q) {
		dqm = pqn->q->device->dqm;
		retval = dqm->destroy_queue(dqm, &pdd->qpd, pqn->q);
		if (retval != 0)
			return retval;

		list_del(&pqn->process_queue_list);
		uninit_queue(pqn->q);
	}

	kfree(pqn);
	clear_bit(qid, pqm->queue_slot_bitmap);

	if (list_empty(&pqm->queues))
		dqm->unregister_process(dqm, &pdd->qpd);

	retval = dqm->execute_queues(dqm);

	return retval;
}

int pqm_update_queue(struct process_queue_manager *pqm, unsigned int qid, struct queue_properties *p)
{
	int retval;
	struct process_queue_node *pqn;
	BUG_ON(!pqm);

	pqn = get_queue_by_qid(pqm, qid);
	BUG_ON(!pqn);

	pqn->q->properties.queue_address = p->queue_address;
	pqn->q->properties.queue_size = p->queue_size;
	pqn->q->properties.queue_percent = p->queue_percent;
	pqn->q->properties.priority = p->priority;

	retval = pqn->q->device->dqm->destroy_queues(pqn->q->device->dqm);
	if (retval != 0)
		return retval;

	retval = pqn->q->device->dqm->update_queue(pqn->q->device->dqm, pqn->q);
	if (retval != 0)
		return retval;

	retval = pqn->q->device->dqm->execute_queues(pqn->q->device->dqm);
	if (retval != 0)
		return retval;

	return 0;
}

struct kernel_queue *pqm_get_kernel_queue(struct process_queue_manager *pqm, unsigned int qid)
{
	struct process_queue_node *pqn;
	BUG_ON(!pqm);

	pqn = get_queue_by_qid(pqm, qid);
	if (pqn && pqn->kq)
		return pqn->kq;

	return NULL;
}


