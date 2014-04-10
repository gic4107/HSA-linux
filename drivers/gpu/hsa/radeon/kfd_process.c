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

#include <linux/mutex.h>
#include <linux/log2.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/amd-iommu.h>
#include <linux/notifier.h>
struct mm_struct;

#include "kfd_priv.h"

/* Initial size for the array of queues.
 * The allocated size is doubled each time it is exceeded up to MAX_PROCESS_QUEUES. */
#define INITIAL_QUEUE_ARRAY_SIZE 16

/* List of struct kfd_process */
static struct list_head kfd_processes_list = LIST_HEAD_INIT(kfd_processes_list);

static DEFINE_MUTEX(kfd_processes_mutex);

static struct kfd_process *create_process(const struct task_struct *thread);

struct kfd_process*
radeon_kfd_create_process(const struct task_struct *thread)
{
	struct kfd_process *process;

	if (thread->mm == NULL)
		return ERR_PTR(-EINVAL);

	/* Only the pthreads threading model is supported. */
	if (thread->group_leader->mm != thread->mm)
		return ERR_PTR(-EINVAL);

	/*
	 * take kfd processes mutex before starting of process creation
	 * so there won't be a case where two threads of the same process
	 * create two kfd_process structures
	 */
	mutex_lock(&kfd_processes_mutex);

	/* A prior open of /dev/kfd could have already created the process. */
	process = thread->mm->kfd_process;
	if (process)
		pr_debug("kfd: process already found\n");

	if (!process)
		process = create_process(thread);

	mutex_unlock(&kfd_processes_mutex);

	return process;
}

struct kfd_process*
radeon_kfd_get_process(const struct task_struct *thread)
{
	struct kfd_process *process;

	if (thread->mm == NULL)
		return ERR_PTR(-EINVAL);

	/* Only the pthreads threading model is supported. */
	if (thread->group_leader->mm != thread->mm)
		return ERR_PTR(-EINVAL);

	process = thread->mm->kfd_process;

	return process;
}

static void free_process(struct kfd_process *p)
{
	struct kfd_process_device *pdd, *temp;

	BUG_ON(p == NULL);

	/* doorbell mappings: automatic */

	list_for_each_entry_safe(pdd, temp, &p->per_device_data, per_device_list) {
		amd_iommu_unbind_pasid(pdd->dev->pdev, p->pasid);
		list_del(&pdd->per_device_list);
		kfree(pdd);
	}

	radeon_kfd_pasid_free(p->pasid);

	mutex_destroy(&p->mutex);

	kfree(p->queues);

	list_del(&p->processes_list);

	kfree(p);
}

int kfd_process_exit(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct mm_struct *mm = data;
	struct kfd_process *p;

	mutex_lock(&kfd_processes_mutex);

	p = mm->kfd_process;
	if (p) {
		free_process(p);
		mm->kfd_process = NULL;
	}

	mutex_unlock(&kfd_processes_mutex);

	return 0;
}

static struct kfd_process *create_process(const struct task_struct *thread)
{
	struct kfd_process *process;
	int err = -ENOMEM;

	process = kzalloc(sizeof(*process), GFP_KERNEL);

	if (!process)
		goto err_alloc;

	process->queues = kmalloc_array(INITIAL_QUEUE_ARRAY_SIZE, sizeof(process->queues[0]), GFP_KERNEL);
	if (!process->queues)
		goto err_alloc;

	process->pasid = radeon_kfd_pasid_alloc();
	if (process->pasid == 0)
		goto err_alloc;

	mutex_init(&process->mutex);

	process->mm = thread->mm;
	thread->mm->kfd_process = process;
	list_add_tail(&process->processes_list, &kfd_processes_list);

	process->lead_thread = thread->group_leader;

	process->queue_array_size = INITIAL_QUEUE_ARRAY_SIZE;

	INIT_LIST_HEAD(&process->per_device_data);

	process->read_ptr.page_mapping = process->write_ptr.page_mapping = NULL;
	err = pqm_init(&process->pqm, process);
	if (err != 0)
		goto err_process_pqm_init;

	return process;

err_process_pqm_init:
	radeon_kfd_pasid_free(process->pasid);
	list_del(&process->processes_list);
	thread->mm->kfd_process = NULL;
err_alloc:
	kfree(process->queues);
	kfree(process);
	return ERR_PTR(err);
}

struct kfd_process_device *
radeon_kfd_get_process_device_data(struct kfd_dev *dev, struct kfd_process *p)
{
	struct kfd_process_device *pdd;

	list_for_each_entry(pdd, &p->per_device_data, per_device_list)
		if (pdd->dev == dev)
			return pdd;

	pdd = kzalloc(sizeof(*pdd), GFP_KERNEL);
	if (pdd != NULL) {
		pdd->dev = dev;
		INIT_LIST_HEAD(&pdd->qpd.queues_list);
		INIT_LIST_HEAD(&pdd->qpd.priv_queue_list);
		pdd->qpd.dqm = dev->dqm;
		list_add(&pdd->per_device_list, &p->per_device_data);
	}

	return pdd;
}

/* Direct the IOMMU to bind the process (specifically the pasid->mm) to the device.
 * Unbinding occurs when the process dies or the device is removed.
 *
 * Assumes that the process lock is held.
 */
struct kfd_process_device *radeon_kfd_bind_process_to_device(struct kfd_dev *dev, struct kfd_process *p)
{
	struct kfd_process_device *pdd = radeon_kfd_get_process_device_data(dev, p);
	int err;

	if (pdd == NULL)
		return ERR_PTR(-ENOMEM);

	if (pdd->bound)
		return pdd;

	err = amd_iommu_bind_pasid(dev->pdev, p->pasid, p->lead_thread);
	if (err < 0)
		return ERR_PTR(err);

	if (err < 0) {
		amd_iommu_unbind_pasid(dev->pdev, p->pasid);
		return ERR_PTR(err);
	}

	pdd->bound = true;

	return pdd;
}

void radeon_kfd_unbind_process_from_device(struct kfd_dev *dev, pasid_t pasid)
{
	struct kfd_process *p;
	struct kfd_process_device *pdd;

	BUG_ON(dev == NULL);

	mutex_lock(&kfd_processes_mutex);

	list_for_each_entry(p, &kfd_processes_list, processes_list)
		if (p->pasid == pasid)
			break;

	mutex_unlock(&kfd_processes_mutex);

	BUG_ON(p->pasid != pasid);

	pdd = radeon_kfd_get_process_device_data(dev, p);

	BUG_ON(pdd == NULL);

	mutex_lock(&p->mutex);

	pqm_uninit(&p->pqm);

	/*
	 * Just mark pdd as unbound, because we still need it to call
	 * amd_iommu_unbind_pasid() in when the process exits.
	 * We don't call amd_iommu_unbind_pasid() here
	 * because the IOMMU called us.
	 */
	pdd->bound = false;

	mutex_unlock(&p->mutex);
}

/* Ensure that the process's queue array is large enough to hold the queue at queue_id.
 * Assumes that the process lock is held. */
static bool ensure_queue_array_size(struct kfd_process *p, unsigned int queue_id)
{
	size_t desired_size;
	struct kfd_queue **new_queues;

	compiletime_assert(INITIAL_QUEUE_ARRAY_SIZE > 0, "INITIAL_QUEUE_ARRAY_SIZE must not be 0");
	compiletime_assert(INITIAL_QUEUE_ARRAY_SIZE <= MAX_PROCESS_QUEUES,
			   "INITIAL_QUEUE_ARRAY_SIZE must be less than MAX_PROCESS_QUEUES");
	/* Ensure that doubling the current size won't ever overflow. */
	compiletime_assert(MAX_PROCESS_QUEUES < SIZE_MAX / 2, "MAX_PROCESS_QUEUES must be less than SIZE_MAX/2");

	/*
	 * These & queue_id < MAX_PROCESS_QUEUES guarantee that
	 * the desired_size calculation will end up <= MAX_PROCESS_QUEUES
	 */
	compiletime_assert(is_power_of_2(INITIAL_QUEUE_ARRAY_SIZE), "INITIAL_QUEUE_ARRAY_SIZE must be power of 2.");
	compiletime_assert(MAX_PROCESS_QUEUES % INITIAL_QUEUE_ARRAY_SIZE == 0,
			   "MAX_PROCESS_QUEUES must be multiple of INITIAL_QUEUE_ARRAY_SIZE.");
	compiletime_assert(is_power_of_2(MAX_PROCESS_QUEUES / INITIAL_QUEUE_ARRAY_SIZE),
			   "MAX_PROCESS_QUEUES must be a power-of-2 multiple of INITIAL_QUEUE_ARRAY_SIZE.");

	if (queue_id < p->queue_array_size)
		return true;

	if (queue_id >= MAX_PROCESS_QUEUES)
		return false;

	desired_size = p->queue_array_size;
	while (desired_size <= queue_id)
		desired_size *= 2;

	BUG_ON(desired_size < queue_id || desired_size > MAX_PROCESS_QUEUES);
	BUG_ON(desired_size % INITIAL_QUEUE_ARRAY_SIZE != 0 || !is_power_of_2(desired_size / INITIAL_QUEUE_ARRAY_SIZE));

	new_queues = kmalloc_array(desired_size, sizeof(p->queues[0]), GFP_KERNEL);
	if (!new_queues)
		return false;

	memcpy(new_queues, p->queues, p->queue_array_size * sizeof(p->queues[0]));

	kfree(p->queues);
	p->queues = new_queues;
	p->queue_array_size = desired_size;

	return true;
}

/* Assumes that the process lock is held. */
bool radeon_kfd_allocate_queue_id(struct kfd_process *p, unsigned int *queue_id)
{
	unsigned int qid = find_first_zero_bit(p->allocated_queue_bitmap, MAX_PROCESS_QUEUES);

	if (qid >= MAX_PROCESS_QUEUES)
		return false;

	if (!ensure_queue_array_size(p, qid))
		return false;

	__set_bit(qid, p->allocated_queue_bitmap);

	p->queues[qid] = NULL;
	*queue_id = qid;

	return true;
}

/* Install a queue into a previously-allocated queue id.
 *  Assumes that the process lock is held. */
void radeon_kfd_install_queue(struct kfd_process *p, unsigned int queue_id, struct kfd_queue *queue)
{
	BUG_ON(queue_id >= p->queue_array_size); /* Have to call allocate_queue_id before install_queue. */
	BUG_ON(queue == NULL);

	p->queues[queue_id] = queue;
}

/* Remove a queue from the open queue list and deallocate the queue id.
 * This can be called whether or not a queue was installed.
 * Assumes that the process lock is held. */
void radeon_kfd_remove_queue(struct kfd_process *p, unsigned int queue_id)
{
	BUG_ON(!test_bit(queue_id, p->allocated_queue_bitmap));
	BUG_ON(queue_id >= p->queue_array_size);

	__clear_bit(queue_id, p->allocated_queue_bitmap);
}

/* Assumes that the process lock is held. */
struct kfd_queue *radeon_kfd_get_queue(struct kfd_process *p, unsigned int queue_id)
{
	/* test_bit because the contents of unallocated queue slots are undefined.
	 * Otherwise ensure_queue_array_size would have to clear new entries and
	 * remove_queue would have to NULL removed queues. */
	return (queue_id < p->queue_array_size &&
		test_bit(queue_id, p->allocated_queue_bitmap)) ?
			p->queues[queue_id] : NULL;
}

struct kfd_process_device *kfd_get_first_process_device_data(struct kfd_process *p)
{
	return list_first_entry(&p->per_device_data, struct kfd_process_device, per_device_list);
}

struct kfd_process_device *kfd_get_next_process_device_data(struct kfd_process *p, struct kfd_process_device *pdd)
{
	if (list_is_last(&pdd->per_device_list, &p->per_device_data))
		return NULL;
	return list_next_entry(pdd, per_device_list);
}

bool kfd_has_process_device_data(struct kfd_process *p)
{
	return !(list_empty(&p->per_device_data));
}
