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
struct mm_struct;

#include "kfd_priv.h"
#include "kfd_dbgmgr.h"

/* Initial size for the array of queues.
 * The allocated size is doubled each time it is exceeded up to MAX_PROCESS_QUEUES. */
#define INITIAL_QUEUE_ARRAY_SIZE 16

/* List of struct kfd_process (field kfd_process). Unique/indexed by mm_struct*. */
#define KFD_PROCESS_TABLE_SIZE 5 /* bits: 32 entries */
static DEFINE_HASHTABLE(kfd_processes, KFD_PROCESS_TABLE_SIZE);
static DEFINE_MUTEX(kfd_processes_mutex);

#ifdef CONFIG_HSA_VIRTUALIZATION
#include <asm/kvm_host.h>
LIST_HEAD(vm_info_list);
#endif

DEFINE_STATIC_SRCU(kfd_processes_srcu);

static struct kfd_process *find_process(const struct task_struct *thread);
static struct kfd_process *create_process(const struct task_struct *thread);
static struct kfd_process *insert_process(struct kfd_process *process);

#define MIN_IDR_ID 1
#define MAX_IDR_ID 0 /*0 - for unlimited*/


struct kfd_process*
radeon_kfd_create_process(const struct task_struct *thread)
{
	struct kfd_process *process;

	if (thread->mm == NULL)
		return ERR_PTR(-EINVAL);

	/* Only the pthreads threading model is supported. */
	if (thread->group_leader->mm != thread->mm)
		return ERR_PTR(-EINVAL);

	/* A prior open of /dev/kfd could have already created the process. */
	process = find_process(thread);
	if (process)
		pr_debug("kfd: process already found\n");

	if (!process) {
		process = create_process(thread);
		if (IS_ERR(process))
			return process;

		process = insert_process(process);
	}

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

	process = find_process(thread);

	return process;
}

static struct kfd_process*
find_process_by_mm(const struct mm_struct *mm)
{
	struct kfd_process *process;

	hash_for_each_possible_rcu(kfd_processes, process, kfd_processes, (uintptr_t)mm)
		if (process->mm == mm)
			return process;

	return NULL;
}

static struct kfd_process*
find_process(const struct task_struct *thread)
{
	struct kfd_process *p;

	int idx = srcu_read_lock(&kfd_processes_srcu);
	p = find_process_by_mm(thread->mm);
	srcu_read_unlock(&kfd_processes_srcu, idx);

	return p;
}

/* Assumes that the kfd_process mutex is held.
 * (Or that it doesn't need to be held because the process is exiting.)
 *
 * dev_filter can be set to only destroy queues for one device.
 * Otherwise all queues for the process are destroyed.
 */

static void free_process(struct kfd_process *p)
{
	struct kfd_process_device *pdd, *temp;

    printk("free_process: pasid=%d\n", p->pasid);
	radeon_kfd_pasid_free(p->pasid);

	list_for_each_entry_safe(pdd, temp, &p->per_device_data, per_device_list) {
		spin_lock(&pdd->dev->pmc_access_lock);
		if (pdd->dev->pmc_locking_process == p) {
			pdd->dev->pmc_locking_process = NULL;
			pdd->dev->pmc_locking_trace = 0;
		}
		spin_unlock(&pdd->dev->pmc_access_lock);
		kfree(pdd);
	}

	kfd_event_free_process(p);

	mutex_destroy(&p->mutex);

#ifdef CONFIG_HSA_VIRTUALIZATION
    if (p->process_type == KFD_PROCESS_TYPE_VIRTIO_BE) {
        printk("kfree p->virtio_be_info\n");
        kfree(p->virtio_be_info);
    }
#endif
	kfree(p->queues);
	kfree(p);
}

static void shutdown_process(struct kfd_process *p)
{
	/* IOMMU bindings: automatic */
	/* doorbell mappings: automatic */
    struct kfd_process *iter;
    int vm_process = 0;

	mutex_lock(&kfd_processes_mutex);
	hash_del_rcu(&p->kfd_processes);
	mutex_unlock(&kfd_processes_mutex);
	synchronize_srcu(&kfd_processes_srcu);

    hlist_for_each_entry_rcu(iter, kfd_processes, kfd_processes) {
        if (p->process_type != KFD_PROCESS_TYPE_NORMAL) {
            printk("shutdown_process, type=%d\n", p->process_type);
            vm_process = 1;
        }
    }
}

static void
kfd_process_notifier_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct kfd_process *p = container_of(mn, struct kfd_process, mmu_notifier);
	BUG_ON(p->mm != mm);

    printk("kfd_process_notifier_release, call shutdown_process\n");
	shutdown_process(p);
}

static void
kfd_process_notifier_destroy(struct mmu_notifier *mn)
{
	struct kfd_process *p = container_of(mn, struct kfd_process, mmu_notifier);

    printk("kfd_process_notifier_destroy, call free_process\n");
	free_process(p);
}

static const struct mmu_notifier_ops kfd_process_mmu_notifier_ops = {
	.release = kfd_process_notifier_release,
	.destroy = kfd_process_notifier_destroy,
};

/* Because mmap_sem precedes kfd_processes_mutex and mmu_notifier_register
 * takes mmap_sem, this must be called without holding kfd_processes_mutex.
 * insert_process will take kfd_processes_mutex and choose a winner.
 * This introduces a small bug in that we could spuriously run out of PASIDs.
 */
static struct kfd_process*
create_process(const struct task_struct *thread)
{
	struct kfd_process *process;
	int err = -ENOMEM;

	process = kzalloc(sizeof(*process), GFP_KERNEL);

	if (!process)
		goto err_alloc;

	process->queues = kmalloc_array(INITIAL_QUEUE_ARRAY_SIZE, sizeof(process->queues[0]), GFP_KERNEL);
	if (!process->queues)
		goto err_alloc_queues;

	process->pasid = radeon_kfd_pasid_alloc();
	if (process->pasid == 0)
		goto err_alloc_queues;

	mutex_init(&process->mutex);

	process->mm = thread->mm;

	process->mmu_notifier.ops = &kfd_process_mmu_notifier_ops;
	err = mmu_notifier_register(&process->mmu_notifier, process->mm);
	if (err)
		goto err_mmu_notifier;

	process->lead_thread = thread->group_leader;
    printk("create_process: task=%p, lead_thread=%p, mm=%p, get_task_mm=%p, mm->pgd=%p, get_task_mm->pgd=%p\n", 
                 thread, process->lead_thread, process->mm, get_task_mm(process->lead_thread), process->mm->pgd, get_task_mm(process->lead_thread)->pgd);

	process->queue_array_size = INITIAL_QUEUE_ARRAY_SIZE;

	INIT_LIST_HEAD(&process->per_device_data);

	kfd_event_init_process(process);

	err = pqm_init(&process->pqm, process);
	if (err != 0)
		goto err_process_pqm_init;

	return process;

err_process_pqm_init:
err_mmu_notifier:
	radeon_kfd_pasid_free(process->pasid);
err_alloc_queues:
	kfree(process->queues);
err_alloc:
	kfree(process);
	return ERR_PTR(err);
}

/* Atomically complete process creation.
 * create_process has to be called outside the kfd_processes_mutex,
 * so this function inserts the process into the list. It might be that
 * another thread beat us to it, in which case we free the new
 * struct kfd_process and return the already-linked one.
 */
static struct kfd_process*
insert_process(struct kfd_process *p)
{
	struct kfd_process *other_p;

	mutex_lock(&kfd_processes_mutex);

	other_p = find_process_by_mm(p->mm);
	if (other_p) {
		/* Another thread beat us to creating & inserting the kfd_process object. */
		mutex_unlock(&kfd_processes_mutex);

		/* Unregister will destroy the struct kfd_process. */
		mmu_notifier_unregister(&p->mmu_notifier, p->mm);

		p = other_p;
	} else {
		/* We are the winner, insert it. */
		hash_add_rcu(kfd_processes, &p->kfd_processes, (uintptr_t)p->mm);
		mutex_unlock(&kfd_processes_mutex);
	}

	return p;
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

	idr_init(&pdd->alloc_idr);

	/* Create the GPUVM context for this specific device */
//	err = radeon_kfd_process_create_vm(dev, &pdd->vm);
	if (err != 0)
		return ERR_PTR(err);

    printk("radeon_kfd_process_create_vm done\n");
    if (p->process_type == KFD_PROCESS_TYPE_VM_PROCESS) {
        struct kfd_process *virtio_be;
        struct kvm *kvm;
        gpa_t pgd_gpa;
        
        virtio_be = p->vm_info->virtio_be_process;
        kvm = virtio_be->virtio_be_info->kvm;
        if (!kvm) {
            printk("radeon_kfd_bind_process_to_device for vm fail %p \n", p);
            return -EINVAL;
        }

        pgd_gpa = p->vm_info->vm_pgd_gpa;

        // set vm_pgd_hpa to IOMMU
    	err = amd_iommu_vm_process_bind_pasid(dev->pdev, p->pasid, kvm, virtio_be->mm, 
                        p->vm_info->vm_task, p->vm_info->vm_mm, pgd_gpa);
    	if (err < 0) {
            printk("amd_iommu_vm_process_bind_pasid fail %d\n", err);
//    		radeon_kfd_process_destroy_vm(dev, pdd->vm);
    		return ERR_PTR(err);
        }        
    }
    else {      // not vm_process, original code
    	err = amd_iommu_bind_pasid(dev->pdev, p->pasid, p->lead_thread);
    	if (err < 0) {
//    		radeon_kfd_process_destroy_vm(dev, pdd->vm);
    		return ERR_PTR(err);
    	}
    }

	pdd->bound = true;

	return pdd;
}

void radeon_kfd_unbind_process_from_device(struct kfd_dev *dev, pasid_t pasid)
{
	struct kfd_process *p;
	struct kfd_process_device *pdd;
	long   status;
	void *mem;
	int id;

	pr_debug("\t unbinding process... pasid is %u\n", pasid);
	p = find_process(current);
	if (p == NULL)
		return;

	pdd = radeon_kfd_get_process_device_data(dev, p);

	BUG_ON(p->pasid != pasid);
	BUG_ON(pdd == NULL);

	mutex_lock(&p->mutex);

	pr_debug("\t kfd process pasid is %u\n", p->pasid);
	pr_debug("\t dev pointer is %p\n", dev);

	if (dev) {
		if ((dev->dbgmgr) && (dev->dbgmgr->pasid == p->pasid)) {

			pr_debug("\t dbg mgr pasid is %u\n", dev->dbgmgr->pasid);
			status = kfd_dbgmgr_abnormal_termination(dev->dbgmgr, p);
			if (status == 0) {
					kfd_dbgmgr_destroy(dev->dbgmgr);
					dev->dbgmgr = NULL;
			} else {
				BUG();
			}

		}
	}
	radeon_kfd_doorbell_unmap(pdd);

	pqm_uninit(&p->pqm);

	/* We don't call amd_iommu_unbind_pasid because the IOMMU is calling us. */

	list_del(&pdd->per_device_list);

	/*Remove all handles from idr and release appropriate local memory object*/
	idr_for_each_entry(&pdd->alloc_idr, mem, id) {
		idr_remove(&pdd->alloc_idr, id);
//		radeon_kfd_process_gpuvm_free(dev, mem);
	}

	/* Destroy the GPUVM VM context */
//	radeon_kfd_process_destroy_vm(dev, pdd->vm);

	kfree(pdd);

	mutex_unlock(&p->mutex);

	/* You may wonder what prevents new queues from being created now that
	 * the locks have been released. Nothing does. This bug exists because
	 * the IOMMU driver uses the PROFILE_TASK_EXIT profiling event which is
	 * called very early during thread shutdown. Other threads in the
	 * process are still running and may create new queues. This could be
	 * fixed by having the IOMMU driver switch to an mmu_notifier. */
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
	/* These & queue_id < MAX_PROCESS_QUEUES guarantee that the desired_size calculation will end up <= MAX_PROCESS_QUEUES. */
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
	return (queue_id < p->queue_array_size && test_bit(queue_id, p->allocated_queue_bitmap)) ? p->queues[queue_id] : NULL;
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


/* Create specific handle mapped to mem from process local memory idr
 * Assumes that the process lock is held. */
int radeon_kfd_process_device_create_obj_handle(struct kfd_process_device *pdd, void *mem)
{
	int handle;

	BUG_ON(pdd == NULL);
	BUG_ON(mem == NULL);

	idr_preload(GFP_KERNEL);

	handle = idr_alloc(&pdd->alloc_idr, mem, MIN_IDR_ID, MAX_IDR_ID, GFP_NOWAIT);

	idr_preload_end();

	return handle;
}

/* Translate specific handle from process local memory idr
 * Assumes that the process lock is held. */
void *radeon_kfd_process_device_translate_handle(struct kfd_process_device *pdd, int handle)
{
	BUG_ON(pdd == NULL);

	if (handle < 0)
		return NULL;

	return idr_find(&pdd->alloc_idr, handle);
}

/* Remove specific handle from process local memory idr
 * Assumes that the process lock is held. */
void radeon_kfd_process_device_remove_obj_handle(struct kfd_process_device *pdd, int handle)
{
	BUG_ON(pdd == NULL);

	if (handle < 0)
		return;

	idr_remove(&pdd->alloc_idr, handle);
}

/* This returns with process->mutex locked. */
struct kfd_process *kfd_lookup_process_by_pasid(pasid_t pasid)
{
	struct kfd_process *p;
	unsigned int temp;

	int idx = srcu_read_lock(&kfd_processes_srcu);

	hash_for_each_rcu(kfd_processes, temp, p, kfd_processes) {
		if (p->pasid == pasid) {
			mutex_lock(&p->mutex);
			break;
		}
	}

	srcu_read_unlock(&kfd_processes_srcu, idx);

	return p;
}

#ifdef CONFIG_HSA_VIRTUALIZATION
struct kfd_process*
find_vm_process(const void *vm_mm)
{
    struct kfd_process *p;
    
	int idx = srcu_read_lock(&kfd_processes_srcu);
	p = find_process_by_mm(vm_mm);
	srcu_read_unlock(&kfd_processes_srcu, idx);

    return p;
}

static struct kfd_process*
create_vm_process(const void *vm_mm)
{
	struct kfd_process *process;
	int err = -ENOMEM;

    printk("create_vm_process %p\n", vm_mm);
	process = kzalloc(sizeof(*process), GFP_KERNEL);

	if (!process)
		goto err_alloc;

	process->queues = kmalloc_array(INITIAL_QUEUE_ARRAY_SIZE, sizeof(process->queues[0]), GFP_KERNEL);
	if (!process->queues)
		goto err_alloc_queues;

	process->pasid = radeon_kfd_pasid_alloc();
	if (process->pasid == 0)
		goto err_alloc_queues;

	mutex_init(&process->mutex);

	process->mm = vm_mm;

    process->process_type = KFD_PROCESS_TYPE_VM_PROCESS;

//	process->mmu_notifier.ops = &kfd_process_mmu_notifier_ops;
//	err = mmu_notifier_register(&process->mmu_notifier, process->mm);
//	if (err)
//		goto err_mmu_notifier;

//	process->lead_thread = thread->group_leader;

	process->queue_array_size = INITIAL_QUEUE_ARRAY_SIZE;

	INIT_LIST_HEAD(&process->per_device_data);

	kfd_event_init_process(process);

	err = pqm_init(&process->pqm, process);
	if (err != 0) {
        printk("!!! pqm_init fail\n");
		goto err_process_pqm_init;
    }

	return process;

err_process_pqm_init:
    printk("!!! err_process_pqm_init\n");
//err_mmu_notifier:
	radeon_kfd_pasid_free(process->pasid);
err_alloc_queues:
    printk("!!! err_alloc_queue\n");
	kfree(process->queues);
err_alloc:
    printk("!!! err_alloc\n");
	kfree(process);
	return ERR_PTR(err);
}

struct kfd_process*
radeon_kfd_vm_create_process(const void *vm_mm)
{
	struct kfd_process *process;

	if (vm_mm == NULL)
		return ERR_PTR(-EINVAL);

	/* A prior open of /dev/kfd could have already created the process. */
	process = find_vm_process(vm_mm);
	if (process)
		printk("!!! radeon_kfd_vm_create_process: vm process already found\n");

	if (!process) {
		process = create_vm_process(vm_mm);
		if (IS_ERR(process))
			return process;

		process = insert_process(process);
	}

	return process;
}

long radeon_kfd_vm_close_process(const void *vm_mm)
{
    struct kfd_process *process;

    if(vm_mm == NULL)
        return ERR_PTR(-EINVAL);

    process = find_vm_process(vm_mm);
    if(process == NULL) {
        printk("!!! radeon_kfd_vm_close_process: process not found\n");
        return -EFAULT;
    }

    kfree(process->vm_info);

    shutdown_process(process);
    free_process(process); 

    return 0;
}

// FIXME: for debugging usage
void read_guest_pgd(struct mm_struct *mm)  
{
    struct kvm *kvm;
    gpa_t pgd_gpa;
    struct kfd_process *p = find_vm_process((const void*)mm); 
    printk("read_guest_pgd, p=%p\n", p);
    if (!p) 
        return;

    kvm = p->vm_info->virtio_be_process->virtio_be_info->kvm;
    pgd_gpa = p->vm_info->vm_pgd_gpa;
    kvm_hsa_read_guest_pgd(kvm, pgd_gpa);
}
EXPORT_SYMBOL(read_guest_pgd);

int kvm_bind_kfd_virtio_be(struct kvm *kvm, const struct task_struct *thread)              
{                                                                                   
    struct kfd_process *p;

    p = find_process(thread);
    if (!p || p->process_type!=KFD_PROCESS_TYPE_VIRTIO_BE) {
        printk("kvm_bind_kfd_virtio_be %p fail\n", thread);
        return -EINVAL;
    }

    p->virtio_be_info->kvm = kvm;
    
    return 0; 
}
EXPORT_SYMBOL(kvm_bind_kfd_virtio_be);

/* Check whether the cr3 use KFD, and whether its SPT is same.
 * If all same, just return.
 * If guest process' SPT changes, bind SPT to IOMMU.
 */ 
void radeon_kfd_bind_iommu_spt(gpa_t guest_cr3, hpa_t spt_root)
{
    struct vm_info *vm_info;
    struct kfd_process *virtio_be;
    struct kvm *kvm;
    int pasid;
    int err;

    if (list_empty(&vm_info_list))
        return;

    printk("guest_cr3=%llx, spt_root=%llx\n", guest_cr3, spt_root);
    list_for_each_entry(vm_info, &vm_info_list, list) {
        if (vm_info->vm_pgd_gpa == guest_cr3) {
            if (vm_info->vm_spt_root == spt_root) { // SPT same, just return
                printk("PASID %d, spt_root same\n", vm_info->kfd_process->pasid);
                return;
            }
            break;
        }
    }

    if (!vm_info) {
        printk("radeon_kfd_bind_iommu_spt: vm_info null\n");
        return;
    }

    if (!vm_info->dev) {
        return;
    }

    if (vm_info->vm_pgd_gpa != guest_cr3) {
        printk("radeon_kfd_bind_iommu_spt: not a kfd_process, vm_info's cr3=%llx\n", vm_info->vm_pgd_gpa);
        return;
    }

    printk("PASID %d, original spt_root=%llx\n", 
                      vm_info->kfd_process->pasid, vm_info->vm_spt_root);
    vm_info->vm_spt_root = spt_root;        // set SPT
    pasid = vm_info->kfd_process->pasid;             
    virtio_be = vm_info->virtio_be_process;
    kvm = virtio_be->virtio_be_info->kvm;

    printk("Set SPT root %llx to PASID %d, dev=%p, pdev=%p\n", spt_root, pasid, vm_info->dev, vm_info->dev->pdev);
    err = amd_iommu_set_gcr3(vm_info->dev->pdev, pasid, spt_root);      // bind SPT to IOMMU
   	if (err < 0) {
        printk("amd_iommu_set_gcr3 fail %d\n", err);
    }        
}
EXPORT_SYMBOL(radeon_kfd_bind_iommu_spt);

uint64_t radeon_kfd_get_vm_process_pgd(uint64_t vm_task)
{
    struct vm_info *vm_info;
    printk("radeon_kfd_get_vm_process_pgd %llx\n", vm_task);

    list_for_each_entry(vm_info, &vm_info_list, list) 
        if(vm_info->vm_task == vm_task)
            return vm_info->vm_pgd_gpa;

    return 0;
}
EXPORT_SYMBOL(radeon_kfd_get_vm_process_pgd);

int adjust_vm_process_pgd(struct kfd_dev *dev, struct kfd_process *p)
{
    struct kfd_process *virtio_be = p->vm_info->virtio_be_process;
    struct mm_struct *mm;
    BUG_ON(!virtio_be);

    mm = get_task_mm(virtio_be->lead_thread);
  	return amd_iommu_set_gcr3(dev->pdev, p->pasid, __pa(mm->pgd));
}

int resume_vm_process_pgd(struct kfd_dev *dev, struct kfd_process *p)
{
  	return amd_iommu_set_gcr3(dev->pdev, p->pasid, p->vm_info->vm_pgd_gpa);
}

#endif // endif CONFIG_HSA_VIRTUALIZATION
