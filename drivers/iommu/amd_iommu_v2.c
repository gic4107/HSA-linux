/*
 * Copyright (C) 2010-2012 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <joerg.roedel@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <linux/mmu_notifier.h>
#include <linux/amd-iommu.h>
#include <linux/mm_types.h>
#include <linux/profile.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/iommu.h>
#include <linux/wait.h>
#include <linux/pci.h>
#include <linux/gfp.h>

#include "amd_iommu_types.h"
#include "amd_iommu_proto.h"
#include "amd_iommu_v2.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Joerg Roedel <joerg.roedel@amd.com>");

static struct device_state **state_table;
static spinlock_t state_lock;

/* List and lock for all pasid_states */
LIST_HEAD(pasid_state_list);
static DEFINE_SPINLOCK(ps_lock);

static struct workqueue_struct *iommu_wq;

static void free_pasid_states(struct device_state *dev_state);
static void unbind_pasid(struct device_state *dev_state, int pasid);
static int task_exit(struct notifier_block *nb, unsigned long e, void *data);

static u16 device_id(struct pci_dev *pdev)
{
	u16 devid;

    if (!pdev) {
        printk("device_id null\n");
        return;
    }

	devid = pdev->bus->number;
	devid = (devid << 8) | pdev->devfn;

	return devid;
}

static struct device_state *get_device_state(u16 devid)
{
	struct device_state *dev_state;
	unsigned long flags;

	spin_lock_irqsave(&state_lock, flags);
	dev_state = state_table[devid];
	if (dev_state != NULL)
		atomic_inc(&dev_state->count);
	spin_unlock_irqrestore(&state_lock, flags);

	return dev_state;
}

static void free_device_state(struct device_state *dev_state)
{
	/*
	 * First detach device from domain - No more PRI requests will arrive
	 * from that device after it is unbound from the IOMMUv2 domain.
	 */
	iommu_detach_device(dev_state->domain, &dev_state->pdev->dev);

	/* Everything is down now, free the IOMMUv2 domain */
	iommu_domain_free(dev_state->domain);

	/* Finally get rid of the device-state */
	kfree(dev_state);
}

static void put_device_state(struct device_state *dev_state)
{
	if (atomic_dec_and_test(&dev_state->count))
		wake_up(&dev_state->wq);
}

static void put_device_state_wait(struct device_state *dev_state)
{
	DEFINE_WAIT(wait);

	prepare_to_wait(&dev_state->wq, &wait, TASK_UNINTERRUPTIBLE);
	if (!atomic_dec_and_test(&dev_state->count))
		schedule();
	finish_wait(&dev_state->wq, &wait);

	free_device_state(dev_state);
}

static struct notifier_block profile_nb = {
	.notifier_call = task_exit,
};

static void link_pasid_state(struct pasid_state *pasid_state)
{
	spin_lock(&ps_lock);
	list_add_tail(&pasid_state->list, &pasid_state_list);
	spin_unlock(&ps_lock);
}

static void __unlink_pasid_state(struct pasid_state *pasid_state)
{
	list_del(&pasid_state->list);
}

static void unlink_pasid_state(struct pasid_state *pasid_state)
{
	spin_lock(&ps_lock);
	__unlink_pasid_state(pasid_state);
	spin_unlock(&ps_lock);
}

/* Must be called under dev_state->lock */
static struct pasid_state **__get_pasid_state_ptr(struct device_state *dev_state,
						  int pasid, bool alloc)
{
	struct pasid_state **root, **ptr;
	int level, index;

	level = dev_state->pasid_levels;
	root  = dev_state->states;

	while (true) {

		index = (pasid >> (9 * level)) & 0x1ff;
		ptr   = &root[index];

		if (level == 0)
			break;

		if (*ptr == NULL) {
			if (!alloc)
				return NULL;

			*ptr = (void *)get_zeroed_page(GFP_ATOMIC);
			if (*ptr == NULL)
				return NULL;
		}

		root   = (struct pasid_state **)*ptr;
		level -= 1;
	}

	return ptr;
}

static int set_pasid_state(struct device_state *dev_state,
			   struct pasid_state *pasid_state,
			   int pasid)
{
	struct pasid_state **ptr;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&dev_state->lock, flags);
	ptr = __get_pasid_state_ptr(dev_state, pasid, true);
    printk("set_pasid_state ptr=%p\n", ptr);

	ret = -ENOMEM;
	if (ptr == NULL)
		goto out_unlock;

	ret = -ENOMEM;
	if (*ptr != NULL)
		goto out_unlock;

	*ptr = pasid_state;

	ret = 0;

out_unlock:
	spin_unlock_irqrestore(&dev_state->lock, flags);

	return ret;
}

static void clear_pasid_state(struct device_state *dev_state, int pasid)
{
	struct pasid_state **ptr;
	unsigned long flags;

	spin_lock_irqsave(&dev_state->lock, flags);
	ptr = __get_pasid_state_ptr(dev_state, pasid, true);

	if (ptr == NULL)
		goto out_unlock;

	*ptr = NULL;

out_unlock:
	spin_unlock_irqrestore(&dev_state->lock, flags);
}

static struct pasid_state *get_pasid_state(struct device_state *dev_state,
					   int pasid)
{
	struct pasid_state **ptr, *ret = NULL;
	unsigned long flags;

	spin_lock_irqsave(&dev_state->lock, flags);
	ptr = __get_pasid_state_ptr(dev_state, pasid, false);

	if (ptr == NULL)
		goto out_unlock;

	ret = *ptr;
	if (ret)
		atomic_inc(&ret->count);

out_unlock:
	spin_unlock_irqrestore(&dev_state->lock, flags);

	return ret;
}

static void free_pasid_state(struct pasid_state *pasid_state)
{
	kfree(pasid_state);
}

void put_pasid_state(struct pasid_state *pasid_state)
{
	if (atomic_dec_and_test(&pasid_state->count)) {
		put_device_state(pasid_state->device_state);
		wake_up(&pasid_state->wq);
	}
}

static void put_pasid_state_wait(struct pasid_state *pasid_state)
{
	DEFINE_WAIT(wait);

	prepare_to_wait(&pasid_state->wq, &wait, TASK_UNINTERRUPTIBLE);

	if (atomic_dec_and_test(&pasid_state->count))
		put_device_state(pasid_state->device_state);
	else
		schedule();

	finish_wait(&pasid_state->wq, &wait);
	mmput(pasid_state->mm);
	free_pasid_state(pasid_state);
}

static void __unbind_pasid(struct pasid_state *pasid_state)
{
	struct iommu_domain *domain;

	domain = pasid_state->device_state->domain;

	amd_iommu_domain_clear_gcr3(domain, pasid_state->pasid);
	clear_pasid_state(pasid_state->device_state, pasid_state->pasid);

	/* Make sure no more pending faults are in the queue */
	flush_workqueue(iommu_wq);

	mmu_notifier_unregister(&pasid_state->mn, pasid_state->mm);

	put_pasid_state(pasid_state); /* Reference taken in bind() function */
}

static void unbind_pasid(struct device_state *dev_state, int pasid)
{
	struct pasid_state *pasid_state;

	pasid_state = get_pasid_state(dev_state, pasid);
	if (pasid_state == NULL)
		return;

	unlink_pasid_state(pasid_state);
	__unbind_pasid(pasid_state);
	put_pasid_state_wait(pasid_state); /* Reference taken in this function */
}

static void free_pasid_states_level1(struct pasid_state **tbl)
{
	int i;

	for (i = 0; i < 512; ++i) {
		if (tbl[i] == NULL)
			continue;

		free_page((unsigned long)tbl[i]);
	}
}

static void free_pasid_states_level2(struct pasid_state **tbl)
{
	struct pasid_state **ptr;
	int i;

	for (i = 0; i < 512; ++i) {
		if (tbl[i] == NULL)
			continue;

		ptr = (struct pasid_state **)tbl[i];
		free_pasid_states_level1(ptr);
	}
}

static void free_pasid_states(struct device_state *dev_state)
{
	struct pasid_state *pasid_state;
	int i;

	for (i = 0; i < dev_state->max_pasids; ++i) {
		pasid_state = get_pasid_state(dev_state, i);
		if (pasid_state == NULL)
			continue;

		put_pasid_state(pasid_state);
		unbind_pasid(dev_state, i);
	}

	if (dev_state->pasid_levels == 2)
		free_pasid_states_level2(dev_state->states);
	else if (dev_state->pasid_levels == 1)
		free_pasid_states_level1(dev_state->states);
	else if (dev_state->pasid_levels != 0)
		BUG();

	free_page((unsigned long)dev_state->states);
}

static struct pasid_state *mn_to_state(struct mmu_notifier *mn)
{
	return container_of(mn, struct pasid_state, mn);
}

static void __mn_flush_page(struct mmu_notifier *mn,
			    unsigned long address)
{
	struct pasid_state *pasid_state;
	struct device_state *dev_state;

	pasid_state = mn_to_state(mn);
	dev_state   = pasid_state->device_state;

	amd_iommu_flush_page(dev_state->domain, pasid_state->pasid, address);
}

static int mn_clear_flush_young(struct mmu_notifier *mn,
				struct mm_struct *mm,
				unsigned long address)
{
    printk("mn_clear_flush_young\n");
	__mn_flush_page(mn, address);

	return 0;
}

static void mn_change_pte(struct mmu_notifier *mn,
			  struct mm_struct *mm,
			  unsigned long address,
			  pte_t pte)
{
    printk("mn_change_pte\n");
	__mn_flush_page(mn, address);
}

static void mn_invalidate_page(struct mmu_notifier *mn,
			       struct mm_struct *mm,
			       unsigned long address)
{
    printk("mn_invalidate_page\n");
	__mn_flush_page(mn, address);
}

static void mn_invalidate_range(struct mmu_notifier *mn,
				struct mm_struct *mm,
				unsigned long start, unsigned long end)
{
	struct pasid_state *pasid_state;
	struct device_state *dev_state;

    printk("mn_invalidate_range\n");
	pasid_state = mn_to_state(mn);
	dev_state   = pasid_state->device_state;
/*
	if ((start ^ (end - 1)) < PAGE_SIZE)
		amd_iommu_flush_page(dev_state->domain, pasid_state->pasid,
				     start);
	else*/
		amd_iommu_flush_tlb(dev_state->domain, pasid_state->pasid);
}

static void mn_invalidate_range_start(struct mmu_notifier *mn,
				      struct mm_struct *mm,
				      unsigned long start, unsigned long end)
{
	struct pasid_state *pasid_state;
	struct device_state *dev_state;

    printk("mn_invalidate_range_start\n");
	pasid_state = mn_to_state(mn);
	dev_state   = pasid_state->device_state;

	/*
	 * Invalidate IOMMU TLB and IOTLB (FIXME: invalidate range only)
	 * FIXME: races if IOTLB actively using page range being invalidated
	 */
	amd_iommu_flush_tlb(dev_state->domain, pasid_state->pasid);
}

static struct mmu_notifier_ops iommu_mn = {
	.clear_flush_young      = mn_clear_flush_young,
	.change_pte             = mn_change_pte,
	.invalidate_page        = mn_invalidate_page,
	.invalidate_range_start = mn_invalidate_range_start,
};

void set_pri_tag_status(struct pasid_state *pasid_state,
			       u16 tag, int status)
{
	unsigned long flags;

    printk("set_pri_tag_status %d\n", status);
	spin_lock_irqsave(&pasid_state->lock, flags);
	pasid_state->pri[tag].status = status;
	spin_unlock_irqrestore(&pasid_state->lock, flags);
}

#ifdef CONFIG_HSA_VIRTUALIZATION
void finish_pri_tag(struct device_state *dev_state,
			   struct pasid_state *pasid_state,
			   u16 tag, bool gn)
{
	unsigned long flags;

    printk("finish_pri_tag tag=%d\n", tag);
	spin_lock_irqsave(&pasid_state->lock, flags);
	if (atomic_dec_and_test(&pasid_state->pri[tag].inflight) &&
	    pasid_state->pri[tag].finish) {
		amd_iommu_complete_ppr(dev_state->pdev, pasid_state->pasid,
				       pasid_state->pri[tag].status, tag, gn);
		pasid_state->pri[tag].finish = false;
		pasid_state->pri[tag].status = PPR_SUCCESS;
	}
	spin_unlock_irqrestore(&pasid_state->lock, flags);
}
#else
void finish_pri_tag(struct device_state *dev_state,
			   struct pasid_state *pasid_state,
			   u16 tag)
{
	unsigned long flags;

    printk("finish_pri_tag tag=%d\n", tag);
	spin_lock_irqsave(&pasid_state->lock, flags);
	if (atomic_dec_and_test(&pasid_state->pri[tag].inflight) &&
	    pasid_state->pri[tag].finish) {
		amd_iommu_complete_ppr(dev_state->pdev, pasid_state->pasid,
				       pasid_state->pri[tag].status, tag);
		pasid_state->pri[tag].finish = false;
		pasid_state->pri[tag].status = PPR_SUCCESS;
	}
	spin_unlock_irqrestore(&pasid_state->lock, flags);
}
#endif

static void do_fault(struct work_struct *work)
{
	struct fault *fault = container_of(work, struct fault, work);
	int npages, write, gn;
	struct page *page;

	write = !!(fault->flags & PPR_FAULT_WRITE);
    gn    = !!(fault->flags & PPR_FAULT_GN);

    printk("do_fault: gn=%d, write=%d, pdev=%p, domain=%p, pasid=%d, task=%p, mm=%p\n", gn, write, fault->dev_state->pdev, fault->dev_state->domain, fault->state->pasid, fault->state->task, fault->state->mm);
    printk("addr=0x%llx, pasid=%d, fault_tag=%d\n", fault->address, fault->pasid, fault->tag);

#ifdef CONFIG_HSA_VIRTUALIZATION
    if (fault->state->virtio_be_mm && gn) {
        return amd_iommu_vm_ppr(fault, write);
    }
#endif

	down_read(&fault->state->mm->mmap_sem);
	npages = get_user_pages(fault->state->task, fault->state->mm,
				fault->address, 1, write, 0, &page, NULL);
	up_read(&fault->state->mm->mmap_sem);

	if (npages == 1) {
		put_page(page);
	} else if (fault->dev_state->inv_ppr_cb) {
		int status;

		status = fault->dev_state->inv_ppr_cb(fault->dev_state->pdev,
						      fault->pasid,
						      fault->address,
						      fault->flags);
		switch (status) {
		case AMD_IOMMU_INV_PRI_RSP_SUCCESS:
			set_pri_tag_status(fault->state, fault->tag, PPR_SUCCESS);
			break;
		case AMD_IOMMU_INV_PRI_RSP_INVALID:
			set_pri_tag_status(fault->state, fault->tag, PPR_INVALID);
			break;
		case AMD_IOMMU_INV_PRI_RSP_FAIL:
			set_pri_tag_status(fault->state, fault->tag, PPR_FAILURE);
			break;
		default:
			BUG();
		}
	} else {
		set_pri_tag_status(fault->state, fault->tag, PPR_INVALID);
	}

#ifdef CONFIG_HSA_VIRTUALIZATION
	finish_pri_tag(fault->dev_state, fault->state, fault->tag, 0);
#else
	finish_pri_tag(fault->dev_state, fault->state, fault->tag);
#endif

	put_pasid_state(fault->state);

	kfree(fault);
}

static int ppr_notifier(struct notifier_block *nb, unsigned long e, void *data)
{
	struct amd_iommu_fault *iommu_fault;
	struct pasid_state *pasid_state;
	struct device_state *dev_state;
	unsigned long flags;
	struct fault *fault;
	bool finish;
	u16 tag;
	int ret;

	iommu_fault = data;
	tag         = iommu_fault->tag & 0x1ff;
	finish      = (iommu_fault->tag >> 9) & 1;
    printk("ppr_notifier, device_id=%d, pasid=%d tag=%d ... ", iommu_fault->device_id, iommu_fault->pasid, tag);

	ret = NOTIFY_DONE;
	dev_state = get_device_state(iommu_fault->device_id);
	if (dev_state == NULL) {
        printk("!!! dev_state NUL\n");
		goto out;
    }
    printk("dev_state=%p ", dev_state);

	pasid_state = get_pasid_state(dev_state, iommu_fault->pasid);
	if (pasid_state == NULL) {
        printk("!!! pasid_state NULL\n");
		/* We know the device but not the PASID -> send INVALID */
#ifdef CONFIG_HSA_VIRTUALIZATION
		amd_iommu_complete_ppr(dev_state->pdev, iommu_fault->pasid,
				       PPR_INVALID, tag, 0);
#else
		amd_iommu_complete_ppr(dev_state->pdev, iommu_fault->pasid,
				       PPR_INVALID, tag);
#endif
		goto out_drop_state;
	}
    printk("pasid_state=%p\n", pasid_state);
    
	spin_lock_irqsave(&pasid_state->lock, flags);
	atomic_inc(&pasid_state->pri[tag].inflight);
	if (finish)
		pasid_state->pri[tag].finish = true;
	spin_unlock_irqrestore(&pasid_state->lock, flags);

	fault = kzalloc(sizeof(*fault), GFP_ATOMIC);
	if (fault == NULL) {
        printk("!!! alloc fault faul\n");
		/* We are OOM - send success and let the device re-fault */
#ifdef CONFIG_HSA_VIRTUALIZATION
		finish_pri_tag(dev_state, pasid_state, tag, 0);
#else
		finish_pri_tag(dev_state, pasid_state, tag);
#endif
		goto out_drop_state;
	}

	fault->dev_state = dev_state;
	fault->address   = iommu_fault->address;
	fault->state     = pasid_state;
	fault->tag       = tag;
	fault->finish    = finish;
	fault->pasid     = iommu_fault->pasid;
	fault->flags     = iommu_fault->flags;
	INIT_WORK(&fault->work, do_fault);

	queue_work(iommu_wq, &fault->work);

	ret = NOTIFY_OK;

out_drop_state:
	put_device_state(dev_state);

out:
	return ret;
}

static struct notifier_block ppr_nb = {
	.notifier_call = ppr_notifier,
};

static int task_exit(struct notifier_block *nb, unsigned long e, void *data)
{
	struct pasid_state *pasid_state;
	struct task_struct *task;

	task = data;

	/*
	 * Using this notifier is a hack - but there is no other choice
	 * at the moment. What I really want is a sleeping notifier that
	 * is called when an MM goes down. But such a notifier doesn't
	 * exist yet. The notifier needs to sleep because it has to make
	 * sure that the device does not use the PASID and the address
	 * space anymore before it is destroyed. This includes waiting
	 * for pending PRI requests to pass the workqueue. The
	 * MMU-Notifiers would be a good fit, but they use RCU and so
	 * they are not allowed to sleep. Lets see how we can solve this
	 * in a more intelligent way in the future.
	 */
again:
	spin_lock(&ps_lock);
	list_for_each_entry(pasid_state, &pasid_state_list, list) {
		struct device_state *dev_state;
		int pasid;

		if (pasid_state->task != task)
			continue;

		/* Drop Lock and unbind */
		spin_unlock(&ps_lock);

		dev_state = pasid_state->device_state;
		pasid     = pasid_state->pasid;

		if (pasid_state->device_state->inv_ctx_cb)
			dev_state->inv_ctx_cb(dev_state->pdev, pasid);

		unbind_pasid(dev_state, pasid);

		/* Task may be in the list multiple times */
		goto again;
	}
	spin_unlock(&ps_lock);

	return NOTIFY_OK;
}

#ifdef CONFIG_HSA_VIRTUALIZATION
int amd_iommu_is_nested_translation(struct pci_dev *pdev)
{
	struct device_state *dev_state;
    struct iommu_domain *dom;
    struct protection_domain *domain;
	u16 devid;

	might_sleep();

	if (!amd_iommu_v2_supported())
		return -ENODEV;

	devid     = device_id(pdev);
	dev_state = get_device_state(devid);

	if (dev_state == NULL)
		return -EINVAL;

    dom = dev_state->domain;
    domain = dom->priv;
    printk("amd_iommu_is_nested_translation: mode=%d\n", domain->mode);
    
    return domain->mode;
}
EXPORT_SYMBOL(amd_iommu_is_nested_translation);

int amd_iommu_enable_nested_translation(struct pci_dev *pdev, int level)
{
	struct device_state *dev_state;
    struct iommu_domain *dom;
    struct protection_domain *domain;
	u16 devid;

	might_sleep();

	if (!amd_iommu_v2_supported())
		return -ENODEV;

	devid     = device_id(pdev);
	dev_state = get_device_state(devid);

	if (dev_state == NULL)
		return -EINVAL;

    dom = dev_state->domain;
    domain = dom->priv;
    
    domain->mode = level;
    printk("=====amd_iommu_enable_nested_translation domain=%p, mode=%d\n", domain, domain->mode);

    domain->updated = true;
    update_domain(domain);
    return 0;
}
EXPORT_SYMBOL(amd_iommu_enable_nested_translation);

int amd_iommu_disable_nested_translation(struct pci_dev *pdev)
{
	struct device_state *dev_state;
    struct iommu_domain *dom;
    struct protection_domain *domain;
	u16 devid;

	might_sleep();

	if (!amd_iommu_v2_supported())
		return -ENODEV;

	devid     = device_id(pdev);
	dev_state = get_device_state(devid);

	if (dev_state == NULL)
		return -EINVAL;

    dom = dev_state->domain;
    domain = dom->priv;
    
    domain->mode = 0;
    printk("=====amd_iommu_disable_nested_translation domain=%p, mode=%d\n", domain, domain->mode);

    domain->updated = true;
    update_domain(domain);
    return 0;
}
EXPORT_SYMBOL(amd_iommu_disable_nested_translation);

int amd_iommu_set_nested_cr3(struct pci_dev *pdev, u64 nested_cr3)
{
	struct device_state *dev_state;
    struct iommu_domain *dom;
    struct protection_domain *domain;
	u16 devid;

	might_sleep();

	if (!amd_iommu_v2_supported())
		return -ENODEV;

	devid     = device_id(pdev);
	dev_state = get_device_state(devid);

	if (dev_state == NULL)
		return -EINVAL;

    dom = dev_state->domain;
    domain = dom->priv;
    printk("=====amd_iommu_set_nested_cr3 domain=%p, pt_root=%llx, __va(nested_cr3)=%llx\n", domain, domain->pt_root, __va(nested_cr3));

    domain->pt_root = __va(nested_cr3);     // set_dte_entry will call virt_to_phys
    printk("=====amd_iommu_set_nested_cr3 domain=%p, pt_root=%llx\n", domain, domain->pt_root);

    domain->updated = true;
    update_domain(domain);
	return 0;
}
EXPORT_SYMBOL(amd_iommu_set_nested_cr3);

int amd_iommu_vm_process_bind_pasid(struct pci_dev *pdev, int pasid, struct kvm *kvm, 
             struct mm_struct *virtio_be_mm, struct task_struct *vm_task, 
             struct mm_struct *vm_mm, unsigned long gcr3)
{
	struct pasid_state *pasid_state;
	struct device_state *dev_state;
	u16 devid;
	int ret;

	might_sleep();

	if (!amd_iommu_v2_supported())
		return -ENODEV;

    if (!pdev) {
        printk("amd_iommu_vm_process_bind_pasid, pdev null\n");
        return -1;
    }

	devid     = device_id(pdev);
	dev_state = get_device_state(devid);
    printk("devid=%d, dev_state=%p\n", devid, dev_state);
    printk("amd_iommu_vm_process_bind_pasid, pdev=%p task=%p, mm=%p, pasid=%d, gcr3=0x%llx\n", pdev, vm_task, vm_mm, pasid, gcr3);

	if (dev_state == NULL)
		return -EINVAL;

	ret = -EINVAL;
	if (pasid < 0 || pasid >= dev_state->max_pasids)
		goto out;

	ret = -ENOMEM;
	pasid_state = kzalloc(sizeof(*pasid_state), GFP_KERNEL);
	if (pasid_state == NULL)
		goto out;

	atomic_set(&pasid_state->count, 1);
	init_waitqueue_head(&pasid_state->wq);
	spin_lock_init(&pasid_state->lock);

	pasid_state->task         = vm_task;
	pasid_state->mm           = vm_mm;
    pasid_state->kvm          = kvm;
	pasid_state->device_state = dev_state;
	pasid_state->pasid        = pasid;
	pasid_state->mn.ops       = &iommu_mn;  // cpu modify page table cause iommu flust
    pasid_state->virtio_be_mm = virtio_be_mm;

	if (pasid_state->mm == NULL)
		goto out_free;

	ret = set_pasid_state(dev_state, pasid_state, pasid);
	if (ret) {
        printk("!!! set_pasid_state fail %d\n", ret);
		goto out_free;
    }

	ret = amd_iommu_domain_set_gcr3(dev_state->domain, pasid, gcr3);
    printk("amd_iommu_vm_process_bind_pasid, pdev=%p, domain=%p, task=%p, mm=%p, pasid=%d, gcr3=0x%llx\n", pdev, dev_state->domain, vm_task, vm_mm, pasid, gcr3);
	if (ret) {
        printk("!!! amd_iommu_domain_set_gcr3 fail %d\n", ret);
		goto out_clear_state;
    }

	link_pasid_state(pasid_state);

	return 0;

out_clear_state:
    printk("out_clear_state\n");
	clear_pasid_state(dev_state, pasid);

out_free:
    printk("out_free\n");
	free_pasid_state(pasid_state);

out:
    printk("out\n");
	put_device_state(dev_state);

	return ret;
}
EXPORT_SYMBOL(amd_iommu_vm_process_bind_pasid);

int amd_iommu_set_gcr3(struct pci_dev *pdev, int pasid, unsigned long gcr3)
{
	struct device_state *dev_state;
	u16 devid;

    if (!pdev) {
        printk("amd_iommu_set_gcr3, pdev null\n");
        return -EINVAL;
    }

	devid     = device_id(pdev);
	dev_state = get_device_state(devid);

    printk("amd_iommu_set_gcr3, dev_state=%p\n", dev_state);
    if (!dev_state)
        return -EINVAL;

    printk("amd_iommu_set_gcr3 domain=%p, pasid=%d, gcr3=%llx\n", dev_state->domain, pasid, gcr3);
    return amd_iommu_domain_set_gcr3(dev_state->domain, pasid, gcr3);
}
EXPORT_SYMBOL(amd_iommu_set_gcr3);
#endif

int amd_iommu_bind_pasid(struct pci_dev *pdev, int pasid,
			 struct task_struct *task)
{
	struct pasid_state *pasid_state;
	struct device_state *dev_state;
	u16 devid;
	int ret;

	might_sleep();

	if (!amd_iommu_v2_supported())
		return -ENODEV;

	devid     = device_id(pdev);
	dev_state = get_device_state(devid);
    printk("devid=%d, dev_state=%p\n", devid, dev_state);

	if (dev_state == NULL)
		return -EINVAL;

	ret = -EINVAL;
	if (pasid < 0 || pasid >= dev_state->max_pasids)
		goto out;

	ret = -ENOMEM;
	pasid_state = kzalloc(sizeof(*pasid_state), GFP_KERNEL);
	if (pasid_state == NULL)
		goto out;

	atomic_set(&pasid_state->count, 1);
	init_waitqueue_head(&pasid_state->wq);
	spin_lock_init(&pasid_state->lock);

	pasid_state->task         = task;
	pasid_state->mm           = get_task_mm(task);
	pasid_state->device_state = dev_state;
	pasid_state->pasid        = pasid;
	pasid_state->mn.ops       = &iommu_mn;

	if (pasid_state->mm == NULL)
		goto out_free;

	mmu_notifier_register(&pasid_state->mn, pasid_state->mm);

	ret = set_pasid_state(dev_state, pasid_state, pasid);
	if (ret)
		goto out_unregister;

	ret = amd_iommu_domain_set_gcr3(dev_state->domain, pasid,
					__pa(pasid_state->mm->pgd));
    printk("amd_iommu_bind_pasid, __pa=0x%llx, virt_to_phys=0x%llx\n", 
                __pa(pasid_state->mm->pgd), virt_to_phys(pasid_state->mm->pgd));
	if (ret)
		goto out_clear_state;

	link_pasid_state(pasid_state);

	return 0;

out_clear_state:
	clear_pasid_state(dev_state, pasid);

out_unregister:
	mmu_notifier_unregister(&pasid_state->mn, pasid_state->mm);

out_free:
	free_pasid_state(pasid_state);

out:
	put_device_state(dev_state);

	return ret;
}
EXPORT_SYMBOL(amd_iommu_bind_pasid);

void amd_iommu_unbind_pasid(struct pci_dev *pdev, int pasid)
{
	struct device_state *dev_state;
	u16 devid;

	might_sleep();

	if (!amd_iommu_v2_supported())
		return;

	devid = device_id(pdev);
	dev_state = get_device_state(devid);
	if (dev_state == NULL)
		return;

	if (pasid < 0 || pasid >= dev_state->max_pasids)
		goto out;

	unbind_pasid(dev_state, pasid);

out:
	put_device_state(dev_state);
}
EXPORT_SYMBOL(amd_iommu_unbind_pasid);

int amd_iommu_init_device(struct pci_dev *pdev, int pasids)
{
	struct device_state *dev_state;
	unsigned long flags;
	int ret, tmp;
	u16 devid;

	might_sleep();

	if (!amd_iommu_v2_supported())
		return -ENODEV;

	if (pasids <= 0 || pasids > (PASID_MASK + 1))
		return -EINVAL;

	devid = device_id(pdev);

	dev_state = kzalloc(sizeof(*dev_state), GFP_KERNEL);
	if (dev_state == NULL)
		return -ENOMEM;

	spin_lock_init(&dev_state->lock);
	init_waitqueue_head(&dev_state->wq);
	dev_state->pdev = pdev;

	tmp = pasids;
	for (dev_state->pasid_levels = 0; (tmp - 1) & ~0x1ff; tmp >>= 9)
		dev_state->pasid_levels += 1;

	atomic_set(&dev_state->count, 1);
	dev_state->max_pasids = pasids;

	ret = -ENOMEM;
	dev_state->states = (void *)get_zeroed_page(GFP_KERNEL);
	if (dev_state->states == NULL)
		goto out_free_dev_state;

	dev_state->domain = iommu_domain_alloc(&pci_bus_type);
	if (dev_state->domain == NULL)
		goto out_free_states;

	amd_iommu_domain_direct_map(dev_state->domain);

	ret = amd_iommu_domain_enable_v2(dev_state->domain, pasids);
	if (ret)
		goto out_free_domain;

	ret = iommu_attach_device(dev_state->domain, &pdev->dev);
	if (ret != 0)
		goto out_free_domain;

	spin_lock_irqsave(&state_lock, flags);

	if (state_table[devid] != NULL) {
		spin_unlock_irqrestore(&state_lock, flags);
		ret = -EBUSY;
		goto out_free_domain;
	}

	state_table[devid] = dev_state;

	spin_unlock_irqrestore(&state_lock, flags);

	return 0;

out_free_domain:
	iommu_domain_free(dev_state->domain);

out_free_states:
	free_page((unsigned long)dev_state->states);

out_free_dev_state:
	kfree(dev_state);

	return ret;
}
EXPORT_SYMBOL(amd_iommu_init_device);

void amd_iommu_free_device(struct pci_dev *pdev)
{
	struct device_state *dev_state;
	unsigned long flags;
	u16 devid;

	if (!amd_iommu_v2_supported())
		return;

	devid = device_id(pdev);

	spin_lock_irqsave(&state_lock, flags);

	dev_state = state_table[devid];
	if (dev_state == NULL) {
		spin_unlock_irqrestore(&state_lock, flags);
		return;
	}

	state_table[devid] = NULL;

	spin_unlock_irqrestore(&state_lock, flags);

	/* Get rid of any remaining pasid states */
	free_pasid_states(dev_state);

	put_device_state_wait(dev_state);
}
EXPORT_SYMBOL(amd_iommu_free_device);

int amd_iommu_set_invalid_ppr_cb(struct pci_dev *pdev,
				 amd_iommu_invalid_ppr_cb cb)
{
	struct device_state *dev_state;
	unsigned long flags;
	u16 devid;
	int ret;

	if (!amd_iommu_v2_supported())
		return -ENODEV;

	devid = device_id(pdev);

	spin_lock_irqsave(&state_lock, flags);

	ret = -EINVAL;
	dev_state = state_table[devid];
	if (dev_state == NULL)
		goto out_unlock;

	dev_state->inv_ppr_cb = cb;

	ret = 0;

out_unlock:
	spin_unlock_irqrestore(&state_lock, flags);

	return ret;
}
EXPORT_SYMBOL(amd_iommu_set_invalid_ppr_cb);

int amd_iommu_set_invalidate_ctx_cb(struct pci_dev *pdev,
				    amd_iommu_invalidate_ctx cb)
{
	struct device_state *dev_state;
	unsigned long flags;
	u16 devid;
	int ret;

	if (!amd_iommu_v2_supported())
		return -ENODEV;

	devid = device_id(pdev);

	spin_lock_irqsave(&state_lock, flags);

	ret = -EINVAL;
	dev_state = state_table[devid];
	if (dev_state == NULL)
		goto out_unlock;

	dev_state->inv_ctx_cb = cb;

	ret = 0;

out_unlock:
	spin_unlock_irqrestore(&state_lock, flags);

	return ret;
}
EXPORT_SYMBOL(amd_iommu_set_invalidate_ctx_cb);

static int __init amd_iommu_v2_init(void)
{
	size_t state_table_size;
	int ret;

	pr_info("AMD IOMMUv2 driver by Joerg Roedel <joerg.roedel@amd.com>\n");

	if (!amd_iommu_v2_supported()) {
		pr_info("AMD IOMMUv2 functionality not available on this system\n");
		/*
		 * Load anyway to provide the symbols to other modules
		 * which may use AMD IOMMUv2 optionally.
		 */
		return 0;
	}

	spin_lock_init(&state_lock);

	state_table_size = MAX_DEVICES * sizeof(struct device_state *);
	state_table = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
					       get_order(state_table_size));
	if (state_table == NULL)
		return -ENOMEM;

	ret = -ENOMEM;
	iommu_wq = create_workqueue("amd_iommu_v2");
	if (iommu_wq == NULL)
		goto out_free;

    printk("amd_iommu_register_ppr_notifier\n");
	amd_iommu_register_ppr_notifier(&ppr_nb);
	profile_event_register(PROFILE_TASK_EXIT, &profile_nb);

	return 0;

out_free:
	free_pages((unsigned long)state_table, get_order(state_table_size));

	return ret;
}

static void __exit amd_iommu_v2_exit(void)
{
	struct device_state *dev_state;
	size_t state_table_size;
	int i;

	if (!amd_iommu_v2_supported())
		return;

	profile_event_unregister(PROFILE_TASK_EXIT, &profile_nb);
	amd_iommu_unregister_ppr_notifier(&ppr_nb);

	flush_workqueue(iommu_wq);

	/*
	 * The loop below might call flush_workqueue(), so call
	 * destroy_workqueue() after it
	 */
	for (i = 0; i < MAX_DEVICES; ++i) {
		dev_state = get_device_state(i);

		if (dev_state == NULL)
			continue;

		WARN_ON_ONCE(1);

		put_device_state(dev_state);
		amd_iommu_free_device(dev_state->pdev);
	}

	destroy_workqueue(iommu_wq);

	state_table_size = MAX_DEVICES * sizeof(struct device_state *);
	free_pages((unsigned long)state_table, get_order(state_table_size));
}

module_init(amd_iommu_v2_init);
module_exit(amd_iommu_v2_exit);
