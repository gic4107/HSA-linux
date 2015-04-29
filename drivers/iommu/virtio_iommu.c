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
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/iommu.h>
#include <linux/wait.h>
#include <linux/pci.h>
#include <linux/gfp.h>
#include <linux/idr.h>
#include <linux/virtio.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_ids.h>
#include <linux/uaccess.h>
//FIXME: Debug
#include <linux/highmem.h>

#include "amd_iommu_types.h"
#include "amd_iommu_proto.h"
#include "amd_iommu_vm_ppr.h"
#include "virtio_iommu.h"

// FIXME: debug
void dump_mqd(void *mqd);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Yu-Ju Huang <gic4107@gmail.com>");

static DEFINE_IDA(virtio_iommu_index_ida);

#define MAX_DEVICES		0x10000
#define PRI_QUEUE_SIZE		512
#define MINORBITS 20
#define PART_BITS 4

static struct virtio_iommu *viommu;
static struct iommu_vm_ppr *ppr;

static int minor_to_index(int minor)
{
	return minor >> PART_BITS;
}

static void virtio_iommu_free_req_param(void *data)
{
//    printk("virtio_iommu_free_req_param, data=%p\n", data);
    kfree(data);
}

int virtio_iommu_add_req0_no_wait(int cmd)
{
    printk("virtio_iommu_add_req0, command=%d\n", cmd);
    struct virtio_iommu_req *req;
    struct scatterlist sg_cmd, sg_status, *sgs[2];
    int num_in=0, num_out=0; 
    struct virtqueue *vq = viommu->vq;
    int ret;
    
	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		printk("virtio_iommu_req alloc fail\n");
        return -1;
	}
    req->wait  = VIRTIO_IOMMU_REQ_NO_WAIT;
    req->cb = NULL;
    req->command = cmd;

    sg_init_one(&sg_cmd, &req->command, sizeof(req->command));
    sg_init_one(&sg_status, &req->status, sizeof(req->status));
    sgs[num_out++] = &sg_cmd;
    sgs[num_out+num_in++] = &sg_status;

    ret = virtqueue_add_sgs(vq, sgs, num_out, num_in, req, GFP_ATOMIC);
    if(ret < 0) {
        printk("virtqueue_add_sgs return %d\n", ret);
        virtqueue_kick(vq);
        return -1;
    }

    ret = virtqueue_kick(vq);
    if(!ret) {
        printk("virtqueue_kick return %d\n", ret);
        return -1;
    }

    return 0;
}

int virtio_iommu_add_req(int cmd, void *param, int param_len, int wait, void (*cb)(void* data))
{
    printk("virtio_iommu_add_req, command=%d, param=%p, wait=%d\n", cmd, param, wait);
    struct virtio_iommu_req *req;
    struct scatterlist sg_cmd, sg_param, sg_status, *sgs[3];
    int num_in=0, num_out=0; 
    struct virtqueue *vq = viommu->vq;
    int ret;
    
	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		printk("virtio_iommu_req alloc fail\n");
        return -1;
	}
    
    if (wait) 
        req->wait  = VIRTIO_IOMMU_REQ_WAIT;
    else 
        req-> wait = VIRTIO_IOMMU_REQ_NO_WAIT;
    req->cb = cb;
    req->command = cmd;
    req->param   = param;

    sg_init_one(&sg_cmd, &req->command, sizeof(req->command));
    sg_init_one(&sg_param, req->param, param_len);
    sg_init_one(&sg_status, &req->status, sizeof(req->status));
    sgs[num_out++] = &sg_cmd;
    sgs[num_out+num_in++] = &sg_param;
    sgs[num_out+num_in++] = &sg_status;

    ret = virtqueue_add_sgs(vq, sgs, num_out, num_in, req, GFP_ATOMIC);
    if(ret < 0) {
        printk("virtqueue_add_sgs return %d\n", ret);
        virtqueue_kick(vq);
        return -1;
    }

    ret = virtqueue_kick(vq);
    if(!ret) {
        printk("virtqueue_kick return %d\n", ret);
        return -1;
    }

    if (wait) {
        printk("virtqueue_kick done, wait %p\n", &req->wait);
        while(req->wait == VIRTIO_IOMMU_REQ_WAIT);        // signal by callback function
        kfree(req); 
    }

    return 0;
}

int virtio_iommu_add_req_wait(int cmd, void *param, int param_len, void (*cb)(void* data))
{
    return virtio_iommu_add_req(cmd, param, param_len, 1, cb);
}

int virtio_iommu_add_req_no_wait(int cmd, void *param, int param_len, void (*cb)(void* data))
{
    return virtio_iommu_add_req(cmd, param, param_len, 0, cb);
}

uint64_t walk_page_table2(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    uint64_t gpa;

    pgd = pgd_offset(mm, addr);
    if (!pgd_present(*pgd))
        return NULL;
    printk("pgd=%p, pgd_val=%llx\n", pgd, pgd_val(*pgd));
    
    pud = pud_offset(pgd, addr);
    if (!pud_present(*pud))
        return NULL;
    printk("pud=%p, pud_val=%llx\n", pud, pud_val(*pud));
    
    pmd = pmd_offset(pud, addr);
    if (!pmd_present(*pmd))
        return NULL;
    printk("pmd=%p, pmd_val=%llx\n", pmd, pmd_val(*pmd));

    pte = pte_offset_map(pmd, addr);
    if (pte_present(*pte)) {
        printk("pte=%p, pte_val=%llx\n", pte, pte_val(*pte));   
        gpa = pte_val(*pte) & 0xFFFFFFFFFF000ULL;
        struct page *page = pte_page(*pte);
        void *map = kmap(page);
        printk("write_dispatch_id=%p, %lld\n", map+2168, *(uint64_t*)(map+2168));
        printk("max_legacy_doorbell_dispatch_id_plus_1=%p, %lld\n", map+2192, *(uint64_t*)(map+2192));
        printk("read_dispatch_id=%p, %lld\n", map+2240, *(uint64_t*)(map+2240));
/*        *(uint64_t*)(map+2168) = 10;
        *(uint64_t*)(map+2192) = 10;
        *(uint64_t*)(map+2240) = 10;
        printk("write_dispatch_id=%p, %lld\n", map+2168, *(uint64_t*)(map+2168));
        printk("max_legacy_doorbell_dispatch_id_plus_1=%p, %lld\n", map+2192, *(uint64_t*)(map+2192));
        printk("read_dispatch_id=%p, %lld\n", map+2240, *(uint64_t*)(map+2240));
*/
        kunmap(page);
        pte_unmap(pte);
    }

    return gpa;
}

static void vm_ppr_handler(void)
{
    struct ppr_log *ppr_log;
    int head;
    int tail;
    int npages;
    struct page *page;
    struct task_struct *task;
    struct mm_struct *mm;
    struct virtio_iommu_mmu_notification *mmu;
    int log_count = 0;
    uint64_t *gpa;

    head = ppr->vm_consume_head;
    tail = ppr->tail;
    printk("vm_ppr_handler, head=%d, tail=%d, vm_consume_head=%d\n", ppr->head, ppr->tail, ppr->vm_consume_head);

//    while (head != tail) {
        ++log_count;
        ppr_log = &ppr->ppr_log_region[head];
        printk("ppr_log=%p, task=0x%llx, mm=0x%llx, addr=0x%llx, write=%d\n",
                    ppr_log, ppr_log->vm_task, ppr_log->vm_mm, ppr_log->address, ppr_log->write);
        mm   = (struct mm_struct*)ppr_log->vm_mm;
        task = (struct task_struct*)ppr_log->vm_task;

//        if (ppr_log->write == 5566)    // FIXME: debug
//            dump_mqd(ppr_log->address);
//        else {
    	down_read(&mm->mmap_sem);
    	npages = get_user_pages(task, mm, ppr_log->address, 1, 
                                        ppr_log->write, 0, &page, NULL);
    	up_read(&mm->mmap_sem);

        if (npages == 1) {
            printk("npages=1\n");

            // gpa send to host to fix stage2 table
            gpa = (uint64_t*)kmalloc(sizeof(uint64_t), GFP_KERNEL);
            *gpa = walk_page_table2(mm, ppr_log->address);
        }
//        }

        head = (head+1) % MAX_PPR_LOG_ENTRY;
//    }
    ppr->vm_consume_head = head;
    printk("vm_ppr_handler, head=%d, tail=%d, vm_consume_head=%d\n", ppr->head, ppr->tail, ppr->vm_consume_head);

    // send back to let host finish_pri_tag 
    if (log_count) {
        virtio_iommu_add_req_no_wait(VIRTIO_IOMMU_VM_FINISH_PPR, gpa, sizeof(*gpa), virtio_iommu_free_req_param);
/*
        mmu = (struct virtio_iommu_mmu_notification*)kmalloc(sizeof(*mmu), GFP_KERNEL);
        mmu->mm = (uint64_t)mm;
        mmu->start = (uint64_t)ppr_log->address;
        mmu->end   = mmu->start + 0x1000;
        virtio_iommu_add_req_no_wait(VIRTIO_IOMMU_INVALIDATE_RANGE_START, mmu, 
                                sizeof(*mmu), virtio_iommu_free_req_param);
        printk("VIRTIO_IOMMU_INVALIDATE_PAGE done\n");
*/
    }
}

static void virtio_iommu_done(struct virtqueue *vq)
{
    struct virtio_iommu_req *req;
    int len;
	unsigned long flags;
    int virtio_req_back = 0;

    printk("virtio_iommu_done\n");
	spin_lock_irqsave(&viommu->vq_lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((req = virtqueue_get_buf(vq, &len)) != NULL) {
            virtio_req_back = 1;
            if (req->cb)
                req->cb(req->param);

            if (req->wait == VIRTIO_IOMMU_REQ_WAIT)
                req->wait = VIRTIO_IOMMU_REQ_DONE;
            else 
                kfree(req); 
		}
		if (unlikely(virtqueue_is_broken(vq)))
			break;
	} while (!virtqueue_enable_cb(vq));

	spin_unlock_irqrestore(&viommu->vq_lock, flags);

    if (!virtio_req_back)   // interrupt by iommu-vm-ppr sending irqfd
        vm_ppr_handler();
}

int virtio_iommu_clear_flush_young(struct mmu_notifier *mn,
				struct mm_struct *mm,
				unsigned long address)
{
    struct virtio_iommu_mmu_notification *mmu;

    printk("virtio_iommu_clear_flush_young, addr=%llx\n", address);
    mmu = (struct virtio_iommu_mmu_notification*)kmalloc(sizeof(*mmu), GFP_KERNEL);
    mmu->mm = (uint64_t)mm;
    mmu->start = (uint64_t)address;
    virtio_iommu_add_req_no_wait(VIRTIO_IOMMU_CLEAR_FLUSH_YOUNG, mmu, 
                            sizeof(*mmu), virtio_iommu_free_req_param);

	return 0;
}

void virtio_iommu_change_pte(struct mmu_notifier *mn,
			  struct mm_struct *mm,
			  unsigned long address,
			  pte_t pte)
{
    struct virtio_iommu_mmu_notification *mmu;

    printk("virtio_iommu_change_pte, addr=%llx\n", address);
    mmu = (struct virtio_iommu_mmu_notification*)kmalloc(sizeof(*mmu), GFP_KERNEL);
    mmu->mm = (uint64_t)mm;
    mmu->start = (uint64_t)address;
    virtio_iommu_add_req_no_wait(VIRTIO_IOMMU_CHANGE_PTE, mmu, sizeof(*mmu),
                                             virtio_iommu_free_req_param);
}

void virtio_iommu_invalidate_page(struct mmu_notifier *mn,
			       struct mm_struct *mm,
			       unsigned long address)
{
    struct virtio_iommu_mmu_notification *mmu;

    printk("virtio_iommu_invalidate_page, addr=%llx\n", address);
    mmu = (struct virtio_iommu_mmu_notification*)kmalloc(sizeof(*mmu), GFP_KERNEL);
    mmu->mm = (uint64_t)mm;
    mmu->start = (uint64_t)address;
    virtio_iommu_add_req_no_wait(VIRTIO_IOMMU_INVALIDATE_PAGE, mmu, 
                            sizeof(*mmu), virtio_iommu_free_req_param);
}

void virtio_iommu_invalidate_range_start(struct mmu_notifier *mn,
				      struct mm_struct *mm,
				      unsigned long start, unsigned long end)
{
    struct virtio_iommu_mmu_notification *mmu;

    printk("virtio_iommu_invalidate_range_start, mm=%p, virtio_iommu_free_req_param=%p, start=%llx, end=%llx\n", 
                            mm, virtio_iommu_free_req_param, start, end);
    mmu = (struct virtio_iommu_mmu_notification*)kmalloc(sizeof(*mmu), GFP_KERNEL);
    mmu->mm    = (uint64_t)mm;
    mmu->start = (uint64_t)start;
    mmu->end   = (uint64_t)end;
    virtio_iommu_add_req_no_wait(VIRTIO_IOMMU_INVALIDATE_RANGE_START, mmu,
                             sizeof(*mmu), virtio_iommu_free_req_param);
}

/*
static struct mmu_notifier_ops iommu_mn = {
	.clear_flush_young      = mn_clear_flush_young,
	.change_pte             = mn_change_pte,
	.invalidate_page        = mn_invalidate_page,
	.invalidate_range_start = mn_invalidate_range_start,
};
*/

static int init_vq(void)
{
	int err = 0;

	/* We expect one virtqueue, for output. */
	viommu->vq = virtio_find_single_vq(viommu->vdev, virtio_iommu_done, "virtio_iommu-requests");
	if (IS_ERR(viommu->vq))
		err = PTR_ERR(viommu->vq);

	return err;
}

static int virtio_iommu_probe(struct virtio_device *vdev)
{
	int err, index;
    uint64_t ppr_region_gpa;
    printk("virtio_iommu_probe\n");

	err = ida_simple_get(&virtio_iommu_index_ida, 0, minor_to_index(1 << MINORBITS),
			     GFP_KERNEL);
	if (err < 0)
		goto out;
	index = err;

	/* We need an extra sg elements at head and tail. */
	vdev->priv = viommu = kmalloc(sizeof(*viommu), GFP_KERNEL);
	if (!viommu) {
		err = -ENOMEM;
		goto out_free_index;
	}

	viommu->vdev = vdev;
	mutex_init(&viommu->config_lock);

	viommu->config_enable = true;

	err = init_vq();
	if (err)
		goto out_free_viommu;
	spin_lock_init(&viommu->vq_lock);

	viommu->index = index;

    // allocate ppr_log_region and do mmap
    ppr = (struct vm_iommu_ppr*)__get_free_page(GFP_KERNEL);
    if (!ppr) {
        err = -ENOMEM;
        goto out_free_vq;
    }
    SetPageReserved(virt_to_page(ppr));       // may not need 
    ppr_region_gpa = (uint64_t)virt_to_phys(ppr);

    virtio_iommu_add_req_wait(VIRTIO_IOMMU_MMAP_PPR_REGION, &ppr_region_gpa, sizeof(*ppr), NULL);
    printk("VIRTIO_IOMMU_MMAP_PPR_REGION done, ppr_region_gpa=%llx\n", ppr_region_gpa);

	return 0;

out_free_vq:
	vdev->config->del_vqs(vdev);
out_free_viommu:
	kfree(viommu);
out_free_index:
	ida_simple_remove(&virtio_iommu_index_ida, index);
out:
	return err;
}

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_IOMMU, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
/*	VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
	VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_SCSI,
	VIRTIO_BLK_F_WCE, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE
*/
};

static struct virtio_driver virtio_iommu = {
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.probe			= virtio_iommu_probe,
};

static int __init virtio_iommu_init(void)
{
	int ret;

	pr_info("AMD IOMMUv2 driver by Joerg Roedel <joerg.roedel@amd.com>\n");

    printk("virtio_iommu_init\n");
//	if (!amd_iommu_v2_supported()) {
//		pr_info("AMD IOMMUv2 functionality not available on this system\n");
		/*
		 * Load anyway to provide the symbols to other modules
		 * which may use AMD IOMMUv2 optionally.
		 */
//		return 0;
//	}

    ret = register_virtio_driver(&virtio_iommu);

	return ret;
}

static void __exit virtio_iommu_exit(void)
{
	unregister_virtio_driver(&virtio_iommu);
}

module_init(virtio_iommu_init);
module_exit(virtio_iommu_exit);
