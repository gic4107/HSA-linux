//#define DEBUG
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/virtio.h>
#include <linux/virtio_blk.h>
#include <linux/scatterlist.h>
#include <linux/string_helpers.h>
#include <scsi/scsi_cmnd.h>
#include <linux/idr.h>
#include <linux/blk-mq.h>
#include <linux/numa.h>
#include <linux/cdev.h>
#include <linux/mman.h>
#include <uapi/linux/virtio_ids.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_iommu.h>     // for mmu_notifier
#include "virtio_kfd_priv.h"

#include <asm/pgtable_types.h>
#define PART_BITS 4

#define VIRTKFD_PROCESS_TABLE_SIZE 5
//#define VIRTIO_DEV_ANY_ID	0xffffffff

static DEFINE_HASHTABLE(virtkfd_processes, VIRTKFD_PROCESS_TABLE_SIZE);                     
static DEFINE_MUTEX(virtkfd_processes_mutex);                                           
                                                                                    
DEFINE_STATIC_SRCU(virtkfd_processes_srcu); 

static int virtkfd_major;
static struct cdev virtkfd_cdev;
static const char virtkfd_name[] = "kfd";
static struct class *virtkfd_class;
struct device *virtkfd_device;
static DEFINE_IDA(virtkfd_index_ida);
struct virtio_kfd *vkfd;

// FIXME: debug
static uint64_t doorbell_addr;
static uint64_t in_buf;
static uint64_t out_buf;


static long virtkfd_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
static int virtkfd_open(struct inode *inode, struct file *filep);
static int virtkfd_release(struct inode *inode, struct file *filep);
static int virtkfd_mmap(struct file *filp, struct vm_area_struct *vma);

static const struct file_operations virtkfd_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = virtkfd_ioctl,
	.compat_ioctl = virtkfd_ioctl,
	.open = virtkfd_open,
    .release = virtkfd_release, 
	.mmap = virtkfd_mmap,
};

#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

static int minor_to_index(int minor)
{
	return minor >> PART_BITS;
}

int virtkfd_add_req(int cmd, void *param, int param_len, uint64_t vm_mm)
{
//    printk("virtkfd_add_req, command=%d, param=%p\n", cmd, param);
    struct virtkfd_req *req;
    struct scatterlist sg_cmd, sg_param, sg_vm_mm, sg_status, *sgs[4];
    int num_in=0, num_out=0; 
    struct virtqueue *vq = vkfd->vq;
    int ret;
    
	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		printk("virtkfd_req alloc fail\n");
        return -1;
	}
    req->signal  = 0;
    req->command = cmd;
    req->vm_mm   = vm_mm;
    req->param   = param;

    sg_init_one(&sg_cmd, &cmd, sizeof(cmd));
    sg_init_one(&sg_vm_mm, &vm_mm, sizeof(vm_mm));
    if (param)
        sg_init_one(&sg_param, param, param_len);
    sg_init_one(&sg_status, &req->status, sizeof(req->status));
    sgs[num_out++] = &sg_cmd;
    sgs[num_out++] = &sg_vm_mm;
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
    while(req->signal == 0);        // signal by virtqueue's callback function

    kfree(req); 

    return 0;
}

static void virtkfd_done(struct virtqueue *vq)
{
    struct virtkfd_req *req;
    int len;
	unsigned long flags;

	spin_lock_irqsave(&vkfd->vq_lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((req = virtqueue_get_buf(vq, &len)) != NULL) {
            req->signal = true;
		}
		if (unlikely(virtqueue_is_broken(vq)))
			break;
	} while (!virtqueue_enable_cb(vq));

	spin_unlock_irqrestore(&vkfd->vq_lock, flags);
}

/*
static void virtblk_config_changed_work(struct work_struct *work)
{
	struct virtio_blk *vblk =
		container_of(work, struct virtio_blk, config_work);
	struct virtio_device *vdev = vblk->vdev;
	struct request_queue *q = vblk->disk->queue;
	char cap_str_2[10], cap_str_10[10];
	char *envp[] = { "RESIZE=1", NULL };
	u64 capacity, size;

	mutex_lock(&vblk->config_lock);
	if (!vblk->config_enable)
		goto done;
*/
	/* Host must always specify the capacity. */
//	virtio_cread(vdev, struct virtio_blk_config, capacity, &capacity);

	/* If capacity is too big, truncate with warning. */
/*	if ((sector_t)capacity != capacity) {
		dev_warn(&vdev->dev, "Capacity %llu too large: truncating\n",
			 (unsigned long long)capacity);
		capacity = (sector_t)-1;
	}

	size = capacity * queue_logical_block_size(q);
	string_get_size(size, STRING_UNITS_2, cap_str_2, sizeof(cap_str_2));
	string_get_size(size, STRING_UNITS_10, cap_str_10, sizeof(cap_str_10));

	dev_notice(&vdev->dev,
		  "new size: %llu %d-byte logical blocks (%s/%s)\n",
		  (unsigned long long)capacity,
		  queue_logical_block_size(q),
		  cap_str_10, cap_str_2);

	set_capacity(vblk->disk, capacity);
	revalidate_disk(vblk->disk);
	kobject_uevent_env(&disk_to_dev(vblk->disk)->kobj, KOBJ_CHANGE, envp);
done:
	mutex_unlock(&vblk->config_lock);
}
*/

/*
static void virtblk_config_changed(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;

	queue_work(virtblk_wq, &vblk->config_work);
}
*/

static int init_vq(void)
{
	int err = 0;

	/* We expect one virtqueue, for output. */
	vkfd->vq = virtio_find_single_vq(vkfd->vdev, virtkfd_done, "virtkfd-requests");
	if (IS_ERR(vkfd->vq))
		err = PTR_ERR(vkfd->vq);

	return err;
}

static int virtkfd_probe(struct virtio_device *vdev)
{
    if(vkfd != NULL) {
        printk("virtkfd_probe vkfd != NULL\n");
        return -1;
    }
	int err, index;

	err = ida_simple_get(&virtkfd_index_ida, 0, minor_to_index(1 << MINORBITS),
			     GFP_KERNEL);
	if (err < 0)
		goto out;
	index = err;

	/* We need to know how many segments before we allocate. */
//	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_SEG_MAX,
//				   struct virtio_blk_config, seg_max,
//				   &sg_elems);

	/* We need an extra sg elements at head and tail. */
	vdev->priv = vkfd = kmalloc(sizeof(*vkfd), GFP_KERNEL);
	if (!vkfd) {
		err = -ENOMEM;
		goto out_free_index;
	}

	vkfd->vdev = vdev;
	mutex_init(&vkfd->config_lock);

//	INIT_WORK(&vblk->config_work, virtblk_config_changed_work);
	vkfd->config_enable = true;

	err = init_vq();
	if (err)
		goto out_free_vkfd;
	spin_lock_init(&vkfd->vq_lock);

	vkfd->index = index;

	/* If disk is read-only in the host, the guest should obey */
//	if (virtio_has_feature(vdev, VIRTIO_BLK_F_RO))
//		set_disk_ro(vblk->disk, 1);

	/* Host must always specify the capacity. */
//	virtio_cread(vdev, struct virtio_blk_config, capacity, &cap);

	/* If capacity is too big, truncate with warning. */
//	if ((sector_t)cap != cap) {
//		dev_warn(&vdev->dev, "Capacity %llu too large: truncating\n",
//			 (unsigned long long)cap);
//		cap = (sector_t)-1;
//	}
//	set_capacity(vblk->disk, cap);

	/* Host can optionally specify maximum segment size and number of
	 * segments. */

	/* Host can optionally specify the block size of the device */

//	err = device_create_file(disk_to_dev(vblk->disk), &dev_attr_serial);
//	if (err)
//		goto out_del_disk;
    err = virtio_kfd_topology_init();
    if(err < 0)
        goto out_free_vq;

	return 0;

out_free_vq:
	vdev->config->del_vqs(vdev);
out_free_vkfd:
	kfree(vkfd);
out_free_index:
	ida_simple_remove(&virtkfd_index_ida, index);
out:
	return err;
}

/*
static void virtblk_remove(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
	int index = vblk->index;
	int refc;
*/
	/* Prevent config work handler from accessing the device. */
/*	mutex_lock(&vblk->config_lock);
	vblk->config_enable = false;
	mutex_unlock(&vblk->config_lock);

	del_gendisk(vblk->disk);
	blk_cleanup_queue(vblk->disk->queue);
*/
	/* Stop all the virtqueues. */
/*	vdev->config->reset(vdev);

	flush_work(&vblk->config_work);

	refc = atomic_read(&disk_to_dev(vblk->disk)->kobj.kref.refcount);
	put_disk(vblk->disk);
	vdev->config->del_vqs(vdev);
	kfree(vblk);
*/
	/* Only free device id if we don't have any users */
//	if (refc == 1)
//		ida_simple_remove(&virtkfd_index_ida, index);
//}

/*
#ifdef CONFIG_PM_SLEEP
static int virtblk_freeze(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
*/
	/* Ensure we don't receive any more interrupts */
//	vdev->config->reset(vdev);

	/* Prevent config work handler from accessing the device. */
/*	mutex_lock(&vblk->config_lock);
	vblk->config_enable = false;
	mutex_unlock(&vblk->config_lock);

	flush_work(&vblk->config_work);

	blk_mq_stop_hw_queues(vblk->disk->queue);

	vdev->config->del_vqs(vdev);
	return 0;
}

static int virtblk_restore(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
	int ret;

	vblk->config_enable = true;
	ret = init_vq(vdev->priv);
	if (!ret)
		blk_mq_start_stopped_hw_queues(vblk->disk->queue);

	return ret;
}
#endif
*/

static int set_queue_properties_from_user(struct queue_properties *q_properties,
                             struct kfd_ioctl_create_queue_args *args)
{
	q_properties->is_interop = false;
	q_properties->queue_percent = args->queue_percentage;
	q_properties->priority = args->queue_priority;
	q_properties->queue_address = args->ring_base_address;
	q_properties->queue_size = args->ring_size;
	q_properties->read_ptr = (qptr_t *) args->read_pointer_address;
	q_properties->write_ptr = (qptr_t *) args->write_pointer_address;
	if (args->queue_type == KFD_IOC_QUEUE_TYPE_COMPUTE ||
		args->queue_type == KFD_IOC_QUEUE_TYPE_COMPUTE_AQL)
		q_properties->type = KFD_QUEUE_TYPE_COMPUTE;
	else if (args->queue_type == KFD_IOC_QUEUE_TYPE_SDMA)
		q_properties->type = KFD_QUEUE_TYPE_SDMA;
	else
		return -ENOTSUPP;
	if (args->queue_type == KFD_IOC_QUEUE_TYPE_COMPUTE_AQL)
		q_properties->format = KFD_QUEUE_FORMAT_AQL;
	else
		q_properties->format = KFD_QUEUE_FORMAT_PM4;

	printk("%s Arguments: Queue Percentage (%d, %d)\n"
			"Queue Priority (%d, %d)\n"
			"Queue Address (0x%llX, 0x%llX)\n"
			"Queue Size (0x%llX, %u)\n"
			"Queue r/w Pointers (0x%llX, 0x%llX)\n"
			"Queue Format (%d)\n",
			__func__,
			q_properties->queue_percent, args->queue_percentage,
			q_properties->priority, args->queue_priority,
			q_properties->queue_address, args->ring_base_address,
			q_properties->queue_size, args->ring_size,
			(uint64_t) q_properties->read_ptr,
			(uint64_t) q_properties->write_ptr,
			q_properties->format);

	return 0;
}

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_KFD, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
/*	VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
	VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_SCSI,
	VIRTIO_BLK_F_WCE, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE
*/
};

static struct virtio_driver virtio_kfd = {
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.probe			= virtkfd_probe,
//	.remove			= virtkfd_remove,
//	.config_changed		= virtkfd_config_changed,
/*
#ifdef CONFIG_PM_SLEEP
	.freeze			= virtkfd_freeze,
	.restore		= virtkfd_restore,
#endif
*/
};

static struct virtkfd_process*                                                       
find_process_by_mm(const struct mm_struct *mm)
{                                                                                
    struct virtkfd_process *process;                                                 
                                                                                 
//    hash_for_each_possible_rcu(virtkfd_processes, process, node, (uintptr_t)mm)
    hash_for_each_possible(virtkfd_processes, process, node, (uintptr_t)mm)
        if (process->mm == mm)                                                   
            return process;                                                     
                                                                                 
    return NULL;                                                                 
} 

static struct virtkfd_process*
find_process(const struct task_struct *thread)
{
    struct virtkfd_process *p;                                                       
                                                                                 
//    int idx = srcu_read_lock(&virtkfd_processes_srcu);                               
    p = find_process_by_mm(thread->mm);
//    srcu_read_unlock(&virtkfd_processes_srcu, idx);                                  
                                                                                 
    return p;
}

static void free_process(struct virtkfd_process *p)                                  
{                                                                                
    kfree(p);                                                                    
}                                                                                
                                                                                 
static void shutdown_process(struct virtkfd_process *p)                              
{                                                                                
    mutex_lock(&virtkfd_processes_mutex);                                            
    hash_del_rcu(&p->node);                                             
    mutex_unlock(&virtkfd_processes_mutex);                                          
    synchronize_srcu(&virtkfd_processes_srcu);                                       
    
    // unmap userspace doorbell mapping
    if(p->doorbell_user_mapping != NULL)
        vm_munmap((uintptr_t)p->doorbell_user_mapping, doorbell_process_allocation());

    // send VIRTKFD_CLOSE to BE
    virtkfd_add_req(VIRTKFD_CLOSE, &p->mm, sizeof(p->mm), (uint64_t)p->mm);
}

static void                                                                      
virtkfd_process_notifier_release(struct mmu_notifier *mn, struct mm_struct *mm)
{                                                                                
    struct virtkfd_process *p = container_of(mn, struct virtkfd_process, mmu_notifier);  
    BUG_ON(p->mm != mm);                                                         
                                                                                 
    shutdown_process(p);                                                         
}                                                                                
                                                                                 
static void                                                                      
virtkfd_process_notifier_destroy(struct mmu_notifier *mn)                            
{                                                                                
    struct virtkfd_process *p = container_of(mn, struct virtkfd_process, mmu_notifier);  
                                                                                 
    free_process(p);                                                             
}                                                                                
                                                                                 
static const struct mmu_notifier_ops virtkfd_process_mmu_notifier_ops = {            
    .release = virtkfd_process_notifier_release,                                     
    .destroy = virtkfd_process_notifier_destroy,                                     
};

static struct virtkfd_process*
create_process(const struct task_struct *thread)
{
    struct virtkfd_process *process;
    int err;

    process = kzalloc(sizeof(*process), GFP_KERNEL);
    if(!process)
        return -ENOMEM;

    process->mm = thread->mm;
    process->mmu_notifier.ops = &virtkfd_process_mmu_notifier_ops;
    err = mmu_notifier_register(&process->mmu_notifier, process->mm);            
    if (err)                                                                     
        return -EFAULT; 

    return process;
}

static struct virtkfd_process*                                                       
insert_process(struct virtkfd_process *p) 
{                                                                                
    struct virtkfd_process *other_p;
                                                                                    
    if(!p) {
        printk("insert_process null\n");
        return -EFAULT;
    }
//    mutex_lock(&virtkfd_processes_mutex);                                               
                                                                                    
//    other_p = find_process_by_mm(p->mm);                                            
//    if (other_p) {                                                                  
        /* Another thread beat us to creating & inserting the kfd_process object. */
//        mutex_unlock(&virtkfd_processes_mutex);                                         
                                                                                    
        /* Unregister will destroy the struct kfd_process. */                       
//        mmu_notifier_unregister(&p->mmu_notifier, p->mm);                           
                                                                                    
//        p = other_p;                                                                
//    } else {                                                                        
        /* We are the winner, insert it. */                                         
//        hash_add_rcu(virtkfd_processes, &p->node, (uintptr_t)p->mm);           
        hash_add(virtkfd_processes, &p->node, (uintptr_t)p->mm);           
//        mutex_unlock(&virtkfd_processes_mutex);                                         
//    }                                                                               
                                                                                    
    return p; 
}   

static struct virtkfd_process*
virtkfd_create_process(const struct task_struct *thread)
{
    struct virtkfd_process *process;
    
    if (thread->mm == NULL)                                                      
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

static int
virtkfd_release(struct inode *inode, struct file *filep)
{
    struct virtkfd_process *p = find_process(current);
    if(!p)
        return -1;
    
    shutdown_process(p);
    free_process(p);
}

static int
virtkfd_open(struct inode *inode, struct file *filep)
{
    printk("kfd_open current=%p, active_mm=%p, mm=%p, pgd=%p\n", current, current->active_mm, current->mm, current->mm->pgd);
    struct virtkfd_process *process;
    uint64_t doorbell_region_gpa;
    struct vm_process_info info;
    struct task_struct *lead_thread = current->group_leader;

    if (current->group_leader->mm != current->mm) {
        printk("current->group_leader->mm != current->mm\n");
        return -EINVAL;
    }

    if (find_process(current)) {
        printk("kfd_process exist\n");
        return 0;
    }

    info.vm_task = (uint64_t)current;
    info.vm_mm   = (uint64_t)current->mm;
    info.vm_pgd_gpa = (uint64_t)__pa(get_task_mm(lead_thread)->pgd);

    virtkfd_add_req(VIRTKFD_OPEN, &info, sizeof(info), NO_MATCH);     

    // create virtkfd_process
    process = virtkfd_create_process(current); 
    
    process->doorbell_region = (doorbell_t*)__get_free_page(GFP_KERNEL);             // aligned 4k region
    if (!process->doorbell_region) {
        printk("get doorbell_region fail\n");
        return -EFAULT;
    }
    SetPageReserved(virt_to_page(process->doorbell_region));                         // for using remap_pfn_page
    memset(process->doorbell_region, 0, 4096);

    doorbell_region_gpa = (uint64_t)virt_to_phys(process->doorbell_region);
    // FIXME: debug
    doorbell_addr = doorbell_region_gpa;

    // send to BE for mmap to host KFD
    virtkfd_add_req(VIRTKFD_MMAP_DOORBELL_REGION, &doorbell_region_gpa, 
                        sizeof(doorbell_region_gpa), (uint64_t)current->mm);
    printk("VIRTKFD_MMAP_DOORBELL_REGION done, doorbell_region_gpa=%llx\n", doorbell_region_gpa);

    // map doorbell_region to userspace
    process->doorbell_user_mapping = (doorbell_t __user *)vm_mmap(filep, 0, 
        doorbell_process_allocation(), PROT_WRITE, MAP_SHARED, VIRTKFD_MMAP_DOORBELL_START);  
    if (IS_ERR(process->doorbell_user_mapping)) {
        printk("vm_mmap fail\n");
        return PTR_ERR(process->doorbell_user_mapping);
    }
    printk("process->doorbell_user_mapping=%p\n", process->doorbell_user_mapping);
    
	return 0;
}

/*
pte_t* walk_page_table(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    int offset = addr & 0xfff;
    printk("walk_page_table, offset=%x\n", offset);

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

    if (pmd_val(*pmd) & _PAGE_PAT)
        return pmd;
 
    pte = pte_offset_map(pmd, addr);

    return pte;
}

uint64_t gva_to_gpa(struct mm_struct *mm, unsigned long gva)
{
    int offset = gva & 0xfff;
    pte_t *pte = walk_page_table(mm, gva);
    uint64_t gpa = 0;

    if (pte_present(*pte)) {
        printk("pte_val=%llx, offset=%llx\n", pte_val(*pte), offset);
        gpa = (pte_val(*pte) & PTE_PFN_MASK) + offset;
    }

    printk("gva_to_gpa: %llx->%llx\n", gva, gpa);
    return gpa;
}

void access_clr_a_page(struct mm_struct *mm, unsigned long addr)
{
    void *entry;
    struct page *page;
    void *map;
    int offset;

    printk("access_clr_a_page: %llx\n", addr);
    entry = walk_page_table(mm, addr);
    if (!entry)
        return;

    printk("entry=%llx\n", *(uint64_t*)entry);

    if (*(uint64_t*)entry & _PAGE_PAT) {     // 2M page
        pmd_t *pmd = (pmd_t*)entry;
        page = pmd_page(*pmd);
        offset = addr & 0x1fffff;

        map = kmap(page);
        printk("map=%p, 0x%x\n", map+offset, *(int*)(map+offset));
        kunmap(page);

        printk("pmd=%p, *pmd=%llx, pmd_val=%llx\n", pmd, *pmd, pmd_val(*pmd));
        pmd->pmd = pmd_val(*pmd) & ~_PAGE_ACCESSED;
        printk("pmd=%p, *pmd=%llx, pmd_val=%llx\n", pmd, *pmd, pmd_val(*pmd));
    }
    else if (pte_present(*(pte_t*)entry)) {
        pte_t *pte = (pte_t*)entry;
        page = pte_page(*pte);
        offset = addr & 0xfff;

        map = kmap(page);
        printk("map=%p, 0x%x\n", map+offset, *(int*)(map+offset));
        kunmap(page);

        printk("pte=%p, *pte=%llx, pte_val=%llx\n", pte, *pte, pte_val(*pte));
        pte->pte = pte_val(*pte) & ~_PAGE_ACCESSED;
        printk("pte=%p, *pte=%llx, pte_val=%llx\n", pte, *pte, pte_val(*pte));
    }
}

void access_page(struct mm_struct *mm, unsigned long addr)
{
    void *entry;
    struct page *page;
    void *map;
    int offset;

    entry = walk_page_table(mm, addr);
    if (!entry)
        return;

    printk("entry=%llx\n", *(uint64_t*)entry);

    if (*(uint64_t*)entry & _PAGE_PAT) {     // 2M page
        pmd_t *pmd = (pmd_t*)entry;
        page = pmd_page(*pmd);
        offset = addr & 0x1fffff;

        printk("pmd=%p, *pmd=%llx, pmd_val=%llx\n", pmd, *pmd, pmd_val(*pmd));

        map = kmap(page);
        printk("map=%p, 0x%x\n", map+offset, *(int*)(map+offset));
        kunmap(page);
    }
    else if (pte_present(*(pte_t*)entry)) {
        pte_t *pte = (pte_t*)entry;
        page = pte_page(*pte);
        offset = addr & 0xfff;

        printk("pte=%p, *pte=%llx, pte_val=%llx\n", pte, *pte, pte_val(*pte));

        map = kmap(page);
        printk("map=%p, 0x%x\n", map+offset, *(int*)(map+offset));
        kunmap(page);
    }
}

void my_clear_page(struct mm_struct *mm, unsigned long addr)
{
    pte_t *pte;
    unsigned long page_start = addr & PAGE_MASK;

    pte = walk_page_table(mm, addr);
    if (pte_present(*pte)) {
        printk("pte=%p, *pte=%llx, pte_val=%llx\n", pte, *pte, pte_val(*pte));   
        pte->pte = pte_val(*pte) & ~_PAGE_PRESENT;
        printk("pte=%p, *pte=%llx, pte_val=%llx\n", pte, *pte, pte_val(*pte));   
        virtio_iommu_invalidate_range_start(NULL, mm, page_start, page_start+4096);
    }
}
*/

static long
virtkfd_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	long err = -EINVAL;
    uint64_t vm_mm = (uint64_t)current->mm; 
    struct virtkfd_process *p = find_process(current);
    int ret;
    // FIXME: debug
    int i;
    static void __user *wptr_user;
    static void __user *rptr_user;
    static void __user *ring_user;
    static void *m;
    unsigned long va;
    struct kfd_ioctl_get_clock_counters_args cc_args;

	dev_dbg(virtkfd_device,
		"ioctl cmd 0x%x (#%d), arg 0x%lx\n",
		cmd, _IOC_NR(cmd), arg);

	switch (cmd) {
    // FIXME: debug
	case KFD_IOC_CLEAR_PAGE:
		printk("KFD_IOC_CLEAR_PAGE");

        if (copy_from_user(&va, arg, sizeof(va)))
            return -EFAULT;

        printk("va=%llx\n", va); 

        break;

    // FIXME: debug
	case KFD_IOC_WALK_PAGE_TABLE:
		printk("KFD_IOC_WALK_PAGE_TABLE ");

        if (copy_from_user(&va, arg, sizeof(va)))
            return -EFAULT;

        printk("va=%llx\n", va); 

        break;

    // FIXME: debug
	case KFD_IOC_WALK_RWPTR:
		printk("KFD_IOC_WALK_RWPTR ");

        break;

    // FIXME: debug
	case KFD_IOC_SET_IN_BUF:
		printk("KFD_IOC_SET_IN_BUF ");

        if (copy_from_user(&in_buf, arg, sizeof(in_buf)))
            return -EFAULT;
        printk("in_buf=%llx\n", in_buf); 
        break;

    // FIXME: debug
	case KFD_IOC_SET_OUT_BUF:
		printk("KFD_IOC_SET_OUT_BUF ");

        if (copy_from_user(&out_buf, arg, sizeof(out_buf)))
            return -EFAULT;
        printk("out_buf=%llx\n", out_buf); 
        break;

    case KFD_IOC_KICK_DOORBELL:
        printk("KFD_IOC_KICK_DOORBELL, doorbell_addr=%llx", doorbell_addr);
		err = virtkfd_add_req(VIRTKFD_KICK_DOORBELL, &doorbell_addr, sizeof(doorbell_addr), vm_mm);
        break;

    case KFD_IOC_GET_DOORBELL:
        printk("KFD_IOC_GET_DOORBELL ");
        uint64_t db_addr = &p->doorbell_user_mapping[0];
        copy_to_user((void __user*)arg, &db_addr, sizeof(db_addr));
        break;

	case KFD_IOC_CREATE_QUEUE:
		printk("KFD_IOC_CREATE_QUEUE\n");
        struct kfd_ioctl_create_queue_args cq_args;
        struct queue_properties q_properties;
        struct cik_mqd *mqd;

        if (copy_from_user(&cq_args, arg, sizeof(struct kfd_ioctl_create_queue_args)))
            return -EFAULT;

        printk("ring_base_address=0x%llx\n", cq_args.ring_base_address);
        printk("write_pointer_address=0x%llx\n", cq_args.write_pointer_address);
        printk("read_pointer_address=0x%llx\n", cq_args.read_pointer_address);
        printk("ring_size=%d\n",cq_args.ring_size);
        printk("gpu_id=%d\n", cq_args.gpu_id);
        printk("queue_type=%d\n", cq_args.queue_type);
        printk("queue_percentage=%d\n", cq_args.queue_percentage);
        printk("queue_priority=%d\n", cq_args.queue_priority);

		err = virtkfd_add_req(VIRTKFD_CREATE_QUEUE, &cq_args, sizeof(cq_args), vm_mm);       // back-end will fill args
        cq_args.queue_id = cq_args.queue_id;
        printk("queue_id=%d\n", cq_args.queue_id);

        // assign doorbell_address with qid
        cq_args.doorbell_address = &p->doorbell_user_mapping[cq_args.queue_id];
        printk("doorbell_address=0x%llx\n", cq_args.doorbell_address);

        if (copy_to_user((void __user*)arg, &cq_args, sizeof(cq_args)))
            return -EFAULT;

		break;

	case KFD_IOC_DESTROY_QUEUE:
		printk("KFD_IOC_DESTROY_QUEUE\n"); 
        struct kfd_ioctl_destroy_queue_args dq_args;

        if (copy_from_user(&dq_args, arg, sizeof(dq_args)))
            return -EFAULT;
		err = virtkfd_add_req(VIRTKFD_DESTROY_QUEUE, &dq_args, sizeof(dq_args), vm_mm);       

		break;
	case KFD_IOC_SET_MEMORY_POLICY:
		printk("KFD_IOC_SET_MEMORY_POLICY\n");
        struct kfd_ioctl_set_memory_policy_args mp_args;

        if (copy_from_user(&mp_args, arg, sizeof(mp_args)))
            return -EFAULT;

        printk("gpu_id=%d\n", mp_args.gpu_id);
        printk("alternate_aperture_base=0x%llx\n", mp_args.alternate_aperture_base);
        printk("alternate_aperture_size=%llu\n", mp_args.alternate_aperture_size);
        printk("default_policy=%u\n", mp_args.default_policy);
        printk("alternate_policy=%u\n", mp_args.alternate_policy);
		err = virtkfd_add_req(VIRTKFD_SET_MEMORY_POLICY, &mp_args, sizeof(mp_args), vm_mm);       // back-end will fill args

		break;

	case KFD_IOC_GET_CLOCK_COUNTERS:
        if (copy_from_user(&cc_args, arg, sizeof(cc_args)))
            return -EFAULT;

		err = virtkfd_add_req(VIRTKFD_GET_CLOCK_COUNTERS, &cc_args, sizeof(cc_args), vm_mm);       // back-end will fill args

        if (copy_to_user((void __user*)arg, &cc_args, sizeof(cc_args)))
            return -EFAULT;

		break;

	case KFD_IOC_GET_PROCESS_APERTURES:
		printk("KFD_IOC_GET_PROCESS_APERTURES\n");
        struct kfd_ioctl_get_process_apertures_args pa_args;

        if (copy_from_user(&pa_args, arg, sizeof(pa_args)))
            return -EFAULT;

		err = virtkfd_add_req(VIRTKFD_GET_PROCESS_APERTURES, &pa_args, sizeof(pa_args), vm_mm);       // back-end will fill args
        printk("num_of_nodes=%d\n", pa_args.num_of_nodes);
        printk("lds_base=0x%llx\n", pa_args.process_apertures[0].lds_base);
        printk("lds_limit=0x%llx\n", pa_args.process_apertures[0].lds_limit);
        printk("gpu_id=%d\n", pa_args.process_apertures[0].gpu_id);

        if (copy_to_user((void __user*)arg, &pa_args, sizeof(pa_args)))
            return -EFAULT;

		break;

	case KFD_IOC_UPDATE_QUEUE:
		printk("KFD_IOC_UPDATE_QUEUE\n");
//		err = kfd_ioctl_update_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_DBG_REGISTER:
		printk("KFD_IOC_DBG_REGISTER\n");
//		err = kfd_ioctl_dbg_register(filep, process, (void __user *) arg);

		break;

	case KFD_IOC_DBG_UNREGISTER:
		printk("KFD_IOC_DBG_UNREGISTER\n");
//		err = kfd_ioctl_dbg_unrgesiter(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_DBG_ADDRESS_WATCH:
		printk("KFD_IOC_DBG_ADDRESS_WATCH\n");
//		err = kfd_ioctl_dbg_address_watch(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_DBG_WAVE_CONTROL:
		printk("KFD_IOC_DBG_WAVE_CONTROL\n");
//		err = kfd_ioctl_dbg_wave_control(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_PMC_ACQUIRE_ACCESS:
		printk("KFD_IOC_PMC_ACQUIRE_ACCESS\n");
//		err = kfd_ioctl_pmc_acquire_access(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_PMC_RELEASE_ACCESS:
		printk("KFD_IOC_PMC_RELEASE_ACCESS\n");
//		err = kfd_ioctl_pmc_release_access(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_CREATE_VIDMEM:
		printk("KFD_IOC_CREATE_VIDMEM\n");
//		err = kfd_ioctl_create_vidmem(filep, process, (void __user *)arg);

		break;

	case KFD_IOC_DESTROY_VIDMEM:
		printk("KFD_IOC_DESTROY_VIDMEM\n");
        struct kfd_ioctl_destroy_vidmem_args dv_args;

        if (copy_from_user(&dv_args, arg, sizeof(dv_args)))
            return -EFAULT;
		err = virtkfd_add_req(VIRTKFD_DESTROY_VIDMEM, &dv_args, sizeof(dv_args), vm_mm);       

		break;

	case KFD_IOC_CREATE_EVENT:
		printk("KFD_IOC_CREATE_EVENT\n");
        struct kfd_ioctl_create_event_args cv_args; 

        if (copy_from_user(&cv_args, arg, sizeof(cv_args)))
            return -EFAULT;

        printk("event_type=%u\n", cv_args.event_type);
        printk("auto_reset=%u\n", cv_args.auto_reset);
        printk("node_id=%u\n", cv_args.node_id);
		err = virtkfd_add_req(VIRTKFD_CREATE_EVENT, &cv_args, sizeof(cv_args), vm_mm);       // back-end will fill args
        printk("event_trigger_address=0x%llx\n", cv_args.event_trigger_address);
        printk("event_trigger_data=%u\n", cv_args.event_trigger_data);
        printk("event_id=%u\n", cv_args.event_id);
        if (copy_to_user((void __user*)arg, &cv_args, sizeof(cv_args)))
            return -EFAULT;
		break;

	case KFD_IOC_DESTROY_EVENT:
		printk("KFD_IOC_DESTROY_EVENT\n");
        struct kfd_ioctl_destroy_event_args de_args;

        if (copy_from_user(&de_args, arg, sizeof(de_args)))
            return -EFAULT;
		err = virtkfd_add_req(VIRTKFD_DESTROY_EVENT, &de_args, sizeof(de_args), vm_mm);       

		break;
	case KFD_IOC_SET_EVENT:
		printk("KFD_IOC_SET_EVENT\n");
//		err = kfd_ioctl_set_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_RESET_EVENT:
		printk("KFD_IOC_RESET_EVENT\n");
//		err = kfd_ioctl_reset_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_WAIT_EVENTS:
		printk("KFD_IOC_WAIT_EVENTS\n");
//		err = kfd_ioctl_wait_events(filep, process, (void __user *) arg);
		break;
	case KFD_IOC_OPEN_GRAPHIC_HANDLE:
		printk("KFD_IOC_OPEN_GRAPHIC_HANDLE\n");

//		err = kfd_ioctl_open_graphic_handle(filep, process, (void __user *)arg);

		break;

    case KFD_IOC_DEBUG_GVA:
        printk("KFD_IOC_DEBUG_GVA\n");
        uint64_t debug_gva;
        if (copy_from_user(&debug_gva, arg, sizeof(debug_gva)))
            return -EFAULT;
		err = virtkfd_add_req(VIRTKFD_DEBUG_GVA, &debug_gva, sizeof(debug_gva), vm_mm);       

	default:
		dev_err(virtkfd_device,
			"unknown ioctl cmd 0x%x, arg 0x%lx)\n",
			cmd, arg);
		err = -EINVAL;
		break;
	}

	if ((err < 0) && (err != -EAGAIN))
		dev_err(virtkfd_device, "ioctl error %ld\n", err);

	return err;
}

static int
virtkfd_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long pgoff = vma->vm_pgoff;
	struct virtkfd_process *process;

    printk("virtkfd_mmap, pgoff=0x%llx\n", pgoff);

	process = find_process(current);
	if (IS_ERR(process)) {
        printk("find_process %p\n", process);
		return PTR_ERR(process);
    }

 	if (pgoff >= VIRTKFD_MMAP_DOORBELL_START && pgoff < VIRTKFD_MMAP_DOORBELL_END)
   		return radeon_virtkfd_doorbell_mmap(process, vma);
//   	else if (pgoff >= VIRTKFD_MMAP_EVENTS_START && pgoff < VIRTKFD_MMAP_EVENTS_END)
//   		return radeon_kfd_event_mmap(process, vma);

	return -EINVAL;
}

static int __init init(void)
{
	int err = 0;
printk("virtio-kfd init\n");
	alloc_chrdev_region(&virtkfd_major, 0, 1, virtkfd_name);
	if (virtkfd_major < 0)
		goto err_register_chrdev;

	virtkfd_class = class_create(THIS_MODULE, virtkfd_name);
	err = PTR_ERR(virtkfd_class);
	if (IS_ERR(virtkfd_class))
		goto err_class_create;

	virtkfd_device = device_create(virtkfd_class, NULL, 
                            virtkfd_major, NULL, virtkfd_name);
	err = PTR_ERR(virtkfd_device);
	if (IS_ERR(virtkfd_device))
		goto err_device_create;

	cdev_init(&virtkfd_cdev, &virtkfd_fops);
	err = cdev_add(&virtkfd_cdev, virtkfd_major, 1);
	if(err) {
		printk("Unable to add virtkfd_cdev\n");
		goto err_device_create;
	}

/*
	virtblk_wq = alloc_workqueue("virtio-blk", 0, 0);
	if (!virtblk_wq)
		return -ENOMEM;

	major = register_blkdev(0, "virtblk");
	if (major < 0) {
		error = major;
		goto out_destroy_workqueue;
	}
*/
	err = register_virtio_driver(&virtio_kfd);
	if (err)
		goto err_device_create;

	return 0;

err_device_create:
	class_destroy(virtkfd_class);
err_class_create:
	unregister_chrdev(virtkfd_major, virtkfd_name);
err_register_chrdev:
	return err;
}

static void __exit fini(void)
{
    printk("module_exit\n");
//	unregister_chrdev(virtkfd_major, virtkfd_name);
    cdev_del(&virtkfd_cdev);
	unregister_virtio_driver(&virtio_kfd);
//	destroy_workqueue(virtblk_wq);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio kfd driver");
MODULE_LICENSE("GPL");
