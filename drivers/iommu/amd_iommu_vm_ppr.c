//#define DEBUG
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/cgroup.h>
#include <linux/module.h>
#include <linux/hashtable.h>
#include <linux/kvm_host.h> // for kvm
#include <uapi/linux/iommu_vm_ppr_ioctl.h>

#include "amd_iommu_v2.h"
#include "amd_iommu_proto.h"
#include "amd_iommu_vm_ppr.h"

//FIXME: for debugging usage
#include <linux/radeon_kfd.h>

#define IOMMU_VM_PPR_TABLE_SIZE 5 /* bits: 32 entries */
//struct hlist_node iommu_vm_pprs;
static DEFINE_HASHTABLE(iommu_vm_pprs, IOMMU_VM_PPR_TABLE_SIZE);
static DEFINE_MUTEX(iommu_vm_ppr_mutex);

//FIXME: for debugging usage
void (*read_guest_pgd_p)(struct mm_struct *mm);

static struct iommu_vm_ppr* find_iommu_vm_ppr(struct mm_struct *mm)
{
    struct iommu_vm_ppr *iommu_vm_ppr;

//    printk("find_iommu_vm_ppr, mm=%p\n", mm);
    hash_for_each_possible(iommu_vm_pprs, iommu_vm_ppr, node, (uintptr_t)mm)
        if (iommu_vm_ppr->virtio_be_mm == mm)
            return iommu_vm_ppr;
}  

static struct pasid_state *mm_to_state(struct mm_struct *mm)
{
    struct pasid_state *pasid_state; 
    list_for_each_entry(pasid_state, &pasid_state_list, list)
        if (pasid_state->mm == mm)
            return pasid_state;
}

static void __mm_flush_page(struct mm_struct *mm,
			    unsigned long address)
{
	struct pasid_state *pasid_state;
	struct device_state *dev_state;

	pasid_state = mm_to_state(mm);
	dev_state   = pasid_state->device_state;

    printk("__mm_flush_page, domain=%p\n", dev_state->domain);
	amd_iommu_flush_page(dev_state->domain, pasid_state->pasid, address);
}

void amd_iommu_vm_ppr(struct fault *fault, int write)
{
    struct iommu_vm_ppr *iommu_vm_ppr;
    struct ppr_log *ppr_log;
    
//    printk("amd_iommu_vm_ppr %p\n", fault->state->virtio_be_mm);

    iommu_vm_ppr = find_iommu_vm_ppr(fault->state->virtio_be_mm); // use virtio_be_mm
//    printk("iommu_vm_ppr=%p\n", iommu_vm_ppr);
    if (!iommu_vm_ppr) {
        printk("!!! find_iommu_vm_ppr null %p\n", fault->state->mm); 
        return;
    }

    ppr_log = &iommu_vm_ppr->ppr_log_region[iommu_vm_ppr->tail];
    if (!ppr_log) {
        printk("!!! ppr_log null\n");
        return;
    }

    printk("tail=%d, head=%d, vm_consume_head=%d, ppr_log=%p\n", 
            iommu_vm_ppr->tail, iommu_vm_ppr->head, iommu_vm_ppr->vm_consume_head, ppr_log);
    ppr_log->vm_task = fault->state->task;
    ppr_log->vm_mm   = fault->state->mm;
    ppr_log->address = fault->address;
    ppr_log->write   = write;
    ppr_log->fault   = (u64)fault;
    printk("task=%p, mm=%p, addr=0x%llx, write=%d, fault=%llx\n", 
        ppr_log->vm_task, ppr_log->vm_mm, ppr_log->address, ppr_log->write, ppr_log->fault);

    iommu_vm_ppr->tail = (iommu_vm_ppr->tail+1)%MAX_PPR_LOG_ENTRY;
    if (iommu_vm_ppr->tail == iommu_vm_ppr->head)
        printk(" !!! guest consume too slow\n");
    printk("tail=%d, head=%d, vm_consume_head=%d, ppr_log=%p\n", 
            iommu_vm_ppr->tail, iommu_vm_ppr->head, iommu_vm_ppr->vm_consume_head, ppr_log);

    // write eventfd to kick guest
    if (!iommu_vm_ppr->call_ctx)
        printk("!!!iommu_vm_ppr->call_ctx %p\n", iommu_vm_ppr->call_ctx);
    else
        eventfd_signal(iommu_vm_ppr->call_ctx, 1);
    printk("amd_iommu_vm_ppr kick guest done\n");
}
EXPORT_SYMBOL(amd_iommu_vm_ppr);

static long vm_finish_ppr(struct iommu_vm_ppr *iommu_vm_ppr, uint64_t gpa)
{
    int head, tail;
    struct fault *fault;
    u32 error_code = 0;
    int ret;

//    printk("vm_finish_ppr: %p\n", iommu_vm_ppr);
    printk("vm_finish_ppr: tail=%d, head=%d, vm_consume_head=%d\n", 
            iommu_vm_ppr->tail, iommu_vm_ppr->head, iommu_vm_ppr->vm_consume_head);
    head = iommu_vm_ppr->head;
    tail = iommu_vm_ppr->vm_consume_head;

//    while (head != tail) {
        fault = (struct fault*)(iommu_vm_ppr->ppr_log_region[head].fault);
        printk("fault=%p, pasid=%d\n", fault, fault->pasid);
    	if (fault->dev_state->inv_ppr_cb) {
	    	int status;

    		status = fault->dev_state->inv_ppr_cb(fault->dev_state->pdev,
	    					      fault->pasid,
    						      fault->address,
    						      fault->flags);
            printk("inv_ppr_cb status=%d\n", status);
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
                printk("inv_ppr_cb BUG\n");
    			BUG();
    		}
    	} 

        // fix stage2 page table
        ret = kvm_hsa_iommu_nested_page_fault(fault->state->kvm, gpa, fault->flags);  
        printk("ret=%d\n", ret);

        // flush
  		amd_iommu_flush_all_tlb(fault->dev_state->domain);

        printk("finish_pri_tag\n");
		set_pri_tag_status(fault->state, fault->tag, PPR_SUCCESS);
	    finish_pri_tag(fault->dev_state, fault->state, fault->tag, 1);    
    	put_pasid_state(fault->state);    
    	kfree(fault);
        
        head = (head+1) % MAX_PPR_LOG_ENTRY;
//    }

    iommu_vm_ppr->head = head;
    printk("tail=%d, head=%d, vm_consume_head=%d\n", 
            iommu_vm_ppr->tail, iommu_vm_ppr->head, iommu_vm_ppr->vm_consume_head);
    return 0;
}
    
static int amd_iommu_vm_ppr_open(struct inode *inode, struct file *f)
{
    struct iommu_vm_ppr *iommu_vm_ppr;
    printk("amd_iommu_vm_ppr_open, current->mm=%p\n", current->mm);

    iommu_vm_ppr = (struct iommu_vm_ppr*)__get_free_page(GFP_KERNEL);
    if (!iommu_vm_ppr)
        return -ENOMEM;
    SetPageReserved(virt_to_page(iommu_vm_ppr));
    
    printk("iommu_vm_ppr=%p, ppr_region=%p\n", iommu_vm_ppr, iommu_vm_ppr->ppr_log_region);
    iommu_vm_ppr->head = 0;
    iommu_vm_ppr->tail = 0;
    iommu_vm_ppr->vm_consume_head = 0;
    iommu_vm_ppr->virtio_be_mm = current->mm;

    mutex_lock(&iommu_vm_ppr_mutex);
    hash_add(iommu_vm_pprs, &iommu_vm_ppr->node, (uintptr_t)current->mm);   
    mutex_unlock(&iommu_vm_ppr_mutex);

    //FIXME: for debugging usage
    read_guest_pgd_p = symbol_request(read_guest_pgd);
    if (!read_guest_pgd_p) {
        printk("symbol_request(read_guest_pgd_be) fail\n");
        return -EINVAL;
    }

    return 0;
}

static long amd_iommu_vm_ppr_ioctl(struct file *f, unsigned int ioctl,
			    unsigned long arg)
{
	struct file *eventfp;
	void __user *argp = (void __user *)arg;
    struct iommu_vm_ppr *iommu_vm_ppr;
    struct vm_mmu_notification mmu_notify;
    struct pasid_state *pasid_state;
    struct device_state *dev_state;
    unsigned long start, end;
    uint64_t gpa;
    int fd;
	int r;

    printk("amd_iommu_vm_ppr_ioctl ...");
    iommu_vm_ppr = find_iommu_vm_ppr(current->mm);

	switch (ioctl) {
	case IVP_IOC_SET_KVM_EVENTFD:
        printk("IVP_IOC_SET_KVM_EVENTFD\n");
		if (copy_from_user(&fd, argp, sizeof fd)) {
			r = -EFAULT;
			break;
		}

		eventfp = fd == -1 ? NULL : eventfd_fget(fd);
        printk("fd=%d, eventfp=%p\n", fd, eventfp);
		if (IS_ERR(eventfp)) {
            printk("!!! eventfp fail\n");
			r = PTR_ERR(eventfp);
			break;
		}

        iommu_vm_ppr->call_ctx = eventfd_ctx_fileget(eventfp);
        printk("iommu_vm_ppr->call_ctx=%p\n", iommu_vm_ppr->call_ctx);
		if (IS_ERR(iommu_vm_ppr->call_ctx)) {
            printk("!!! call_ctx fail\n");
			r = PTR_ERR(iommu_vm_ppr->call_ctx);
			break;
		}

//        printk("eventfd_signal in IVP_IOC_SET_KVM_EVENTFD ...");
//        eventfd_signal(iommu_vm_ppr->call_ctx, 1);
//        printk(" done \n");
		break;

    case IVP_IOC_VM_FINISH_PPR:
		if (copy_from_user(&gpa, argp, sizeof gpa)) {
			r = -EFAULT;
			break;
		}
        printk("IVP_IOC_VM_FINISH_PPR, gpa=%llx\n", gpa);

        r = vm_finish_ppr(iommu_vm_ppr, gpa);
        break;

    case IVP_IOC_MMU_CLEAR_FLUSH_YOUNG:
        printk("IVP_IOC_MMU_CLEAR_FLUSH_YOUNG\n");
		if (copy_from_user(&mmu_notify, argp, sizeof mmu_notify)) {
			r = -EFAULT;
			break;
		}

        printk("mm=%llx, addr=%llx\n", mmu_notify.mm, mmu_notify.start);
        __mm_flush_page((struct mm_struct*)(mmu_notify.mm), mmu_notify.start);
        break;

    case IVP_IOC_MMU_CHANGE_PTE:
        printk("IVP_IOC_MMU_CHANGE_PTE\n");
		if (copy_from_user(&mmu_notify, argp, sizeof mmu_notify)) {
			r = -EFAULT;
			break;
		}

        printk("mm=%llx, addr=%llx\n", mmu_notify.mm, mmu_notify.start);
        __mm_flush_page((struct mm_struct*)(mmu_notify.mm), mmu_notify.start);
        break;

    case IVP_IOC_MMU_INVALIDATE_PAGE:
        printk("IVP_IOC_MMU_INVALIDATE_PAGE\n");
		if (copy_from_user(&mmu_notify, argp, sizeof mmu_notify)) {
			r = -EFAULT;
			break;
		}

        printk("mm=%llx, addr=%llx\n", mmu_notify.mm, mmu_notify.start);
        __mm_flush_page((struct mm_struct*)(mmu_notify.mm), mmu_notify.start);
        break;

    case IVP_IOC_MMU_INVALIDATE_RANGE_START:
        printk("IVP_IOC_MMU_INVALIDATE_RANGE_START\n");
		if (copy_from_user(&mmu_notify, argp, sizeof mmu_notify)) {
			r = -EFAULT;
			break;
		}
        start = mmu_notify.start;
        end   = mmu_notify.end;
        printk("mm=%llx, start=%llx, end=%llx\n", mmu_notify.mm, start, end);
        pasid_state = mm_to_state((struct mm_struct*)(mmu_notify.mm));
        dev_state   = pasid_state->device_state;

        printk("domain=%p, pasid=%d\n", dev_state->domain, pasid_state->pasid);

/*    	if ((start ^ (end - 1)) < PAGE_SIZE)
    		amd_iommu_flush_page(dev_state->domain, pasid_state->pasid,
    				     start);
    	else*/
    		amd_iommu_flush_all_tlb(dev_state->domain);

        break;

	default:
        printk("unknown ioctl cmd 0x%x\n", ioctl);
		return -EFAULT;
	}

    return r;
}

static int
amd_iommu_vm_ppr_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long pgoff = vma->vm_pgoff;
    struct iommu_vm_ppr *iommu_vm_ppr;
	phys_addr_t start;

    printk("amd_iommu_vm_ppr_mmap\n");
    iommu_vm_ppr = find_iommu_vm_ppr(current->mm);
    if (!iommu_vm_ppr) {
        printk(" find_iommu_vm_ppr null\n");
        return -EFAULT;
    }
    printk("pgoff=0x%llx, iommu_vm_ppr=%p, __pa=0x%llx, virt_to_phys=0x%llx\n", 
                pgoff, iommu_vm_ppr, __pa(iommu_vm_ppr), virt_to_phys(iommu_vm_ppr));

    printk("vm_start=0x%lx, vm_end=0x%lx\n", vma->vm_start, vma->vm_end);

	vma->vm_flags |= VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_NORESERVE | VM_DONTDUMP | VM_PFNMAP;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	start = virt_to_phys(iommu_vm_ppr);
    vma->vm_pgoff = start >> PAGE_SHIFT;
    printk("start=0x%lx, vma->pgoff=0x%lx, vm_flags=%llx\n", start, vma->vm_pgoff, vma->vm_flags);

	return io_remap_pfn_range(vma, vma->vm_start, start >> PAGE_SHIFT, VM_PPR_SIZE, vma->vm_page_prot);
}

static const struct file_operations amd_iommu_vm_ppr_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = amd_iommu_vm_ppr_ioctl,
	.compat_ioctl   = amd_iommu_vm_ppr_ioctl,
	.open           = amd_iommu_vm_ppr_open,
    .mmap           = amd_iommu_vm_ppr_mmap,
};

static struct miscdevice amd_iommu_vm_ppr_misc = {
	.minor = IOMMU_VM_PPR_MINOR,
	.name = "iommu-vm-ppr",
	.fops = &amd_iommu_vm_ppr_fops,
};

static int amd_iommu_vm_ppr_init(void)
{
	return misc_register(&amd_iommu_vm_ppr_misc);
}
module_init(amd_iommu_vm_ppr_init);

static void amd_iommu_vm_ppr_exit(void)
{
	misc_deregister(&amd_iommu_vm_ppr_misc);
}
module_exit(amd_iommu_vm_ppr_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Yu-Ju Huang <gic4107@gmail.com>");
MODULE_DESCRIPTION("Kernel module to allow virtual machine gather iommu ppr log for guest OS page fault");
MODULE_ALIAS_MISCDEV(AMD_IOMMU_GUEST_PPR_MINOR);
MODULE_ALIAS("devname:iommu-vm-ppr");
