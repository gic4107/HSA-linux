#include <linux/mm.h>    
#include <linux/mman.h>                                                             
#include <linux/slab.h> 
#include "virtio_kfd_priv.h"
/* # of doorbell bytes allocated for each process. */                               
inline size_t doorbell_process_allocation(void)
{                                                                                   
    return roundup(sizeof(doorbell_t) * MAX_PROCESS_QUEUES, PAGE_SIZE);             
} 

/* This is the /dev/kfd mmap (for doorbell) implementation. We intend that this is only called through map_doorbells,
** not through user-mode mmap of /dev/kfd. */
int radeon_virtkfd_doorbell_mmap(struct virtkfd_process *process, struct vm_area_struct *vma)
{
    printk("radeon_virtkfd_doorbell_mmap\n");
	phys_addr_t start;

	BUG_ON(vma->vm_pgoff < VIRTKFD_MMAP_DOORBELL_START || vma->vm_pgoff >= VIRTKFD_MMAP_DOORBELL_END);

    printk("vm_end=0x%lx, vm_start=0x%lx\n", vma->vm_end, vma->vm_start);
	/* For simplicitly we only allow mapping of the entire doorbell allocation of a single device & process. */
	if (vma->vm_end - vma->vm_start != doorbell_process_allocation())
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_NORESERVE | VM_DONTDUMP | VM_PFNMAP;
//	vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND | VM_NORESERVE | VM_DONTDUMP | VM_PFNMAP;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	start = virt_to_phys(process->doorbell_region);

	printk("kfd: mapping doorbell page in radeon_kfd_doorbell_mmap\n"
		 "     target user address == 0x%016llX\n"
		 "     physical address    == 0x%016llX\n"
		 "     vm_flags            == 0x%08lX\n"
		 "     size                == 0x%08lX\n",
		 (long long unsigned int) vma->vm_start, start, vma->vm_flags,
		 doorbell_process_allocation());

	pr_debug("kfd: mapping doorbell page in radeon_kfd_doorbell_mmap\n"
		 "     target user address == 0x%016llX\n"
		 "     physical address    == 0x%016llX\n"
		 "     vm_flags            == 0x%08lX\n"
		 "     size                == 0x%08lX\n",
		 (long long unsigned int) vma->vm_start, start, vma->vm_flags,
		 doorbell_process_allocation());

	return remap_pfn_range(vma, vma->vm_start, start >> PAGE_SHIFT, doorbell_process_allocation(), vma->vm_page_prot);
}
