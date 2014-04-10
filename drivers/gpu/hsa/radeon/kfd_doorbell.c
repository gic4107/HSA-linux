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

#include "kfd_priv.h"
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>

/*
 * This extension supports a kernel level doorbells management for the kernel queues
 * basically the last doorbells page is devoted to kernel queues and that's assures
 * that any user process won't get access to the kernel doorbells page
 */
static DEFINE_MUTEX(doorbell_mutex);
static unsigned long doorbell_available_index[DIV_ROUND_UP(MAX_PROCESS_QUEUES, BITS_PER_LONG)] = { 0 };
#define KERNEL_DOORBELL_PASID 1

/* Each device exposes a doorbell aperture, a PCI MMIO aperture that receives 32-bit writes that are passed to queues
** as wptr values.
** The doorbells are intended to be written by applications as part of queueing work on user-mode queues.
** We assign doorbells to applications in PAGE_SIZE-sized and aligned chunks. We map the doorbell address space into
** user-mode when a process creates its first queue on each device.
** Although the mapping is done by KFD, it is equivalent to an mmap of the /dev/kfd with the particular device encoded
** in the mmap offset.
** There will be other uses for mmap of /dev/kfd, so only a range of offsets (KFD_MMAP_DOORBELL_START-END) is used for
** doorbells. */

/* # of doorbell bytes allocated for each process. */
static inline size_t doorbell_process_allocation(void)
{
	return roundup(sizeof(doorbell_t) * MAX_PROCESS_QUEUES, PAGE_SIZE);
}

/* Doorbell calculations for device init. */
void radeon_kfd_doorbell_init(struct kfd_dev *kfd)
{
	size_t doorbell_start_offset;
	size_t doorbell_aperture_size;
	size_t doorbell_process_limit;

	/* We start with calculations in bytes because the input data might only be byte-aligned.
	** Only after we have done the rounding can we assume any alignment. */

	doorbell_start_offset = roundup(kfd->shared_resources.doorbell_start_offset, doorbell_process_allocation());
	doorbell_aperture_size = rounddown(kfd->shared_resources.doorbell_aperture_size, doorbell_process_allocation());

	if (doorbell_aperture_size > doorbell_start_offset)
		doorbell_process_limit = (doorbell_aperture_size - doorbell_start_offset) / doorbell_process_allocation();
	else
		doorbell_process_limit = 0;

	kfd->doorbell_base = kfd->shared_resources.doorbell_physical_address + doorbell_start_offset;
	kfd->doorbell_id_offset = doorbell_start_offset / sizeof(doorbell_t);
	kfd->doorbell_process_limit = doorbell_process_limit - 1;

	kfd->doorbell_kernel_ptr = ioremap(kfd->doorbell_base, doorbell_process_allocation());
	BUG_ON(!kfd->doorbell_kernel_ptr);

	pr_debug("kfd: doorbell initialization\n"
				 "     doorbell base           == 0x%08lX\n"
				 "     doorbell_id_offset      == 0x%08lu\n"
				 "     doorbell_process_limit  == 0x%08lu\n"
				 "     doorbell_kernel_offset  == 0x%08lX\n"
				 "     doorbell aperture size  == 0x%08lX\n"
				 "     doorbell kernel address == 0x%08lX\n",
				 (uintptr_t)kfd->doorbell_base, kfd->doorbell_id_offset, doorbell_process_limit,
				 (uintptr_t)kfd->doorbell_base, kfd->shared_resources.doorbell_aperture_size,
				 (uintptr_t)kfd->doorbell_kernel_ptr);

}

/* This is the /dev/kfd mmap (for doorbell) implementation. We intend that this is only called through map_doorbells,
** not through user-mode mmap of /dev/kfd. */
int radeon_kfd_doorbell_mmap(struct kfd_process *process, struct vm_area_struct *vma)
{
	unsigned int device_index;
	struct kfd_dev *dev;
	phys_addr_t start;

	BUG_ON(vma->vm_pgoff < KFD_MMAP_DOORBELL_START || vma->vm_pgoff >= KFD_MMAP_DOORBELL_END);

	/* For simplicitly we only allow mapping of the entire doorbell allocation of a single device & process. */
	if (vma->vm_end - vma->vm_start != doorbell_process_allocation())
		return -EINVAL;

	/* device_index must be GPU ID!! */
	device_index = vma->vm_pgoff - KFD_MMAP_DOORBELL_START;

	dev = radeon_kfd_device_by_id(device_index);
	if (dev == NULL)
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_NORESERVE | VM_DONTDUMP | VM_PFNMAP;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	start = dev->doorbell_base + process->pasid * doorbell_process_allocation();

	pr_debug("kfd: mapping doorbell page in radeon_kfd_doorbell_mmap\n"
		 "     target user address == 0x%016llX\n"
		 "     physical address    == 0x%016llX\n"
		 "     vm_flags            == 0x%08lX\n"
		 "     size                == 0x%08lX\n",
		 (long long unsigned int) vma->vm_start, start, vma->vm_flags,
		 doorbell_process_allocation());

	return io_remap_pfn_range(vma, vma->vm_start, start >> PAGE_SHIFT, doorbell_process_allocation(), vma->vm_page_prot);
}

/* Map the doorbells for a single process & device. This will indirectly call radeon_kfd_doorbell_mmap.
** This assumes that the process mutex is being held. */
static int
map_doorbells(struct file *devkfd, struct kfd_process *process, struct kfd_dev *dev)
{
	struct kfd_process_device *pdd = radeon_kfd_get_process_device_data(dev, process);

	if (pdd == NULL)
		return -ENOMEM;

	if (pdd->doorbell_mapping == NULL) {
		unsigned long offset = (KFD_MMAP_DOORBELL_START + dev->id) << PAGE_SHIFT;
		doorbell_t __user *doorbell_mapping;

		doorbell_mapping = (doorbell_t __user *)vm_mmap(devkfd, 0, doorbell_process_allocation(), PROT_WRITE,
								MAP_SHARED, offset);
		if (IS_ERR(doorbell_mapping))
			return PTR_ERR(doorbell_mapping);

		pdd->doorbell_mapping = doorbell_mapping;
	}

	return 0;
}

/* get kernel iomem pointer for a doorbell */
u32 __iomem *radeon_kfd_get_kernel_doorbell(struct kfd_dev *kfd, unsigned int *doorbell_off)
{
	u32 inx;
	BUG_ON(!kfd || !doorbell_off);

	mutex_lock(&doorbell_mutex);
	inx = find_first_zero_bit(doorbell_available_index, MAX_PROCESS_QUEUES);
	__set_bit(inx, doorbell_available_index);
	mutex_unlock(&doorbell_mutex);

	if (inx >= MAX_PROCESS_QUEUES)
		return NULL;

	/* caluculating the kernel doorbell offset using "faked" kernel pasid that allocated for kernel queues only */
	*doorbell_off = KERNEL_DOORBELL_PASID * (doorbell_process_allocation()/sizeof(doorbell_t)) + inx;

	pr_debug("kfd: get kernel queue doorbell\n"
			 "     doorbell offset   == 0x%08d\n"
			 "     kernel address    == 0x%08lX\n",
			 *doorbell_off, (uintptr_t)(kfd->doorbell_kernel_ptr + inx));

	return kfd->doorbell_kernel_ptr + inx;
}

void radeon_kfd_release_kernel_doorbell(struct kfd_dev *kfd, u32 __iomem *db_addr)
{
	unsigned int inx;
	BUG_ON(!kfd || !db_addr);

	inx = (unsigned int)(db_addr - kfd->doorbell_kernel_ptr);

	mutex_lock(&doorbell_mutex);
	__clear_bit(inx, doorbell_available_index);
	mutex_unlock(&doorbell_mutex);
}

inline void write_kernel_doorbell(u32 __iomem *db, u32 value)
{
	if (db) {
		writel(value, db);
		pr_debug("writing %d to doorbell address 0x%p\n", value, db);
	}
}

/* Get the user-mode address of a doorbell. Assumes that the process mutex is being held. */
doorbell_t __user *radeon_kfd_get_doorbell(struct file *devkfd, struct kfd_process *process, struct kfd_dev *dev,
					   unsigned int doorbell_index)
{
	struct kfd_process_device *pdd;
	int err;

	BUG_ON(doorbell_index > MAX_DOORBELL_INDEX);

	err = map_doorbells(devkfd, process, dev);
	if (err)
		return ERR_PTR(err);

	pdd = radeon_kfd_get_process_device_data(dev, process);
	BUG_ON(pdd == NULL); /* map_doorbells would have failed otherwise */

	pr_debug("doorbell value on creation 0x%x\n", pdd->doorbell_mapping[doorbell_index]);

	return &pdd->doorbell_mapping[doorbell_index];
}

/* queue_ids are in the range [0,MAX_PROCESS_QUEUES) and are mapped 1:1 to doorbells with the process's doorbell page. */
unsigned int radeon_kfd_queue_id_to_doorbell(struct kfd_dev *kfd, struct kfd_process *process, unsigned int queue_id)
{
	/* doorbell_id_offset accounts for doorbells taken by KGD.
	 * pasid * doorbell_process_allocation/sizeof(doorbell_t) adjusts to the process's doorbells */
	return kfd->doorbell_id_offset + process->pasid * (doorbell_process_allocation()/sizeof(doorbell_t)) + queue_id;
}

void radeon_kfd_doorbell_unmap(struct kfd_process_device *pdd)
{
	if (pdd->doorbell_mapping != NULL)
		vm_munmap((uintptr_t)pdd->doorbell_mapping, doorbell_process_allocation());
}
