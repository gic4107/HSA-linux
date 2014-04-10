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
 * Author: Ben Goz
 */

#include <linux/types.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/io.h>
#include "kfd_hw_pointer_store.h"
#include "kfd_priv.h"

/* do the same trick as in map_doorbells() */
static int hw_pointer_store_map(struct hw_pointer_store_properties *ptr,
		struct file *devkfd)
{
	qptr_t __user *user_address;

	BUG_ON(!ptr || !devkfd);

	if (!ptr->page_mapping) {
		if (!ptr->page_address)
			return -EINVAL;

		user_address = (qptr_t __user *)vm_mmap(devkfd, 0, PAGE_SIZE,
			PROT_WRITE | PROT_READ , MAP_SHARED, ptr->offset);

		if (IS_ERR(user_address))
			return PTR_ERR(user_address);

		ptr->page_mapping = user_address;
	}

	return 0;
}

int hw_pointer_store_init(struct hw_pointer_store_properties *ptr,
		enum hw_pointer_store_type type)
{
	unsigned long *addr;

	BUG_ON(!ptr);

	/* using the offset value as a hint for mmap to distinguish between page types */
	if (type == KFD_HW_POINTER_STORE_TYPE_RPTR)
		ptr->offset = KFD_MMAP_RPTR_START << PAGE_SHIFT;
	else if (type == KFD_HW_POINTER_STORE_TYPE_WPTR)
		ptr->offset = KFD_MMAP_WPTR_START << PAGE_SHIFT;
	else
		return -EINVAL;

	addr = (unsigned long *)get_zeroed_page(GFP_KERNEL);
	if (!addr) {
		pr_debug("Error allocating page\n");
		return -ENOMEM;
	}

	ptr->page_address = addr;
	ptr->page_mapping = NULL;

	return 0;
}

void hw_pointer_store_destroy(struct hw_pointer_store_properties *ptr)
{
	BUG_ON(!ptr);
	pr_debug("kfd in func: %s\n", __func__);
	if (ptr->page_address)
		free_page((unsigned long)ptr->page_address);
	if (ptr->page_mapping)
		vm_munmap((uintptr_t)ptr->page_mapping, PAGE_SIZE);
	ptr->page_address = NULL;
	ptr->page_mapping = NULL;
}

qptr_t __user *
hw_pointer_store_create_queue(struct hw_pointer_store_properties *ptr,
		unsigned int queue_id, struct file *devkfd)
{
	BUG_ON(!ptr || queue_id >= MAX_PROCESS_QUEUES);

	/* mapping value to user space*/
	hw_pointer_store_map(ptr, devkfd);

	/* User process address */
	if (!ptr->page_mapping) {
		pr_debug(KERN_ERR "kfd: hw pointer store doesn't mapped to user space\n");
		return NULL;
	}

	ptr->page_mapping[queue_id] = 0;

	return ptr->page_mapping + queue_id;
}

unsigned long *hw_pointer_store_get_address
	(struct hw_pointer_store_properties *ptr, unsigned int queue_id)
{
	return ptr->page_address + queue_id;
}

int radeon_kfd_hw_pointer_store_mmap(struct hw_pointer_store_properties *ptr,
		struct vm_area_struct *vma)
{
	BUG_ON(!ptr || !vma);

	if (vma->vm_end - vma->vm_start != PAGE_SIZE) {
		pr_debug("start address(0x%lx) - end address(0x%lx) != len(0x%lx)\n", vma->vm_end, vma->vm_start, PAGE_SIZE);
		return -EINVAL;
	}

	vma->vm_flags |= VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_NORESERVE
		       | VM_DONTDUMP | VM_PFNMAP;

	pr_debug("kfd: mapping hw pointer page in radeon_kfd_hw_pointer_store_mmap\n"
			 "     target user address == 0x%016llX\n"
			 "     physical address    == 0x%016lX\n"
			 "     vm_flags            == 0x%08lX\n"
			 "     size                == 0x%08lX\n",
			 (long long unsigned int) vma->vm_start,
			 __pa(ptr->page_address), vma->vm_flags, PAGE_SIZE);

	/* mapping the page to user process */
	return remap_pfn_range(vma, vma->vm_start, __pa(ptr->page_address) >> PAGE_SHIFT, PAGE_SIZE, vma->vm_page_prot);
}

