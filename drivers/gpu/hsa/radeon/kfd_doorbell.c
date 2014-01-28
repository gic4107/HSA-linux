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
	kfd->doorbell_process_limit = doorbell_process_limit;
}

void radeon_kfd_doorbell_unmap(struct kfd_process_device *pdd)
{
	if (pdd->doorbell_mapping != NULL)
		vm_munmap((uintptr_t)pdd->doorbell_mapping, doorbell_process_allocation());
}
