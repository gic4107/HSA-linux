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
 */

#include <linux/device.h>
#include <linux/export.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/compat.h>
#include <uapi/linux/kfd_ioctl.h>
#include <linux/time.h>
#include "kfd_priv.h"
#include <linux/mm.h>
#include <uapi/asm-generic/mman-common.h>
#include <asm/processor.h>


#define MAKE_GPUVM_APP_BASE(gpu_num) (((uint64_t)(gpu_num) << 61) + 0x1000000000000)
#define MAKE_GPUVM_APP_LIMIT(base) (((uint64_t)(base) & 0xFFFFFF0000000000) | 0xFFFFFFFFFF)
#define MAKE_SCRATCH_APP_BASE(gpu_num) (((uint64_t)(gpu_num) << 61) + 0x100000000)
#define MAKE_SCRATCH_APP_LIMIT(base) (((uint64_t)base & 0xFFFFFFFF00000000) | 0xFFFFFFFF)
#define MAKE_LDS_APP_BASE(gpu_num) (((uint64_t)(gpu_num) << 61) + 0x0)
#define MAKE_LDS_APP_LIMIT(base) (((uint64_t)(base) & 0xFFFFFFFF00000000) | 0xFFFFFFFF)

#define HSA_32BIT_LDS_APP_SIZE 0x10000
#define HSA_32BIT_LDS_APP_ALIGNMENT 0x10000

static unsigned long kfd_reserve_aperture(struct kfd_process *process, unsigned long len, unsigned long alignment)
{

	unsigned long addr = 0;
	unsigned long start_address;

	/*Go bottom up and find the first available aligned address. We may narrow space to scan by getting mmap range limits */
	for (start_address =  alignment; start_address < (TASK_SIZE - alignment); start_address += alignment) {
		addr = vm_mmap(NULL, start_address, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
		if (!IS_ERR_VALUE(addr)) {
			if (addr == start_address)
				return addr;
			else
				vm_munmap(addr, len);
		}
	}
	return 0;

}

int kfd_init_apertures(struct kfd_process *process)
{
	uint8_t id  = 0;
	struct kfd_dev *dev;
	struct kfd_process_device *pdd;

	mutex_lock(&process->mutex);

	/*Iterating over all devices*/
	while ((dev = kfd_topology_enum_kfd_devices(id)) != NULL && id < NUM_OF_SUPPORTED_GPUS) {

		pdd = radeon_kfd_get_process_device_data(dev, process);

		/*for 64 bit process aperture will be statically reserved in the non canonical process address space
		 *for 32 bit process the aperture will be reserved in the process address space
		 */
		if (process->is_32bit_user_mode) {
			/*try to reserve aperture. continue on failure, just put the aperture size to be 0*/
			pdd->lds_base = kfd_reserve_aperture(process, HSA_32BIT_LDS_APP_SIZE, HSA_32BIT_LDS_APP_ALIGNMENT);
			if (pdd->lds_base)
				pdd->lds_limit = pdd->lds_base + HSA_32BIT_LDS_APP_SIZE - 1;
			else
				pdd->lds_limit = 0;

			/*GPUVM and Scratch apertures are not supported*/
			pdd->gpuvm_base = pdd->gpuvm_limit = pdd->scratch_base = pdd->scratch_limit = 0;
		} else {
			/*node id couldn't be 0 - the three MSB bits of aperture shoudn't be 0*/
			pdd->lds_base = MAKE_LDS_APP_BASE(id + 1);
			pdd->lds_limit = MAKE_LDS_APP_LIMIT(pdd->lds_base);
			pdd->gpuvm_base = MAKE_GPUVM_APP_BASE(id + 1);
			pdd->gpuvm_limit = MAKE_GPUVM_APP_LIMIT(pdd->gpuvm_base);
			pdd->scratch_base = MAKE_SCRATCH_APP_BASE(id + 1);
			pdd->scratch_limit = MAKE_SCRATCH_APP_LIMIT(pdd->scratch_base);
		}

		dev_dbg(kfd_device, "node id %u, gpu id %u, lds_base %llX lds_limit %llX gpuvm_base %llX gpuvm_limit %llX scratch_base %llX scratch_limit %llX",
				id, pdd->dev->id, pdd->lds_base, pdd->lds_limit, pdd->gpuvm_base, pdd->gpuvm_limit, pdd->scratch_base, pdd->scratch_limit);

		id++;
	}

	mutex_unlock(&process->mutex);

	return 0;
}


