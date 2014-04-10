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

#ifndef KFD_IOCTL_H_INCLUDED
#define KFD_IOCTL_H_INCLUDED

#include <linux/types.h>
#include <linux/ioctl.h>

#define KFD_IOCTL_CURRENT_VERSION 1

/* The 64-bit ABI is the authoritative version. */
#pragma pack(push, 1)

struct kfd_ioctl_get_version_args {
	uint32_t min_supported_version;	/* from KFD */
	uint32_t max_supported_version;	/* from KFD */
};

/* For kfd_ioctl_create_queue_args.queue_type. */
#define KFD_IOC_QUEUE_TYPE_COMPUTE   0
#define KFD_IOC_QUEUE_TYPE_SDMA      1

struct kfd_ioctl_create_queue_args {
	uint64_t ring_base_address;	/* to KFD */
	uint32_t ring_size;		/* to KFD */
	uint32_t gpu_id;		/* to KFD */
	uint32_t queue_type;		/* to KFD */
	uint32_t queue_percentage;	/* to KFD */
	uint32_t queue_priority;	/* to KFD */

	uint64_t write_pointer_address;	/* from KFD */
	uint64_t read_pointer_address;	/* from KFD */
	uint64_t doorbell_address;	/* from KFD */
	uint32_t queue_id;		/* from KFD */
};

struct kfd_ioctl_destroy_queue_args {
	uint32_t queue_id;		/* to KFD */
};

/* For kfd_ioctl_set_memory_policy_args.default_policy and alternate_policy */
#define KFD_IOC_CACHE_POLICY_COHERENT 0
#define KFD_IOC_CACHE_POLICY_NONCOHERENT 1

struct kfd_ioctl_set_memory_policy_args {
	uint32_t gpu_id;			/* to KFD */
	uint32_t default_policy;		/* to KFD */
	uint32_t alternate_policy;		/* to KFD */
	uint64_t alternate_aperture_base;	/* to KFD */
	uint64_t alternate_aperture_size;	/* to KFD */
};

struct kfd_ioctl_get_clock_counters_args {
	uint32_t gpu_id;		/* to KFD */
	uint64_t gpu_clock_counter;	/* from KFD */
	uint64_t cpu_clock_counter;	/* from KFD */
	uint64_t system_clock_counter;	/* from KFD */
	uint64_t system_clock_freq;	/* from KFD */
};

#define NUM_OF_SUPPORTED_GPUS 7

struct kfd_process_device_apertures{
	uint64_t lds_base;/* from KFD */
	uint64_t lds_limit;/* from KFD */
	uint64_t scratch_base;/* from KFD */
	uint64_t scratch_limit;/* from KFD */
	uint64_t gpuvm_base;/* from KFD */
	uint64_t gpuvm_limit;/* from KFD */
	uint32_t gpu_id;/* from KFD */
};

struct kfd_ioctl_get_process_apertures_args{
	struct kfd_process_device_apertures process_apertures[NUM_OF_SUPPORTED_GPUS];/* from KFD */
	uint8_t num_of_nodes; /* from KFD, should be in the range [1 - NUM_OF_SUPPORTED_GPUS]*/
};

#define KFD_IOC_MAGIC 'K'

#define KFD_IOC_GET_VERSION	_IOR(KFD_IOC_MAGIC, 1, struct kfd_ioctl_get_version_args)
#define KFD_IOC_CREATE_QUEUE	_IOWR(KFD_IOC_MAGIC, 2, struct kfd_ioctl_create_queue_args)
#define KFD_IOC_DESTROY_QUEUE	_IOWR(KFD_IOC_MAGIC, 3, struct kfd_ioctl_destroy_queue_args)
#define KFD_IOC_SET_MEMORY_POLICY	_IOW(KFD_IOC_MAGIC, 4, struct kfd_ioctl_set_memory_policy_args)
#define KFD_IOC_GET_CLOCK_COUNTERS	_IOWR(KFD_IOC_MAGIC, 5, struct kfd_ioctl_get_clock_counters_args)
#define KFD_IOC_GET_PROCESS_APERTURES _IOR(KFD_IOC_MAGIC, 6, struct kfd_ioctl_get_process_apertures_args)

#pragma pack(pop)

#endif
