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

#ifndef KFD_SCHEDULER_H_INCLUDED
#define KFD_SCHEDULER_H_INCLUDED

#include <linux/types.h>
struct kfd_process;

/* Opaque types for scheduler private data. */
struct kfd_scheduler;
struct kfd_scheduler_process;
struct kfd_scheduler_queue;

struct kfd_scheduler_class {
	const char *name;

	int (*create)(struct kfd_dev *, struct kfd_scheduler **);
	void (*destroy)(struct kfd_scheduler *);

	void (*start)(struct kfd_scheduler *);
	void (*stop)(struct kfd_scheduler *);

	int (*register_process)(struct kfd_scheduler *, struct kfd_process *, struct kfd_scheduler_process **);
	void (*deregister_process)(struct kfd_scheduler *, struct kfd_scheduler_process *);

	size_t queue_size;

	int (*create_queue)(struct kfd_scheduler *scheduler,
			    struct kfd_scheduler_process *process,
			    struct kfd_scheduler_queue *queue,
			    void __user *ring_address,
			    uint64_t ring_size,
			    void __user *rptr_address,
			    void __user *wptr_address,
			    unsigned int doorbell);

	void (*destroy_queue)(struct kfd_scheduler *, struct kfd_scheduler_queue *);

	bool (*interrupt_isr)(struct kfd_scheduler *, const void *ih_ring_entry);
	void (*interrupt_wq)(struct kfd_scheduler *, const void *ih_ring_entry);

	bool (*set_cache_policy)(struct kfd_scheduler *scheduler,
				 struct kfd_scheduler_process *process,
				 enum cache_policy default_policy,
				 enum cache_policy alternate_policy,
				 void __user *alternate_aperture_base,
				 uint64_t alternate_aperture_size);
};

extern const struct kfd_scheduler_class radeon_kfd_cik_static_scheduler_class;

#endif
