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

#ifndef MQD_MANAGER_H_
#define MQD_MANAGER_H_

#include "kfd_priv.h"

struct mqd_manager {
	int	(*init_mqd)(struct mqd_manager *mm, void **mqd, kfd_mem_obj *mqd_mem_obj, uint64_t *gart_addr,
			    struct queue_properties *q);
	int	(*load_mqd)(struct mqd_manager *mm, void *mqd);
	int	(*update_mqd)(struct mqd_manager *mm, void *mqd, struct queue_properties *q);
	int	(*destroy_mqd)(struct mqd_manager *mm, void *mqd, enum kfd_preempt_type type, unsigned int timeout);
	void	(*uninit_mqd)(struct mqd_manager *mm, void *mqd, kfd_mem_obj mqd_mem_obj);
	void	(*acquire_hqd)(struct mqd_manager *mm, unsigned int pipe, unsigned int queue, unsigned int vmid);
	void	(*release_hqd)(struct mqd_manager *mm);
	bool	(*is_occupied)(struct mqd_manager *mm, void *mqd, struct queue_properties *q);
	int	(*initialize)(struct mqd_manager *mm);
	void	(*uninitialize)(struct mqd_manager *mm);

	struct mutex		mqd_mutex;
	struct kfd_dev		*dev;
};


#endif /* MQD_MANAGER_H_ */
