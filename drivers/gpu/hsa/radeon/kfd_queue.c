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

#include <linux/slab.h>
#include "kfd_priv.h"

void print_queue_properties(struct queue_properties *q)
{
	if (!q)
		return;

	pr_debug("Printing queue properties\n"
			"Queue Type: %u\n"
			"Queue Size: %llu\n"
			"Queue percent: %u\n"
			"Queue Address: 0x%llX\n"
			"Queue Id: %u\n"
			"Queue Process Vmid: %u\n"
			"Queue Read Pointer: 0x%p\n"
			"Queue Write Pointer: 0x%p\n"
			"Queue Doorbell Pointer: 0x%p\n"
			"Queue Doorbell Offset: %u\n",  q->type,
							q->queue_size,
							q->queue_percent,
							q->queue_address,
							q->queue_id,
							q->vmid,
							q->read_ptr,
							q->write_ptr,
							q->doorbell_ptr,
							q->doorbell_off);
}

void print_queue(struct queue *q)
{
	if (!q)
		return;
	pr_debug("Printing queue\n"
			"Queue Type: %u\n"
			"Queue Size: %llu\n"
			"Queue percent: %u\n"
			"Queue Address: 0x%llX\n"
			"Queue Id: %u\n"
			"Queue Process Vmid: %u\n"
			"Queue Read Pointer: 0x%p\n"
			"Queue Write Pointer: 0x%p\n"
			"Queue Doorbell Pointer: 0x%p\n"
			"Queue Doorbell Offset: %u\n"
			"Queue MQD Address: 0x%p\n"
			"Queue MQD Gart: 0x%llX\n"
			"Queue Process Address: 0x%p\n"
			"Queue Device Address: 0x%p\n",
			q->properties.type,
			q->properties.queue_size,
			q->properties.queue_percent,
			q->properties.queue_address,
			q->properties.queue_id,
			q->properties.vmid,
			q->properties.read_ptr,
			q->properties.write_ptr,
			q->properties.doorbell_ptr,
			q->properties.doorbell_off,
			q->mqd,
			q->gart_mqd_addr,
			q->process,
			q->device);
}

int init_queue(struct queue **q, struct queue_properties properties)
{
	struct queue *tmp;
	BUG_ON(!q);

	tmp = kzalloc(sizeof(struct queue), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	memset(&tmp->properties, 0, sizeof(struct queue_properties));
	memcpy(&tmp->properties, &properties, sizeof(struct queue_properties));

	*q = tmp;
	return 0;
}

void uninit_queue(struct queue *q)
{
	kfree(q);
}
