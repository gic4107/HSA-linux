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

#ifndef HW_POINTER_STORE_H_
#define HW_POINTER_STORE_H_

#include <linux/mutex.h>

/* Type that represents a HW doorbell slot. and read/write HW pointers */
typedef u32 qptr_t;

/* Hw Pointer Store */
enum hw_pointer_store_type {
	KFD_HW_POINTER_STORE_TYPE_RPTR = 0,
	KFD_HW_POINTER_STORE_TYPE_WPTR
};

struct hw_pointer_store_properties {
	qptr_t __user		*page_mapping;
	unsigned long		*page_address;
	unsigned long		offset;
};

int
hw_pointer_store_init(struct hw_pointer_store_properties *ptr,
		enum hw_pointer_store_type type);

void
hw_pointer_store_destroy(struct hw_pointer_store_properties *ptr);

qptr_t __user *
hw_pointer_store_create_queue(struct hw_pointer_store_properties *ptr,
		unsigned int queue_id, struct file *devkfd);

unsigned long *
hw_pointer_store_get_address(struct hw_pointer_store_properties *ptr,
		unsigned int queue_id);

int
radeon_kfd_hw_pointer_store_mmap(struct hw_pointer_store_properties *ptr,
		struct vm_area_struct *vma);


#endif /* HW_POINTER_STORE_H_ */
