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
 * Author: Andrew Lewycky
 */

#include <linux/slab.h>
#include <linux/types.h>
#include "kfd_priv.h"

#define INITIAL_PASID_LIMIT (1<<20)

static unsigned long *pasid_bitmap;
static pasid_t pasid_limit;
static DEFINE_MUTEX(pasid_mutex);

int radeon_kfd_pasid_init(void)
{
	pasid_limit = INITIAL_PASID_LIMIT;

	pasid_bitmap = kzalloc(DIV_ROUND_UP(INITIAL_PASID_LIMIT, BITS_PER_BYTE), GFP_KERNEL);
	if (!pasid_bitmap)
		return -ENOMEM;

	set_bit(0, pasid_bitmap); /* PASID 0 is reserved. */

	return 0;
}

void radeon_kfd_pasid_exit(void)
{
	kfree(pasid_bitmap);
}

bool radeon_kfd_set_pasid_limit(pasid_t new_limit)
{
	if (new_limit < pasid_limit) {
		bool ok;

		mutex_lock(&pasid_mutex);

		/* ensure that no pasids >= new_limit are in-use */
		ok = (find_next_bit(pasid_bitmap, pasid_limit, new_limit) == pasid_limit);
		if (ok)
			pasid_limit = new_limit;

		mutex_unlock(&pasid_mutex);

		return ok;
	} else {
		return true;
	}
}

inline pasid_t radeon_kfd_get_pasid_limit(void)
{
	return pasid_limit;
}

pasid_t radeon_kfd_pasid_alloc(void)
{
	pasid_t found;

	mutex_lock(&pasid_mutex);

	found = find_first_zero_bit(pasid_bitmap, pasid_limit);
	if (found == pasid_limit)
		found = 0;
	else
		set_bit(found, pasid_bitmap);

	mutex_unlock(&pasid_mutex);

	return found;
}

void radeon_kfd_pasid_free(pasid_t pasid)
{
	BUG_ON(pasid == 0 || pasid >= pasid_limit);
	clear_bit(pasid, pasid_bitmap);
}
