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

#include <linux/io.h>
#include "kfd_priv.h"

/* In KFD, "reg" is the byte offset of the register. */
static void __iomem *reg_address(struct kfd_dev *dev, uint32_t reg)
{
	return dev->regs + reg;
}

void radeon_kfd_write_reg(struct kfd_dev *dev, uint32_t reg, uint32_t value)
{
	writel(value, reg_address(dev, reg));
}

uint32_t radeon_kfd_read_reg(struct kfd_dev *dev, uint32_t reg)
{
	return readl(reg_address(dev, reg));
}

void radeon_kfd_lock_srbm_index(struct kfd_dev *dev)
{
	kfd2kgd->lock_srbm_gfx_cntl(dev->kgd);
}

void radeon_kfd_unlock_srbm_index(struct kfd_dev *dev)
{
	kfd2kgd->unlock_srbm_gfx_cntl(dev->kgd);
}
