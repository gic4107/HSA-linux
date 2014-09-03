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
#include <linux/radeon_kfd.h>
#include <linux/device.h>

void radeon_flush_tlb(struct kfd_dev *dev, pasid_t pasid)
{
	uint8_t vmid;
	int first_vmid_to_scan = 8;
	int last_vmid_to_scan = 15;

	/* Scan all registers in the range ATC_VMID8_PASID_MAPPING .. ATC_VMID15_PASID_MAPPING
	 * to check which VMID the current process is mapped to
	 * and flush TLB for this VMID if found*/
	for (vmid = first_vmid_to_scan; vmid <= last_vmid_to_scan; vmid++) {
		if (kfd2kgd->read_atc_vmid_pasid_mapping_reg_valid_field(dev->kgd, vmid)) {
			if (kfd2kgd->read_atc_vmid_pasid_mapping_reg_pasid_field(dev->kgd, vmid) == pasid) {
				dev_dbg(kfd_device, "TLB of vmid %u", vmid);
				kfd2kgd->write_vmid_invalidate_request(dev->kgd, vmid);
				break;
			}
		}
	}
}
