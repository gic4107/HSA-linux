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
 * Authors: Andrew Lewycky
 *          Oded Gabbay
 */

#include <linux/amd-iommu.h>
#include <linux/bsearch.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include "kfd_priv.h"
#include "kfd_scheduler.h"

static const struct kfd_device_info kaveri_device_info = {
	.scheduler_class = &radeon_kfd_cik_static_scheduler_class,
	.max_pasid_bits = 16,
	.ih_ring_entry_size = 4 * sizeof(uint32_t)
};

struct kfd_deviceid {
	unsigned short did;
	const struct kfd_device_info *device_info;
};

/* Please keep this sorted by increasing device id. */
static const struct kfd_deviceid supported_devices[] = {
	{ 0x1304, &kaveri_device_info },	/* Kaveri */
	{ 0x1305, &kaveri_device_info },	/* Kaveri */
	{ 0x1306, &kaveri_device_info },	/* Kaveri */
	{ 0x1307, &kaveri_device_info },	/* Kaveri */
	{ 0x1309, &kaveri_device_info },	/* Kaveri */
	{ 0x130A, &kaveri_device_info },	/* Kaveri */
	{ 0x130B, &kaveri_device_info },	/* Kaveri */
	{ 0x130C, &kaveri_device_info },	/* Kaveri */
	{ 0x130D, &kaveri_device_info },	/* Kaveri */
	{ 0x130E, &kaveri_device_info },	/* Kaveri */
	{ 0x130F, &kaveri_device_info },	/* Kaveri */
	{ 0x1310, &kaveri_device_info },	/* Kaveri */
	{ 0x1311, &kaveri_device_info },	/* Kaveri */
	{ 0x1312, &kaveri_device_info },	/* Kaveri */
	{ 0x1313, &kaveri_device_info },	/* Kaveri */
	{ 0x1315, &kaveri_device_info },	/* Kaveri */
	{ 0x1316, &kaveri_device_info },	/* Kaveri */
	{ 0x1317, &kaveri_device_info },	/* Kaveri */
	{ 0x1318, &kaveri_device_info },	/* Kaveri */
	{ 0x131B, &kaveri_device_info },	/* Kaveri */
	{ 0x131C, &kaveri_device_info },	/* Kaveri */
	{ 0x131D, &kaveri_device_info },	/* Kaveri */
};

static const struct kfd_device_info *
lookup_device_info(unsigned short did)
{
	size_t i;
	for (i = 0; i < ARRAY_SIZE(supported_devices); i++) {
		if (supported_devices[i].did == did) {
			BUG_ON(supported_devices[i].device_info == NULL);
			return supported_devices[i].device_info;
		}
	}

	return NULL;
}

struct kfd_dev *kgd2kfd_probe(struct kgd_dev *kgd, struct pci_dev *pdev)
{
	struct kfd_dev *kfd;

	const struct kfd_device_info *device_info = lookup_device_info(pdev->device);

	if (!device_info)
		return NULL;

	kfd = kzalloc(sizeof(*kfd), GFP_KERNEL);
	kfd->kgd = kgd;
	kfd->device_info = device_info;
	kfd->pdev = pdev;

	return kfd;
}

static bool
device_iommu_pasid_init(struct kfd_dev *kfd)
{
	const u32 required_iommu_flags = AMD_IOMMU_DEVICE_FLAG_ATS_SUP | AMD_IOMMU_DEVICE_FLAG_PRI_SUP
					| AMD_IOMMU_DEVICE_FLAG_PASID_SUP;

	struct amd_iommu_device_info iommu_info;
	pasid_t pasid_limit;
	int err;

	err = amd_iommu_device_info(kfd->pdev, &iommu_info);
	if (err < 0)
		return false;

	if ((iommu_info.flags & required_iommu_flags) != required_iommu_flags)
		return false;

	pasid_limit = min_t(pasid_t, (pasid_t)1 << kfd->device_info->max_pasid_bits, iommu_info.max_pasids);
	pasid_limit = min_t(pasid_t, pasid_limit, kfd->doorbell_process_limit);

	err = amd_iommu_init_device(kfd->pdev, pasid_limit);
	if (err < 0)
		return false;

	if (!radeon_kfd_set_pasid_limit(pasid_limit)) {
		amd_iommu_free_device(kfd->pdev);
		return false;
	}

	return true;
}

static void iommu_pasid_shutdown_callback(struct pci_dev *pdev, int pasid)
{
	struct kfd_dev *dev = radeon_kfd_device_by_pci_dev(pdev);
	if (dev)
		radeon_kfd_unbind_process_from_device(dev, pasid);
}

bool kgd2kfd_device_init(struct kfd_dev *kfd,
			 const struct kgd2kfd_shared_resources *gpu_resources)
{
	kfd->shared_resources = *gpu_resources;

	kfd->regs = gpu_resources->mmio_registers;

	radeon_kfd_doorbell_init(kfd);

	if (radeon_kfd_interrupt_init(kfd))
		return false;

	if (!device_iommu_pasid_init(kfd))
		return false;

	if (kfd_topology_add_device(kfd) != 0) {
		amd_iommu_free_device(kfd->pdev);
		return false;
	}

	amd_iommu_set_invalidate_ctx_cb(kfd->pdev, iommu_pasid_shutdown_callback);

	if (kfd->device_info->scheduler_class->create(kfd, &kfd->scheduler)) {		// assign kfd->scheduler
		amd_iommu_free_device(kfd->pdev);
		return false;
	}

	kfd->device_info->scheduler_class->start(kfd->scheduler);

	kfd->init_complete = true;

	return true;
}

void kgd2kfd_device_exit(struct kfd_dev *kfd)
{
	int err = kfd_topology_remove_device(kfd);
	BUG_ON(err != 0);

	if (kfd->init_complete)
		kfd->device_info->scheduler_class->stop(kfd->scheduler);

	radeon_kfd_interrupt_exit(kfd);

	if (kfd->init_complete) {
		kfd->device_info->scheduler_class->destroy(kfd->scheduler);
		amd_iommu_free_device(kfd->pdev);
	}

	kfree(kfd);
}

void kgd2kfd_suspend(struct kfd_dev *kfd)
{
	BUG_ON(kfd == NULL);

	if (kfd->init_complete) {
		kfd->device_info->scheduler_class->stop(kfd->scheduler);
		amd_iommu_free_device(kfd->pdev);
	}
}

int kgd2kfd_resume(struct kfd_dev *kfd)
{
	pasid_t pasid_limit;
	int err;
	BUG_ON(kfd == NULL);

	pasid_limit = radeon_kfd_get_pasid_limit();

	if (kfd->init_complete) {
		err = amd_iommu_init_device(kfd->pdev, pasid_limit);
		if (err < 0)
			return -ENXIO;
		amd_iommu_set_invalidate_ctx_cb(kfd->pdev, iommu_pasid_shutdown_callback);
		kfd->device_info->scheduler_class->start(kfd->scheduler);
	}

	return 0;
}
