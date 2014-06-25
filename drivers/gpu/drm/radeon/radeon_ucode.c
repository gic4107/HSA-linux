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

#include <linux/firmware.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <drm/drmP.h>
#include "radeon.h"
#include "radeon_ucode.h"

static void radeon_ucode_print_common_hdr(const struct common_firmware_header *hdr)
{
	DRM_DEBUG("size_bytes: %u\n", le32_to_cpu(hdr->size_bytes));
	DRM_DEBUG("header_size_bytes: %u\n", le32_to_cpu(hdr->header_size_bytes));
	DRM_DEBUG("header_version_major: %u\n", le16_to_cpu(hdr->header_version_major));
	DRM_DEBUG("header_version_minor: %u\n", le16_to_cpu(hdr->header_version_minor));
	DRM_DEBUG("ip_version_major: %u\n", le16_to_cpu(hdr->ip_version_major));
	DRM_DEBUG("ip_version_minor: %u\n", le16_to_cpu(hdr->ip_version_minor));
	DRM_DEBUG("crc32: 0x%08x\n", le32_to_cpu(hdr->crc32));

}

void radeon_ucode_print_mc_hdr(const struct mc_firmware_header_v1_0 *hdr)
{
	DRM_DEBUG("MC\n");
	radeon_ucode_print_common_hdr(&hdr->header);

	DRM_DEBUG("ucode_version: 0x%08x\n", le32_to_cpu(hdr->ucode_version));
	DRM_DEBUG("io_debug_size_bytes: %u\n", le32_to_cpu(hdr->io_debug_size_bytes));
	DRM_DEBUG("io_debug_array_offset_bytes: %u\n",
	       le32_to_cpu(hdr->io_debug_array_offset_bytes));
	DRM_DEBUG("ucode_size_bytes: %u\n", le32_to_cpu(hdr->ucode_size_bytes));
	DRM_DEBUG("ucode_array_offset_bytes: %u\n",
	       le32_to_cpu(hdr->ucode_array_offset_bytes));
}

void radeon_ucode_print_smc_hdr(const struct smc_firmware_header_v1_0 *hdr)
{
	DRM_DEBUG("SMC\n");
	radeon_ucode_print_common_hdr(&hdr->header);

	DRM_DEBUG("ucode_version: %u\n", le32_to_cpu(hdr->ucode_version));
	DRM_DEBUG("ucode_start_addr: %u\n", le32_to_cpu(hdr->ucode_start_addr));
	DRM_DEBUG("ucode_size_bytes: %u\n", le32_to_cpu(hdr->ucode_size_bytes));
	DRM_DEBUG("ucode_array_offset_bytes: %u\n",
	       le32_to_cpu(hdr->ucode_array_offset_bytes));
}

void radeon_ucode_print_me_hdr(const struct me_firmware_header_v1_0 *hdr)
{
	DRM_DEBUG("ME\n");
	radeon_ucode_print_common_hdr(&hdr->header);

	DRM_DEBUG("ucode_version: %u\n", le32_to_cpu(hdr->ucode_version));
	DRM_DEBUG("ucode_feature_version: %u\n", le32_to_cpu(hdr->ucode_feature_version));
	DRM_DEBUG("ucode_size_bytes: %u\n", le32_to_cpu(hdr->ucode_size_bytes));
	DRM_DEBUG("jt_offset: %u\n", le32_to_cpu(hdr->jt_offset));
	DRM_DEBUG("jt_size: %u\n", le32_to_cpu(hdr->jt_size));
	DRM_DEBUG("ucode_array_offset_bytes: %u\n",
	       le32_to_cpu(hdr->ucode_array_offset_bytes));
}

void radeon_ucode_print_pfp_hdr(const struct pfp_firmware_header_v1_0 *hdr)
{
	DRM_DEBUG("PFP\n");
	radeon_ucode_print_common_hdr(&hdr->header);

	DRM_DEBUG("ucode_version: %u\n", le32_to_cpu(hdr->ucode_version));
	DRM_DEBUG("ucode_feature_version: %u\n", le32_to_cpu(hdr->ucode_feature_version));
	DRM_DEBUG("ucode_size_bytes: %u\n", le32_to_cpu(hdr->ucode_size_bytes));
	DRM_DEBUG("jt_offset: %u\n", le32_to_cpu(hdr->jt_offset));
	DRM_DEBUG("jt_size: %u\n", le32_to_cpu(hdr->jt_size));
	DRM_DEBUG("ucode_array_offset_bytes: %u\n",
	       le32_to_cpu(hdr->ucode_array_offset_bytes));
}

void radeon_ucode_print_ce_hdr(const struct ce_firmware_header_v1_0 *hdr)
{
	DRM_DEBUG("CE\n");
	radeon_ucode_print_common_hdr(&hdr->header);

	DRM_DEBUG("ucode_version: %u\n", le32_to_cpu(hdr->ucode_version));
	DRM_DEBUG("ucode_feature_version: %u\n", le32_to_cpu(hdr->ucode_feature_version));
	DRM_DEBUG("ucode_size_bytes: %u\n", le32_to_cpu(hdr->ucode_size_bytes));
	DRM_DEBUG("jt_offset: %u\n", le32_to_cpu(hdr->jt_offset));
	DRM_DEBUG("jt_size: %u\n", le32_to_cpu(hdr->jt_size));
	DRM_DEBUG("ucode_array_offset_bytes: %u\n",
	       le32_to_cpu(hdr->ucode_array_offset_bytes));
}

void radeon_ucode_print_mec_hdr(const struct mec_firmware_header_v1_0 *hdr)
{
	DRM_DEBUG("MEC\n");
	radeon_ucode_print_common_hdr(&hdr->header);

	DRM_DEBUG("ucode_version: %u\n", le32_to_cpu(hdr->ucode_version));
	DRM_DEBUG("ucode_feature_version: %u\n", le32_to_cpu(hdr->ucode_feature_version));
	DRM_DEBUG("ucode_size_bytes: %u\n", le32_to_cpu(hdr->ucode_size_bytes));
	DRM_DEBUG("jt_offset: %u\n", le32_to_cpu(hdr->jt_offset));
	DRM_DEBUG("jt_size: %u\n", le32_to_cpu(hdr->jt_size));
	DRM_DEBUG("ucode_array_offset_bytes: %u\n",
	       le32_to_cpu(hdr->ucode_array_offset_bytes));
}

void radeon_ucode_print_rlc_hdr(const struct rlc_firmware_header_v1_0 *hdr)
{
	DRM_DEBUG("RLC\n");
	radeon_ucode_print_common_hdr(&hdr->header);

	DRM_DEBUG("ucode_version: %u\n", le32_to_cpu(hdr->ucode_version));
	DRM_DEBUG("ucode_feature_version: %u\n", le32_to_cpu(hdr->ucode_feature_version));
	DRM_DEBUG("ucode_size_bytes: %u\n", le32_to_cpu(hdr->ucode_size_bytes));
	DRM_DEBUG("save_and_restore_offset: %u\n",
	       le32_to_cpu(hdr->save_and_restore_offset));
	DRM_DEBUG("clear_state_descriptor_offset: %u\n",
	       le32_to_cpu(hdr->clear_state_descriptor_offset));
	DRM_DEBUG("avail_scratch_ram_locations: %u\n",
	       le32_to_cpu(hdr->avail_scratch_ram_locations));
	DRM_DEBUG("master_pkt_description_offset: %u\n",
	       le32_to_cpu(hdr->master_pkt_description_offset));
	DRM_DEBUG("ucode_array_offset_bytes: %u\n",
	       le32_to_cpu(hdr->ucode_array_offset_bytes));
}

void radeon_ucode_print_sdma_hdr(const struct sdma_firmware_header_v1_0 *hdr)
{
	DRM_DEBUG("SDMA\n");
	radeon_ucode_print_common_hdr(&hdr->header);

	DRM_DEBUG("ucode_version: %u\n", le32_to_cpu(hdr->ucode_version));
	DRM_DEBUG("ucode_feature_version: %u\n", le32_to_cpu(hdr->ucode_feature_version));
	DRM_DEBUG("ucode_size_bytes: %u\n", le32_to_cpu(hdr->ucode_size_bytes));
	DRM_DEBUG("jt_offset: %u\n", le32_to_cpu(hdr->jt_offset));
	DRM_DEBUG("jt_size: %u\n", le32_to_cpu(hdr->jt_size));
	DRM_DEBUG("ucode_array_offset_bytes: %u\n",
	       le32_to_cpu(hdr->ucode_array_offset_bytes));
}

void radeon_ucode_print_uvd_hdr(const struct uvd_firmware_header_v1_0 *hdr)
{
	DRM_DEBUG("UVD\n");
	radeon_ucode_print_common_hdr(&hdr->header);

	DRM_DEBUG("ucode_version: %u\n", le32_to_cpu(hdr->ucode_version));
	DRM_DEBUG("ucode_feature_version: %u\n", le32_to_cpu(hdr->ucode_feature_version));
	DRM_DEBUG("ucode_size_bytes: %u\n", le32_to_cpu(hdr->ucode_size_bytes));
	DRM_DEBUG("ucode_array_offset_bytes: %u\n",
	       le32_to_cpu(hdr->ucode_array_offset_bytes));
}

void radeon_ucode_print_vce_hdr(const struct uvd_firmware_header_v1_0 *hdr)
{
	DRM_DEBUG("VCE\n");
	radeon_ucode_print_common_hdr(&hdr->header);

	DRM_DEBUG("ucode_version: %u\n", le32_to_cpu(hdr->ucode_version));
	DRM_DEBUG("ucode_feature_version: %u\n", le32_to_cpu(hdr->ucode_feature_version));
	DRM_DEBUG("ucode_size_bytes: %u\n", le32_to_cpu(hdr->ucode_size_bytes));
	DRM_DEBUG("ucode_array_offset_bytes: %u\n",
	       le32_to_cpu(hdr->ucode_array_offset_bytes));
}

int radeon_ucode_validate(const struct firmware *fw)
{
	const struct common_firmware_header *hdr =
		(const struct common_firmware_header *)fw->data;

	if (fw->size == le32_to_cpu(hdr->size_bytes))
		return 0;

	return -EINVAL;
}

