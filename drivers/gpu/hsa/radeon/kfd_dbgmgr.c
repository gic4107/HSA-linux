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
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/device.h>

#include "kfd_priv.h"
#include "cik_regs.h"
#include "kfd_pm4_headers.h"
#include "kfd_pm4_headers_diq.h"
#include "kfd_dbgmgr.h"
#include "kfd_dbgdev.h"

static DEFINE_MUTEX(kfd_dbgmgr_mutex);

struct mutex *
get_dbgmgr_mutex(void)
{
	return &kfd_dbgmgr_mutex;
}

/*===========================================================================*/

static void
kfd_dbgmgr_uninitialize(struct kfd_dbgmgr *pmgr)
{
	kfree(pmgr->dbgdev);
	pmgr->dbgdev = NULL;
	pmgr->pasid = 0;
	pmgr->dev = NULL;
}

/*===========================================================================*/

void
kfd_dbgmgr_destroy(struct kfd_dbgmgr *pmgr)
{
	if (pmgr != NULL) {
		kfd_dbgmgr_uninitialize(pmgr);
		kfree(pmgr);
		pmgr = NULL;
	}
}

/*===========================================================================*/

bool
kfd_dbgmgr_create(struct kfd_dbgmgr **ppmgr, struct kfd_dev *pdev)
{
	DBGDEV_TYPE  type = DBGDEV_TYPE_DIQ;
	struct kfd_dbgmgr *new_buff;

	BUG_ON(pdev == NULL);
	BUG_ON(!pdev->init_complete);

	new_buff = kfd_alloc_struct(new_buff);
	if (!new_buff)
	{
		dev_err(NULL, "Error! kfd: In func %s >> failed to allocate dbgmgr instance\n", __func__);
		return false;
	}

	new_buff->pasid = 0;
	new_buff->dev = pdev;
	new_buff->dbgdev = kfd_alloc_struct(new_buff->dbgdev);
	if (!new_buff->dbgdev) {
		dev_err(NULL, "Error! kfd: In func %s >> failed to allocate dbgdev\n", __func__);
		kfree(new_buff);
		return false;
	}

	/* get actual type of DBGDevice cpsch or not */
	if (sched_policy == KFD_SCHED_POLICY_NO_HWS)
		type = DBGDEV_TYPE_NODIQ;

	kfd_dbgdev_init(new_buff->dbgdev, pdev, type);
	*ppmgr = new_buff;

	return true;
}

/*===========================================================================*/

long
kfd_dbgmgr_register(struct kfd_dbgmgr *pmgr, struct kfd_process *p)
{
	long status = 0;

	do {

		if ((pmgr == NULL) || (pmgr->dev == NULL) || (pmgr->dbgdev == NULL)) {
			dev_info(NULL, "Error! kfd: In func %s >> Illegal pointers\n", __func__);
			/*  Invalid Pointer.  */
			status = -EINVAL;
			break;
		}
		if (pmgr->pasid != 0) {
			/*  HW debugger is already active.  */
			status = -EBUSY;
			break;
		}

		/* remember pasid */

		pmgr->pasid = p->pasid;

		/* provide the pqm for diq generation */

		pmgr->dbgdev->pqm = &p->pqm;

		/* activate the actual registering */
		/* todo: you should lock with the process mutex here */
		pmgr->dbgdev->dbgdev_register(pmgr->dbgdev);
		/* todo: you should unlock with the process mutex here  */

	} while (false);

	return status;
}

/* ========================================================================== */

long
kfd_dbgmgr_unregister(struct kfd_dbgmgr *pmgr, struct kfd_process *p)
{

	long status = 0;

	do {

		if ((pmgr == NULL) || (pmgr->dev == NULL) || (pmgr->dbgdev == NULL)) {
			dev_info(NULL, "Error! kfd: In func %s >> Illegal pointers\n", __func__);
			/* Invalid Pointer */
			status = -EINVAL;
			break;
		}
		if (pmgr->pasid != p->pasid) {
			/* Is the requests coming from the already registered process? */
			status = -EINVAL;
			break;
		}

		/* todo: you should lock with the process mutex here */

		pmgr->dbgdev->dbgdev_unregister(pmgr->dbgdev);

		/* todo: you should unlock with the process mutex here  */

		pmgr->pasid = 0;

	} while (false);

	return status;
}

/* =========================================================================== */

long
kfd_dbgmgr_wave_control(struct kfd_dbgmgr *pmgr, struct dbg_wave_control_info *wac_info)
{
	long status = 0;

	dev_info(NULL, "kfd: In func %s\n", __func__);

	do {

		if ((pmgr == NULL) || (pmgr->dev == NULL) || (pmgr->dbgdev == NULL) || (wac_info == NULL)
		    || (wac_info->process == NULL)) {
			/* Invalid Pointer */
			dev_info(NULL, "Error! kfd: In func %s >> Illegal pointers\n", __func__);
			status = -EINVAL;
			break;
		}
		/* Is the requests coming from the already registered process? */
		if (pmgr->pasid != wac_info->process->pasid) {
			/* HW debugger support was not registered for requester process */
			status = -EINVAL;
			break;
		}

		status = (long) pmgr->dbgdev->dbgdev_wave_control(pmgr->dbgdev, wac_info);

	} while (false);

	return status;

}

/* =========================================================================== */

long
kfd_dbgmgr_address_watch(struct kfd_dbgmgr *pmgr, struct dbg_address_watch_info *adw_info)
{
	long status = 0;

	dev_info(NULL, "kfd: In func %s\n", __func__);

	do {

		if ((pmgr == NULL) || (pmgr->dev == NULL) || (pmgr->dbgdev == NULL) || (adw_info == NULL)
		    || (adw_info->process == NULL)) {
			/* Invalid Pointer */
			dev_info(NULL, "Error! kfd: In func %s >> Illegal pointers\n", __func__);
			status = -EINVAL;
			break;
		}
		/* Is the requests coming from the already registered process? */
		if (pmgr->pasid != adw_info->process->pasid) {
			/* HW debugger support was not registered for requester process */
			status = -EINVAL;
			break;
		}

		status = (long) pmgr->dbgdev->dbgdev_address_watch(pmgr->dbgdev, adw_info);

	} while (false);

	return status;

}

/*///////////////////////////////////////////////////////////////////////////////////////// */
