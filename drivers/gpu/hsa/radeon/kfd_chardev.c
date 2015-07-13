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

#define DEBUG

#include <linux/device.h>
#include <linux/export.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/compat.h>
#include <uapi/linux/kfd_ioctl.h>
#include <linux/time.h>
#include "kfd_priv.h"
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <uapi/asm-generic/mman-common.h>
#include <asm/processor.h>
#include "kfd_device_queue_manager.h"
#include "kfd_dbgmgr.h"
#include "cik_regs.h"
#include <linux/kvm_host.h>     // kvm for translate mqd
// FIXME: Debug
#include <linux/highmem.h>
#include <asm/pgtable_types.h>
extern u32 __iomem *pasid1_doorbell_kernel_ptr;
extern u32 __iomem *pasid2_doorbell_kernel_ptr;
uint64_t in_buf;
uint64_t out_buf;

// FIXME: mqd identical mapping
#ifdef IDENTICAL_MAPPING
struct identical_mapping_info identical_mapping;
#endif

#ifdef CONFIG_HSA_VIRTUALIZATION
#include <asm/kvm_host.h>
extern struct list_head vm_info_list;
#endif

static long kfd_ioctl(struct file *, unsigned int, unsigned long);
static int kfd_open(struct inode *, struct file *);
static int kfd_mmap(struct file *, struct vm_area_struct *);

static const char kfd_dev_name[] = "kfd";

static const struct file_operations kfd_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = kfd_ioctl,
	.compat_ioctl = kfd_ioctl,
	.open = kfd_open,
	.mmap = kfd_mmap,
};

static int kfd_char_dev_major = -1;
static struct class *kfd_class;
struct device *kfd_device;

int
radeon_kfd_chardev_init(void)
{
	int err = 0;

	kfd_char_dev_major = register_chrdev(0, kfd_dev_name, &kfd_fops);
	err = kfd_char_dev_major;
	if (err < 0)
		goto err_register_chrdev;

	kfd_class = class_create(THIS_MODULE, kfd_dev_name);
	err = PTR_ERR(kfd_class);
	if (IS_ERR(kfd_class))
		goto err_class_create;

	kfd_device = device_create(kfd_class, NULL, MKDEV(kfd_char_dev_major, 0), NULL, kfd_dev_name);
	err = PTR_ERR(kfd_device);
	if (IS_ERR(kfd_device))
		goto err_device_create;

	return 0;

err_device_create:
	class_destroy(kfd_class);
err_class_create:
	unregister_chrdev(kfd_char_dev_major, kfd_dev_name);
err_register_chrdev:
	return err;
}

void
radeon_kfd_chardev_exit(void)
{
	device_destroy(kfd_class, MKDEV(kfd_char_dev_major, 0));
	class_destroy(kfd_class);
	unregister_chrdev(kfd_char_dev_major, kfd_dev_name);
}

struct device*
radeon_kfd_chardev(void)
{
	return kfd_device;
}


static int
kfd_open(struct inode *inode, struct file *filep)
{
	struct kfd_process *process;

	if (iminor(inode) != 0)
		return -ENODEV;

    printk("host kfd open\n");
	process = radeon_kfd_create_process(current);
	if (IS_ERR(process))
		return PTR_ERR(process);

	process->is_32bit_user_mode = is_compat_task();

	dev_dbg(kfd_device, "process %d opened, compat mode (32 bit) - %d\n",
		process->pasid, process->is_32bit_user_mode);

	kfd_init_apertures(process);

	return 0;
}

static int
set_queue_properties_from_user(struct queue_properties *q_properties, struct kfd_ioctl_create_queue_args *args)
{
	q_properties->is_interop = false;
	q_properties->queue_percent = args->queue_percentage;
	q_properties->priority = args->queue_priority;
	q_properties->queue_address = args->ring_base_address;
	q_properties->queue_size = args->ring_size;
	q_properties->read_ptr = (qptr_t *) args->read_pointer_address;
	q_properties->write_ptr = (qptr_t *) args->write_pointer_address;
	if (args->queue_type == KFD_IOC_QUEUE_TYPE_COMPUTE ||
		args->queue_type == KFD_IOC_QUEUE_TYPE_COMPUTE_AQL)
		q_properties->type = KFD_QUEUE_TYPE_COMPUTE;
	else if (args->queue_type == KFD_IOC_QUEUE_TYPE_SDMA)
		q_properties->type = KFD_QUEUE_TYPE_SDMA;
	else
		return -ENOTSUPP;
	if (args->queue_type == KFD_IOC_QUEUE_TYPE_COMPUTE_AQL)
		q_properties->format = KFD_QUEUE_FORMAT_AQL;
	else
		q_properties->format = KFD_QUEUE_FORMAT_PM4;

	pr_debug("%s Arguments: Queue Percentage (%d, %d)\n"
			"Queue Priority (%d, %d)\n"
			"Queue Address (0x%llX, 0x%llX)\n"
			"Queue Size (0x%llX, %u)\n"
			"Queue r/w Pointers (0x%llX, 0x%llX)\n"
			"Queue Format (%d)\n",
			__func__,
			q_properties->queue_percent, args->queue_percentage,
			q_properties->priority, args->queue_priority,
			q_properties->queue_address, args->ring_base_address,
			q_properties->queue_size, args->ring_size,
			(uint64_t) q_properties->read_ptr,
			(uint64_t) q_properties->write_ptr,
			q_properties->format);

	return 0;
}

static long
kfd_ioctl_create_queue(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_create_queue_args args;
	struct kfd_dev *dev;
	int err = 0;
	unsigned int queue_id;
	struct kfd_process_device *pdd;
	struct queue_properties q_properties;

	memset(&q_properties, 0, sizeof(struct queue_properties));

  	if (copy_from_user(&args, arg, sizeof(args)))
   		return -EFAULT;

    printk("ring_base_address=0x%llx\n", args.ring_base_address);
    printk("write_pointer_address=0x%llx\n", args.write_pointer_address);
    printk("read_pointer_address=0x%llx\n", args.read_pointer_address);
    printk("ring_size=%d\n", args.ring_size);
    printk("gpu_id=%d\n", args.gpu_id);
    printk("queue_type=%d\n", args.queue_type);
    printk("queue_percentage=%d\n", args.queue_percentage);

	if (!access_ok(VERIFY_WRITE, args.read_pointer_address, sizeof(qptr_t))) {
		pr_err("kfd: can't access read pointer");
		return -EFAULT;
	}

	if (!access_ok(VERIFY_WRITE, args.write_pointer_address, sizeof(qptr_t))) {
		pr_err("kfd: can't access write pointer");
		return -EFAULT;
	}

	err = set_queue_properties_from_user(&q_properties, &args);
	if (err != 0)
		return -EINVAL;

	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (dev == NULL)
		return -EINVAL;

	mutex_lock(&p->mutex);

	pdd = radeon_kfd_bind_process_to_device(dev, p);
	if (IS_ERR(pdd) < 0) {
		err = PTR_ERR(pdd);
		goto err_bind_process;
	}

#ifdef CONFIG_HSA_VIRTUALIZATION
    if (p->process_type == KFD_PROCESS_TYPE_VM_PROCESS) {
        p->vm_info->dev = dev;
        printk("dev=%p, pdev=%p\n", dev, dev->pdev);
    }
#endif

	pr_debug("kfd: creating queue for PASID %d on GPU 0x%x\n",
			p->pasid,
			dev->id);

	err = pqm_create_queue(&p->pqm, dev, filep, &q_properties, 0, q_properties.type, &queue_id);
	if (err != 0)
		goto err_create_queue;

	args.queue_id = queue_id;
	args.doorbell_address = (uint64_t)q_properties.doorbell_ptr;

	if (copy_to_user(arg, &args, sizeof(args))) {
		err = -EFAULT;
		goto err_copy_args_out;
	}

	mutex_unlock(&p->mutex);

	printk("kfd: gpu id %d was created successfully.\n"
		 "     ring size         == 0x%X\n"
		 "     ring size         == %d\n"
		 "     queue type        == 0x%X\n"
		 "     queue percentage  == 0x%X\n"
		 "     queue priority    == 0x%X\n",
			args.gpu_id,
			args.ring_size,
			args.ring_size,
			args.queue_type,
			args.queue_percentage,
			args.queue_priority);

	pr_debug("kfd: queue id %d was created successfully.\n"
		 "     ring buffer address == 0x%016llX\n"
		 "     read ptr address    == 0x%016llX\n"
		 "     write ptr address   == 0x%016llX\n"
		 "     doorbell address    == 0x%016llX\n",
			args.queue_id,
			args.ring_base_address,
			args.read_pointer_address,
			args.write_pointer_address,
			args.doorbell_address);
	return 0;

err_copy_args_out:
	pqm_destroy_queue(&p->pqm, queue_id);
err_create_queue:
err_bind_process:
	mutex_unlock(&p->mutex);
	return err;
}

static int
kfd_ioctl_destroy_queue(struct file *filp, struct kfd_process *p, void __user *arg)
{
	int retval;
	struct kfd_ioctl_destroy_queue_args args;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	pr_debug("kfd: destroying queue id %d for PASID %d\n",
				args.queue_id,
				p->pasid);

	mutex_lock(&p->mutex);

	retval = pqm_destroy_queue(&p->pqm, args.queue_id);

	mutex_unlock(&p->mutex);
	return retval;
}

static int
kfd_ioctl_update_queue(struct file *filp, struct kfd_process *p, void __user *arg)
{
	int retval;
	struct kfd_ioctl_update_queue_args args;
	struct queue_properties properties;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	properties.queue_address = args.ring_base_address;
	properties.queue_size = args.ring_size;
	properties.queue_percent = args.queue_percentage;
	properties.priority = args.queue_priority;

	pr_debug("kfd: updating queue id %d for PASID %d\n", args.queue_id, p->pasid);

	mutex_lock(&p->mutex);

	retval = pqm_update_queue(&p->pqm, args.queue_id, &properties);

	mutex_unlock(&p->mutex);

	return retval;
}

static long
kfd_ioctl_set_memory_policy(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_set_memory_policy_args args;
	struct kfd_dev *dev;
	int err = 0;
	struct kfd_process_device *pdd;
	enum cache_policy default_policy, alternate_policy;

    printk("kfd_ioctl_set_memory_policy1\n");
	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	if (args.default_policy != KFD_IOC_CACHE_POLICY_COHERENT
	    && args.default_policy != KFD_IOC_CACHE_POLICY_NONCOHERENT) {
		return -EINVAL;
	}

	if (args.alternate_policy != KFD_IOC_CACHE_POLICY_COHERENT
	    && args.alternate_policy != KFD_IOC_CACHE_POLICY_NONCOHERENT) {
		return -EINVAL;
	}

    printk("kfd_ioctl_set_memory_policy2\n");
	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (dev == NULL)
		return -EINVAL;

	mutex_lock(&p->mutex);

    printk("kfd_ioctl_set_memory_policy3\n");
	pdd = radeon_kfd_bind_process_to_device(dev, p);
	if (IS_ERR(pdd) < 0) {
		err = PTR_ERR(pdd);
		goto out;
	}

    printk("alternate_paerture_base=%llx\n", args.alternate_aperture_base);
    printk("alternate_paerture_size=%llx\n", args.alternate_aperture_size);
    printk("default_policy=%d\n", args.default_policy); 
    printk("alternate_policy=%d\n", args.alternate_policy);

	default_policy = (args.default_policy == KFD_IOC_CACHE_POLICY_COHERENT)
			 ? cache_policy_coherent : cache_policy_noncoherent;

	alternate_policy = (args.alternate_policy == KFD_IOC_CACHE_POLICY_COHERENT)
			   ? cache_policy_coherent : cache_policy_noncoherent;

	if (!dev->dqm->set_cache_memory_policy(dev->dqm,
					 &pdd->qpd,
					 default_policy,
					 alternate_policy,
					 (void __user *)args.alternate_aperture_base,
					 args.alternate_aperture_size))
		err = -EINVAL;

    printk("kfd_ioctl_set_memory_policy done\n");
out:
	mutex_unlock(&p->mutex);

	return err;
}

static long
kfd_ioctl_dbg_register(struct file *filep, struct kfd_process *p, void __user *arg)
{
	long status = -EFAULT;
	struct kfd_ioctl_dbg_register_args args;
	struct kfd_dev *dev;
	struct kfd_dbgmgr *dbgmgr_ptr;
	struct kfd_process_device *pdd;
	bool create_ok = false;
	pr_debug("kfd:dbg: %s\n", __func__);
	if (copy_from_user(&args, arg, sizeof(args))) {
		dev_info(NULL, "Error! kfd: In func %s >> copy_from_user failed\n", __func__);
		return status;
	}

	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (!dev) {
		dev_info(NULL, "Error! kfd: In func %s >> getting device by id failed\n", __func__);
		return status;
	}
	mutex_lock(get_dbgmgr_mutex());
	mutex_lock(&p->mutex);

	/* make sure that we have pdd, if this the first queue created for this process */
	pdd = radeon_kfd_bind_process_to_device(dev, p);
	if (IS_ERR(pdd) < 0) {
		mutex_unlock(&p->mutex);
		mutex_unlock(get_dbgmgr_mutex());
		return PTR_ERR(pdd);
	}

	if (dev->dbgmgr == NULL) {
		/* In case of a legal call, we have no dbgmgr yet */

		create_ok = kfd_dbgmgr_create(&dbgmgr_ptr, dev);
		if (create_ok) {
			status = kfd_dbgmgr_register(dbgmgr_ptr, p);
			if (status != 0)
				kfd_dbgmgr_destroy(dbgmgr_ptr);
			else
				dev->dbgmgr = dbgmgr_ptr;
		}
	}
	mutex_unlock(&p->mutex);
	mutex_unlock(get_dbgmgr_mutex());

	return status;
}

/*
 * Unregister dbg IOCTL
 */

static long
kfd_ioctl_dbg_unrgesiter(struct file *filep, struct kfd_process *p, void __user *arg)
{
	long status = -EFAULT;
	struct kfd_ioctl_dbg_unregister_args args;
	struct kfd_dev *dev;

	if (copy_from_user(&args, arg, sizeof(args))) {
		dev_info(NULL, "Error! kfd: In func %s >> copy_from_user failed\n", __func__);
		return status;
	}
	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (!dev) {
		dev_info(NULL, "Error! kfd: In func %s >> getting device by id failed\n", __func__);
		return status;
	}
	mutex_lock(get_dbgmgr_mutex());

	status = kfd_dbgmgr_unregister(dev->dbgmgr, p);
	if (status == 0) {
		kfd_dbgmgr_destroy(dev->dbgmgr);
		dev->dbgmgr = NULL;
	}

	mutex_unlock(get_dbgmgr_mutex());

	return status;
}

/*
 * Parse and generate variable size data structure for address watch.
 * Total size of the buffer and # watch points is limited in order
 * to prevent kernel abuse. (no bearing to the much smaller HW limitation
 * which is enforced by dbgdev module.
 * please also note that the watch address itself are not "copied from user",
 * since it be set into the HW in user mode values.
 *
 */

static long
kfd_ioctl_dbg_address_watch(struct file *filep, struct kfd_process *p, void __user *arg)
{
	long status = -EFAULT;
	struct kfd_ioctl_dbg_address_watch_args args;
	struct kfd_dev *dev;
	struct dbg_address_watch_info aw_info = { 0 };
	unsigned char *args_buff = NULL;
	unsigned int args_idx = 0;
	uint64_t watch_mask_value = 0;

	do {
		/* first copy_from_user, only to get the buffer size */

		if (copy_from_user(&args, arg, sizeof(args))) {
			dev_info(NULL, "Error! kfd: In func %s >> copy_from_user failed\n", __func__);
			break;
		}

		dev = radeon_kfd_device_by_id(args.gpu_id);
		if (!dev) {
			dev_info(NULL, "Error! kfd: In func %s >> getting device by id failed\n", __func__);
			break;
		}

		if (args.buf_size_in_bytes > MAX_ALLOWED_AW_BUFF_SIZE) {
			status = -EINVAL;
			break;
		}

		/* this is the actual buffer to work with */

		args_buff = (unsigned char *) kzalloc(args.buf_size_in_bytes, GFP_KERNEL);

		if (args_buff == NULL) {
			status = -ENOMEM;
			break;
		}

		/* Now copy the entire buffer from user */

		if (copy_from_user(args_buff , arg, args.buf_size_in_bytes)) {
			dev_info(NULL, "Error! kfd: In func %s >> copy_from_user failed\n", __func__);
			break;
		}

		/* move ptr to the start of the "pay-load" area */

		args_idx = sizeof(args.gpu_id) + sizeof(args.buf_size_in_bytes);

		aw_info.process = p;

		aw_info.num_watch_points = *((uint32_t *)(&args_buff[args_idx]));
		args_idx += sizeof(aw_info.num_watch_points);

		aw_info.watch_mode = (HSA_DBG_WATCH_MODE *) &args_buff[args_idx];
		args_idx += sizeof(HSA_DBG_WATCH_MODE) * aw_info.num_watch_points;

		/* set watch address base pointer to point on the array base within args_buff */

		aw_info.watch_address = (uint64_t *) &args_buff[args_idx];

		/*skip over the addresses buffer */
		args_idx += sizeof(aw_info.watch_address) * aw_info.num_watch_points;

		if (args_idx >= args.buf_size_in_bytes) {
			status = -EINVAL;
			break;
		}

		watch_mask_value = (uint64_t) args_buff[args_idx];

		if (watch_mask_value > 0) {
			/* there is an array of masks */

			/* set watch mask base pointer to point on the array base within args_buff */
			aw_info.watch_mask = (uint64_t *) &args_buff[args_idx];

			/*skip over the masks buffer */
			args_idx += sizeof(aw_info.watch_mask) * aw_info.num_watch_points;
		}

		else
			/* just the NULL mask, set to NULL and skip over it */
		{
			aw_info.watch_mask = NULL;
			args_idx += sizeof(aw_info.watch_mask);
		}

		if (args_idx >= args.buf_size_in_bytes) {
			status = -EINVAL;
			break;
		}

		aw_info.watch_event = NULL;	/* Currently HSA Event is not supported for DBG */
		status = 0;

	} while (0);

	if (status == 0) {
		mutex_lock(get_dbgmgr_mutex());

		status = kfd_dbgmgr_address_watch(dev->dbgmgr, &aw_info);

		mutex_unlock(get_dbgmgr_mutex());

	}

	kfree(args_buff);

	return status;
}

/*
 * Parse and generate fixed size data structure for wave control.
 * Buffer is generated in a "packed" form, for avoiding structure packing/pending dependencies.
 */

static long
kfd_ioctl_dbg_wave_control(struct file *filep, struct kfd_process *p, void __user *arg)
{
	long status = -EFAULT;
	struct kfd_ioctl_dbg_wave_control_args args;
	struct kfd_dev *dev;
	struct dbg_wave_control_info wac_info = { 0 };
	unsigned char *args_buff = NULL;
	unsigned int args_idx = 0;

	/* we use compact form, independent of the packing attribute value */

	uint32_t computed_buff_size = sizeof(args) + sizeof(wac_info.mode) + sizeof(wac_info.operand) +
	    +sizeof(wac_info.dbgWave_msg.DbgWaveMsg) + sizeof(wac_info.dbgWave_msg.MemoryVA) + sizeof(wac_info.trapId);


	dev_info(NULL, "kfd: In func %s - start\n", __func__);

	do {

		if (copy_from_user(&args, arg, sizeof(args))) {
			/* first copy_from_user, only to get the buffer size */
			dev_info(NULL, "Error! kfd: In func %s >> copy_from_user failed\n", __func__);
			break;
		}
		dev = radeon_kfd_device_by_id(args.gpu_id);
		if (!dev) {
			dev_info(NULL, "Error! kfd: In func %s >> getting device by id failed\n", __func__);
			break;
		}

		/* input size must match the computed "compact" size */

		if (args.buf_size_in_bytes != computed_buff_size) {
			dev_info(NULL, "Error! kfd: In func %s >> size mismatch, computed : actual %u : %u\n",
					__func__, args.buf_size_in_bytes, computed_buff_size);
			status = -EINVAL;
			break;
		}

		/* this is the actual buffer to work with */

		args_buff = (unsigned char *) kzalloc(args.buf_size_in_bytes, GFP_KERNEL);

		if (args_buff == NULL) {
			status = -ENOMEM;
			break;
		}
		/* Now copy the entire buffer from user */

		if (copy_from_user(args_buff , arg, args.buf_size_in_bytes)) {
			dev_info(NULL, "Error! kfd: In func %s >> copy_from_user failed\n", __func__);
			break;
		}

		/* move ptr to the start of the "pay-load" area */

		args_idx = sizeof(args.gpu_id) + sizeof(args.buf_size_in_bytes);

		wac_info.process = p;

		wac_info.operand = (HSA_DBG_WAVEOP) *((HSA_DBG_WAVEOP *)(&args_buff[args_idx]));
		args_idx += sizeof(wac_info.operand);

		wac_info.mode = (HSA_DBG_WAVEMODE) *((HSA_DBG_WAVEMODE *)(&args_buff[args_idx]));
		args_idx += sizeof(wac_info.mode);

		wac_info.trapId = (uint32_t) *((uint32_t *)(&args_buff[args_idx]));
		args_idx += sizeof(wac_info.trapId);

		wac_info.dbgWave_msg.DbgWaveMsg.WaveMsgInfoGen2.Value = *((uint32_t *)(&args_buff[args_idx]));
		wac_info.dbgWave_msg.MemoryVA = NULL;


		status = 0;

	} while (0);
	if (status == 0) {
		mutex_lock(get_dbgmgr_mutex());

		dev_info(NULL,
				"kfd: In func %s >> calling dbg manager process %p, operand %u, mode %u, trapId %u, message %u\n",
				__func__, wac_info.process, wac_info.operand, wac_info.mode, wac_info.trapId,
				wac_info.dbgWave_msg.DbgWaveMsg.WaveMsgInfoGen2.Value);

		status = kfd_dbgmgr_wave_control(dev->dbgmgr, &wac_info);

		dev_info(NULL, "kfd: In func %s >> returned status of dbg manager is %ld\n", __func__, status);

		mutex_unlock(get_dbgmgr_mutex());

	}

	kfree(args_buff);

	return status;
}

static long
kfd_ioctl_get_clock_counters(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_get_clock_counters_args args;
	struct kfd_dev *dev;
	struct timespec time;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (dev == NULL)
		return -EINVAL;

	/* Reading GPU clock counter from KGD */
	args.gpu_clock_counter = kfd2kgd->get_gpu_clock_counter(dev->kgd);

	/* No access to rdtsc. Using raw monotonic time */
	getrawmonotonic(&time);
	args.cpu_clock_counter = (uint64_t)timespec_to_ns(&time);

	get_monotonic_boottime(&time);
	args.system_clock_counter = (uint64_t)timespec_to_ns(&time);

	/* Since the counter is in nano-seconds we use 1GHz frequency */
	args.system_clock_freq = 1000000000;

	if (copy_to_user(arg, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}


static int kfd_ioctl_get_process_apertures(struct file *filp, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_get_process_apertures_args args;
	struct kfd_process_device *pdd;

	dev_dbg(kfd_device, "get apertures for PASID %d", p->pasid);
    printk("args=%p, arg=%p, sizeof(args)=%d\n", args, arg, sizeof(args));

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	args.num_of_nodes = 0;

	mutex_lock(&p->mutex);

	/*if the process-device list isn't empty*/
	if (kfd_has_process_device_data(p)) {
		/* Run over all pdd of the process */
		pdd = kfd_get_first_process_device_data(p);
		do {

			args.process_apertures[args.num_of_nodes].gpu_id = pdd->dev->id;
			args.process_apertures[args.num_of_nodes].lds_base = pdd->lds_base;
			args.process_apertures[args.num_of_nodes].lds_limit = pdd->lds_limit;
			args.process_apertures[args.num_of_nodes].gpuvm_base = pdd->gpuvm_base;
			args.process_apertures[args.num_of_nodes].gpuvm_limit = pdd->gpuvm_limit;
			args.process_apertures[args.num_of_nodes].scratch_base = pdd->scratch_base;
			args.process_apertures[args.num_of_nodes].scratch_limit = pdd->scratch_limit;

			dev_dbg(kfd_device, "node id %u, gpu id %u, lds_base %llX lds_limit %llX gpuvm_base %llX gpuvm_limit %llX scratch_base %llX scratch_limit %llX",
					args.num_of_nodes, pdd->dev->id, pdd->lds_base, pdd->lds_limit, pdd->gpuvm_base, pdd->gpuvm_limit, pdd->scratch_base, pdd->scratch_limit);
			args.num_of_nodes++;
		} while ((pdd = kfd_get_next_process_device_data(p, pdd)) != NULL && (args.num_of_nodes < NUM_OF_SUPPORTED_GPUS));
	}

	mutex_unlock(&p->mutex);

	if (copy_to_user(arg, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static long
kfd_ioctl_pmc_acquire_access(struct file *filp, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_pmc_acquire_access_args args;
	struct kfd_dev *dev;
	int err = -EBUSY;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (dev == NULL)
		return -EINVAL;

	spin_lock(&dev->pmc_access_lock);
	if (dev->pmc_locking_process == NULL) {
		dev->pmc_locking_process = p;
		dev->pmc_locking_trace = args.trace_id;
		err = 0;
	} else if (dev->pmc_locking_process == p && dev->pmc_locking_trace == args.trace_id) {
		/* Same trace already has an access. Returning success */
		err = 0;
	}

	spin_unlock(&dev->pmc_access_lock);

	return err;
}

static long
kfd_ioctl_pmc_release_access(struct file *filp, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_pmc_release_access_args args;
	struct kfd_dev *dev;
	int err = -EINVAL;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (dev == NULL)
		return -EINVAL;

	spin_lock(&dev->pmc_access_lock);
	if (dev->pmc_locking_process == p && dev->pmc_locking_trace == args.trace_id) {
		dev->pmc_locking_process = NULL;
		dev->pmc_locking_trace = 0;
		err = 0;
	}
	spin_unlock(&dev->pmc_access_lock);

	return err;
}

static int
kfd_ioctl_create_vidmem(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_create_vidmem_args args;
	struct kfd_dev *dev;
	struct kfd_process_device *pdd;
	void *mem;
	int idr_handle;
	long err;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	if (args.size == 0)
		return -EINVAL;

	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (dev == NULL)
		return -EINVAL;

	mutex_lock(&p->mutex);

	pdd = radeon_kfd_bind_process_to_device(dev, p);
	if (IS_ERR(pdd) < 0) {
		err = PTR_ERR(pdd);
		goto bind_process_to_device_failed;
	}

	err = radeon_kfd_process_gpuvm_alloc(dev, args.va_addr, args.size, pdd->vm, &mem);
	if (err != 0)
		goto gpuvm_alloc_failed;

	radeon_flush_tlb(dev, p->pasid);

	idr_handle = radeon_kfd_process_device_create_obj_handle(pdd, mem);		// idr is an integer ID map onto arbitary pointer
	if (idr_handle < 0)
		goto handle_creation_failed;

	args.handle = MAKE_HANDLE(args.gpu_id, idr_handle);

	if (copy_to_user(arg, &args, sizeof(args))) {
		err = -EFAULT;
		goto copy_to_usr_failed;
	}

	mutex_unlock(&p->mutex);

	return 0;


copy_to_usr_failed:
	radeon_kfd_process_device_remove_obj_handle(pdd, idr_handle);
handle_creation_failed:
	radeon_kfd_process_gpuvm_free(dev, mem);
gpuvm_alloc_failed:
bind_process_to_device_failed:
	mutex_unlock(&p->mutex);

	return err;
}

static int
kfd_ioctl_destroy_vidmem(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_destroy_vidmem_args args;
	struct kfd_process_device *pdd;
	void *mem;
	struct kfd_dev *dev;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	dev = radeon_kfd_device_by_id(GET_GPU_ID(args.handle));
	if (dev == NULL)
		return -EINVAL;

	mutex_lock(&p->mutex);

	pdd = radeon_kfd_get_process_device_data(dev, p);
	BUG_ON(pdd == NULL);

	mem = radeon_kfd_process_device_translate_handle(pdd, GET_IDR_HANDLE(args.handle));
	BUG_ON(mem == NULL);

	radeon_kfd_process_device_remove_obj_handle(pdd, GET_IDR_HANDLE(args.handle));
	radeon_kfd_process_gpuvm_free(dev, mem);

	radeon_flush_tlb(dev, p->pasid);
	mutex_unlock(&p->mutex);
	return 0;
}

static int
kfd_ioctl_open_graphic_handle(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_open_graphic_handle_args args;
	struct kfd_dev *dev;
	struct kfd_process_device *pdd;
	void *mem;
	int idr_handle;
	long err;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (dev == NULL)
		return -EINVAL;

	mutex_lock(&p->mutex);

	pdd = radeon_kfd_bind_process_to_device(dev, p);
	if (IS_ERR(pdd) < 0) {
		err = PTR_ERR(pdd);
		goto bind_process_to_device_failed;
	}

	err = radeon_kfd_process_open_graphic_handle(dev, args.va_addr, pdd->vm, args.graphic_device_fd, args.graphic_handle, &mem);
	if (err != 0)
		goto gpuvm_alloc_failed;

	idr_handle = radeon_kfd_process_device_create_obj_handle(pdd, mem);
	if (idr_handle < 0)
		goto handle_creation_failed;

	args.handle = MAKE_HANDLE(args.gpu_id, idr_handle);

	if (copy_to_user(arg, &args, sizeof(args))) {
		err = -EFAULT;
		goto copy_to_usr_failed;
	}

	mutex_unlock(&p->mutex);

	return 0;


copy_to_usr_failed:
	radeon_kfd_process_device_remove_obj_handle(pdd, idr_handle);
handle_creation_failed:
	radeon_kfd_process_gpuvm_free(dev, mem);
gpuvm_alloc_failed:
bind_process_to_device_failed:
	mutex_unlock(&p->mutex);

	return err;
}


static long
kfd_ioctl_create_event(struct file *filp, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_create_event_args args;
	void __user *event_trigger_address;
	int err;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	err = kfd_event_create(filp, p, args.event_type, args.auto_reset != 0, args.node_id,
			       &args.event_id,
			       &event_trigger_address, &args.event_trigger_data);

	args.event_trigger_address = (uint64_t)(uintptr_t)event_trigger_address;
    printk("kfd_ioctl_create_event:%p\n", event_trigger_address);
    printk("kfd_ioctl_create_even, type=%d\n", args.event_type);
    printk("kfd_ioctl_create_even, data=%p\n", args.event_trigger_data);

	if (err)
		return err;

	if (copy_to_user(arg, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static long
kfd_ioctl_destroy_event(struct file *filp, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_destroy_event_args args;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	return  kfd_event_destroy(p, args.event_id);
}

static long
kfd_ioctl_set_event(struct file *filp, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_set_event_args args;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	return  kfd_set_event(p, args.event_id);
}

static long
kfd_ioctl_reset_event(struct file *filp, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_reset_event_args args;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	return  kfd_reset_event(p, args.event_id);
}

static long
kfd_ioctl_wait_events(struct file *filp, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_wait_events_args args;
	enum kfd_event_wait_result wait_result;
	int err;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	err = kfd_wait_on_events(p, args.num_events, (uint32_t __user *)args.events_ptr,
				 (args.wait_for_all != 0), args.timeout, &wait_result);

	args.wait_result = wait_result;

	if (copy_to_user(arg, &args, sizeof(args)))
		return -EFAULT;

	return err;
}

#ifdef CONFIG_HSA_VIRTUALIZATION
static long 
kfd_ioctl_vm_create_process(struct file *filep, struct kfd_process *p, void __user *arg)
{
    struct vm_process_info vm_info;
    struct kfd_process *process;
    
    if(copy_from_user(&vm_info, arg, sizeof(vm_info))) {
        printk("kfd_ioctl_vm_create_process copy_from_user fail\n");
        return -EFAULT;
    }
    printk("kfd_ioctl_vm_create_process task=0x%llx, mm=0x%llx, pgd_gpa=0x%llx\n", 
                    vm_info.vm_task, vm_info.vm_mm, vm_info.vm_pgd_gpa);

    process = radeon_kfd_vm_create_process((const void*)vm_info.vm_mm);
    if (IS_ERR(process)) {
        printk("vm create kfd_process fail\n");
        return PTR_ERR(process);
    }

    process->vm_info = kmalloc(sizeof(struct vm_info), GFP_KERNEL);
    process->vm_info->kfd_process = process;
    process->vm_info->virtio_be_process = p; 
    process->vm_info->vm_task = vm_info.vm_task;
    process->vm_info->vm_mm   = vm_info.vm_mm;
    process->vm_info->vm_pgd_gpa = vm_info.vm_pgd_gpa;
    process->vm_info->vm_spt_root = 0;
    process->vm_info->dev = NULL;

    process->is_32bit_user_mode = is_compat_task();
    list_add(&process->vm_info->list, &vm_info_list);
   

	dev_dbg(kfd_device, "process %d opened, compat mode (32 bit) - %d\n",
		process->pasid, process->is_32bit_user_mode);

    kfd_init_apertures(process);

    return 0;
}

static long 
kfd_ioctl_vm_close_process(struct file *filep, struct kfd_process *p, void __user *arg)
{
    uint64_t vm_mm;
    struct kfd_process *process;
    
    if(copy_from_user(&vm_mm, arg, sizeof(vm_mm))) {
        printk("copy_from_user fail\n");
        return -EFAULT;
    }
    printk("vm_mm=0x%llx\n", vm_mm);
    radeon_kfd_vm_close_process((const void*)vm_mm);

    return 0;
}

static long
kfd_ioctl_vm_create_queue(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_vm_create_queue_args args;
    struct kfd_process *vm_process;

	if (copy_from_user(&args, arg, sizeof(args))) {
        printk("copy_from_user fail\n");
        return -EFAULT;
    }

    vm_process = find_vm_process((void*)args.vm_mm);
    if(!vm_process) {
        printk("find_vm_process 0x%llx fail\n", (long long)args.vm_mm);
        return -EFAULT;
    }

    return kfd_ioctl_create_queue(filep, vm_process, arg);
}

static int
kfd_ioctl_vm_destroy_queue(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_vm_destroy_queue_args args;
    struct kfd_process *vm_process;

	if (copy_from_user(&args, arg, sizeof(args))) {
        printk("copy_from_user fail\n");
		return -EFAULT;
    }

    vm_process = find_vm_process((void*)args.vm_mm);
    if(!vm_process) {
        printk("find_vm_process 0x%llx fail\n", (long long)args.vm_mm);
        return -EFAULT;
    }

    return kfd_ioctl_destroy_queue(filep, vm_process, arg);
}

static long
kfd_ioctl_vm_set_memory_policy(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_vm_set_memory_policy_args args;
    struct kfd_process *vm_process;

	if (copy_from_user(&args, arg, sizeof(args))) {
        printk("copy_from_user fail\n");
		return -EFAULT;
    }

    vm_process = find_vm_process((void*)args.vm_mm);
    if(!vm_process) {
        printk("find_vm_process 0x%llx fail\n", (long long)args.vm_mm);
        return -EFAULT;
    }

    printk("call kfd_ioctl_set_memory_policy\n");
    return kfd_ioctl_set_memory_policy(filep, vm_process, arg);
}

static long
kfd_ioctl_vm_get_clock_counters(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_vm_get_clock_counters_args args;
    struct kfd_process *vm_process;

	if (copy_from_user(&args, arg, sizeof(args))) {
        printk("copy_from_user fail\n");
		return -EFAULT;
    }

    vm_process = find_vm_process((void*)args.vm_mm);
    if(!vm_process) {
        printk("find_vm_process 0x%llx fail\n", (long long)args.vm_mm);
        return -EFAULT;
    }

    return kfd_ioctl_get_clock_counters(filep, vm_process, arg);
}

static int 
kfd_ioctl_vm_get_process_apertures(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_vm_get_process_apertures_args args;
    struct kfd_process *vm_process;

	if (copy_from_user(&args, arg, sizeof(args))) {
        printk("copy_from_user fail\n");
		return -EFAULT;
    }

    vm_process = find_vm_process((void*)args.vm_mm);
    if(!vm_process) {
        printk("find_vm_process 0x%llx fail\n", (long long)args.vm_mm);
        return -EFAULT;
    }

    return kfd_ioctl_get_process_apertures(filep, vm_process, arg);
}

static long
kfd_ioctl_vm_create_event(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_vm_create_event_args args;
    struct kfd_process *vm_process;

	if (copy_from_user(&args, arg, sizeof(args))) {
        printk("copy_from_user fail\n");
		return -EFAULT;
    }

    vm_process = find_vm_process((void*)args.vm_mm);
    if(!vm_process) {
        printk("find_vm_process 0x%llx fail\n", (long long)args.vm_mm);
        return -EFAULT;
    }

    return kfd_ioctl_create_event(filep, vm_process, arg);
}

static DEFINE_MUTEX(virtio_be_bind_vm_processes_mutex);

static int kfd_ioctl_vm_virtio_be_bind_vm_process(struct file *filep, 
                struct kfd_process *p, void __user *arg)
{
    uint64_t vm_mm;
    struct kfd_process *vm_process;

	if (copy_from_user(&vm_mm, arg, sizeof(vm_mm))) {
        printk("copy_from_user fail\n");
		return -EFAULT;
    }

    vm_process = find_vm_process((const void*)vm_mm);
    if(!vm_process) {
        printk("find_vm_process 0x%llx fail\n", (long long)vm_mm);
        return -EFAULT;
    }

    mutex_lock(&virtio_be_bind_vm_processes_mutex);
    if(p->virtio_be_info->bind_vm_process != NULL) {
        printk("p->bind_vm_process not null\n");
        return -EFAULT;
    }
    p->virtio_be_info->bind_vm_process = vm_process;
    mutex_unlock(&virtio_be_bind_vm_processes_mutex);

    return 0;
}

/*
static int kfd_ioctl_iommu_enable_nested_translation(struct file *filep,
                struct kfd_process *p, void __user *arg)
{
    uint32_t gpu_id;
    struct kfd_dev *dev;
    int ret;

	if (copy_from_user(&gpu_id, arg, sizeof(gpu_id))) {
        printk("kfd_ioctl_set_iommu_nested_cr3 copy_from_user fail\n");
		return -EFAULT;
    }

	dev = radeon_kfd_device_by_id(gpu_id);
	if (dev == NULL)
		return -EINVAL;

    if (p->process_type!=KFD_PROCESS_TYPE_VIRTIO_BE || !p->virtio_be_info->kvm) {
        printk("kfd_ioctl_set_iommu_nested_cr3 fail\n");
        return -EINVAL;
    }
    
    ret = kvm_hsa_enable_iommu_nested_translation(dev->pdev);
    if (ret) {
        printk("kvm_hsa_enable_iommu_nested_translation fail\n");
        return -EINVAL;
    }
    
    return 0;
}
*/
#endif

static long
kfd_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct kfd_process *process;
	long err = -EINVAL;
    volatile int i;
    // FIXME: debug
    unsigned long va;

	dev_dbg(kfd_device,
		"ioctl cmd 0x%x (#%d), arg 0x%lx\n",
		cmd, _IOC_NR(cmd), arg);

	process = radeon_kfd_get_process(current);
	if (IS_ERR(process))
		return PTR_ERR(process);

	switch (cmd) {
	case KFD_IOC_CREATE_QUEUE:
		printk("KFD_IOC_CREATE_QUEUE\n");
		err = kfd_ioctl_create_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_DESTROY_QUEUE:
		printk("KFD_IOC_DESTROY_QUEUE\n");
		err = kfd_ioctl_destroy_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_SET_MEMORY_POLICY:
		printk("KFD_IOC_SET_MEMORY_POLICY\n");
		err = kfd_ioctl_set_memory_policy(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_GET_CLOCK_COUNTERS:
		printk("KFD_IOC_GET_CLOCK_COUNTERS\n");
		err = kfd_ioctl_get_clock_counters(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_GET_PROCESS_APERTURES:
		printk("KFD_IOC_GET_PROCESS_APERTURES\n");
		err = kfd_ioctl_get_process_apertures(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_UPDATE_QUEUE:
		printk("KFD_IOC_UPDATE_QUEUE\n");
		err = kfd_ioctl_update_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_DBG_REGISTER:
		printk("KFD_IOC_DBG_REGISTER\n");
		err = kfd_ioctl_dbg_register(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_DBG_UNREGISTER:
		printk("KFD_IOC_DBG_UNREGISTER\n");
		err = kfd_ioctl_dbg_unrgesiter(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_DBG_ADDRESS_WATCH:
		printk("KFD_IOC_DBG_ADDRESS_WATCH\n");
		err = kfd_ioctl_dbg_address_watch(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_DBG_WAVE_CONTROL:
		printk("KFD_IOC_DBG_WAVE_CONTROL\n");
		err = kfd_ioctl_dbg_wave_control(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_PMC_ACQUIRE_ACCESS:
		printk("KFD_IOC_PMC_ACQUIRE_ACCESS\n");
		err = kfd_ioctl_pmc_acquire_access(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_PMC_RELEASE_ACCESS:
		printk("KFD_IOC_PMC_RELEASE_ACCESS\n");
		err = kfd_ioctl_pmc_release_access(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_CREATE_VIDMEM:
		printk("KFD_IOC_CREATE_VIDMEM\n");
//		err = kfd_ioctl_create_vidmem(filep, process, (void __user *)arg);
        printk("Not support now !\n");
        err = -EINVAL;
		break;

	case KFD_IOC_DESTROY_VIDMEM:
		printk("KFD_IOC_DESTROY_VIDMEM\n");
//		err = kfd_ioctl_destroy_vidmem(filep, process, (void __user *)arg);
        printk("Not support now !\n");
        err = -EINVAL;
		break;

	case KFD_IOC_CREATE_EVENT:
		printk("KFD_IOC_CREATE_EVENT\n");
		err = kfd_ioctl_create_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_DESTROY_EVENT:
		printk("KFD_IOC_DESTROY_EVENT\n");
		err = kfd_ioctl_destroy_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_SET_EVENT:
		printk("KFD_IOC_SET_EVENT\n");
		err = kfd_ioctl_set_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_RESET_EVENT:
		printk("KFD_IOC_RESET_EVENT\n");
		err = kfd_ioctl_reset_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_WAIT_EVENTS:
		printk("KFD_IOC_WAIT_EVENTS\n");
		err = kfd_ioctl_wait_events(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_OPEN_GRAPHIC_HANDLE:
		printk("KFD_IOC_OPEN_GRAPHIC_HANDLE\n");
//		err = kfd_ioctl_open_graphic_handle(filep, process, (void __user *)arg);
        printk("Not support now !\n");
        err = -EINVAL;
		break;

#ifdef CONFIG_HSA_VIRTUALIZATION
    case KFD_IOC_VM_SET_VIRTIO_BE:
        printk("KFD_IOC_VM_SET_VIRTIO_BE\n");
        process->process_type = KFD_PROCESS_TYPE_VIRTIO_BE; 
        process->virtio_be_info = kmalloc(sizeof(struct virtio_be_info), GFP_KERNEL);
        if (!process->virtio_be_info) {
            printk("!!! alloc virtio_be_info fail\n");
            err = -ENOMEM;
        }
        process->virtio_be_info->kvm = NULL;
        process->virtio_be_info->bind_vm_process = NULL;
        printk("bind_vm_process=%p\n", process->virtio_be_info->bind_vm_process);
        err = 0;
        break;

/*    case KFD_IOC_IOMMU_ENABLE_NESTED_TRANSLATION:
        printk("KFD_IOC_IOMMU_ENABLE_NESTED_TRANSLATION\n");
        err = kfd_ioctl_iommu_enable_nested_translation(filep, process, (void __user *)arg); 
        break;
*/
    case KFD_IOC_VM_VIRTIO_BE_BIND_VM_PROCESS:  // used for mmap
        printk("KFD_IOC_VM_VIRTIO_BE_BIND_VM_PROCESS\n");
        err = kfd_ioctl_vm_virtio_be_bind_vm_process(filep, process, (void __user *)arg);
        break;

    case KFD_IOC_VM_VIRTIO_BE_UNBIND_VM_PROCESS:
        printk("KFD_IOC_VM_VIRTIO_BE_UNBIND_VM_PROCESS\n");
        process->virtio_be_info->bind_vm_process = NULL;
        err = 0;
        break;

    case KFD_IOC_VM_CREATE_PROCESS:
        printk("KFD_IOC_VM_CREATE_PROCESS\n");
        err = kfd_ioctl_vm_create_process(filep, process, (void __user *)arg);
        break;

    case KFD_IOC_VM_CLOSE_PROCESS:
        printk("KFD_IOC_VM_CLOSE_PROCESS\n");
        err = kfd_ioctl_vm_close_process(filep, process, (void __user *)arg);
        break;

	case KFD_IOC_VM_CREATE_QUEUE:
		printk("KFD_IOC_VM_CREATE_QUEUE\n");
		err = kfd_ioctl_vm_create_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_VM_DESTROY_QUEUE:
		printk("KFD_IOC_VM_DESTROY_QUEUE\n");
		err = kfd_ioctl_vm_destroy_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_VM_SET_MEMORY_POLICY:
		printk("KFD_IOC_VM_SET_MEMORY_POLICY\n");
		err = kfd_ioctl_vm_set_memory_policy(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_VM_GET_CLOCK_COUNTERS:
		printk("KFD_IOC_VM_GET_CLOCK_COUNTERS\n");
		err = kfd_ioctl_vm_get_clock_counters(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_VM_GET_PROCESS_APERTURES:
		printk("KFD_IOC_VM_GET_PROCESS_AERTURES\n");
		err = kfd_ioctl_vm_get_process_apertures(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_VM_UPDATE_QUEUE:
		printk("KFD_IOC_VM_UPDATE_QUEUE\n");
		err = kfd_ioctl_update_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_VM_DBG_REGISTER:
		printk("KFD_IOC_VM_DBG_REGISTER\n");
		err = kfd_ioctl_dbg_register(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_VM_DBG_UNREGISTER:
		printk("KFD_IOC_VM_DBG_UNREGISTER\n");
		err = kfd_ioctl_dbg_unrgesiter(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_VM_DBG_ADDRESS_WATCH:
		printk("KFD_IOC_VM_DBG_ADDRESS_WATCH\n");
		err = kfd_ioctl_dbg_address_watch(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_VM_DBG_WAVE_CONTROL:
		printk("KFD_IOC_VM_DBG_WAVE_CONTROL\n");
		err = kfd_ioctl_dbg_wave_control(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_VM_PMC_ACQUIRE_ACCESS:
		printk("KFD_IOC_VM_PMC_ACQUIRE_ACCESS\n");
		err = kfd_ioctl_pmc_acquire_access(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_VM_PMC_RELEASE_ACCESS:
		printk("KFD_IOC_VM_PMC_RELEASE_ACCESS\n");
		err = kfd_ioctl_pmc_release_access(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_VM_CREATE_VIDMEM:
		printk("KFD_IOC_VM_CREATE_VIDMEM\n");
//		err = kfd_ioctl_create_vidmem(filep, process, (void __user *)arg);
        printk("Not support now !\n");
        err = -EINVAL;
		break;

	case KFD_IOC_VM_DESTROY_VIDMEM:
		printk("KFD_IOC_VM_DESTROY_VIDMEM\n");
//		err = kfd_ioctl_destroy_vidmem(filep, process, (void __user *)arg);
        printk("Not support now !\n");
        err = -EINVAL;
		break;

	case KFD_IOC_VM_CREATE_EVENT:
		printk("KFD_IOC_VM_CREATE_EVENT\n");
		err = kfd_ioctl_vm_create_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_VM_DESTROY_EVENT:
		printk("KFD_IOC_VM_DESTROY_EVENT\n");
		err = kfd_ioctl_destroy_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_VM_SET_EVENT:
		printk("KFD_IOC_VM_SET_EVENT\n");
		err = kfd_ioctl_set_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_VM_RESET_EVENT:
		printk("KFD_IOC_VM_RESET_EVENT\n");
		err = kfd_ioctl_reset_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_VM_WAIT_EVENTS:
		printk("KFD_IOC_VM_WAIT_EVENTS\n");
		err = kfd_ioctl_wait_events(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_VM_OPEN_GRAPHIC_HANDLE:
		printk("KFD_IOC_VM_OPEN_GRAPHIC_HANDLE\n");
//		err = kfd_ioctl_open_graphic_handle(filep, process, (void __user *)arg);
        printk("Not support now !\n");
        err = -EINVAL;
		break;

#ifdef IDENTICAL_MAPPING
	case KFD_IOC_VM_IDENTICAL_MAPPING_SPACE:
		printk("KFD_IOC_VM_IDENTICAL_MAPPING_SPACE\n");
        struct kfd_ioctl_vm_identical_mapping_space_args args;
    	if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
    		return -EFAULT;    
        identical_mapping.start     = args.identical_hva_start;
        identical_mapping.num_pages = args.num_pages;
        identical_mapping.used      = 0;
        printk("identical_hva_space=%llx\n", identical_mapping.start);
        
        err = 0;
		break;
#endif

    // FIXME: debug
	case KFD_IOC_KICK_DOORBELL1:
		printk("KFD_IOC_KICK_DOORBELL1, %p\n", pasid1_doorbell_kernel_ptr);
        write_kernel_doorbell((u32 *)pasid1_doorbell_kernel_ptr, 16);
        break;

    // FIXME: debug
	case KFD_IOC_KICK_DOORBELL2:
		printk("KFD_IOC_KICK_DOORBELL2, %p\n", pasid2_doorbell_kernel_ptr);
        write_kernel_doorbell((u32 *)pasid2_doorbell_kernel_ptr, 16);
        break;

    // FIXME: debug
	case KFD_IOC_SET_IN_BUF:
		printk("KFD_IOC_SET_IN_BUF ");
        if (copy_from_user(&in_buf, arg, sizeof(in_buf)))
            return -EFAULT;
        printk("in_buf=%llx\n", in_buf);
        break;

    // FIXME: debug
	case KFD_IOC_SET_OUT_BUF:
		printk("KFD_IOC_SET_OUT_BUF ");
        if (copy_from_user(&out_buf, arg, sizeof(out_buf)))
            return -EFAULT;
        printk("out_buf=%llx\n", out_buf);
        break;

    // FIXME: debug
	case KFD_IOC_WALK_RWPTR:
		printk("KFD_IOC_WALK_RWPTR ");
        break;

    // FIXME: debug
	case KFD_IOC_WALK_PAGE_TABLE:
		printk("KFD_IOC_WALK_PAGE_TABLE ");

        if (copy_from_user(&va, arg, sizeof(va)))
            return -EFAULT;

        printk("va=%llx\n", va); 
        break;

    // FIXME: debug
	case KFD_IOC_CLEAR_PAGE:
		printk("KFD_IOC_CLEAR_PAGE   ");

        if (copy_from_user(&va, arg, sizeof(va)))
            return -EFAULT;

        printk("va=%llx\n", va); 
        break;

#endif
	default:
		dev_err(kfd_device,
			"unknown ioctl cmd 0x%x, arg 0x%lx)\n",
			cmd, arg);
		err = -EINVAL;
		break;
	}

	if ((err < 0) && (err != -EAGAIN))
		dev_err(kfd_device, "ioctl error %ld\n", err);

	return err;
}

static int
kfd_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long pgoff = vma->vm_pgoff;
	struct kfd_process *process;
    struct kfd_process *vm_process;

    printk("kfd_mmap, pgoff=0x%llx\n", pgoff);

	process = radeon_kfd_get_process(current);
	if (IS_ERR(process))
		return PTR_ERR(process);

    if (process->process_type == KFD_PROCESS_TYPE_VIRTIO_BE) {
        vm_process = process->virtio_be_info->bind_vm_process;
        printk("vm_process=%p\n", vm_process);
        if (vm_process != NULL) {   // will be NULL when create_queue call
            if (pgoff >= KFD_MMAP_VM_PROCESS_DOORBELL_START && 
                                        pgoff < KFD_MMAP_VM_PROCESS_DOORBELL_END)
                return radeon_kfd_vm_doorbell_mmap(vm_process, vma);
            else if (pgoff >= KFD_MMAP_VM_PROCESS_EVENTS_START &&
                                        pgoff < KFD_MMAP_VM_PROCESS_EVENTS_END)
                printk("not mmap for event now\n");
//              return radeon_kfd_vm_event_mmap(vm_process, vma); 
        }
    }

 	if (pgoff >= KFD_MMAP_DOORBELL_START && pgoff < KFD_MMAP_DOORBELL_END)
   		return radeon_kfd_doorbell_mmap(process, vma);
   	else if (pgoff >= KFD_MMAP_EVENTS_START && pgoff < KFD_MMAP_EVENTS_END)
   		return radeon_kfd_event_mmap(process, vma);

	return -EINVAL;
}
