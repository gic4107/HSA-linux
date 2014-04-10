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
#include <uapi/asm-generic/mman-common.h>
#include <asm/processor.h>
#include "kfd_hw_pointer_store.h"
#include "kfd_device_queue_manager.h"

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

	process = radeon_kfd_create_process(current);
	if (IS_ERR(process))
		return PTR_ERR(process);

	process->is_32bit_user_mode = is_compat_task();

	dev_info(kfd_device, "process %d opened, compat mode (32 bit) - %d\n", process->pasid, process->is_32bit_user_mode);

	kfd_init_apertures(process);

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

	/* need to validate parameters */

	q_properties.is_interop = false;
	q_properties.queue_percent = args.queue_percentage;
	q_properties.priority = args.queue_priority;
	q_properties.queue_address = args.ring_base_address;
	q_properties.queue_size = args.ring_size;


	pr_debug("%s Arguments: Queue Percentage (%d, %d)\n"
			"Queue Priority (%d, %d)\n"
			"Queue Address (0x%llX, 0x%llX)\n"
			"Queue Size (%u64, %ll)\n",
			__func__,
			q_properties.queue_percent, args.queue_percentage,
			q_properties.priority, args.queue_priority,
			q_properties.queue_address, args.ring_base_address,
			q_properties.queue_size, args.ring_size);

	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (dev == NULL)
		return -EINVAL;

	mutex_lock(&p->mutex);

	pdd = radeon_kfd_bind_process_to_device(dev, p);
	if (IS_ERR(pdd) < 0) {
		err = PTR_ERR(pdd);
		goto err_bind_process;
	}

	pr_debug("kfd: creating queue for PASID %d on GPU 0x%x\n",
			p->pasid,
			dev->id);

	err = pqm_create_queue(&p->pqm, dev, filep, &q_properties, 0, KFD_QUEUE_TYPE_COMPUTE, &queue_id);
	if (err != 0)
		goto err_create_queue;

	args.queue_id = queue_id;
	args.read_pointer_address = (uint64_t)q_properties.read_ptr;
	args.write_pointer_address = (uint64_t)q_properties.write_ptr;
	args.doorbell_address = (uint64_t)q_properties.doorbell_ptr;

	if (copy_to_user(arg, &args, sizeof(args))) {
		err = -EFAULT;
		goto err_copy_args_out;
	}

	mutex_unlock(&p->mutex);

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

	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (dev == NULL)
		return -EINVAL;

	mutex_lock(&p->mutex);

	pdd = radeon_kfd_bind_process_to_device(dev, p);
	if (IS_ERR(pdd) < 0) {
		err = PTR_ERR(pdd);
		goto out;
	}

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

out:
	mutex_unlock(&p->mutex);

	return err;
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
kfd_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct kfd_process *process;
	long err = -EINVAL;

	dev_dbg(kfd_device,
		"ioctl cmd 0x%x (#%d), arg 0x%lx\n",
		cmd, _IOC_NR(cmd), arg);

	process = radeon_kfd_get_process(current);
	if (IS_ERR(process))
		return PTR_ERR(process);

	switch (cmd) {
	case KFD_IOC_CREATE_QUEUE:
		err = kfd_ioctl_create_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_DESTROY_QUEUE:
		err = kfd_ioctl_destroy_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_SET_MEMORY_POLICY:
		err = kfd_ioctl_set_memory_policy(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_GET_CLOCK_COUNTERS:
		err = kfd_ioctl_get_clock_counters(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_GET_PROCESS_APERTURES:
		err = kfd_ioctl_get_process_apertures(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_UPDATE_QUEUE:
		err = kfd_ioctl_update_queue(filep, process, (void __user *)arg);
		break;

	default:
		dev_err(kfd_device,
			"unknown ioctl cmd 0x%x, arg 0x%lx)\n",
			cmd, arg);
		err = -EINVAL;
		break;
	}

	if (err < 0)
		dev_err(kfd_device, "ioctl error %ld\n", err);

	return err;
}

static int
kfd_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long pgoff = vma->vm_pgoff;
	struct kfd_process *process;

	process = radeon_kfd_get_process(current);
	if (IS_ERR(process))
		return PTR_ERR(process);

	if (pgoff >= KFD_MMAP_DOORBELL_START && pgoff < KFD_MMAP_DOORBELL_END)
		return radeon_kfd_doorbell_mmap(process, vma);
	else if (pgoff >= KFD_MMAP_RPTR_START && pgoff < KFD_MMAP_RPTR_END)
		return radeon_kfd_hw_pointer_store_mmap(&process->read_ptr, vma);
	else if (pgoff >= KFD_MMAP_WPTR_START && pgoff < KFD_MMAP_WPTR_END)
		return radeon_kfd_hw_pointer_store_mmap(&process->write_ptr, vma);

	return -EINVAL;
}
