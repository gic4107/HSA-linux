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
#include <uapi/linux/kfd_ioctl.h>
#include "kfd_priv.h"
#include "kfd_scheduler.h"

static long kfd_ioctl(struct file *, unsigned int, unsigned long);
static int kfd_open(struct inode *, struct file *);
static int kfd_mmap(struct file *, struct vm_area_struct *);

static const char kfd_dev_name[] = "kfd";

static const struct file_operations kfd_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = kfd_ioctl,
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

	pr_debug("\nkfd: process %d opened dev/kfd", process->pasid);

	return 0;
}

static long
kfd_ioctl_create_queue(struct file *filep, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_create_queue_args args;
	struct kfd_dev *dev;
	int err = 0;
	unsigned int queue_id;
	struct kfd_queue *queue;
	struct kfd_process_device *pdd;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	dev = radeon_kfd_device_by_id(args.gpu_id);
	if (dev == NULL)
		return -EINVAL;

	queue = kzalloc(offsetof(struct kfd_queue, scheduler_queue) + dev->device_info->scheduler_class->queue_size, GFP_KERNEL);
	if (!queue)
		return -ENOMEM;

	queue->dev = dev;

	mutex_lock(&p->mutex);

	pdd = radeon_kfd_bind_process_to_device(dev, p);
	if (IS_ERR(pdd) < 0) {
		err = PTR_ERR(pdd);
		goto err_bind_process;
	}

	pr_debug("kfd: creating queue for PASID %d on GPU 0x%x\n",
			p->pasid,
			dev->id);

	if (!radeon_kfd_allocate_queue_id(p, &queue_id))
		goto err_allocate_queue_id;

	err = dev->device_info->scheduler_class->create_queue(dev->scheduler, pdd->scheduler_process,
							      &queue->scheduler_queue,
							      (void __user *)args.ring_base_address,
							      args.ring_size,
							      (void __user *)args.read_pointer_address,
							      (void __user *)args.write_pointer_address,
							      radeon_kfd_queue_id_to_doorbell(dev, p, queue_id));
	if (err)
		goto err_create_queue;

	radeon_kfd_install_queue(p, queue_id, queue);

	args.queue_id = queue_id;
	args.doorbell_address = (uint64_t)(uintptr_t)radeon_kfd_get_doorbell(filep, p, dev, queue_id);

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
	dev->device_info->scheduler_class->destroy_queue(dev->scheduler, &queue->scheduler_queue);
err_create_queue:
	radeon_kfd_remove_queue(p, queue_id);
err_allocate_queue_id:
err_bind_process:
	kfree(queue);
	mutex_unlock(&p->mutex);
	return err;
}

static int
kfd_ioctl_destroy_queue(struct file *filp, struct kfd_process *p, void __user *arg)
{
	struct kfd_ioctl_destroy_queue_args args;
	struct kfd_queue *queue;
	struct kfd_dev *dev;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	mutex_lock(&p->mutex);

	queue = radeon_kfd_get_queue(p, args.queue_id);
	if (!queue) {
		mutex_unlock(&p->mutex);
		return -EINVAL;
	}

	dev = queue->dev;

	pr_debug("kfd: destroying queue id %d for PASID %d\n",
			args.queue_id,
			p->pasid);

	radeon_kfd_remove_queue(p, args.queue_id);
	dev->device_info->scheduler_class->destroy_queue(dev->scheduler, &queue->scheduler_queue);

	kfree(queue);

	mutex_unlock(&p->mutex);
	return 0;
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

	if (!dev->device_info->scheduler_class->set_cache_policy(dev->scheduler,
								 pdd->scheduler_process,
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
kfd_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct kfd_process *process;
	long err = -EINVAL;

	dev_info(kfd_device,
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

	if (pgoff < KFD_MMAP_DOORBELL_START)
		return -EINVAL;
	else if (pgoff < KFD_MMAP_DOORBELL_END)
		return radeon_kfd_doorbell_mmap(process, vma);
	else
		return -EINVAL;
}
