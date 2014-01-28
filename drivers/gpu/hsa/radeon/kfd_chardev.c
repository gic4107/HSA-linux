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
#include "kfd_priv.h"
#include "kfd_scheduler.h"

static long kfd_ioctl(struct file *, unsigned int, unsigned long);
static int kfd_open(struct inode *, struct file *);
static int kfd_release(struct inode *, struct file *);
static int kfd_mmap(struct file *, struct vm_area_struct *);

static const char kfd_dev_name[] = "kfd";

static const struct file_operations kfd_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = kfd_ioctl,
	.open = kfd_open,
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
kfd_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct kfd_process *process;
	long err = -EINVAL;

	dev_info(kfd_device,
		 "ioctl cmd 0x%x (#%d), arg 0x%lx\n",
		 cmd, _IOC_NR(cmd), arg);

	switch (cmd) {
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
