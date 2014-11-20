//#define DEBUG
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/virtio.h>
#include <linux/virtio_blk.h>
#include <linux/scatterlist.h>
#include <linux/string_helpers.h>
#include <scsi/scsi_cmnd.h>
#include <linux/idr.h>
#include <linux/blk-mq.h>
#include <linux/numa.h>
#include <linux/cdev.h>
#include <uapi/linux/kfd_ioctl.h>
#include <uapi/linux/virtio_ids.h>
#include <linux/virtio_ring.h>
#include "virtio_kfd_priv.h"

#define PART_BITS 4

#define VIRTIO_ID_KFD 13
//#define VIRTIO_DEV_ANY_ID	0xffffffff

static int virtkfd_major;
static struct cdev virtkfd_cdev;
static const char virtkfd_name[] = "virtio-kfd";
static struct class *virtkfd_class;
struct device *virtkfd_device;
static DEFINE_IDA(virtkfd_index_ida);

#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

static int minor_to_index(int minor)
{
	return minor >> PART_BITS;
}

int virtkfd_add_req(struct virtio_kfd *vkfd, int *cmd, void *param, int param_len)
{
    printk("virtkfd_add_req, command=%d, param=%p\n", *cmd, param);
    struct virtkfd_req *req;
    struct scatterlist sg_cmd, sg_param, sg_status, *sgs[3];
    int num_in=0, num_out=0; 
    struct virtqueue *vq = vkfd->vq;
    int ret;
    
	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		printk("virtkfd_req alloc fail\n");
        return -1;
	}
    req->signal  = 0;
    req->command = cmd;
    req->param   = param;

    printk("cmd=%p param=%p status=%p\n", req->command, req->param, &req->status);
    sg_init_one(&sg_cmd, cmd, sizeof(int));
    sg_init_one(&sg_param, param, param_len);
    sg_init_one(&sg_status, &req->status, sizeof(req->status));
    sgs[num_out++] = &sg_cmd;
    sgs[num_out+num_in++] = &sg_param;
    sgs[num_out+num_in++] = &sg_status;

    ret = virtqueue_add_sgs(vq, sgs, num_out, num_in, req, GFP_ATOMIC);
    if(ret < 0) {
        printk("virtqueue_add_sgs return %d\n", ret);
        virtqueue_kick(vq);
        return -1;
    }
    ret = virtqueue_kick(vq);
    if(!ret) {
        printk("virtqueue_kick return %d\n", ret);
        return -1;
    }
    printk("virtqueue_kick done, wait %p\n", &req->signal);
    while(req->signal == 0);        // signal by virtqueue's callback function

    kfree(req); 

    return 0;
}

static void virtkfd_done(struct virtqueue *vq)
{
    struct virtio_kfd *vkfd = vq->vdev->priv;
    struct virtkfd_req *req;
    int len;
	unsigned long flags;

    printk("virtkfd_done\n");
	spin_lock_irqsave(&vkfd->vq_lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((req = virtqueue_get_buf(vq, &len)) != NULL) {
            printk("req->signal=%p, true\n", &req->signal);
            req->signal = true;
		}
		if (unlikely(virtqueue_is_broken(vq)))
			break;
	} while (!virtqueue_enable_cb(vq));

	spin_unlock_irqrestore(&vkfd->vq_lock, flags);
}

/*
static void virtblk_config_changed_work(struct work_struct *work)
{
	struct virtio_blk *vblk =
		container_of(work, struct virtio_blk, config_work);
	struct virtio_device *vdev = vblk->vdev;
	struct request_queue *q = vblk->disk->queue;
	char cap_str_2[10], cap_str_10[10];
	char *envp[] = { "RESIZE=1", NULL };
	u64 capacity, size;

	mutex_lock(&vblk->config_lock);
	if (!vblk->config_enable)
		goto done;
*/
	/* Host must always specify the capacity. */
//	virtio_cread(vdev, struct virtio_blk_config, capacity, &capacity);

	/* If capacity is too big, truncate with warning. */
/*	if ((sector_t)capacity != capacity) {
		dev_warn(&vdev->dev, "Capacity %llu too large: truncating\n",
			 (unsigned long long)capacity);
		capacity = (sector_t)-1;
	}

	size = capacity * queue_logical_block_size(q);
	string_get_size(size, STRING_UNITS_2, cap_str_2, sizeof(cap_str_2));
	string_get_size(size, STRING_UNITS_10, cap_str_10, sizeof(cap_str_10));

	dev_notice(&vdev->dev,
		  "new size: %llu %d-byte logical blocks (%s/%s)\n",
		  (unsigned long long)capacity,
		  queue_logical_block_size(q),
		  cap_str_10, cap_str_2);

	set_capacity(vblk->disk, capacity);
	revalidate_disk(vblk->disk);
	kobject_uevent_env(&disk_to_dev(vblk->disk)->kobj, KOBJ_CHANGE, envp);
done:
	mutex_unlock(&vblk->config_lock);
}
*/

/*
static void virtblk_config_changed(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;

	queue_work(virtblk_wq, &vblk->config_work);
}
*/

static int init_vq(struct virtio_kfd *vkfd)
{
	int err = 0;

	/* We expect one virtqueue, for output. */
	vkfd->vq = virtio_find_single_vq(vkfd->vdev, virtkfd_done, "virtkfd-requests");
	if (IS_ERR(vkfd->vq))
		err = PTR_ERR(vkfd->vq);

	return err;
}

static int virtkfd_probe(struct virtio_device *vdev)
{
    struct virtio_kfd *vkfd;
	int err, index;
printk("virtiokfd_probe\n");

	err = ida_simple_get(&virtkfd_index_ida, 0, minor_to_index(1 << MINORBITS),
			     GFP_KERNEL);
	if (err < 0)
		goto out;
	index = err;

	/* We need to know how many segments before we allocate. */
//	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_SEG_MAX,
//				   struct virtio_blk_config, seg_max,
//				   &sg_elems);

	/* We need an extra sg elements at head and tail. */
	vdev->priv = vkfd = kmalloc(sizeof(*vkfd), GFP_KERNEL);
	if (!vkfd) {
		err = -ENOMEM;
		goto out_free_index;
	}

	vkfd->vdev = vdev;
	mutex_init(&vkfd->config_lock);

//	INIT_WORK(&vblk->config_work, virtblk_config_changed_work);
	vkfd->config_enable = true;

	err = init_vq(vkfd);
	if (err)
		goto out_free_vkfd;
	spin_lock_init(&vkfd->vq_lock);

	vkfd->index = index;

	/* If disk is read-only in the host, the guest should obey */
//	if (virtio_has_feature(vdev, VIRTIO_BLK_F_RO))
//		set_disk_ro(vblk->disk, 1);

	/* Host must always specify the capacity. */
//	virtio_cread(vdev, struct virtio_blk_config, capacity, &cap);

	/* If capacity is too big, truncate with warning. */
//	if ((sector_t)cap != cap) {
//		dev_warn(&vdev->dev, "Capacity %llu too large: truncating\n",
//			 (unsigned long long)cap);
//		cap = (sector_t)-1;
//	}
//	set_capacity(vblk->disk, cap);

	/* Host can optionally specify maximum segment size and number of
	 * segments. */

	/* Host can optionally specify the block size of the device */

//	err = device_create_file(disk_to_dev(vblk->disk), &dev_attr_serial);
//	if (err)
//		goto out_del_disk;
    err = virtio_kfd_topology_init(vkfd);
    if(err < 0)
        goto out_free_vq;

	return 0;

out_free_vq:
	vdev->config->del_vqs(vdev);
out_free_vkfd:
	kfree(vkfd);
out_free_index:
	ida_simple_remove(&virtkfd_index_ida, index);
out:
	return err;
}

/*
static void virtblk_remove(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
	int index = vblk->index;
	int refc;
*/
	/* Prevent config work handler from accessing the device. */
/*	mutex_lock(&vblk->config_lock);
	vblk->config_enable = false;
	mutex_unlock(&vblk->config_lock);

	del_gendisk(vblk->disk);
	blk_cleanup_queue(vblk->disk->queue);
*/
	/* Stop all the virtqueues. */
/*	vdev->config->reset(vdev);

	flush_work(&vblk->config_work);

	refc = atomic_read(&disk_to_dev(vblk->disk)->kobj.kref.refcount);
	put_disk(vblk->disk);
	vdev->config->del_vqs(vdev);
	kfree(vblk);
*/
	/* Only free device id if we don't have any users */
//	if (refc == 1)
//		ida_simple_remove(&virtkfd_index_ida, index);
//}

/*
#ifdef CONFIG_PM_SLEEP
static int virtblk_freeze(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
*/
	/* Ensure we don't receive any more interrupts */
//	vdev->config->reset(vdev);

	/* Prevent config work handler from accessing the device. */
/*	mutex_lock(&vblk->config_lock);
	vblk->config_enable = false;
	mutex_unlock(&vblk->config_lock);

	flush_work(&vblk->config_work);

	blk_mq_stop_hw_queues(vblk->disk->queue);

	vdev->config->del_vqs(vdev);
	return 0;
}

static int virtblk_restore(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
	int ret;

	vblk->config_enable = true;
	ret = init_vq(vdev->priv);
	if (!ret)
		blk_mq_start_stopped_hw_queues(vblk->disk->queue);

	return ret;
}
#endif
*/

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_KFD, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
/*	VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
	VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_SCSI,
	VIRTIO_BLK_F_WCE, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE
*/
};

static struct virtio_driver virtio_kfd = {
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.probe			= virtkfd_probe,
//	.remove			= virtkfd_remove,
//	.config_changed		= virtkfd_config_changed,
/*
#ifdef CONFIG_PM_SLEEP
	.freeze			= virtkfd_freeze,
	.restore		= virtkfd_restore,
#endif
*/
};

static int
virtkfd_open(struct inode *inode, struct file *filep)
{
	printk("kfd_open file=%p\n", filep);
	return 0;
}

static long
virtkfd_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
//	struct kfd_process *process;
	long err = -EINVAL;

	dev_dbg(virtkfd_device,
		"ioctl cmd 0x%x (#%d), arg 0x%lx\n",
		cmd, _IOC_NR(cmd), arg);

//	process = radeon_kfd_get_process(current);
//	if (IS_ERR(process))
//		return PTR_ERR(process);

	switch (cmd) {
	case KFD_IOC_CREATE_QUEUE:
		printk("KFD_IOC_CREATE_QUEUE\n");
//		err = kfd_ioctl_create_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_DESTROY_QUEUE:
		printk("KFD_IOC_DESTROY_QUEUE\n"); 
//		err = kfd_ioctl_destroy_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_SET_MEMORY_POLICY:
		printk("KFD_IOC_SET_MEMORY_POLICY\n");
//		err = kfd_ioctl_set_memory_policy(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_GET_CLOCK_COUNTERS:
		printk("KFD_IOC_GET_CLOCK_COUNTERS\n");
//		err = kfd_ioctl_get_clock_counters(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_GET_PROCESS_APERTURES:
		printk("KFD_IOC_GET_PROCESS_APERTURES\n");
//		err = kfd_ioctl_get_process_apertures(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_UPDATE_QUEUE:
		printk("KFD_IOC_UPDATE_QUEUE\n");
//		err = kfd_ioctl_update_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_DBG_REGISTER:
		printk("KFD_IOC_DBG_REGISTER\n");
//		err = kfd_ioctl_dbg_register(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_DBG_UNREGISTER:
		printk("KFD_IOC_DBG_UNREGISTER\n");
//		err = kfd_ioctl_dbg_unrgesiter(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_DBG_ADDRESS_WATCH:
		printk("KFD_IOC_DBG_ADDRESS_WATCH\n");
//		err = kfd_ioctl_dbg_address_watch(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_DBG_WAVE_CONTROL:
		printk("KFD_IOC_DBG_WAVE_CONTROL\n");
//		err = kfd_ioctl_dbg_wave_control(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_PMC_ACQUIRE_ACCESS:
		printk("KFD_IOC_PMC_ACQUIRE_ACCESS\n");
//		err = kfd_ioctl_pmc_acquire_access(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_PMC_RELEASE_ACCESS:
		printk("KFD_IOC_PMC_RELEASE_ACCESS\n");
//		err = kfd_ioctl_pmc_release_access(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_CREATE_VIDMEM:
		printk("KFD_IOC_CREATE_VIDMEM\n");
//		err = kfd_ioctl_create_vidmem(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_DESTROY_VIDMEM:
		printk("KFD_IOC_DESTROY_VIDMEM\n");
//		err = kfd_ioctl_destroy_vidmem(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_CREATE_EVENT:
		printk("KFD_IOC_CREATE_EVENT\n");
//		err = kfd_ioctl_create_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_DESTROY_EVENT:
		printk("KFD_IOC_DESTROY_EVENT\n");
//		err = kfd_ioctl_destroy_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_SET_EVENT:
		printk("KFD_IOC_SET_EVENT\n");
//		err = kfd_ioctl_set_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_RESET_EVENT:
		printk("KFD_IOC_RESET_EVENT\n");
//		err = kfd_ioctl_reset_event(filep, process, (void __user *) arg);
		break;

	case KFD_IOC_WAIT_EVENTS:
		printk("KFD_IOC_WAIT_EVENTS\n");
//		err = kfd_ioctl_wait_events(filep, process, (void __user *) arg);
		break;
	case KFD_IOC_OPEN_GRAPHIC_HANDLE:
		printk("KFD_IOC_OPEN_GRAPHIC_HANDLE\n");
//		err = kfd_ioctl_open_graphic_handle(filep, process, (void __user *)arg);
		break;

	default:
		dev_err(virtkfd_device,
			"unknown ioctl cmd 0x%x, arg 0x%lx)\n",
			cmd, arg);
		err = -EINVAL;
		break;
	}

	if ((err < 0) && (err != -EAGAIN))
		dev_err(virtkfd_device, "ioctl error %ld\n", err);

	return err;
}

static const struct file_operations virtkfd_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = virtkfd_ioctl,
	.compat_ioctl = virtkfd_ioctl,
	.open = virtkfd_open,
//	.mmap = virtkfd_mmap,
};

static int __init init(void)
{
	int err = 0;
printk("virtio-kfd init\n");
	alloc_chrdev_region(&virtkfd_major, 0, 1, virtkfd_name);
	if (virtkfd_major < 0)
		goto err_register_chrdev;

	virtkfd_class = class_create(THIS_MODULE, virtkfd_name);
	err = PTR_ERR(virtkfd_class);
	if (IS_ERR(virtkfd_class))
		goto err_class_create;

	virtkfd_device = device_create(virtkfd_class, NULL, 
                            virtkfd_major, NULL, virtkfd_name);
	err = PTR_ERR(virtkfd_device);
	if (IS_ERR(virtkfd_device))
		goto err_device_create;

	cdev_init(&virtkfd_cdev, &virtkfd_fops);
	err = cdev_add(&virtkfd_cdev, virtkfd_major, 1);
	if(err) {
		printk("Unable to add virtkfd_cdev\n");
		goto err_device_create;
	}

/*
	virtblk_wq = alloc_workqueue("virtio-blk", 0, 0);
	if (!virtblk_wq)
		return -ENOMEM;

	major = register_blkdev(0, "virtblk");
	if (major < 0) {
		error = major;
		goto out_destroy_workqueue;
	}
*/
	err = register_virtio_driver(&virtio_kfd);
	if (err)
		goto err_device_create;

	return 0;

err_device_create:
	class_destroy(virtkfd_class);
err_class_create:
	unregister_chrdev(virtkfd_major, virtkfd_name);
err_register_chrdev:
	return err;
}

static void __exit fini(void)
{
    printk("module_exit\n");
//	unregister_chrdev(virtkfd_major, virtkfd_name);
    cdev_del(&virtkfd_cdev);
	unregister_virtio_driver(&virtio_kfd);
//	destroy_workqueue(virtblk_wq);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio kfd driver");
MODULE_LICENSE("GPL");
