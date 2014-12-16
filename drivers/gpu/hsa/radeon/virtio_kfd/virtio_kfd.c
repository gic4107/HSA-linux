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
static const char virtkfd_name[] = "kfd";
static struct class *virtkfd_class;
struct device *virtkfd_device;
static DEFINE_IDA(virtkfd_index_ida);
struct virtio_kfd *vkfd;

#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

static int minor_to_index(int minor)
{
	return minor >> PART_BITS;
}

int virtkfd_add_req(int cmd, void *param, int param_len, uint64_t match)
{
    printk("virtkfd_add_req, command=%d, param=%p\n", cmd, param);
    struct virtkfd_req *req;
    struct scatterlist sg_cmd, sg_param, sg_match, sg_status, *sgs[4];
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
    req->match   = match;
    req->param   = param;

    printk("cmd=%p param=%p match=0x%x status=%p\n", req->command, req->param, match, &req->status);
    sg_init_one(&sg_cmd, &cmd, sizeof(cmd));
    sg_init_one(&sg_match, &match, sizeof(match));
    sg_init_one(&sg_param, param, param_len);
    sg_init_one(&sg_status, &req->status, sizeof(req->status));
    sgs[num_out++] = &sg_cmd;
    sgs[num_out++] = &sg_match;
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

static int init_vq(void)
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
    if(vkfd != NULL) {
        printk("virtkfd_probe vkfd != NULL\n");
        return -1;
    }
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

	err = init_vq();
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
    err = virtio_kfd_topology_init();
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
    printk("kfd_open current=%p, mm=%p\n", current, current->mm);
	printk("kfd_open file=%p\n", filep);
    uint64_t match;

    match = (uint64_t)current->mm;
    printk("match=0x%x\n", match);
    virtkfd_add_req(VIRTKFD_OPEN, &match, sizeof(match), NO_MATCH);     // match used for finding forwarder in back-end, kfd_open will create forwarder and no need to find one
    printk("VIRTKFD_OPEN done\n"); 

	return 0;
}

static long
virtkfd_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	long err = -EINVAL;
    uint64_t match = (uint64_t)current->mm; 
    void *args;

	dev_dbg(virtkfd_device,
		"ioctl cmd 0x%x (#%d), arg 0x%lx\n",
		cmd, _IOC_NR(cmd), arg);

	switch (cmd) {
	case KFD_IOC_CREATE_QUEUE:
		printk("KFD_IOC_CREATE_QUEUE\n");
        args = (struct kfd_ioctl_create_queue_args*)kmalloc(sizeof(struct kfd_ioctl_create_queue_args), GFP_KERNEL);
        if (copy_from_user(args, arg, sizeof(struct kfd_ioctl_create_queue_args)))
            return -EFAULT;
        printk("ring_base_address=0x%llx\n", ((struct kfd_ioctl_create_queue_args*)args)->ring_base_address);
        printk("write_pointer_address=0x%llx\n", ((struct kfd_ioctl_create_queue_args*)args)->write_pointer_address);
        printk("read_pointer_address=0x%llx\n", ((struct kfd_ioctl_create_queue_args*)args)->read_pointer_address);
        printk("ring_size=%d\n",((struct kfd_ioctl_create_queue_args*)args)->ring_size);
        printk("gpu_id=%d\n",((struct kfd_ioctl_create_queue_args*)args)->gpu_id);
        printk("queue_type=%d\n",((struct kfd_ioctl_create_queue_args*)args)->queue_type);
        printk("queue_percentage=%d\n",((struct kfd_ioctl_create_queue_args*)args)->queue_percentage);
        printk("queue_priority=%d\n",((struct kfd_ioctl_create_queue_args*)args)->queue_priority);
		err = virtkfd_add_req(VIRTKFD_CREATE_QUEUE, (struct kfd_ioctl_create_queue_args*)args,
                                sizeof(struct kfd_ioctl_create_queue_args), match);       // back-end will fill args
        printk("queue_id=%d\n", ((struct kfd_ioctl_create_queue_args*)args)->queue_id);
        printk("doorbell_address=0x%llx\n",((struct kfd_ioctl_create_queue_args*)args)->doorbell_address);
        if (copy_to_user((void __user*)arg, args, sizeof(struct kfd_ioctl_create_queue_args))) 
            return -EFAULT;
        kfree(args);
		break;
	case KFD_IOC_DESTROY_QUEUE:
		printk("KFD_IOC_DESTROY_QUEUE\n"); 
//		err = kfd_ioctl_destroy_queue(filep, process, (void __user *)arg);
		break;

	case KFD_IOC_SET_MEMORY_POLICY:
		printk("KFD_IOC_SET_MEMORY_POLICY\n");
        args = (struct kfd_ioctl_set_memory_policy_args*)kmalloc(sizeof(struct kfd_ioctl_set_memory_policy_args), GFP_KERNEL);
        if (copy_from_user(args, arg, sizeof(struct kfd_ioctl_set_memory_policy_args)))
            return -EFAULT;
        printk("gpu_id=%d\n", ((struct kfd_ioctl_set_memory_policy_args*)args)->gpu_id);
        printk("alternate_aperture_base=0x%llx\n", ((struct kfd_ioctl_set_memory_policy_args*)args)->alternate_aperture_base);
        printk("alternate_aperture_size=%llu\n", ((struct kfd_ioctl_set_memory_policy_args*)args)->alternate_aperture_size);
        printk("default_policy=%u\n", ((struct kfd_ioctl_set_memory_policy_args*)args)->default_policy);
        printk("alternate_policy=%u\n", ((struct kfd_ioctl_set_memory_policy_args*)args)->alternate_policy);
		err = virtkfd_add_req(VIRTKFD_SET_MEMORY_POLICY, (struct kfd_ioctl_set_memory_policy_args*)args,
                                sizeof(struct kfd_ioctl_set_memory_policy_args), match);       // back-end will fill args
        kfree(args);
		break;
	case KFD_IOC_GET_CLOCK_COUNTERS:
		printk("KFD_IOC_GET_CLOCK_COUNTERS\n");
        args = (struct kfd_ioctl_get_clock_counters_args*)kmalloc(sizeof(struct kfd_ioctl_get_clock_counters_args), GFP_KERNEL);
        if (copy_from_user(args, arg, sizeof(struct kfd_ioctl_get_clock_counters_args)))
            return -EFAULT;
        printk("gpu_id=%d\n", ((struct kfd_ioctl_get_clock_counters_args*)args)->gpu_id);
		err = virtkfd_add_req(VIRTKFD_GET_CLOCK_COUNTERS, (struct kfd_ioctl_get_clock_counters_args*)args,
                                sizeof(struct kfd_ioctl_get_clock_counters_args), match);       // back-end will fill args
        printk("gpu_clock_counter=%llu\n", ((struct kfd_ioctl_get_clock_counters_args*)args)->gpu_clock_counter);
        printk("cpu_clock_counter=%llu\n", ((struct kfd_ioctl_get_clock_counters_args*)args)->cpu_clock_counter);
        printk("system_clock_counter=%llu\n", ((struct kfd_ioctl_get_clock_counters_args*)args)->system_clock_counter);
        printk("system_clock_freq=%llu\n", ((struct kfd_ioctl_get_clock_counters_args*)args)->system_clock_freq);
        if (copy_to_user((void __user*)arg, args, sizeof(((struct kfd_ioctl_get_clock_counters_args*)args)))) 
            return -EFAULT;
        kfree(args);
		break;
	case KFD_IOC_GET_PROCESS_APERTURES:
		printk("KFD_IOC_GET_PROCESS_APERTURES\n");
        args = (struct kfd_ioctl_get_process_apertures_args*)kmalloc(sizeof(struct kfd_ioctl_get_process_apertures_args), GFP_KERNEL);
        if (copy_from_user(args, arg, sizeof(struct kfd_ioctl_get_process_apertures_args)))
            return -EFAULT;
		err = virtkfd_add_req(VIRTKFD_GET_PROCESS_APERTURES, (struct kfd_ioctl_get_process_apertures_args*)args,
                                sizeof(struct kfd_ioctl_get_process_apertures_args), match);       // back-end will fill args
        printk("num_of_nodes=%d\n", ((struct kfd_ioctl_get_process_apertures_args*)args)->num_of_nodes);
        printk("lds_base=0x%llx\n", ((struct kfd_ioctl_get_process_apertures_args*)args)->process_apertures[0].lds_base);
        printk("lds_limit=0x%llx\n",((struct kfd_ioctl_get_process_apertures_args*)args)->process_apertures[0].lds_limit);
        printk("gpu_id=%d\n",((struct kfd_ioctl_get_process_apertures_args*)args)->process_apertures[0].gpu_id);
        if (copy_to_user((void __user*)arg, args, sizeof(struct kfd_ioctl_get_process_apertures_args))) 
            return -EFAULT;
        kfree(args);
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
        args = (struct kfd_ioctl_create_event_args*)kmalloc(sizeof(struct kfd_ioctl_create_event_args), GFP_KERNEL);
        if (copy_from_user(args, arg, sizeof(struct kfd_ioctl_create_event_args)))
            return -EFAULT;
        printk("event_type=%u\n", ((struct kfd_ioctl_create_event_args*)args)->event_type);
        printk("auto_reset=%u\n", ((struct kfd_ioctl_create_event_args*)args)->auto_reset);
        printk("node_id=%u\n", ((struct kfd_ioctl_create_event_args*)args)->node_id);
		err = virtkfd_add_req(VIRTKFD_CREATE_EVENT, (struct kfd_ioctl_create_event_args*)args,
                                sizeof(struct kfd_ioctl_create_event_args), match);       // back-end will fill args
        printk("event_trigger_address=0x%llx\n", ((struct kfd_ioctl_create_event_args*)args)->event_trigger_address);
        printk("event_trigger_data=%u\n", ((struct kfd_ioctl_create_event_args*)args)->event_trigger_data);
        printk("event_id=%u\n", ((struct kfd_ioctl_create_event_args*)args)->event_id);
        if (copy_to_user((void __user*)arg, args, sizeof(((struct kfd_ioctl_create_event_args*)args)))) 
            return -EFAULT;
        kfree(args);
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
