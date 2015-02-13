#ifndef VIRTIO_IOMMU_H
#define VIRTIO_IOMMU_H

// The command store inside virtqueue
#define VIRTIO_IOMMU_MMAP_PPR_REGION           1
#define VIRTIO_IOMMU_VM_FINISH_PPR             2
#define VIRTIO_IOMMU_CLEAR_FLUSH_YOUNG         3
#define VIRTIO_IOMMU_CHANGE_PTE                4
#define VIRTIO_IOMMU_INVALIDATE_PAGE           5
#define VIRTIO_IOMMU_INVALIDATE_RANGE_START    6

struct virtio_iommu
{
	struct virtio_device *vdev;
	struct virtqueue *vq;
	spinlock_t vq_lock;

	/* Process context for config space updates */
//	struct work_struct config_work;

	/* Lock for config space updates */
	struct mutex config_lock;

	/* enable config space updates */
	bool config_enable;

	/* Ida index - used to track minor number allocations. */
	int index;
};

#define VIRTIO_IOMMU_REQ_NO_WAIT 0
#define VIRTIO_IOMMU_REQ_WAIT 1
#define VIRTIO_IOMMU_REQ_DONE 2

struct virtio_iommu_req 
{
    int command;                        // command out to back-end
    void *param;                        // parameter
    u8 status;                          // status of back-end finishing req
    int wait;                         // request thread wait for this signale
    void (*cb)(void*);
};

struct virtio_iommu_mmu_notification {
    uint64_t mm;
    uint64_t address;
};
#endif
