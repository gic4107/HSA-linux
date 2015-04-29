#ifndef AMD_IOMMU_V2_H
#define AMD_IOMMU_V2_H

#include <linux/mmu_notifier.h>
#include <linux/amd-iommu.h>

#define MAX_DEVICES		0x10000
#define PRI_QUEUE_SIZE		512

extern struct list_head pasid_state_list;

struct pri_queue {
	atomic_t inflight;
	bool finish;
	int status;
};

struct pasid_state {
	struct list_head list;			/* For global state-list */
	atomic_t count;				/* Reference count */
	struct task_struct *task;		/* Task bound to this PASID */
	struct mm_struct *mm;			/* mm_struct for the faults */
	struct mmu_notifier mn;                 /* mmu_otifier handle */
	struct pri_queue pri[PRI_QUEUE_SIZE];	/* PRI tag states */
	struct device_state *device_state;	/* Link to our device_state */
	int pasid;				/* PASID index */
	spinlock_t lock;			/* Protect pri_queues */
	wait_queue_head_t wq;			/* To wait for count == 0 */
#ifdef CONFIG_HSA_VIRTUALIZATION
    struct mm_struct *virtio_be_mm;
    struct kvm *kvm;
#endif
};

struct device_state {
	atomic_t count;
	struct pci_dev *pdev;
	struct pasid_state **states;
	struct iommu_domain *domain;
	int pasid_levels;
	int max_pasids;
	amd_iommu_invalid_ppr_cb inv_ppr_cb;
	amd_iommu_invalidate_ctx inv_ctx_cb;
	spinlock_t lock;
	wait_queue_head_t wq;
};

struct fault {
	struct work_struct work;
	struct device_state *dev_state;
	struct pasid_state *state;
	struct mm_struct *mm;
	u64 address;
	u16 devid;
	u16 pasid;
	u16 tag;
	u16 finish;
	u16 flags;
};

void put_pasid_state(struct pasid_state *pasid_state);
#ifdef CONFIG_HSA_VIRTUALIZATION
void finish_pri_tag(struct device_state *dev_state, struct pasid_state *pasid_state, u16 tag, bool gn);
#else
void finish_pri_tag(struct device_state *dev_state, struct pasid_state *pasid_state, u16 tag);
#endif
void set_pri_tag_status(struct pasid_state *pasid_state, u16 tag, int status);

#endif
