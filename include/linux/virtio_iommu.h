#ifndef _LINUX_VIRTIO_IOMMU_H
#define _LINUX_VIRTIO_IOMMU_H

int virtio_iommu_clear_flush_young(struct mmu_notifier *mn,
				struct mm_struct *mm,
				unsigned long address);
void virtio_iommu_change_pte(struct mmu_notifier *mn,
			  struct mm_struct *mm,
			  unsigned long address,
			  pte_t pte);
void virtio_iommu_invalidate_page(struct mmu_notifier *mn,
			       struct mm_struct *mm,
			       unsigned long address);
void virtio_iommu_invalidate_range_start(struct mmu_notifier *mn,
				      struct mm_struct *mm,
				      unsigned long start, unsigned long end);
#endif
