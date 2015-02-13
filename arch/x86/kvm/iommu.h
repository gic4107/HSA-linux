#ifndef __KVM_X86_IOMMU_H
#define __KVM_X86_IOMMU_H

#define PT_IW_MASK           (1ULL << 62)
#define PT_IR_MASK           (1ULL << 61)
#define PTE_FC_MASK          (1ULL << 60)
#define PTE_U_MASK           (1ULL << 59)
#define PT_NEXT_LEVEL_SHIFT   9
#define PT_NEXT_LEVEL_MASK   (7ULL << PT_NEXT_LEVEL_SHIFT)

#endif
