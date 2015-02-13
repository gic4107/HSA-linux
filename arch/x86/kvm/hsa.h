#ifndef __KVM_X86_HSA_H
#define __KVM_X86_HSA_H
#include <linux/sched.h>
int kvm_hsa_set_iommu_nested_cr3(struct kvm *kvm, struct pci_dev *dev);
int kvm_hsa_bind_kfd_virtio_be(struct kvm *kvm, const struct task_struct *thread);

#endif
