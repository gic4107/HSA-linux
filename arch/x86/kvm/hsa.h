#ifndef __KVM_X86_HSA_H
#define __KVM_X86_HSA_H
#include <linux/sched.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#define IDENTICAL_MAPPING_MASK (1U << 10)
int kvm_hsa_set_iommu_nested_cr3(hpa_t root_hpa);
int kvm_hsa_is_iommu_nested_translation(void);
int kvm_hsa_bind_kfd_virtio_be(struct kvm *kvm, const struct task_struct *thread);

#endif
