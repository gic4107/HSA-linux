#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kvm_types.h>
#include <linux/radeon_kfd.h>
#include <linux/amd-iommu.h>
#include <linux/highmem.h>
#include "mmu.h"
#include "hsa.h"

int (*kvm_bind_kfd_virtio_be_p)(struct kvm *kvm, const struct task_struct *thread);
int (*radeon_kfd_bind_iommu_spt_p)(gpa_t guest_cr3, hpa_t spt_root);
void (*radeon_kfd_flush_iommu_p)(gpa_t guest_cr3, gva_t fault_addr);

int kvm_hsa_init(void)
{
    kvm_bind_kfd_virtio_be_p = symbol_request(kvm_bind_kfd_virtio_be);
    if (!kvm_bind_kfd_virtio_be_p) {
        printk("symbol_request(kvm_bind_kfd_virtio_be) fail\n");
        return -EINVAL;
    }

    radeon_kfd_bind_iommu_spt_p = symbol_request(radeon_kfd_bind_iommu_spt);
    if (!radeon_kfd_bind_iommu_spt_p) {
        printk("symbol_request(radeon_kfd_bind_iommu_kfd) fail\n");
        return -EINVAL;
    }

    radeon_kfd_flush_iommu_p = symbol_request(radeon_kfd_flush_iommu);
    if (!radeon_kfd_flush_iommu_p) {
        printk("symbol_request(radeon_kfd_bind_iommu_kfd) fail\n");
        return -EINVAL;
    }

    return 0;
}

int kvm_hsa_bind_kfd_virtio_be(struct kvm *kvm, const struct task_struct *thread)
{
    BUG_ON(!kvm_bind_kfd_virtio_be_p);
    return kvm_bind_kfd_virtio_be_p(kvm, thread);
}

void kvm_hsa_iommu_bind_spt(gpa_t guest_cr3, hpa_t spt_root)
{
    if (!radeon_kfd_bind_iommu_spt_p)   // no guest process use HSA for now
        return;
    radeon_kfd_bind_iommu_spt_p(guest_cr3, spt_root);
}

void kvm_hsa_page_fault_flush(gpa_t guest_cr3, gva_t fault_addr)
{
    if (!radeon_kfd_flush_iommu_p)   // no guest process use HSA for now
        return;
    radeon_kfd_flush_iommu_p(guest_cr3, fault_addr);
}

int iommu_spt_page_fault(struct kvm_vcpu *vcpu, gva_t addr, u32 error_code, 
                            bool prefault, u64 guest_cr3);
int kvm_hsa_iommu_spt_page_fault(struct kvm *kvm, gva_t gva, u32 flags, u64 guest_cr3)
{
    struct kvm_vcpu *vcpu;
    struct kvm_vcpu_arch *arch;
    struct kvm_mmu *mmu;
    u32 error_code = 0;

    vcpu = kvm->vcpus[0];
    arch = &vcpu->arch;
    mmu  = &arch->mmu;

    if (flags & PPR_FAULT_WRITE)
        error_code |= PFERR_WRITE_MASK;
    if (flags & PPR_FAULT_GN)
        error_code |= PFERR_USER_MASK;
    error_code |= PFERR_IOMMU_MASK;

    printk("=====kvm_hsa_iommu_spt_page_fault, kvm=%p, gva=%llx, flags=%d, error=%x, guest_cr3=%llx\n", kvm, gva, flags, error_code, guest_cr3);
    return iommu_spt_page_fault(kvm->vcpus[0], gva, error_code, false, guest_cr3);  
}
EXPORT_SYMBOL_GPL(kvm_hsa_iommu_spt_page_fault);
