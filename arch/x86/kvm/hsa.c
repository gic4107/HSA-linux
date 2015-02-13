#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/kvm_types.h>
#include <linux/radeon_kfd.h>
#include <linux/amd-iommu.h>
#include "hsa.h"
#include "mmu.h"

int kvm_hsa_bind_kfd_virtio_be(struct kvm *kvm, const struct task_struct *thread)
{
    int (*kvm_bind_kfd_virtio_be_p)(struct kvm *kvm, const struct task_struct *thread);
    kvm_bind_kfd_virtio_be_p = symbol_request(kvm_bind_kfd_virtio_be);
    if (!kvm_bind_kfd_virtio_be_p) {
        printk("symbol_request(kvm_bind_kfd_virtio_be) fail\n");
        return -EINVAL;
    }

    return kvm_bind_kfd_virtio_be_p(kvm, thread);
}

int kvm_hsa_enable_iommu_nested_translation(struct pci_dev *dev)
{
    int ret;

    printk("=====kvm_hsa_enable_iommu_nested_translation dev=%p\n", dev);

    ret = amd_iommu_enable_nested_translation(dev, PT64_ROOT_LEVEL);  // PT64_ROOT_LEVEL in CPU MMU setting
    if (ret) {
        printk("amd_iommu_enable_nested_translation fail\n");
        return -EINVAL;
    }

    return 0;
}
EXPORT_SYMBOL_GPL(kvm_hsa_enable_iommu_nested_translation);

int kvm_hsa_disable_iommu_nested_translation(struct pci_dev *dev)
{
    int ret;

    printk("=====kvm_hsa_disable_iommu_nested_translation dev=%p\n", dev);

    ret = amd_iommu_enable_nested_translation(dev, 0);  // PT64_ROOT_LEVEL in CPU MMU setting
    if (ret) {
        printk("amd_iommu_enable_nested_translation fail\n");
        return -EINVAL;
    }

    return 0;
}
EXPORT_SYMBOL_GPL(kvm_hsa_disable_iommu_nested_translation);

int kvm_hsa_set_iommu_nested_cr3(struct kvm *kvm, struct pci_dev *dev)
{
    struct kvm_vcpu *vcpu;
    struct kvm_vcpu_arch *arch;
    struct kvm_mmu *mmu;
    hpa_t nested_cr3 = 0;
    int i;
    int ret;

    printk("=====kvm_hsa_set_iommu_nested_cr3, kvm=%p, dev=%p\n", kvm, dev);

    // get stage2 page table from kvm
    for(i=0; i<4; i++) {
        if (kvm->vcpus[i]) {
            vcpu = kvm->vcpus[i];
            arch = &vcpu->arch;
            mmu  = &arch->mmu;
            printk("mmu->get_cr3=%llx, root_hpa=%llx\n", mmu->get_cr3(kvm->vcpus[i]), mmu->root_hpa);
            if (nested_cr3 == 0)
                nested_cr3 = mmu->root_hpa;
            else if (nested_cr3 != mmu->root_hpa) {
                printk("FAIL: different root_hpa for vcpus, 0x%lx 0x%lx\n", nested_cr3, mmu->root_hpa);
                return -EINVAL;
            }
        }
    }

    // send pdev, stage2 page table to IOMMU
    ret = amd_iommu_set_nested_cr3(dev, nested_cr3);  
    if (ret) {
        printk("amd_iommu_set_nested_cr3 fail\n");
        return -EINVAL;
    }

    return 0;
}
EXPORT_SYMBOL_GPL(kvm_hsa_set_iommu_nested_cr3);

void kvm_hsa_read_guest_pgd(struct kvm* kvm, gpa_t gpa)
{
    int i;
    gfn_t gfn = gpa_to_gfn(gpa);
    printk("kvm_hsa_read_guest_pgd, gpa=%llx, gfn=%llx\n", gpa, gfn);
    void *data = __get_free_page(GFP_KERNEL);
    if (!data) {
        printk("kvm_hsa_read_guest_pgd GFP fail\n");
        return;
    }

    if (kvm_read_guest_page(kvm, gfn, data, 0, 4096) < 0) {
        printk("kvm_read_guest_page fault\n");
        return;
    }

    for (i=0; i<PTRS_PER_PGD; i++)
        printk("(%d,%llx) ", i, *((pgd_t*)data+i));
    printk("\n");

    free_page((unsigned long)data);
}
EXPORT_SYMBOL_GPL(kvm_hsa_read_guest_pgd);

hpa_t kvm_hsa_translate_gpa_to_hpa(struct kvm *kvm, gpa_t gpa)
{
    gfn_t gfn = gpa_to_gfn(gpa);
    hpa_t hpa;
    pfn_t pfn;
    bool writable;

    pfn = gfn_to_pfn_prot(kvm, gfn, 1, &writable);
    hpa = pfn_to_hpa(pfn);
    printk("kvm_hsa_translate_gfn_to_pfn, hpa=0x%llx, writable=%d\n", hpa, writable);
    return hpa;
//    return gfn_to_pfn_prot(kvm, gpa, false, NULL);
}
EXPORT_SYMBOL_GPL(kvm_hsa_translate_gpa_to_hpa);

