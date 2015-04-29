#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kvm_types.h>
#include <linux/radeon_kfd.h>
#include <linux/amd-iommu.h>
#include <linux/highmem.h>
#include "mmu.h"
#include "hsa.h"

static struct pci_dev *hsa_dev;

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

int kvm_hsa_is_iommu_nested_translation(void)
{
    if (hsa_dev == NULL)
        return 0;
    return amd_iommu_is_nested_translation(hsa_dev)>0? 1: 0;
}
EXPORT_SYMBOL(kvm_hsa_is_iommu_nested_translation);

int kvm_hsa_enable_iommu_nested_translation(struct pci_dev *dev)
{
    int ret;

    printk("=====kvm_hsa_enable_iommu_nested_translation dev=%p\n", dev);
    if (!hsa_dev)
        hsa_dev = dev;

    ret = amd_iommu_enable_nested_translation(dev, PT64_ROOT_LEVEL);  // PT64_ROOT_LEVEL in CPU MMU setting
    if (ret) {
        printk("amd_iommu_enable_nested_translation fail\n");
        return -EINVAL;
    }

    return 0;
}
EXPORT_SYMBOL_GPL(kvm_hsa_enable_iommu_nested_translation);

int kvm_hsa_disable_iommu_nested_translation(void)   // reset hsa_dev
{
    int ret;

    printk("=====kvm_hsa_disable_iommu_nested_translation hsa_dev=%p\n", hsa_dev);
    if (hsa_dev == NULL)
        return 1;

    ret = amd_iommu_disable_nested_translation(hsa_dev);
    if (ret) {
        printk("amd_iommu_disable_nested_translation fail\n");
        return -EINVAL;
    }
    hsa_dev = NULL;

    return 0;
}
EXPORT_SYMBOL_GPL(kvm_hsa_disable_iommu_nested_translation);

int kvm_hsa_resume_iommu_nested_translation(void)
{
    int ret;

    printk("=====kvm_hsa_resume_iommu_nested_translation hsa_dev=%p\n", hsa_dev);
    BUG_ON(hsa_dev == NULL);

    ret = amd_iommu_enable_nested_translation(hsa_dev, PT64_ROOT_LEVEL);  // PT64_ROOT_LEVEL in CPU MMU setting
    if (ret) {
        printk("amd_iommu_resume_nested_translation fail\n");
        return -EINVAL;
    }

    return 0;
}
EXPORT_SYMBOL_GPL(kvm_hsa_resume_iommu_nested_translation);

int kvm_hsa_stop_iommu_nested_translation(void)     // not reset hsa_dev
{
    int ret;

    printk("=====kvm_hsa_stop_iommu_nested_translation hsa_dev=%p\n", hsa_dev);
    if (hsa_dev == NULL)
        return 1;

    ret = amd_iommu_disable_nested_translation(hsa_dev);
    if (ret) {
        printk("amd_iommu_disable_nested_translation fail\n");
        return -EINVAL;
    }

    return 0;
}
EXPORT_SYMBOL_GPL(kvm_hsa_stop_iommu_nested_translation);

int kvm_hsa_set_iommu_nested_cr3(hpa_t root_hpa)
{
    int ret;

    BUG_ON(hsa_dev == NULL);

    printk("=====kvm_hsa_set_iommu_nested_cr3, dev=%p, root_hpa=%llx\n", hsa_dev, root_hpa);

    // send pdev, stage2 page table to IOMMU
    ret = amd_iommu_set_nested_cr3(hsa_dev, root_hpa);  
    if (ret) {
        printk("amd_iommu_set_nested_cr3 fail\n");
        return -EINVAL;
    }

    return 0;
}
EXPORT_SYMBOL_GPL(kvm_hsa_set_iommu_nested_cr3);
/*
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
*/
void walk_page_table(hpa_t root_hpa, unsigned long addr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    int offset = addr & 0x1fffff;
    printk("walk_page_table, offset=0x%x\n", offset);

    pgd = (pgd_t*)(__va(root_hpa) + pgd_index(addr));
    if (!pgd_present(*pgd))
        return NULL;
    printk("pgd=%p, pgd_val=%llx\n", pgd, pgd_val(*pgd));
    
    pud = pud_offset(pgd, addr);
    if (!pud_present(*pud))
        return NULL;
    printk("pud=%p, pud_val=%llx\n", pud, pud_val(*pud));
    
    pmd = pmd_offset(pud, addr);
    if (!pmd_present(*pmd))
        return NULL;
    printk("pmd=%p, pmd_val=%llx\n", pmd, pmd_val(*pmd));

    pte = pte_offset_map(pmd, addr);
    if (pte_present(*pte)) {
        printk("pte=%p, pte_val=%llx\n", pte, pte_val(*pte));   
        
        struct page *page = pte_page(*pte);
        void *map = kmap(page);
        printk("map=%p, %d\n", map+offset, *(int*)(map+offset));

        kunmap(page);
        pte_unmap(pte);
    }
}

int kvm_hsa_iommu_nested_page_fault(struct kvm *kvm, gpa_t gpa, u32 flags)
{
    struct kvm_vcpu *vcpu;
    struct kvm_vcpu_arch *arch;
    struct kvm_mmu *mmu;
    u32 error_code = 0;
    int ret;

    vcpu = kvm->vcpus[0];
    arch = &vcpu->arch;
    mmu  = &arch->mmu;

    if (flags & PPR_FAULT_WRITE)
        error_code |= PFERR_WRITE_MASK;
    if (flags & PPR_FAULT_GN)
        error_code |= PFERR_USER_MASK;
    if (flags & IDENTICAL_MAPPING_MASK)     // for mqd's identical mapping
        error_code |= IDENTICAL_MAPPING_MASK; 
    
    printk("=====kvm_hsa_iommu_nested_page_fault, kvm=%p, gpa=%llx, flags=%d, error=%x\n", kvm, gpa, flags, error_code);
    return mmu->page_fault(kvm->vcpus[0], gpa, error_code, false);  
}
EXPORT_SYMBOL_GPL(kvm_hsa_iommu_nested_page_fault);

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

