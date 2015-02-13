#ifndef AMD_IOMMU_VM_PPR_H
#define AMD_IOMMU_VM_PPR_H

#include <linux/mm_types.h>
#include <linux/eventfd.h>

#define MAX_PPR_LOG_ENTRY 100 
#define VM_PPR_SIZE PAGE_SIZE

struct ppr_log {
    u64 vm_task;
    u64 vm_mm;
    u64 address;
    int write;
    u64 fault;      // fault address used for finish_ppr_tag
};

/* FIXME: Size of this structure cannot exceed PAGE_SIZE.
          Because this is mmap from guest OS.
          Add lock to head, tail, vm_consume_head.
*/
struct iommu_vm_ppr {
    struct hlist_node node;
    u64 virtio_be_mm;
    struct ppr_log ppr_log_region[MAX_PPR_LOG_ENTRY];
    int head;               // increased by iommu-vm-ppr when finish_ppr_tag
    int tail;               // increased by iommu-vm-ppr when new guest ppr request
    int vm_consume_head;    // increased by guest OS when it fix page fault
    struct eventfd_ctx *call_ctx;
};

#endif
