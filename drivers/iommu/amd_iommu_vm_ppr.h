#ifndef AMD_IOMMU_VM_PPR_H
#define AMD_IOMMU_VM_PPR_H

#include <linux/mm_types.h>
#include <linux/eventfd.h>

#define MAX_PPR_LOG_ENTRY 50 
#define VM_PPR_SIZE PAGE_SIZE

struct ppr_log {
    u64 vm_task;
    u64 vm_mm;
    u64 address;
    u64 fault;      // fault structure address used for finish_ppr_tag
    u64 start_ns;   // handling start time
    int write;
};

/* FIXME: Size of this structure cannot exceed PAGE_SIZE.
          Because this is mmap from guest OS.
          Add lock to head, tail, vm_consume_head.
*/
struct iommu_vm_ppr {
    struct hlist_node node;
    u64 virtio_be_mm;
    struct ppr_log ppr_log_region[MAX_PPR_LOG_ENTRY];
    volatile int head;               // increased by iommu-vm-ppr when finish_ppr_tag
    volatile int tail;               // increased by iommu-vm-ppr when new guest ppr request
    volatile int vm_consume_head;    // increased by guest OS when it fix page fault
    volatile struct mutex head_lock;
    volatile struct mutex tail_lock;
    volatile struct mutex vm_consume_head_lock;
    struct eventfd_ctx *call_ctx;   // IRQFD to kick guest
};

#endif
