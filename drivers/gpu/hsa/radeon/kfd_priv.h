/*
 * Copyright 2014 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef KFD_PRIV_H_INCLUDED
#define KFD_PRIV_H_INCLUDED

#include <linux/hashtable.h>
#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/radeon_kfd.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include "kfd_hw_pointer_store.h"

struct kfd_scheduler_class;

#define MAX_KFD_DEVICES 16	/* Global limit - only MAX_KFD_DEVICES will be supported by KFD. */
#define MAX_PROCESS_QUEUES 1024	/* Per-process limit. Each process can only create MAX_PROCESS_QUEUES across all devices. */
#define MAX_DOORBELL_INDEX MAX_PROCESS_QUEUES
#define KFD_SYSFS_FILE_MODE 0444

/* We multiplex different sorts of mmap-able memory onto /dev/kfd.
** We figure out what type of memory the caller wanted by comparing the mmap page offset to known ranges. */
#define KFD_MMAP_DOORBELL_START	(((1ULL << 32)*1) >> PAGE_SHIFT)
#define KFD_MMAP_DOORBELL_END	(((1ULL << 32)*2) >> PAGE_SHIFT)
#define KFD_MMAP_RPTR_START	KFD_MMAP_DOORBELL_END
#define KFD_MMAP_RPTR_END	(((1ULL << 32)*3) >> PAGE_SHIFT)
#define KFD_MMAP_WPTR_START	KFD_MMAP_RPTR_END
#define KFD_MMAP_WPTR_END	(((1ULL << 32)*4) >> PAGE_SHIFT)

/*
 * When working with cp scheduler we should assign the HIQ manually or via the radeon driver
 * to a fixed hqd slot, here are the fixed HIQ hqd slot definitions for Kaveri.
 * In Kaveri only the first ME queues participates in the cp scheduling taking that in mind
 * we set the HIQ slot in the second ME.
 */
#define KFD_CIK_HIQ_PIPE 4
#define KFD_CIK_HIQ_QUEUE 0

/* GPU ID hash width in bits */
#define KFD_GPU_ID_HASH_WIDTH 16

/* Macro for allocating structures */
#define kfd_alloc_struct(ptr_to_struct)	((typeof(ptr_to_struct)) kzalloc(sizeof(*ptr_to_struct), GFP_KERNEL));

/* Kernel module parameter to specify the scheduling policy */
extern int sched_policy;

enum kfd_sched_policy {
	KFD_SCHED_POLICY_HWS = 0,
	KFD_SCHED_POLICY_HWS_NO_OVERSUBSCRIPTION,
	KFD_SCHED_POLICY_NO_HWS
};

/* Large enough to hold the maximum usable pasid + 1.
** It must also be able to store the number of doorbells reported by a KFD device. */
typedef unsigned int pasid_t;

/* Type that represents a HW doorbell slot. */
typedef u32 doorbell_t;

enum cache_policy {
	cache_policy_coherent,
	cache_policy_noncoherent
};

struct kfd_device_info {
	const struct kfd_scheduler_class *scheduler_class;
	unsigned int max_pasid_bits;
	size_t ih_ring_entry_size;
};

struct kfd_dev {
	struct kgd_dev *kgd;

	const struct kfd_device_info *device_info;
	struct pci_dev *pdev;

	void __iomem *regs;

	bool init_complete;

	unsigned int id;		/* topology stub index */

	phys_addr_t doorbell_base;	/* Start of actual doorbells used by KFD. It is aligned for mapping into user mode. */
	size_t doorbell_id_offset;	/* Doorbell offset (from KFD doorbell to HW doorbell, GFX reserved some at the start). */
	size_t doorbell_process_limit;	/* Number of processes we have doorbell space for. */
	u32 __iomem *doorbell_kernel_ptr; /* this is a pointer for a doorbells page used by kernel queue */

	struct kgd2kfd_shared_resources shared_resources;

	struct kfd_scheduler *scheduler;

	/* Interrupts of interest to KFD are copied from the HW ring into a SW ring. */
	bool interrupts_active;
	void *interrupt_ring;
	size_t interrupt_ring_size;
	atomic_t interrupt_ring_rptr;
	atomic_t interrupt_ring_wptr;
	struct work_struct interrupt_work;
	spinlock_t interrupt_lock;

	/* QCM Device instance */
	struct device_queue_manager *dqm;
};

/* KGD2KFD callbacks */
void kgd2kfd_exit(void);
struct kfd_dev *kgd2kfd_probe(struct kgd_dev *kgd, struct pci_dev *pdev);
bool kgd2kfd_device_init(struct kfd_dev *kfd,
			 const struct kgd2kfd_shared_resources *gpu_resources);
void kgd2kfd_device_exit(struct kfd_dev *kfd);

extern const struct kfd2kgd_calls *kfd2kgd;


/* KFD2KGD callback wrappers */
void radeon_kfd_lock_srbm_index(struct kfd_dev *kfd);
void radeon_kfd_unlock_srbm_index(struct kfd_dev *kfd);

enum kfd_mempool {
	KFD_MEMPOOL_SYSTEM_CACHEABLE = 1,
	KFD_MEMPOOL_SYSTEM_WRITECOMBINE = 2,
	KFD_MEMPOOL_FRAMEBUFFER = 3,
};

struct kfd_mem_obj_s; /* Dummy struct just to make kfd_mem_obj* a unique pointer type. */
typedef struct kfd_mem_obj_s *kfd_mem_obj;

int radeon_kfd_vidmem_alloc(struct kfd_dev *kfd, size_t size, size_t alignment, enum kfd_mempool pool, kfd_mem_obj *mem_obj);
void radeon_kfd_vidmem_free(struct kfd_dev *kfd, kfd_mem_obj mem_obj);
int radeon_kfd_vidmem_gpumap(struct kfd_dev *kfd, kfd_mem_obj mem_obj, uint64_t *vmid0_address);
void radeon_kfd_vidmem_ungpumap(struct kfd_dev *kfd, kfd_mem_obj mem_obj);
int radeon_kfd_vidmem_kmap(struct kfd_dev *kfd, kfd_mem_obj mem_obj, void **ptr);
void radeon_kfd_vidmem_unkmap(struct kfd_dev *kfd, kfd_mem_obj mem_obj);
int radeon_kfd_vidmem_alloc_map(struct kfd_dev *kfd, kfd_mem_obj *mem_obj, void **ptr, uint64_t *vmid0_address, size_t size);
void radeon_kfd_vidmem_free_unmap(struct kfd_dev *kfd, kfd_mem_obj mem_obj);

/* Character device interface */
int radeon_kfd_chardev_init(void);
void radeon_kfd_chardev_exit(void);
struct device *radeon_kfd_chardev(void);

/* Scheduler */
struct kfd_scheduler;
struct kfd_scheduler_process;
struct kfd_scheduler_queue {
	uint64_t dummy;
};

struct kfd_queue {
	struct kfd_dev *dev;

	/* scheduler_queue must be last. It is variable sized (dev->device_info->scheduler_class->queue_size) */
	struct kfd_scheduler_queue scheduler_queue;
};

enum kfd_preempt_type_filter {
	KFD_PREEMPT_TYPE_FILTER_SINGLE_QUEUE,
	KFD_PRERMPT_TYPE_FILTER_ALL_QUEUES,
	KFD_PRERMPT_TYPE_FILTER_BY_PASID
};

enum kfd_preempt_type {
	KFD_PREEMPT_TYPE_WAVEFRONT,
	KFD_PREEMPT_TYPE_WAVEFRONT_RESET
};

enum kfd_queue_type  {
	KFD_QUEUE_TYPE_COMPUTE,
	KFD_QUEUE_TYPE_SDMA,
	KFD_QUEUE_TYPE_HIQ,
	KFD_QUEUE_TYPE_DIQ
};

struct queue_properties {
	enum kfd_queue_type type;
	unsigned int queue_id;
	uint64_t queue_address;
	uint64_t  queue_size;
	uint32_t priority;
	uint32_t queue_percent;
	qptr_t *read_ptr;
	qptr_t *write_ptr;
	qptr_t *doorbell_ptr;
	qptr_t doorbell_off;
	bool is_interop;
	bool is_active;
	/* Not relevant for user mode queues in cp scheduling */
	unsigned int vmid;
};

struct queue {
	struct list_head list;
	void *mqd;
	/* kfd_mem_obj contains the mqd */
	kfd_mem_obj mqd_mem_obj;
	uint64_t gart_mqd_addr; /* needed for cp scheduling */
	struct queue_properties properties;

	/* Used by the queue device manager to track the hqd slot per queue
	 * when using no cp scheduling
	 */
	uint32_t mec;
	uint32_t pipe;
	uint32_t queue;

	struct kfd_process	*process;
	struct kfd_dev		*device;
};

enum KFD_MQD_TYPE {
	KFD_MQD_TYPE_CIK_COMPUTE = 0, /* for no cp scheduling */
	KFD_MQD_TYPE_CIK_HIQ, /* for hiq */
	KFD_MQD_TYPE_CIK_CP, /* for cp queues and diq */
	KFD_MQD_TYPE_CIK_SDMA, /* for sdma queues */
	KFD_MQD_TYPE_MAX
};

struct scheduling_resources {
	unsigned int vmid_mask;
	enum kfd_queue_type type;
	uint64_t queue_mask;
	uint64_t gws_mask;
	uint32_t oac_mask;
	uint32_t gds_heap_base;
	uint32_t gds_heap_size;
};

struct process_queue_manager {
	/* data */
	struct kfd_process	*process;
	unsigned int		num_concurrent_processes;
	struct list_head	queues;
	unsigned long		*queue_slot_bitmap;
};

struct qcm_process_device {
	/* The Device Queue Manager that owns this data */
	struct device_queue_manager *dqm;
	struct process_queue_manager *pqm;
	/* Device Queue Manager lock */
	struct mutex *lock;
	/* Queues list */
	struct list_head queues_list;
	struct list_head priv_queue_list;

	unsigned int queue_count;
	unsigned int vmid;
	bool is_debug;
	/*
	 * All the memory management data should be here too
	 */
	uint64_t gds_context_area;
	uint32_t sh_mem_config;
	uint32_t sh_mem_bases;
	uint32_t sh_mem_ape1_base;
	uint32_t sh_mem_ape1_limit;
	uint32_t page_table_base;
	uint32_t gds_size;
	uint32_t num_gws;
	uint32_t num_oac;
};

/* Data that is per-process-per device. */
struct kfd_process_device {
	/* List of all per-device data for a process. Starts from kfd_process.per_device_data. */
	struct list_head per_device_list;

	/* The device that owns this data. */
	struct kfd_dev *dev;

	/* The user-mode address of the doorbell mapping for this device. */
	doorbell_t __user *doorbell_mapping;

	/* Scheduler process data for this device. */
	struct kfd_scheduler_process *scheduler_process;

	/* Is this process/pasid bound to this device? (amd_iommu_bind_pasid) */
	bool bound;

	/*Apertures*/
	uint64_t lds_base;
	uint64_t lds_limit;
	uint64_t gpuvm_base;
	uint64_t gpuvm_limit;
	uint64_t scratch_base;
	uint64_t scratch_limit;


};

/* Process data */
struct kfd_process {
	/* kfd_process are stored in an mm_struct*->kfd_process* hash table (kfd_processes in kfd_process.c) */
	struct hlist_node kfd_processes;
	struct mm_struct *mm;

	struct mutex mutex;

	/* In any process, the thread that started main() is the lead thread and outlives the rest.
	 * It is here because amd_iommu_bind_pasid wants a task_struct. */
	struct task_struct *lead_thread;

	/* We want to receive a notification when the mm_struct is destroyed. */
	struct mmu_notifier mmu_notifier;

	pasid_t pasid;

	/* List of kfd_process_device structures, one for each device the process is using. */
	struct list_head per_device_data;

	/* The process's queues. */
	size_t queue_array_size;
	struct kfd_queue **queues;	/* Size is queue_array_size, up to MAX_PROCESS_QUEUES. */
	unsigned long allocated_queue_bitmap[DIV_ROUND_UP(MAX_PROCESS_QUEUES, BITS_PER_LONG)];

	/*Is the user space process 32 bit?*/
	bool is_32bit_user_mode;

};

struct kfd_process *radeon_kfd_create_process(const struct task_struct *);
struct kfd_process *radeon_kfd_get_process(const struct task_struct *);

struct kfd_process_device *radeon_kfd_bind_process_to_device(struct kfd_dev *dev, struct kfd_process *p);
void radeon_kfd_unbind_process_from_device(struct kfd_dev *dev, pasid_t pasid);
struct kfd_process_device *radeon_kfd_get_process_device_data(struct kfd_dev *dev, struct kfd_process *p);

bool radeon_kfd_allocate_queue_id(struct kfd_process *p, unsigned int *queue_id);
void radeon_kfd_install_queue(struct kfd_process *p, unsigned int queue_id, struct kfd_queue *queue);
void radeon_kfd_remove_queue(struct kfd_process *p, unsigned int queue_id);
struct kfd_queue *radeon_kfd_get_queue(struct kfd_process *p, unsigned int queue_id);

/* Process device data iterator */
struct kfd_process_device *kfd_get_first_process_device_data(struct kfd_process *p);
struct kfd_process_device *kfd_get_next_process_device_data(struct kfd_process *p, struct kfd_process_device *pdd);
bool kfd_has_process_device_data(struct kfd_process *p);

/* PASIDs */
int radeon_kfd_pasid_init(void);
void radeon_kfd_pasid_exit(void);
bool radeon_kfd_set_pasid_limit(pasid_t new_limit);
pasid_t radeon_kfd_get_pasid_limit(void);
pasid_t radeon_kfd_pasid_alloc(void);
void radeon_kfd_pasid_free(pasid_t pasid);

/* Doorbells */
void radeon_kfd_doorbell_init(struct kfd_dev *kfd);
int radeon_kfd_doorbell_mmap(struct kfd_process *process, struct vm_area_struct *vma);
doorbell_t __user *radeon_kfd_get_doorbell(struct file *devkfd, struct kfd_process *process, struct kfd_dev *dev,
					   unsigned int doorbell_index);
u32 __iomem *radeon_kfd_get_kernel_doorbell(struct kfd_dev *kfd, unsigned int *doorbell_off);
void radeon_kfd_release_kernel_doorbell(struct kfd_dev *kfd, u32 __iomem *db_addr);
u32 read_kernel_doorbell(u32 __iomem *db);
void write_kernel_doorbell(u32 __iomem *db, u32 value);
unsigned int radeon_kfd_queue_id_to_doorbell(struct kfd_dev *kfd, struct kfd_process *process, unsigned int queue_id);
void radeon_kfd_doorbell_unmap(struct kfd_process_device *pdd);

extern struct device *kfd_device;

/* Topology */
int kfd_topology_init(void);
void kfd_topology_shutdown(void);
int kfd_topology_add_device(struct kfd_dev *gpu);
int kfd_topology_remove_device(struct kfd_dev *gpu);
struct kfd_dev *radeon_kfd_device_by_id(uint32_t gpu_id);
struct kfd_dev *radeon_kfd_device_by_pci_dev(const struct pci_dev *pdev);
struct kfd_dev *kfd_topology_enum_kfd_devices(uint8_t idx);

/* MMIO registers */
#define WRITE_REG(dev, reg, value) radeon_kfd_write_reg((dev), (reg), (value))
#define READ_REG(dev, reg) radeon_kfd_read_reg((dev), (reg))
void radeon_kfd_write_reg(struct kfd_dev *dev, uint32_t reg, uint32_t value);
uint32_t radeon_kfd_read_reg(struct kfd_dev *dev, uint32_t reg);

/* Interrupts */
int radeon_kfd_interrupt_init(struct kfd_dev *dev);
void radeon_kfd_interrupt_exit(struct kfd_dev *dev);
void kgd2kfd_interrupt(struct kfd_dev *dev, const void *ih_ring_entry);

/* Power Management */
void kgd2kfd_suspend(struct kfd_dev *dev);
int kgd2kfd_resume(struct kfd_dev *dev);

/*HSA apertures*/
int kfd_init_apertures(struct kfd_process *process);

/* Queue Context Management */
inline uint32_t lower_32(uint64_t x);
inline uint32_t upper_32(uint64_t x);
inline void busy_wait(unsigned long ms);

int init_queue(struct queue **q, struct queue_properties properties);
void uninit_queue(struct queue *q);
void print_queue_properties(struct queue_properties *q);
void print_queue(struct queue *q);

struct mqd_manager *mqd_manager_init(enum KFD_MQD_TYPE type, struct kfd_dev *dev);
struct kernel_queue *kernel_queue_init(struct kfd_dev *dev, enum kfd_queue_type type);
void kernel_queue_uninit(struct kernel_queue *kq);

/* Packet Manager */

#define KFD_HIQ_TIMEOUT (500)

#define KFD_FENCE_COMPLETED (100)
#define KFD_FENCE_INIT   (10)
#define KFD_UNMAP_LATENCY (15)

struct packet_manager {
	struct device_queue_manager *dqm;
	struct kernel_queue *priv_queue;
	struct mutex lock;
	bool allocated;
	kfd_mem_obj ib_buffer_obj;
};

int pm_init(struct packet_manager *pm, struct device_queue_manager *dqm);
void pm_uninit(struct packet_manager *pm);
int pm_send_set_resources(struct packet_manager *pm, struct scheduling_resources *res);
int pm_send_runlist(struct packet_manager *pm, struct list_head *dqm_queues);
int pm_send_query_status(struct packet_manager *pm, uint64_t fence_address, uint32_t fence_value);
int pm_send_unmap_queue(struct packet_manager *pm, enum kfd_queue_type type,
			enum kfd_preempt_type_filter mode, uint32_t filter_param, bool reset);
void pm_release_ib(struct packet_manager *pm);

#endif
