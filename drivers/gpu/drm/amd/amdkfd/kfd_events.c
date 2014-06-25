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

#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include "kfd_priv.h"
#include "kfd_events.h"

/* A task can only be on a single wait_queue at a time, but we need to support
 * waiting on multiple events (any/all).
 * Instead of each event simply having a wait_queue with sleeping tasks, it has a
 * singly-linked list of tasks.
 * A thread that wants to sleep creates an array of these, one for each event
 * and adds one to each event's waiter chain.
 */
struct kfd_event_waiter {
	struct list_head waiters;
	struct task_struct *sleeping_task;

	/* Transitions to true when the event this belongs to is signaled. */
	bool activated;
};

/* Over-complicated pooled allocator for event notification slots.
 *
 * Each signal event needs a 64-bit signal slot where the signaler will write a 1
 * before sending an interrupt.l (This is needed because some interrupts do not
 * contain enough spare data bits to identify an event.)
 * We get whole pages from vmalloc and map them to the process VA.
 * Individual signal events are then allocated a slot in a page.
 */

struct signal_page {
	struct list_head event_pages;	/* kfd_process.signal_event_pages */
	kfd_signal_slot_t *kernel_address;
	kfd_signal_slot_t __user *user_address;
	uint32_t page_index;		/* Index into the mmap aperture. */
	unsigned int free_slots;
	unsigned long used_slot_bitmap[0];
};

#define SLOTS_PER_PAGE (PAGE_SIZE / sizeof(kfd_signal_slot_t))
#define SLOT_BITMAP_SIZE BITS_TO_LONGS(SLOTS_PER_PAGE)
#define BITS_PER_PAGE (ilog2(SLOTS_PER_PAGE)+1)
#define SIGNAL_PAGE_SIZE (sizeof(struct signal_page) + SLOT_BITMAP_SIZE * sizeof(long))

/* For signal events, the event ID is broken down as follows:
 * bit 31: 1 (0 would indicate a non-signal event)
 * bit 28-30: unused, 0
 * bit 27 - (27 - BITS_PER_PAGE + 1): slot index in page
 * bits 0 - (27 - BITS_PER_PAGE): page index
 *
 * This breakdown is chosen because, for the foreseeable future, HW supports
 * (up to) 28 bits of sender-defined data in the interrupt.
 * (And not all blocks actually allow arbitrary setting of all 28 bits.)
 *
 * For x86-64 with 4K pages, we have BITS_PER_PAGE = 9 so page index is bits 0-18,
 * slot index is 19-27.
 */
#define INTERRUPT_DATA_BITS 28
#define SIGNAL_EVENT_ID_SLOT_SHIFT (INTERRUPT_DATA_BITS - BITS_PER_PAGE)

static kfd_signal_slot_t *page_slots(struct signal_page *page)
{
	return page->kernel_address;
}

static bool
allocate_free_slot(struct kfd_process *process,
		   struct signal_page **out_page,
		   unsigned int *out_slot_index)
{
	struct signal_page *page;

	list_for_each_entry(page, &process->signal_event_pages, event_pages) {
		if (page->free_slots > 0) {
			unsigned int slot = find_first_zero_bit(page->used_slot_bitmap, SLOTS_PER_PAGE);
			__set_bit(slot, page->used_slot_bitmap);
			page->free_slots--;

			page_slots(page)[slot] = UNSIGNALED_EVENT_SLOT;

			*out_page = page;
			*out_slot_index = slot;
			return true;
		}
	}

	return false;
}

static int map_signal_page_to_user(struct file *devkfd, struct signal_page *page)
{
	void __user *user_address;

#if 0
	user_address = (void __user *)vm_mmap(devkfd, 0, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED,
					      (KFD_MMAP_EVENTS_START + page->page_index) << PAGE_SHIFT);
#endif

	if (IS_ERR(user_address))
		return PTR_ERR(user_address);

	page->user_address = user_address;

	return 0;
}

#define list_tail_entry(head, type, member) \
	list_entry((head)->prev, type, member)

bool allocate_signal_page(struct file *devkfd, struct kfd_process *p)
{
	void *backing_store;
	struct signal_page *page;

	page = kzalloc(SIGNAL_PAGE_SIZE, GFP_KERNEL);
	if (!page)
		goto fail_alloc_signal_page;

	page->free_slots = SLOTS_PER_PAGE;

	backing_store = vmalloc(PAGE_SIZE);
	if (!backing_store)
		goto fail_alloc_signal_store;

	memset(backing_store, 0, PAGE_SIZE); /* prevent user-mode info leaks */
	page->kernel_address = backing_store;

	if (list_empty(&p->signal_event_pages))
		/* This is a hack to ensure the signal / event ID is never 0. It's needed
		 * because the event signaller writes the event ID into the event slot
		 * and we can't distinguish 0 from unsignalled. */
		page->page_index = 1;
	else
		page->page_index = list_tail_entry(&p->signal_event_pages,
						   struct signal_page,
						   event_pages)->page_index + 1;

	list_add(&page->event_pages, &p->signal_event_pages);

	if (map_signal_page_to_user(devkfd, page))
		goto fail_map_signal_page;

	return true;

fail_map_signal_page:
	list_del(&page->event_pages);
	vfree(backing_store);
fail_alloc_signal_store:
	kfree(page);
fail_alloc_signal_page:
	return false;
}

static bool
allocate_event_notification_slot(struct file *devkfd, struct kfd_process *p,
				 struct signal_page **page,
				 unsigned int *signal_slot_index)
{
	if (!allocate_free_slot(p, page, signal_slot_index)) {
		allocate_signal_page(devkfd, p);
		return allocate_free_slot(p, page, signal_slot_index);
	}

	return true;
}

/* Given the kernel-mode pointer to a signal notification slot, return the page
 * that it belongs to.
 * Requires that p->event_mutex is held and p isn't going away.
 * We do this when destroying an event, maybe the event should just store the page pointer.
 */
struct signal_page *slot_to_page(struct kfd_process *p, kfd_signal_slot_t *slot)
{
	struct signal_page *page;

	list_for_each_entry(page, &p->signal_event_pages, event_pages) {
		kfd_signal_slot_t *slots = page_slots(page);

		if (slot >= slots && slot < slots + SLOTS_PER_PAGE)
			return page;
	}

	return NULL;
}

/* Assumes that the process's event_mutex is locked. */
void release_event_notification_slot(struct signal_page *page, size_t slot_index)
{
	__clear_bit(slot_index, page->used_slot_bitmap);
	page->free_slots++;

	/* We don't free signal pages, they are retained by the process
	 * and reused until it exits. */
}

struct signal_page *lookup_signal_page_by_index(struct kfd_process *p,
						unsigned int page_index)
{
	struct signal_page *page;

	/* This is safe because we don't delete signal pages until the process exits. */
	list_for_each_entry(page, &p->signal_event_pages, event_pages)
		if (page->page_index == page_index)
			return page;

	return NULL;
}

/* Assumes that p->event_mutex is held and of course that p is not going away (current or locked). */
static struct kfd_event *lookup_event_by_id(struct kfd_process *p, uint32_t id)
{
	struct kfd_event *ev;

	hash_for_each_possible(p->events, ev, events, id)
		if (ev->event_id == id)
			return ev;

	return NULL;
}

static u32 make_signal_event_id(struct signal_page *page,
					 unsigned int signal_slot_index)
{
	return page->page_index | (signal_slot_index << SIGNAL_EVENT_ID_SLOT_SHIFT);
}

/* Produce a kfd event id for a nonsignal event.
 * These are arbitrary numbers, so we do a sequential search through the hash table
 * for an unused number.
 */
static u32 make_nonsignal_event_id(struct kfd_process *p)
{
	u32 id;

	for (id = p->next_nonsignal_event_id;
	     id < KFD_LAST_NONSIGNAL_EVENT_ID && lookup_event_by_id(p, id) != NULL;
	     id++)
		;

	if (id < KFD_LAST_NONSIGNAL_EVENT_ID) {

		/* What if id == LAST_NONSIGNAL_EVENT_ID - 1?
		 * Then next_nonsignal_event_id = LAST_NONSIGNAL_EVENT_ID so the first loop
		 * fails immediately and we proceed with the wraparound loop below.
		 */
		p->next_nonsignal_event_id = id + 1;

		return id;
	}

	for (id = KFD_FIRST_NONSIGNAL_EVENT_ID;
	     id < KFD_LAST_NONSIGNAL_EVENT_ID && lookup_event_by_id(p, id) != NULL;
	     id++)
		;


	if (id < KFD_LAST_NONSIGNAL_EVENT_ID) {
		p->next_nonsignal_event_id = id + 1;
		return id;
	} else {
		p->next_nonsignal_event_id = KFD_FIRST_NONSIGNAL_EVENT_ID;
		return 0;
	}
}

static struct kfd_event *
lookup_event_by_page_slot(struct kfd_process *p,
			  struct signal_page *page, unsigned int signal_slot)
{
	return lookup_event_by_id(p, make_signal_event_id(page, signal_slot));
}

static int
create_signal_event(struct file *devkfd, struct kfd_process *p, struct kfd_event *ev)
{
	if (!allocate_event_notification_slot(devkfd, p, &ev->signal_page, &ev->signal_slot_index))
		return -ENOMEM;

	ev->user_signal_address = &ev->signal_page->user_address[ev->signal_slot_index];

	ev->event_id = make_signal_event_id(ev->signal_page, ev->signal_slot_index);

	return 0;
}

/* No non-signal events are supported yet.
 * We create them as events that never signal. Set event calls from user-mode are failed. */
static int
create_other_event(struct kfd_process *p, struct kfd_event *ev)
{
	ev->event_id = make_nonsignal_event_id(p);
	if (ev->event_id == 0)
		return -ENOMEM;

	return 0;
}

void kfd_event_init_process(struct kfd_process *p)
{
	mutex_init(&p->event_mutex);
	hash_init(p->events);
	INIT_LIST_HEAD(&p->signal_event_pages);
	p->next_nonsignal_event_id = KFD_FIRST_NONSIGNAL_EVENT_ID;
}

static void destroy_event(struct kfd_event *ev)
{
	if (ev->signal_page != NULL)
		release_event_notification_slot(ev->signal_page, ev->signal_slot_index);
	hash_del(&ev->events);
	kfree(ev);
}

static void destroy_events(struct kfd_process *p)
{
	struct kfd_event *ev;
	struct hlist_node *tmp;
	unsigned int hash_bkt;

	hash_for_each_safe(p->events, hash_bkt, tmp, ev, events)
		destroy_event(ev);
}

/* We assume that the process is being destroyed and there is no need to unmap the pages
 * or keep bookkeeping data in order. */
static void shutdown_signal_pages(struct kfd_process *p)
{
	struct signal_page *page, *tmp;

	list_for_each_entry_safe(page, tmp, &p->signal_event_pages, event_pages) {
		vfree(page->kernel_address);
		kfree(page);
	}
}

void kfd_event_free_process(struct kfd_process *p)
{
	destroy_events(p);
	shutdown_signal_pages(p);
}

int kfd_event_create(struct file *devkfd, struct kfd_process *p,
		     uint32_t event_type, bool auto_reset, uint32_t node_id,
		     uint32_t *event_id, void __user **event_trigger_address, uint32_t *event_trigger_data)
{
	int ret = 0;

	struct kfd_event *ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return -ENOMEM;

	ev->type = event_type;
	ev->auto_reset = auto_reset;
	ev->signaled = false;

	INIT_LIST_HEAD(&ev->waiters);

	mutex_lock(&p->event_mutex);

	switch (event_type) {
	case KFD_EVENT_TYPE_SIGNAL:
		ret = create_signal_event(devkfd, p, ev);
		break;
	default:
		ret = create_other_event(p, ev);
		break;
	}

	if (!ret) {
		hash_add(p->events, &ev->events, ev->event_id);

		*event_id = ev->event_id;
		*event_trigger_address = ev->user_signal_address;
		*event_trigger_data = ev->event_id;
	} else {
		kfree(ev);
	}

	mutex_unlock(&p->event_mutex);

	return ret;
}

/* Assumes that p is current. */
int kfd_event_destroy(struct kfd_process *p, uint32_t event_id)
{
	struct kfd_event *ev;
	int ret = 0;

	mutex_lock(&p->event_mutex);

	ev = lookup_event_by_id(p, event_id);

	if (ev)
		if (!list_empty(&ev->waiters)) {
			pr_err("kfd: can't destroy event with waiters\n");
			ret = -EBUSY;
		}
		else {
			destroy_event(ev);
		}
	else
		ret = -EINVAL;

	mutex_unlock(&p->event_mutex);
	return ret;
}

static void set_event(struct kfd_event *ev)
{
	struct kfd_event_waiter *waiter;
	struct kfd_event_waiter *next;

	ev->signaled = true;

	list_for_each_entry_safe(waiter, next, &ev->waiters, waiters) {
		waiter->activated = true;

		/* _init because free_waiters will call list_del */
		list_del_init(&waiter->waiters);

		wake_up_process(waiter->sleeping_task);
	}

	if (ev->auto_reset)
		ev->signaled = false;
}

/* Assumes that p is current. */
int kfd_set_event(struct kfd_process *p, uint32_t event_id)
{
	int ret = 0;
	struct kfd_event *ev;

	mutex_lock(&p->event_mutex);

	ev = lookup_event_by_id(p, event_id);

	if (ev || ev->type == KFD_EVENT_TYPE_SIGNAL)
		set_event(ev);
	else
		ret = -EINVAL;

	mutex_unlock(&p->event_mutex);
	return ret;
}

static void reset_event(struct kfd_event *ev)
{
	ev->signaled = false;
}

/* Assumes that p is current. */
int kfd_reset_event(struct kfd_process *p, uint32_t event_id)
{
	int ret = 0;
	struct kfd_event *ev;

	mutex_lock(&p->event_mutex);

	ev = lookup_event_by_id(p, event_id);

	if (ev || ev->type == KFD_EVENT_TYPE_SIGNAL)
		reset_event(ev);
	else
		ret = -EINVAL;

	mutex_unlock(&p->event_mutex);
	return ret;

}

static void acknowledge_signal(struct kfd_process *p, struct kfd_event *ev)
{
	page_slots(ev->signal_page)[ev->signal_slot_index] = UNSIGNALED_EVENT_SLOT;
}

static bool is_slot_signaled(struct signal_page *page, unsigned int index)
{
	return page_slots(page)[index] != UNSIGNALED_EVENT_SLOT;
}

static void set_event_from_interrupt(struct kfd_process *p, struct kfd_event *ev)
{
	if (ev && ev->type == KFD_EVENT_TYPE_SIGNAL) {
		acknowledge_signal(p, ev);
		set_event(ev);
	}
}

void kfd_signal_event_interrupt(unsigned int pasid, uint32_t partial_id,
				uint32_t valid_id_bits)
{
	struct kfd_event *ev;

	/* Because we are called from arbitrary context (workqueue) as opposed
	 * to process context, kfd_process could attempt to exit while we are
	 * running so the lookup function returns a locked process. */
	struct kfd_process *p = kfd_lookup_process_by_pasid(pasid);
	if (!p)
		return; /* Presumably process exited. */

	mutex_lock(&p->event_mutex);

	if (valid_id_bits >= INTERRUPT_DATA_BITS) {
		/* Partial ID is a full ID. */
		ev = lookup_event_by_id(p, partial_id);
		set_event_from_interrupt(p, ev);
	} else {
		/* Partial ID is in fact partial. For now we completely ignore it,
		 * but we could use any bits we did receive to search faster. */
		struct signal_page *page;
		unsigned i;

		list_for_each_entry(page, &p->signal_event_pages, event_pages) {
			for (i = 0; i < SLOTS_PER_PAGE; i++) {
				if (is_slot_signaled(page, i)) {
					ev = lookup_event_by_page_slot(p, page, i);
					set_event_from_interrupt(p, ev);
				}
			}
		}
	}

	mutex_unlock(&p->event_mutex);
	mutex_unlock(&p->mutex);
}

static struct kfd_event_waiter *alloc_event_waiters(uint32_t num_events)
{
	struct kfd_event_waiter *event_waiters;
	uint32_t i;

	event_waiters = kmalloc(num_events * sizeof(struct kfd_event_waiter), GFP_KERNEL);

	if (event_waiters) {
		for (i = 0; i < num_events; i++) {
			INIT_LIST_HEAD(&event_waiters[i].waiters);
			event_waiters[i].sleeping_task = current;
			event_waiters[i].activated = false;
		}
	}

	return event_waiters;
}

static int init_event_waiter(struct kfd_process *p, struct kfd_event_waiter *waiter, uint32_t event_id)
{
	struct kfd_event *ev = lookup_event_by_id(p, event_id);

	if (!ev)
		return -EINVAL;

	waiter->activated = ev->signaled;

	list_add(&waiter->waiters, &ev->waiters);

	return 0;
}

static bool test_event_condition(bool all, uint32_t num_events, struct kfd_event_waiter *event_waiters)
{
	uint32_t i;
	uint32_t activated_count = 0;

	for (i = 0; i < num_events; i++) {
		if (event_waiters[i].activated) {
			if (!all)
				return true;

			activated_count++;
		}
	}

	return activated_count == num_events;
}

static long user_timeout_to_jiffies(uint32_t user_timeout_ms)
{
	if (user_timeout_ms == KFD_EVENT_TIMEOUT_IMMEDIATE)
		return 0;

	if (user_timeout_ms == KFD_EVENT_TIMEOUT_INFINITE)
		return MAX_SCHEDULE_TIMEOUT;

	/* msecs_to_jiffies interprets all values above 2^31-1 as infinite,
	 * but we consider them finite.
	 * This hack is wrong, but nobody is likely to notice. */
	user_timeout_ms = min_t(uint32_t, user_timeout_ms, 0x7FFFFFFF);

	return msecs_to_jiffies(user_timeout_ms) + 1;
}

static void free_waiters(uint32_t num_events, struct kfd_event_waiter *waiters)
{
	uint32_t i;

	for (i = 0; i < num_events; i++)
		list_del(&waiters[i].waiters);

	kfree(waiters);
}

int kfd_wait_on_events(struct kfd_process *p,
		       uint32_t num_events, const uint32_t __user *event_ids,
		       bool all, uint32_t user_timeout_ms,
		       enum kfd_event_wait_result *wait_result)
{
	uint32_t i;
	int ret = 0;
	struct kfd_event_waiter *event_waiters = NULL;
	long timeout = user_timeout_to_jiffies(user_timeout_ms);

	mutex_lock(&p->event_mutex);

	event_waiters = alloc_event_waiters(num_events);
	if (!event_waiters) {
		ret = -ENOMEM;
		goto fail;
	}

	for (i = 0; i < num_events; i++) {
		uint32_t event_id;
		ret = get_user(event_id, &event_ids[i]);
		if (ret)
			goto fail;

		ret = init_event_waiter(p, &event_waiters[i], event_id);
		if (ret)
			goto fail;
	}

	mutex_unlock(&p->event_mutex);

	while (true) {
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		if (signal_pending(current)) {
			/*
			 * This is wrong when a nonzero, non-infinite timeout is specified.
			 * We need to use ERESTARTSYS_RESTARTBLOCK, but struct restart_block
			 * contains a union with data for each user and it's in generic
			 * kernel code that I don't want to touch yet.
			 */
			ret = -ERESTARTSYS;
			break;
		}

		if (test_event_condition(all, num_events, event_waiters)) {
			*wait_result = KFD_WAIT_COMPLETE;
			break;
		}

		if (timeout <= 0) {
			*wait_result = KFD_WAIT_TIMEOUT;
			break;
		}

		timeout = schedule_timeout_interruptible(timeout);
	}
	__set_current_state(TASK_RUNNING);

	mutex_lock(&p->event_mutex);
	free_waiters(num_events, event_waiters);
	mutex_unlock(&p->event_mutex);

	return ret;

fail:
	if (event_waiters)
		free_waiters(num_events, event_waiters);

	mutex_unlock(&p->event_mutex);

	*wait_result = KFD_WAIT_ERROR;

	return ret;
}

int radeon_kfd_event_mmap(struct kfd_process *p,
			  struct vm_area_struct *vma)
{
#if 0
	unsigned int page_index;
	unsigned long pfn;
	struct signal_page *page;

	if (vma->vm_end - vma->vm_start != PAGE_SIZE) {
		pr_debug("start address(0x%lx) - end address(0x%lx) != len(0x%lx)\n", vma->vm_end, vma->vm_start, PAGE_SIZE);
		return -EINVAL;
	}

	page_index = vma->vm_pgoff - KFD_MMAP_EVENTS_START;

	page = lookup_signal_page_by_index(p, page_index);
	if (!page) {
		/* Probably KFD bug, but mmap is user-accessible. */
		pr_debug("signal page could not be found for page_index %u\n", page_index);
		return -EINVAL;
	}

	pfn = vmalloc_to_pfn(page->kernel_address);

	vma->vm_flags |= VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_NORESERVE
		       | VM_DONTDUMP | VM_PFNMAP;

	pr_debug("kfd: mapping signal page\n"
			 "     target user address == 0x%016llX\n"
			 "     pfn                 == 0x%016lX\n"
			 "     vm_flags            == 0x%08lX\n"
			 "     size                == 0x%08lX\n",
			 (long long unsigned int) vma->vm_start,
			 (unsigned long)pfn, vma->vm_flags, PAGE_SIZE);

	/* mapping the page to user process */
	return remap_pfn_range(vma, vma->vm_start, pfn, PAGE_SIZE, vma->vm_page_prot);
#else
	return 0;
#endif
}
