#
# Makefile for Heterogenous System Architecture support for AMD Radeon devices
#

radeon_kfd-y	:= kfd_module.o kfd_device.o kfd_chardev.o \
		kfd_pasid.o kfd_topology.o kfd_process.o \
		kfd_doorbell.o kfd_sched_cik_static.o kfd_registers.o \
		kfd_vidmem.o kfd_interrupt.o kfd_aperture.o \
		kfd_queue.o kfd_hw_pointer_store.o kfd_mqd_manager.o \
		kfd_kernel_queue.o kfd_packet_manager.o

obj-$(CONFIG_HSA_RADEON)	+= radeon_kfd.o
