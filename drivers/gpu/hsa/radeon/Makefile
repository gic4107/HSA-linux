#
# Makefile for Heterogenous System Architecture support for AMD Radeon devices
#

ifeq ($(CONFIG_PR_DEBUG), y)
        EXTRA_CFLAGS := -DDEBUG
endif

radeon_kfd-y	:= kfd_module.o kfd_device.o kfd_chardev.o \
		kfd_pasid.o kfd_topology.o kfd_process.o \
		kfd_doorbell.o kfd_sched_cik_static.o kfd_registers.o \
		kfd_vidmem.o kfd_interrupt.o

obj-$(CONFIG_HSA_RADEON)	+= radeon_kfd.o
