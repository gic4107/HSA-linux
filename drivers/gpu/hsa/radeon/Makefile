#
# Makefile for Heterogenous System Architecture support for AMD Radeon devices
#

radeon_kfd-y	:= kfd_module.o kfd_device.o kfd_chardev.o \
		kfd_pasid.o kfd_topology.o kfd_process.o \
		kfd_doorbell.o

obj-$(CONFIG_HSA_RADEON)	+= radeon_kfd.o
