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

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/acpi.h>
#include <linux/hash.h>
#include <linux/cpufreq.h>
#include "virtio_kfd_priv.h"

static struct list_head topology_device_list;
static int topology_crat_parsed;
static struct kfd_system_properties sys_props;
static struct virtkfd_sysfs_info sys_info;

static DECLARE_RWSEM(topology_lock);

#define sysfs_show_gen_prop(buffer, fmt, ...) \
		snprintf(buffer, PAGE_SIZE, "%s"fmt, buffer, __VA_ARGS__)
#define sysfs_show_32bit_prop(buffer, name, value) \
		sysfs_show_gen_prop(buffer, "%s %u\n", name, value)
#define sysfs_show_64bit_prop(buffer, name, value) \
		sysfs_show_gen_prop(buffer, "%s %llu\n", name, value)
#define sysfs_show_32bit_val(buffer, value) \
		sysfs_show_gen_prop(buffer, "%u\n", value)
#define sysfs_show_str_val(buffer, value) \
		sysfs_show_gen_prop(buffer, "%s\n", value)

static ssize_t sysprops_show(struct kobject *kobj, struct attribute *attr,
		char *buffer)
{
	ssize_t ret;

    printk("sysprops_show: %s\n", attr->name);
	/* Making sure that the buffer is an empty string */
	buffer[0] = 0;

	if (attr == &sys_props.attr_genid) {
		ret = sysfs_show_32bit_val(buffer, sys_props.generation_count);
	} else if (attr == &sys_props.attr_props) {
		sysfs_show_64bit_prop(buffer, "platform_oem",
				sys_props.platform_oem);
		sysfs_show_64bit_prop(buffer, "platform_id",
				sys_props.platform_id);
		ret = sysfs_show_64bit_prop(buffer, "platform_rev",
				sys_props.platform_rev);
	} else {
		ret = -EINVAL;
	}

	return ret;
}

static const struct sysfs_ops sysprops_ops = {
	.show = sysprops_show,
};

static struct kobj_type sysprops_type = {
	.sysfs_ops = &sysprops_ops,
};

static ssize_t iolink_show(struct kobject *kobj, struct attribute *attr,
		char *buffer)
{
	ssize_t ret;
	struct kfd_iolink_properties *iolink;

    pr_debug("iolink_show\n");
	/* Making sure that the buffer is an empty string */
	buffer[0] = 0;

	iolink = container_of(attr, struct kfd_iolink_properties, attr);
	sysfs_show_32bit_prop(buffer, "type", iolink->iolink_type);
	sysfs_show_32bit_prop(buffer, "version_major", iolink->ver_maj);
	sysfs_show_32bit_prop(buffer, "version_minor", iolink->ver_min);
	sysfs_show_32bit_prop(buffer, "node_from", iolink->node_from);
	sysfs_show_32bit_prop(buffer, "node_to", iolink->node_to);
	sysfs_show_32bit_prop(buffer, "weight", iolink->weight);
	sysfs_show_32bit_prop(buffer, "min_latency", iolink->min_latency);
	sysfs_show_32bit_prop(buffer, "max_latency", iolink->max_latency);
	sysfs_show_32bit_prop(buffer, "min_bandwidth", iolink->min_bandwidth);
	sysfs_show_32bit_prop(buffer, "max_bandwidth", iolink->max_bandwidth);
	sysfs_show_32bit_prop(buffer, "recommended_transfer_size",
			iolink->rec_transfer_size);
	ret = sysfs_show_32bit_prop(buffer, "flags", iolink->flags);

	return ret;
}

static const struct sysfs_ops iolink_ops = {
	.show = iolink_show,
};

static struct kobj_type iolink_type = {
	.sysfs_ops = &iolink_ops,
};

static ssize_t mem_show(struct kobject *kobj, struct attribute *attr,
		char *buffer)
{
	ssize_t ret;
	struct kfd_mem_properties *mem;
    pr_debug("mem_show\n");
	/* Making sure that the buffer is an empty string */
	buffer[0] = 0;

	mem = container_of(attr, struct kfd_mem_properties, attr);
	sysfs_show_32bit_prop(buffer, "heap_type", mem->heap_type);
	sysfs_show_64bit_prop(buffer, "size_in_bytes", mem->size_in_bytes);
	sysfs_show_32bit_prop(buffer, "flags", mem->flags);
	sysfs_show_32bit_prop(buffer, "width", mem->width);
	ret = sysfs_show_32bit_prop(buffer, "mem_clk_max", mem->mem_clk_max);

	return ret;
}

static const struct sysfs_ops mem_ops = {
	.show = mem_show,
};

static struct kobj_type mem_type = {
	.sysfs_ops = &mem_ops,
};

static ssize_t kfd_cache_show(struct kobject *kobj, struct attribute *attr,
		char *buffer)
{
	ssize_t ret;
	uint32_t i;
	struct kfd_cache_properties *cache;

    pr_debug("kfd_cache_show\n");
	/* Making sure that the buffer is an empty string */
	buffer[0] = 0;

	cache = container_of(attr, struct kfd_cache_properties, attr);
	sysfs_show_32bit_prop(buffer, "processor_id_low",
			cache->processor_id_low);
	sysfs_show_32bit_prop(buffer, "level", cache->cache_level);
	sysfs_show_32bit_prop(buffer, "size", cache->cache_size);
	sysfs_show_32bit_prop(buffer, "cache_line_size", cache->cacheline_size);
	sysfs_show_32bit_prop(buffer, "cache_lines_per_tag",
			cache->cachelines_per_tag);
	sysfs_show_32bit_prop(buffer, "association", cache->cache_assoc);
	sysfs_show_32bit_prop(buffer, "latency", cache->cache_latency);
	sysfs_show_32bit_prop(buffer, "type", cache->cache_type);
	snprintf(buffer, PAGE_SIZE, "%ssibling_map ", buffer);
	for (i = 0; i < KFD_TOPOLOGY_CPU_SIBLINGS; i++)
		ret = snprintf(buffer, PAGE_SIZE, "%s%d%s",
				buffer, cache->sibling_map[i],
				(i == KFD_TOPOLOGY_CPU_SIBLINGS-1) ?
						"\n" : ",");

	return ret;
}

static const struct sysfs_ops cache_ops = {
	.show = kfd_cache_show,
};

static struct kobj_type cache_type = {
	.sysfs_ops = &cache_ops,
};

static ssize_t node_show(struct kobject *kobj, struct attribute *attr,
		char *buffer)
{
	ssize_t ret;
	struct kfd_topology_device *dev;
	char public_name[KFD_TOPOLOGY_PUBLIC_NAME_SIZE];
	uint32_t i;

    pr_debug("node_show: %s\n", attr->name);
	/* Making sure that the buffer is an empty string */
	buffer[0] = 0;

	if (strcmp(attr->name, "gpu_id") == 0) {
		dev = container_of(attr, struct kfd_topology_device,
				attr_gpuid);
		ret = sysfs_show_32bit_val(buffer, dev->gpu_id);
	} else if (strcmp(attr->name, "name") == 0) {
		dev = container_of(attr, struct kfd_topology_device,
				attr_name);
		for (i = 0; i < KFD_TOPOLOGY_PUBLIC_NAME_SIZE; i++) {
			public_name[i] =
					(char)dev->node_props.marketing_name[i];
			if (dev->node_props.marketing_name[i] == 0)
				break;
		}
		public_name[KFD_TOPOLOGY_PUBLIC_NAME_SIZE-1] = 0x0;
		ret = sysfs_show_str_val(buffer, public_name);
	} else {
/*
		dev = container_of(attr, struct kfd_topology_device,
				attr_props);
		sysfs_show_32bit_prop(buffer, "cpu_cores_count",
				dev->node_props.cpu_cores_count);
		sysfs_show_32bit_prop(buffer, "simd_count",
				dev->node_props.simd_count);
		sysfs_show_32bit_prop(buffer, "mem_banks_count",
				dev->node_props.mem_banks_count);
		sysfs_show_32bit_prop(buffer, "caches_count",
				dev->node_props.caches_count);
		sysfs_show_32bit_prop(buffer, "io_links_count",
				dev->node_props.io_links_count);
		sysfs_show_32bit_prop(buffer, "cpu_core_id_base",
				dev->node_props.cpu_core_id_base);
		sysfs_show_32bit_prop(buffer, "simd_id_base",
				dev->node_props.simd_id_base);
		sysfs_show_32bit_prop(buffer, "capability",
				dev->node_props.capability);
		sysfs_show_32bit_prop(buffer, "max_waves_per_simd",
				dev->node_props.max_waves_per_simd);
		sysfs_show_32bit_prop(buffer, "lds_size_in_kb",
				dev->node_props.lds_size_in_kb);
		sysfs_show_32bit_prop(buffer, "gds_size_in_kb",
				dev->node_props.gds_size_in_kb);
		sysfs_show_32bit_prop(buffer, "wave_front_size",
				dev->node_props.wave_front_size);
		sysfs_show_32bit_prop(buffer, "array_count",
				dev->node_props.array_count);
		sysfs_show_32bit_prop(buffer, "simd_arrays_per_engine",
				dev->node_props.simd_arrays_per_engine);
		sysfs_show_32bit_prop(buffer, "cu_per_simd_array",
				dev->node_props.cu_per_simd_array);
		sysfs_show_32bit_prop(buffer, "simd_per_cu",
				dev->node_props.simd_per_cu);
		sysfs_show_32bit_prop(buffer, "max_slots_scratch_cu",
				dev->node_props.max_slots_scratch_cu);
		sysfs_show_32bit_prop(buffer, "engine_id",
				dev->node_props.engine_id);
		sysfs_show_32bit_prop(buffer, "vendor_id",
				dev->node_props.vendor_id);
		sysfs_show_32bit_prop(buffer, "device_id",
				dev->node_props.device_id);
		sysfs_show_32bit_prop(buffer, "location_id",
				dev->node_props.location_id);
		sysfs_show_32bit_prop(buffer, "max_engine_clk_fcompute",
				kfd2kgd->get_max_engine_clock_in_mhz(
					dev->gpu->kgd));
		sysfs_show_64bit_prop(buffer, "local_mem_size",
				kfd2kgd->get_vmem_size(dev->gpu->kgd));
		ret = sysfs_show_32bit_prop(buffer, "max_engine_clk_ccompute",
				cpufreq_quick_get_max(0)/1000);
*/
	}

	return ret;
}

static const struct sysfs_ops node_ops = {
	.show = node_show,
};

static struct kobj_type node_type = {
	.sysfs_ops = &node_ops,
};

static int virtio_kfd_build_sysfs_node_entry(struct kfd_topology_device *dev,
		uint32_t id)
{
	struct kfd_iolink_properties *iolink;
	struct kfd_cache_properties *cache;
	struct kfd_mem_properties *mem;
	int ret;
	uint32_t i;
    pr_debug("virtio_kfd_build_sysfs_node_entry\n");

	BUG_ON(!dev);

	/*
	 * Creating the sysfs folders
	 */
	BUG_ON(dev->kobj_node);
	dev->kobj_node = kfd_alloc_struct(dev->kobj_node);
	if (!dev->kobj_node)
		return -ENOMEM;

	ret = kobject_init_and_add(dev->kobj_node, &node_type,
			sys_props.kobj_nodes, "%d", id);
	if (ret < 0)
		return ret;

	dev->kobj_mem = kobject_create_and_add("mem_banks", dev->kobj_node);
	if (!dev->kobj_mem)
		return -ENOMEM;

	dev->kobj_cache = kobject_create_and_add("caches", dev->kobj_node);
	if (!dev->kobj_cache)
		return -ENOMEM;

	dev->kobj_iolink = kobject_create_and_add("io_links", dev->kobj_node);
	if (!dev->kobj_iolink)
		return -ENOMEM;

	/*
	 * Creating sysfs files for node properties
	 */
	dev->attr_gpuid.name = "gpu_id";
	dev->attr_gpuid.mode = KFD_SYSFS_FILE_MODE;
	sysfs_attr_init(&dev->attr_gpuid);
	dev->attr_name.name = "name";
	dev->attr_name.mode = KFD_SYSFS_FILE_MODE;
	sysfs_attr_init(&dev->attr_name);
	dev->attr_props.name = "properties";
	dev->attr_props.mode = KFD_SYSFS_FILE_MODE;
	sysfs_attr_init(&dev->attr_props);
	ret = sysfs_create_file(dev->kobj_node, &dev->attr_gpuid);
	if (ret < 0)
		return ret;
	ret = sysfs_create_file(dev->kobj_node, &dev->attr_name);
	if (ret < 0)
		return ret;
	ret = sysfs_create_file(dev->kobj_node, &dev->attr_props);
	if (ret < 0)
		return ret;

	i = 0;
	list_for_each_entry(mem, &dev->mem_props, list) {
		mem->kobj = kzalloc(sizeof(struct kobject), GFP_KERNEL);
		if (!mem->kobj)
			return -ENOMEM;
		ret = kobject_init_and_add(mem->kobj, &mem_type,
				dev->kobj_mem, "%d", i);
		if (ret < 0)
			return ret;

		mem->attr.name = "properties";
		mem->attr.mode = KFD_SYSFS_FILE_MODE;
		sysfs_attr_init(&mem->attr);
		ret = sysfs_create_file(mem->kobj, &mem->attr);
		if (ret < 0)
			return ret;
		i++;
	}

	i = 0;
	list_for_each_entry(cache, &dev->cache_props, list) {
		cache->kobj = kzalloc(sizeof(struct kobject), GFP_KERNEL);
		if (!cache->kobj)
			return -ENOMEM;
		ret = kobject_init_and_add(cache->kobj, &cache_type,
				dev->kobj_cache, "%d", i);
		if (ret < 0)
			return ret;

		cache->attr.name = "properties";
		cache->attr.mode = KFD_SYSFS_FILE_MODE;
		sysfs_attr_init(&cache->attr);
		ret = sysfs_create_file(cache->kobj, &cache->attr);
		if (ret < 0)
			return ret;
		i++;
	}

	i = 0;
	list_for_each_entry(iolink, &dev->io_link_props, list) {
		iolink->kobj = kzalloc(sizeof(struct kobject), GFP_KERNEL);
		if (!iolink->kobj)
			return -ENOMEM;
		ret = kobject_init_and_add(iolink->kobj, &iolink_type,
				dev->kobj_iolink, "%d", i);
		if (ret < 0)
			return ret;

		iolink->attr.name = "properties";
		iolink->attr.mode = KFD_SYSFS_FILE_MODE;
		sysfs_attr_init(&iolink->attr);
		ret = sysfs_create_file(iolink->kobj, &iolink->attr);
		if (ret < 0)
			return ret;
		i++;
}

	return 0;
}

static int virtio_kfd_build_sysfs_node_tree(void)
{
	struct kfd_topology_device *dev;
	int ret;
	uint32_t i = 0;

    printk("virtio_kfd_build_sysfs_node_tree");
    // Get host topology information here
	list_for_each_entry(dev, &topology_device_list, list) {
		ret = virtio_kfd_build_sysfs_node_entry(dev, 0);
		if (ret < 0)
			return ret;
		i++;
	}
    printk("\n");

	return 0;
}

static int virtio_kfd_topology_update_sysfs(void)
{
	int ret;
	pr_debug("Creating topology SYSFS entries\n");
	if (sys_props.kobj_topology == 0) {
		sys_props.kobj_topology = kfd_alloc_struct(sys_props.kobj_topology);
		if (!sys_props.kobj_topology)
			return -ENOMEM;

		ret = kobject_init_and_add(sys_props.kobj_topology,
				&sysprops_type,  &virtkfd_device->kobj,
				"topology");
		if (ret < 0)
			return ret;

		sys_props.kobj_nodes = kobject_create_and_add("nodes",
				sys_props.kobj_topology);
		if (!sys_props.kobj_nodes)
			return -ENOMEM;

		sys_props.attr_genid.name = "generation_id";
		sys_props.attr_genid.mode = KFD_SYSFS_FILE_MODE;
		sysfs_attr_init(&sys_props.attr_genid);
		ret = sysfs_create_file(sys_props.kobj_topology,
				&sys_props.attr_genid);
		if (ret < 0)
			return ret;

		sys_props.attr_props.name = "system_properties";
		sys_props.attr_props.mode = KFD_SYSFS_FILE_MODE;
		sysfs_attr_init(&sys_props.attr_props);
		ret = sysfs_create_file(sys_props.kobj_topology,
				&sys_props.attr_props);
		if (ret < 0)
			return ret;
	}

//	kfd_remove_sysfs_node_tree();

	return virtio_kfd_build_sysfs_node_tree();
}

int virtio_kfd_topology_init(struct virtio_kfd *vkfd)
{
	int ret;
    printk("virtio_kfd_topology_init\n");
	/*
	 * Initialize the head for the topology device list
	 */
	INIT_LIST_HEAD(&topology_device_list);
	init_rwsem(&topology_lock);

	memset(&sys_props, 0, sizeof(sys_props));
	ret = virtio_kfd_topology_update_sysfs();
    if(ret < 0)
        goto err_topology;

    int cmd = VIRTKFD_GET_SYSINFO;
    printk("call virtkfd_add_req\n");
    
//    sys_info.system_properties.generation_count = 80;
    virtkfd_add_req(vkfd, &cmd, &sys_info, sizeof(sys_info));       // a blocking call
    printk("virtkfd_add_req done\n");

err_topology:
	return ret;
}

static void virtio_kfd_debug_print_topology(void)
{
	struct kfd_topology_device *dev;
	uint32_t i = 0;

	pr_info("DEBUG PRINT OF TOPOLOGY:");
	list_for_each_entry(dev, &topology_device_list, list) {
		pr_info("Node: %d\n", i);
		pr_info("\tGPU assigned: %s\n", (dev->gpu ? "yes" : "no"));
		pr_info("\tCPU count: %d\n", dev->node_props.cpu_cores_count);
		pr_info("\tSIMD count: %d", dev->node_props.simd_count);
		i++;
	}
}
