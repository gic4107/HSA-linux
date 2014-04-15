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
 *
 */

#ifndef KFD_PM4_HEADERS_H_
#define KFD_PM4_HEADERS_H_

#ifndef PM4_HEADER_DEFINED
#define PM4_HEADER_DEFINED

typedef union PM4_TYPE_3_HEADER {
	struct {
		unsigned int predicate:1;	/* < 0 for diq packets */
		unsigned int shader_type:1;	/* < 0 for diq packets */
		unsigned int reserved1:6;	/* < reserved */
		unsigned int opcode:8;		/* < IT opcode */
		unsigned int count:14;		/* < number of DWORDs - 1 in the information body. */
		unsigned int type:2;		/* < packet identifier. It should be 3 for type 3 packets */
	};
	unsigned int u32all;
} PM4_TYPE_3_HEADER;
#endif

/*
 * --------------------_MAP_QUEUES--------------------
 */

#ifndef _PM4__MAP_QUEUES_DEFINED
#define _PM4__MAP_QUEUES_DEFINED
enum _map_queues_queue_sel_enum {
	queue_sel___map_queues__map_to_specified_queue_slots = 0,
	queue_sel___map_queues__map_to_hws_determined_queue_slots = 1,
	queue_sel___map_queues__enable_process_queues = 2,
	queue_sel___map_queues__reserved = 3 };

enum _map_queues_vidmem_enum {
	vidmem___map_queues__uses_no_video_memory = 0,
	vidmem___map_queues__uses_video_memory = 1 };

enum _map_queues_alloc_format_enum {
	alloc_format___map_queues__one_per_pipe = 0,
	alloc_format___map_queues__all_on_one_pipe = 1 };

enum _map_queues_engine_sel_enum {
	engine_sel___map_queues__compute = 0,
	engine_sel___map_queues__sdma0_queue = 2,
	engine_sel___map_queues__sdma1_queue = 3 };

struct pm4_map_queues {
	union {
		PM4_TYPE_3_HEADER header;
		unsigned int ordinal1;
	};

	union {
		struct {
			unsigned int reserved1:4;
			enum _map_queues_queue_sel_enum queue_sel:2;
			unsigned int reserved2:2;
			unsigned int vmid:4;
			unsigned int reserved3:4;
			enum _map_queues_vidmem_enum vidmem:2;
			unsigned int reserved4:6;
			enum _map_queues_alloc_format_enum alloc_format:2;
			enum _map_queues_engine_sel_enum engine_sel:3;
			unsigned int num_queues:3;
		} bitfields2;
		unsigned int ordinal2;
	};

	struct {
		union {
			struct {
				unsigned int reserved5:2;
				unsigned int doorbell_offset:21;
				unsigned int reserved6:3;
				unsigned int queue:6;
			} bitfields3;
			unsigned int ordinal3;
		};

		unsigned int mqd_addr_lo;
		unsigned int mqd_addr_hi;
		unsigned int wptr_addr_lo;
		unsigned int wptr_addr_hi;

	} _map_queues_ordinals[1];	/* 1..N of these ordinal groups */

};
#endif

/*
 * --------------------_QUERY_STATUS--------------------
 */

#ifndef _PM4__QUERY_STATUS_DEFINED
#define _PM4__QUERY_STATUS_DEFINED
enum _query_status_interrupt_sel_enum {
	interrupt_sel___query_status__completion_status = 0,
	interrupt_sel___query_status__process_status = 1,
	interrupt_sel___query_status__queue_status = 2,
	interrupt_sel___query_status__reserved = 3 };

enum _query_status_command_enum {
	command___query_status__interrupt_only = 0,
	command___query_status__fence_only_immediate = 1,
	command___query_status__fence_only_after_write_ack = 2,
	command___query_status__fence_wait_for_write_ack_send_interrupt = 3 };

enum _query_status_engine_sel_enum {
	engine_sel___query_status__compute = 0,
	engine_sel___query_status__sdma0 = 2,
	engine_sel___query_status__sdma1 = 3 };

struct pm4_query_status {
	union {
		PM4_TYPE_3_HEADER header;
		unsigned int ordinal1;
	};

	union {
		struct {
			unsigned int context_id:28;
			enum _query_status_interrupt_sel_enum interrupt_sel:2;
			enum _query_status_command_enum command:2;
		} bitfields2;
		unsigned int ordinal2;
	};

	union {
		struct {
			unsigned int pasid:16;
			unsigned int reserved1:16;
		} bitfields3;
		struct {
			unsigned int reserved2:2;
			unsigned int doorbell_offset:21;
			unsigned int reserved3:3;
			enum _query_status_engine_sel_enum engine_sel:3;
			unsigned int reserved4:3;
		} bitfields4;
		unsigned int ordinal3;
	};

	unsigned int addr_lo;
	unsigned int addr_hi;
	unsigned int data_lo;
	unsigned int data_hi;

};
#endif

/*
 * --------------------_UNMAP_QUEUES--------------------
 */

#ifndef _PM4__UNMAP_QUEUES_DEFINED
#define _PM4__UNMAP_QUEUES_DEFINED
enum _unmap_queues_action_enum {
	action___unmap_queues__preempt_queues = 0,
	action___unmap_queues__reset_queues = 1,
	action___unmap_queues__disable_process_queues = 2,
	action___unmap_queues__reserved = 3 };

enum _unmap_queues_queue_sel_enum {
	queue_sel___unmap_queues__perform_request_on_specified_queues = 0,
	queue_sel___unmap_queues__perform_request_on_pasid_queues = 1,
	queue_sel___unmap_queues__perform_request_on_all_active_queues = 2,
	queue_sel___unmap_queues__reserved = 3 };

enum _unmap_queues_engine_sel_enum {
	engine_sel___unmap_queues__compute = 0,
	engine_sel___unmap_queues__sdma0 = 2,
	engine_sel___unmap_queues__sdma1 = 3 };

struct pm4_unmap_queues {
	union {
		PM4_TYPE_3_HEADER header;
		unsigned int ordinal1;
	};

	union {
		struct {
			enum _unmap_queues_action_enum action:2;
			unsigned int reserved1:2;
			enum _unmap_queues_queue_sel_enum queue_sel:2;
			unsigned int reserved2:20;
			enum _unmap_queues_engine_sel_enum engine_sel:3;
			unsigned int num_queues:3;
		} bitfields2;
		unsigned int ordinal2;
	};

	union {
		struct {
			unsigned int pasid:16;
			unsigned int reserved3:16;
		} bitfields3;
		struct {
			unsigned int reserved4:2;
			unsigned int doorbell_offset0:21;
			unsigned int reserved5:9;
		} bitfields4;
		unsigned int ordinal3;
	};

	union {
		struct {
			unsigned int reserved6:2;
			unsigned int doorbell_offset1:21;
			unsigned int reserved7:9;
		} bitfields5;
		unsigned int ordinal4;
	};

	union {
		struct {
			unsigned int reserved8:2;
			unsigned int doorbell_offset2:21;
			unsigned int reserved9:9;
		} bitfields6;
		unsigned int ordinal5;
	};

	union {
		struct {
			unsigned int reserved10:2;
			unsigned int doorbell_offset3:21;
			unsigned int reserved11:9;
		} bitfields7;
		unsigned int ordinal6;
	};

};
#endif

/*
 * --------------------_SET_RESOURCES--------------------
 */

#ifndef _PM4__SET_RESOURCES_DEFINED
#define _PM4__SET_RESOURCES_DEFINED
enum _set_resources_queue_type_enum {
	queue_type___set_resources__hsa_interface_queue_hiq = 1,
	queue_type___set_resources__hsa_debug_interface_queue = 4 };

struct pm4_set_resources {
	union {
		PM4_TYPE_3_HEADER header;
		unsigned int ordinal1;
	};

	union {
		struct {

			unsigned int vmid_mask:16;
			unsigned int unmap_latency:8;
			unsigned int reserved1:5;
			enum _set_resources_queue_type_enum queue_type:3;
		} bitfields2;
		unsigned int ordinal2;
	};

	unsigned int queue_mask_lo;
	unsigned int queue_mask_hi;
	unsigned int gws_mask_lo;
	unsigned int gws_mask_hi;

	union {
		struct {
			unsigned int oac_mask:16;
			unsigned int reserved2:16;
		} bitfields3;
		unsigned int ordinal7;
	};

	union {
		struct {
			unsigned int gds_heap_base:6;
			unsigned int reserved3:5;
			unsigned int gds_heap_size:6;
			unsigned int reserved4:15;
		} bitfields4;
		unsigned int ordinal8;
	};

};
#endif

/*
 * --------------------_RUN_LIST--------------------
 */

#ifndef _PM4__RUN_LIST_DEFINED
#define _PM4__RUN_LIST_DEFINED

struct pm4_runlist {
	union {
		PM4_TYPE_3_HEADER header;
		unsigned int ordinal1;
	};

	union {
		struct {
			unsigned int reserved1:2;
			unsigned int ib_base_lo:30;
		} bitfields2;
		unsigned int ordinal2;
	};

	union {
		struct {
			unsigned int ib_base_hi:16;
			unsigned int reserved2:16;
		} bitfields3;
		unsigned int ordinal3;
	};

	union {
		struct {
			unsigned int ib_size:20;
			unsigned int chain:1;
			unsigned int offload_polling:1;
			unsigned int reserved3:1;
			unsigned int valid:1;
			unsigned int vmid:4;
			unsigned int reserved4:4;
		} bitfields4;
		unsigned int ordinal4;
	};

};
#endif

/*
 * --------------------_MAP_PROCESS--------------------
 */

#ifndef _PM4__MAP_PROCESS_DEFINED
#define _PM4__MAP_PROCESS_DEFINED

struct pm4_map_process {
	union {
		PM4_TYPE_3_HEADER header;
		unsigned int ordinal1;
	};

	union {
		struct {
			unsigned int pasid:16;
			unsigned int reserved1:8;
			unsigned int diq_enable:1;
			unsigned int reserved2:7;
		} bitfields2;
		unsigned int ordinal2;
	};

	union {
		struct {
			unsigned int page_table_base:28;
			unsigned int reserved3:4;
		} bitfields3;
		unsigned int ordinal3;
	};

	unsigned int sh_mem_bases;
	unsigned int sh_mem_ape1_base;
	unsigned int sh_mem_ape1_limit;
	unsigned int sh_mem_config;
	unsigned int gds_addr_lo;
	unsigned int gds_addr_hi;

	union {
		struct {
			unsigned int num_gws:6;
			unsigned int reserved4:2;
			unsigned int num_oac:4;
			unsigned int reserved5:4;
			unsigned int gds_size:6;
			unsigned int reserved6:10;
		} bitfields4;
		unsigned int ordinal10;
	};

};
#endif

/*--------------------_MAP_QUEUES--------------------*/

#ifndef _PM4__MAP_QUEUES_DEFINED
#define _PM4__MAP_QUEUES_DEFINED
enum _MAP_QUEUES_queue_sel_enum {
	 queue_sel___map_queues__map_to_specified_queue_slots = 0,
	 queue_sel___map_queues__map_to_hws_determined_queue_slots = 1,
	 queue_sel___map_queues__enable_process_queues = 2,
	 queue_sel___map_queues__reserved = 3 };

enum _MAP_QUEUES_vidmem_enum {
	 vidmem___map_queues__uses_no_video_memory = 0,
	 vidmem___map_queues__uses_video_memory = 1 };

enum _MAP_QUEUES_alloc_format_enum {
	 alloc_format___map_queues__one_per_pipe = 0,
	 alloc_format___map_queues__all_on_one_pipe = 1 };

enum _MAP_QUEUES_engine_sel_enum {
	 engine_sel___map_queues__compute = 0,
	 engine_sel___map_queues__sdma0_queue = 2,
	 engine_sel___map_queues__sdma1_queue = 3 };


typedef struct _PM4__MAP_QUEUES {
	union {
		PM4_TYPE_3_HEADER header;
		unsigned int ordinal1;
	};

	union {
		struct {
			unsigned int reserved1:4;
			enum _MAP_QUEUES_queue_sel_enum queue_sel:2;
			unsigned int reserved2:2;
			unsigned int vmid:4;
			unsigned int reserved3:4;
			enum _MAP_QUEUES_vidmem_enum vidmem:2;
			unsigned int reserved4:6;
			enum _MAP_QUEUES_alloc_format_enum alloc_format:2;
			enum _MAP_QUEUES_engine_sel_enum engine_sel:3;
			unsigned int num_queues:3;
		} bitfields2;
		unsigned int ordinal2;
	};

	struct {
		union {
			struct {
				unsigned int reserved5:2;
				unsigned int doorbell_offset:21;
				unsigned int reserved6:3;
				unsigned int queue:6;
			} bitfields3;
			unsigned int ordinal3;
		};

		unsigned int mqd_addr_lo;

		unsigned int mqd_addr_hi;

		unsigned int wptr_addr_lo;

		unsigned int wptr_addr_hi;

	} _map_queues_ordinals[1];	/* 1..N of these ordinal groups */

}  PM4_MAP_QUEUES, *PPM4_MAP_QUEUES;
#endif

/*--------------------_QUERY_STATUS--------------------*/

#ifndef _PM4__QUERY_STATUS_DEFINED
#define _PM4__QUERY_STATUS_DEFINED
enum _QUERY_STATUS_interrupt_sel_enum {
	 interrupt_sel___query_status__completion_status = 0,
	 interrupt_sel___query_status__process_status = 1,
	 interrupt_sel___query_status__queue_status = 2,
	 interrupt_sel___query_status__reserved = 3 };

enum _QUERY_STATUS_command_enum {
	 command___query_status__interrupt_only = 0,
	 command___query_status__fence_only_immediate = 1,
	 command___query_status__fence_only_after_write_ack = 2,
	 command___query_status__fence_wait_for_write_ack_send_interrupt = 3 };

enum _QUERY_STATUS_engine_sel_enum {
	 engine_sel___query_status__compute = 0,
	 engine_sel___query_status__sdma0 = 2,
	 engine_sel___query_status__sdma1 = 3 };


typedef struct _PM4__QUERY_STATUS {
	union {
		PM4_TYPE_3_HEADER header;
		unsigned int ordinal1;
	};

	union {
		struct {
			unsigned int context_id:28;
			enum _QUERY_STATUS_interrupt_sel_enum interrupt_sel:2;
			enum _QUERY_STATUS_command_enum command:2;
		} bitfields2;
		unsigned int ordinal2;
	};

	union {
		struct {
			unsigned int pasid:16;
			unsigned int reserved1:16;
		} bitfields3;
		struct {
			unsigned int reserved2:2;
			unsigned int doorbell_offset:21;
			unsigned int reserved3:3;
			enum _QUERY_STATUS_engine_sel_enum engine_sel:3;
			unsigned int reserved4:3;
		} bitfields4;
		unsigned int ordinal3;
	};

	unsigned int addr_lo;

	unsigned int addr_hi;

	unsigned int data_lo;

	unsigned int data_hi;

}  PM4_QUERY_STATUS, *PPM4_QUERY_STATUS;
#endif

/*
 *  --------------------UNMAP_QUEUES--------------------
 */

#ifndef _PM4__UNMAP_QUEUES_DEFINED
#define _PM4__UNMAP_QUEUES_DEFINED
enum _unmap_queues_action_enum {
	 action___unmap_queues__preempt_queues = 0,
	 action___unmap_queues__reset_queues = 1,
	 action___unmap_queues__disable_process_queues = 2,
	 action___unmap_queues__reserved = 3 };

enum _unmap_queues_queue_sel_enum {
	 queue_sel___unmap_queues__perform_request_on_specified_queues = 0,
	 queue_sel___unmap_queues__perform_request_on_pasid_queues = 1,
	 queue_sel___unmap_queues__perform_request_on_all_active_queues = 2,
	 queue_sel___unmap_queues__reserved = 3 };

enum _unmap_queues_engine_sel_enum {
	 engine_sel___unmap_queues__compute = 0,
	 engine_sel___unmap_queues__sdma0 = 2,
	 engine_sel___unmap_queues__sdma1 = 3 };


struct pm4_unmap_queues {
	union {
		PM4_TYPE_3_HEADER header;
		unsigned int ordinal1;
	};

	union {
		struct {
			_unmap_queues_action_enum action:2;
			unsigned int reserved1:2;
			_unmap_queues_queue_sel_enum queue_sel:2;
			unsigned int reserved2:20;
			_unmap_queues_engine_sel_enum engine_sel:3;
			unsigned int num_queues:3;
		} bitfields2;
		unsigned int ordinal2;
	};

	union {
		struct {
			unsigned int pasid:16;
			unsigned int reserved3:16;
		} bitfields3;
		struct {
			unsigned int reserved4:2;
			unsigned int doorbell_offset0:21;
			unsigned int reserved5:9;
		} bitfields4;
		unsigned int ordinal3;
	};

	union {
		struct {
			unsigned int reserved6:2;
			unsigned int doorbell_offset1:21;
			unsigned int reserved7:9;
		} bitfields5;
		unsigned int ordinal4;
	};

	union {
		struct {
			unsigned int reserved8:2;
			unsigned int doorbell_offset2:21;
			unsigned int reserved9:9;
		} bitfields6;
		unsigned int ordinal5;
	};

	union {
		struct {
			unsigned int reserved10:2;
			unsigned int doorbell_offset3:21;
			unsigned int reserved11:9;
		} bitfields7;
		unsigned int ordinal6;
	};

};
#endif

/* --------------------_SET_SH_REG--------------------*/

#ifndef _PM4__SET_SH_REG_DEFINED
#define _PM4__SET_SH_REG_DEFINED

typedef struct _PM4__SET_SH_REG {
	union {
		PM4_TYPE_3_HEADER header;
		unsigned int ordinal1;
	};

	union {
		struct {
			unsigned int reg_offset:16;
			unsigned int reserved1:8;
			unsigned int vmid_shift:5;
			unsigned int insert_vmid:1;
			unsigned int reserved2:1;
			unsigned int non_incr_addr:1;
		} bitfields2;
		unsigned int ordinal2;
	};

	unsigned int reg_data[1];	/* 1..N of these fields */

}  PM4_SET_SH_REG, *PPM4_SET_SH_REG;
#endif

/*--------------------_SET_CONFIG_REG--------------------*/

#ifndef _PM4__SET_CONFIG_REG_DEFINED
#define _PM4__SET_CONFIG_REG_DEFINED

struct pm4__set_config_reg {
	union {
		PM4_TYPE_3_HEADER header;
		unsigned int ordinal1;
	};

	union {
		struct {
			unsigned int reg_offset:16;
			unsigned int reserved1:8;
			unsigned int vmid_shift:5;
			unsigned int insert_vmid:1;
			unsigned int reserved2:2;
		} bitfields2;
		unsigned int ordinal2;
	};

	unsigned int reg_data[1];	/* 1..N of these fields */

};
#endif

enum {
	CACHE_FLUSH_AND_INV_TS_EVENT = 0x00000014
};

#endif /* KFD_PM4_HEADERS_H_ */
