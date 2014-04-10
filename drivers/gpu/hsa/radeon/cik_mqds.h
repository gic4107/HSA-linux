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
 * Author: Ben Goz
 */

#ifndef CIK_MQDS_H_
#define CIK_MQDS_H_

#pragma pack(push, 4)

struct cik_sdma_rlc_registers {
	u32 sdma0_rlc0_rb_cntl;
	u32 sdma0_rlc0_rb_base;
	u32 sdma0_rlc0_rb_base_hi;
	u32 sdma0_rlc0_rb_rptr;
	u32 sdma0_rlc0_rb_wptr;
	u32 sdma0_rlc0_rb_wptr_poll_cntl;
	u32 sdma0_rlc0_rb_wptr_poll_addr_hi;
	u32 sdma0_rlc0_rb_wptr_poll_addr_lo;
	u32 sdma0_rlc0_rb_rptr_addr_hi;
	u32 sdma0_rlc0_rb_rptr_addr_lo;
	u32 sdma0_rlc0_ib_cntl;
	u32 sdma0_rlc0_ib_rptr;
	u32 sdma0_rlc0_ib_offset;
	u32 sdma0_rlc0_ib_base_lo;
	u32 sdma0_rlc0_ib_base_hi;
	u32 sdma0_rlc0_ib_size;
	u32 sdma0_rlc0_skip_cntl;
	u32 sdma0_rlc0_context_status;
	u32 sdma0_rlc0_doorbell;
};

struct cik_hpd_registers {
	u32 cp_hpd_roq_offsets;
	u32 cp_hpd_eop_base_addr;
	u32 cp_hpd_eop_base_addr_hi;
	u32 cp_hpd_eop_vmid;
	u32 cp_hpd_eop_control;
};

struct cik_hqd_registers {
	u32 cp_mqd_base_addr;
	u32 cp_mqd_base_addr_hi;
	u32 cp_hqd_active;
	u32 cp_hqd_vmid;
	u32 cp_hqd_persistent_state;
	u32 cp_hqd_pipe_priority;
	u32 cp_hqd_queue_priority;
	u32 cp_hqd_quantum;
	u32 cp_hqd_pq_base;
	u32 cp_hqd_pq_base_hi;
	u32 cp_hqd_pq_rptr;
	u32 cp_hqd_pq_rptr_report_addr;
	u32 cp_hqd_pq_rptr_report_addr_hi;
	u32 cp_hqd_pq_wptr_poll_addr;
	u32 cp_hqd_pq_wptr_poll_addr_hi;
	u32 cp_hqd_pq_doorbell_control;
	u32 cp_hqd_pq_wptr;
	u32 cp_hqd_pq_control;
	u32 cp_hqd_ib_base_addr;
	u32 cp_hqd_ib_base_addr_hi;
	u32 cp_hqd_ib_rptr;
	u32 cp_hqd_ib_control;
	u32 cp_hqd_iq_timer;
	u32 cp_hqd_iq_rptr;
	u32 cp_hqd_dequeue_request;
	u32 cp_hqd_dma_offload;
	u32 cp_hqd_sema_cmd;
	u32 cp_hqd_msg_type;
	u32 cp_hqd_atomic0_preop_lo;
	u32 cp_hqd_atomic0_preop_hi;
	u32 cp_hqd_atomic1_preop_lo;
	u32 cp_hqd_atomic1_preop_hi;
	u32 cp_hqd_hq_scheduler0;
	u32 cp_hqd_hq_scheduler1;
	u32 cp_mqd_control;
};

struct cik_mqd {
	u32 header;
	u32 dispatch_initiator;
	u32 dimensions[3];
	u32 start_idx[3];
	u32 num_threads[3];
	u32 pipeline_stat_enable;
	u32 perf_counter_enable;
	u32 pgm[2];
	u32 tba[2];
	u32 tma[2];
	u32 pgm_rsrc[2];
	u32 vmid;
	u32 resource_limits;
	u32 static_thread_mgmt01[2];
	u32 tmp_ring_size;
	u32 static_thread_mgmt23[2];
	u32 restart[3];
	u32 thread_trace_enable;
	u32 reserved1;
	u32 user_data[16];
	u32 vgtcs_invoke_count[2];
	struct cik_hqd_registers queue_state;
	u32 dequeue_cntr;
	u32 interrupt_queue[64];
};

/* This structure represents mqd used for cp scheduling queue
 * taken from Gfx72_cp_program_spec.pdf
 */
struct cik_compute_mqd {
	u32 header;
	u32 compute_dispatch_initiator;
	u32 compute_dim_x;
	u32 compute_dim_y;
	u32 compute_dim_z;
	u32 compute_start_x;
	u32 compute_start_y;
	u32 compute_start_z;
	u32 compute_num_thread_x;
	u32 compute_num_thread_y;
	u32 compute_num_thread_z;
	u32 compute_pipelinestat_enable;
	u32 compute_perfcount_enable;
	u32 compute_pgm_lo;
	u32 compute_pgm_hi;
	u32 compute_tba_lo;
	u32 compute_tba_hi;
	u32 compute_tma_lo;
	u32 compute_tma_hi;
	u32 compute_pgm_rsrc1;
	u32 compute_pgm_rsrc2;
	u32 compute_vmid;
	u32 compute_resource_limits;
	u32 compute_static_thread_mgmt_se0;
	u32 compute_static_thread_mgmt_se1;
	u32 compute_tmpring_size;
	u32 compute_static_thread_mgmt_se2;
	u32 compute_static_thread_mgmt_se3;
	u32 compute_restart_x;
	u32 compute_restart_y;
	u32 compute_restart_z;
	u32 compute_thread_trace_enable;
	u32 compute_misc_reserved;
	u32 compute_user_data[16];
	u32 vgt_csinvoc_count_lo;
	u32 vgt_csinvoc_count_hi;
	u32 cp_mqd_base_addr51;
	u32 cp_mqd_base_addr_hi;
	u32 cp_hqd_active;
	u32 cp_hqd_vmid;
	u32 cp_hqd_persistent_state;
	u32 cp_hqd_pipe_priority;
	u32 cp_hqd_queue_priority;
	u32 cp_hqd_quantum;
	u32 cp_hqd_pq_base;
	u32 cp_hqd_pq_base_hi;
	u32 cp_hqd_pq_rptr;
	u32 cp_hqd_pq_rptr_report_addr;
	u32 cp_hqd_pq_rptr_report_addr_hi;
	u32 cp_hqd_pq_wptr_poll_addr;
	u32 cp_hqd_pq_wptr_poll_addr_hi;
	u32 cp_hqd_pq_doorbell_control;
	u32 cp_hqd_pq_wptr;
	u32 cp_hqd_pq_control;
	u32 cp_hqd_ib_base_addr;
	u32 cp_hqd_ib_base_addr_hi;
	u32 cp_hqd_ib_rptr;
	u32 cp_hqd_ib_control;
	u32 cp_hqd_iq_timer;
	u32 cp_hqd_iq_rptr;
	u32 cp_hqd_dequeue_request;
	u32 cp_hqd_dma_offload;
	u32 cp_hqd_sema_cmd;
	u32 cp_hqd_msg_type;
	u32 cp_hqd_atomic0_preop_lo;
	u32 cp_hqd_atomic0_preop_hi;
	u32 cp_hqd_atomic1_preop_lo;
	u32 cp_hqd_atomic1_preop_hi;
	u32 cp_hqd_hq_scheduler0;
	u32 cp_hqd_hq_scheduler1;
	u32 cp_mqd_control;
	u32 reserved1[10];
	u32 cp_mqd_query_time_lo;
	u32 cp_mqd_query_time_hi;
	u32 reserved2[4];
	u32 cp_mqd_connect_start_time_lo;
	u32 cp_mqd_connect_start_time_hi;
	u32 cp_mqd_connect_end_time_lo;
	u32 cp_mqd_connect_end_time_hi;
	u32 cp_mqd_connect_end_wf_count;
	u32 cp_mqd_connect_end_pq_rptr;
	u32 cp_mqd_connect_end_pq_wptr;
	u32 cp_mqd_connect_end_ib_rptr;
	u32 reserved3[18];
};

/* This structure represents all *IQs
 * Taken from Gfx73_CPC_Eng_Init_Prog.pdf
 */
struct cik_interface_mqd {
	u32 reserved1[128];
	u32 cp_mqd_base_addr;
	u32 cp_mqd_base_addr_hi;
	u32 cp_hqd_active;
	u32 cp_hqd_vmid;
	u32 cp_hqd_persistent_state;
	u32 cp_hqd_pipe_priority;
	u32 cp_hqd_queue_priority;
	u32 cp_hqd_quantum;
	u32 cp_hqd_pq_base;
	u32 cp_hqd_pq_base_hi;
	u32 cp_hqd_pq_rptr;
	u32 cp_hqd_pq_rptr_report_addr;
	u32 cp_hqd_pq_rptr_report_addr_hi;
	u32 cp_hqd_pq_wptr_poll_addr;
	u32 cp_hqd_pq_wptr_poll_addr_hi;
	u32 cp_hqd_pq_doorbell_control;
	u32 cp_hqd_pq_wptr;
	u32 cp_hqd_pq_control;
	u32 cp_hqd_ib_base_addr;
	u32 cp_hqd_ib_base_addr_hi;
	u32 cp_hqd_ib_rptr;
	u32 cp_hqd_ib_control;
	u32 cp_hqd_iq_timer;
	u32 cp_hqd_iq_rptr;
	u32 cp_hqd_dequeue_request;
	u32 cp_hqd_dma_offload;
	u32 cp_hqd_sema_cmd;
	u32 cp_hqd_msg_type;
	u32 cp_hqd_atomic0_preop_lo;
	u32 cp_hqd_atomic0_preop_hi;
	u32 cp_hqd_atomic1_preop_lo;
	u32 cp_hqd_atomic1_preop_hi;
	u32 cp_hqd_hq_status0;
	u32 cp_hqd_hq_control0;
	u32 cp_mqd_control;
	u32 reserved2[3];
	u32 cp_hqd_hq_status1;
	u32 cp_hqd_hq_control1;
	u32 reserved3[16];
	u32 cp_hqd_hq_status2;
	u32 cp_hqd_hq_control2;
	u32 cp_hqd_hq_status3;
	u32 cp_hqd_hq_control3;
	u32 reserved4[2];
	u32 cp_mqd_query_time_lo;
	u32 cp_mqd_query_time_hi;
	u32 reserved5[48];
	u32 cp_mqd_skip_process[16];
};

#pragma pack(pop)


#endif /* CIK_MQDS_H_ */
