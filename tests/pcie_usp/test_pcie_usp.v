/*

Copyright (c) 2020 Alex Forencich

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

// Language: Verilog 2001

`resetall
`timescale 1ns / 1ns
`default_nettype none

/*
 * Xilinx UltraScale+ PCIe IP core model test module
 */
module test_pcie_usp #
(
    parameter DATA_WIDTH = 64,
    parameter KEEP_WIDTH = (DATA_WIDTH/32),
    parameter RQ_USER_WIDTH = 62,
    parameter RC_USER_WIDTH = 75,
    parameter CQ_USER_WIDTH = 88,
    parameter CC_USER_WIDTH = 33
)
(
    output                      user_clk,
    output                      user_reset,
    output                      user_lnk_up,
    input  [DATA_WIDTH-1:0]     s_axis_rq_tdata,
    input  [KEEP_WIDTH-1:0]     s_axis_rq_tkeep,
    input                       s_axis_rq_tlast,
    output [3:0]                s_axis_rq_tready,
    input  [RQ_USER_WIDTH-1:0]  s_axis_rq_tuser,
    input                       s_axis_rq_tvalid,
    output [DATA_WIDTH-1:0]     m_axis_rc_tdata,
    output [KEEP_WIDTH-1:0]     m_axis_rc_tkeep,
    output                      m_axis_rc_tlast,
    input                       m_axis_rc_tready,
    output [RC_USER_WIDTH-1:0]  m_axis_rc_tuser,
    output                      m_axis_rc_tvalid,
    output [DATA_WIDTH-1:0]     m_axis_cq_tdata,
    output [KEEP_WIDTH-1:0]     m_axis_cq_tkeep,
    output                      m_axis_cq_tlast,
    input                       m_axis_cq_tready,
    output [CQ_USER_WIDTH-1:0]  m_axis_cq_tuser,
    output                      m_axis_cq_tvalid,
    input  [DATA_WIDTH-1:0]     s_axis_cc_tdata,
    input  [KEEP_WIDTH-1:0]     s_axis_cc_tkeep,
    input                       s_axis_cc_tlast,
    output [3:0]                s_axis_cc_tready,
    input  [CC_USER_WIDTH-1:0]  s_axis_cc_tuser,
    input                       s_axis_cc_tvalid,
    output [5:0]                pcie_rq_seq_num0,
    output                      pcie_rq_seq_num_vld0,
    output [5:0]                pcie_rq_seq_num1,
    output                      pcie_rq_seq_num_vld1,
    output [7:0]                pcie_rq_tag0,
    output [7:0]                pcie_rq_tag1,
    output [3:0]                pcie_rq_tag_av,
    output                      pcie_rq_tag_vld0,
    output                      pcie_rq_tag_vld1,
    output [3:0]                pcie_tfc_nph_av,
    output [3:0]                pcie_tfc_npd_av,
    input  [1:0]                pcie_cq_np_req,
    output [5:0]                pcie_cq_np_req_count,
    output                      cfg_phy_link_down,
    output [1:0]                cfg_phy_link_status,
    output [2:0]                cfg_negotiated_width,
    output [1:0]                cfg_current_speed,
    output [1:0]                cfg_max_payload,
    output [2:0]                cfg_max_read_req,
    output [15:0]               cfg_function_status,
    output [11:0]               cfg_function_power_state,
    output [503:0]              cfg_vf_status,
    output [755:0]              cfg_vf_power_state,
    output [1:0]                cfg_link_power_state,
    input  [9:0]                cfg_mgmt_addr,
    input  [7:0]                cfg_mgmt_function_number,
    input                       cfg_mgmt_write,
    input  [31:0]               cfg_mgmt_write_data,
    input  [3:0]                cfg_mgmt_byte_enable,
    input                       cfg_mgmt_read,
    output [31:0]               cfg_mgmt_read_data,
    output                      cfg_mgmt_read_write_done,
    input                       cfg_mgmt_debug_access,
    output                      cfg_err_cor_out,
    output                      cfg_err_nonfatal_out,
    output                      cfg_err_fatal_out,
    output                      cfg_local_error_valid,
    output [4:0]                cfg_local_error_out,
    output [5:0]                cfg_ltssm_state,
    output [1:0]                cfg_rx_pm_state,
    output [1:0]                cfg_tx_pm_state,
    output [3:0]                cfg_rcb_status,
    output [1:0]                cfg_obff_enable,
    output                      cfg_pl_status_change,
    output [3:0]                cfg_tph_requester_enable,
    output [11:0]               cfg_tph_st_mode,
    output [251:0]              cfg_vf_tph_requester_enable,
    output [755:0]              cfg_vf_tph_st_mode,
    output                      cfg_msg_received,
    output [7:0]                cfg_msg_received_data,
    output [4:0]                cfg_msg_received_type,
    input                       cfg_msg_transmit,
    input  [2:0]                cfg_msg_transmit_type,
    input  [31:0]               cfg_msg_transmit_data,
    output                      cfg_msg_transmit_done,
    output [7:0]                cfg_fc_ph,
    output [11:0]               cfg_fc_pd,
    output [7:0]                cfg_fc_nph,
    output [11:0]               cfg_fc_npd,
    output [7:0]                cfg_fc_cplh,
    output [11:0]               cfg_fc_cpld,
    input  [2:0]                cfg_fc_sel,
    input  [63:0]               cfg_dsn,
    output [7:0]                cfg_bus_number,
    input                       cfg_power_state_change_ack,
    output                      cfg_power_state_change_interrupt,
    input                       cfg_err_cor_in,
    input                       cfg_err_uncor_in,
    output [3:0]                cfg_flr_in_process,
    input  [3:0]                cfg_flr_done,
    output [251:0]              cfg_vf_flr_in_process,
    input  [7:0]                cfg_vf_flr_func_num,
    input  [0:0]                cfg_vf_flr_done,
    input                       cfg_link_training_enable,
    input  [3:0]                cfg_interrupt_int,
    input  [3:0]                cfg_interrupt_pending,
    output                      cfg_interrupt_sent,
    output [3:0]                cfg_interrupt_msi_enable,
    output [11:0]               cfg_interrupt_msi_mmenable,
    output                      cfg_interrupt_msi_mask_update,
    output [31:0]               cfg_interrupt_msi_data,
    input  [1:0]                cfg_interrupt_msi_select,
    input  [31:0]               cfg_interrupt_msi_int,
    input  [31:0]               cfg_interrupt_msi_pending_status,
    input                       cfg_interrupt_msi_pending_status_data_enable,
    input  [1:0]                cfg_interrupt_msi_pending_status_function_num,
    output                      cfg_interrupt_msi_sent,
    output                      cfg_interrupt_msi_fail,
    output [3:0]                cfg_interrupt_msix_enable,
    output [3:0]                cfg_interrupt_msix_mask,
    output [251:0]              cfg_interrupt_msix_vf_enable,
    output [251:0]              cfg_interrupt_msix_vf_mask,
    input  [63:0]               cfg_interrupt_msix_address,
    input  [31:0]               cfg_interrupt_msix_data,
    input                       cfg_interrupt_msix_int,
    input  [1:0]                cfg_interrupt_msix_vec_pending,
    output                      cfg_interrupt_msix_vec_pending_status,
    output                      cfg_interrupt_msix_sent,
    output                      cfg_interrupt_msix_fail,
    input  [2:0]                cfg_interrupt_msi_attr,
    input                       cfg_interrupt_msi_tph_present,
    input  [1:0]                cfg_interrupt_msi_tph_type,
    input  [7:0]                cfg_interrupt_msi_tph_st_tag,
    input  [7:0]                cfg_interrupt_msi_function_number,
    input                       cfg_pm_aspm_l1_entry_reject,
    input                       cfg_pm_aspm_tx_l0s_entry_disable,
    output                      cfg_hot_reset_out,
    input                       cfg_config_space_enable,
    input                       cfg_req_pm_transition_l23_ready,
    input                       cfg_hot_reset_in,
    input  [7:0]                cfg_ds_port_number,
    input  [7:0]                cfg_ds_bus_number,
    input  [4:0]                cfg_ds_device_number,
    input                       sys_clk,
    input                       sys_clk_gt,
    input                       sys_reset,
    output                      phy_rdy_out
);

endmodule

`resetall
