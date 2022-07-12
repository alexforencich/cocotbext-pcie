/*

Copyright (c) 2022 Alex Forencich

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
 * Intel P-Tile PCIe IP core model test module
 */
module test_pcie_ptile #
(
    parameter SEG_COUNT = 1,
    parameter SEG_DATA_WIDTH = 128,
    parameter SEG_HDR_WIDTH = 128,
    parameter SEG_PRFX_WIDTH = 32,
    parameter SEG_DATA_PAR_WIDTH = SEG_DATA_WIDTH/8,
    parameter SEG_HDR_PAR_WIDTH = SEG_HDR_WIDTH/8,
    parameter SEG_PRFX_PAR_WIDTH = SEG_PRFX_WIDTH/8,
    parameter SEG_EMPTY_WIDTH = $clog2(SEG_DATA_WIDTH/32)
)
(
    // Clock and reset
    output wire                                     reset_status_n,
    output wire                                     coreclkout_hip,
    input  wire                                     refclk0,
    input  wire                                     refclk1,
    input  wire                                     pin_perst_n,
    // RX interface
    output wire [SEG_COUNT*SEG_DATA_WIDTH-1:0]      rx_st_data,
    output wire [SEG_COUNT*SEG_EMPTY_WIDTH-1:0]     rx_st_empty,
    output wire [SEG_COUNT-1:0]                     rx_st_sop,
    output wire [SEG_COUNT-1:0]                     rx_st_eop,
    output wire [SEG_COUNT-1:0]                     rx_st_valid,
    input  wire                                     rx_st_ready,
    output wire [SEG_COUNT*SEG_HDR_WIDTH-1:0]       rx_st_hdr,
    output wire [SEG_COUNT*SEG_PRFX_WIDTH-1:0]      rx_st_tlp_prfx,
    output wire [SEG_COUNT-1:0]                     rx_st_vf_active,
    output wire [SEG_COUNT*3-1:0]                   rx_st_func_num,
    output wire [SEG_COUNT*11-1:0]                  rx_st_vf_num,
    output wire [SEG_COUNT*3-1:0]                   rx_st_bar_range,
    output wire [SEG_COUNT-1:0]                     rx_st_tlp_abort,
    output wire [SEG_COUNT*SEG_DATA_PAR_WIDTH-1:0]  rx_st_data_par,
    output wire [SEG_COUNT*SEG_HDR_PAR_WIDTH-1:0]   rx_st_hdr_par,
    output wire [SEG_COUNT*SEG_PRFX_PAR_WIDTH-1:0]  rx_st_tlp_prfx_par,
    output wire                                     rx_par_err,
    // TX interface
    input  wire [SEG_COUNT*SEG_DATA_WIDTH-1:0]      tx_st_data,
    input  wire [SEG_COUNT-1:0]                     tx_st_sop,
    input  wire [SEG_COUNT-1:0]                     tx_st_eop,
    input  wire [SEG_COUNT-1:0]                     tx_st_valid,
    output wire                                     tx_st_ready,
    input  wire [SEG_COUNT-1:0]                     tx_st_err,
    input  wire [SEG_COUNT*SEG_HDR_WIDTH-1:0]       tx_st_hdr,
    input  wire [SEG_COUNT*SEG_PRFX_WIDTH-1:0]      tx_st_tlp_prfx,
    input  wire [SEG_COUNT*SEG_DATA_PAR_WIDTH-1:0]  tx_st_data_par,
    input  wire [SEG_COUNT*SEG_HDR_PAR_WIDTH-1:0]   tx_st_hdr_par,
    input  wire [SEG_COUNT*SEG_PRFX_PAR_WIDTH-1:0]  tx_st_tlp_prfx_par,
    output wire                                     tx_par_err,
    // RX flow control
    input  wire [11:0]                              rx_buffer_limit,
    input  wire [1:0]                               rx_buffer_limit_tdm_idx,
    // TX flow control
    output wire [15:0]                              tx_cdts_limit,
    output wire [2:0]                               tx_cdts_limit_tdm_idx,
    // Power management and hard IP status interface
    output wire                                     link_up,
    output wire                                     dl_up,
    output wire                                     surprise_down_err,
    output wire [5:0]                               ltssm_state,
    output wire [2:0]                               pm_state,
    output wire [31:0]                              pm_dstate,
    input  wire [7:0]                               apps_pm_xmt_pme,
    input  wire [7:0]                               app_req_retry_en,
    // Interrupt interface
    input  wire [7:0]                               app_int,
    input  wire [2:0]                               msi_pnd_func,
    input  wire [7:0]                               msi_pnd_byte,
    input  wire [1:0]                               msi_pnd_addr,
    // Error interface
    output wire                                     serr_out,
    output wire                                     hip_enter_err_mode,
    input  wire                                     app_err_valid,
    input  wire [31:0]                              app_err_hdr,
    input  wire [12:0]                              app_err_info,
    input  wire [2:0]                               app_err_func_num,
    // Completion timeout interface
    output wire                                     cpl_timeout,
    input  wire                                     cpl_timeout_avmm_clk,
    input  wire [2:0]                               cpl_timeout_avmm_address,
    input  wire                                     cpl_timeout_avmm_read,
    output wire [7:0]                               cpl_timeout_avmm_readdata,
    output wire                                     cpl_timeout_avmm_readdatavalid,
    input  wire                                     cpl_timeout_avmm_write,
    input  wire [7:0]                               cpl_timeout_avmm_writedata,
    output wire                                     cpl_timeout_avmm_waitrequest,
    // Configuration output
    output wire [2:0]                               tl_cfg_func,
    output wire [4:0]                               tl_cfg_add,
    output wire [15:0]                              tl_cfg_ctl,
    output wire                                     dl_timer_update,
    // Configuration intercept interface
    output wire                                     cii_req,
    output wire                                     cii_hdr_poisoned,
    output wire [3:0]                               cii_hdr_first_be,
    output wire [2:0]                               cii_func_num,
    output wire                                     cii_wr_vf_active,
    output wire [10:0]                              cii_vf_num,
    output wire                                     cii_wr,
    output wire [9:0]                               cii_addr,
    output wire [31:0]                              cii_dout,
    input  wire                                     cii_override_en,
    input  wire [31:0]                              cii_override_din,
    input  wire                                     cii_halt,
    // Hard IP reconfiguration interface
    input  wire                                     hip_reconfig_clk,
    input  wire [20:0]                              hip_reconfig_address,
    input  wire                                     hip_reconfig_read,
    output wire [7:0]                               hip_reconfig_readdata,
    output wire                                     hip_reconfig_readdatavalid,
    input  wire                                     hip_reconfig_write,
    input  wire [7:0]                               hip_reconfig_writedata,
    output wire                                     hip_reconfig_waitrequest,
    // Page request service
    input  wire                                     prs_event_valid,
    input  wire [2:0]                               prs_event_func,
    input  wire [1:0]                               prs_event,
    // SR-IOV (VF error)
    output wire                                     vf_err_ur_posted_s0,
    output wire                                     vf_err_ur_posted_s1,
    output wire                                     vf_err_ur_posted_s2,
    output wire                                     vf_err_ur_posted_s3,
    output wire [2:0]                               vf_err_func_num_s0,
    output wire [2:0]                               vf_err_func_num_s1,
    output wire [2:0]                               vf_err_func_num_s2,
    output wire [2:0]                               vf_err_func_num_s3,
    output wire                                     vf_err_ca_postedreq_s0,
    output wire                                     vf_err_ca_postedreq_s1,
    output wire                                     vf_err_ca_postedreq_s2,
    output wire                                     vf_err_ca_postedreq_s3,
    output wire [10:0]                              vf_err_vf_num_s0,
    output wire [10:0]                              vf_err_vf_num_s1,
    output wire [10:0]                              vf_err_vf_num_s2,
    output wire [10:0]                              vf_err_vf_num_s3,
    output wire                                     vf_err_poisonedwrreq_s0,
    output wire                                     vf_err_poisonedwrreq_s1,
    output wire                                     vf_err_poisonedwrreq_s2,
    output wire                                     vf_err_poisonedwrreq_s3,
    output wire                                     vf_err_poisonedcompl_s0,
    output wire                                     vf_err_poisonedcompl_s1,
    output wire                                     vf_err_poisonedcompl_s2,
    output wire                                     vf_err_poisonedcompl_s3,
    input  wire [2:0]                               user_vfnonfatalmsg_func_num,
    input  wire [10:0]                              user_vfnonfatalmsg_vfnum,
    input  wire                                     user_sent_vfnonfatalmsg,
    output wire                                     vf_err_overflow,
    // FLR
    output wire [7:0]                               flr_rcvd_pf,
    output wire                                     flr_rcvd_vf,
    output wire [2:0]                               flr_rcvd_pf_num,
    output wire [10:0]                              flr_rcvd_vf_num,
    input  wire [7:0]                               flr_completed_pf,
    input  wire                                     flr_completed_vf,
    input  wire [2:0]                               flr_completed_pf_num,
    input  wire [10:0]                              flr_completed_vf_num,
    // VirtIO
    output wire                                     virtio_pcicfg_vfaccess,
    output wire [10:0]                              virtio_pcicfg_vfnum,
    output wire [2:0]                               virtio_pcicfg_pfnum,
    output wire [7:0]                               virtio_pcicfg_bar,
    output wire [31:0]                              virtio_pcicfg_length,
    output wire [31:0]                              virtio_pcicfg_baroffset,
    output wire [31:0]                              virtio_pcicfg_cfgdata,
    output wire                                     virtio_pcicfg_cfgwr,
    output wire                                     virtio_pcicfg_cfgrd,
    input  wire [10:0]                              virtio_pcicfg_appvfnum,
    input  wire [2:0]                               virtio_pcicfg_apppfnum,
    input  wire                                     virtio_pcicfg_rdack,
    input  wire [3:0]                               virtio_pcicfg_rdbe,
    input  wire [31:0]                              virtio_pcicfg_data
);

endmodule

`resetall
