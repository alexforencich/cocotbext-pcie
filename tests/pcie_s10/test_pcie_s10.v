/*

Copyright (c) 2021 Alex Forencich

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
 * Intel Stratix 10 H-Tile/L-Tile PCIe IP core model test module
 */
module test_pcie_s10 #
(
    parameter SEG_COUNT = 1,
    parameter SEG_DATA_WIDTH = 256,
    parameter SEG_PARITY_WIDTH = SEG_DATA_WIDTH/8,
    parameter SEG_EMPTY_WIDTH = $clog2(SEG_DATA_WIDTH/32)
)
(
    // Clock and reset
    input  wire                                   npor,
    input  wire                                   pin_perst,
    input  wire                                   ninit_done,
    output wire                                   pld_clk_inuse,
    input  wire                                   pld_core_ready,
    output wire                                   reset_status,
    output wire                                   clr_st,
    input  wire                                   refclk,
    output wire                                   coreclkout_hip,
    // RX interface
    output wire [SEG_COUNT*SEG_DATA_WIDTH-1:0]    rx_st_data,
    output wire [SEG_COUNT*SEG_EMPTY_WIDTH-1:0]   rx_st_empty,
    output wire [SEG_COUNT-1:0]                   rx_st_sop,
    output wire [SEG_COUNT-1:0]                   rx_st_eop,
    output wire [SEG_COUNT-1:0]                   rx_st_valid,
    input  wire                                   rx_st_ready,
    output wire [SEG_COUNT-1:0]                   rx_st_vf_active,
    output wire [SEG_COUNT*2-1:0]                 rx_st_func_num,
    output wire [SEG_COUNT*11-1:0]                rx_st_vf_num,
    output wire [SEG_COUNT*3-1:0]                 rx_st_bar_range,
    output wire [SEG_COUNT*SEG_PARITY_WIDTH-1:0]  rx_st_parity,
    // TX interface
    input  wire [SEG_COUNT*SEG_DATA_WIDTH-1:0]    tx_st_data,
    input  wire [SEG_COUNT-1:0]                   tx_st_sop,
    input  wire [SEG_COUNT-1:0]                   tx_st_eop,
    input  wire [SEG_COUNT-1:0]                   tx_st_valid,
    output wire                                   tx_st_ready,
    input  wire [SEG_COUNT-1:0]                   tx_st_err,
    input  wire [SEG_COUNT-1:0]                   tx_st_vf_active,
    input  wire [SEG_COUNT*SEG_PARITY_WIDTH-1:0]  tx_st_parity,
    // TX flow control
    output wire [7:0]                             tx_ph_cdts,
    output wire [11:0]                            tx_pd_cdts,
    output wire [7:0]                             tx_nph_cdts,
    output wire [11:0]                            tx_npd_cdts,
    output wire [7:0]                             tx_cplh_cdts,
    output wire [11:0]                            tx_cpld_cdts,
    output wire [SEG_COUNT-1:0]                   tx_hdr_cdts_consumed,
    output wire [SEG_COUNT-1:0]                   tx_data_cdts_consumed,
    output wire [SEG_COUNT*2-1:0]                 tx_cdts_type,
    output wire [SEG_COUNT*1-1:0]                 tx_cdts_data_value,
    // Hard IP status
    output wire [10:0]                            int_status,
    output wire [2:0]                             int_status_common,
    output wire                                   derr_cor_ext_rpl,
    output wire                                   derr_rpl,
    output wire                                   derr_cor_ext_rcv,
    output wire                                   derr_uncor_ext_rcv,
    output wire                                   rx_par_err,
    output wire                                   tx_par_err,
    output wire [5:0]                             ltssmstate,
    output wire                                   link_up,
    output wire [4:0]                             lane_act,
    output wire [1:0]                             currentspeed,
    // Power management
    output wire                                   pm_linkst_in_l1,
    output wire                                   pm_linkst_in_l0s,
    output wire [2:0]                             pm_state,
    output wire [2:0]                             pm_dstate,
    input  wire                                   apps_pm_xmt_pme,
    input  wire                                   apps_ready_entr_l23,
    input  wire                                   apps_pm_xmt_turnoff,
    input  wire                                   app_init_rst,
    input  wire                                   app_xfer_pending,
    // Interrupt interface
    input  wire                                   app_msi_req,
    output wire                                   app_msi_ack,
    input  wire [2:0]                             app_msi_tc,
    input  wire [4:0]                             app_msi_num,
    input  wire [1:0]                             app_msi_func_num,
    input  wire [3:0]                             app_int_sts,
    // Error interface
    input  wire                                   app_err_valid,
    input  wire [31:0]                            app_err_hdr,
    input  wire [10:0]                            app_err_info,
    input  wire [1:0]                             app_err_func_num,
    // Configuration output interface
    output wire [1:0]                             tl_cfg_func,
    output wire [4:0]                             tl_cfg_add,
    output wire [31:0]                            tl_cfg_ctl,
    // Configuration extension bus
    output wire                                   ceb_req,
    input  wire                                   ceb_ack,
    output wire [11:0]                            ceb_addr,
    input  wire [31:0]                            ceb_din,
    output wire [31:0]                            ceb_dout,
    output wire [3:0]                             ceb_wr,
    input  wire [31:0]                            ceb_cdm_convert_data,
    output wire [1:0]                             ceb_func_num,
    output wire [10:0]                            ceb_vf_num,
    output wire                                   ceb_vf_active,
    // Hard IP reconfiguration interface
    input  wire                                   hip_reconfig_clk,
    input  wire                                   hip_reconfig_rst_n,
    input  wire [20:0]                            hip_reconfig_address,
    input  wire                                   hip_reconfig_read,
    output wire [7:0]                             hip_reconfig_readdata,
    output wire                                   hip_reconfig_readdatavalid,
    input  wire                                   hip_reconfig_write,
    input  wire [7:0]                             hip_reconfig_writedata,
    output wire                                   hip_reconfig_waitrequest
);

endmodule

`resetall
