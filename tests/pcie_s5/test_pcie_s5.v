/*

Copyright (c) 2026 Anderson Ignacio da Silva

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
 * Intel Stratix V Hard IP for PCI Express (Avalon-ST) core model test module
 */
module test_pcie_s5 #
(
    parameter DATA_WIDTH = 128,
    parameter PARITY_WIDTH = DATA_WIDTH/8,
    parameter EMPTY_WIDTH = $clog2(DATA_WIDTH/64)
)
(
    // Clocks
    input  wire                      refclk,
    input  wire                      pld_clk,
    output wire                      coreclkout,
    // Reset, status, and link training
    input  wire                      npor,
    input  wire                      pin_perst,
    output wire                      reset_status,
    output wire                      clr_st,
    output wire                      serdes_pll_locked,
    input  wire                      pld_core_ready,
    output wire                      pld_clk_inuse,
    output wire                      dlup,
    output wire                      dlup_exit,
    output wire                      hotrst_exit,
    output wire                      l2_exit,
    output wire                      ev128ns,
    output wire                      ev1us,
    output wire [3:0]                lane_act,
    output wire [1:0]                currentspeed,
    output wire [4:0]                ltssmstate,
    // RX interface
    output wire [DATA_WIDTH-1:0]     rx_st_data,
    output wire                      rx_st_sop,
    output wire                      rx_st_eop,
    output wire                      rx_st_valid,
    input  wire                      rx_st_ready,
    output wire [EMPTY_WIDTH-1:0]    rx_st_empty,
    output wire                      rx_st_err,
    output wire [7:0]                rx_st_bar,
    input  wire                      rx_st_mask,
    output wire [PARITY_WIDTH-1:0]   rx_st_parity,
    // TX interface
    input  wire [DATA_WIDTH-1:0]     tx_st_data,
    input  wire                      tx_st_sop,
    input  wire                      tx_st_eop,
    input  wire                      tx_st_valid,
    output wire                      tx_st_ready,
    input  wire [EMPTY_WIDTH-1:0]    tx_st_empty,
    input  wire                      tx_st_err,
    input  wire [PARITY_WIDTH-1:0]   tx_st_parity,
    // TX flow control
    output wire [7:0]                tx_cred_hdrfcp,
    output wire [11:0]               tx_cred_datafcp,
    output wire [7:0]                tx_cred_hdrfcnp,
    output wire [11:0]               tx_cred_datafcnp,
    output wire [7:0]                tx_cred_hdrfccp,
    output wire [11:0]               tx_cred_datafccp,
    output wire [5:0]                tx_cred_fchipcons,
    output wire [5:0]                tx_cred_fc_infinite,
    input  wire                      tx_cons_cred_sel,
    output wire [7:0]                ko_cpl_spc_header,
    output wire [11:0]               ko_cpl_spc_data,
    // Error signals
    output wire                      derr_cor_ext_rcv0,
    output wire                      derr_rpl,
    output wire                      derr_cor_ext_rpl0,
    output wire                      rxfc_cplbuf_ovf,
    // Interrupts for endpoints
    input  wire                      app_msi_req,
    output wire                      app_msi_ack,
    input  wire [2:0]                app_msi_tc,
    input  wire [4:0]                app_msi_num,
    input  wire                      app_int_sts,
    output wire                      app_int_ack,
    // Interrupts for root ports
    output wire [3:0]                int_status,
    output wire                      serr_out,
    // Completion side band signals
    input  wire [6:0]                cpl_err,
    input  wire                      cpl_pending,
    // Transaction layer configuration space signals
    output wire [3:0]                tl_cfg_add,
    output wire [31:0]               tl_cfg_ctl,
    output wire [52:0]               tl_cfg_sts,
    // Power management
    input  wire                      pme_to_cr,
    output wire                      pme_to_sr,
    input  wire                      pm_event,
    input  wire [9:0]                pm_data,
    input  wire                      pm_auxpwr
);

endmodule

`resetall
