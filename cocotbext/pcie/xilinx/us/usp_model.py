"""

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

"""

import enum

import cocotb
from cocotb.clock import Clock
from cocotb.queue import Queue
from cocotb.triggers import RisingEdge, FallingEdge, Timer, First, Event

from cocotbext.pcie.core import Device, Endpoint, __version__
from cocotbext.pcie.core.caps import MsiCapability, MsixCapability
from cocotbext.pcie.core.caps import AerExtendedCapability, PcieExtendedCapability
from cocotbext.pcie.core.utils import PcieId
from cocotbext.pcie.core.tlp import Tlp, TlpType, TlpAttr, CplStatus

from .interface import RqSink, RcSource, CqSource, CcSink
from .tlp import Tlp_us, ErrorCode


valid_configs = [
    # speed, links, width, freq
    (1,  1,  64,  62.5e6),
    (1,  1,  64, 125.0e6),
    (1,  1,  64, 250.0e6),
    (1,  2,  64,  62.5e6),
    (1,  2,  64, 125.0e6),
    (1,  2,  64, 250.0e6),
    (1,  4,  64, 125.0e6),
    (1,  4,  64, 250.0e6),
    (1,  8,  64, 250.0e6),
    (1,  8, 128, 125.0e6),
    (1, 16, 128, 250.0e6),
    (2,  1,  64,  62.5e6),
    (2,  1,  64, 125.0e6),
    (2,  1,  64, 250.0e6),
    (2,  2,  64, 125.0e6),
    (2,  2,  64, 250.0e6),
    (2,  4,  64, 250.0e6),
    (2,  4, 128, 125.0e6),
    (2,  8, 128, 250.0e6),
    (2,  8, 256, 125.0e6),
    (2, 16, 256, 250.0e6),
    (3,  1,  64, 125.0e6),
    (3,  1,  64, 250.0e6),
    (3,  2,  64, 250.0e6),
    (3,  2, 128, 125.0e6),
    (3,  4, 128, 250.0e6),
    (3,  4, 256, 125.0e6),
    (3,  8, 256, 250.0e6),
    (3, 16, 512, 250.0e6),
    (4,  1,  64, 250.0e6),
    (4,  1, 128, 125.0e6),
    (4,  2, 128, 250.0e6),
    (4,  2, 256, 125.0e6),
    (4,  4, 256, 250.0e6),
    (4,  8, 512, 250.0e6),
]


class LocalError(enum.IntEnum):
    PHY_LAYER_ERROR_DETECTED    = 0b00001
    LINK_REPLAY_TIMEOUT         = 0b00010
    LINK_REPLAY_ROLLOVER        = 0b00011
    LINK_RX_BAD_TLP             = 0b00100
    LINK_RX_BAD_DLLP            = 0b00101
    LINK_PROTOCOL_ERR           = 0b00110
    REPLAY_BUF_COR_ECC_ERR      = 0b00111
    REPLAY_BUF_UNCOR_ECC_ERR    = 0b01000
    RX_P_REQ_BUF_COR_ECC_ERR    = 0b01001
    RX_P_REQ_BUF_UNCOR_ECC_ERR  = 0b01010
    RX_CPL_BUF_COR_ECC_ERR      = 0b01011
    RX_CPL_BUF_UNCOR_ECC_ERR    = 0b01100
    RX_P_REQ_BUF_OVF_ERR        = 0b01101
    RX_NP_REQ_BUF_OVF_ERR       = 0b01110
    RX_CPL_BUF_OVF_ERR          = 0b01111
    FC_PROTOCOL_ERR             = 0b10000
    TX_PAR_ERR                  = 0b10001
    RX_UNEXPECTED_CPL           = 0b10010
    CPL_TIMEOUT                 = 0b10011
    AXI4ST_RQ_INTFC_PKT_DROP    = 0b10100
    AXI4ST_CC_INTFC_PKT_DROP    = 0b10101
    AXI4ST_CQ_EP_DROP           = 0b10110
    USER_SIG_INT_COR_ERR        = 0b10111
    USER_SIG_INT_UNCOR_ERR      = 0b11000


class UltraScalePlusPcieFunction(Endpoint):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # PCIe capabilities
        self.register_capability(self.pm_cap, offset=0x10)

        self.msi_cap = MsiCapability()
        self.msi_cap.msi_64bit_address_capable = 1
        self.msi_cap.msi_per_vector_mask_capable = 0
        self.register_capability(self.msi_cap, offset=0x12)

        self.msix_cap = MsixCapability()
        self.register_capability(self.msix_cap, offset=0x18)

        self.register_capability(self.pcie_cap, offset=0x1c)

        # PCIe extended capabilities
        self.aer_ext_cap = AerExtendedCapability()
        self.register_capability(self.aer_ext_cap, offset=0x40)

        # SRIOV 0x50
        # ARI 0x60
        # DSN 0x68

        self.pcie_ext_cap = PcieExtendedCapability()
        self.register_capability(self.pcie_ext_cap, offset=0x70)

        # VC 0x80
        # TPH 0x88
        # VSEC 0xd4 (MCAP)


def init_signal(sig, width=None, initval=None):
    if sig is None:
        return None
    if width is not None:
        assert len(sig) == width
    if initval is not None:
        sig.setimmediatevalue(initval)
    return sig


class UltraScalePlusPcieDevice(Device):
    def __init__(self,
            # configuration options
            pcie_generation=None,
            pcie_link_width=None,
            user_clk_frequency=None,
            alignment="dword",
            cq_straddle=False,
            cc_straddle=False,
            rq_straddle=False,
            rc_straddle=False,
            rc_4tlp_straddle=False,
            pf_count=1,
            max_payload_size=128,
            enable_client_tag=True,
            enable_extended_tag=False,
            enable_parity=False,
            enable_rx_msg_interface=False,
            enable_sriov=False,
            enable_extended_configuration=False,

            pf0_msi_enable=False,
            pf0_msi_count=1,
            pf1_msi_enable=False,
            pf1_msi_count=1,
            pf2_msi_enable=False,
            pf2_msi_count=1,
            pf3_msi_enable=False,
            pf3_msi_count=1,
            pf0_msix_enable=False,
            pf0_msix_table_size=0,
            pf0_msix_table_bir=0,
            pf0_msix_table_offset=0x00000000,
            pf0_msix_pba_bir=0,
            pf0_msix_pba_offset=0x00000000,
            pf1_msix_enable=False,
            pf1_msix_table_size=0,
            pf1_msix_table_bir=0,
            pf1_msix_table_offset=0x00000000,
            pf1_msix_pba_bir=0,
            pf1_msix_pba_offset=0x00000000,
            pf2_msix_enable=False,
            pf2_msix_table_size=0,
            pf2_msix_table_bir=0,
            pf2_msix_table_offset=0x00000000,
            pf2_msix_pba_bir=0,
            pf2_msix_pba_offset=0x00000000,
            pf3_msix_enable=False,
            pf3_msix_table_size=0,
            pf3_msix_table_bir=0,
            pf3_msix_table_offset=0x00000000,
            pf3_msix_pba_bir=0,
            pf3_msix_pba_offset=0x00000000,

            # signals
            # Clock and Reset Interface
            user_clk=None,
            user_reset=None,
            user_lnk_up=None,
            sys_clk=None,
            sys_clk_gt=None,
            sys_reset=None,
            phy_rdy_out=None,

            # Requester reQuest Interface
            rq_bus=None,
            pcie_rq_seq_num0=None,
            pcie_rq_seq_num_vld0=None,
            pcie_rq_seq_num1=None,
            pcie_rq_seq_num_vld1=None,
            pcie_rq_tag0=None,
            pcie_rq_tag1=None,
            pcie_rq_tag_av=None,
            pcie_rq_tag_vld0=None,
            pcie_rq_tag_vld1=None,

            # Requester Completion Interface
            rc_bus=None,

            # Completer reQuest Interface
            cq_bus=None,
            pcie_cq_np_req=None,
            pcie_cq_np_req_count=None,

            # Completer Completion Interface
            cc_bus=None,

            # Transmit Flow Control Interface
            pcie_tfc_nph_av=None,
            pcie_tfc_npd_av=None,

            # Configuration Management Interface
            cfg_mgmt_addr=None,
            cfg_mgmt_function_number=None,
            cfg_mgmt_write=None,
            cfg_mgmt_write_data=None,
            cfg_mgmt_byte_enable=None,
            cfg_mgmt_read=None,
            cfg_mgmt_read_data=None,
            cfg_mgmt_read_write_done=None,
            cfg_mgmt_debug_access=None,

            # Configuration Status Interface
            cfg_phy_link_down=None,
            cfg_phy_link_status=None,
            cfg_negotiated_width=None,
            cfg_current_speed=None,
            cfg_max_payload=None,
            cfg_max_read_req=None,
            cfg_function_status=None,
            cfg_vf_status=None,
            cfg_function_power_state=None,
            cfg_vf_power_state=None,
            cfg_link_power_state=None,
            cfg_err_cor_out=None,
            cfg_err_nonfatal_out=None,
            cfg_err_fatal_out=None,
            cfg_local_error_out=None,
            cfg_local_error_valid=None,
            cfg_rx_pm_state=None,
            cfg_tx_pm_state=None,
            cfg_ltssm_state=None,
            cfg_rcb_status=None,
            cfg_obff_enable=None,
            cfg_pl_status_change=None,
            cfg_tph_requester_enable=None,
            cfg_tph_st_mode=None,
            cfg_vf_tph_requester_enable=None,
            cfg_vf_tph_st_mode=None,

            # Configuration Received Message Interface
            cfg_msg_received=None,
            cfg_msg_received_data=None,
            cfg_msg_received_type=None,

            # Configuration Transmit Message Interface
            cfg_msg_transmit=None,
            cfg_msg_transmit_type=None,
            cfg_msg_transmit_data=None,
            cfg_msg_transmit_done=None,

            # Configuration Flow Control Interface
            cfg_fc_ph=None,
            cfg_fc_pd=None,
            cfg_fc_nph=None,
            cfg_fc_npd=None,
            cfg_fc_cplh=None,
            cfg_fc_cpld=None,
            cfg_fc_sel=None,

            # Configuration Control Interface
            cfg_hot_reset_in=None,
            cfg_hot_reset_out=None,
            cfg_config_space_enable=None,
            cfg_dsn=None,
            cfg_bus_number=None,
            cfg_ds_port_number=None,
            cfg_ds_bus_number=None,
            cfg_ds_device_number=None,
            cfg_ds_function_number=None,
            cfg_power_state_change_ack=None,
            cfg_power_state_change_interrupt=None,
            cfg_err_cor_in=None,
            cfg_err_uncor_in=None,
            cfg_flr_in_process=None,
            cfg_flr_done=None,
            cfg_vf_flr_in_process=None,
            cfg_vf_flr_func_num=None,
            cfg_vf_flr_done=None,
            cfg_pm_aspm_l1_entry_reject=None,
            cfg_pm_aspm_tx_l0s_entry_disable=None,
            cfg_req_pm_transition_l23_ready=None,
            cfg_link_training_enable=None,

            # Configuration Interrupt Controller Interface
            cfg_interrupt_int=None,
            cfg_interrupt_sent=None,
            cfg_interrupt_pending=None,
            cfg_interrupt_msi_enable=None,
            cfg_interrupt_msi_mmenable=None,
            cfg_interrupt_msi_mask_update=None,
            cfg_interrupt_msi_data=None,
            cfg_interrupt_msi_select=None,
            cfg_interrupt_msi_int=None,
            cfg_interrupt_msi_pending_status=None,
            cfg_interrupt_msi_pending_status_data_enable=None,
            cfg_interrupt_msi_pending_status_function_num=None,
            cfg_interrupt_msi_sent=None,
            cfg_interrupt_msi_fail=None,
            cfg_interrupt_msix_enable=None,
            cfg_interrupt_msix_mask=None,
            cfg_interrupt_msix_vf_enable=None,
            cfg_interrupt_msix_vf_mask=None,
            cfg_interrupt_msix_address=None,
            cfg_interrupt_msix_data=None,
            cfg_interrupt_msix_int=None,
            cfg_interrupt_msix_vec_pending=None,
            cfg_interrupt_msix_vec_pending_status=None,
            cfg_interrupt_msix_sent=None,
            cfg_interrupt_msix_fail=None,
            cfg_interrupt_msi_attr=None,
            cfg_interrupt_msi_tph_present=None,
            cfg_interrupt_msi_tph_type=None,
            cfg_interrupt_msi_tph_st_tag=None,
            cfg_interrupt_msi_function_number=None,

            # Configuration Extend Interface
            cfg_ext_read_received=None,
            cfg_ext_write_received=None,
            cfg_ext_register_number=None,
            cfg_ext_function_number=None,
            cfg_ext_write_data=None,
            cfg_ext_write_byte_enable=None,
            cfg_ext_read_data=None,
            cfg_ext_read_data_valid=None,

            *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.log.info("Xilinx UltraScale+ PCIe hard IP core model")
        self.log.info("cocotbext-pcie version %s", __version__)
        self.log.info("Copyright (c) 2020 Alex Forencich")
        self.log.info("https://github.com/alexforencich/cocotbext-pcie")

        self.default_function = UltraScalePlusPcieFunction

        self.dw = None

        self.rq_seq_num = Queue()
        self.rq_tag = Queue()
        self.rc_queue = Queue()
        self.cq_queue = Queue()
        self.cq_np_queue = Queue()
        self.cq_np_req_count = 0
        self.msg_queue = Queue()

        self.rq_np_queue = Queue()
        self.rq_np_queue_dequeue = Event()
        self.rq_np_limit = 16

        # PG213 lists 128 CPLH and "32768B CPLD"
        # Tests confirm 256 CPLH and ~32KB combined header + data
        self.rx_buf_cplh_fc_limit = 256
        self.rx_buf_cpld_fc_limit = 32768 // 16
        self.rx_buf_cplh_fc_count = 0
        self.rx_buf_cpld_fc_count = 0

        self.cpld_credit_limit = self.rx_buf_cpld_fc_limit
        self.cpld_credit_count = 0
        self.cpld_credit_released = Event()

        self.active_request = [None for x in range(256)]
        self.tag_release = Event()
        self.tag_available_count = 32
        self.tag_count = 256
        self.current_tag = 0

        self.local_error = Queue()

        self.config_space_enable = False

        # configuration options
        self.pcie_generation = pcie_generation
        self.pcie_link_width = pcie_link_width
        self.user_clk_frequency = user_clk_frequency
        self.alignment = alignment
        self.cq_straddle = cq_straddle
        self.cc_straddle = cc_straddle
        self.rq_straddle = rq_straddle
        self.rc_straddle = rc_straddle
        self.rc_4tlp_straddle = rc_4tlp_straddle
        self.pf_count = pf_count
        self.max_payload_size = max_payload_size
        self.enable_client_tag = enable_client_tag
        self.enable_extended_tag = enable_extended_tag
        self.enable_parity = enable_parity
        self.enable_rx_msg_interface = enable_rx_msg_interface
        self.enable_sriov = enable_sriov
        self.enable_extended_configuration = enable_extended_configuration

        self.pf0_msi_enable = pf0_msi_enable
        self.pf0_msi_count = pf0_msi_count
        self.pf1_msi_enable = pf1_msi_enable
        self.pf1_msi_count = pf1_msi_count
        self.pf2_msi_enable = pf2_msi_enable
        self.pf2_msi_count = pf2_msi_count
        self.pf3_msi_enable = pf3_msi_enable
        self.pf3_msi_count = pf3_msi_count
        self.pf0_msix_enable = pf0_msix_enable
        self.pf0_msix_table_size = pf0_msix_table_size
        self.pf0_msix_table_bir = pf0_msix_table_bir
        self.pf0_msix_table_offset = pf0_msix_table_offset
        self.pf0_msix_pba_bir = pf0_msix_pba_bir
        self.pf0_msix_pba_offset = pf0_msix_pba_offset
        self.pf1_msix_enable = pf1_msix_enable
        self.pf1_msix_table_size = pf1_msix_table_size
        self.pf1_msix_table_bir = pf1_msix_table_bir
        self.pf1_msix_table_offset = pf1_msix_table_offset
        self.pf1_msix_pba_bir = pf1_msix_pba_bir
        self.pf1_msix_pba_offset = pf1_msix_pba_offset
        self.pf2_msix_enable = pf2_msix_enable
        self.pf2_msix_table_size = pf2_msix_table_size
        self.pf2_msix_table_bir = pf2_msix_table_bir
        self.pf2_msix_table_offset = pf2_msix_table_offset
        self.pf2_msix_pba_bir = pf2_msix_pba_bir
        self.pf2_msix_pba_offset = pf2_msix_pba_offset
        self.pf3_msix_enable = pf3_msix_enable
        self.pf3_msix_table_size = pf3_msix_table_size
        self.pf3_msix_table_bir = pf3_msix_table_bir
        self.pf3_msix_table_offset = pf3_msix_table_offset
        self.pf3_msix_pba_bir = pf3_msix_pba_bir
        self.pf3_msix_pba_offset = pf3_msix_pba_offset

        # signals

        # Clock and Reset Interface
        self.user_clk = init_signal(user_clk, 1, 0)
        self.user_reset = init_signal(user_reset, 1, 0)
        self.user_lnk_up = init_signal(user_lnk_up, 1, 0)
        self.sys_clk = init_signal(sys_clk, 1)
        self.sys_clk_gt = init_signal(sys_clk_gt, 1)
        self.sys_reset = init_signal(sys_reset, 1)
        self.phy_rdy_out = init_signal(phy_rdy_out, 1, 0)

        # Requester reQuest Interface
        self.rq_sink = None
        self.pcie_rq_seq_num0 = init_signal(pcie_rq_seq_num0, 6, 0)
        self.pcie_rq_seq_num_vld0 = init_signal(pcie_rq_seq_num_vld0, 1, 0)
        self.pcie_rq_seq_num1 = init_signal(pcie_rq_seq_num1, 6, 0)
        self.pcie_rq_seq_num_vld1 = init_signal(pcie_rq_seq_num_vld1, 1, 0)
        self.pcie_rq_tag0 = init_signal(pcie_rq_tag0, 8, 0)
        self.pcie_rq_tag1 = init_signal(pcie_rq_tag1, 8, 0)
        self.pcie_rq_tag_av = init_signal(pcie_rq_tag_av, 4, 0)
        self.pcie_rq_tag_vld0 = init_signal(pcie_rq_tag_vld0, 1, 0)
        self.pcie_rq_tag_vld1 = init_signal(pcie_rq_tag_vld1, 1, 0)

        if rq_bus is not None:
            rq_segments = 1
            if len(rq_bus.tdata) == 512 and self.rq_straddle:
                rq_segments = 2
            self.rq_sink = RqSink(rq_bus, self.user_clk, self.user_reset, segments=rq_segments)
            self.rq_sink.queue_occupancy_limit_frames = 2
            self.dw = self.rq_sink.width

        # Requester Completion Interface
        self.rc_source = None

        if rc_bus is not None:
            rc_segments = 1
            if len(rc_bus.tdata) == 512 and self.rc_4tlp_straddle:
                rc_segments = 4
            elif len(rc_bus.tdata) >= 256 and self.rc_straddle:
                rc_segments = 2
            self.rc_source = RcSource(rc_bus, self.user_clk, self.user_reset, segments=rc_segments)
            self.rc_source.queue_occupancy_limit_frames = 2
            self.dw = self.rc_source.width

        # Completer reQuest Interface
        self.cq_source = None
        self.pcie_cq_np_req = init_signal(pcie_cq_np_req, 2)
        self.pcie_cq_np_req_count = init_signal(pcie_cq_np_req_count, 6, 0)

        if cq_bus is not None:
            cq_segments = 1
            if len(cq_bus.tdata) == 512 and self.cq_straddle:
                cq_segments = 2
            self.cq_source = CqSource(cq_bus, self.user_clk, self.user_reset, segments=cq_segments)
            self.cq_source.queue_occupancy_limit_frames = 2
            self.dw = self.cq_source.width

        # Completer Completion Interface
        self.cc_sink = None

        if cc_bus is not None:
            cc_segments = 1
            if len(cc_bus.tdata) == 512 and self.cc_straddle:
                cc_segments = 2
            self.cc_sink = CcSink(cc_bus, self.user_clk, self.user_reset, segments=cc_segments)
            self.cc_sink.queue_occupancy_limit_frames = 2
            self.dw = self.cc_sink.width

        # Transmit Flow Control Interface
        self.pcie_tfc_nph_av = init_signal(pcie_tfc_nph_av, 4, 0)
        self.pcie_tfc_npd_av = init_signal(pcie_tfc_npd_av, 4, 0)

        # Configuration Management Interface
        self.cfg_mgmt_addr = init_signal(cfg_mgmt_addr, 10)
        self.cfg_mgmt_function_number = init_signal(cfg_mgmt_function_number, 8)
        self.cfg_mgmt_write = init_signal(cfg_mgmt_write, 1)
        self.cfg_mgmt_write_data = init_signal(cfg_mgmt_write_data, 32)
        self.cfg_mgmt_byte_enable = init_signal(cfg_mgmt_byte_enable, 4)
        self.cfg_mgmt_read = init_signal(cfg_mgmt_read, 1)
        self.cfg_mgmt_read_data = init_signal(cfg_mgmt_read_data, 32, 0)
        self.cfg_mgmt_read_write_done = init_signal(cfg_mgmt_read_write_done, 1, 0)
        self.cfg_mgmt_debug_access = init_signal(cfg_mgmt_debug_access, 1)

        # Configuration Status Interface
        self.cfg_phy_link_down = init_signal(cfg_phy_link_down, 1, 0)
        self.cfg_phy_link_status = init_signal(cfg_phy_link_status, 2, 0)
        self.cfg_negotiated_width = init_signal(cfg_negotiated_width, 3, 0)
        self.cfg_current_speed = init_signal(cfg_current_speed, 2, 0)
        self.cfg_max_payload = cfg_max_payload
        if self.cfg_max_payload is not None:
            assert len(self.cfg_max_payload) in {2, 3}
            self.cfg_max_payload.setimmediatevalue(0)
        self.cfg_max_read_req = init_signal(cfg_max_read_req, 3, 0)
        self.cfg_function_status = init_signal(cfg_function_status, 16, 0)
        self.cfg_vf_status = init_signal(cfg_vf_status, 504, 0)
        self.cfg_function_power_state = init_signal(cfg_function_power_state, 12, 0)
        self.cfg_vf_power_state = init_signal(cfg_vf_power_state, 756, 0)
        self.cfg_link_power_state = init_signal(cfg_link_power_state, 2, 0)
        self.cfg_err_cor_out = init_signal(cfg_err_cor_out, 1, 0)
        self.cfg_err_nonfatal_out = init_signal(cfg_err_nonfatal_out, 1, 0)
        self.cfg_err_fatal_out = init_signal(cfg_err_fatal_out, 1, 0)
        self.cfg_local_error_out = init_signal(cfg_local_error_out, 5, 0)
        self.cfg_local_error_valid = init_signal(cfg_local_error_valid, 1, 0)
        self.cfg_rx_pm_state = init_signal(cfg_rx_pm_state, 2, 0)
        self.cfg_tx_pm_state = init_signal(cfg_tx_pm_state, 2, 0)
        self.cfg_ltssm_state = init_signal(cfg_ltssm_state, 6, 0)
        self.cfg_rcb_status = init_signal(cfg_rcb_status, 4, 0)
        self.cfg_obff_enable = init_signal(cfg_obff_enable, 2, 0)
        self.cfg_pl_status_change = init_signal(cfg_pl_status_change, 1, 0)
        self.cfg_tph_requester_enable = init_signal(cfg_tph_requester_enable, 4, 0)
        self.cfg_tph_st_mode = init_signal(cfg_tph_st_mode, 12, 0)
        self.cfg_vf_tph_requester_enable = init_signal(cfg_vf_tph_requester_enable, 252, 0)
        self.cfg_vf_tph_st_mode = init_signal(cfg_vf_tph_st_mode, 756, 0)

        # Configuration Received Message Interface
        self.cfg_msg_received = init_signal(cfg_msg_received, 1, 0)
        self.cfg_msg_received_data = init_signal(cfg_msg_received_data, 8, 0)
        self.cfg_msg_received_type = init_signal(cfg_msg_received_type, 5, 0)

        # Configuration Transmit Message Interface
        self.cfg_msg_transmit = init_signal(cfg_msg_transmit, 1)
        self.cfg_msg_transmit_type = init_signal(cfg_msg_transmit_type, 3)
        self.cfg_msg_transmit_data = init_signal(cfg_msg_transmit_data, 32)
        self.cfg_msg_transmit_done = init_signal(cfg_msg_transmit_done, 1, 0)

        # Configuration Flow Control Interface
        self.cfg_fc_ph = init_signal(cfg_fc_ph, 8, 0)
        self.cfg_fc_pd = init_signal(cfg_fc_pd, 12, 0)
        self.cfg_fc_nph = init_signal(cfg_fc_nph, 8, 0)
        self.cfg_fc_npd = init_signal(cfg_fc_npd, 12, 0)
        self.cfg_fc_cplh = init_signal(cfg_fc_cplh, 8, 0)
        self.cfg_fc_cpld = init_signal(cfg_fc_cpld, 12, 0)
        if isinstance(cfg_fc_sel, int):
            assert 0 <= cfg_fc_sel < 8
            self.cfg_fc_sel = cfg_fc_sel
        else:
            self.cfg_fc_sel = init_signal(cfg_fc_sel, 3)

        # Configuration Control Interface
        self.cfg_hot_reset_in = init_signal(cfg_hot_reset_in, 1)
        self.cfg_hot_reset_out = init_signal(cfg_hot_reset_out, 1, 0)
        self.cfg_config_space_enable = init_signal(cfg_config_space_enable, 1)
        self.cfg_dsn = init_signal(cfg_dsn, 64)
        self.cfg_bus_number = init_signal(cfg_bus_number, 8, 0)
        self.cfg_ds_port_number = init_signal(cfg_ds_port_number, 8)
        self.cfg_ds_bus_number = init_signal(cfg_ds_bus_number, 8)
        self.cfg_ds_device_number = init_signal(cfg_ds_device_number, 5)
        self.cfg_ds_function_number = init_signal(cfg_ds_function_number, 3)
        self.cfg_power_state_change_ack = init_signal(cfg_power_state_change_ack, 1)
        self.cfg_power_state_change_interrupt = init_signal(cfg_power_state_change_interrupt, 1, 0)
        self.cfg_err_cor_in = init_signal(cfg_err_cor_in, 1)
        self.cfg_err_uncor_in = init_signal(cfg_err_uncor_in, 1)
        self.cfg_flr_in_process = init_signal(cfg_flr_in_process, 4)
        self.cfg_flr_done = init_signal(cfg_flr_done, 4)
        self.cfg_vf_flr_in_process = init_signal(cfg_vf_flr_in_process, 252)
        self.cfg_vf_flr_func_num = init_signal(cfg_vf_flr_func_num, 8)
        self.cfg_vf_flr_done = init_signal(cfg_vf_flr_done, 1)
        self.cfg_pm_aspm_l1_entry_reject = init_signal(cfg_pm_aspm_l1_entry_reject, 1)
        self.cfg_pm_aspm_tx_l0s_entry_disable = init_signal(cfg_pm_aspm_tx_l0s_entry_disable, 1)
        self.cfg_req_pm_transition_l23_ready = init_signal(cfg_req_pm_transition_l23_ready, 1)
        self.cfg_link_training_enable = init_signal(cfg_link_training_enable, 1)

        # Configuration Interrupt Controller Interface
        self.cfg_interrupt_int = init_signal(cfg_interrupt_int, 4)
        self.cfg_interrupt_sent = init_signal(cfg_interrupt_sent, 1, 0)
        self.cfg_interrupt_pending = init_signal(cfg_interrupt_pending, 4)
        self.cfg_interrupt_msi_enable = init_signal(cfg_interrupt_msi_enable, 4, 0)
        self.cfg_interrupt_msi_mmenable = init_signal(cfg_interrupt_msi_mmenable, 12, 0)
        self.cfg_interrupt_msi_mask_update = init_signal(cfg_interrupt_msi_mask_update, 1, 0)
        self.cfg_interrupt_msi_data = init_signal(cfg_interrupt_msi_data, 32, 0)
        self.cfg_interrupt_msi_select = init_signal(cfg_interrupt_msi_select, 2)
        self.cfg_interrupt_msi_int = init_signal(cfg_interrupt_msi_int, 32)
        self.cfg_interrupt_msi_pending_status = init_signal(cfg_interrupt_msi_pending_status, 32)
        self.cfg_interrupt_msi_pending_status_data_enable = init_signal(cfg_interrupt_msi_pending_status_data_enable, 1)
        self.cfg_interrupt_msi_pending_status_function_num = init_signal(cfg_interrupt_msi_pending_status_function_num, 2)
        self.cfg_interrupt_msi_fail = init_signal(cfg_interrupt_msi_fail, 1, 0)
        self.cfg_interrupt_msi_sent = init_signal(cfg_interrupt_msi_sent, 1, 0)
        self.cfg_interrupt_msix_enable = init_signal(cfg_interrupt_msix_enable, 4, 0)
        self.cfg_interrupt_msix_mask = init_signal(cfg_interrupt_msix_mask, 4)
        self.cfg_interrupt_msix_vf_enable = init_signal(cfg_interrupt_msix_vf_enable, 252, 0)
        self.cfg_interrupt_msix_vf_mask = init_signal(cfg_interrupt_msix_vf_mask, 252)
        self.cfg_interrupt_msix_address = init_signal(cfg_interrupt_msix_address, 64)
        self.cfg_interrupt_msix_data = init_signal(cfg_interrupt_msix_data, 32)
        self.cfg_interrupt_msix_int = init_signal(cfg_interrupt_msix_int, 1)
        self.cfg_interrupt_msix_vec_pending = init_signal(cfg_interrupt_msix_vec_pending, 2)
        self.cfg_interrupt_msix_vec_pending_status = init_signal(cfg_interrupt_msix_vec_pending_status, 1)
        self.cfg_interrupt_msix_sent = init_signal(cfg_interrupt_msix_sent, 1, 0)
        self.cfg_interrupt_msix_fail = init_signal(cfg_interrupt_msix_fail, 1, 0)
        self.cfg_interrupt_msi_attr = init_signal(cfg_interrupt_msi_attr, 3)
        self.cfg_interrupt_msi_tph_present = init_signal(cfg_interrupt_msi_tph_present, 1)
        self.cfg_interrupt_msi_tph_type = init_signal(cfg_interrupt_msi_tph_type, 2)
        self.cfg_interrupt_msi_tph_st_tag = init_signal(cfg_interrupt_msi_tph_st_tag, 8)
        self.cfg_interrupt_msi_function_number = init_signal(cfg_interrupt_msi_function_number, 8)

        # Configuration Extend Interface
        self.cfg_ext_read_received = init_signal(cfg_ext_read_received, 1, 0)
        self.cfg_ext_write_received = init_signal(cfg_ext_write_received, 1, 0)
        self.cfg_ext_register_number = init_signal(cfg_ext_register_number, 10, 0)
        self.cfg_ext_function_number = init_signal(cfg_ext_function_number, 8, 0)
        self.cfg_ext_write_data = init_signal(cfg_ext_write_data, 32, 0)
        self.cfg_ext_write_byte_enable = init_signal(cfg_ext_write_byte_enable, 4, 0)
        self.cfg_ext_read_data = init_signal(cfg_ext_read_data, 32)
        self.cfg_ext_read_data_valid = init_signal(cfg_ext_read_data_valid, 1)

        # validate parameters
        assert self.dw in {64, 128, 256, 512}

        # rescale clock frequency
        if self.user_clk_frequency is not None and self.user_clk_frequency < 1e6:
            self.user_clk_frequency *= 1e6

        if not self.pcie_generation or not self.pcie_link_width or not self.user_clk_frequency:
            self.log.info("Incomplete configuration specified, attempting to select reasonable options")
            # guess some reasonable values for unspecified parameters
            for config in reversed(valid_configs):
                # find configuration matching specified parameters
                if self.pcie_generation is not None and self.pcie_generation != config[0]:
                    continue
                if self.pcie_link_width is not None and self.pcie_link_width != config[1]:
                    continue
                if self.dw != config[2]:
                    continue
                if self.user_clk_frequency is not None and self.user_clk_frequency != config[3]:
                    continue

                # set the unspecified parameters
                if self.pcie_generation is None:
                    self.log.info("Setting PCIe speed to gen %d", config[0])
                    self.pcie_generation = config[0]
                if self.pcie_link_width is None:
                    self.log.info("Setting PCIe link width to x%d", config[1])
                    self.pcie_link_width = config[1]
                if self.user_clk_frequency is None:
                    self.log.info("Setting user clock frequency to %d MHz", config[3]/1e6)
                    self.user_clk_frequency = config[3]
                break

        self.log.info("Xilinx UltraScale+ PCIe hard IP core configuration:")
        self.log.info("  PCIe speed: gen %d", self.pcie_generation)
        self.log.info("  PCIe link width: x%d", self.pcie_link_width)
        self.log.info("  User clock frequency: %d MHz", self.user_clk_frequency/1e6)
        self.log.info("  Alignment: %s", self.alignment)
        self.log.info("  Enable CQ straddling: %s", self.cq_straddle)
        self.log.info("  Enable CC straddling: %s", self.cc_straddle)
        self.log.info("  Enable RQ straddling: %s", self.rq_straddle)
        self.log.info("  Enable RC straddling: %s", self.rc_straddle)
        self.log.info("  Enable RC 4 TLP straddling: %s", self.rc_4tlp_straddle)
        self.log.info("  PF count: %d", self.pf_count)
        self.log.info("  Max payload size: %d", self.max_payload_size)
        self.log.info("  Enable client tag: %s", self.enable_client_tag)
        self.log.info("  Enable extended tag: %s", self.enable_extended_tag)
        self.log.info("  Enable parity: %s", self.enable_parity)
        self.log.info("  Enable RX message interface: %s", self.enable_rx_msg_interface)
        self.log.info("  Enable SR-IOV: %s", self.enable_sriov)
        self.log.info("  Enable extended configuration: %s", self.enable_extended_configuration)
        self.log.info("  Enable PF0 MSI: %s", self.pf0_msi_enable)
        self.log.info("  PF0 MSI vector count: %d", self.pf0_msi_count)
        self.log.info("  Enable PF1 MSI: %s", self.pf1_msi_enable)
        self.log.info("  PF1 MSI vector count: %d", self.pf1_msi_count)
        self.log.info("  Enable PF2 MSI: %s", self.pf2_msi_enable)
        self.log.info("  PF2 MSI vector count: %d", self.pf2_msi_count)
        self.log.info("  Enable PF3 MSI: %s", self.pf3_msi_enable)
        self.log.info("  PF3 MSI vector count: %d", self.pf3_msi_count)
        self.log.info("  Enable PF0 MSIX: %s", self.pf0_msix_enable)
        self.log.info("  PF0 MSIX table size: %d", self.pf0_msix_table_size)
        self.log.info("  PF0 MSIX table BIR: %d", self.pf0_msix_table_bir)
        self.log.info("  PF0 MSIX table offset: 0x%08x", self.pf0_msix_table_offset)
        self.log.info("  PF0 MSIX PBA BIR: %d", self.pf0_msix_pba_bir)
        self.log.info("  PF0 MSIX PBA offset: 0x%08x", self.pf0_msix_pba_offset)
        self.log.info("  Enable PF1 MSIX: %s", self.pf1_msix_enable)
        self.log.info("  PF1 MSIX table size: %d", self.pf1_msix_table_size)
        self.log.info("  PF1 MSIX table BIR: %d", self.pf1_msix_table_bir)
        self.log.info("  PF1 MSIX table offset: 0x%08x", self.pf1_msix_table_offset)
        self.log.info("  PF1 MSIX PBA BIR: %d", self.pf1_msix_pba_bir)
        self.log.info("  PF1 MSIX PBA offset: 0x%08x", self.pf1_msix_pba_offset)
        self.log.info("  Enable PF2 MSIX: %s", self.pf2_msix_enable)
        self.log.info("  PF2 MSIX table size: %d", self.pf2_msix_table_size)
        self.log.info("  PF2 MSIX table BIR: %d", self.pf2_msix_table_bir)
        self.log.info("  PF2 MSIX table offset: 0x%08x", self.pf2_msix_table_offset)
        self.log.info("  PF2 MSIX PBA BIR: %d", self.pf2_msix_pba_bir)
        self.log.info("  PF2 MSIX PBA offset: 0x%08x", self.pf2_msix_pba_offset)
        self.log.info("  Enable PF3 MSIX: %s", self.pf3_msix_enable)
        self.log.info("  PF3 MSIX table size: %d", self.pf3_msix_table_size)
        self.log.info("  PF3 MSIX table BIR: %d", self.pf3_msix_table_bir)
        self.log.info("  PF3 MSIX table offset: 0x%08x", self.pf3_msix_table_offset)
        self.log.info("  PF3 MSIX PBA BIR: %d", self.pf3_msix_pba_bir)
        self.log.info("  PF3 MSIX PBA offset: 0x%08x", self.pf3_msix_pba_offset)

        assert self.pcie_generation in {1, 2, 3, 4}
        assert self.pcie_link_width in {1, 2, 4, 8, 16}
        assert self.user_clk_frequency in {62.5e6, 125e6, 250e6}
        assert self.alignment in {"address", "dword"}

        if self.dw < 256 or self.alignment != "dword":
            assert not self.rc_straddle, "RC straddling only supported with 256- or 512-bit, DWORD-aligned interface"
            if self.dw != 512:
                assert not self.rq_straddle, "RQ straddling only supported with 512-bit, DWORD-aligned interface"
                assert not self.cq_straddle, "CQ straddling only supported with 512-bit, DWORD-aligned interface"
                assert not self.cc_straddle, "CC straddling only supported with 512-bit, DWORD-aligned interface"
                assert not self.rc_4tlp_straddle, "RC 4 TLP straddling only supported with 512-bit, DWORD-aligned interface"

        # TODO change this when support added
        assert self.alignment == 'dword', "only dword alignment currently supported"

        # check for valid configuration
        config_valid = False
        for config in valid_configs:
            if self.pcie_generation != config[0]:
                continue
            if self.pcie_link_width != config[1]:
                continue
            if self.dw != config[2]:
                continue
            if self.user_clk_frequency != config[3]:
                continue

            config_valid = True
            break

        assert config_valid, "link speed/link width/clock speed/interface width setting combination not valid"

        # configure port
        self.upstream_port.max_link_speed = self.pcie_generation
        self.upstream_port.max_link_width = self.pcie_link_width

        # configure functions

        self.make_function()

        if self.pf0_msi_enable:
            self.functions[0].msi_cap.msi_multiple_message_capable = (self.pf0_msi_count-1).bit_length()
        else:
            self.functions[0].deregister_capability(self.functions[0].msi_cap)

        if self.pf0_msix_enable:
            self.functions[0].msix_cap.msix_table_size = self.pf0_msix_table_size
            self.functions[0].msix_cap.msix_table_bar_indicator_register = self.pf0_msix_table_bir
            self.functions[0].msix_cap.msix_table_offset = self.pf0_msix_table_offset
            self.functions[0].msix_cap.msix_pba_bar_indicator_register = self.pf0_msix_pba_bir
            self.functions[0].msix_cap.msix_pba_offset = self.pf0_msix_pba_offset
        else:
            self.functions[0].deregister_capability(self.functions[0].msix_cap)

        if self.pf_count > 1:
            self.make_function()

            if self.pf1_msi_enable:
                self.functions[1].msi_cap.msi_multiple_message_capable = (self.pf1_msi_count-1).bit_length()
            else:
                self.functions[1].deregister_capability(self.functions[1].msi_cap)

            if self.pf1_msix_enable:
                self.functions[1].msix_cap.msix_table_size = self.pf1_msix_table_size
                self.functions[1].msix_cap.msix_table_bar_indicator_register = self.pf1_msix_table_bir
                self.functions[1].msix_cap.msix_table_offset = self.pf1_msix_table_offset
                self.functions[1].msix_cap.msix_pba_bar_indicator_register = self.pf1_msix_pba_bir
                self.functions[1].msix_cap.msix_pba_offset = self.pf1_msix_pba_offset
            else:
                self.functions[1].deregister_capability(self.functions[1].msix_cap)

        if self.pf_count > 2:
            self.make_function()

            if self.pf2_msi_enable:
                self.functions[2].msi_cap.msi_multiple_message_capable = (self.pf2_msi_count-2).bit_length()
            else:
                self.functions[2].deregister_capability(self.functions[2].msi_cap)

            if self.pf2_msix_enable:
                self.functions[2].msix_cap.msix_table_size = self.pf2_msix_table_size
                self.functions[2].msix_cap.msix_table_bar_indicator_register = self.pf2_msix_table_bir
                self.functions[2].msix_cap.msix_table_offset = self.pf2_msix_table_offset
                self.functions[2].msix_cap.msix_pba_bar_indicator_register = self.pf2_msix_pba_bir
                self.functions[2].msix_cap.msix_pba_offset = self.pf2_msix_pba_offset
            else:
                self.functions[2].deregister_capability(self.functions[2].msix_cap)

        if self.pf_count > 3:
            self.make_function()

            if self.pf3_msi_enable:
                self.functions[3].msi_cap.msi_multiple_message_capable = (self.pf3_msi_count-3).bit_length()
            else:
                self.functions[3].deregister_capability(self.functions[3].msi_cap)

            if self.pf3_msix_enable:
                self.functions[3].msix_cap.msix_table_size = self.pf3_msix_table_size
                self.functions[3].msix_cap.msix_table_bar_indicator_register = self.pf3_msix_table_bir
                self.functions[3].msix_cap.msix_table_offset = self.pf3_msix_table_offset
                self.functions[3].msix_cap.msix_pba_bar_indicator_register = self.pf3_msix_pba_bir
                self.functions[3].msix_cap.msix_pba_offset = self.pf3_msix_pba_offset
            else:
                self.functions[3].deregister_capability(self.functions[3].msix_cap)

        for f in self.functions:
            f.pcie_cap.max_payload_size_supported = (self.max_payload_size//128-1).bit_length()
            f.pcie_cap.extended_tag_supported = self.enable_extended_tag

        if self.cfg_config_space_enable is None:
            self.config_space_enable = True

        # fork coroutines

        if self.user_clk is not None:
            cocotb.start_soon(Clock(self.user_clk, int(1e9/self.user_clk_frequency), units="ns").start())

        if self.rq_sink:
            cocotb.start_soon(self._run_rq_logic())
            cocotb.start_soon(self._run_rq_np_queue_logic())
            cocotb.start_soon(self._run_rq_seq_num_logic())
            if not self.enable_client_tag:
                cocotb.start_soon(self._run_rq_tag_logic())
        if self.rc_source:
            cocotb.start_soon(self._run_rc_logic())
        if self.cq_source:
            cocotb.start_soon(self._run_cq_logic())
        if self.cc_sink:
            cocotb.start_soon(self._run_cc_logic())
        if self.cfg_mgmt_addr is not None:
            cocotb.start_soon(self._run_cfg_mgmt_logic())
        cocotb.start_soon(self._run_cfg_status_logic())
        if self.cfg_fc_sel is not None:
            cocotb.start_soon(self._run_cfg_fc_logic())
        cocotb.start_soon(self._run_cfg_ctrl_logic())
        cocotb.start_soon(self._run_cfg_int_logic())

        cocotb.start_soon(self._run_reset())

    def get_free_tag(self):
        tag_count = min(256 if self.functions[0].pcie_cap.extended_tag_field_enable else 32, self.tag_count)

        tag = self.current_tag
        for k in range(tag_count):
            tag = (tag + 1) % tag_count
            if self.active_request[tag] is None:
                self.current_tag = tag
                return tag

        return None

    def get_available_tag_count(self):
        if self.functions[0].pcie_cap.extended_tag_field_enable:
            return self.active_request.count(None)
        else:
            return self.active_request[0:32].count(None)

    async def upstream_recv(self, tlp):
        self.log.debug("Got downstream TLP: %r", tlp)

        if tlp.fmt_type in {TlpType.CFG_READ_0, TlpType.CFG_WRITE_0}:
            # config type 0

            if not self.config_space_enable:
                self.log.warning("Configuration space disabled")

                tlp.release_fc()

                cpl = Tlp.create_crs_completion_for_tlp(tlp, PcieId(self.bus_num, 0, 0))
                self.log.debug("CRS Completion: %r", cpl)
                await self.upstream_send(cpl)
                return
            else:
                # capture address information
                self.bus_num = tlp.dest_id.bus

                # pass TLP to function
                for f in self.functions:
                    if f.pcie_id == tlp.dest_id:
                        await f.upstream_recv(tlp)
                        return

                tlp.release_fc()

                self.log.warning("Function not found: failed to route config type 0 TLP: %r", tlp)

        elif tlp.fmt_type in {TlpType.CFG_READ_1, TlpType.CFG_WRITE_1}:
            # config type 1

            tlp.release_fc()

            self.log.warning("Malformed TLP: endpoint received config type 1 TLP: %r", tlp)
        elif tlp.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
            # Completion

            for f in self.functions:
                if f.pcie_id == tlp.requester_id:

                    tlp.release_fc()

                    tlp = Tlp_us(tlp)

                    tlp.error_code = ErrorCode.NORMAL_TERMINATION

                    if tlp.ep:
                        # poisoned
                        self.log.warning("Poisoned TLP: %r", tlp)
                        tlp.error_code = ErrorCode.POISONED

                    req = self.active_request[tlp.tag]

                    if not req:
                        # tag not active
                        self.log.warning("Invalid tag: %r", tlp)
                        tlp.error_code = ErrorCode.INVALID_TAG
                    elif tlp.requester_id != req.requester_id or tlp.attr != req.attr or tlp.tc != req.tc:
                        # requester ID, ATTR, or TC field mismatch
                        self.log.warning("Mismatched fields: %r", tlp)
                        tlp.error_code = ErrorCode.MISMATCH
                    elif tlp.status != CplStatus.SC:
                        # bad status
                        self.log.warning("Bad status: %r", tlp)
                        tlp.error_code = ErrorCode.BAD_STATUS
                        tlp.request_completed = True
                        self.active_request[tlp.tag] = None
                    elif req.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64}:
                        # completion for memory read request

                        # reconstruct lower address MSBs
                        lower_address = req.address + req.get_first_be_offset() + req.get_be_byte_count() - tlp.byte_count

                        if tlp.lower_address != lower_address & 0x7f:
                            self.log.warning("Lower address mismatch: %r", tlp)
                            tlp.error_code = ErrorCode.INVALID_ADDRESS
                        else:
                            tlp.lower_address = lower_address & 0xfff

                        # mark request completed
                        if tlp.byte_count <= tlp.length*4 - (tlp.lower_address & 0x3):
                            tlp.request_completed = True
                            self.active_request[tlp.tag] = None

                        # completion for read request has SC status but no data
                        if tlp.fmt_type in {TlpType.CPL, TlpType.CPL_LOCKED}:
                            tlp.error_code = ErrorCode.INVALID_LENGTH
                            tlp.request_completed = True
                            self.active_request[tlp.tag] = None

                    else:
                        # completion for other request
                        tlp.request_completed = True
                        self.active_request[tlp.tag] = None

                    # TODO track individual operations
                    self.cpld_credit_count = max(self.cpld_credit_count-tlp.get_data_credits(), 0)
                    self.cpld_credit_released.set()

                    # check and track buffer occupancy
                    data_fc = tlp.get_data_credits()

                    if self.rx_buf_cplh_fc_count+1 <= self.rx_buf_cplh_fc_limit and self.rx_buf_cpld_fc_count+data_fc+1 <= self.rx_buf_cpld_fc_limit:
                        self.rx_buf_cplh_fc_count += 1
                        self.rx_buf_cpld_fc_count += data_fc+1
                        self.rc_queue.put_nowait(tlp)
                    else:
                        self.log.warning("No space in RX completion buffer, dropping TLP: CPLH %d (limit %d), CPLD %d (limit %d)",
                            self.rx_buf_cplh_fc_count, self.rx_buf_cplh_fc_limit, self.rx_buf_cpld_fc_count, self.rx_buf_cpld_fc_limit)
                        self.local_error.put_nowait(LocalError.RX_CPL_BUF_OVF_ERR)

                    self.tag_available_count = self.get_available_tag_count()

                    return

            tlp.release_fc()

            self.log.warning("Unexpected completion: failed to route completion to function: %r", tlp)
            return  # no UR response for completion
        elif tlp.fmt_type in {TlpType.IO_READ, TlpType.IO_WRITE}:
            # IO read/write

            for f in self.functions:
                bar = f.match_bar(tlp.address, True)
                if bar:

                    tlp.release_fc()

                    tlp = Tlp_us(tlp)
                    tlp.bar_id = bar[0]
                    tlp.bar_aperture = (~self.functions[0].bar_mask[bar[0]] & 0xffffffff).bit_length()
                    tlp.completer_id = tlp.completer_id._replace(bus=self.bus_num)
                    self.cq_queue.put_nowait(tlp)

                    return

            tlp.release_fc()

            self.log.warning("No BAR match: IO request did not match any BARs: %r", tlp)
        elif tlp.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64, TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
            # Memory read/write

            for f in self.functions:
                bar = f.match_bar(tlp.address)
                if bar:

                    tlp.release_fc()

                    tlp = Tlp_us(tlp)
                    tlp.bar_id = bar[0]
                    if self.functions[0].bar[bar[0]] & 4:
                        tlp.bar_aperture = (~(self.functions[0].bar_mask[bar[0]] |
                            (self.functions[0].bar_mask[bar[0]+1] << 32)) & 0xffffffffffffffff).bit_length()
                    else:
                        tlp.bar_aperture = (~self.functions[0].bar_mask[bar[0]] & 0xffffffff).bit_length()
                    tlp.completer_id = f.pcie_id
                    self.cq_queue.put_nowait(tlp)

                    return

            tlp.release_fc()

            if tlp.fmt_type in {TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
                self.log.warning("No BAR match: memory write request did not match any BARs: %r", tlp)
                return  # no UR response for write request
            else:
                self.log.warning("No BAR match: memory read request did not match any BARs: %r", tlp)
        else:
            raise Exception("TODO")

        # Unsupported request
        cpl = Tlp.create_ur_completion_for_tlp(tlp, PcieId(self.bus_num, 0, 0))
        self.log.debug("UR Completion: %r", cpl)
        await self.upstream_send(cpl)

    async def _run_reset(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event
            await clock_edge_event

            if self.user_reset is not None:
                self.user_reset.value = 1

            if self.sys_reset is not None:
                if not self.sys_reset.value:
                    await RisingEdge(self.sys_reset)
                await First(FallingEdge(self.sys_reset), Timer(100, 'ns'))
                await First(FallingEdge(self.sys_reset), RisingEdge(self.user_clk))
                if not self.sys_reset.value:
                    continue
            else:
                await Timer(100, 'ns')
                await RisingEdge(self.user_clk)

            if self.user_reset is not None:
                self.user_reset.value = 0

            if self.sys_reset is not None:
                await FallingEdge(self.sys_reset)
            else:
                return

    async def _run_cq_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            # increment cq_np_req_count and saturate at 32
            if self.pcie_cq_np_req is None or self.pcie_cq_np_req.value:
                self.cq_np_req_count = min(self.cq_np_req_count+1, 32)

            # handle completer requests
            # send any queued non-posted requests first
            while not self.cq_np_queue.empty() and self.cq_np_req_count > 0:
                tlp = self.cq_np_queue.get_nowait()
                self.cq_np_req_count -= 1
                await self.cq_source.send(tlp.pack_us_cq())

            # handle new requests
            while not self.cq_queue.empty():
                tlp = self.cq_queue.get_nowait()

                if tlp.fmt_type in {TlpType.IO_READ, TlpType.IO_WRITE, TlpType.MEM_READ, TlpType.MEM_READ_64}:
                    # non-posted request
                    if self.cq_np_req_count > 0:
                        # have credit, can forward
                        self.cq_np_req_count -= 1
                        await self.cq_source.send(tlp.pack_us_cq())
                    else:
                        # no credits, put it in the queue
                        self.cq_np_queue.put_nowait(tlp)
                else:
                    # posted request
                    await self.cq_source.send(tlp.pack_us_cq())

            # output new cq_np_req_count
            if self.pcie_cq_np_req_count is not None:
                self.pcie_cq_np_req_count.value = self.cq_np_req_count

    async def _run_cc_logic(self):
        while True:
            tlp = Tlp_us.unpack_us_cc(await self.cc_sink.recv(), self.enable_parity)

            if not tlp.completer_id_enable:
                tlp.completer_id = tlp.completer_id._replace(bus=self.bus_num)

            if not tlp.discontinue:
                await self.send(Tlp(tlp))

    async def _run_rq_logic(self):
        while True:
            tlp = Tlp_us.unpack_us_rq(await self.rq_sink.recv(), self.enable_parity)

            if tlp.discontinue:
                self.log.warning("Discontinue bit set, discarding TLP: %r", tlp)
                continue

            if not tlp.requester_id_enable:
                tlp.requester_id = tlp.requester_id._replace(bus=self.bus_num)

            if tlp.is_nonposted():
                # non-posted request

                if self.rq_np_queue.empty() and self.cpld_credit_count+tlp.get_data_credits() <= self.cpld_credit_limit and (self.enable_client_tag or self.tag_available_count > 0):
                    # queue empty and have data credits; skip queue and send immediately to preserve ordering

                    if not self.functions[tlp.requester_id.function].bus_master_enable:
                        self.log.warning("Bus mastering disabled, dropping TLP: %r", tlp)
                        # TODO: internal response
                        continue

                    if self.functions[0].pcie_cap.extended_tag_field_enable:
                        assert tlp.tag < 256, "tag out of range (extended tags enabled)"
                    else:
                        assert tlp.tag < 32, "tag out of range (extended tags disabled)"

                    if not self.enable_client_tag:
                        tlp.tag = self.get_free_tag()
                        self.rq_tag.put_nowait(tlp.tag)

                    assert not self.active_request[tlp.tag], "active tag reused"
                    self.active_request[tlp.tag] = tlp
                    self.tag_available_count = self.get_available_tag_count()

                    self.cpld_credit_count += tlp.get_data_credits()

                    await self.send(Tlp(tlp))
                    self.rq_seq_num.put_nowait(tlp.seq_num)

                else:
                    # queue not empty or insufficient data credits; enqueue

                    # block to wait for space in queue
                    while self.rq_np_queue.qsize() >= self.rq_np_limit:
                        self.rq_np_queue_dequeue.clear()
                        await self.rq_np_queue_dequeue.wait()

                    self.rq_np_queue.put_nowait(tlp)
            else:
                # posted request; send immediately

                if not self.functions[tlp.requester_id.function].bus_master_enable:
                    self.log.warning("Bus mastering disabled, dropping TLP: %r", tlp)
                    # TODO: internal response
                    continue

                await self.send(Tlp(tlp))
                self.rq_seq_num.put_nowait(tlp.seq_num)

    async def _run_rq_np_queue_logic(self):
        while True:
            tlp = await self.rq_np_queue.get()
            self.rq_np_queue_dequeue.set()

            while True:
                # wait for data credits
                if self.cpld_credit_count+tlp.get_data_credits() > self.cpld_credit_limit:
                    self.cpld_credit_released.clear()
                    await self.cpld_credit_released.wait()
                    continue

                # wait for tags
                if not self.enable_client_tag and self.tag_available_count <= 0:
                    self.tag_release.clear()
                    await self.tag_release.wait()
                    continue

                break

            if not self.functions[tlp.requester_id.function].bus_master_enable:
                self.log.warning("Bus mastering disabled, dropping TLP: %r", tlp)
                # TODO: internal response
                continue

            self.cpld_credit_count += tlp.get_data_credits()

            if not self.enable_client_tag:
                tlp.tag = self.get_free_tag()
                self.rq_tag.put_nowait(tlp.tag)

            assert not self.active_request[tlp.tag], "active tag reused"
            self.active_request[tlp.tag] = tlp
            self.tag_available_count = self.get_available_tag_count()

            await self.send(Tlp(tlp))
            self.rq_seq_num.put_nowait(tlp.seq_num)

    async def _run_rq_seq_num_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            if self.pcie_rq_seq_num0 is not None:
                self.pcie_rq_seq_num_vld0.value = 0
                if not self.rq_seq_num.empty():
                    self.pcie_rq_seq_num0.value = self.rq_seq_num.get_nowait()
                    self.pcie_rq_seq_num_vld0.value = 1
            elif not self.rq_seq_num.empty():
                self.rq_seq_num.get_nowait()

            if self.dw == 512:

                if self.pcie_rq_seq_num1 is not None:
                    self.pcie_rq_seq_num_vld1.value = 0
                    if not self.rq_seq_num.empty():
                        self.pcie_rq_seq_num1.value = self.rq_seq_num.get_nowait()
                        self.pcie_rq_seq_num_vld1.value = 1
                elif not self.rq_seq_num.empty():
                    self.rq_seq_num.get_nowait()

    async def _run_rq_tag_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            if self.pcie_rq_tag_av is not None:
                self.pcie_rq_tag_av.value = min(0xf, self.tag_available_count)

            if self.pcie_rq_tag0 is not None:
                self.pcie_rq_tag_vld0.value = 0
                if not self.rq_tag.empty():
                    self.pcie_rq_tag0.value = self.rq_tag.get_nowait()
                    self.pcie_rq_tag_vld0.value = 1
            elif not self.rq_tag.empty():
                self.rq_tag.get_nowait()

            if self.dw == 512:

                if self.pcie_rq_tag1 is not None:
                    self.pcie_rq_tag_vld1.value = 0
                    if not self.rq_tag.empty():
                        self.pcie_rq_tag1.value = self.rq_tag.get_nowait()
                        self.pcie_rq_tag_vld1.value = 1
                elif not self.rq_tag.empty():
                    self.rq_tag.get_nowait()

    async def _run_rc_logic(self):
        while True:
            tlp = await self.rc_queue.get()
            await self.rc_source.send(tlp.pack_us_rc())

            self.rx_buf_cplh_fc_count = max(self.rx_buf_cplh_fc_count-1, 0)
            self.rx_buf_cpld_fc_count = max(self.rx_buf_cpld_fc_count-(tlp.get_data_credits()+1), 0)

    async def _run_tx_fc_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            # transmit flow control
            # TODO
            if self.pcie_tfc_nph_av is not None:
                self.pcie_tfc_nph_av.value = 0xf
            if self.pcie_tfc_npd_av is not None:
                self.pcie_tfc_npd_av.value = 0xf

    async def _run_cfg_mgmt_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            # configuration management
            function = self.cfg_mgmt_function_number.value.integer
            reg_num = self.cfg_mgmt_addr.value.integer
            write_data = self.cfg_mgmt_write_data.value.integer
            byte_enable = self.cfg_mgmt_byte_enable.value.integer
            cfg_mgmt_read = self.cfg_mgmt_read.value.integer
            cfg_mgmt_write = self.cfg_mgmt_write.value.integer

            if self.cfg_mgmt_read_write_done.value:
                self.cfg_mgmt_read_write_done.value = 0
            elif cfg_mgmt_read or cfg_mgmt_write:
                for k in range(3):
                    await RisingEdge(self.user_clk)
                if cfg_mgmt_read:
                    self.cfg_mgmt_read_data.value = await self.functions[function].read_config_register(reg_num)
                else:
                    await self.functions[function].write_config_register(reg_num, write_data, byte_enable)
                self.cfg_mgmt_read_write_done.value = 1
            # cfg_mgmt_debug_access

    async def _run_cfg_status_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            # configuration status
            if self.sys_reset is not None and not self.sys_reset.value:
                if self.cfg_phy_link_down is not None:
                    self.cfg_phy_link_down.value = 1
                if self.user_lnk_up is not None:
                    self.user_lnk_up.value = 0
            else:
                if self.cfg_phy_link_down is not None:
                    self.cfg_phy_link_down.value = 0  # TODO
                if self.user_lnk_up is not None:
                    self.user_lnk_up.value = 1  # TODO

            # cfg_phy_link_status
            if self.cfg_negotiated_width is not None:
                self.cfg_negotiated_width.value = min(max((self.functions[0].pcie_cap.negotiated_link_width).bit_length()-1, 0), 4)
            if self.cfg_current_speed is not None:
                self.cfg_current_speed.value = min(max(self.functions[0].pcie_cap.current_link_speed-1, 0), 3)
            if self.cfg_max_payload is not None:
                self.cfg_max_payload.value = self.functions[0].pcie_cap.max_payload_size & 3
            if self.cfg_max_read_req is not None:
                self.cfg_max_read_req.value = self.functions[0].pcie_cap.max_read_request_size

            if self.cfg_function_status is not None:
                status = 0
                for k in range(len(self.functions)):
                    if self.functions[k].bus_master_enable:
                        status |= 0x07 << k*4
                    if self.functions[k].interrupt_disable:
                        status |= 0x08 << k*4
                self.cfg_function_status.value = status

            # cfg_vf_status
            # cfg_function_power_state
            # cfg_vf_power_state
            # cfg_link_power_state
            # cfg_err_cor_out
            # cfg_err_nonfatal_out
            # cfg_err_fatal_out

            if self.cfg_local_error_out is not None:
                if not self.local_error.empty():
                    self.cfg_local_error_out.value = self.local_error.get_nowait()
                    self.cfg_local_error_valid.value = 1
                else:
                    self.cfg_local_error_out.value = 0
                    self.cfg_local_error_valid.value = 0

            # cfg_rx_pm_state
            # cfg_tx_pm_state
            # cfg_ltssm_state

            if self.cfg_rcb_status is not None:
                status = 0
                for k in range(len(self.functions)):
                    if self.functions[k].pcie_cap.read_completion_boundary:
                        status |= 1 << k
                self.cfg_rcb_status.value = status

            # cfg_obff_enable
            # cfg_pl_status_change
            # cfg_tph_requester_enable
            # cfg_tph_st_mode
            # cfg_vf_tph_requester_enable
            # cfg_vf_tph_st_mode

    async def _run_cfg_msg_rx_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            # cfg_msg_received
            # cfg_msg_received_data
            # cfg_msg_received_type

    async def _run_cfg_msg_tx_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            # cfg_msg_transmit
            # cfg_msg_transmit_type
            # cfg_msg_transmit_data
            # cfg_msg_transmit_done

    async def _run_cfg_fc_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            if isinstance(self.cfg_fc_sel, int):
                sel = self.cfg_fc_sel
            else:
                sel = self.cfg_fc_sel.value.integer

            if (sel == 0b010):
                # Receive credits consumed
                cfg_fc_ph = self.upstream_port.fc_state[0].ph.rx_credits_consumed
                cfg_fc_pd = self.upstream_port.fc_state[0].pd.rx_credits_consumed
                cfg_fc_nph = self.upstream_port.fc_state[0].nph.rx_credits_consumed
                cfg_fc_npd = self.upstream_port.fc_state[0].npd.rx_credits_consumed
                cfg_fc_cplh = self.upstream_port.fc_state[0].cplh.rx_credits_consumed
                cfg_fc_cpld = self.upstream_port.fc_state[0].cpld.rx_credits_consumed
            elif (sel == 0b100):
                # Transmit credits available
                cfg_fc_ph = self.upstream_port.fc_state[0].ph.tx_credits_available
                cfg_fc_pd = self.upstream_port.fc_state[0].pd.tx_credits_available
                cfg_fc_nph = self.upstream_port.fc_state[0].nph.tx_credits_available
                cfg_fc_npd = self.upstream_port.fc_state[0].npd.tx_credits_available
                cfg_fc_cplh = self.upstream_port.fc_state[0].cplh.tx_credits_available
                cfg_fc_cpld = self.upstream_port.fc_state[0].cpld.tx_credits_available
            elif (sel == 0b101):
                # Transmit credit limit
                cfg_fc_ph = self.upstream_port.fc_state[0].ph.tx_credit_limit
                cfg_fc_pd = self.upstream_port.fc_state[0].pd.tx_credit_limit
                cfg_fc_nph = self.upstream_port.fc_state[0].nph.tx_credit_limit
                cfg_fc_npd = self.upstream_port.fc_state[0].npd.tx_credit_limit
                cfg_fc_cplh = self.upstream_port.fc_state[0].cplh.tx_credit_limit
                cfg_fc_cpld = self.upstream_port.fc_state[0].cpld.tx_credit_limit
            elif (sel == 0b110):
                # Transmit credits consumed
                cfg_fc_ph = self.upstream_port.fc_state[0].ph.tx_credits_consumed
                cfg_fc_pd = self.upstream_port.fc_state[0].pd.tx_credits_consumed
                cfg_fc_nph = self.upstream_port.fc_state[0].nph.tx_credits_consumed
                cfg_fc_npd = self.upstream_port.fc_state[0].npd.tx_credits_consumed
                cfg_fc_cplh = self.upstream_port.fc_state[0].cplh.tx_credits_consumed
                cfg_fc_cpld = self.upstream_port.fc_state[0].cpld.tx_credits_consumed
            else:
                # Reserved
                cfg_fc_ph = 0
                cfg_fc_pd = 0
                cfg_fc_nph = 0
                cfg_fc_npd = 0
                cfg_fc_cplh = 0
                cfg_fc_cpld = 0

            if self.cfg_fc_ph is not None:
                self.cfg_fc_ph.value = cfg_fc_ph & 0xff
            if self.cfg_fc_pd is not None:
                self.cfg_fc_pd.value = cfg_fc_pd & 0xfff
            if self.cfg_fc_nph is not None:
                self.cfg_fc_nph.value = cfg_fc_nph & 0xff
            if self.cfg_fc_npd is not None:
                self.cfg_fc_npd.value = cfg_fc_npd & 0xfff
            if self.cfg_fc_cplh is not None:
                self.cfg_fc_cplh.value = cfg_fc_cplh & 0xff
            if self.cfg_fc_cpld is not None:
                self.cfg_fc_cpld.value = cfg_fc_cpld & 0xfff

    async def _run_cfg_ctrl_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            if self.sys_reset is not None and not self.sys_reset.value:
                self.config_space_enable = False
            else:
                if self.cfg_config_space_enable is not None:
                    self.config_space_enable = bool(self.cfg_config_space_enable.value)
                else:
                    self.config_space_enable = True

            # cfg_hot_reset_in
            # cfg_hot_reset_out
            # cfg_dsn
            if self.cfg_bus_number is not None:
                self.cfg_bus_number.value = self.bus_num
            # cfg_ds_port_number
            # cfg_ds_bus_number
            # cfg_ds_device_number
            # cfg_ds_function_number
            # cfg_power_state_change_ack
            # cfg_power_state_change_interrupt
            # cfg_err_cor_in
            # cfg_err_uncor_in
            # cfg_flr_in_process
            # cfg_flr_done
            # cfg_vf_flr_in_process
            # cfg_vf_flr_func_num
            # cfg_vf_flr_done
            # cfg_pm_aspm_l1_entry_reject
            # cfg_pm_aspm_tx_l0s_entry_disable
            # cfg_req_pm_transition_l23_ready
            # cfg_link_training_enable

    async def _run_cfg_int_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            msi_int = 0
            msi_function_number = 0
            msi_attr = TlpAttr(0)
            msi_select = 0
            msi_pending_status_data_enable = 0
            msi_pending_status_function_num = 0
            msi_pending_status = 0
            msix_int = 0
            msix_address = 0
            msix_data = 0

            if self.cfg_interrupt_msi_int is not None:
                msi_int = self.cfg_interrupt_msi_int.value.integer
            if self.cfg_interrupt_msi_function_number is not None:
                msi_function_number = self.cfg_interrupt_msi_function_number.value.integer
            if self.cfg_interrupt_msi_attr is not None:
                msi_attr = TlpAttr(self.cfg_interrupt_msi_attr.value.integer)
            if self.cfg_interrupt_msi_select is not None:
                msi_select = self.cfg_interrupt_msi_select.value.integer
            if self.cfg_interrupt_msi_pending_status_data_enable is not None:
                msi_pending_status_data_enable = self.cfg_interrupt_msi_pending_status_data_enable.value.integer
            if self.cfg_interrupt_msi_pending_status_function_num is not None:
                msi_pending_status_function_num = self.cfg_interrupt_msi_pending_status_function_num.value.integer
            if self.cfg_interrupt_msi_pending_status is not None:
                msi_pending_status = self.cfg_interrupt_msi_pending_status.value.integer
            if self.cfg_interrupt_msix_int is not None:
                msix_int = self.cfg_interrupt_msix_int.value.integer
            if self.cfg_interrupt_msix_address is not None:
                msix_address = self.cfg_interrupt_msix_address.value.integer
            if self.cfg_interrupt_msix_data is not None:
                msix_data = self.cfg_interrupt_msix_data.value.integer

            # INTx
            # cfg_interrupt_int
            # cfg_interrupt_sent
            # cfg_interrupt_pending

            # MSI
            if self.cfg_interrupt_msi_enable is not None:
                val = 0
                for k in range(min(len(self.functions), 2)):
                    if self.functions[k].msi_cap.msi_enable:
                        val |= 1 << k
                self.cfg_interrupt_msi_enable.value = val

            if self.cfg_interrupt_msi_sent is not None:
                self.cfg_interrupt_msi_sent.value = 0
            if self.cfg_interrupt_msi_fail is not None:
                self.cfg_interrupt_msi_fail.value = 0
            if msi_int:
                bits = [i for i in range(32) if msi_int >> i & 1]
                if len(bits) == 1 and msi_function_number < len(self.functions):
                    self.log.info("Issue MSI interrupt (index %d)", bits[0])
                    await self.functions[msi_function_number].msi_cap.issue_msi_interrupt(bits[0], attr=msi_attr)
                    if self.cfg_interrupt_msi_sent is not None:
                        self.cfg_interrupt_msi_sent.value = 1

            if self.cfg_interrupt_msi_mmenable is not None:
                val = 0
                for k in range(min(len(self.functions), 2)):
                    val |= (self.functions[k].msi_cap.msi_multiple_message_enable & 0x7) << k*3
                self.cfg_interrupt_msi_mmenable.value = val

            # cfg_interrupt_msi_mask_update

            if self.cfg_interrupt_msi_data is not None:
                if msi_select == 0b1111:
                    self.cfg_interrupt_msi_data.value = 0
                else:
                    if msi_select < len(self.functions):
                        self.cfg_interrupt_msi_data.value = self.functions[msi_select].msi_cap.msi_mask_bits
                    else:
                        self.cfg_interrupt_msi_data.value = 0
            if msi_pending_status_data_enable:
                if msi_pending_status_function_num < len(self.functions):
                    self.functions[msi_pending_status_function_num].msi_cap.msi_pending_bits = msi_pending_status

            # MSI-X
            if self.cfg_interrupt_msix_enable is not None:
                val = 0
                for k in range(min(len(self.functions), 4)):
                    if self.functions[k].msix_cap.msix_enable:
                        val |= 1 << k
                self.cfg_interrupt_msix_enable.value = val
            if self.cfg_interrupt_msix_mask is not None:
                val = 0
                for k in range(min(len(self.functions), 4)):
                    if self.functions[k].msix_cap.msix_function_mask:
                        val |= 1 << k
                self.cfg_interrupt_msix_mask.value = val
            # cfg_interrupt_msix_vf_enable
            # cfg_interrupt_msix_vf_mask

            if self.cfg_interrupt_msix_sent is not None:
                self.cfg_interrupt_msix_sent.value = 0
            if self.cfg_interrupt_msix_fail is not None:
                self.cfg_interrupt_msix_fail.value = 0
            if msix_int:
                if msi_function_number < len(self.functions):
                    self.log.info("Issue MSI-X interrupt (addr 0x%08x, data 0x%08x)", msix_address, msix_data)
                    await self.functions[msi_function_number].msix_cap.issue_msix_interrupt(msix_address, msix_data, attr=msi_attr)
                    if self.cfg_interrupt_msix_sent is not None:
                        self.cfg_interrupt_msix_sent.value = 1

            # MSI/MSI-X
            # cfg_interrupt_msi_tph_present
            # cfg_interrupt_msi_tph_type
            # cfg_interrupt_msi_tph_st_tag

    async def _run_cfg_extend_logic(self):
        clock_edge_event = RisingEdge(self.user_clk)

        while True:
            await clock_edge_event

            # cfg_ext_read_received
            # cfg_ext_write_received
            # cfg_ext_register_number
            # cfg_ext_function_number
            # cfg_ext_write_data
            # cfg_ext_write_byte_enable
            # cfg_ext_read_data
            # cfg_ext_read_data_valid
