"""

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

"""

import cocotb
from cocotb.clock import Clock
from cocotb.queue import Queue
from cocotb.triggers import RisingEdge, FallingEdge, Timer, First
from cocotb.handle import Immediate

from cocotbext.pcie.core import Device, Endpoint, __version__
from cocotbext.pcie.core.caps import MsiCapability, MsixCapability
from cocotbext.pcie.core.caps import AerExtendedCapability, PcieExtendedCapability
from cocotbext.pcie.core.utils import PcieId
from cocotbext.pcie.core.tlp import Tlp, TlpType

from .interface import S5PcieFrame, S5PcieSource, S5PcieSink


# (speed, link width, AVST width, coreclkout_hip/pld_clk frequency)
#
# Transcribed from UG-01097_avst Table 7-3 "Application Layer Clock Frequency
# for All Combinations of Link Width, Data Rate and Application Layer Interface
# Widths".  Only the rows using a 128-bit or 256-bit Avalon-ST interface are
# listed here, since the 64-bit interface is not modeled (see interface.py).
# Note that every gen1/gen2 x1/x2 combination, and gen1 x1/x2/x4, only exist
# with the 64-bit interface and therefore cannot be represented by this model.
valid_configs = [
    (1,  8, 128, 125.0e6),
    (2,  4, 128, 125.0e6),
    (2,  8, 128, 250.0e6),
    (2,  8, 256, 125.0e6),
    (3,  2, 128, 125.0e6),
    (3,  4, 128, 250.0e6),
    # Table 7-3 as printed stops at gen3 x4; the feature list (Table 1-1) and
    # the datasheet's "x1, x2, x4, and x8 configurations with Gen1, Gen2, or
    # Gen3 lane rates" statement both claim gen3 x8 support.  Gen3 x8 needs
    # ~7.88 GB/s, which requires the 256-bit interface at 250 MHz.
    (3,  8, 256, 250.0e6),
]


class S5PcieFunction(Endpoint):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # PCIe capabilities
        self.register_capability(self.pm_cap, offset=0x10)

        self.msi_cap = MsiCapability()
        self.msi_cap.msi_64bit_address_capable = 1
        self.msi_cap.msi_per_vector_mask_capable = 0
        self.register_capability(self.msi_cap, offset=0x14)

        self.register_capability(self.pcie_cap, offset=0x1c)

        self.msix_cap = MsixCapability()
        self.register_capability(self.msix_cap, offset=0x2c)

        # PCIe extended capabilities
        self.aer_ext_cap = AerExtendedCapability()
        self.register_capability(self.aer_ext_cap, offset=0x40)

        self.pcie_ext_cap = PcieExtendedCapability()
        self.register_capability(self.pcie_ext_cap, offset=0x62)


def init_signal(sig, width=None, initval=None):
    if sig is None:
        return None
    if width is not None:
        assert len(sig) == width
    if initval is not None:
        sig.value = Immediate(initval)
    return sig


class S5PcieDevice(Device):
    def __init__(self,
            # configuration options
            pcie_generation=None,
            pcie_link_width=None,
            pld_clk_frequency=None,
            pf_count=1,
            max_payload_size=128,
            enable_extended_tag=False,

            pf0_msi_enable=False,
            pf0_msi_count=1,
            pf0_msix_enable=False,
            pf0_msix_table_size=0,
            pf0_msix_table_bir=0,
            pf0_msix_table_offset=0x00000000,
            pf0_msix_pba_bir=0,
            pf0_msix_pba_offset=0x00000000,

            # signals
            # Clocks
            refclk=None,
            pld_clk=None,
            coreclkout=None,

            # Reset, status, and link training
            npor=None,
            pin_perst=None,
            reset_status=None,
            clr_st=None,
            serdes_pll_locked=None,
            pld_core_ready=None,
            pld_clk_inuse=None,
            dlup=None,
            dlup_exit=None,
            hotrst_exit=None,
            l2_exit=None,
            ev128ns=None,
            ev1us=None,
            lane_act=None,
            currentspeed=None,
            ltssmstate=None,

            # RX interface
            rx_bus=None,

            # TX interface
            tx_bus=None,

            # TX flow control (component specific TX credit signals)
            tx_cred_hdrfcp=None,
            tx_cred_datafcp=None,
            tx_cred_hdrfcnp=None,
            tx_cred_datafcnp=None,
            tx_cred_hdrfccp=None,
            tx_cred_datafccp=None,
            tx_cred_fchipcons=None,
            tx_cred_fc_infinite=None,
            tx_cons_cred_sel=None,
            ko_cpl_spc_header=None,
            ko_cpl_spc_data=None,

            # Error signals
            derr_cor_ext_rcv0=None,
            derr_rpl=None,
            derr_cor_ext_rpl0=None,
            rxfc_cplbuf_ovf=None,

            # Interrupts for endpoints
            app_msi_req=None,
            app_msi_ack=None,
            app_msi_tc=None,
            app_msi_num=None,
            app_int_sts=None,
            app_int_ack=None,

            # Interrupts for root ports
            int_status=None,
            serr_out=None,

            # Completion side band signals
            cpl_err=None,
            cpl_pending=None,

            # Transaction layer configuration space signals
            tl_cfg_add=None,
            tl_cfg_ctl=None,
            tl_cfg_sts=None,

            # Power management
            pme_to_cr=None,
            pme_to_sr=None,
            pm_event=None,
            pm_data=None,
            pm_auxpwr=None,

            *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.log.info("Intel Stratix V Hard IP for PCI Express (Avalon-ST) core model")
        self.log.info("cocotbext-pcie version %s", __version__)
        self.log.info("Copyright (c) 2026 Anderson Ignacio da Silva")

        self.default_function = S5PcieFunction

        self.dw = None

        self.rx_queue = Queue()

        self.rx_buf_cplh_fc_limit = 32
        self.rx_buf_cpld_fc_limit = 128
        self.rx_buf_cplh_fc_count = 0
        self.rx_buf_cpld_fc_count = 0

        # configuration options
        self.pcie_generation = pcie_generation
        self.pcie_link_width = pcie_link_width
        self.pld_clk_frequency = pld_clk_frequency
        self.pf_count = pf_count
        self.max_payload_size = max_payload_size
        self.enable_extended_tag = enable_extended_tag

        self.pf0_msi_enable = pf0_msi_enable
        self.pf0_msi_count = pf0_msi_count
        self.pf0_msix_enable = pf0_msix_enable
        self.pf0_msix_table_size = pf0_msix_table_size
        self.pf0_msix_table_bir = pf0_msix_table_bir
        self.pf0_msix_table_offset = pf0_msix_table_offset
        self.pf0_msix_pba_bir = pf0_msix_pba_bir
        self.pf0_msix_pba_offset = pf0_msix_pba_offset

        # signals

        # Clocks
        self.refclk = init_signal(refclk, 1)
        self.pld_clk = init_signal(pld_clk, 1)
        self.coreclkout = init_signal(coreclkout, 1, 0)

        # Reset, status, and link training
        self.npor = init_signal(npor, 1)
        self.pin_perst = init_signal(pin_perst, 1)
        self.reset_status = init_signal(reset_status, 1, 0)
        self.clr_st = init_signal(clr_st, 1, 0)
        self.serdes_pll_locked = init_signal(serdes_pll_locked, 1, 0)
        self.pld_core_ready = init_signal(pld_core_ready, 1)
        self.pld_clk_inuse = init_signal(pld_clk_inuse, 1, 0)
        self.dlup = init_signal(dlup, 1, 0)
        self.dlup_exit = init_signal(dlup_exit, 1, 1)
        self.hotrst_exit = init_signal(hotrst_exit, 1, 0)
        self.l2_exit = init_signal(l2_exit, 1, 1)
        self.ev128ns = init_signal(ev128ns, 1, 0)
        self.ev1us = init_signal(ev1us, 1, 0)
        self.lane_act = init_signal(lane_act, 4, 0)
        self.currentspeed = init_signal(currentspeed, 2, 0)
        self.ltssmstate = init_signal(ltssmstate, 5, 0)

        # RX interface
        self.rx_source = None
        self.rx_st_mask = None

        if rx_bus is not None:
            self.rx_source = S5PcieSource(rx_bus, self.pld_clk)
            self.rx_source.queue_occupancy_limit_frames = 2
            self.rx_source.ready_latency = 3
            self.dw = self.rx_source.width
            # rx_st_mask is an Application Layer input that stalls non-posted
            # requests; it lives on the RX bus rather than being a separate port
            self.rx_st_mask = getattr(rx_bus, "mask", None)

        # TX interface
        self.tx_sink = None

        if tx_bus is not None:
            self.tx_sink = S5PcieSink(tx_bus, self.pld_clk)
            self.tx_sink.queue_occupancy_limit_frames = 2
            self.tx_sink.ready_latency = 2
            self.dw = self.tx_sink.width

        # TX flow control
        self.tx_cred_hdrfcp = init_signal(tx_cred_hdrfcp, 8, 0)
        self.tx_cred_datafcp = init_signal(tx_cred_datafcp, 12, 0)
        self.tx_cred_hdrfcnp = init_signal(tx_cred_hdrfcnp, 8, 0)
        self.tx_cred_datafcnp = init_signal(tx_cred_datafcnp, 12, 0)
        self.tx_cred_hdrfccp = init_signal(tx_cred_hdrfccp, 8, 0)
        self.tx_cred_datafccp = init_signal(tx_cred_datafccp, 12, 0)
        self.tx_cred_fchipcons = init_signal(tx_cred_fchipcons, 6, 0)
        self.tx_cred_fc_infinite = init_signal(tx_cred_fc_infinite, 6, 0)
        self.tx_cons_cred_sel = init_signal(tx_cons_cred_sel, 1)
        self.ko_cpl_spc_header = init_signal(ko_cpl_spc_header, 8, self.rx_buf_cplh_fc_limit)
        self.ko_cpl_spc_data = init_signal(ko_cpl_spc_data, 12, self.rx_buf_cpld_fc_limit)

        # Error signals
        self.derr_cor_ext_rcv0 = init_signal(derr_cor_ext_rcv0, 1, 0)
        self.derr_rpl = init_signal(derr_rpl, 1, 0)
        self.derr_cor_ext_rpl0 = init_signal(derr_cor_ext_rpl0, 1, 0)
        self.rxfc_cplbuf_ovf = init_signal(rxfc_cplbuf_ovf, 1, 0)

        # Interrupts for endpoints
        self.app_msi_req = init_signal(app_msi_req, 1)
        self.app_msi_ack = init_signal(app_msi_ack, 1, 0)
        self.app_msi_tc = init_signal(app_msi_tc, 3)
        self.app_msi_num = init_signal(app_msi_num, 5)
        self.app_int_sts = init_signal(app_int_sts, 1)
        self.app_int_ack = init_signal(app_int_ack, 1, 0)

        # Interrupts for root ports
        self.int_status = init_signal(int_status, 4, 0)
        self.serr_out = init_signal(serr_out, 1, 0)

        # Completion side band signals
        self.cpl_err = init_signal(cpl_err, 7)
        self.cpl_pending = init_signal(cpl_pending, 1)

        # Transaction layer configuration space signals
        self.tl_cfg_add = init_signal(tl_cfg_add, 4, 0)
        self.tl_cfg_ctl = init_signal(tl_cfg_ctl, 32, 0)
        self.tl_cfg_sts = init_signal(tl_cfg_sts, 53, 0)
        # number of pld_clk cycles each tl_cfg_add index is held; the datasheet
        # allows 4 or 8 depending on parameterization (Table 5-16)
        self.tl_cfg_update_cycles = 8

        # Power management
        self.pme_to_cr = init_signal(pme_to_cr, 1)
        self.pme_to_sr = init_signal(pme_to_sr, 1, 0)
        self.pm_event = init_signal(pm_event, 1)
        self.pm_data = init_signal(pm_data, 10)
        self.pm_auxpwr = init_signal(pm_auxpwr, 1)

        # validate parameters
        assert self.dw in {128, 256}

        # rescale clock frequency
        if self.pld_clk_frequency is not None and self.pld_clk_frequency < 1e6:
            self.pld_clk_frequency *= 1e6

        if not self.pcie_generation or not self.pcie_link_width or not self.pld_clk_frequency:
            self.log.info("Incomplete configuration specified, attempting to select reasonable options")
            for config in reversed(valid_configs):
                if self.pcie_generation is not None and self.pcie_generation != config[0]:
                    continue
                if self.pcie_link_width is not None and self.pcie_link_width != config[1]:
                    continue
                if self.dw != config[2]:
                    continue
                if self.pld_clk_frequency is not None and self.pld_clk_frequency != config[3]:
                    continue

                if self.pcie_generation is None:
                    self.log.info("Setting PCIe speed to gen %d", config[0])
                    self.pcie_generation = config[0]
                if self.pcie_link_width is None:
                    self.log.info("Setting PCIe link width to x%d", config[1])
                    self.pcie_link_width = config[1]
                if self.pld_clk_frequency is None:
                    self.log.info("Setting pld_clk frequency to %d MHz", config[3]/1e6)
                    self.pld_clk_frequency = config[3]
                break

        self.log.info("Intel Stratix V Hard IP for PCI Express configuration:")
        self.log.info("  PCIe speed: gen %d", self.pcie_generation)
        self.log.info("  PCIe link width: x%d", self.pcie_link_width)
        self.log.info("  pld_clk frequency: %d MHz", self.pld_clk_frequency/1e6)
        self.log.info("  Avalon-ST width: %d", self.dw)
        self.log.info("  PF count: %d", self.pf_count)
        self.log.info("  Max payload size: %d", self.max_payload_size)
        self.log.info("  Enable extended tag: %s", self.enable_extended_tag)

        assert self.pcie_generation in {1, 2, 3}
        assert self.pcie_link_width in {1, 2, 4, 8}
        assert self.pf_count == 1, \
            "this IP variant multiplexes a single function onto tl_cfg_ctl; " \
            "multi-function requires the SR-IOV variant"

        config_valid = False
        for config in valid_configs:
            if self.pcie_generation != config[0]:
                continue
            if self.pcie_link_width != config[1]:
                continue
            if self.dw != config[2]:
                continue
            if self.pld_clk_frequency != config[3]:
                continue

            config_valid = True
            break

        assert config_valid, "link speed/link width/pld_clk frequency/interface width combination not valid"

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

        for f in self.functions:
            f.pcie_cap.max_payload_size_supported = (self.max_payload_size//128-1).bit_length()
            f.pcie_cap.extended_tag_supported = self.enable_extended_tag

        self.bus_num = 0
        self.device_num = 0

        # fork coroutines

        if self.coreclkout is not None:
            cocotb.start_soon(Clock(self.coreclkout, int(1e9/self.pld_clk_frequency), units="ns").start())

        if self.rx_source is not None:
            cocotb.start_soon(self._run_rx_logic())
        if self.tx_sink is not None:
            cocotb.start_soon(self._run_tx_logic())
        if self.tx_cred_datafcp is not None:
            cocotb.start_soon(self._run_tx_fc_logic())
        if self.app_msi_req is not None:
            cocotb.start_soon(self._run_int_logic())
        if self.tl_cfg_ctl is not None:
            cocotb.start_soon(self._run_cfg_out_logic())

        cocotb.start_soon(self._run_reset())

    async def upstream_recv(self, tlp):
        self.log.debug("Got downstream TLP: %r", tlp)

        if tlp.fmt_type in {TlpType.CFG_READ_0, TlpType.CFG_WRITE_0}:
            self.bus_num = tlp.completer_id.bus
            self.device_num = tlp.completer_id.device

            for f in self.functions:
                if f.pcie_id == tlp.completer_id:
                    await f.upstream_recv(tlp)
                    return

            tlp.release_fc()

            self.log.warning("Function not found: failed to route config type 0 TLP: %r", tlp)
        elif tlp.fmt_type in {TlpType.CFG_READ_1, TlpType.CFG_WRITE_1}:
            tlp.release_fc()

            self.log.warning("Malformed TLP: endpoint received config type 1 TLP: %r", tlp)
        elif tlp.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
            for f in self.functions:
                if f.pcie_id == tlp.requester_id:

                    frame = S5PcieFrame.from_tlp(tlp)

                    data_fc = tlp.get_data_credits()

                    if self.rx_buf_cplh_fc_count+1 <= self.rx_buf_cplh_fc_limit and self.rx_buf_cpld_fc_count+data_fc <= self.rx_buf_cpld_fc_limit:
                        self.rx_buf_cplh_fc_count += 1
                        self.rx_buf_cpld_fc_count += data_fc
                        await self.rx_queue.put((tlp, frame))
                    else:
                        self.log.warning("No space in RX completion buffer, dropping TLP: CPLH %d (limit %d), CPLD %d (limit %d)",
                            self.rx_buf_cplh_fc_count, self.rx_buf_cplh_fc_limit, self.rx_buf_cpld_fc_count, self.rx_buf_cpld_fc_limit)

                    tlp.release_fc()

                    return

            tlp.release_fc()

            self.log.warning("Unexpected completion: failed to route completion to function: %r", tlp)
            return  # no UR response for completion
        elif tlp.fmt_type in {TlpType.IO_READ, TlpType.IO_WRITE}:
            for f in self.functions:
                bar = f.match_bar(tlp.address, True)
                if bar:

                    frame = S5PcieFrame.from_tlp(tlp)

                    frame.bar = 1 << bar[0]

                    await self.rx_queue.put((tlp, frame))

                    tlp.release_fc()

                    return

            tlp.release_fc()

            self.log.warning("No BAR match: IO request did not match any BARs: %r", tlp)
        elif tlp.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64, TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
            for f in self.functions:
                bar = f.match_bar(tlp.address)
                if bar:

                    frame = S5PcieFrame.from_tlp(tlp)

                    frame.bar = 1 << bar[0]

                    await self.rx_queue.put((tlp, frame))

                    tlp.release_fc()

                    return

            tlp.release_fc()

            if tlp.fmt_type in {TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
                self.log.warning("No BAR match: memory write request did not match any BARs: %r", tlp)
                return  # no UR response for write request
            else:
                self.log.warning("No BAR match: memory read request did not match any BARs: %r", tlp)
        else:
            raise Exception("TODO")

        cpl = Tlp.create_ur_completion_for_tlp(tlp, PcieId(self.bus_num, 0, 0))
        self.log.debug("UR Completion: %r", cpl)
        await self.upstream_send(cpl)

    async def _run_reset(self):
        # reset_status is synchronous to pld_clk (UG-01097_avst Table 5-6), and
        # the reset sequence in Figure 7-2 is expressed in pld_clk cycles, so
        # the whole sequence runs on pld_clk rather than on coreclkout.
        clock_edge_event = RisingEdge(self.pld_clk)

        # lane_act is a one-hot encoding of the negotiated link width
        lane_act_val = {1: 0b0001, 2: 0b0010, 4: 0b0100, 8: 0b1000}[self.pcie_link_width]

        while True:
            await clock_edge_event
            await clock_edge_event

            # in reset: pld_clk_inuse is deasserted until the Transaction Layer
            # is running on pld_clk, reset_status/clr_st are asserted
            if self.pld_clk_inuse is not None:
                self.pld_clk_inuse.value = 0
            if self.serdes_pll_locked is not None:
                self.serdes_pll_locked.value = 0
            if self.reset_status is not None:
                self.reset_status.value = 1
            if self.clr_st is not None:
                self.clr_st.value = 1
            if self.dlup is not None:
                self.dlup.value = 0
            if self.ltssmstate is not None:
                self.ltssmstate.value = 0x00  # Detect.Quiet
            if self.lane_act is not None:
                self.lane_act.value = 0
            if self.currentspeed is not None:
                self.currentspeed.value = 0

            for f in self.functions:
                f.pcie_cap.current_link_speed = 0
                f.pcie_cap.negotiated_link_width = 0

            if self.pin_perst is not None:
                if not self.pin_perst.value:
                    await RisingEdge(self.pin_perst)
                await First(FallingEdge(self.pin_perst), Timer(100, 'ns'))
                await First(FallingEdge(self.pin_perst), clock_edge_event)
                if not self.pin_perst.value:
                    continue
            else:
                await Timer(100, 'ns')
                await clock_edge_event

            # PLL locks, then the Transaction Layer starts using pld_clk
            if self.serdes_pll_locked is not None:
                self.serdes_pll_locked.value = 1
            if self.pld_clk_inuse is not None:
                self.pld_clk_inuse.value = 1

            # crst/srst are released 32 cycles after pld_clk_inuse asserts
            for _ in range(32):
                await clock_edge_event

            if self.reset_status is not None:
                self.reset_status.value = 0
            if self.clr_st is not None:
                self.clr_st.value = 0
            if self.dlup is not None:
                self.dlup.value = 1
            if self.ltssmstate is not None:
                self.ltssmstate.value = 0x0f  # L0
            if self.lane_act is not None:
                self.lane_act.value = lane_act_val
            if self.currentspeed is not None:
                self.currentspeed.value = self.pcie_generation

            # the core never populates these, but the Hard IP reports the
            # negotiated values in Link Status (and hence on tl_cfg_sts), so
            # fill them in from the configured link parameters
            for f in self.functions:
                f.pcie_cap.current_link_speed = self.pcie_generation
                f.pcie_cap.negotiated_link_width = self.pcie_link_width

            if self.pin_perst is not None:
                await FallingEdge(self.pin_perst)
            else:
                return

    async def _run_rx_logic(self):
        clock_edge_event = RisingEdge(self.pld_clk)

        while True:
            tlp, frame = await self.rx_queue.get()

            # rx_st_mask stalls only non-posted requests; posted requests and
            # completions continue to be forwarded (UG-01097_avst Table 5-2).
            # NOTE: the RX path is modeled as a single queue, so a stalled
            # non-posted request also holds up TLPs queued behind it. The real
            # Hard IP holds masked non-posted requests in the RX buffer and
            # keeps draining posted traffic past them.
            if self.rx_st_mask is not None and tlp.is_nonposted():
                while self.rx_st_mask.value:
                    await clock_edge_event

            await self.rx_source.send(frame)

            self.rx_buf_cplh_fc_count = max(self.rx_buf_cplh_fc_count-1, 0)
            self.rx_buf_cpld_fc_count = max(self.rx_buf_cpld_fc_count-tlp.get_data_credits(), 0)

    async def _run_tx_logic(self):
        while True:
            frame = await self.tx_sink.recv()
            tlp = frame.to_tlp()
            await self.send(tlp)

    async def _run_tx_fc_logic(self):
        clock_edge_event = RisingEdge(self.pld_clk)

        while True:
            fc = self.upstream_port.fc_state[0]

            if self.tx_cred_hdrfcp is not None:
                self.tx_cred_hdrfcp.value = fc.ph.tx_credits_available & 0xff
            if self.tx_cred_datafcp is not None:
                self.tx_cred_datafcp.value = fc.pd.tx_credits_available & 0xfff
            if self.tx_cred_hdrfcnp is not None:
                self.tx_cred_hdrfcnp.value = fc.nph.tx_credits_available & 0xff
            if self.tx_cred_datafcnp is not None:
                self.tx_cred_datafcnp.value = fc.npd.tx_credits_available & 0xfff
            if self.tx_cred_hdrfccp is not None:
                self.tx_cred_hdrfccp.value = fc.cplh.tx_credits_available & 0xff
            if self.tx_cred_datafccp is not None:
                self.tx_cred_datafccp.value = fc.cpld.tx_credits_available & 0xfff

            await clock_edge_event

    async def _run_int_logic(self):
        clock_edge_event = RisingEdge(self.pld_clk)

        while True:
            await clock_edge_event

            while not int(self.app_msi_req.value):
                await RisingEdge(self.app_msi_req)
                await clock_edge_event

            app_msi_num = int(self.app_msi_num.value)
            app_msi_tc = int(self.app_msi_tc.value)
            await self.functions[0].msi_cap.issue_msi_interrupt(app_msi_num, tc=app_msi_tc)

            self.app_msi_ack.value = 1
            await clock_edge_event
            self.app_msi_ack.value = 0

            while int(self.app_msi_req.value):
                await clock_edge_event

    def _get_tl_cfg_ctl(self, addr):
        """Return the 32-bit tl_cfg_ctl word for a given tl_cfg_add index.

        Layout is taken from UG-01097_avst Figure 5-40 "Multiplexed
        Configuration Register Information Available on tl_cfg_ctl".  Fields
        marked in the datasheet as Root Port only read back as zero, since
        this model only implements Endpoint operation.
        """
        func = self.functions[0]

        if addr == 0x0:
            # cfg_dev_ctrl[15:0] : cfg_dev_ctrl2[15:0]
            dev_ctrl = bool(func.pcie_cap.correctable_error_reporting_enable)
            dev_ctrl |= bool(func.pcie_cap.non_fatal_error_reporting_enable) << 1
            dev_ctrl |= bool(func.pcie_cap.fatal_error_reporting_enable) << 2
            dev_ctrl |= bool(func.pcie_cap.unsupported_request_reporting_enable) << 3
            dev_ctrl |= bool(func.pcie_cap.enable_relaxed_ordering) << 4
            dev_ctrl |= (func.pcie_cap.max_payload_size & 0x7) << 5
            dev_ctrl |= bool(func.pcie_cap.extended_tag_field_enable) << 8
            dev_ctrl |= bool(func.pcie_cap.enable_no_snoop) << 11
            dev_ctrl |= (func.pcie_cap.max_read_request_size & 0x7) << 12

            dev_ctrl2 = bool(func.pcie_cap.ari_forwarding_enable) << 5
            dev_ctrl2 |= bool(func.pcie_cap.atomic_op_requester_enable) << 6
            dev_ctrl2 |= bool(func.pcie_cap.ido_request_enable) << 8
            dev_ctrl2 |= bool(func.pcie_cap.ido_completion_enable) << 9

            return (dev_ctrl & 0xffff) << 16 | (dev_ctrl2 & 0xffff)

        elif addr == 0x1:
            # 16'h0000 : cfg_slot_ctrl[15:0] (Root Port only)
            return 0

        elif addr == 0x2:
            # cfg_link_ctrl[15:0] : cfg_link_ctrl2[15:0]
            link_ctrl = bool(func.pcie_cap.read_completion_boundary) << 3
            link_ctrl |= bool(func.pcie_cap.link_disable) << 4
            link_ctrl |= bool(func.pcie_cap.common_clock_configuration) << 6
            link_ctrl |= bool(func.pcie_cap.extended_synch) << 7
            link_ctrl |= bool(func.pcie_cap.hardware_autonomous_width_disable) << 9
            link_ctrl |= bool(func.pcie_cap.link_bandwidth_management_interrupt_enable) << 10

            link_ctrl2 = func.pcie_cap.target_link_speed & 0xf

            return (link_ctrl & 0xffff) << 16 | (link_ctrl2 & 0xffff)

        elif addr == 0x3:
            # 8'h00 : cfg_prm_cmd[15:0] : cfg_root_ctrl[7:0] (RP only)
            prm_cmd = bool(func.io_space_enable)
            prm_cmd |= bool(func.memory_space_enable) << 1
            prm_cmd |= bool(func.bus_master_enable) << 2
            prm_cmd |= bool(func.parity_error_response_enable) << 6
            prm_cmd |= bool(func.serr_enable) << 8
            prm_cmd |= bool(func.interrupt_disable) << 10

            return (prm_cmd & 0xffff) << 8

        elif addr == 0x4:
            # cfg_sec_ctrl : cfg_secbus : cfg_subbus (Root Port only)
            return 0

        elif addr == 0x5:
            # cfg_msi_addr[11:0] : cfg_io_bas[19:0] (io_bas is Root Port only)
            return (func.msi_cap.msi_message_address & 0xfff) << 20

        elif addr == 0x6:
            # cfg_msi_addr[43:32] : cfg_io_lim[19:0] (io_lim is Root Port only)
            return ((func.msi_cap.msi_message_address >> 32) & 0xfff) << 20

        elif addr == 0x7:
            # 8'h00 : cfg_np_bas[11:0] : cfg_np_lim[11:0] (Root Port only)
            return 0

        elif addr == 0x8:
            # cfg_pr_bas[31:0] (Root Port only)
            return 0

        elif addr == 0x9:
            # cfg_msi_addr[31:12] : cfg_pr_bas[43:32] (pr_bas is RP only)
            return ((func.msi_cap.msi_message_address >> 12) & 0xfffff) << 12

        elif addr == 0xa:
            # cfg_pr_lim[31:0] (Root Port only)
            return 0

        elif addr == 0xb:
            # cfg_msi_addr[63:44] : cfg_pr_lim[43:32] (pr_lim is RP only)
            return ((func.msi_cap.msi_message_address >> 44) & 0xfffff) << 12

        elif addr == 0xc:
            # cfg_pmcsr[31:0]
            pmcsr = func.pm_cap.power_state & 0x3
            pmcsr |= bool(func.pm_cap.no_soft_reset) << 3
            pmcsr |= bool(func.pm_cap.pme_enable) << 8
            pmcsr |= bool(func.pm_cap.pme_status) << 15
            return pmcsr & 0xffffffff

        elif addr == 0xd:
            # cfg_msixcsr[15:0] : cfg_msicsr[15:0]
            # cfg_msicsr field map is UG-01097_avst Figure 5-41 / Table 5-19
            msicsr = bool(func.msi_cap.msi_enable)
            msicsr |= (func.msi_cap.msi_multiple_message_capable & 0x7) << 1
            msicsr |= (func.msi_cap.msi_multiple_message_enable & 0x7) << 4
            msicsr |= bool(func.msi_cap.msi_64bit_address_capable) << 7
            msicsr |= bool(func.msi_cap.msi_per_vector_mask_capable) << 8

            # MSI-X Message Control, per the PCI Local Bus Specification
            msixcsr = func.msix_cap.msix_table_size & 0x7ff
            msixcsr |= bool(func.msix_cap.msix_function_mask) << 14
            msixcsr |= bool(func.msix_cap.msix_enable) << 15

            return (msixcsr & 0xffff) << 16 | (msicsr & 0xffff)

        elif addr == 0xe:
            # 6'h00 : tx_ecrcgen[25] : rx_ecrccheck[24] : cfg_tcvcmap[23:0]
            # a single VC is implemented, so every TC maps to VC0 (all zeros)
            val = bool(func.aer_ext_cap.ecrc_check_enable) << 24
            val |= bool(func.aer_ext_cap.ecrc_generation_enable) << 25
            return val

        elif addr == 0xf:
            # cfg_msi_data[15:0] : 3'b000 : cfg_busdev[12:0]
            busdev = ((self.bus_num & 0xff) << 5) | (self.device_num & 0x1f)
            return (func.msi_cap.msi_message_data & 0xffff) << 16 | busdev

        return 0

    def _get_tl_cfg_sts(self):
        """Return the 53-bit tl_cfg_sts word (UG-01097_avst Table 5-17)."""
        func = self.functions[0]

        # [52:49] Device Status Register[3:0]
        dev_sts = bool(func.pcie_cap.correctable_error_detected)
        dev_sts |= bool(func.pcie_cap.nonfatal_error_detected) << 1
        dev_sts |= bool(func.pcie_cap.fatal_error_detected) << 2
        dev_sts |= bool(func.pcie_cap.unsupported_request_detected) << 3

        # [46:31] Link Status Register[15:0]. Bit 13 (Data Link Layer link
        # active) is defined as always 0 for Endpoints.
        link_sts = func.pcie_cap.current_link_speed & 0xf
        link_sts |= (func.pcie_cap.negotiated_link_width & 0x3f) << 4
        link_sts |= bool(func.pcie_cap.link_training) << 11
        link_sts |= bool(func.pcie_cap.slot_clock_configuration) << 12
        link_sts |= bool(func.pcie_cap.link_bandwidth_management_status) << 14
        link_sts |= bool(func.pcie_cap.link_autonomous_bandwidth_status) << 15

        # [29:25] Status Register[15:11]
        cmd_sts = bool(func.signaled_target_abort)
        cmd_sts |= bool(func.received_target_abort) << 1
        cmd_sts |= bool(func.received_master_abort) << 2
        cmd_sts |= bool(func.signaled_system_error) << 3
        cmd_sts |= bool(func.detected_parity_error) << 4

        val = (dev_sts & 0xf) << 49
        val |= (link_sts & 0xffff) << 31
        val |= (cmd_sts & 0x1f) << 25
        return val

    async def _run_cfg_out_logic(self):
        # The Configuration Space is presented to the Application Layer as a
        # round-robin multiplex over tl_cfg_ctl, indexed by tl_cfg_add. The
        # datasheet specifies that the index advances every 4 or 8 pld_clk
        # cycles (Table 5-16 / Figure 5-39) so that the Application Layer can
        # strobe-sample in the middle of each window; advancing it every cycle
        # would break the sampling logic the datasheet recommends.
        clock_edge_event = RisingEdge(self.pld_clk)

        while True:
            for addr in range(16):
                self.tl_cfg_add.value = addr
                self.tl_cfg_ctl.value = self._get_tl_cfg_ctl(addr)
                if self.tl_cfg_sts is not None:
                    self.tl_cfg_sts.value = self._get_tl_cfg_sts()

                for _ in range(self.tl_cfg_update_cycles):
                    await clock_edge_event
