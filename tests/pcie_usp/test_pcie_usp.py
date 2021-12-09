#!/usr/bin/env python
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

import itertools
import logging
import mmap
import os

import cocotb_test.simulator
import pytest

import cocotb
from cocotb.triggers import RisingEdge, FallingEdge, Timer, Event
from cocotb.regression import TestFactory

from cocotbext.axi import AxiStreamBus
from cocotbext.pcie.core import RootComplex
from cocotbext.pcie.xilinx.us import UltraScalePlusPcieDevice
from cocotbext.pcie.xilinx.us.interface import RqSource, RcSink, CqSink, CcSource
from cocotbext.pcie.xilinx.us.tlp import Tlp_us
from cocotbext.pcie.core.tlp import TlpType, CplStatus
from cocotbext.pcie.core.utils import PcieId


class TB:
    def __init__(self, dut):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        # PCIe
        self.rc = RootComplex()

        self.dev = UltraScalePlusPcieDevice(
            # configuration options
            pcie_generation=3,
            # pcie_link_width=2,
            # user_clk_frequency=250e6,
            alignment="dword",
            cq_cc_straddle=False,
            rq_rc_straddle=False,
            rc_4tlp_straddle=False,
            enable_pf1=False,
            enable_client_tag=True,
            enable_extended_tag=False,
            enable_parity=False,
            enable_rx_msg_interface=False,
            enable_sriov=False,
            enable_extended_configuration=False,

            enable_pf0_msi=True,
            enable_pf1_msi=False,

            # signals
            user_clk=dut.user_clk,
            user_reset=dut.user_reset,
            user_lnk_up=dut.user_lnk_up,
            sys_clk=dut.sys_clk,
            sys_clk_gt=dut.sys_clk_gt,
            sys_reset=dut.sys_reset,
            phy_rdy_out=dut.phy_rdy_out,

            rq_bus=AxiStreamBus.from_prefix(dut, "s_axis_rq"),
            pcie_rq_seq_num0=dut.pcie_rq_seq_num0,
            pcie_rq_seq_num_vld0=dut.pcie_rq_seq_num_vld0,
            pcie_rq_seq_num1=dut.pcie_rq_seq_num1,
            pcie_rq_seq_num_vld1=dut.pcie_rq_seq_num_vld1,
            pcie_rq_tag0=dut.pcie_rq_tag0,
            pcie_rq_tag1=dut.pcie_rq_tag1,
            pcie_rq_tag_av=dut.pcie_rq_tag_av,
            pcie_rq_tag_vld0=dut.pcie_rq_tag_vld0,
            pcie_rq_tag_vld1=dut.pcie_rq_tag_vld1,

            rc_bus=AxiStreamBus.from_prefix(dut, "m_axis_rc"),

            cq_bus=AxiStreamBus.from_prefix(dut, "m_axis_cq"),
            pcie_cq_np_req=dut.pcie_cq_np_req,
            pcie_cq_np_req_count=dut.pcie_cq_np_req_count,

            cc_bus=AxiStreamBus.from_prefix(dut, "s_axis_cc"),

            pcie_tfc_nph_av=dut.pcie_tfc_nph_av,
            pcie_tfc_npd_av=dut.pcie_tfc_npd_av,
            cfg_phy_link_down=dut.cfg_phy_link_down,
            cfg_phy_link_status=dut.cfg_phy_link_status,
            cfg_negotiated_width=dut.cfg_negotiated_width,
            cfg_current_speed=dut.cfg_current_speed,
            cfg_max_payload=dut.cfg_max_payload,
            cfg_max_read_req=dut.cfg_max_read_req,
            cfg_function_status=dut.cfg_function_status,
            cfg_function_power_state=dut.cfg_function_power_state,
            cfg_vf_status=dut.cfg_vf_status,
            cfg_vf_power_state=dut.cfg_vf_power_state,
            cfg_link_power_state=dut.cfg_link_power_state,
            cfg_mgmt_addr=dut.cfg_mgmt_addr,
            cfg_mgmt_function_number=dut.cfg_mgmt_function_number,
            cfg_mgmt_write=dut.cfg_mgmt_write,
            cfg_mgmt_write_data=dut.cfg_mgmt_write_data,
            cfg_mgmt_byte_enable=dut.cfg_mgmt_byte_enable,
            cfg_mgmt_read=dut.cfg_mgmt_read,
            cfg_mgmt_read_data=dut.cfg_mgmt_read_data,
            cfg_mgmt_read_write_done=dut.cfg_mgmt_read_write_done,
            cfg_mgmt_debug_access=dut.cfg_mgmt_debug_access,
            cfg_err_cor_out=dut.cfg_err_cor_out,
            cfg_err_nonfatal_out=dut.cfg_err_nonfatal_out,
            cfg_err_fatal_out=dut.cfg_err_fatal_out,
            cfg_local_error_valid=dut.cfg_local_error_valid,
            cfg_local_error_out=dut.cfg_local_error_out,
            cfg_ltssm_state=dut.cfg_ltssm_state,
            cfg_rx_pm_state=dut.cfg_rx_pm_state,
            cfg_tx_pm_state=dut.cfg_tx_pm_state,
            cfg_rcb_status=dut.cfg_rcb_status,
            cfg_obff_enable=dut.cfg_obff_enable,
            cfg_pl_status_change=dut.cfg_pl_status_change,
            cfg_tph_requester_enable=dut.cfg_tph_requester_enable,
            cfg_tph_st_mode=dut.cfg_tph_st_mode,
            cfg_vf_tph_requester_enable=dut.cfg_vf_tph_requester_enable,
            cfg_vf_tph_st_mode=dut.cfg_vf_tph_st_mode,
            cfg_msg_received=dut.cfg_msg_received,
            cfg_msg_received_data=dut.cfg_msg_received_data,
            cfg_msg_received_type=dut.cfg_msg_received_type,
            cfg_msg_transmit=dut.cfg_msg_transmit,
            cfg_msg_transmit_type=dut.cfg_msg_transmit_type,
            cfg_msg_transmit_data=dut.cfg_msg_transmit_data,
            cfg_msg_transmit_done=dut.cfg_msg_transmit_done,
            cfg_fc_ph=dut.cfg_fc_ph,
            cfg_fc_pd=dut.cfg_fc_pd,
            cfg_fc_nph=dut.cfg_fc_nph,
            cfg_fc_npd=dut.cfg_fc_npd,
            cfg_fc_cplh=dut.cfg_fc_cplh,
            cfg_fc_cpld=dut.cfg_fc_cpld,
            cfg_fc_sel=dut.cfg_fc_sel,
            cfg_dsn=dut.cfg_dsn,
            cfg_bus_number=dut.cfg_bus_number,
            cfg_power_state_change_ack=dut.cfg_power_state_change_ack,
            cfg_power_state_change_interrupt=dut.cfg_power_state_change_interrupt,
            cfg_err_cor_in=dut.cfg_err_cor_in,
            cfg_err_uncor_in=dut.cfg_err_uncor_in,
            cfg_flr_in_process=dut.cfg_flr_in_process,
            cfg_flr_done=dut.cfg_flr_done,
            cfg_vf_flr_in_process=dut.cfg_vf_flr_in_process,
            cfg_vf_flr_func_num=dut.cfg_vf_flr_func_num,
            cfg_vf_flr_done=dut.cfg_vf_flr_done,
            cfg_link_training_enable=dut.cfg_link_training_enable,
            cfg_interrupt_int=dut.cfg_interrupt_int,
            cfg_interrupt_pending=dut.cfg_interrupt_pending,
            cfg_interrupt_sent=dut.cfg_interrupt_sent,
            cfg_interrupt_msi_enable=dut.cfg_interrupt_msi_enable,
            cfg_interrupt_msi_mmenable=dut.cfg_interrupt_msi_mmenable,
            cfg_interrupt_msi_mask_update=dut.cfg_interrupt_msi_mask_update,
            cfg_interrupt_msi_data=dut.cfg_interrupt_msi_data,
            cfg_interrupt_msi_select=dut.cfg_interrupt_msi_select,
            cfg_interrupt_msi_int=dut.cfg_interrupt_msi_int,
            cfg_interrupt_msi_pending_status=dut.cfg_interrupt_msi_pending_status,
            cfg_interrupt_msi_pending_status_data_enable=dut.cfg_interrupt_msi_pending_status_data_enable,
            cfg_interrupt_msi_pending_status_function_num=dut.cfg_interrupt_msi_pending_status_function_num,
            cfg_interrupt_msi_sent=dut.cfg_interrupt_msi_sent,
            cfg_interrupt_msi_fail=dut.cfg_interrupt_msi_fail,
            cfg_interrupt_msi_attr=dut.cfg_interrupt_msi_attr,
            cfg_interrupt_msi_tph_present=dut.cfg_interrupt_msi_tph_present,
            cfg_interrupt_msi_tph_type=dut.cfg_interrupt_msi_tph_type,
            cfg_interrupt_msi_tph_st_tag=dut.cfg_interrupt_msi_tph_st_tag,
            cfg_interrupt_msi_function_number=dut.cfg_interrupt_msi_function_number,
            cfg_pm_aspm_l1_entry_reject=dut.cfg_pm_aspm_l1_entry_reject,
            cfg_pm_aspm_tx_l0s_entry_disable=dut.cfg_pm_aspm_tx_l0s_entry_disable,
            cfg_hot_reset_out=dut.cfg_hot_reset_out,
            cfg_config_space_enable=dut.cfg_config_space_enable,
            cfg_req_pm_transition_l23_ready=dut.cfg_req_pm_transition_l23_ready,
            cfg_hot_reset_in=dut.cfg_hot_reset_in,
            cfg_ds_port_number=dut.cfg_ds_port_number,
            cfg_ds_bus_number=dut.cfg_ds_bus_number,
            cfg_ds_device_number=dut.cfg_ds_device_number,
        )

        self.dev.log.setLevel(logging.DEBUG)

        dut.pcie_cq_np_req.setimmediatevalue(1)
        dut.cfg_mgmt_addr.setimmediatevalue(0)
        dut.cfg_mgmt_function_number.setimmediatevalue(0)
        dut.cfg_mgmt_write.setimmediatevalue(0)
        dut.cfg_mgmt_write_data.setimmediatevalue(0)
        dut.cfg_mgmt_byte_enable.setimmediatevalue(0)
        dut.cfg_mgmt_read.setimmediatevalue(0)
        dut.cfg_mgmt_debug_access.setimmediatevalue(0)
        dut.cfg_msg_transmit.setimmediatevalue(0)
        dut.cfg_msg_transmit_type.setimmediatevalue(0)
        dut.cfg_msg_transmit_data.setimmediatevalue(0)
        dut.cfg_fc_sel.setimmediatevalue(0)
        dut.cfg_dsn.setimmediatevalue(0)
        dut.cfg_power_state_change_ack.setimmediatevalue(0)
        dut.cfg_err_cor_in.setimmediatevalue(0)
        dut.cfg_err_uncor_in.setimmediatevalue(0)
        dut.cfg_flr_done.setimmediatevalue(0)
        dut.cfg_vf_flr_func_num.setimmediatevalue(0)
        dut.cfg_vf_flr_done.setimmediatevalue(0)
        dut.cfg_link_training_enable.setimmediatevalue(1)
        dut.cfg_interrupt_int.setimmediatevalue(0)
        dut.cfg_interrupt_pending.setimmediatevalue(0)
        dut.cfg_interrupt_msi_select.setimmediatevalue(0)
        dut.cfg_interrupt_msi_int.setimmediatevalue(0)
        dut.cfg_interrupt_msi_pending_status.setimmediatevalue(0)
        dut.cfg_interrupt_msi_pending_status_data_enable.setimmediatevalue(0)
        dut.cfg_interrupt_msi_pending_status_function_num.setimmediatevalue(0)
        dut.cfg_interrupt_msi_attr.setimmediatevalue(0)
        dut.cfg_interrupt_msi_tph_present.setimmediatevalue(0)
        dut.cfg_interrupt_msi_tph_type.setimmediatevalue(0)
        dut.cfg_interrupt_msi_tph_st_tag.setimmediatevalue(0)
        dut.cfg_interrupt_msi_function_number.setimmediatevalue(0)
        dut.cfg_pm_aspm_l1_entry_reject.setimmediatevalue(0)
        dut.cfg_pm_aspm_tx_l0s_entry_disable.setimmediatevalue(0)
        dut.cfg_config_space_enable.setimmediatevalue(1)
        dut.cfg_req_pm_transition_l23_ready.setimmediatevalue(0)
        dut.cfg_hot_reset_in.setimmediatevalue(0)
        dut.cfg_ds_port_number.setimmediatevalue(0)
        dut.cfg_ds_bus_number.setimmediatevalue(0)
        dut.cfg_ds_device_number.setimmediatevalue(0)
        dut.sys_clk.setimmediatevalue(0)
        dut.sys_clk_gt.setimmediatevalue(0)
        dut.sys_reset.setimmediatevalue(1)

        self.rc.make_port().connect(self.dev)

        # user logic
        self.rq_source = RqSource(AxiStreamBus.from_prefix(dut, "s_axis_rq"), dut.user_clk, dut.user_reset)
        self.rc_sink = RcSink(AxiStreamBus.from_prefix(dut, "m_axis_rc"), dut.user_clk, dut.user_reset)
        self.cq_sink = CqSink(AxiStreamBus.from_prefix(dut, "m_axis_cq"), dut.user_clk, dut.user_reset)
        self.cc_source = CcSource(AxiStreamBus.from_prefix(dut, "s_axis_cc"), dut.user_clk, dut.user_reset)

        self.regions = [None]*6
        self.regions[0] = mmap.mmap(-1, 1024*1024)
        self.regions[1] = mmap.mmap(-1, 1024*1024)
        self.regions[3] = mmap.mmap(-1, 1024)

        self.current_tag = 0
        self.tag_count = 32
        self.tag_active = [False]*256
        self.tag_release = Event()

        self.dev.functions[0].msi_cap.msi_multiple_message_capable = 5

        self.dev.functions[0].configure_bar(0, len(self.regions[0]))
        self.dev.functions[0].configure_bar(1, len(self.regions[1]), True, True)
        self.dev.functions[0].configure_bar(3, len(self.regions[3]), False, False, True)

        cocotb.start_soon(self._run_cq())

    def set_idle_generator(self, generator=None):
        if generator:
            self.dev.rc_source.set_pause_generator(generator())
            self.dev.cq_source.set_pause_generator(generator())

    def set_backpressure_generator(self, generator=None):
        if generator:
            self.dev.rq_sink.set_pause_generator(generator())
            self.dev.cc_sink.set_pause_generator(generator())

    async def alloc_tag(self):
        tag_count = min(256, self.tag_count)

        while True:
            tag = self.current_tag
            for k in range(tag_count):
                tag = (tag + 1) % tag_count
                if not self.tag_active[tag]:
                    self.tag_active[tag] = True
                    self.current_tag = tag
                    return tag

            self.tag_release.clear()
            await self.tag_release.wait()

    def release_tag(self, tag):
        assert self.tag_active[tag]
        self.tag_active[tag] = False
        self.tag_release.set()

    async def dma_io_write(self, addr, data, timeout=0, timeout_unit='ns'):
        n = 0

        while True:
            tlp = Tlp_us()
            tlp.fmt_type = TlpType.IO_WRITE
            tlp.requester_id = PcieId(0, 0, 0)

            first_pad = addr % 4
            byte_length = min(len(data)-n, 4-first_pad)
            tlp.set_addr_be_data(addr, data[n:n+byte_length])

            tlp.tag = await self.alloc_tag()

            await self.rq_source.send(tlp.pack_us_rq())
            pkt = await self.rc_sink.recv()

            self.release_tag(tlp.tag)

            if not pkt:
                raise Exception("Timeout")

            cpl = Tlp_us.unpack_us_rc(pkt)

            if cpl.status != CplStatus.SC:
                raise Exception("Unsuccessful completion")

            n += byte_length
            addr += byte_length

            if n >= len(data):
                break

    async def dma_io_read(self, addr, length, timeout=0, timeout_unit='ns'):
        data = b''
        n = 0

        while True:
            tlp = Tlp_us()
            tlp.fmt_type = TlpType.IO_READ
            tlp.requester_id = PcieId(0, 0, 0)

            first_pad = addr % 4
            byte_length = min(length-n, 4-first_pad)
            tlp.set_addr_be(addr, byte_length)

            tlp.tag = await self.alloc_tag()

            await self.rq_source.send(tlp.pack_us_rq())
            pkt = await self.rc_sink.recv()

            self.release_tag(tlp.tag)

            if not pkt:
                raise Exception("Timeout")

            cpl = Tlp_us.unpack_us_rc(pkt)

            if cpl.status != CplStatus.SC:
                raise Exception("Unsuccessful completion")
            else:
                d = cpl.get_data()

            data += d[first_pad:]

            n += byte_length
            addr += byte_length

            if n >= length:
                break

        return data[:length]

    async def dma_mem_write(self, addr, data, timeout=0, timeout_unit='ns'):
        n = 0

        while True:
            tlp = Tlp_us()
            if addr > 0xffffffff:
                tlp.fmt_type = TlpType.MEM_WRITE_64
            else:
                tlp.fmt_type = TlpType.MEM_WRITE
            tlp.requester_id = PcieId(0, 0, 0)

            first_pad = addr % 4
            byte_length = len(data)-n
            # max payload size
            byte_length = min(byte_length, (128 << self.dut.cfg_max_payload.value.integer)-first_pad)
            # 4k address align
            byte_length = min(byte_length, 0x1000 - (addr & 0xfff))
            tlp.set_addr_be_data(addr, data[n:n+byte_length])

            await self.rq_source.send(tlp.pack_us_rq())

            n += byte_length
            addr += byte_length

            if n >= len(data):
                break

    async def dma_mem_read(self, addr, length, timeout=0, timeout_unit='ns'):
        data = b''
        n = 0

        while True:
            tlp = Tlp_us()
            if addr > 0xffffffff:
                tlp.fmt_type = TlpType.MEM_READ_64
            else:
                tlp.fmt_type = TlpType.MEM_READ
            tlp.requester_id = PcieId(0, 0, 0)

            first_pad = addr % 4
            byte_length = length-n
            # max read request size
            byte_length = min(byte_length, (128 << self.dut.cfg_max_read_req.value.integer)-first_pad)
            # 4k address align
            byte_length = min(byte_length, 0x1000 - (addr & 0xfff))
            tlp.set_addr_be(addr, byte_length)

            tlp.tag = await self.alloc_tag()

            await self.rq_source.send(tlp.pack_us_rq())

            m = 0

            while True:
                pkt = await self.rc_sink.recv()

                if not pkt:
                    raise Exception("Timeout")

                cpl = Tlp_us.unpack_us_rc(pkt)

                if cpl.status != CplStatus.SC:
                    raise Exception("Unsuccessful completion")
                else:
                    assert cpl.byte_count+3+(cpl.lower_address & 3) >= cpl.length*4
                    assert cpl.byte_count == max(byte_length - m, 1)

                    d = cpl.get_data()

                    offset = cpl.lower_address & 3
                    data += d[offset:offset+cpl.byte_count]

                m += len(d)-offset

                if m >= byte_length:
                    break

            self.release_tag(tlp.tag)

            n += byte_length
            addr += byte_length

            if n >= length:
                break

        return data[:length]

    async def _run_cq(self):
        while True:
            pkt = await self.cq_sink.recv()

            tlp = Tlp_us.unpack_us_cq(pkt)

            self.log.debug("CQ TLP: %s", repr(tlp))

            if tlp.fmt_type == TlpType.IO_READ:
                self.log.info("IO read")

                cpl = Tlp_us.create_completion_data_for_tlp(tlp, PcieId(0, 0, 0))

                region = tlp.bar_id
                addr = tlp.address % len(self.regions[region])
                offset = 0
                start_offset = None
                mask = tlp.first_be

                # perform operation
                data = bytearray(4)

                for k in range(4):
                    if mask & (1 << k):
                        if start_offset is None:
                            start_offset = offset
                    else:
                        if start_offset is not None and offset != start_offset:
                            data[start_offset:offset] = self.regions[region][addr+start_offset:addr+offset]
                        start_offset = None

                    offset += 1

                if start_offset is not None and offset != start_offset:
                    data[start_offset:offset] = self.regions[region][addr+start_offset:addr+offset]

                cpl.set_data(data)
                cpl.byte_count = 4
                cpl.length = 1

                self.log.debug("Completion: %s", repr(cpl))
                await self.cc_source.send(cpl.pack_us_cc())

            elif tlp.fmt_type == TlpType.IO_WRITE:
                self.log.info("IO write")

                cpl = Tlp_us.create_completion_for_tlp(tlp, PcieId(0, 0, 0))

                region = tlp.bar_id
                addr = tlp.address % len(self.regions[region])
                offset = 0
                start_offset = None
                mask = tlp.first_be

                # perform operation
                data = tlp.get_data()

                for k in range(4):
                    if mask & (1 << k):
                        if start_offset is None:
                            start_offset = offset
                    else:
                        if start_offset is not None and offset != start_offset:
                            self.regions[region][addr+start_offset:addr+offset] = data[start_offset:offset]
                        start_offset = None

                    offset += 1

                if start_offset is not None and offset != start_offset:
                    self.regions[region][addr+start_offset:addr+offset] = data[start_offset:offset]

                self.log.debug("Completion: %s", repr(cpl))
                await self.cc_source.send(cpl.pack_us_cc())

            elif tlp.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64}:
                self.log.info("Memory read")

                # perform operation
                region = tlp.bar_id
                addr = tlp.address % len(self.regions[region])
                offset = 0
                length = tlp.length

                # perform read
                data = self.regions[region][addr:addr+length*4]

                # prepare completion TLP(s)
                m = 0
                n = 0
                addr = tlp.address+tlp.get_first_be_offset()
                dw_length = tlp.length
                byte_length = tlp.get_be_byte_count()

                while m < dw_length:
                    cpl = Tlp_us.create_completion_data_for_tlp(tlp, PcieId(0, 0, 0))

                    cpl_dw_length = dw_length - m
                    cpl_byte_length = byte_length - n
                    cpl.byte_count = cpl_byte_length
                    if cpl_dw_length > 32 << self.dut.cfg_max_payload.value.integer:
                        # max payload size
                        cpl_dw_length = 32 << self.dut.cfg_max_payload.value.integer
                        # RCB align
                        cpl_dw_length -= (addr & 0x7c) >> 2

                    cpl.lower_address = addr & 0x7f

                    cpl.set_data(data[m*4:(m+cpl_dw_length)*4])

                    self.log.debug("Completion: %s", repr(cpl))
                    await self.cc_source.send(cpl.pack_us_cc())

                    m += cpl_dw_length
                    n += cpl_dw_length*4 - (addr & 3)
                    addr += cpl_dw_length*4 - (addr & 3)

            elif tlp.fmt_type in {TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
                self.log.info("Memory write")

                # perform operation
                region = tlp.bar_id
                addr = tlp.address % len(self.regions[region])
                offset = 0
                start_offset = None
                mask = tlp.first_be
                length = tlp.length

                # perform write
                data = tlp.get_data()

                # first dword
                for k in range(4):
                    if mask & (1 << k):
                        if start_offset is None:
                            start_offset = offset
                    else:
                        if start_offset is not None and offset != start_offset:
                            self.regions[region][addr+start_offset:addr+offset] = data[start_offset:offset]
                        start_offset = None

                    offset += 1

                if length > 2:
                    # middle dwords
                    if start_offset is None:
                        start_offset = offset
                    offset += (length-2)*4

                if length > 1:
                    # last dword
                    mask = tlp.last_be

                    for k in range(4):
                        if mask & (1 << k):
                            if start_offset is None:
                                start_offset = offset
                        else:
                            if start_offset is not None and offset != start_offset:
                                self.regions[region][addr+start_offset:addr+offset] = data[start_offset:offset]
                            start_offset = None

                        offset += 1

                if start_offset is not None and offset != start_offset:
                    self.regions[region][addr+start_offset:addr+offset] = data[start_offset:offset]


async def run_test_mem(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    await FallingEdge(dut.user_reset)
    await Timer(100, 'ns')

    await tb.rc.enumerate(enable_bus_mastering=True, configure_msi=True)

    dev_bar0 = tb.rc.tree[0][0].bar_window[0]
    dev_bar1 = tb.rc.tree[0][0].bar_window[1]
    dev_bar3 = tb.rc.tree[0][0].bar_window[3]

    for length in list(range(0, 8)):
        for offset in list(range(8)):
            tb.log.info("IO operation length: %d offset: %d", length, offset)
            test_data = bytearray([x % 256 for x in range(length)])

            await dev_bar3.write(offset, test_data, timeout=5000)
            assert tb.regions[3][offset:offset+length] == test_data

            assert await dev_bar3.read(offset, length, timeout=5000) == test_data

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (32-bit BAR) length: %d offset: %d", length, offset)
            test_data = bytearray([x % 256 for x in range(length)])

            await dev_bar0.write(offset, test_data, timeout=100)
            # wait for write to complete
            await dev_bar0.read(offset, 1, timeout=5000)
            assert tb.regions[0][offset:offset+length] == test_data

            assert await dev_bar0.read(offset, length, timeout=5000) == test_data

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (64-bit BAR) length: %d offset: %d", length, offset)
            test_data = bytearray([x % 256 for x in range(length)])

            await dev_bar1.write(offset, test_data, timeout=100)
            # wait for write to complete
            await dev_bar1.read(offset, 1, timeout=5000)
            assert tb.regions[1][offset:offset+length] == test_data

            assert await dev_bar1.read(offset, length, timeout=5000) == test_data

    await RisingEdge(dut.user_clk)
    await RisingEdge(dut.user_clk)


async def run_test_dma(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    mem = tb.rc.mem_pool.alloc_region(16*1024*1024)
    mem_base = mem.get_absolute_address(0)

    io = tb.rc.io_pool.alloc_region(1024)
    io_base = io.get_absolute_address(0)

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    await FallingEdge(dut.user_reset)
    await Timer(100, 'ns')

    await tb.rc.enumerate(enable_bus_mastering=True, configure_msi=True)

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (DMA) length: %d offset: %d", length, offset)
            addr = mem_base+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await tb.dma_mem_write(addr, test_data, 5000, 'ns')
            # wait for write to complete
            await tb.dma_mem_read(addr, 1, 5000, 'ns')
            assert mem[offset:offset+length] == test_data

            assert await tb.dma_mem_read(addr, length, 5000, 'ns') == test_data

    for length in list(range(0, 8)):
        for offset in list(range(8)):
            tb.log.info("IO operation (DMA) length: %d offset: %d", length, offset)
            addr = io_base+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await tb.dma_io_write(addr, test_data, 5000, 'ns')
            assert io[offset:offset+length] == test_data

            assert await tb.dma_io_read(addr, length, 5000, 'ns') == test_data

    await RisingEdge(dut.user_clk)
    await RisingEdge(dut.user_clk)


async def run_test_msi(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    await FallingEdge(dut.user_reset)
    await Timer(100, 'ns')

    await tb.rc.enumerate(enable_bus_mastering=True, configure_msi=True)

    for k in range(32):
        tb.log.info("Send MSI %d", k)

        await RisingEdge(dut.user_clk)
        tb.dut.cfg_interrupt_msi_int.value = 1 << k
        await RisingEdge(dut.user_clk)
        tb.dut.cfg_interrupt_msi_int.value = 0

        event = tb.rc.msi_get_event(tb.dev.functions[0].pcie_id, k)
        event.clear()
        await event.wait()

    await RisingEdge(dut.user_clk)
    await RisingEdge(dut.user_clk)


def cycle_pause():
    return itertools.cycle([1, 1, 1, 0])


if cocotb.SIM_NAME:

    for test in [
                run_test_mem,
                run_test_dma,
                run_test_msi,
            ]:

        factory = TestFactory(test)
        factory.add_option(("idle_inserter", "backpressure_inserter"), [(None, None), (cycle_pause, cycle_pause)])
        factory.generate_tests()


# cocotb-test

tests_dir = os.path.dirname(__file__)


@pytest.mark.parametrize("data_width", [64, 128, 256, 512])
def test_pcie_usp(request, data_width):
    dut = "test_pcie_usp"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(tests_dir, f"{dut}.v"),
    ]

    parameters = {}

    parameters['DATA_WIDTH'] = data_width
    parameters['KEEP_WIDTH'] = (parameters['DATA_WIDTH'] // 32)
    parameters['RQ_USER_WIDTH'] = 62 if parameters['DATA_WIDTH'] < 512 else 137
    parameters['RC_USER_WIDTH'] = 75 if parameters['DATA_WIDTH'] < 512 else 161
    parameters['CQ_USER_WIDTH'] = 88 if parameters['DATA_WIDTH'] < 512 else 183
    parameters['CC_USER_WIDTH'] = 33 if parameters['DATA_WIDTH'] < 512 else 81

    extra_env = {f'PARAM_{k}': str(v) for k, v in parameters.items()}

    sim_build = os.path.join(tests_dir, "sim_build",
        request.node.name.replace('[', '-').replace(']', ''))

    cocotb_test.simulator.run(
        python_search=[tests_dir],
        verilog_sources=verilog_sources,
        toplevel=toplevel,
        module=module,
        parameters=parameters,
        sim_build=sim_build,
        extra_env=extra_env,
    )
