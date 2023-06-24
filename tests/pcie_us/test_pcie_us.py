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
from cocotb.queue import Queue
from cocotb.triggers import RisingEdge, FallingEdge, Timer, Event, First
from cocotb.regression import TestFactory

from cocotbext.axi import AxiStreamBus
from cocotbext.pcie.core import RootComplex
from cocotbext.pcie.core.tlp import TlpType, CplStatus
from cocotbext.pcie.core.utils import PcieId
from cocotbext.pcie.xilinx.us import UltraScalePcieDevice
from cocotbext.pcie.xilinx.us.interface import RqSource, RcSink, CqSink, CcSource
from cocotbext.pcie.xilinx.us.tlp import Tlp_us


class TB:
    def __init__(self, dut, msix=False):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        # PCIe
        self.rc = RootComplex()

        rc_straddle = False
        if int(os.getenv("STRADDLE", "0")):
            if len(dut.s_axis_rq_tdata) == 256:
                rc_straddle = True

        self.client_tag = bool(int(os.getenv("CLIENT_TAG", "1")))

        self.dev = UltraScalePcieDevice(
            # configuration options
            # pcie_generation=3,
            # pcie_link_width=2,
            # user_clk_frequency=250e6,
            alignment="dword",
            rc_straddle=rc_straddle,
            pf_count=1,
            max_payload_size=128,
            enable_client_tag=self.client_tag,
            enable_extended_tag=False,
            enable_parity=False,
            enable_rx_msg_interface=False,
            enable_sriov=False,
            enable_extended_configuration=False,

            pf0_msi_enable=True,
            pf0_msi_count=32,
            pf1_msi_enable=False,
            pf1_msi_count=1,
            pf0_msix_enable=msix,
            pf0_msix_table_size=63,
            pf0_msix_table_bir=4,
            pf0_msix_table_offset=0x00000000,
            pf0_msix_pba_bir=4,
            pf0_msix_pba_offset=0x00008000,
            pf1_msix_enable=False,
            pf1_msix_table_size=0,
            pf1_msix_table_bir=0,
            pf1_msix_table_offset=0x00000000,
            pf1_msix_pba_bir=0,
            pf1_msix_pba_offset=0x00000000,

            # signals
            user_clk=dut.user_clk,
            user_reset=dut.user_reset,
            user_lnk_up=dut.user_lnk_up,
            sys_clk=dut.sys_clk,
            sys_clk_gt=dut.sys_clk_gt,
            sys_reset=dut.sys_reset,
            pcie_perstn1_in=dut.pcie_perstn1_in,
            pcie_perstn0_out=dut.pcie_perstn0_out,
            pcie_perstn1_out=dut.pcie_perstn1_out,
            phy_rdy_out=dut.phy_rdy_out,

            rq_bus=AxiStreamBus.from_prefix(dut, "s_axis_rq"),
            pcie_rq_seq_num=dut.pcie_rq_seq_num,
            pcie_rq_seq_num_vld=dut.pcie_rq_seq_num_vld,
            pcie_rq_tag=dut.pcie_rq_tag,
            pcie_rq_tag_av=dut.pcie_rq_tag_av,
            pcie_rq_tag_vld=dut.pcie_rq_tag_vld,

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
            cfg_mgmt_write=dut.cfg_mgmt_write,
            cfg_mgmt_write_data=dut.cfg_mgmt_write_data,
            cfg_mgmt_byte_enable=dut.cfg_mgmt_byte_enable,
            cfg_mgmt_read=dut.cfg_mgmt_read,
            cfg_mgmt_read_data=dut.cfg_mgmt_read_data,
            cfg_mgmt_read_write_done=dut.cfg_mgmt_read_write_done,
            cfg_mgmt_type1_cfg_reg_access=dut.cfg_mgmt_type1_cfg_reg_access,
            cfg_err_cor_out=dut.cfg_err_cor_out,
            cfg_err_nonfatal_out=dut.cfg_err_nonfatal_out,
            cfg_err_fatal_out=dut.cfg_err_fatal_out,
            cfg_local_error=dut.cfg_local_error,
            cfg_ltr_enable=dut.cfg_ltr_enable,
            cfg_ltssm_state=dut.cfg_ltssm_state,
            cfg_rcb_status=dut.cfg_rcb_status,
            cfg_dpa_substate_change=dut.cfg_dpa_substate_change,
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
            cfg_per_func_status_control=dut.cfg_per_func_status_control,
            cfg_per_func_status_data=dut.cfg_per_func_status_data,
            cfg_per_function_number=dut.cfg_per_function_number,
            cfg_per_function_output_request=dut.cfg_per_function_output_request,
            cfg_per_function_update_done=dut.cfg_per_function_update_done,
            cfg_dsn=dut.cfg_dsn,
            cfg_power_state_change_ack=dut.cfg_power_state_change_ack,
            cfg_power_state_change_interrupt=dut.cfg_power_state_change_interrupt,
            cfg_err_cor_in=dut.cfg_err_cor_in,
            cfg_err_uncor_in=dut.cfg_err_uncor_in,
            cfg_flr_in_process=dut.cfg_flr_in_process,
            cfg_flr_done=dut.cfg_flr_done,
            cfg_vf_flr_in_process=dut.cfg_vf_flr_in_process,
            cfg_vf_flr_done=dut.cfg_vf_flr_done,
            cfg_link_training_enable=dut.cfg_link_training_enable,
            cfg_interrupt_int=dut.cfg_interrupt_int,
            cfg_interrupt_pending=dut.cfg_interrupt_pending,
            cfg_interrupt_sent=dut.cfg_interrupt_sent,
            cfg_interrupt_msi_enable=dut.cfg_interrupt_msi_enable,
            cfg_interrupt_msi_vf_enable=dut.cfg_interrupt_msi_vf_enable,
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
            cfg_interrupt_msix_enable=dut.cfg_interrupt_msix_enable,
            cfg_interrupt_msix_mask=dut.cfg_interrupt_msix_mask,
            cfg_interrupt_msix_vf_enable=dut.cfg_interrupt_msix_vf_enable,
            cfg_interrupt_msix_vf_mask=dut.cfg_interrupt_msix_vf_mask,
            cfg_interrupt_msix_address=dut.cfg_interrupt_msix_address,
            cfg_interrupt_msix_data=dut.cfg_interrupt_msix_data,
            cfg_interrupt_msix_int=dut.cfg_interrupt_msix_int,
            cfg_interrupt_msix_sent=dut.cfg_interrupt_msix_sent,
            cfg_interrupt_msix_fail=dut.cfg_interrupt_msix_fail,
            cfg_interrupt_msi_attr=dut.cfg_interrupt_msi_attr,
            cfg_interrupt_msi_tph_present=dut.cfg_interrupt_msi_tph_present,
            cfg_interrupt_msi_tph_type=dut.cfg_interrupt_msi_tph_type,
            cfg_interrupt_msi_tph_st_tag=dut.cfg_interrupt_msi_tph_st_tag,
            cfg_interrupt_msi_function_number=dut.cfg_interrupt_msi_function_number,
            cfg_hot_reset_out=dut.cfg_hot_reset_out,
            cfg_config_space_enable=dut.cfg_config_space_enable,
            cfg_req_pm_transition_l23_ready=dut.cfg_req_pm_transition_l23_ready,
            cfg_hot_reset_in=dut.cfg_hot_reset_in,
            cfg_ds_port_number=dut.cfg_ds_port_number,
            cfg_ds_bus_number=dut.cfg_ds_bus_number,
            cfg_ds_device_number=dut.cfg_ds_device_number,
            cfg_ds_function_number=dut.cfg_ds_function_number,
            cfg_subsys_vend_id=dut.cfg_subsys_vend_id
        )

        self.dev.log.setLevel(logging.DEBUG)

        dut.pcie_cq_np_req.setimmediatevalue(1)
        dut.cfg_mgmt_addr.setimmediatevalue(0)
        dut.cfg_mgmt_write.setimmediatevalue(0)
        dut.cfg_mgmt_write_data.setimmediatevalue(0)
        dut.cfg_mgmt_byte_enable.setimmediatevalue(0)
        dut.cfg_mgmt_read.setimmediatevalue(0)
        dut.cfg_mgmt_type1_cfg_reg_access.setimmediatevalue(0)
        dut.cfg_msg_transmit.setimmediatevalue(0)
        dut.cfg_msg_transmit_type.setimmediatevalue(0)
        dut.cfg_msg_transmit_data.setimmediatevalue(0)
        dut.cfg_fc_sel.setimmediatevalue(0)
        dut.cfg_per_func_status_control.setimmediatevalue(0)
        dut.cfg_per_function_number.setimmediatevalue(0)
        dut.cfg_per_function_output_request.setimmediatevalue(0)
        dut.cfg_dsn.setimmediatevalue(0)
        dut.cfg_power_state_change_ack.setimmediatevalue(0)
        dut.cfg_err_cor_in.setimmediatevalue(0)
        dut.cfg_err_uncor_in.setimmediatevalue(0)
        dut.cfg_flr_done.setimmediatevalue(0)
        dut.cfg_vf_flr_done.setimmediatevalue(0)
        dut.cfg_link_training_enable.setimmediatevalue(1)
        dut.cfg_interrupt_int.setimmediatevalue(0)
        dut.cfg_interrupt_pending.setimmediatevalue(0)
        dut.cfg_interrupt_msi_select.setimmediatevalue(0)
        dut.cfg_interrupt_msi_int.setimmediatevalue(0)
        dut.cfg_interrupt_msi_pending_status.setimmediatevalue(0)
        dut.cfg_interrupt_msi_pending_status_data_enable.setimmediatevalue(0)
        dut.cfg_interrupt_msi_pending_status_function_num.setimmediatevalue(0)
        dut.cfg_interrupt_msix_address.setimmediatevalue(0)
        dut.cfg_interrupt_msix_data.setimmediatevalue(0)
        dut.cfg_interrupt_msix_int.setimmediatevalue(0)
        dut.cfg_interrupt_msi_attr.setimmediatevalue(0)
        dut.cfg_interrupt_msi_tph_present.setimmediatevalue(0)
        dut.cfg_interrupt_msi_tph_type.setimmediatevalue(0)
        dut.cfg_interrupt_msi_tph_st_tag.setimmediatevalue(0)
        dut.cfg_interrupt_msi_function_number.setimmediatevalue(0)
        dut.cfg_config_space_enable.setimmediatevalue(1)
        dut.cfg_req_pm_transition_l23_ready.setimmediatevalue(0)
        dut.cfg_hot_reset_in.setimmediatevalue(0)
        dut.cfg_ds_port_number.setimmediatevalue(0)
        dut.cfg_ds_bus_number.setimmediatevalue(0)
        dut.cfg_ds_device_number.setimmediatevalue(0)
        dut.cfg_ds_function_number.setimmediatevalue(0)
        dut.cfg_subsys_vend_id.setimmediatevalue(0)
        dut.sys_clk.setimmediatevalue(0)
        dut.sys_clk_gt.setimmediatevalue(0)
        dut.sys_reset.setimmediatevalue(1)
        dut.pcie_perstn1_in.setimmediatevalue(1)

        self.rc.make_port().connect(self.dev)

        # user logic
        rc_segments = 2 if rc_straddle else 1

        self.rq_source = RqSource(AxiStreamBus.from_prefix(dut, "s_axis_rq"), dut.user_clk, dut.user_reset)
        self.rc_sink = RcSink(AxiStreamBus.from_prefix(dut, "m_axis_rc"), dut.user_clk, dut.user_reset, segments=rc_segments)
        self.cq_sink = CqSink(AxiStreamBus.from_prefix(dut, "m_axis_cq"), dut.user_clk, dut.user_reset)
        self.cc_source = CcSource(AxiStreamBus.from_prefix(dut, "s_axis_cc"), dut.user_clk, dut.user_reset)

        self.regions = [None]*6
        self.regions[0] = mmap.mmap(-1, 1024*1024)
        self.regions[1] = mmap.mmap(-1, 1024*1024)
        self.regions[3] = mmap.mmap(-1, 1024)
        self.regions[4] = mmap.mmap(-1, 1024*64)

        self.current_tag = 0
        self.tag_count = 64
        self.tag_active = [False]*256
        self.tag_release = Event()

        self.rq_tag = Queue()

        self.rx_cpl_queues = [Queue() for k in range(256)]
        self.rx_cpl_sync = [Event() for k in range(256)]

        self.dev.functions[0].configure_bar(0, len(self.regions[0]))
        self.dev.functions[0].configure_bar(1, len(self.regions[1]), True, True)
        self.dev.functions[0].configure_bar(3, len(self.regions[3]), False, False, True)
        self.dev.functions[0].configure_bar(4, len(self.regions[4]))

        if not self.client_tag:
            cocotb.start_soon(self._run_rq_tags())
        cocotb.start_soon(self._run_rc())
        cocotb.start_soon(self._run_cq())

    def set_idle_generator(self, generator=None):
        if generator:
            self.dev.rc_source.set_pause_generator(generator())
            self.dev.cq_source.set_pause_generator(generator())

    def set_backpressure_generator(self, generator=None):
        if generator:
            self.dev.rq_sink.set_pause_generator(generator())
            self.dev.cc_sink.set_pause_generator(generator())

    async def recv_cpl(self, tag, timeout=0, timeout_unit='ns'):
        queue = self.rx_cpl_queues[tag]
        sync = self.rx_cpl_sync[tag]

        if not queue.empty():
            return queue.get_nowait()

        sync.clear()
        if timeout:
            await First(sync.wait(), Timer(timeout, timeout_unit))
        else:
            await sync.wait()

        if not queue.empty():
            return queue.get_nowait()

        return None

    async def alloc_tag(self):
        tag_count = min(256 if self.dev.functions[0].pcie_cap.extended_tag_field_enable else 32, self.tag_count)

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

    async def perform_posted_operation(self, req):
        await self.rq_source.send(req.pack_us_rq())

    async def perform_nonposted_operation(self, req, timeout=0, timeout_unit='ns'):
        completions = []

        if self.client_tag:
            req.tag = await self.alloc_tag()
            await self.rq_source.send(req.pack_us_rq())
        else:
            await self.rq_source.send(req.pack_us_rq())
            req.tag = await self.rq_tag.get()

        while True:
            cpl = await self.recv_cpl(req.tag, timeout, timeout_unit)

            if not cpl:
                break

            completions.append(cpl)

            if cpl.status != CplStatus.SC:
                # bad status
                break
            elif req.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64}:
                # completion for memory read request

                # request completed
                if cpl.byte_count <= cpl.length*4 - (cpl.lower_address & 0x3):
                    break

                # completion for read request has SC status but no data
                if cpl.fmt_type in {TlpType.CPL, TlpType.CPL_LOCKED}:
                    break

            else:
                # completion for other request
                break

        if self.client_tag:
            self.release_tag(req.tag)

        return completions

    async def dma_io_write(self, addr, data, timeout=0, timeout_unit='ns'):
        n = 0

        zero_len = len(data) == 0
        if zero_len:
            data = b'\x00'

        op_list = []

        while n < len(data):
            req = Tlp_us()
            req.fmt_type = TlpType.IO_WRITE
            req.requester_id = PcieId(0, 0, 0)

            first_pad = addr % 4
            byte_length = min(len(data)-n, 4-first_pad)
            req.set_addr_be_data(addr, data[n:n+byte_length])

            if zero_len:
                req.first_be = 0

            op_list.append(cocotb.start_soon(self.perform_nonposted_operation(req, timeout, timeout_unit)))

            n += byte_length
            addr += byte_length

        for op in op_list:
            cpl_list = await op.join()

            if not cpl_list:
                raise Exception("Timeout")
            if cpl_list[0].status != CplStatus.SC:
                raise Exception("Unsuccessful completion")

    async def dma_io_read(self, addr, length, timeout=0, timeout_unit='ns'):
        data = bytearray()
        n = 0

        zero_len = length <= 0
        if zero_len:
            length = 1

        op_list = []

        while n < length:
            req = Tlp_us()
            req.fmt_type = TlpType.IO_READ
            req.requester_id = PcieId(0, 0, 0)

            first_pad = addr % 4
            byte_length = min(length-n, 4-first_pad)
            req.set_addr_be(addr, byte_length)

            if zero_len:
                req.first_be = 0

            op_list.append((first_pad, cocotb.start_soon(self.perform_nonposted_operation(req, timeout, timeout_unit))))

            n += byte_length
            addr += byte_length

        for first_pad, op in op_list:
            cpl_list = await op.join()

            if not cpl_list:
                raise Exception("Timeout")
            cpl = cpl_list[0]
            if cpl.status != CplStatus.SC:
                raise Exception("Unsuccessful completion")

            assert cpl.length == 1
            d = cpl.get_data()

            data.extend(d[first_pad:])

        if zero_len:
            return b''

        return bytes(data[:length])

    async def dma_mem_write(self, addr, data, timeout=0, timeout_unit='ns'):
        n = 0

        zero_len = len(data) == 0
        if zero_len:
            data = b'\x00'

        while n < len(data):
            req = Tlp_us()
            if addr > 0xffffffff:
                req.fmt_type = TlpType.MEM_WRITE_64
            else:
                req.fmt_type = TlpType.MEM_WRITE
            req.requester_id = PcieId(0, 0, 0)

            first_pad = addr % 4
            byte_length = len(data)-n
            # max payload size
            byte_length = min(byte_length, (128 << self.dut.cfg_max_payload.value.integer)-first_pad)
            # 4k address align
            byte_length = min(byte_length, 0x1000 - (addr & 0xfff))
            req.set_addr_be_data(addr, data[n:n+byte_length])

            if zero_len:
                req.first_be = 0

            await self.perform_posted_operation(req)

            n += byte_length
            addr += byte_length

    async def dma_mem_read(self, addr, length, timeout=0, timeout_unit='ns'):
        data = bytearray()
        n = 0

        zero_len = length <= 0
        if zero_len:
            length = 1

        op_list = []

        while n < length:
            req = Tlp_us()
            if addr > 0xffffffff:
                req.fmt_type = TlpType.MEM_READ_64
            else:
                req.fmt_type = TlpType.MEM_READ
            req.requester_id = PcieId(0, 0, 0)

            first_pad = addr % 4
            # remaining length
            byte_length = length-n
            # limit to max read request size
            if byte_length > (128 << self.dut.cfg_max_read_req.value.integer) - first_pad:
                # split on 128-byte read completion boundary
                byte_length = min(byte_length, (128 << self.dut.cfg_max_read_req.value.integer) - (addr & 0x7f))
            # 4k align
            byte_length = min(byte_length, 0x1000 - (addr & 0xfff))
            req.set_addr_be(addr, byte_length)

            if zero_len:
                req.first_be = 0

            op_list.append((byte_length, cocotb.start_soon(self.perform_nonposted_operation(req, timeout, timeout_unit))))

            n += byte_length
            addr += byte_length

        for byte_length, op in op_list:
            cpl_list = await op.join()

            m = 0

            while m < byte_length:
                if not cpl_list:
                    raise Exception("Timeout")

                cpl = cpl_list.pop(0)

                if cpl.status != CplStatus.SC:
                    raise Exception("Unsuccessful completion")

                assert cpl.byte_count+3+(cpl.lower_address & 3) >= cpl.length*4
                assert cpl.byte_count == max(byte_length - m, 1)

                d = cpl.get_data()

                offset = cpl.lower_address & 3
                data.extend(d[offset:offset+cpl.byte_count])

                m += len(d)-offset

        if zero_len:
            return b''

        return bytes(data[:length])

    async def _run_rq_tags(self):
        clock_edge_event = RisingEdge(self.dut.user_clk)

        while True:
            await clock_edge_event

            if self.dut.pcie_rq_tag_vld.value:
                self.rq_tag.put_nowait(self.dut.pcie_rq_tag.value.integer)

    async def _run_rc(self):
        while True:
            pkt = await self.rc_sink.recv()

            tlp = Tlp_us.unpack_us_rc(pkt)

            self.log.debug("RC TLP: %s", repr(tlp))

            self.rx_cpl_queues[tlp.tag].put_nowait(tlp)
            self.rx_cpl_sync[tlp.tag].set()

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

    await tb.rc.enumerate()

    dev = tb.rc.find_device(tb.dev.functions[0].pcie_id)
    await dev.enable_device()

    dev_bar0 = dev.bar_window[0]
    dev_bar1 = dev.bar_window[1]
    dev_bar3 = dev.bar_window[3]

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
            await dev_bar0.read(offset, 0, timeout=5000)
            assert tb.regions[0][offset:offset+length] == test_data

            assert await dev_bar0.read(offset, length, timeout=5000) == test_data

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (64-bit BAR) length: %d offset: %d", length, offset)
            test_data = bytearray([x % 256 for x in range(length)])

            await dev_bar1.write(offset, test_data, timeout=100)
            # wait for write to complete
            await dev_bar1.read(offset, 0, timeout=5000)
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

    await tb.rc.enumerate()

    dev = tb.rc.find_device(tb.dev.functions[0].pcie_id)
    await dev.enable_device()
    await dev.set_master()

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (DMA) length: %d offset: %d", length, offset)
            addr = mem_base+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await tb.dma_mem_write(addr, test_data, 5000, 'ns')
            # wait for write to complete
            await tb.dma_mem_read(addr, 0, 5000, 'ns')
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

    await tb.rc.enumerate()

    dev = tb.rc.find_device(tb.dev.functions[0].pcie_id)
    await dev.enable_device()
    await dev.set_master()
    await dev.alloc_irq_vectors(32, 32)

    assert dut.cfg_interrupt_msi_enable.value.integer & 1

    for k in range(32):
        tb.log.info("Send MSI %d", k)

        await RisingEdge(dut.user_clk)
        tb.dut.cfg_interrupt_msi_int.value = 1 << k
        await RisingEdge(dut.user_clk)
        tb.dut.cfg_interrupt_msi_int.value = 0

        while not tb.dut.cfg_interrupt_msi_sent.value.integer and not tb.dut.cfg_interrupt_msi_fail.value.integer:
            await RisingEdge(dut.user_clk)

        event = dev.msi_vectors[k].event
        event.clear()
        await event.wait()

    await RisingEdge(dut.user_clk)
    await RisingEdge(dut.user_clk)


async def run_test_msix(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut, msix=True)

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    await FallingEdge(dut.user_reset)
    await Timer(100, 'ns')

    await tb.rc.enumerate()

    dev = tb.rc.find_device(tb.dev.functions[0].pcie_id)
    await dev.enable_device()
    await dev.set_master()
    await dev.alloc_irq_vectors(64, 64)

    for k in range(64):
        tb.log.info("Send MSI %d", k)

        addr = int.from_bytes(tb.regions[4][16*k+0:16*k+8], 'little')
        data = int.from_bytes(tb.regions[4][16*k+8:16*k+12], 'little')

        await RisingEdge(dut.user_clk)
        tb.dut.cfg_interrupt_msix_address.value = addr
        tb.dut.cfg_interrupt_msix_data.value = data
        tb.dut.cfg_interrupt_msix_int.value = 1
        await RisingEdge(dut.user_clk)
        tb.dut.cfg_interrupt_msix_int.value = 0

        while not tb.dut.cfg_interrupt_msix_sent.value.integer and not tb.dut.cfg_interrupt_msix_fail.value.integer:
            await RisingEdge(dut.user_clk)

        event = dev.msi_vectors[k].event
        event.clear()
        await event.wait()

    await RisingEdge(dut.user_clk)
    await RisingEdge(dut.user_clk)


async def run_test_crs(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    await FallingEdge(dut.user_reset)
    await Timer(100, 'ns')

    async def toggle_config_space_enable(dut):
        dut.cfg_config_space_enable.setimmediatevalue(0)
        await Timer(100, 'us')
        dut.cfg_config_space_enable.setimmediatevalue(1)

    cocotb.start_soon(toggle_config_space_enable(dut))

    await tb.rc.enumerate()

    dev = tb.rc.find_device(tb.dev.functions[0].pcie_id)
    await dev.enable_device()

    dut.cfg_config_space_enable.setimmediatevalue(0)

    val = await dev.config_read_dword(0x00)
    tb.log.info("ID register values: 0x%08x", val)

    assert val == 0xffff0001

    dut.cfg_config_space_enable.setimmediatevalue(1)

    val = await dev.config_read_dword(0x00)
    tb.log.info("ID register values: 0x%08x", val)

    assert val != 0xffff0001 and val != 0xffffffff

    await RisingEdge(dut.user_clk)
    await RisingEdge(dut.user_clk)


def cycle_pause():
    return itertools.cycle([1, 1, 1, 0])


if cocotb.SIM_NAME:

    for test in [
                run_test_mem,
                run_test_dma,
                run_test_msi,
                run_test_msix,
                run_test_crs,
            ]:

        factory = TestFactory(test)
        factory.add_option(("idle_inserter", "backpressure_inserter"), [(None, None), (cycle_pause, cycle_pause)])
        factory.generate_tests()


# cocotb-test

tests_dir = os.path.dirname(__file__)


@pytest.mark.parametrize("client_tag", [True, False])
@pytest.mark.parametrize(("data_width", "straddle"),
    [(64, False), (128, False), (256, False), (256, True)])
def test_pcie_us(request, data_width, straddle, client_tag):
    dut = "test_pcie_us"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(tests_dir, f"{dut}.v"),
    ]

    parameters = {}

    parameters['DATA_WIDTH'] = data_width
    parameters['KEEP_WIDTH'] = (parameters['DATA_WIDTH'] // 32)
    parameters['RQ_USER_WIDTH'] = 60
    parameters['RC_USER_WIDTH'] = 75
    parameters['CQ_USER_WIDTH'] = 85
    parameters['CC_USER_WIDTH'] = 33

    extra_env = {f'PARAM_{k}': str(v) for k, v in parameters.items()}

    extra_env['STRADDLE'] = str(int(straddle))
    extra_env['CLIENT_TAG'] = str(int(client_tag))

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
