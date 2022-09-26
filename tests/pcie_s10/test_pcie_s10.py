#!/usr/bin/env python
"""

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

from cocotbext.pcie.core import RootComplex
from cocotbext.pcie.intel.s10 import S10PcieDevice, S10RxBus, S10TxBus
from cocotbext.pcie.intel.s10.interface import S10PcieFrame, S10PcieSource, S10PcieSink
from cocotbext.pcie.core.tlp import Tlp, TlpType, CplStatus
from cocotbext.pcie.core.utils import PcieId


class TB:
    def __init__(self, dut, msix=False):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        # PCIe
        self.rc = RootComplex()

        self.dev = S10PcieDevice(
            # configuration options
            pcie_generation=3,
            # pcie_link_width=2,
            # pld_clk_frequency=250e6,
            l_tile=False,
            pf_count=1,
            max_payload_size=128,
            enable_extended_tag=False,

            pf0_msi_enable=True,
            pf0_msi_count=32,
            pf1_msi_enable=False,
            pf1_msi_count=1,
            pf2_msi_enable=False,
            pf2_msi_count=1,
            pf3_msi_enable=False,
            pf3_msi_count=1,
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
            # Clock and reset
            npor=dut.npor,
            pin_perst=dut.pin_perst,
            ninit_done=dut.ninit_done,
            pld_clk_inuse=dut.pld_clk_inuse,
            pld_core_ready=dut.pld_core_ready,
            reset_status=dut.reset_status,
            clr_st=dut.clr_st,
            refclk=dut.refclk,
            coreclkout_hip=dut.coreclkout_hip,

            # RX interface
            rx_bus=S10RxBus.from_prefix(dut, "rx_st"),

            # TX interface
            tx_bus=S10TxBus.from_prefix(dut, "tx_st"),

            # TX flow control
            tx_ph_cdts=dut.tx_ph_cdts,
            tx_pd_cdts=dut.tx_pd_cdts,
            tx_nph_cdts=dut.tx_nph_cdts,
            tx_npd_cdts=dut.tx_npd_cdts,
            tx_cplh_cdts=dut.tx_cplh_cdts,
            tx_cpld_cdts=dut.tx_cpld_cdts,
            tx_hdr_cdts_consumed=dut.tx_hdr_cdts_consumed,
            tx_data_cdts_consumed=dut.tx_data_cdts_consumed,
            tx_cdts_type=dut.tx_cdts_type,
            tx_cdts_data_value=dut.tx_cdts_data_value,

            # Hard IP status
            int_status=dut.int_status,
            int_status_common=dut.int_status_common,
            derr_cor_ext_rpl=dut.derr_cor_ext_rpl,
            derr_rpl=dut.derr_rpl,
            derr_cor_ext_rcv=dut.derr_cor_ext_rcv,
            derr_uncor_ext_rcv=dut.derr_uncor_ext_rcv,
            rx_par_err=dut.rx_par_err,
            tx_par_err=dut.tx_par_err,
            ltssmstate=dut.ltssmstate,
            link_up=dut.link_up,
            lane_act=dut.lane_act,
            currentspeed=dut.currentspeed,

            # Power management
            pm_linkst_in_l1=dut.pm_linkst_in_l1,
            pm_linkst_in_l0s=dut.pm_linkst_in_l0s,
            pm_state=dut.pm_state,
            pm_dstate=dut.pm_dstate,
            apps_pm_xmt_pme=dut.apps_pm_xmt_pme,
            apps_ready_entr_l23=dut.apps_ready_entr_l23,
            apps_pm_xmt_turnoff=dut.apps_pm_xmt_turnoff,
            app_init_rst=dut.app_init_rst,
            app_xfer_pending=dut.app_xfer_pending,

            # Interrupt interface
            app_msi_req=dut.app_msi_req,
            app_msi_ack=dut.app_msi_ack,
            app_msi_tc=dut.app_msi_tc,
            app_msi_num=dut.app_msi_num,
            app_msi_func_num=dut.app_msi_func_num,
            app_int_sts=dut.app_int_sts,

            # Error interface
            app_err_valid=dut.app_err_valid,
            app_err_hdr=dut.app_err_hdr,
            app_err_info=dut.app_err_info,
            app_err_func_num=dut.app_err_func_num,

            # Configuration output
            tl_cfg_func=dut.tl_cfg_func,
            tl_cfg_add=dut.tl_cfg_add,
            tl_cfg_ctl=dut.tl_cfg_ctl,

            # Configuration extension bus
            ceb_req=dut.ceb_req,
            ceb_ack=dut.ceb_ack,
            ceb_addr=dut.ceb_addr,
            ceb_din=dut.ceb_din,
            ceb_dout=dut.ceb_dout,
            ceb_wr=dut.ceb_wr,
            ceb_cdm_convert_data=dut.ceb_cdm_convert_data,
            ceb_func_num=dut.ceb_func_num,
            ceb_vf_num=dut.ceb_vf_num,
            ceb_vf_active=dut.ceb_vf_active,

            # Hard IP reconfiguration interface
            hip_reconfig_clk=dut.hip_reconfig_clk,
            hip_reconfig_address=dut.hip_reconfig_address,
            hip_reconfig_read=dut.hip_reconfig_read,
            hip_reconfig_readdata=dut.hip_reconfig_readdata,
            hip_reconfig_readdatavalid=dut.hip_reconfig_readdatavalid,
            hip_reconfig_write=dut.hip_reconfig_write,
            hip_reconfig_writedata=dut.hip_reconfig_writedata,
            hip_reconfig_waitrequest=dut.hip_reconfig_waitrequest,
        )

        self.dev.log.setLevel(logging.DEBUG)

        dut.npor.setimmediatevalue(1)
        dut.pin_perst.setimmediatevalue(1)
        dut.ninit_done.setimmediatevalue(0)
        dut.pld_core_ready.setimmediatevalue(1)
        dut.refclk.setimmediatevalue(0)
        dut.apps_pm_xmt_pme.setimmediatevalue(0)
        dut.apps_ready_entr_l23.setimmediatevalue(0)
        dut.apps_pm_xmt_turnoff.setimmediatevalue(0)
        dut.app_init_rst.setimmediatevalue(0)
        dut.app_xfer_pending.setimmediatevalue(0)
        dut.app_msi_req.setimmediatevalue(0)
        dut.app_msi_tc.setimmediatevalue(0)
        dut.app_msi_num.setimmediatevalue(0)
        dut.app_msi_func_num.setimmediatevalue(0)
        dut.app_int_sts.setimmediatevalue(0)
        dut.app_err_valid.setimmediatevalue(0)
        dut.app_err_hdr.setimmediatevalue(0)
        dut.app_err_info.setimmediatevalue(0)
        dut.app_err_func_num.setimmediatevalue(0)
        dut.ceb_ack.setimmediatevalue(0)
        dut.ceb_din.setimmediatevalue(0)
        dut.ceb_cdm_convert_data.setimmediatevalue(0)
        dut.hip_reconfig_clk.setimmediatevalue(0)
        dut.hip_reconfig_rst_n.setimmediatevalue(1)
        dut.hip_reconfig_address.setimmediatevalue(0)
        dut.hip_reconfig_read.setimmediatevalue(0)
        dut.hip_reconfig_write.setimmediatevalue(0)
        dut.hip_reconfig_writedata.setimmediatevalue(0)

        self.rc.make_port().connect(self.dev)

        # user logic
        self.tx_source = S10PcieSource(S10TxBus.from_prefix(dut, "tx_st"), dut.coreclkout_hip)
        self.tx_source.ready_latency = 3
        self.rx_sink = S10PcieSink(S10RxBus.from_prefix(dut, "rx_st"), dut.coreclkout_hip)
        self.rx_sink.ready_latency = 18 if self.tx_source.width == 512 else 17

        self.regions = [None]*6
        self.regions[0] = mmap.mmap(-1, 1024*1024)
        self.regions[1] = mmap.mmap(-1, 1024*1024)
        self.regions[3] = mmap.mmap(-1, 1024)
        self.regions[4] = mmap.mmap(-1, 1024*64)

        self.current_tag = 0
        self.tag_count = 256
        self.tag_active = [False]*256
        self.tag_release = Event()

        self.rx_cpl_queues = [Queue() for k in range(256)]
        self.rx_cpl_sync = [Event() for k in range(256)]

        self.dev_bus_num = 0
        self.dev_device_num = 0
        self.dev_max_payload = 0
        self.dev_max_read_req = 0
        self.dev_msi_enable = 0
        self.dev_msi_multi_msg_enable = 0
        self.dev_msi_address = 0
        self.dev_msi_data = 0
        self.dev_msi_mask = 0
        self.dev.msix_enable = 0
        self.dev.msix_function_mask = 0

        self.dev.functions[0].configure_bar(0, len(self.regions[0]))
        self.dev.functions[0].configure_bar(1, len(self.regions[1]), True, True)
        self.dev.functions[0].configure_bar(3, len(self.regions[3]), False, False, True)
        self.dev.functions[0].configure_bar(4, len(self.regions[4]))

        cocotb.start_soon(self._run_rx_tlp())
        cocotb.start_soon(self._run_cfg())

    def set_idle_generator(self, generator=None):
        if generator:
            self.dev.rx_source.set_pause_generator(generator())

    def set_backpressure_generator(self, generator=None):
        if generator:
            self.dev.tx_sink.set_pause_generator(generator())

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
        await self.tx_source.send(S10PcieFrame.from_tlp(req))

    async def perform_nonposted_operation(self, req, timeout=0, timeout_unit='ns'):
        completions = []

        req.tag = await self.alloc_tag()

        await self.tx_source.send(S10PcieFrame.from_tlp(req))

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

        self.release_tag(req.tag)

        return completions

    async def dma_io_write(self, addr, data, timeout=0, timeout_unit='ns'):
        n = 0

        zero_len = len(data) == 0
        if zero_len:
            data = b'\x00'

        op_list = []

        while n < len(data):
            req = Tlp()
            req.fmt_type = TlpType.IO_WRITE
            req.requester_id = PcieId(self.dev_bus_num, self.dev_device_num, 0)

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
            req = Tlp()
            req.fmt_type = TlpType.IO_READ
            req.requester_id = PcieId(self.dev_bus_num, self.dev_device_num, 0)

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
            req = Tlp()
            if addr > 0xffffffff:
                req.fmt_type = TlpType.MEM_WRITE_64
            else:
                req.fmt_type = TlpType.MEM_WRITE
            req.requester_id = PcieId(self.dev_bus_num, self.dev_device_num, 0)

            first_pad = addr % 4
            byte_length = len(data)-n
            # max payload size
            byte_length = min(byte_length, (128 << self.dev_max_payload)-first_pad)
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
            req = Tlp()
            if addr > 0xffffffff:
                req.fmt_type = TlpType.MEM_READ_64
            else:
                req.fmt_type = TlpType.MEM_READ
            req.requester_id = PcieId(self.dev_bus_num, self.dev_device_num, 0)

            first_pad = addr % 4
            # remaining length
            byte_length = length-n
            # limit to max read request size
            if byte_length > (128 << self.dev_max_read_req) - first_pad:
                # split on 128-byte read completion boundary
                byte_length = min(byte_length, (128 << self.dev_max_read_req) - (addr & 0x7f))
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

    async def _run_rx_tlp(self):
        while True:
            frame = await self.rx_sink.recv()

            tlp = frame.to_tlp()

            self.log.debug("RX TLP: %s", repr(tlp))

            if tlp.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
                self.log.info("Completion")

                self.rx_cpl_queues[tlp.tag].put_nowait(tlp)
                self.rx_cpl_sync[tlp.tag].set()

            elif tlp.fmt_type == TlpType.IO_READ:
                self.log.info("IO read")

                cpl = Tlp.create_completion_data_for_tlp(tlp, PcieId(self.dev_bus_num, 0, 0))

                # region = tlp.bar_id
                region = 3
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
                await self.tx_source.send(S10PcieFrame.from_tlp(cpl))

            elif tlp.fmt_type == TlpType.IO_WRITE:
                self.log.info("IO write")

                cpl = Tlp.create_completion_for_tlp(tlp, PcieId(self.dev_bus_num, 0, 0))

                # region = tlp.bar_id
                region = 3
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
                await self.tx_source.send(S10PcieFrame.from_tlp(cpl))

            elif tlp.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64}:
                self.log.info("Memory read")

                # perform operation
                region = frame.bar_range
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
                    cpl = Tlp.create_completion_data_for_tlp(tlp, PcieId(self.dev_bus_num, 0, 0))

                    cpl_dw_length = dw_length - m
                    cpl_byte_length = byte_length - n
                    cpl.byte_count = cpl_byte_length
                    if cpl_dw_length > 32 << self.dev_max_payload:
                        # max payload size
                        cpl_dw_length = 32 << self.dev_max_payload
                        # RCB align
                        cpl_dw_length -= (addr & 0x7c) >> 2

                    cpl.lower_address = addr & 0x7f

                    cpl.set_data(data[m*4:(m+cpl_dw_length)*4])

                    self.log.debug("Completion: %s", repr(cpl))
                    await self.tx_source.send(S10PcieFrame.from_tlp(cpl))

                    m += cpl_dw_length
                    n += cpl_dw_length*4 - (addr & 3)
                    addr += cpl_dw_length*4 - (addr & 3)

            elif tlp.fmt_type in {TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
                self.log.info("Memory write")

                # perform operation
                region = frame.bar_range
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

    async def _run_cfg(self):
        while True:
            await RisingEdge(self.dut.coreclkout_hip)

            if self.dut.tl_cfg_func.value.integer == 0:
                addr = self.dut.tl_cfg_add.value.integer
                ctl = self.dut.tl_cfg_ctl.value.integer
                if addr == 0x00:
                    self.dev_max_payload = ctl & 0x7
                    self.dev_max_read_req = (ctl >> 3) & 0x7
                    self.dev_bus_num = (ctl >> 16) & 0xff
                    self.dev_device_num = (ctl >> 24) & 0x1f
                elif addr == 0x03:
                    self.dev_msi_address = (self.dev_msi_address & ~(0xffffffff << 0)) | ctl << 0
                elif addr == 0x04:
                    self.dev_msi_address = (self.dev_msi_address & ~(0xffffffff << 32)) | ctl << 32
                elif addr == 0x05:
                    self.dev_msi_mask = ctl
                elif addr == 0x06:
                    self.dev_msi_enable = ctl & 1
                    self.dev_msi_multi_msg_enable = (ctl >> 2) & 0x7
                    self.dev_msi_data = ctl >> 16
                    self.dev_msix_enable = (ctl >> 5) & 1
                    self.dev_msix_function_mask = (ctl >> 6) & 1


async def run_test_mem(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    await FallingEdge(dut.reset_status)
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

    await RisingEdge(dut.coreclkout_hip)
    await RisingEdge(dut.coreclkout_hip)


async def run_test_dma(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    mem = tb.rc.mem_pool.alloc_region(16*1024*1024)
    mem_base = mem.get_absolute_address(0)

    io = tb.rc.io_pool.alloc_region(1024)
    io_base = io.get_absolute_address(0)

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    await FallingEdge(dut.reset_status)
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

    await RisingEdge(dut.coreclkout_hip)
    await RisingEdge(dut.coreclkout_hip)


async def run_test_msi(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    await FallingEdge(dut.reset_status)
    await Timer(100, 'ns')

    await tb.rc.enumerate()

    dev = tb.rc.find_device(tb.dev.functions[0].pcie_id)
    await dev.enable_device()
    await dev.set_master()
    await dev.alloc_irq_vectors(32, 32)

    await Timer(100, 'ns')
    assert tb.dev_msi_enable

    for k in range(32):
        tb.log.info("Send MSI %d", k)

        await RisingEdge(dut.coreclkout_hip)
        dut.app_msi_req.value = 1
        dut.app_msi_tc.value = 0
        dut.app_msi_num.value = k
        dut.app_msi_func_num.value = 0

        while not dut.app_msi_ack.value.integer:
            await RisingEdge(dut.coreclkout_hip)

        dut.app_msi_req.value = 0
        await RisingEdge(dut.coreclkout_hip)

        event = dev.msi_vectors[k].event
        event.clear()
        await event.wait()

    await RisingEdge(dut.coreclkout_hip)
    await RisingEdge(dut.coreclkout_hip)


async def run_test_msix(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut, msix=True)

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    await FallingEdge(dut.reset_status)
    await Timer(100, 'ns')

    await tb.rc.enumerate()

    dev = tb.rc.find_device(tb.dev.functions[0].pcie_id)
    await dev.enable_device()
    await dev.set_master()
    await dev.alloc_irq_vectors(64, 64)

    await Timer(100, 'ns')
    assert tb.dev_msix_enable

    for k in range(64):
        tb.log.info("Send MSI %d", k)

        addr = int.from_bytes(tb.regions[4][16*k+0:16*k+8], 'little')
        data = int.from_bytes(tb.regions[4][16*k+8:16*k+12], 'little')

        await tb.dma_mem_write(addr, data.to_bytes(4, 'little'), 5000, 'ns')

        event = dev.msi_vectors[k].event
        event.clear()
        await event.wait()

    await RisingEdge(dut.coreclkout_hip)
    await RisingEdge(dut.coreclkout_hip)


def cycle_pause():
    return itertools.cycle([1, 1, 1, 0])


if cocotb.SIM_NAME:

    for test in [
                run_test_mem,
                run_test_dma,
                run_test_msi,
                run_test_msix,
            ]:

        factory = TestFactory(test)
        factory.add_option(("idle_inserter", "backpressure_inserter"), [(None, None), (cycle_pause, cycle_pause)])
        factory.generate_tests()


# cocotb-test

tests_dir = os.path.dirname(__file__)


@pytest.mark.parametrize("data_width", [256, 512])
def test_pcie_s10(request, data_width):
    dut = "test_pcie_s10"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(tests_dir, f"{dut}.v"),
    ]

    parameters = {}

    parameters['SEG_COUNT'] = 2 if data_width == 512 else 1
    parameters['SEG_DATA_WIDTH'] = data_width // parameters['SEG_COUNT']
    parameters['SEG_PARITY_WIDTH'] = parameters['SEG_DATA_WIDTH'] // 8
    parameters['SEG_EMPTY_WIDTH'] = ((parameters['SEG_DATA_WIDTH'] // 32) - 1).bit_length()

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
