#!/usr/bin/env python
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

import itertools
import logging
import mmap
import os

import cocotb_test.simulator
import pytest

import cocotb
from cocotb.clock import Clock
from cocotb.queue import Queue
from cocotb.triggers import RisingEdge, FallingEdge, Timer, Event, First
from cocotb.regression import TestFactory

from cocotbext.pcie.core import RootComplex
from cocotbext.pcie.intel.s5 import S5PcieDevice, S5RxBus, S5TxBus
from cocotbext.pcie.intel.s5.interface import S5PcieFrame, S5PcieSource, S5PcieSink
from cocotbext.pcie.core.tlp import Tlp, TlpType, CplStatus
from cocotbext.pcie.core.utils import PcieId


class TB:
    def __init__(self, dut):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        # Per UG-01097_avst Table 7-3, the 128-bit interface pairs with gen1 x8
        # at 125 MHz and the 256-bit interface pairs with gen2 x8 at 125 MHz.
        if len(dut.tx_st_data) == 128:
            pcie_generation = 1
        else:
            pcie_generation = 2
        cocotb.start_soon(Clock(dut.pld_clk, 8, units="ns").start())

        # PCIe
        self.rc = RootComplex()

        self.dev = S5PcieDevice(
            # configuration options
            pcie_generation=pcie_generation,
            pcie_link_width=8,
            pld_clk_frequency=125e6,
            pf_count=1,
            max_payload_size=128,
            enable_extended_tag=False,

            pf0_msi_enable=True,
            pf0_msi_count=32,

            # signals
            # Clocks
            refclk=dut.refclk,
            pld_clk=dut.pld_clk,
            coreclkout=dut.coreclkout,

            # Reset, status, and link training
            npor=dut.npor,
            pin_perst=dut.pin_perst,
            reset_status=dut.reset_status,
            clr_st=dut.clr_st,
            serdes_pll_locked=dut.serdes_pll_locked,
            pld_core_ready=dut.pld_core_ready,
            pld_clk_inuse=dut.pld_clk_inuse,
            dlup=dut.dlup,
            dlup_exit=dut.dlup_exit,
            hotrst_exit=dut.hotrst_exit,
            l2_exit=dut.l2_exit,
            ev128ns=dut.ev128ns,
            ev1us=dut.ev1us,
            lane_act=dut.lane_act,
            currentspeed=dut.currentspeed,
            ltssmstate=dut.ltssmstate,

            # RX interface
            rx_bus=S5RxBus.from_prefix(dut, "rx_st"),

            # TX interface
            tx_bus=S5TxBus.from_prefix(dut, "tx_st"),

            # TX flow control
            tx_cred_hdrfcp=dut.tx_cred_hdrfcp,
            tx_cred_datafcp=dut.tx_cred_datafcp,
            tx_cred_hdrfcnp=dut.tx_cred_hdrfcnp,
            tx_cred_datafcnp=dut.tx_cred_datafcnp,
            tx_cred_hdrfccp=dut.tx_cred_hdrfccp,
            tx_cred_datafccp=dut.tx_cred_datafccp,
            tx_cred_fchipcons=dut.tx_cred_fchipcons,
            tx_cred_fc_infinite=dut.tx_cred_fc_infinite,
            tx_cons_cred_sel=dut.tx_cons_cred_sel,
            ko_cpl_spc_header=dut.ko_cpl_spc_header,
            ko_cpl_spc_data=dut.ko_cpl_spc_data,

            # Error signals
            derr_cor_ext_rcv0=dut.derr_cor_ext_rcv0,
            derr_rpl=dut.derr_rpl,
            derr_cor_ext_rpl0=dut.derr_cor_ext_rpl0,
            rxfc_cplbuf_ovf=dut.rxfc_cplbuf_ovf,

            # Interrupts for endpoints
            app_msi_req=dut.app_msi_req,
            app_msi_ack=dut.app_msi_ack,
            app_msi_tc=dut.app_msi_tc,
            app_msi_num=dut.app_msi_num,
            app_int_sts=dut.app_int_sts,
            app_int_ack=dut.app_int_ack,

            # Completion side band signals
            cpl_err=dut.cpl_err,
            cpl_pending=dut.cpl_pending,

            # Transaction layer configuration space signals
            tl_cfg_add=dut.tl_cfg_add,
            tl_cfg_ctl=dut.tl_cfg_ctl,
            tl_cfg_sts=dut.tl_cfg_sts,

            # Power management
            pme_to_cr=dut.pme_to_cr,
            pme_to_sr=dut.pme_to_sr,
            pm_event=dut.pm_event,
            pm_data=dut.pm_data,
            pm_auxpwr=dut.pm_auxpwr,
        )

        self.dev.log.setLevel(logging.DEBUG)

        dut.npor.setimmediatevalue(1)
        dut.pin_perst.setimmediatevalue(1)
        dut.pld_core_ready.setimmediatevalue(1)
        dut.refclk.setimmediatevalue(0)
        dut.rx_st_mask.setimmediatevalue(0)
        dut.tx_cons_cred_sel.setimmediatevalue(0)
        dut.app_msi_req.setimmediatevalue(0)
        dut.app_msi_tc.setimmediatevalue(0)
        dut.app_msi_num.setimmediatevalue(0)
        dut.app_int_sts.setimmediatevalue(0)
        dut.cpl_err.setimmediatevalue(0)
        dut.cpl_pending.setimmediatevalue(0)
        dut.pme_to_cr.setimmediatevalue(0)
        dut.pm_event.setimmediatevalue(0)
        dut.pm_data.setimmediatevalue(0)
        dut.pm_auxpwr.setimmediatevalue(0)

        self.rc.make_port().connect(self.dev)

        # user logic
        self.tx_source = S5PcieSource(S5TxBus.from_prefix(dut, "tx_st"), dut.pld_clk)
        self.tx_source.ready_latency = 2
        self.rx_sink = S5PcieSink(S5RxBus.from_prefix(dut, "rx_st"), dut.pld_clk)
        self.rx_sink.ready_latency = 3

        self.regions = [None]*6
        self.regions[0] = mmap.mmap(-1, 1024*1024)
        self.regions[1] = mmap.mmap(-1, 1024*1024)
        self.regions[3] = mmap.mmap(-1, 1024)

        self.current_tag = 0
        self.tag_count = 256
        self.tag_active = [False]*256
        self.tag_release = Event()

        self.rx_cpl_queues = [Queue() for k in range(256)]
        self.rx_cpl_sync = [Event() for k in range(256)]

        self.cfg_regs = [None]*16

        self.dev_bus_num = 0
        self.dev_device_num = 0
        self.dev_max_payload = 0
        self.dev_max_read_req = 0
        self.dev_memory_space_enable = 0
        self.dev_bus_master_enable = 0
        self.dev_interrupt_disable = 0
        self.dev_msi_address = 0
        self.dev_msi_data = 0
        self.dev_msi_enable = 0
        self.dev_msi_multi_msg_enable = 0
        self.dev_msix_enable = 0
        self.dev_msix_function_mask = 0

        self.dev.functions[0].configure_bar(0, len(self.regions[0]))
        self.dev.functions[0].configure_bar(1, len(self.regions[1]), True, True)
        self.dev.functions[0].configure_bar(3, len(self.regions[3]), False, False, True)

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
        await self.tx_source.send(S5PcieFrame.from_tlp(req))

    async def perform_nonposted_operation(self, req, timeout=0, timeout_unit='ns'):
        completions = []

        req.tag = await self.alloc_tag()

        await self.tx_source.send(S5PcieFrame.from_tlp(req))

        while True:
            cpl = await self.recv_cpl(req.tag, timeout, timeout_unit)

            if not cpl:
                break

            completions.append(cpl)

            if cpl.status != CplStatus.SC:
                break
            elif req.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64}:
                if cpl.byte_count <= cpl.length*4 - (cpl.lower_address & 0x3):
                    break

                if cpl.fmt_type in {TlpType.CPL, TlpType.CPL_LOCKED}:
                    break

            else:
                break

        self.release_tag(req.tag)

        return completions

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
            byte_length = min(byte_length, (128 << self.dev_max_payload)-first_pad)
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
            byte_length = length-n
            if byte_length > (128 << self.dev_max_read_req) - first_pad:
                byte_length = min(byte_length, (128 << self.dev_max_read_req) - (addr & 0x7f))
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

            elif tlp.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64}:
                self.log.info("Memory read")

                region = frame.bar.bit_length()-1
                addr = tlp.address % len(self.regions[region])
                length = tlp.length

                data = self.regions[region][addr:addr+length*4]

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
                        cpl_dw_length = 32 << self.dev_max_payload
                        cpl_dw_length -= (addr & 0x7c) >> 2

                    cpl.lower_address = addr & 0x7f

                    cpl.set_data(data[m*4:(m+cpl_dw_length)*4])

                    self.log.debug("Completion: %s", repr(cpl))
                    await self.tx_source.send(S5PcieFrame.from_tlp(cpl))

                    m += cpl_dw_length
                    n += cpl_dw_length*4 - (addr & 3)
                    addr += cpl_dw_length*4 - (addr & 3)

            elif tlp.fmt_type in {TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
                self.log.info("Memory write")

                region = frame.bar.bit_length()-1
                addr = tlp.address % len(self.regions[region])
                offset = 0
                start_offset = None
                mask = tlp.first_be
                length = tlp.length

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

                if length > 2:
                    if start_offset is None:
                        start_offset = offset
                    offset += (length-2)*4

                if length > 1:
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
        # tl_cfg_add/tl_cfg_ctl are multi-cycle paths that hold each index for
        # several pld_clk cycles. Sample in the middle of the window, as the
        # datasheet's recommended Application Layer RTL does (Figure 5-39).
        prev_addr = None

        while True:
            await RisingEdge(self.dut.pld_clk)

            try:
                addr = int(self.dut.tl_cfg_add.value)
            except ValueError:
                continue

            if addr == prev_addr:
                continue
            prev_addr = addr

            # wait out half of the update window before capturing
            for _ in range(4):
                await RisingEdge(self.dut.pld_clk)

            try:
                addr = int(self.dut.tl_cfg_add.value)
                ctl = int(self.dut.tl_cfg_ctl.value)
            except ValueError:
                continue

            self.cfg_regs[addr] = ctl

            if addr == 0x0:
                self.dev_max_payload = (ctl >> 21) & 0x7
                self.dev_max_read_req = (ctl >> 28) & 0x7
            elif addr == 0x3:
                prm_cmd = (ctl >> 8) & 0xffff
                self.dev_memory_space_enable = (prm_cmd >> 1) & 1
                self.dev_bus_master_enable = (prm_cmd >> 2) & 1
                self.dev_interrupt_disable = (prm_cmd >> 10) & 1
            elif addr == 0x5:
                self.dev_msi_address = ((self.dev_msi_address & ~0xfff)
                                        | ((ctl >> 20) & 0xfff))
            elif addr == 0x9:
                self.dev_msi_address = ((self.dev_msi_address & ~(0xfffff << 12))
                                        | (((ctl >> 12) & 0xfffff) << 12))
            elif addr == 0x6:
                self.dev_msi_address = ((self.dev_msi_address & ~(0xfff << 32))
                                        | (((ctl >> 20) & 0xfff) << 32))
            elif addr == 0xb:
                self.dev_msi_address = ((self.dev_msi_address & ~(0xfffff << 44))
                                        | (((ctl >> 12) & 0xfffff) << 44))
            elif addr == 0xd:
                msicsr = ctl & 0xffff
                msixcsr = (ctl >> 16) & 0xffff
                self.dev_msi_enable = msicsr & 1
                self.dev_msi_multi_msg_enable = (msicsr >> 4) & 0x7
                self.dev_msix_enable = (msixcsr >> 15) & 1
                self.dev_msix_function_mask = (msixcsr >> 14) & 1
            elif addr == 0xf:
                self.dev_msi_data = (ctl >> 16) & 0xffff
                self.dev_bus_num = (ctl >> 5) & 0xff
                self.dev_device_num = ctl & 0x1f


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

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (32-bit BAR) length: %d offset: %d", length, offset)
            test_data = bytearray([x % 256 for x in range(length)])

            await dev_bar0.write(offset, test_data, timeout=100)
            await dev_bar0.read(offset, 0, timeout=5000)
            assert tb.regions[0][offset:offset+length] == test_data

            assert await dev_bar0.read(offset, length, timeout=5000) == test_data

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (64-bit BAR) length: %d offset: %d", length, offset)
            test_data = bytearray([x % 256 for x in range(length)])

            await dev_bar1.write(offset, test_data, timeout=100)
            await dev_bar1.read(offset, 0, timeout=5000)
            assert tb.regions[1][offset:offset+length] == test_data

            assert await dev_bar1.read(offset, length, timeout=5000) == test_data

    await RisingEdge(dut.pld_clk)
    await RisingEdge(dut.pld_clk)


async def run_test_dma(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    mem = tb.rc.mem_pool.alloc_region(16*1024*1024)
    mem_base = mem.get_absolute_address(0)

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
            await tb.dma_mem_read(addr, 0, 5000, 'ns')
            assert mem[offset:offset+length] == test_data

            assert await tb.dma_mem_read(addr, length, 5000, 'ns') == test_data

    await RisingEdge(dut.pld_clk)
    await RisingEdge(dut.pld_clk)


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

    for k in range(32):
        tb.log.info("Send MSI %d", k)

        # the Hard IP emits the MSI TLP before it asserts app_msi_ack, so the
        # interrupt can be delivered before the handshake completes; arm the
        # event before requesting the interrupt to avoid losing it
        event = dev.msi_vectors[k].event
        event.clear()

        await RisingEdge(dut.pld_clk)
        dut.app_msi_req.value = 1
        dut.app_msi_tc.value = 0
        dut.app_msi_num.value = k

        while not int(dut.app_msi_ack.value):
            await RisingEdge(dut.pld_clk)

        dut.app_msi_req.value = 0
        await RisingEdge(dut.pld_clk)

        await event.wait()

    await RisingEdge(dut.pld_clk)
    await RisingEdge(dut.pld_clk)


async def run_test_cfg(dut, idle_inserter=None, backpressure_inserter=None):

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

    func = tb.dev.functions[0]

    # let the multiplex walk every index at least once
    await Timer(16*8*8*2, 'ns')

    assert None not in tb.cfg_regs, \
        f"tl_cfg_add never presented every index: {tb.cfg_regs}"

    tb.log.info("Captured tl_cfg_ctl: %s", [hex(x) for x in tb.cfg_regs])

    # index 0x0 - Device Control / Device Control 2
    assert tb.dev_max_payload == func.pcie_cap.max_payload_size
    assert tb.dev_max_read_req == func.pcie_cap.max_read_request_size

    # index 0x3 - Primary Command register
    assert tb.dev_memory_space_enable == bool(func.memory_space_enable)
    assert tb.dev_bus_master_enable == bool(func.bus_master_enable)
    assert tb.dev_bus_master_enable, "bus master enable not visible on tl_cfg_ctl"
    assert tb.dev_interrupt_disable == bool(func.interrupt_disable)

    # indices 0x5/0x6/0x9/0xb - MSI address, reassembled from four slices
    assert tb.dev_msi_address == func.msi_cap.msi_message_address, \
        f"MSI address {tb.dev_msi_address:#x} != {func.msi_cap.msi_message_address:#x}"

    # index 0xd - MSI / MSI-X control, index 0xf - MSI data and bus/device
    assert tb.dev_msi_enable == bool(func.msi_cap.msi_enable)
    assert tb.dev_msi_multi_msg_enable == func.msi_cap.msi_multiple_message_enable
    assert tb.dev_msi_data == func.msi_cap.msi_message_data
    assert tb.dev_bus_num == func.pcie_id.bus
    assert tb.dev_device_num == func.pcie_id.device

    # tl_cfg_sts carries the Link Status register in bits [46:31]. Compare
    # against the configured link parameters rather than against the model's
    # own capability fields, so this cannot pass by both sides reading zero.
    sts = int(dut.tl_cfg_sts.value)
    link_sts = (sts >> 31) & 0xffff
    assert (link_sts & 0xf) == tb.dev.pcie_generation, \
        f"link speed {link_sts & 0xf} != gen {tb.dev.pcie_generation}"
    assert ((link_sts >> 4) & 0x3f) == tb.dev.pcie_link_width, \
        f"negotiated width {(link_sts >> 4) & 0x3f} != x{tb.dev.pcie_link_width}"

    await RisingEdge(dut.pld_clk)
    await RisingEdge(dut.pld_clk)


async def run_test_rx_mask(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    await FallingEdge(dut.reset_status)
    await Timer(100, 'ns')

    await tb.rc.enumerate()

    dev = tb.rc.find_device(tb.dev.functions[0].pcie_id)
    await dev.enable_device()

    dev_bar0 = dev.bar_window[0]

    # rx_st_mask stalls non-posted requests only, so a posted write must still
    # land while it is asserted
    dut.rx_st_mask.value = 1
    await RisingEdge(dut.pld_clk)

    test_data = b'\xde\xad\xbe\xef'
    await dev_bar0.write(0, test_data, timeout=5000)
    await Timer(2000, 'ns')
    assert tb.regions[0][0:4] == test_data, "posted write blocked by rx_st_mask"

    # a non-posted read must not complete until the mask is released.
    # Completion is tracked with an Event rather than Task.done() so this
    # works across the cocotb versions the package supports.
    read_done = Event()
    read_result = {}

    async def _masked_read():
        read_result['data'] = await dev_bar0.read(0, 4, timeout=20000)
        read_done.set()

    cocotb.start_soon(_masked_read())

    await Timer(2000, 'ns')
    assert not read_done.is_set(), "non-posted request not stalled by rx_st_mask"

    dut.rx_st_mask.value = 0
    await read_done.wait()
    assert read_result['data'] == test_data

    await RisingEdge(dut.pld_clk)
    await RisingEdge(dut.pld_clk)


def cycle_pause():
    return itertools.cycle([1, 1, 1, 0])


if getattr(cocotb, 'top', None) is not None:

    for test in [
                run_test_mem,
                run_test_dma,
                run_test_msi,
            ]:

        factory = TestFactory(test)
        factory.add_option(("idle_inserter", "backpressure_inserter"), [(None, None), (cycle_pause, cycle_pause)])
        factory.generate_tests()

    for test in [
                run_test_cfg,
                run_test_rx_mask,
            ]:

        factory = TestFactory(test)
        factory.generate_tests()


# cocotb-test

tests_dir = os.path.dirname(__file__)


@pytest.mark.parametrize("data_width", [128, 256])
def test_pcie_s5(request, data_width):
    dut = "test_pcie_s5"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(tests_dir, f"{dut}.v"),
    ]

    parameters = {}

    parameters['DATA_WIDTH'] = data_width
    parameters['PARITY_WIDTH'] = parameters['DATA_WIDTH'] // 8
    parameters['EMPTY_WIDTH'] = ((parameters['DATA_WIDTH'] // 64) - 1).bit_length()

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
