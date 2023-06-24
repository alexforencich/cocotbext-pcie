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

import logging
import struct

from cocotb.queue import Queue
from cocotb.triggers import Event, Timer, First

from cocotbext.axi import AddressSpace

from .caps import PciCapList, PciExtCapList
from .caps import PmCapability, PcieCapability
from .region import MemoryTlpRegion, IoTlpRegion
from .tlp import Tlp, TlpType, TlpAttr, TlpTc, CplStatus
from .utils import PcieId


class Function:
    """PCIe function, implements config TLP handling"""
    def __init__(self, *args, **kwargs):
        self._pcie_id = PcieId()

        self.log = logging.getLogger(f"cocotb.pcie.{type(self).__name__}.{id(self)}")
        self.log.name = f"cocotb.pcie.{type(self).__name__}[{self._pcie_id}]"

        self.upstream_tx_handler = None

        self.current_tag = 0
        self.tag_count = 256
        self.tag_active = [False]*256
        self.tag_release = Event()

        self.rx_cpl_queues = [Queue() for k in range(256)]
        self.rx_cpl_sync = [Event() for k in range(256)]

        self.rx_tlp_handler = {}

        self.capabilities = PciCapList()
        self.ext_capabilities = PciExtCapList()

        # configuration registers
        # Vendor ID
        self.vendor_id = 0x1234
        # Device ID
        self.device_id = 0x00FF
        # Command
        self.io_space_enable = False
        self.memory_space_enable = False
        self.bus_master_enable = False
        self.parity_error_response_enable = False
        self.serr_enable = False
        self.interrupt_disable = False
        # Status
        self.interrupt_status = False
        self.capabilities_list = True
        self.master_data_parity_error = False
        self.signaled_target_abort = False
        self.received_target_abort = False
        self.received_master_abort = False
        self.signaled_system_error = False
        self.detected_parity_error = False
        # Revision ID
        self.revision_id = 0
        # Class code
        self.class_code = 0
        # Cache line size
        self.cache_line_size = 0
        # Latency timer
        self.latency_timer = 0
        # Header type
        self.header_layout = 0
        self.multifunction_device = False
        # BIST
        self.bist_capable = False
        self.start_bist = False
        self.bist_completion_code = 0
        # Base Address Registers
        self.bar = []
        self.bar_mask = []
        # Expansion ROM Base Address Register
        self.expansion_rom_addr = 0
        self.expansion_rom_addr_mask = 0
        self.expansion_rom_enable = 0
        # Capabilities pointer
        self.capabilities_ptr = 0
        # Interrupt line
        self.interrupt_line = 0
        # Interrupt pin
        self.interrupt_pin = 0

        self.register_rx_tlp_handler(TlpType.CFG_READ_0, self.handle_config_0_read_tlp)
        self.register_rx_tlp_handler(TlpType.CFG_WRITE_0, self.handle_config_0_write_tlp)

        self.pm_cap = PmCapability()
        self.register_capability(self.pm_cap)

        self.pcie_cap = PcieCapability()
        self.register_capability(self.pcie_cap)

        self.mem_address_space = AddressSpace(2**64)
        self.io_address_space = AddressSpace(2**32)

        self.mem_region = MemoryTlpRegion(self)
        self.io_region = IoTlpRegion(self)

        self.mem_address_space.register_region(self.mem_region, 0, 2**64)
        self.io_address_space.register_region(self.io_region, 0, 2**32)

        super().__init__(*args, **kwargs)

    @property
    def pcie_id(self):
        return self._pcie_id

    @pcie_id.setter
    def pcie_id(self, val):
        val = PcieId(val)
        if self._pcie_id != val:
            self.log.info("Assigned PCIe ID %s", val)
            self._pcie_id = val
            self.log.name = f"cocotb.pcie.{type(self).__name__}[{self._pcie_id}]"

    @property
    def bus_num(self):
        return self._pcie_id.bus

    @property
    def device_num(self):
        return self._pcie_id.device

    @property
    def function_num(self):
        return self._pcie_id.function

    """
    Common config space

    31                                                                  0
    +---------------------------------+---------------------------------+
    |            Device ID            |            Vendor ID            |   0   0x00
    +---------------------------------+---------------------------------+
    |             Status              |             Command             |   1   0x04
    +---------------------------------+----------------+----------------+
    |                    Class Code                    |  Revision ID   |   2   0x08
    +----------------+----------------+----------------+----------------+
    |      BIST      |  Header Type   |    Primary     |   Cache Line   |   3   0x0C
    |                |                | Latency Timer  |      Size      |
    +----------------+----------------+----------------+----------------+
    |                                                                   |   4   0x10
    +-------------------------------------------------------------------+
    |                                                                   |   5   0x14
    +-------------------------------------------------------------------+
    |                                                                   |   6   0x18
    +-------------------------------------------------------------------+
    |                                                                   |   7   0x1C
    +-------------------------------------------------------------------+
    |                                                                   |   8   0x20
    +-------------------------------------------------------------------+
    |                                                                   |   9   0x24
    +-------------------------------------------------------------------+
    |                                                                   |  10   0x28
    +-------------------------------------------------------------------+
    |                                                                   |  11   0x2C
    +-------------------------------------------------------------------+
    |                                                                   |  12   0x30
    +--------------------------------------------------+----------------+
    |                                                  |    Cap Ptr     |  13   0x34
    +--------------------------------------------------+----------------+
    |                                                                   |  14   0x38
    +---------------------------------+----------------+----------------+
    |                                 |    Int Pin     |    Int Line    |  15   0x3C
    +---------------------------------+----------------+----------------+
    """
    async def read_config_register(self, reg):
        if reg == 0:
            # Vendor ID
            val = self.vendor_id & 0xffff
            # Device ID
            val |= (self.device_id & 0xffff) << 16
            return val
        elif reg == 1:
            val = 0
            # Command
            val |= bool(self.io_space_enable) << 0
            val |= bool(self.memory_space_enable) << 1
            val |= bool(self.bus_master_enable) << 2
            val |= bool(self.parity_error_response_enable) << 6
            val |= bool(self.serr_enable) << 8
            val |= bool(self.interrupt_disable) << 10
            # Status
            val |= bool(self.interrupt_status) << 19
            val |= bool(self.capabilities_list) << 20
            val |= bool(self.master_data_parity_error) << 24
            val |= bool(self.signaled_target_abort) << 27
            val |= bool(self.received_target_abort) << 28
            val |= bool(self.received_master_abort) << 29
            val |= bool(self.signaled_system_error) << 30
            val |= bool(self.detected_parity_error) << 31
            return val
        elif reg == 2:
            # Revision ID
            val = self.revision_id & 0xff
            # Class code
            val |= (self.class_code & 0xffffff) << 8
            return val
        elif reg == 3:
            # Cache line size
            val = self.cache_line_size & 0xff
            # Latency timer
            val |= (self.latency_timer & 0xff) << 8
            # Header type
            val |= (self.header_layout & 0x7f) << 16
            val |= bool(self.multifunction_device) << 23
            # BIST
            val |= (self.bist_completion_code & 0xf) << 24
            val |= bool(self.start_bist) << 30
            val |= bool(self.bist_capable) << 31
            return val
        elif reg == 13:
            # Capabilities pointer
            return self.capabilities_ptr & 0xff
        elif reg == 15:
            # Interrupt line
            val = self.interrupt_line & 0xff
            # Interrupt pin
            val |= (self.interrupt_pin & 0xff) << 8
            return val
        elif 16 <= reg < 64:
            # PCIe capabilities
            return await self.read_capability_register(reg)
        elif 64 <= reg < 1024:
            # PCIe extended capabilities
            return await self.read_extended_capability_register(reg)
        else:
            return 0

    async def write_config_register(self, reg, data, mask):
        if reg == 1:
            # command
            if mask & 0x1:
                self.io_space_enable = (data & 1 << 0 != 0)
                self.memory_space_enable = (data & 1 << 1 != 0)
                self.bus_master_enable = (data & 1 << 2 != 0)
                self.parity_error_response_enable = (data & 1 << 6 != 0)
            if mask & 0x2:
                self.serr_enable = (data & 1 << 8 != 0)
                self.interrupt_disable = (data & 1 << 10 != 0)
            # status
            if mask & 0x8:
                if data & 1 << 24:
                    self.master_data_parity_error = False
                if data & 1 << 27:
                    self.signaled_target_abort = False
                if data & 1 << 28:
                    self.received_target_abort = False
                if data & 1 << 29:
                    self.received_master_abort = False
                if data & 1 << 30:
                    self.signaled_system_error = False
                if data & 1 << 31:
                    self.detected_parity_error = False
        elif reg == 3:
            if mask & 1:
                # Cache line size
                self.cache_line_size = data & 0xff
            if mask & 4:
                # BIST
                self.start_bist = bool(data & 1 << 30)
        elif reg == 15:
            # Interrupt line
            if mask & 1:
                self.interrupt_line = data & 0xff
        elif 16 <= reg < 64:
            # PCIe capabilities
            await self.write_capability_register(reg, data, mask)
        elif 64 <= reg < 1024:
            # PCIe extended capabilities
            await self.write_extended_capability_register(reg, data, mask)

    async def read_capability_register(self, reg):
        return await self.capabilities.read_register(reg)

    async def write_capability_register(self, reg, data, mask):
        await self.capabilities.write_register(reg, data, mask)

    def register_capability(self, cap, offset=None):
        cap.parent = self
        self.capabilities.register(cap, offset)
        if self.capabilities.list:
            self.capabilities_ptr = self.capabilities.list[0].offset*4
        else:
            self.capabilities_ptr = 0

    def deregister_capability(self, cap):
        self.capabilities.deregister(cap)

    async def read_extended_capability_register(self, reg):
        return await self.ext_capabilities.read_register(reg)

    async def write_extended_capability_register(self, reg, data, mask):
        await self.ext_capabilities.write_register(reg, data, mask)

    def register_extended_capability(self, cap, offset=None):
        cap.parent = self
        self.ext_capabilities.register(cap, offset)

    def deregister_extended_capability(self, cap):
        self.ext_capabilities.deregister(cap)

    def configure_bar(self, idx, size, ext=False, prefetch=False, io=False):
        mask = 2**((size-1).bit_length())-1

        if idx >= len(self.bar) or (ext and idx+1 >= len(self.bar)):
            raise Exception("BAR index out of range")

        if io:
            self.bar[idx] = 1
            self.bar_mask[idx] = 0xfffffffc & ~mask
        else:
            self.bar[idx] = 0
            self.bar_mask[idx] = 0xfffffff0 & ~mask

            if ext:
                self.bar[idx] |= 4
                self.bar[idx+1] = 0
                self.bar_mask[idx+1] = 0xffffffff & (~mask >> 32)

            if prefetch:
                self.bar[idx] |= 8

    def configure_io_bar(self, idx, size):
        self.configure_bar(idx, size, io=True)

    def match_bar(self, addr, io=False):
        bar = 0
        while bar < len(self.bar):
            bar_val = self.bar[bar]
            bar_mask = self.bar_mask[bar]

            orig_bar = bar
            bar += 1

            if bar_mask == 0:
                # unimplemented BAR
                continue

            if bar_val & 1:
                # IO BAR

                if io and (addr ^ bar_val) & bar_mask == 0:
                    return (orig_bar, addr & ~bar_mask)

            else:
                # Memory BAR

                if bar_val & 4:
                    # 64 bit BAR

                    if bar >= len(self.bar):
                        raise Exception("Final BAR marked as 64 bit, but no extension BAR available")

                    bar_val |= self.bar[bar] << 32
                    bar_mask |= self.bar_mask[bar] << 32

                    bar += 1

                if not io and (addr ^ bar_val) & bar_mask == 0:
                    return (orig_bar, addr & ~bar_mask)

        return None

    def match_io_bar(self, addr):
        return self.match_bar(addr, io=True)

    def match_tlp(self, tlp):
        if tlp.fmt_type in {TlpType.CFG_READ_0, TlpType.CFG_WRITE_0}:
            # Config type 0
            return self.device_num == tlp.dest_id.device and self.function_num == tlp.dest_id.function
        elif tlp.fmt_type in {TlpType.CFG_READ_1, TlpType.CFG_WRITE_1}:
            # Config type 1
            return False
        elif tlp.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
            # Completion
            return self.pcie_id == tlp.requester_id
        elif tlp.fmt_type in {TlpType.IO_READ, TlpType.IO_WRITE}:
            # IO read/write
            return bool(self.match_bar(tlp.address, True))
        elif tlp.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64, TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
            # Memory read/write
            return bool(self.match_bar(tlp.address))
        else:
            raise Exception("TODO")
        return False

    async def upstream_send(self, tlp):
        self.log.debug("Sending upstream TLP: %r", tlp)
        assert tlp.check()
        if self.parity_error_response_enable and tlp.ep:
            self.log.warning("Sending poisoned TLP, reporting master data parity error")
            self.master_data_parity_error = True
        if self.upstream_tx_handler is None:
            raise Exception("Transmit handler not set")
        await self.upstream_tx_handler(tlp)

    async def send(self, tlp):
        if tlp.is_completion() and tlp.status == CplStatus.CA:
            self.log.warning("Sending completion with CA status, reporting target abort")
            self.signaled_target_abort = True
        await self.upstream_send(tlp)

    async def upstream_recv(self, tlp):
        self.log.debug("Got downstream TLP: %r", tlp)
        assert tlp.check()
        if tlp.is_completion():
            if tlp.status == CplStatus.CA:
                self.log.warning("Received completion with CA status, reporting target abort")
                self.received_target_abort = True
            elif tlp.status == CplStatus.UR:
                self.log.warning("Received completion with UR status, reporting master abort")
                self.received_master_abort = True
        if self.parity_error_response_enable and tlp.ep:
            self.log.warning("Received poisoned TLP, reporting master data parity error")
            self.master_data_parity_error = True
        await self.handle_tlp(tlp)

    async def handle_tlp(self, tlp):
        if tlp.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
            # completion
            self.rx_cpl_queues[tlp.tag].put_nowait(tlp)
            self.rx_cpl_sync[tlp.tag].set()
        elif tlp.fmt_type in self.rx_tlp_handler:
            # call registered handler
            tlp.release_fc()
            await self.rx_tlp_handler[tlp.fmt_type](tlp)
        else:
            # no handler registered for TLP type
            tlp.release_fc()
            raise Exception("Unhandled TLP")

    def register_rx_tlp_handler(self, fmt_type, func):
        self.rx_tlp_handler[fmt_type] = func

    async def recv_cpl(self, tag, timeout=0, timeout_unit='ns'):
        queue = self.rx_cpl_queues[tag]
        sync = self.rx_cpl_sync[tag]

        if not queue.empty():
            cpl = queue.get_nowait()
            cpl.release_fc()
            return cpl

        sync.clear()
        if timeout:
            await First(sync.wait(), Timer(timeout, timeout_unit))
        else:
            await sync.wait()

        if not queue.empty():
            cpl = queue.get_nowait()
            cpl.release_fc()
            return cpl

        return None

    async def alloc_tag(self):
        tag_count = min(256 if self.pcie_cap.extended_tag_field_enable else 32, self.tag_count)

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
        await self.send(req)

    async def perform_nonposted_operation(self, req, timeout=0, timeout_unit='ns'):
        completions = []

        req.tag = await self.alloc_tag()

        await self.send(req)

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

    async def handle_config_0_read_tlp(self, tlp):
        if tlp.dest_id.device == self.device_num and tlp.dest_id.function == self.function_num:
            self.log.info("Config type 0 read, reg 0x%03x", tlp.register_number)

            # capture address information
            if self.bus_num != tlp.dest_id.bus:
                self.log.info("Capture bus number %d", tlp.dest_id.bus)
                self.pcie_id = self.pcie_id._replace(bus=tlp.dest_id.bus)

            # perform operation
            data = await self.read_config_register(tlp.register_number)

            # prepare completion TLP
            cpl = Tlp.create_completion_data_for_tlp(tlp, self.pcie_id)
            cpl.set_data(struct.pack('<L', data))
            cpl.byte_count = 4

            self.log.debug("Completion: %r", cpl)
            await self.upstream_send(cpl)
        else:
            self.log.warning("Type 0 configuration read request device and function number mismatch: %r", tlp)

            # Unsupported request
            cpl = Tlp.create_ur_completion_for_tlp(tlp, self.pcie_id)
            self.log.debug("UR Completion: %r", cpl)
            await self.upstream_send(cpl)

    async def handle_config_0_write_tlp(self, tlp):
        if tlp.dest_id.device == self.device_num and tlp.dest_id.function == self.function_num:
            self.log.info("Config type 0 write, reg 0x%03x data 0x%08x",
                tlp.register_number, struct.unpack('<L', tlp.get_data())[0])

            # capture address information
            if self.bus_num != tlp.dest_id.bus:
                self.log.info("Capture bus number %d", tlp.dest_id.bus)
                self.pcie_id = self.pcie_id._replace(bus=tlp.dest_id.bus)

            data, = struct.unpack('<L', tlp.get_data())

            # perform operation
            await self.write_config_register(tlp.register_number, data, tlp.first_be)

            # prepare completion TLP
            cpl = Tlp.create_completion_for_tlp(tlp, self.pcie_id)

            self.log.debug("Completion: %r", cpl)
            await self.upstream_send(cpl)
        else:
            self.log.warning("Type 0 configuration write request device and function number mismatch: %r", tlp)

            # Unsupported request
            cpl = Tlp.create_ur_completion_for_tlp(tlp, self.pcie_id)
            self.log.debug("UR Completion: %r", cpl)
            await self.upstream_send(cpl)

    async def io_read(self, addr, length, timeout=0, timeout_unit='ns'):
        return await self.io_address_space.read(addr, length, timeout=timeout, timeout_unit=timeout_unit)

    async def io_read_words(self, addr, count, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        data = await self.io_read(addr, count*ws, timeout, timeout_unit)
        words = []
        for k in range(count):
            words.append(int.from_bytes(data[ws*k:ws*(k+1)], byteorder))
        return words

    async def io_read_dwords(self, addr, count, byteorder='little', timeout=0, timeout_unit='ns'):
        return await self.io_read_words(addr, count, byteorder, 4, timeout, timeout_unit)

    async def io_read_qwords(self, addr, count, byteorder='little', timeout=0, timeout_unit='ns'):
        return await self.io_read_words(addr, count, byteorder, 8, timeout, timeout_unit)

    async def io_read_byte(self, addr, timeout=0, timeout_unit='ns'):
        return (await self.io_read(addr, 1, timeout, timeout_unit))[0]

    async def io_read_word(self, addr, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        return (await self.io_read_words(addr, 1, byteorder, ws, timeout, timeout_unit))[0]

    async def io_read_dword(self, addr, byteorder='little', timeout=0, timeout_unit='ns'):
        return (await self.io_read_dwords(addr, 1, byteorder, timeout, timeout_unit))[0]

    async def io_read_qword(self, addr, byteorder='little', timeout=0, timeout_unit='ns'):
        return (await self.io_read_qwords(addr, 1, byteorder, timeout, timeout_unit))[0]

    async def io_write(self, addr, data, timeout=0, timeout_unit='ns'):
        await self.io_address_space.write(addr, data, timeout=timeout, timeout_unit=timeout_unit)

    async def io_write_words(self, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        words = data
        data = bytearray()
        for w in words:
            data.extend(w.to_bytes(ws, byteorder))
        await self.io_write(addr, data, timeout, timeout_unit)

    async def io_write_dwords(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.io_write_words(addr, data, byteorder, 4, timeout, timeout_unit)

    async def io_write_qwords(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.io_write_words(addr, data, byteorder, 8, timeout, timeout_unit)

    async def io_write_byte(self, addr, data, timeout=0, timeout_unit='ns'):
        await self.io_write(addr, [data], timeout, timeout_unit)

    async def io_write_word(self, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        await self.io_write_words(addr, [data], byteorder, ws, timeout, timeout_unit)

    async def io_write_dword(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.io_write_dwords(addr, [data], byteorder, timeout, timeout_unit)

    async def io_write_qword(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.io_write_qwords(addr, [data], byteorder, timeout, timeout_unit)

    async def mem_read(self, addr, length, timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        return await self.mem_address_space.read(addr, length, timeout=timeout, timeout_unit=timeout_unit, attr=attr, tc=tc)

    async def mem_read_words(self, addr, count, byteorder='little', ws=2, timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        data = await self.mem_read(addr, count*ws, timeout, timeout_unit, attr, tc)
        words = []
        for k in range(count):
            words.append(int.from_bytes(data[ws*k:ws*(k+1)], byteorder))
        return words

    async def mem_read_dwords(self, addr, count, byteorder='little', timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        return await self.mem_read_words(addr, count, byteorder, 4, timeout, timeout_unit, attr, tc)

    async def mem_read_qwords(self, addr, count, byteorder='little', timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        return await self.mem_read_words(addr, count, byteorder, 8, timeout, timeout_unit, attr, tc)

    async def mem_read_byte(self, addr, timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        return (await self.mem_read(addr, 1, timeout, timeout_unit, attr, tc))[0]

    async def mem_read_word(self, addr, byteorder='little', ws=2, timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        return (await self.mem_read_words(addr, 1, byteorder, ws, timeout, timeout_unit, attr, tc))[0]

    async def mem_read_dword(self, addr, byteorder='little', timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        return (await self.mem_read_dwords(addr, 1, byteorder, timeout, timeout_unit, attr, tc))[0]

    async def mem_read_qword(self, addr, byteorder='little', timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        return (await self.mem_read_qwords(addr, 1, byteorder, timeout, timeout_unit, attr, tc))[0]

    async def mem_write(self, addr, data, timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        await self.mem_address_space.write(addr, data, timeout=timeout, timeout_unit=timeout_unit, attr=attr, tc=tc)

    async def mem_write_words(self, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        words = data
        data = bytearray()
        for w in words:
            data.extend(w.to_bytes(ws, byteorder))
        await self.mem_write(addr, data, timeout, timeout_unit, attr, tc)

    async def mem_write_dwords(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        await self.mem_write_words(addr, data, byteorder, 4, timeout, timeout_unit, attr, tc)

    async def mem_write_qwords(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        await self.mem_write_words(addr, data, byteorder, 8, timeout, timeout_unit, attr, tc)

    async def mem_write_byte(self, addr, data, timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        await self.mem_write(addr, [data], timeout, timeout_unit, attr, tc)

    async def mem_write_word(self, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        await self.mem_write_words(addr, [data], byteorder, ws, timeout, timeout_unit, attr, tc)

    async def mem_write_dword(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        await self.mem_write_dwords(addr, [data], byteorder, timeout, timeout_unit, attr, tc)

    async def mem_write_qword(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        await self.mem_write_qwords(addr, [data], byteorder, timeout, timeout_unit, attr, tc)
