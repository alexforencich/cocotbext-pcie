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

from cocotb.triggers import Event, Timer, First
from collections import deque

from .caps import PcieCapList, PcieExtCapList
from .caps import PmCapability, PcieCapability
from .tlp import Tlp, TlpType, CplStatus
from .utils import PcieId, byte_mask_update


class Function(PmCapability, PcieCapability):
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

        self.rx_cpl_queues = [deque() for k in range(256)]
        self.rx_cpl_sync = [Event() for k in range(256)]

        self.rx_tlp_handler = {}

        self.capabilities = PcieCapList()
        self.ext_capabilities = PcieExtCapList()

        # configuration registers
        self.vendor_id = 0
        self.device_id = 0
        # command register
        self.bus_master_enable = False
        self.parity_error_response = False
        self.serr_enable = False
        self.interrupt_disable = False
        # status register
        self.interrupt_status = False
        self.capabilities_list = True
        self.master_data_parity_error = False
        self.signaled_target_abort = False
        self.received_target_abort = False
        self.received_master_abort = False
        self.signaled_system_error = False
        self.detected_parity_error = False
        self.revision_id = 0
        self.class_code = 0
        self.cache_ln = 0
        self.lat_timer = 0
        self.header_type = 0
        self.bist = 0
        self.bar = []
        self.bar_mask = []
        self.expansion_rom_addr = 0
        self.expansion_rom_addr_mask = 0
        self.expansion_rom_enable = 0
        self.cap_ptr = 0
        self.intr_pin = 0
        self.intr_line = 0

        self.read_completion_boundary = 128

        self.register_rx_tlp_handler(TlpType.CFG_READ_0, self.handle_config_0_read_tlp)
        self.register_rx_tlp_handler(TlpType.CFG_WRITE_0, self.handle_config_0_write_tlp)

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
            return (self.device_id << 16) | self.vendor_id
        elif reg == 1:
            val = 0
            # command
            val |= bool(self.bus_master_enable) << 2
            val |= bool(self.parity_error_response) << 6
            val |= bool(self.serr_enable) << 8
            val |= bool(self.interrupt_disable) << 10
            # status
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
            return (self.class_code << 8) | self.revision_id
        elif reg == 3:
            return (self.bist << 24) | (self.header_type << 16) | (self.lat_timer << 8) | self.cache_ln
        elif reg == 13:
            return self.cap_ptr
        elif reg == 15:
            return (self.intr_pin << 8) | self.intr_line
        elif 16 <= reg < 256:
            return await self.read_capability_register(reg)
        elif 256 <= reg < 4096:
            return await self.read_extended_capability_register(reg)
        else:
            return 0

    async def write_config_register(self, reg, data, mask):
        if reg == 1:
            # command
            if mask & 0x1:
                self.bus_master_enable = (data & 1 << 2 != 0)
                self.parity_error_response = (data & 1 << 6 != 0)
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
            self.cache_ln = byte_mask_update(self.cache_ln, mask & 1, data)
            self.lat_timer = byte_mask_update(self.lat_timer, (mask >> 1) & 1, data >> 8)
            self.bist = byte_mask_update(self.bist, (mask >> 3) & 1, data >> 24)
        elif reg == 15:
            self.intr_line = byte_mask_update(self.intr_line, mask & 1, data)
            self.intr_pin = byte_mask_update(self.intr_pin, (mask >> 1) & 1, data >> 8)
        elif 16 <= reg < 256:
            await self.write_capability_register(reg, data, mask)
        elif 256 <= reg < 4096:
            await self.write_extended_capability_register(reg, data, mask)

    async def read_capability_register(self, reg):
        return await self.capabilities.read_register(reg)

    async def write_capability_register(self, reg, data, mask):
        await self.capabilities.write_register(reg, data, mask)

    def register_capability(self, cap_id, length=None, read=None, write=None, offset=None):
        self.capabilities.register(cap_id, 0, length, read, write, offset)
        if self.capabilities.list:
            self.cap_ptr = self.capabilities.list[0].offset*4
        else:
            self.cap_ptr = 0

    async def read_extended_capability_register(self, reg):
        return await self.ext_capabilities.read_register(reg)

    async def write_extended_capability_register(self, reg, data, mask):
        await self.ext_capabilities.write_register(reg, data, mask)

    def register_extended_capability(self, cap_id, cap_ver, length=None, read=None, write=None, offset=None):
        self.ext_capabilities.register(cap_id, cap_ver, length, read, write, offset)

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
        m = []
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

                if io and addr & bar_mask == bar_val & bar_mask:
                    m.append((orig_bar, addr & ~bar_mask))

            else:
                # Memory BAR

                if bar_val & 4:
                    # 64 bit BAR

                    if bar >= len(self.bar):
                        raise Exception("Final BAR marked as 64 bit, but no extension BAR available")

                    bar_val |= self.bar[bar] << 32
                    bar_mask |= self.bar_mask[bar] << 32

                    bar += 1

                if not io and addr & bar_mask == bar_val & bar_mask:
                    m.append((orig_bar, addr & ~bar_mask))

        return m

    def match_io_bar(self, addr):
        return self.match_bar(addr, io=True)

    async def upstream_send(self, tlp):
        self.log.debug("Sending upstream TLP: %s", repr(tlp))
        assert tlp.check()
        if self.upstream_tx_handler is None:
            raise Exception("Transmit handler not set")
        await self.upstream_tx_handler(tlp)

    async def send(self, tlp):
        await self.upstream_send(tlp)

    async def upstream_recv(self, tlp):
        self.log.debug("Got downstream TLP: %s", repr(tlp))
        assert tlp.check()
        await self.handle_tlp(tlp)

    async def handle_tlp(self, tlp):
        if (tlp.fmt_type == TlpType.CPL or tlp.fmt_type == TlpType.CPL_DATA or
                tlp.fmt_type == TlpType.CPL_LOCKED or tlp.fmt_type == TlpType.CPL_LOCKED_DATA):
            # completion
            self.rx_cpl_queues[tlp.tag].append(tlp)
            self.rx_cpl_sync[tlp.tag].set()
        elif tlp.fmt_type in self.rx_tlp_handler:
            # call registered handler
            await self.rx_tlp_handler[tlp.fmt_type](tlp)
        else:
            # no handler registered for TLP type
            raise Exception("Unhandled TLP")

    def register_rx_tlp_handler(self, fmt_type, func):
        self.rx_tlp_handler[fmt_type] = func

    async def recv_cpl(self, tag, timeout=0, timeout_unit='ns'):
        queue = self.rx_cpl_queues[tag]
        sync = self.rx_cpl_sync[tag]

        if queue:
            return queue.popleft()

        sync.clear()
        if timeout:
            await First(sync.wait(), Timer(timeout, timeout_unit))
        else:
            await sync.wait()

        if queue:
            return queue.popleft()

        return None

    async def alloc_tag(self):
        tag_count = min(256 if self.extended_tag_field_enable else 32, self.tag_count)

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
            cpl.data = [data]
            cpl.byte_count = 4
            cpl.length = 1

            self.log.debug("Completion: %s", repr(cpl))
            await self.upstream_send(cpl)
        else:
            # error
            pass

    async def handle_config_0_write_tlp(self, tlp):
        if tlp.dest_id.device == self.device_num and tlp.dest_id.function == self.function_num:
            self.log.info("Config type 0 write, reg 0x%03x data 0x%08x", tlp.register_number, tlp.data[0])

            # capture address information
            if self.bus_num != tlp.dest_id.bus:
                self.log.info("Capture bus number %d", tlp.dest_id.bus)
                self.pcie_id = self.pcie_id._replace(bus=tlp.dest_id.bus)

            # perform operation
            await self.write_config_register(tlp.register_number, tlp.data[0], tlp.first_be)

            # prepare completion TLP
            cpl = Tlp.create_completion_for_tlp(tlp, self.pcie_id)

            self.log.debug("Completion: %s", repr(cpl))
            await self.upstream_send(cpl)
        else:
            # error
            pass

    async def io_read(self, addr, length, timeout=0, timeout_unit='ns'):
        n = 0
        data = b''

        if not self.bus_master_enable:
            self.log.warning("Bus mastering not enabled, aborting")
            return None

        while n < length:
            tlp = Tlp()
            tlp.fmt_type = TlpType.IO_READ
            tlp.requester_id = self.pcie_id

            first_pad = addr % 4
            byte_length = min(length-n, 4-first_pad)
            tlp.set_addr_be(addr, byte_length)

            tlp.tag = await self.alloc_tag()

            await self.send(tlp)
            cpl = await self.recv_cpl(tlp.tag, timeout, timeout_unit)

            self.release_tag(tlp.tag)

            if not cpl:
                raise Exception("Timeout")
            if cpl.status != CplStatus.SC:
                raise Exception("Unsuccessful completion")
            else:
                assert cpl.length == 1
                d = struct.pack('<L', cpl.data[0])

            data += d[first_pad:]

            n += byte_length
            addr += byte_length

        return data[:length]

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
        n = 0

        if not self.bus_master_enable:
            self.log.warning("Bus mastering not enabled, aborting")
            return

        while n < len(data):
            tlp = Tlp()
            tlp.fmt_type = TlpType.IO_WRITE
            tlp.requester_id = self.pcie_id

            first_pad = addr % 4
            byte_length = min(len(data)-n, 4-first_pad)
            tlp.set_addr_be_data(addr, data[n:n+byte_length])

            tlp.tag = await self.alloc_tag()

            await self.send(tlp)
            cpl = await self.recv_cpl(tlp.tag, timeout, timeout_unit)

            self.release_tag(tlp.tag)

            if not cpl:
                raise Exception("Timeout")
            if cpl.status != CplStatus.SC:
                raise Exception("Unsuccessful completion")

            n += byte_length
            addr += byte_length

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

    async def mem_read(self, addr, length, timeout=0, timeout_unit='ns', attr=0, tc=0):
        n = 0
        data = b''

        if not self.bus_master_enable:
            self.log.warning("Bus mastering not enabled, aborting")
            return None

        while n < length:
            tlp = Tlp()
            if addr > 0xffffffff:
                tlp.fmt_type = TlpType.MEM_READ_64
            else:
                tlp.fmt_type = TlpType.MEM_READ
            tlp.requester_id = self.pcie_id
            tlp.attr = attr
            tlp.tc = tc

            first_pad = addr % 4
            byte_length = length-n
            byte_length = min(byte_length, (128 << self.max_read_request_size)-first_pad)  # max read request size
            byte_length = min(byte_length, 0x1000 - (addr & 0xfff))  # 4k align
            tlp.set_addr_be(addr, byte_length)

            tlp.tag = await self.alloc_tag()

            await self.send(tlp)

            m = 0

            while m < byte_length:
                cpl = await self.recv_cpl(tlp.tag, timeout, timeout_unit)

                if not cpl:
                    self.release_tag(tlp.tag)
                    raise Exception("Timeout")
                if cpl.status != CplStatus.SC:
                    self.release_tag(tlp.tag)
                    raise Exception("Unsuccessful completion")
                else:
                    assert cpl.byte_count+3+(cpl.lower_address & 3) >= cpl.length*4
                    assert cpl.byte_count == byte_length - m

                    d = bytearray()

                    for k in range(cpl.length):
                        d.extend(struct.pack('<L', cpl.data[k]))

                    offset = cpl.lower_address & 3
                    data += d[offset:offset+cpl.byte_count]

                m += len(d)-offset

            self.release_tag(tlp.tag)

            n += byte_length
            addr += byte_length

        return data

    async def mem_read_words(self, addr, count, byteorder='little', ws=2, timeout=0, timeout_unit='ns', attr=0, tc=0):
        data = await self.mem_read(addr, count*ws, timeout, timeout_unit, attr, tc)
        words = []
        for k in range(count):
            words.append(int.from_bytes(data[ws*k:ws*(k+1)], byteorder))
        return words

    async def mem_read_dwords(self, addr, count, byteorder='little', timeout=0, timeout_unit='ns', attr=0, tc=0):
        return await self.mem_read_words(addr, count, byteorder, 4, timeout, timeout_unit, attr, tc)

    async def mem_read_qwords(self, addr, count, byteorder='little', timeout=0, timeout_unit='ns', attr=0, tc=0):
        return await self.mem_read_words(addr, count, byteorder, 8, timeout, timeout_unit, attr, tc)

    async def mem_read_byte(self, addr, timeout=0, timeout_unit='ns', attr=0, tc=0):
        return (await self.mem_read(addr, 1, timeout, timeout_unit, attr, tc))[0]

    async def mem_read_word(self, addr, byteorder='little', ws=2, timeout=0, timeout_unit='ns', attr=0, tc=0):
        return (await self.mem_read_words(addr, 1, byteorder, ws, timeout, timeout_unit, attr, tc))[0]

    async def mem_read_dword(self, addr, byteorder='little', timeout=0, timeout_unit='ns', attr=0, tc=0):
        return (await self.mem_read_dwords(addr, 1, byteorder, timeout, timeout_unit, attr, tc))[0]

    async def mem_read_qword(self, addr, byteorder='little', timeout=0, timeout_unit='ns', attr=0, tc=0):
        return (await self.mem_read_qwords(addr, 1, byteorder, timeout, timeout_unit, attr, tc))[0]

    async def mem_write(self, addr, data, timeout=0, timeout_unit='ns', attr=0, tc=0):
        n = 0

        if not self.bus_master_enable:
            self.log.warning("Bus mastering not enabled, aborting")
            return

        while n < len(data):
            tlp = Tlp()
            if addr > 0xffffffff:
                tlp.fmt_type = TlpType.MEM_WRITE_64
            else:
                tlp.fmt_type = TlpType.MEM_WRITE
            tlp.requester_id = self.pcie_id
            tlp.attr = attr
            tlp.tc = tc

            first_pad = addr % 4
            byte_length = len(data)-n
            byte_length = min(byte_length, (128 << self.max_payload_size)-first_pad)  # max payload size
            byte_length = min(byte_length, 0x1000 - (addr & 0xfff))  # 4k align
            tlp.set_addr_be_data(addr, data[n:n+byte_length])

            await self.send(tlp)

            n += byte_length
            addr += byte_length

    async def mem_write_words(self, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns', attr=0, tc=0):
        words = data
        data = bytearray()
        for w in words:
            data.extend(w.to_bytes(ws, byteorder))
        await self.mem_write(addr, data, timeout, timeout_unit, attr, tc)

    async def mem_write_dwords(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns', attr=0, tc=0):
        await self.mem_write_words(addr, data, byteorder, 4, timeout, timeout_unit, attr, tc)

    async def mem_write_qwords(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns', attr=0, tc=0):
        await self.mem_write_words(addr, data, byteorder, 8, timeout, timeout_unit, attr, tc)

    async def mem_write_byte(self, addr, data, timeout=0, timeout_unit='ns', attr=0, tc=0):
        await self.mem_write(addr, [data], timeout, timeout_unit, attr, tc)

    async def mem_write_word(self, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns', attr=0, tc=0):
        await self.mem_write_words(addr, [data], byteorder, ws, timeout, timeout_unit, attr, tc)

    async def mem_write_dword(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns', attr=0, tc=0):
        await self.mem_write_dwords(addr, [data], byteorder, timeout, timeout_unit, attr, tc)

    async def mem_write_qword(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns', attr=0, tc=0):
        await self.mem_write_qwords(addr, [data], byteorder, timeout, timeout_unit, attr, tc)
