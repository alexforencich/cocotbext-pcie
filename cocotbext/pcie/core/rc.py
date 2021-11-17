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

from .version import __version__
from .bridge import HostBridge, RootPort
from .caps import PcieCapId
from .msi import MsiRegion
from .region import MemoryTlpRegion, IoTlpRegion
from .switch import Switch
from .tlp import Tlp, TlpType, TlpAttr, TlpTc, CplStatus
from .utils import PcieId, TreeItem, align


class RootComplex(Switch):
    def __init__(self, mem_address_space=None, io_address_space=None, *args, **kwargs):

        self.default_upstream_bridge = HostBridge
        self.default_downstream_bridge = RootPort

        super().__init__(*args, **kwargs)

        self.log = logging.getLogger(f"cocotb.pcie.{type(self).__name__}.{id(self)}")
        self.log.name = f"cocotb.pcie.{type(self).__name__}"

        self.log.info("PCIe root complex model")
        self.log.info("cocotbext-pcie version %s", __version__)
        self.log.info("Copyright (c) 2020 Alex Forencich")
        self.log.info("https://github.com/alexforencich/cocotbext-pcie")

        self.min_dev = 1

        self.current_tag = 0
        self.tag_count = 32
        self.tag_active = [False]*256
        self.tag_release = Event()

        self.downstream_tag_recv_queues = {}

        self.rx_cpl_queues = [Queue() for k in range(256)]
        self.rx_cpl_sync = [Event() for k in range(256)]

        self.rx_tlp_handler = {}

        self.upstream_bridge.upstream_tx_handler = self.downstream_recv

        self.tree = TreeItem()

        self.io_base = 0x8000_0000
        self.io_limit = self.io_base
        self.mem_base = 0xc000_0000
        self.mem_limit = self.mem_base
        self.prefetchable_mem_base = 0x8000_0000_0000_0000
        self.prefetchable_mem_limit = self.prefetchable_mem_base

        self.upstream_bridge.io_base = self.io_base
        self.upstream_bridge.io_limit = self.io_limit
        self.upstream_bridge.mem_base = self.mem_base
        self.upstream_bridge.mem_limit = self.mem_limit
        self.upstream_bridge.prefetchable_mem_base = self.prefetchable_mem_base
        self.upstream_bridge.prefetchable_mem_limit = self.prefetchable_mem_limit

        self.max_payload_size = 0
        self.max_read_request_size = 2
        self.read_completion_boundary = 128
        self.extended_tag_field_enable = True
        self.bus_master_enable = True

        self.mem_address_space = mem_address_space or AddressSpace(2**64)
        self.io_address_space = io_address_space or AddressSpace(2**32)

        self.mem_region = MemoryTlpRegion(self)
        self.io_region = IoTlpRegion(self)

        self.mem_address_space.register_region(self.mem_region,
                self.mem_base, self.mem_base & -self.mem_base, offset=None)
        self.mem_address_space.register_region(self.mem_region,
                self.prefetchable_mem_base, self.prefetchable_mem_base & -self.prefetchable_mem_base, offset=None)
        self.io_address_space.register_region(self.io_region,
                self.io_base, self.io_base & -self.io_base, offset=None)

        self.mem_pool = self.mem_address_space.create_pool(0x0000_0000, 0x8000_0000)
        self.io_pool = self.io_address_space.create_pool(0x0000_0000, 0x8000_0000)

        self.region_base = 0
        self.region_limit = self.region_base

        self.io_region_base = 0
        self.io_region_limit = self.io_region_base

        self.regions = []
        self.io_regions = []

        self.msi_region = MsiRegion(self)

        self.mem_address_space.register_region(self.msi_region, 0x8000_0000)

        self.msi_addr = None
        self.msi_msg_limit = 0
        self.msi_events = {}
        self.msi_callbacks = {}

        self.register_rx_tlp_handler(TlpType.IO_READ, self.handle_io_read_tlp)
        self.register_rx_tlp_handler(TlpType.IO_WRITE, self.handle_io_write_tlp)
        self.register_rx_tlp_handler(TlpType.MEM_READ, self.handle_mem_read_tlp)
        self.register_rx_tlp_handler(TlpType.MEM_READ_64, self.handle_mem_read_tlp)
        self.register_rx_tlp_handler(TlpType.MEM_WRITE, self.handle_mem_write_tlp)
        self.register_rx_tlp_handler(TlpType.MEM_WRITE_64, self.handle_mem_write_tlp)

    def alloc_region(self, size):
        region = self.mem_pool.alloc_region(size)
        return region.get_absolute_address(0), region.mem

    def alloc_io_region(self, size):
        region = self.io_pool.alloc_region(size)
        return region.get_absolute_address(0), region.mem

    async def read_region(self, addr, length):
        return await self.mem_region.read(addr, length)

    async def write_region(self, addr, data):
        await self.mem_region.write(addr, data)

    async def read_io_region(self, addr, length):
        return await self.io_region.read(addr, length)

    async def write_io_region(self, addr, data):
        await self.io_region.write(addr, data)

    async def downstream_send(self, tlp):
        self.log.debug("Sending TLP: %r", tlp)
        assert tlp.check()
        await self.upstream_bridge.upstream_recv(tlp)

    async def send(self, tlp):
        await self.downstream_send(tlp)

    async def downstream_recv(self, tlp):
        self.log.debug("Got TLP: %r", tlp)
        assert tlp.check()
        await self.handle_tlp(tlp)

    async def handle_tlp(self, tlp):
        if tlp.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
            self.rx_cpl_queues[tlp.tag].put_nowait(tlp)
            self.rx_cpl_sync[tlp.tag].set()
        elif tlp.fmt_type in self.rx_tlp_handler:
            tlp.release_fc()
            await self.rx_tlp_handler[tlp.fmt_type](tlp)
        else:
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

    async def handle_io_read_tlp(self, tlp):
        self.log.info("IO read, address 0x%08x, BE 0x%x, tag %d",
                tlp.address, tlp.first_be, tlp.tag)

        if not self.io_address_space.find_regions(tlp.address, tlp.length*4):
            self.log.warning("IO request did not match any regions: %r", tlp)

            # Unsupported request
            cpl = Tlp.create_ur_completion_for_tlp(tlp, PcieId(0, 0, 0))
            self.log.debug("UR Completion: %r", cpl)
            await self.send(cpl)
            return

        assert tlp.length == 1

        # prepare completion TLP
        cpl = Tlp.create_completion_data_for_tlp(tlp, PcieId(0, 0, 0))

        addr = tlp.address
        offset = 0
        start_offset = None
        mask = tlp.first_be

        # generate operation list
        read_ops = []

        data = bytearray(4)

        for k in range(4):
            if mask & (1 << k):
                if start_offset is None:
                    start_offset = offset
            else:
                if start_offset is not None and offset != start_offset:
                    read_ops.append((start_offset, addr+start_offset, offset-start_offset))
                start_offset = None

            offset += 1

        if start_offset is not None and offset != start_offset:
            read_ops.append((start_offset, addr+start_offset, offset-start_offset))

        # perform reads
        try:
            for offset, addr, length in read_ops:
                data[offset:offset+length] = await self.io_address_space.read(addr, length)
        except Exception:
            self.log.warning("IO read operation failed: %r", tlp)

            # Completer abort
            cpl = Tlp.create_ca_completion_for_tlp(tlp, PcieId(0, 0, 0))
            self.log.debug("CA Completion: %r", cpl)
            await self.send(cpl)
            return

        cpl.set_data(data)
        cpl.byte_count = 4
        cpl.length = 1

        self.log.debug("Completion: %r", cpl)
        await self.send(cpl)

    async def handle_io_write_tlp(self, tlp):
        self.log.info("IO write, address 0x%08x, BE 0x%x, tag %d, data 0x%08x",
                tlp.address, tlp.first_be, tlp.tag, int.from_bytes(tlp.get_data(), 'little'))

        if not self.io_address_space.find_regions(tlp.address, tlp.length*4):
            self.log.warning("IO request did not match any regions: %r", tlp)

            # Unsupported request
            cpl = Tlp.create_ur_completion_for_tlp(tlp, PcieId(0, 0, 0))
            self.log.debug("UR Completion: %r", cpl)
            await self.send(cpl)
            return

        assert tlp.length == 1

        # prepare completion TLP
        cpl = Tlp.create_completion_for_tlp(tlp, PcieId(0, 0, 0))

        addr = tlp.address
        offset = 0
        start_offset = None
        mask = tlp.first_be

        # generate operation list
        write_ops = []

        data = tlp.get_data()

        for k in range(4):
            if mask & (1 << k):
                if start_offset is None:
                    start_offset = offset
            else:
                if start_offset is not None and offset != start_offset:
                    write_ops.append((addr+start_offset, data[start_offset:offset]))
                start_offset = None

            offset += 1

        if start_offset is not None and offset != start_offset:
            write_ops.append((addr+start_offset, data[start_offset:offset]))

        # perform writes
        try:
            for addr, data in write_ops:
                await self.io_address_space.write(addr, data)
        except Exception:
            self.log.warning("IO write operation failed: %r", tlp)

            # Completer abort
            cpl = Tlp.create_ca_completion_for_tlp(tlp, PcieId(0, 0, 0))
            self.log.debug("CA Completion: %r", cpl)
            await self.send(cpl)
            return

        cpl.byte_count = 4

        self.log.debug("Completion: %r", cpl)
        await self.send(cpl)

    async def handle_mem_read_tlp(self, tlp):
        self.log.info("Memory read, address 0x%08x, length %d, BE 0x%x/0x%x, tag %d",
                tlp.address, tlp.length, tlp.first_be, tlp.last_be, tlp.tag)

        if not self.mem_address_space.find_regions(tlp.address, tlp.length*4):
            self.log.warning("Memory request did not match any regions: %r", tlp)

            # Unsupported request
            cpl = Tlp.create_ur_completion_for_tlp(tlp, PcieId(0, 0, 0))
            self.log.debug("UR Completion: %r", cpl)
            await self.send(cpl)
            return

        # perform operation
        addr = tlp.address

        # check for 4k boundary crossing
        if tlp.length*4 > 0x1000 - (addr & 0xfff):
            self.log.warning("Request crossed 4k boundary, discarding request")
            return

        # perform read
        try:
            data = await self.mem_address_space.read(addr, tlp.length*4)
        except Exception:
            self.log.warning("Memory read operation failed: %r", tlp)

            # Completer abort
            cpl = Tlp.create_ca_completion_for_tlp(tlp, PcieId(0, 0, 0))
            self.log.debug("CA Completion: %r", cpl)
            await self.send(cpl)
            return

        # prepare completion TLP(s)
        m = 0
        n = 0
        addr = tlp.address+tlp.get_first_be_offset()
        dw_length = tlp.length
        byte_length = tlp.get_be_byte_count()

        while m < dw_length:
            cpl = Tlp.create_completion_data_for_tlp(tlp, PcieId(0, 0, 0))

            cpl_dw_length = dw_length - m
            cpl_byte_length = byte_length - n
            cpl.byte_count = cpl_byte_length
            if cpl_dw_length > 32 << self.max_payload_size:
                cpl_dw_length = 32 << self.max_payload_size  # max payload size
                cpl_dw_length -= (addr & 0x7c) >> 2  # RCB align

            cpl.lower_address = addr & 0x7f

            cpl.set_data(data[m*4:(m+cpl_dw_length)*4])

            self.log.debug("Completion: %r", cpl)
            await self.send(cpl)

            m += cpl_dw_length
            n += cpl_dw_length*4 - (addr & 3)
            addr += cpl_dw_length*4 - (addr & 3)

    async def handle_mem_write_tlp(self, tlp):
        self.log.info("Memory write, address 0x%08x, length %d, BE 0x%x/0x%x",
                tlp.address, tlp.length, tlp.first_be, tlp.last_be)

        if not self.mem_address_space.find_regions(tlp.address, tlp.length*4):
            self.log.warning("Memory request did not match any regions: %r", tlp)
            return

        # perform operation
        addr = tlp.address
        offset = 0
        start_offset = None
        mask = tlp.first_be

        # check for 4k boundary crossing
        if tlp.length*4 > 0x1000 - (addr & 0xfff):
            self.log.warning("Request crossed 4k boundary, discarding request")
            return

        # generate operation list
        write_ops = []

        data = tlp.get_data()

        # first dword
        for k in range(4):
            if mask & (1 << k):
                if start_offset is None:
                    start_offset = offset
            else:
                if start_offset is not None and offset != start_offset:
                    write_ops.append((addr+start_offset, data[start_offset:offset]))
                start_offset = None

            offset += 1

        if tlp.length > 2:
            # middle dwords
            if start_offset is None:
                start_offset = offset
            offset += (tlp.length-2)*4

        if tlp.length > 1:
            # last dword
            mask = tlp.last_be

            for k in range(4):
                if mask & (1 << k):
                    if start_offset is None:
                        start_offset = offset
                else:
                    if start_offset is not None and offset != start_offset:
                        write_ops.append((addr+start_offset, data[start_offset:offset]))
                    start_offset = None

                offset += 1

        if start_offset is not None and offset != start_offset:
            write_ops.append((addr+start_offset, data[start_offset:offset]))

        # perform writes
        try:
            for addr, data in write_ops:
                await self.mem_address_space.write(addr, data)
        except Exception:
            self.log.warning("Memory write operation failed: %r", tlp)
            return

        # memory writes are posted, so don't send a completion

    async def config_read(self, dev, addr, length, timeout=0, timeout_unit='ns'):
        n = 0
        data = b''

        while True:
            tlp = Tlp()
            tlp.fmt_type = TlpType.CFG_READ_1
            tlp.requester_id = PcieId(0, 0, 0)
            tlp.dest_id = dev

            first_pad = addr % 4
            byte_length = min(length-n, 4-first_pad)
            tlp.set_addr_be(addr, byte_length)

            tlp.register_number = addr >> 2

            tlp.tag = await self.alloc_tag()

            await self.send(tlp)
            cpl = await self.recv_cpl(tlp.tag, timeout, timeout_unit)

            self.release_tag(tlp.tag)

            if not cpl or cpl.status != CplStatus.SC:
                d = b'\xff\xff\xff\xff'
            else:
                assert cpl.length == 1
                d = cpl.get_data()

            data += d[first_pad:]

            n += byte_length
            addr += byte_length

            if n >= length:
                break

        return data[:length]

    async def config_read_words(self, dev, addr, count, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        data = await self.config_read(dev, addr, count*ws, timeout, timeout_unit)
        words = []
        for k in range(count):
            words.append(int.from_bytes(data[ws*k:ws*(k+1)], byteorder))
        return words

    async def config_read_dwords(self, dev, addr, count, byteorder='little', timeout=0, timeout_unit='ns'):
        return await self.config_read_words(dev, addr, count, byteorder, 4, timeout, timeout_unit)

    async def config_read_qwords(self, dev, addr, count, byteorder='little', timeout=0, timeout_unit='ns'):
        return await self.config_read_words(dev, addr, count, byteorder, 8, timeout, timeout_unit)

    async def config_read_byte(self, dev, addr, timeout=0, timeout_unit='ns'):
        return (await self.config_read(dev, addr, 1, timeout, timeout_unit))[0]

    async def config_read_word(self, dev, addr, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        return (await self.config_read_words(dev, addr, 1, byteorder, ws, timeout, timeout_unit))[0]

    async def config_read_dword(self, dev, addr, byteorder='little', timeout=0, timeout_unit='ns'):
        return (await self.config_read_dwords(dev, addr, 1, byteorder, timeout, timeout_unit))[0]

    async def config_read_qword(self, dev, addr, byteorder='little', timeout=0, timeout_unit='ns'):
        return (await self.config_read_qwords(dev, addr, 1, byteorder, timeout, timeout_unit))[0]

    async def config_write(self, dev, addr, data, timeout=0, timeout_unit='ns'):
        n = 0

        while True:
            tlp = Tlp()
            tlp.fmt_type = TlpType.CFG_WRITE_1
            tlp.requester_id = PcieId(0, 0, 0)
            tlp.dest_id = dev

            first_pad = addr % 4
            byte_length = min(len(data)-n, 4-first_pad)
            tlp.set_addr_be_data(addr, data[n:n+byte_length])

            tlp.register_number = addr >> 2

            tlp.tag = await self.alloc_tag()

            await self.send(tlp)
            await self.recv_cpl(tlp.tag, timeout, timeout_unit)

            self.release_tag(tlp.tag)

            n += byte_length
            addr += byte_length

            if n >= len(data):
                break

    async def config_write_words(self, dev, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        words = data
        data = bytearray()
        for w in words:
            data.extend(w.to_bytes(ws, byteorder))
        await self.config_write(dev, addr, data, timeout, timeout_unit)

    async def config_write_dwords(self, dev, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.config_write_words(dev, addr, data, byteorder, 4, timeout, timeout_unit)

    async def config_write_qwords(self, dev, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.config_write_words(dev, addr, data, byteorder, 8, timeout, timeout_unit)

    async def config_write_byte(self, dev, addr, data, timeout=0, timeout_unit='ns'):
        await self.config_write(dev, addr, [data], timeout, timeout_unit)

    async def config_write_word(self, dev, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        await self.config_write_words(dev, addr, [data], byteorder, ws, timeout, timeout_unit)

    async def config_write_dword(self, dev, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.config_write_dwords(dev, addr, [data], byteorder, timeout, timeout_unit)

    async def config_write_qword(self, dev, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.config_write_qwords(dev, addr, [data], byteorder, timeout, timeout_unit)

    async def capability_read(self, dev, cap_id, addr, length, timeout=0, timeout_unit='ns'):
        ti = self.tree.find_child_dev(dev)

        if not ti:
            raise Exception("Device not found")

        offset = ti.get_capability_offset(cap_id)

        if not offset:
            raise Exception("Capability not found")

        return await self.config_read(dev, addr+offset, length, timeout, timeout_unit)

    async def capability_read_words(self, dev, cap_id, addr, count, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        data = await self.capability_read(dev, cap_id, addr, count*ws, timeout, timeout_unit)
        words = []
        for k in range(count):
            words.append(int.from_bytes(data[ws*k:ws*(k+1)], byteorder))
        return words

    async def capability_read_dwords(self, dev, cap_id, addr, count, byteorder='little', timeout=0, timeout_unit='ns'):
        return await self.capability_read_words(dev, cap_id, addr, count, byteorder, 4, timeout, timeout_unit)

    async def capability_read_qwords(self, dev, cap_id, addr, count, byteorder='little', timeout=0, timeout_unit='ns'):
        return await self.capability_read_words(dev, cap_id, addr, count, byteorder, 8, timeout, timeout_unit)

    async def capability_read_byte(self, dev, cap_id, addr, timeout=0, timeout_unit='ns'):
        return (await self.capability_read(dev, cap_id, addr, 1, timeout, timeout_unit))[0]

    async def capability_read_word(self, dev, cap_id, addr, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        return (await self.capability_read_words(dev, cap_id, addr, 1, byteorder, ws, timeout, timeout_unit))[0]

    async def capability_read_dword(self, dev, cap_id, addr, byteorder='little', timeout=0, timeout_unit='ns'):
        return (await self.capability_read_dwords(dev, cap_id, addr, 1, byteorder, timeout, timeout_unit))[0]

    async def capability_read_qword(self, dev, cap_id, addr, byteorder='little', timeout=0, timeout_unit='ns'):
        return (await self.capability_read_qwords(dev, cap_id, addr, 1, byteorder, timeout, timeout_unit))[0]

    async def capability_write(self, dev, cap_id, addr, data, timeout=0, timeout_unit='ns'):
        ti = self.tree.find_child_dev(dev)

        if not ti:
            raise Exception("Device not found")

        offset = ti.get_capability_offset(cap_id)

        if not offset:
            raise Exception("Capability not found")

        await self.config_write(dev, addr+offset, data, timeout, timeout_unit)

    async def capability_write_words(self, dev, cap_id, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        words = data
        data = bytearray()
        for w in words:
            data.extend(w.to_bytes(ws, byteorder))
        await self.capability_write(dev, cap_id, addr, data, timeout, timeout_unit)

    async def capability_write_dwords(self, dev, cap_id, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.capability_write_words(dev, cap_id, addr, data, byteorder, 4, timeout, timeout_unit)

    async def capability_write_qwords(self, dev, cap_id, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.capability_write_words(dev, cap_id, addr, data, byteorder, 8, timeout, timeout_unit)

    async def capability_write_byte(self, dev, cap_id, addr, data, timeout=0, timeout_unit='ns'):
        await self.capability_write(dev, cap_id, addr, [data], timeout, timeout_unit)

    async def capability_write_word(self, dev, cap_id, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        await self.capability_write_words(dev, cap_id, addr, [data], byteorder, ws, timeout, timeout_unit)

    async def capability_write_dword(self, dev, cap_id, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.capability_write_dwords(dev, cap_id, addr, [data], byteorder, timeout, timeout_unit)

    async def capability_write_qword(self, dev, cap_id, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.capability_write_qwords(dev, cap_id, addr, [data], byteorder, timeout, timeout_unit)

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

    async def configure_msi(self, dev):
        await self.msi_region.configure_msi(dev)

    def msi_get_event(self, dev, number=0):
        return self.msi_region.get_event(dev, number)

    def msi_register_callback(self, dev, callback, number=0):
        self.msi_region.register_callback(dev, callback, number)

    async def enumerate_segment(self, tree, bus, timeout=1000, timeout_unit='ns',
            enable_bus_mastering=False, configure_msi=False):
        sec_bus = bus+1
        sub_bus = bus

        tree.sec_bus_num = bus

        # align limits against bridge registers
        self.io_limit = align(self.io_limit, 0xfff)
        self.mem_limit = align(self.mem_limit, 0xfffff)
        self.prefetchable_mem_limit = align(self.prefetchable_mem_limit, 0xfffff)

        tree.io_base = self.io_limit
        tree.io_limit = self.io_limit
        tree.mem_base = self.mem_limit
        tree.mem_limit = self.mem_limit
        tree.prefetchable_mem_base = self.prefetchable_mem_limit
        tree.prefetchable_mem_limit = self.prefetchable_mem_limit

        self.log.info("Enumerating bus %d", bus)

        for d in range(32):
            if bus == 0 and d == 0:
                continue

            self.log.info("Enumerating bus %d device %d", bus, d)

            # read vendor ID and device ID
            val = await self.config_read_dword(PcieId(bus, d, 0), 0x000, 'little', timeout, timeout_unit)

            if val is None or val == 0xffffffff:
                continue

            # valid vendor ID
            self.log.info("Found device at %02x:%02x.%x", bus, d, 0)

            for f in range(8):
                cur_func = PcieId(bus, d, f)

                # read vendor ID and device ID
                val = await self.config_read_dword(cur_func, 0x000, 'little', timeout, timeout_unit)

                if val is None or val == 0xffffffff:
                    continue

                ti = TreeItem()
                tree.children.append(ti)
                ti.pcie_id = cur_func
                ti.vendor_id = val & 0xffff
                ti.device_id = (val >> 16) & 0xffff

                # read header type
                header_type = await self.config_read_byte(cur_func, 0x00e, timeout, timeout_unit)
                ti.header_type = header_type

                val = await self.config_read_dword(cur_func, 0x008, 'little', timeout, timeout_unit)

                ti.revision_id = val & 0xff
                ti.class_code = val >> 8

                self.log.info("Found function at %s", cur_func)
                self.log.info("Header type: 0x%02x", header_type)
                self.log.info("Vendor ID: 0x%04x", ti.vendor_id)
                self.log.info("Device ID: 0x%04x", ti.device_id)
                self.log.info("Revision ID: 0x%02x", ti.revision_id)
                self.log.info("Class code: 0x%06x", ti.class_code)

                bridge = header_type & 0x7f == 0x01

                bar_cnt = 6

                if bridge:
                    # bridge (type 1 header)
                    self.log.info("Found bridge at %s", cur_func)

                    bar_cnt = 2
                else:
                    # normal function (type 0 header)
                    val = await self.config_read_dword(cur_func, 0x02c)
                    ti.subsystem_vendor_id = val & 0xffff
                    ti.subsystem_id = (val >> 16) & 0xffff

                    self.log.info("Subsystem vendor ID: 0x%04x", ti.subsystem_vendor_id)
                    self.log.info("Subsystem ID: 0x%04x", ti.subsystem_id)

                # configure base address registers
                bar = 0
                while bar < bar_cnt:
                    # read BAR
                    await self.config_write_dword(cur_func, 0x010+bar*4, 0xffffffff)
                    val = await self.config_read_dword(cur_func, 0x010+bar*4)

                    if val == 0:
                        # unimplemented BAR
                        ti.bar_raw[bar] = 0
                        bar += 1
                        continue

                    self.log.info("Configure function %s BAR%d", cur_func, bar)

                    if val & 0x1:
                        # IO BAR
                        mask = (~val & 0xffffffff) | 0x3
                        size = mask + 1
                        self.log.info("Function %s IO BAR%d raw: 0x%08x, mask: 0x%08x, size: %d",
                            cur_func, bar, val, mask, size)

                        # align
                        self.io_limit = align(self.io_limit, mask)

                        addr = self.io_limit
                        self.io_limit += size

                        val = val & 0x3 | addr

                        ti.bar[bar] = val
                        ti.bar_raw[bar] = val
                        ti.bar_addr[bar] = addr
                        ti.bar_size[bar] = size
                        ti.bar_window[bar] = self.io_address_space.create_window(addr, size)

                        self.log.info("Function %s IO BAR%d allocation: 0x%08x, raw: 0x%08x, size: %d",
                            cur_func, bar, addr, val, size)

                        # write BAR
                        await self.config_write_dword(cur_func, 0x010+bar*4, val)

                        bar += 1

                    elif val & 0x4:
                        # 64 bit memory BAR
                        if bar >= bar_cnt-1:
                            raise Exception("Invalid BAR configuration")

                        # read adjacent BAR
                        await self.config_write_dword(cur_func, 0x010+(bar+1)*4, 0xffffffff)
                        val2 = await self.config_read_dword(cur_func, 0x010+(bar+1)*4)
                        val |= val2 << 32
                        mask = (~val & 0xffffffffffffffff) | 0xf
                        size = mask + 1
                        self.log.info("Function %s Mem BAR%d (64-bit) raw: 0x%016x, mask: 0x%016x, size: %d",
                            cur_func, bar, val, mask, size)

                        if val & 0x8:
                            # prefetchable
                            # align and allocate
                            self.prefetchable_mem_limit = align(self.prefetchable_mem_limit, mask)
                            addr = self.prefetchable_mem_limit
                            self.prefetchable_mem_limit += size

                        else:
                            # not-prefetchable
                            self.log.info("Function %s Mem BAR%d (64-bit) marked non-prefetchable, "
                                "allocating from 32-bit non-prefetchable address space", cur_func, bar)
                            # align and allocate
                            self.mem_limit = align(self.mem_limit, mask)
                            addr = self.mem_limit
                            self.mem_limit += size

                        val = val & 0xf | addr

                        ti.bar[bar] = val
                        ti.bar_raw[bar] = val & 0xffffffff
                        ti.bar_raw[bar+1] = (val >> 32) & 0xffffffff
                        ti.bar_addr[bar] = addr
                        ti.bar_size[bar] = size
                        ti.bar_window[bar] = self.mem_address_space.create_window(addr, size)

                        self.log.info("Function %s Mem BAR%d (64-bit) allocation: 0x%016x, raw: 0x%016x, size: %d",
                            cur_func, bar, addr, val, size)

                        # write BAR
                        await self.config_write_dword(cur_func, 0x010+bar*4, val & 0xffffffff)
                        await self.config_write_dword(cur_func, 0x010+(bar+1)*4, (val >> 32) & 0xffffffff)

                        bar += 2

                    else:
                        # 32 bit memory BAR
                        mask = (~val & 0xffffffff) | 0xf
                        size = mask + 1
                        self.log.info("Function %s Mem BAR%d (32-bit) raw: 0x%08x, mask: 0x%08x, size: %d",
                            cur_func, bar, val, mask, size)

                        if val & 0x8:
                            # prefetchable
                            self.log.info("Function %s Mem BAR%d (32-bit) marked prefetchable, "
                                "but allocating as non-prefetchable", cur_func, bar)

                        # align and allocate
                        self.mem_limit = align(self.mem_limit, mask)
                        addr = self.mem_limit
                        self.mem_limit += size

                        val = val & 0xf | addr

                        ti.bar[bar] = val
                        ti.bar_raw[bar] = val
                        ti.bar_addr[bar] = addr
                        ti.bar_size[bar] = size
                        ti.bar_window[bar] = self.mem_address_space.create_window(addr, size)

                        self.log.info("Function %s Mem BAR%d (32-bit) allocation: 0x%08x, raw: 0x%08x, size: %d",
                            cur_func, bar, addr, val, size)

                        # write BAR
                        await self.config_write_dword(cur_func, 0x010+bar*4, val)

                        bar += 1

                # configure expansion ROM

                # read register
                await self.config_write_dword(cur_func, 0x038 if bridge else 0x30, 0xfffff800)
                val = await self.config_read_dword(cur_func, 0x038 if bridge else 0x30)

                if val:
                    self.log.info("Configure function %s expansion ROM", cur_func)

                    mask = (~val & 0xffffffff) | 0x7ff
                    size = mask + 1
                    self.log.info("Function %s expansion ROM raw: 0x%08x, mask: 0x%08x, size: %d",
                        cur_func, val, mask, size)

                    # align and allocate
                    self.mem_limit = align(self.mem_limit, mask)
                    addr = self.mem_limit
                    self.mem_limit += size

                    val = val & 15 | addr

                    ti.expansion_rom_raw = val
                    ti.expansion_rom_addr = addr
                    ti.expansion_rom_size = size

                    self.log.info("Function %s expansion ROM allocation: 0x%08x, raw: 0x%08x, size: %d",
                        cur_func, addr, val, size)

                    # write register
                    await self.config_write_dword(cur_func, 0x038 if bridge else 0x30, val)
                else:
                    # not implemented
                    ti.expansion_rom_raw = 0

                self.log.info("Walk capabilities of function %s", cur_func)

                # walk capabilities
                ptr = await self.config_read_byte(cur_func, 0x34)
                ptr = ptr & 0xfc

                while ptr > 0:
                    val = await self.config_read(cur_func, ptr, 2)

                    cap_id = val[0]
                    next_ptr = val[1] & 0xfc

                    self.log.info("Found capability ID 0x%02x at offset 0x%02x, next ptr 0x%02x",
                        cap_id, ptr, next_ptr)

                    ti.capabilities.append((cap_id, ptr))
                    ptr = next_ptr

                # walk extended capabilities
                ptr = 0x100

                while True:
                    val = await self.config_read_dword(cur_func, ptr)
                    if not val:
                        break

                    cap_id = val & 0xffff
                    cap_ver = (val >> 16) & 0xf
                    next_ptr = (val >> 20) & 0xffc

                    self.log.info("Found extended capability ID 0x%04x version %d at offset 0x%03x, next ptr 0x%03x",
                        cap_id, cap_ver, ptr, next_ptr)

                    ti.ext_capabilities.append((cap_id, ptr))
                    ptr = next_ptr

                # set max payload size, max read request size, and extended tag enable
                dev_cap = await self.capability_read_dword(cur_func, PcieCapId.EXP, 4)
                dev_ctrl_sta = await self.capability_read_dword(cur_func, PcieCapId.EXP, 8)

                max_payload = min(0x5, min(self.max_payload_size, dev_cap & 7))
                ext_tag = bool(self.extended_tag_field_enable and (dev_cap & (1 << 5)))
                max_read_req = min(0x5, self.max_read_request_size)

                new_dev_ctrl = (dev_ctrl_sta & 0x00008e1f) | (max_payload << 5) | (ext_tag << 8) | (max_read_req << 12)

                await self.capability_write_dword(cur_func, PcieCapId.EXP, 8, new_dev_ctrl)

                # configure command register
                val = await self.config_read_word(cur_func, 0x04)

                # enable IO and memory space
                val |= (1 << 0) | (1 << 1)

                if enable_bus_mastering:
                    # enable bus mastering
                    val |= 1 << 2

                await self.config_write_word(cur_func, 0x04, val | 4)

                if configure_msi:
                    # configure MSI
                    try:
                        await self.configure_msi(cur_func)
                    except Exception:
                        pass

                if bridge:
                    # set bridge registers for enumeration
                    self.log.info("Configure bridge registers for enumeration")
                    self.log.info("Set pri %d, sec %d, sub %d", bus, sec_bus, 255)

                    ti.pri_bus_num = bus
                    ti.sec_bus_num = sec_bus

                    await self.config_write(cur_func, 0x018, bytearray([bus, sec_bus, 255]))

                    # enumerate secondary bus
                    self.log.info("Enumerate secondary bus")
                    sub_bus = await self.enumerate_segment(tree=ti, bus=sec_bus, timeout=timeout,
                        enable_bus_mastering=enable_bus_mastering, configure_msi=configure_msi)

                    # finalize bridge configuration
                    self.log.info("Finalize bridge configuration")
                    self.log.info("Set pri %d, sec %d, sub %d", bus, sec_bus, sub_bus)

                    ti.pri_bus_num = bus
                    ti.sec_bus_num = sec_bus
                    ti.sub_bus_num = sub_bus

                    await self.config_write(cur_func, 0x018, bytearray([bus, sec_bus, sub_bus]))

                    # set base/limit registers
                    self.log.info("Set IO base: 0x%08x, limit: 0x%08x", ti.io_base, ti.io_limit)

                    await self.config_write(cur_func, 0x01C, struct.pack('BB',
                        (ti.io_base >> 8) & 0xf0, (ti.io_limit >> 8) & 0xf0))
                    await self.config_write(cur_func, 0x030, struct.pack('<HH', ti.io_base >> 16, ti.io_limit >> 16))

                    self.log.info("Set mem base: 0x%08x, limit: 0x%08x", ti.mem_base, ti.mem_limit)

                    await self.config_write(cur_func, 0x020, struct.pack('<HH',
                        (ti.mem_base >> 16) & 0xfff0, (ti.mem_limit >> 16) & 0xfff0))

                    self.log.info("Set prefetchable mem base: 0x%016x, limit: 0x%016x",
                        ti.prefetchable_mem_base, ti.prefetchable_mem_limit)

                    await self.config_write(cur_func, 0x024, struct.pack('<HH',
                        (ti.prefetchable_mem_base >> 16) & 0xfff0, (ti.prefetchable_mem_limit >> 16) & 0xfff0))
                    await self.config_write(cur_func, 0x028, struct.pack('<L', ti.prefetchable_mem_base >> 32))
                    await self.config_write(cur_func, 0x02c, struct.pack('<L', ti.prefetchable_mem_limit >> 32))

                    sec_bus = sub_bus+1

                if header_type & 0x80 == 0:
                    # only one function
                    break

        tree.sub_bus_num = sub_bus

        # align limits against bridge registers
        self.io_limit = align(self.io_limit, 0xfff)
        self.mem_limit = align(self.mem_limit, 0xfffff)
        self.prefetchable_mem_limit = align(self.prefetchable_mem_limit, 0xfffff)

        tree.io_limit = self.io_limit-1
        tree.mem_limit = self.mem_limit-1
        tree.prefetchable_mem_limit = self.prefetchable_mem_limit-1

        self.log.info("Enumeration of bus %d complete", bus)

        return sub_bus

    async def enumerate(self, timeout=1000, timeout_unit='ns', enable_bus_mastering=False, configure_msi=False):
        self.log.info("Enumerating bus")

        self.io_limit = self.io_base
        self.mem_limit = self.mem_base
        self.prefetchable_mem_limit = self.prefetchable_mem_base

        self.tree = TreeItem()
        await self.enumerate_segment(tree=self.tree, bus=0, timeout=timeout, timeout_unit=timeout_unit,
            enable_bus_mastering=enable_bus_mastering, configure_msi=configure_msi)

        self.upstream_bridge.io_base = self.io_base
        self.upstream_bridge.io_limit = self.io_limit
        self.upstream_bridge.mem_base = self.mem_base
        self.upstream_bridge.mem_limit = self.mem_limit
        self.upstream_bridge.prefetchable_mem_base = self.prefetchable_mem_base
        self.upstream_bridge.prefetchable_mem_limit = self.prefetchable_mem_limit

        self.log.info("Enumeration complete")
        self.log.info("Device tree: \n%s", self.tree.to_str().strip())
