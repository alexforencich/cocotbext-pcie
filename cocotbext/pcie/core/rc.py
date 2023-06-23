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

from cocotb.queue import Queue
from cocotb.triggers import Event, Timer, First

from cocotbext.axi import AddressSpace

from .version import __version__
from .bridge import HostBridge, RootPort
from .msi import MsiRegion
from .region import MemoryTlpRegion, IoTlpRegion
from .switch import Switch
from .tlp import Tlp, TlpType, TlpAttr, TlpTc, CplStatus
from .utils import PcieId
from .pci import PciDevice, PciHostBridge


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

        self.host_bridge = PciHostBridge(rc=self)

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

        self._max_payload_size = 0
        self._max_payload_size_supported = 5
        self._max_read_request_size = 2
        self._read_completion_boundary = False
        self.bus_master_enable = True

        self.split_on_all_rcb = False

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

    @property
    def max_payload_size(self):
        return self._max_payload_size

    @max_payload_size.setter
    def max_payload_size(self, val):
        self._max_payload_size = val
        self.upstream_bridge.pcie_cap.max_payload_size = val

    @property
    def max_payload_size_supported(self):
        return self._max_payload_size_supported

    @max_payload_size_supported.setter
    def max_payload_size_supported(self, val):
        self._max_payload_size_supported = val
        self.upstream_bridge.pcie_cap.max_payload_size_supported = val

    @property
    def max_read_request_size(self):
        return self._max_read_request_size

    @max_read_request_size.setter
    def max_read_request_size(self, val):
        self._max_read_request_size = val
        self.upstream_bridge.pcie_cap.max_read_request_size = val

    @property
    def read_completion_boundary(self):
        return self._read_completion_boundary

    @read_completion_boundary.setter
    def read_completion_boundary(self, val):
        self._read_completion_boundary = val
        self.upstream_bridge.pcie_cap.read_completion_boundary = val

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
        max_payload_dw = 32 << self.max_payload_size
        rcb = 64
        if self.read_completion_boundary:
            rcb = 128
        rcb_mask = (rcb-1) & 0xfc

        while m < dw_length:
            cpl = Tlp.create_completion_data_for_tlp(tlp, PcieId(0, 0, 0))

            cpl_dw_length = dw_length - m
            cpl.byte_count = byte_length - n
            if self.split_on_all_rcb:
                # split on every RCB
                cpl_dw_length = min(cpl_dw_length, (rcb - (addr & rcb_mask)) >> 2);
            else:
                # produce largest possible TLPs
                if cpl_dw_length > max_payload_dw:
                    cpl_dw_length = max_payload_dw - ((addr & rcb_mask) >> 2)

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
        data = bytearray()

        while n < length:
            req = Tlp()
            req.fmt_type = TlpType.CFG_READ_1
            req.requester_id = PcieId(0, 0, 0)
            req.dest_id = dev

            first_pad = addr % 4
            byte_length = min(length-n, 4-first_pad)
            req.set_addr_be(addr, byte_length)

            req.register_number = addr >> 2

            cpl_list = await self.perform_nonposted_operation(req, timeout, timeout_unit)

            if not cpl_list:
                # timed out
                d = b'\xff\xff\xff\xff'
            elif cpl_list[0].status == CplStatus.CRS and req.register_number == 0 and cpl_list[0].ingress_port:
                # completion retry status
                if cpl_list[0].ingress_port.pcie_cap.crs_software_visibility_enable:
                    d = b'\x01\x00\xff\xff'
                else:
                    d = b'\xff\xff\xff\xff'
            elif cpl_list[0].status != CplStatus.SC:
                # unsupported request or completer abort status
                d = b'\xff\xff\xff\xff'
            else:
                # success
                assert cpl_list[0].length == 1
                d = cpl_list[0].get_data()

            data.extend(d[first_pad:])

            n += byte_length
            addr += byte_length

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

        while n < len(data):
            req = Tlp()
            req.fmt_type = TlpType.CFG_WRITE_1
            req.requester_id = PcieId(0, 0, 0)
            req.dest_id = dev

            first_pad = addr % 4
            byte_length = min(len(data)-n, 4-first_pad)
            req.set_addr_be_data(addr, data[n:n+byte_length])

            req.register_number = addr >> 2

            cpl_list = await self.perform_nonposted_operation(req, timeout, timeout_unit)

            n += byte_length
            addr += byte_length

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
        ti = self.host_bridge.find_child_dev(dev)

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
        ti = self.host_bridge.find_child_dev(dev)

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

    def msi_alloc_vectors(self, num):
        return self.msi_region.alloc_vectors(num)

    def find_device(self, pcie_id):
        return self.host_bridge.find_device(pcie_id)

    async def enumerate(self, timeout=1000, timeout_unit='ns'):
        self.log.info("Enumerating bus")

        self.host_bridge.max_payload_size = self.max_payload_size
        self.host_bridge.max_payload_size_supported = self.max_payload_size_supported
        self.host_bridge.max_read_request_size = self.max_read_request_size

        self.host_bridge.io_base = self.io_base
        self.host_bridge.io_limit = self.io_base
        self.host_bridge.mem_base = self.mem_base
        self.host_bridge.mem_limit = self.mem_base
        self.host_bridge.prefetchable_mem_base = self.prefetchable_mem_base
        self.host_bridge.prefetchable_mem_limit = self.prefetchable_mem_base

        await self.host_bridge.probe(timeout=timeout, timeout_unit=timeout_unit)

        self.io_base = self.host_bridge.io_base
        self.io_limit = self.host_bridge.io_limit
        self.mem_base = self.host_bridge.mem_base
        self.mem_limit = self.host_bridge.mem_limit
        self.prefetchable_mem_base = self.host_bridge.prefetchable_mem_base
        self.prefetchable_mem_limit = self.host_bridge.prefetchable_mem_limit

        self.upstream_bridge.io_base = self.io_base
        self.upstream_bridge.io_limit = self.io_limit
        self.upstream_bridge.mem_base = self.mem_base
        self.upstream_bridge.mem_limit = self.mem_limit
        self.upstream_bridge.prefetchable_mem_base = self.prefetchable_mem_base
        self.upstream_bridge.prefetchable_mem_limit = self.prefetchable_mem_limit

        self.log.info("Enumeration complete")
        self.log.info("Device tree: \n%s", self.host_bridge.to_str().strip())
