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

from cocotbext.axi import Region

from .tlp import Tlp, TlpType, TlpAttr, TlpTc, CplStatus


class MemoryTlpRegion(Region):
    def __init__(self, func, size=2**64, *kwargs):
        super().__init__(size=size, *kwargs)
        self.func = func

        if hasattr(self.func, 'pcie_cap'):
            self.cfg = self.func.pcie_cap
        else:
            self.cfg = self.func

    async def read(self, addr, length, timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        n = 0
        data = bytearray()

        if not self.func.bus_master_enable:
            raise Exception("Bus mastering not enabled")

        while n < length:
            tlp = Tlp()
            if addr > 0xffffffff:
                tlp.fmt_type = TlpType.MEM_READ_64
            else:
                tlp.fmt_type = TlpType.MEM_READ
            tlp.requester_id = self.func.pcie_id
            tlp.attr = attr
            tlp.tc = tc

            first_pad = addr % 4
            # remaining length
            byte_length = length-n
            # limit to max read request size
            if byte_length > (128 << self.cfg.max_read_request_size) - first_pad:
                # split on 128-byte read completion boundary
                byte_length = min(byte_length, (128 << self.cfg.max_read_request_size) - (addr & 0x7f))
            # 4k align
            byte_length = min(byte_length, 0x1000 - (addr & 0xfff))
            tlp.set_addr_be(addr, byte_length)

            tlp.tag = await self.func.alloc_tag()

            await self.func.send(tlp)

            m = 0

            while m < byte_length:
                cpl = await self.func.recv_cpl(tlp.tag, timeout, timeout_unit)

                if not cpl:
                    self.func.release_tag(tlp.tag)
                    raise Exception("Timeout")
                if cpl.status != CplStatus.SC:
                    self.func.release_tag(tlp.tag)
                    raise Exception("Unsuccessful completion")

                assert cpl.byte_count+3+(cpl.lower_address & 3) >= cpl.length*4
                assert cpl.byte_count == max(byte_length - m, 1)

                d = cpl.get_data()

                offset = cpl.lower_address & 3
                data.extend(d[offset:offset+cpl.byte_count])

                m += len(d)-offset

            self.func.release_tag(tlp.tag)

            n += byte_length
            addr += byte_length

        return bytes(data[:length])

    async def write(self, addr, data, timeout=0, timeout_unit='ns', attr=TlpAttr(0), tc=TlpTc.TC0):
        n = 0

        if not self.func.bus_master_enable:
            raise Exception("Bus mastering not enabled")

        while n < len(data):
            tlp = Tlp()
            if addr > 0xffffffff:
                tlp.fmt_type = TlpType.MEM_WRITE_64
            else:
                tlp.fmt_type = TlpType.MEM_WRITE
            tlp.requester_id = self.func.pcie_id
            tlp.attr = attr
            tlp.tc = tc

            first_pad = addr % 4
            byte_length = len(data)-n
            byte_length = min(byte_length, (128 << self.cfg.max_payload_size)-first_pad)  # max payload size
            byte_length = min(byte_length, 0x1000 - (addr & 0xfff))  # 4k align
            tlp.set_addr_be_data(addr, data[n:n+byte_length])

            await self.func.send(tlp)

            n += byte_length
            addr += byte_length


class IoTlpRegion(Region):
    def __init__(self, func, size=2**32, *kwargs):
        super().__init__(size=size, *kwargs)
        self.func = func

    async def read(self, addr, length, timeout=0, timeout_unit='ns'):
        n = 0
        data = b''

        if not self.func.bus_master_enable:
            raise Exception("Bus mastering not enabled")

        while n < length:
            tlp = Tlp()
            tlp.fmt_type = TlpType.IO_READ
            tlp.requester_id = self.func.pcie_id

            first_pad = addr % 4
            byte_length = min(length-n, 4-first_pad)
            tlp.set_addr_be(addr, byte_length)

            tlp.tag = await self.func.alloc_tag()

            await self.func.send(tlp)
            cpl = await self.func.recv_cpl(tlp.tag, timeout, timeout_unit)

            self.func.release_tag(tlp.tag)

            if not cpl:
                raise Exception("Timeout")
            if cpl.status != CplStatus.SC:
                raise Exception("Unsuccessful completion")

            assert cpl.length == 1
            d = cpl.get_data()

            data += d[first_pad:]

            n += byte_length
            addr += byte_length

        return data[:length]

    async def write(self, addr, data, timeout=0, timeout_unit='ns'):
        n = 0

        if not self.func.bus_master_enable:
            raise Exception("Bus mastering not enabled")

        while n < len(data):
            tlp = Tlp()
            tlp.fmt_type = TlpType.IO_WRITE
            tlp.requester_id = self.func.pcie_id

            first_pad = addr % 4
            byte_length = min(len(data)-n, 4-first_pad)
            tlp.set_addr_be_data(addr, data[n:n+byte_length])

            tlp.tag = await self.func.alloc_tag()

            await self.func.send(tlp)
            cpl = await self.func.recv_cpl(tlp.tag, timeout, timeout_unit)

            self.func.release_tag(tlp.tag)

            if not cpl:
                raise Exception("Timeout")
            if cpl.status != CplStatus.SC:
                raise Exception("Unsuccessful completion")

            n += byte_length
            addr += byte_length
