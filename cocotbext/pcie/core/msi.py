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

import struct

import cocotb
from cocotb.triggers import Event

from cocotbext.axi import Region

from .caps import PcieCapId


class MsiRegion(Region):
    def __init__(self, rc, size=16, *kwargs):
        super().__init__(size=size, *kwargs)
        self.rc = rc

        self.msi_msg_limit = 0
        self.msi_events = {}
        self.msi_callbacks = {}

    async def read(self, addr, length, **kwargs):
        return bytearray(1)*length

    async def write(self, addr, data, **kwargs):
        assert addr == 0
        assert len(data) == 4
        number, = struct.unpack('<L', data)
        self.rc.log.info("MSI interrupt: 0x%08x, 0x%04x", addr, number)
        assert number in self.msi_events
        self.msi_events[number].set()
        for cb in self.msi_callbacks[number]:
            cocotb.start_soon(cb())

    async def configure_msi(self, dev):
        if not self.rc.tree:
            raise Exception("Enumeration has not yet been run")
        ti = self.rc.tree.find_child_dev(dev)
        if not ti:
            raise Exception("Invalid device")
        if ti.get_capability_offset(PcieCapId.MSI) is None:
            raise Exception("Device does not support MSI")
        if ti.msi_addr is not None and ti.msi_data is not None:
            # already configured
            return

        self.rc.log.info("Configure MSI on %s", ti.pcie_id)

        msg_ctrl = await self.rc.capability_read_dword(dev, PcieCapId.MSI, 0)

        msi_64bit = (msg_ctrl >> 23) & 1
        msi_mmcap = (msg_ctrl >> 17) & 7

        msi_addr = self.get_absolute_address(0)

        # message address
        await self.rc.capability_write_dword(dev, PcieCapId.MSI, 4, msi_addr & 0xfffffffc)

        if msi_64bit:
            # 64 bit message address
            # message upper address
            await self.rc.capability_write_dword(dev, PcieCapId.MSI, 8, (msi_addr >> 32) & 0xffffffff)
            # message data
            await self.rc.capability_write_dword(dev, PcieCapId.MSI, 12, self.msi_msg_limit)

        else:
            # 32 bit message address
            # message data
            await self.rc.capability_write_dword(dev, PcieCapId.MSI, 8, self.msi_msg_limit)

        # enable and set enabled messages
        msg_ctrl |= 1 << 16
        msg_ctrl = (msg_ctrl & ~(7 << 20)) | (msi_mmcap << 20)
        await self.rc.capability_write_dword(dev, PcieCapId.MSI, 0, msg_ctrl)

        ti.msi_count = 2**msi_mmcap
        ti.msi_addr = msi_addr
        ti.msi_data = self.msi_msg_limit

        self.rc.log.info("MSI count: %d", ti.msi_count)
        self.rc.log.info("MSI address: 0x%08x", ti.msi_addr)
        self.rc.log.info("MSI base data: 0x%08x", ti.msi_data)

        for k in range(32):
            self.msi_events[self.msi_msg_limit] = Event()
            self.msi_callbacks[self.msi_msg_limit] = []
            self.msi_msg_limit += 1

    def get_event(self, dev, number=0):
        if not self.rc.tree:
            return None
        ti = self.rc.tree.find_child_dev(dev)
        if not ti:
            raise Exception("Invalid device")
        if ti.msi_data is None:
            raise Exception("MSI not configured on device")
        if number < 0 or number >= ti.msi_count or ti.msi_data+number not in self.msi_events:
            raise Exception("MSI number out of range")
        return self.msi_events[ti.msi_data+number]

    def register_callback(self, dev, callback, number=0):
        if not self.rc.tree:
            return
        ti = self.rc.tree.find_child_dev(dev)
        if not ti:
            raise Exception("Invalid device")
        if ti.msi_data is None:
            raise Exception("MSI not configured on device")
        if number < 0 or number >= ti.msi_count or ti.msi_data+number not in self.msi_callbacks:
            raise Exception("MSI number out of range")
        self.msi_callbacks[ti.msi_data+number].append(callback)
