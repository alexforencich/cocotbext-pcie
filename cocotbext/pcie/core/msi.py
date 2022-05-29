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


class MsiVector:
    def __init__(self):
        self.addr = None
        self.data = None
        self.event = Event()
        self.cb = []


class MsiRegion(Region):
    def __init__(self, rc, size=16, *kwargs):
        super().__init__(size=size, *kwargs)
        self.rc = rc

        self.msi_msg_limit = 0
        self.msi_vectors = {}

    def alloc_vectors(self, num):
        vecs = []

        for k in range(num):
            vec = MsiVector()
            vec.addr = self.get_absolute_address(0)
            vec.data = self.msi_msg_limit
            vecs.append(vec)
            self.msi_vectors[vec.data] = vec
            self.msi_msg_limit += 1

        self.msi_msg_limit += self.msi_msg_limit % 32

        return vecs

    async def read(self, addr, length, **kwargs):
        return bytearray(1)*length

    async def write(self, addr, data, **kwargs):
        assert addr == 0
        assert len(data) == 4
        number, = struct.unpack('<L', data)
        self.rc.log.info("MSI interrupt: 0x%08x, 0x%04x", addr, number)
        assert number in self.msi_vectors
        vec = self.msi_vectors[number]
        vec.event.set()
        for cb in vec.cb:
            cocotb.start_soon(cb())
