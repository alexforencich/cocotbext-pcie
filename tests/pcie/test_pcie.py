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
import os

import cocotb_test.simulator
import pytest

import cocotb
from cocotb.log import SimLog
from cocotb.triggers import Timer
from cocotb.regression import TestFactory

from cocotbext.pcie import RootComplex, MemoryEndpoint, Device, Switch
from cocotbext.pcie.caps import MsiCapability


class TestEndpoint(MemoryEndpoint, MsiCapability):
    __test__ = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.vendor_id = 0x1234
        self.device_id = 0x5678

        self.msi_multiple_message_capable = 5
        self.msi_64bit_address_capable = 1
        self.msi_per_vector_mask_capable = 1

        self.add_mem_region(1024)
        self.add_prefetchable_mem_region(1024*1024)
        self.add_io_region(32)


class TB(object):
    def __init__(self, dut):
        self.dut = dut

        self.log = SimLog(f"cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        self.rc = RootComplex()
        self.rc.log.setLevel(logging.DEBUG)

        self.ep = TestEndpoint()
        self.ep.log.setLevel(logging.DEBUG)
        self.dev = Device(self.ep)

        self.rc.make_port().connect(self.dev)

        self.sw = Switch()

        self.rc.make_port().connect(self.sw)

        self.ep2 = TestEndpoint()
        self.ep2.log.setLevel(logging.DEBUG)
        self.dev2 = Device(self.ep2)

        self.sw.make_port().connect(self.dev2)

        self.ep3 = TestEndpoint()
        self.dev3 = Device(self.ep3)

        self.sw.make_port().connect(self.dev3)

        self.ep4 = TestEndpoint()
        self.dev4 = Device(self.ep4)

        self.rc.make_port().connect(self.dev4)


async def run_test(dut):

    tb = TB(dut)

    tb.log.info("Enumerate")

    await tb.rc.enumerate(enable_bus_mastering=True, configure_msi=True)

    tb.log.info("IO and memory read/write")

    await tb.rc.io_write(0x80000000, bytearray(range(16)), 1000, 'ns')
    assert await tb.ep.read_region(3, 0, 16) == bytearray(range(16))

    assert await tb.rc.io_read(0x80000000, 16, 1000, 'ns') == bytearray(range(16))

    await tb.rc.mem_write(0x80000000, bytearray(range(16)), 1000, 'ns')
    await Timer(1000, 'ns')
    assert await tb.ep.read_region(0, 0, 16) == bytearray(range(16))

    assert await tb.rc.mem_read(0x80000000, 16, 1000, 'ns') == bytearray(range(16))

    await tb.rc.mem_write(0x8000000000000000, bytearray(range(16)), 1000, 'ns')
    await Timer(1000, 'ns')
    assert await tb.ep.read_region(1, 0, 16) == bytearray(range(16))

    assert await tb.rc.mem_read(0x8000000000000000, 16, 1000, 'ns') == bytearray(range(16))

    await tb.rc.mem_write(0x8000000000000000, bytearray(range(256))*32, 100)
    await Timer(1000, 'ns')
    assert await tb.ep.read_region(1, 0, 256*32) == bytearray(range(256))*32

    assert await tb.rc.mem_read(0x8000000000000000, 256*32, 1000, 'ns') == bytearray(range(256))*32

    tb.log.info("Root complex memory")

    mem_base, mem_data = tb.rc.alloc_region(1024*1024)
    io_base, io_data = tb.rc.alloc_io_region(1024)

    await tb.rc.io_write(io_base, bytearray(range(16)))
    assert io_data[0:16] == bytearray(range(16))

    assert await tb.rc.io_read(io_base, 16) == bytearray(range(16))

    await tb.rc.mem_write(mem_base, bytearray(range(16)))
    assert mem_data[0:16] == bytearray(range(16))

    assert await tb.rc.mem_read(mem_base, 16) == bytearray(range(16))

    tb.log.info("Device-to-device DMA")

    await tb.ep.io_write(0x80001000, bytearray(range(16)), 1000, 'ns')
    assert await tb.ep2.read_region(3, 0, 16) == bytearray(range(16))

    assert await tb.ep.io_read(0x80001000, 16, 1000, 'ns') == bytearray(range(16))

    await tb.ep.mem_write(0x80100000, bytearray(range(16)), 1000, 'ns')
    await Timer(1000, 'ns')
    assert await tb.ep2.read_region(0, 0, 16) == bytearray(range(16))

    assert await tb.ep.mem_read(0x80100000, 16, 1000, 'ns') == bytearray(range(16))

    await tb.ep.mem_write(0x8000000000100000, bytearray(range(16)), 1000, 'ns')
    await Timer(1000, 'ns')
    assert await tb.ep2.read_region(1, 0, 16) == bytearray(range(16))

    assert await tb.ep.mem_read(0x8000000000100000, 16, 1000, 'ns') == bytearray(range(16))

    tb.log.info("Device-to-root DMA")

    await tb.ep.io_write(io_base, bytearray(range(16)), 1000, 'ns')
    assert io_data[0:16] == bytearray(range(16))

    assert await tb.ep.io_read(io_base, 16, 1000, 'ns') == bytearray(range(16))

    await tb.ep.mem_write(mem_base, bytearray(range(16)), 1000, 'ns')
    await Timer(1000, 'ns')
    assert mem_data[0:16] == bytearray(range(16))

    assert await tb.ep.mem_read(mem_base, 16, 1000, 'ns') == bytearray(range(16))

    tb.log.info("MSI")
    
    await tb.ep.issue_msi_interrupt(4)

    event = tb.rc.msi_get_event(tb.ep.pcie_id, 4)
    event.clear()
    await event.wait()

if cocotb.SIM_NAME:

    factory = TestFactory(run_test)
    factory.generate_tests()


tests_dir = os.path.dirname(__file__)

def test_pcie(request):
    dut = "pcie"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(os.path.dirname(__file__), f"{dut}.v"),
    ]

    sim_build = os.path.join(tests_dir,
        "sim_build_"+request.node.name.replace('[', '-').replace(']', ''))

    cocotb_test.simulator.run(
        python_search=[tests_dir],
        verilog_sources=verilog_sources,
        toplevel=toplevel,
        module=module,
        sim_build=sim_build,
    )

