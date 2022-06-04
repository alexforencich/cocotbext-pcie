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

import logging
import os

import cocotb_test.simulator

import cocotb
from cocotb.regression import TestFactory

from cocotbext.pcie.core import RootComplex, MemoryEndpoint, Device, Switch
from cocotbext.pcie.core.caps import MsiCapability
from cocotbext.pcie.core.utils import PcieId


class TestEndpoint(MemoryEndpoint):
    __test__ = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.vendor_id = 0x1234
        self.device_id = 0x5678

        self.msi_cap = MsiCapability()
        self.msi_cap.msi_multiple_message_capable = 5
        self.msi_cap.msi_64bit_address_capable = 1
        self.msi_cap.msi_per_vector_mask_capable = 1
        self.register_capability(self.msi_cap)

        self.add_mem_region(1024*1024)
        self.add_prefetchable_mem_region(1024*1024)
        self.add_io_region(1024)


class TB:
    def __init__(self, dut):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        self.rc = RootComplex()

        self.ep = []

        ep = TestEndpoint()
        self.dev = Device(ep)
        self.dev.upstream_port.max_link_speed = 3
        self.dev.upstream_port.max_link_width = 16
        self.ep.append(ep)

        self.rc.make_port().connect(self.dev)

        self.sw = Switch()

        self.rc.make_port().connect(self.sw)

        ep = TestEndpoint()
        self.dev2 = Device(ep)
        self.dev2.upstream_port.max_link_speed = 3
        self.dev2.upstream_port.max_link_width = 16
        self.ep.append(ep)

        self.sw.make_port().connect(self.dev2)

        ep = TestEndpoint()
        self.dev3 = Device(ep)
        self.dev3.upstream_port.max_link_speed = 3
        self.dev3.upstream_port.max_link_width = 16
        self.ep.append(ep)

        self.sw.make_port().connect(self.dev3)

        ep = TestEndpoint()
        self.dev4 = Device(ep)
        self.dev4.upstream_port.max_link_speed = 3
        self.dev4.upstream_port.max_link_width = 16
        self.ep.append(ep)

        self.rc.make_port().connect(self.dev4)


async def run_test_rc_mem(dut):

    tb = TB(dut)

    tb.rc.log.setLevel(logging.DEBUG)

    mem = tb.rc.mem_pool.alloc_region(16*1024*1024)
    mem_base = mem.get_absolute_address(0)

    io = tb.rc.io_pool.alloc_region(1024)
    io_base = io.get_absolute_address(0)

    for length in list(range(1, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation length: %d offset: %d", length, offset)
            addr = mem_base+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await tb.rc.mem_write(addr, test_data)
            assert mem[offset:offset+length] == test_data

            assert await tb.rc.mem_read(addr, length) == test_data

    for length in list(range(1, 32)):
        for offset in list(range(8)):
            tb.log.info("IO operation length: %d offset: %d", length, offset)
            addr = io_base+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await tb.rc.io_write(addr, test_data)
            assert io[offset:offset+length] == test_data

            assert await tb.rc.io_read(addr, length) == test_data


async def run_test_config(dut):

    tb = TB(dut)

    tb.rc.log.setLevel(logging.DEBUG)

    tb.log.info("Read complete config space")
    orig = await tb.rc.config_read(PcieId(0, 1, 0), 0x000, 256, timeout=1000, timeout_unit='ns')

    tb.log.info("Read and write interrupt line register")
    await tb.rc.config_write(PcieId(0, 1, 0), 0x03c, b'\x12', timeout=1000, timeout_unit='ns')
    val = await tb.rc.config_read(PcieId(0, 1, 0), 0x03c, 1, timeout=1000, timeout_unit='ns')

    assert val == b'\x12'

    tb.log.info("Write complete config space")
    await tb.rc.config_write(PcieId(0, 1, 0), 0x000, orig, timeout=1000, timeout_unit='ns')


async def run_test_enumerate(dut):

    tb = TB(dut)

    all_ep = tb.rc.endpoints+[tb.sw.upstream_bridge]+tb.sw.endpoints+tb.ep

    tb.rc.log.setLevel(logging.DEBUG)
    for ep in all_ep:
        ep.log.setLevel(logging.DEBUG)

    await tb.rc.enumerate()

    # check that enumerated tree matches devices
    def check_dev(dev):
        tb.log.info("Check device at %s", dev.pcie_id)

        # ensure ID was assigned to device
        assert dev.pcie_id != PcieId(0, 0, 0)

        # get device
        pdev = tb.rc.find_device(dev.pcie_id)
        assert pdev is not None

        # check informational registers
        tb.log.info("Header type: 0x%02x", pdev.header_type)
        tb.log.info("Vendor ID: 0x%04x", pdev.vendor_id)
        tb.log.info("Device ID: 0x%04x", pdev.device_id)
        tb.log.info("Revision ID: 0x%02x", pdev.revision_id)
        tb.log.info("Class code: 0x%06x", pdev.class_code)

        assert pdev.header_type == dev.header_layout | (bool(dev.multifunction_device) << 7)
        assert pdev.class_code == dev.class_code
        assert pdev.revision_id == dev.revision_id

        assert pdev.vendor_id == dev.vendor_id
        assert pdev.device_id == dev.device_id

        if pdev.header_type == 0x01:
            # bridge
            bar_cnt = 2

            # check bridge registers
            tb.log.info("Primary bus %d", pdev.subordinate.primary)
            tb.log.info("Secondary bus %d", pdev.subordinate.bus_num)
            tb.log.info("Subordinate bus %d", pdev.subordinate.last_bus_num)
            tb.log.info("IO base 0x%08x", pdev.io_base)
            tb.log.info("IO limit 0x%08x", pdev.io_limit)
            tb.log.info("Mem base 0x%08x", pdev.mem_base)
            tb.log.info("Mem limit 0x%08x", pdev.mem_limit)
            tb.log.info("Prefetchable mem base 0x%016x", pdev.prefetchable_mem_base)
            tb.log.info("Prefetchable mem limit 0x%016x", pdev.prefetchable_mem_limit)

            assert pdev.subordinate.primary == dev.pri_bus_num
            assert pdev.subordinate.bus_num == dev.sec_bus_num
            assert pdev.subordinate.last_bus_num == dev.sub_bus_num

            assert pdev.io_base == dev.io_base
            assert pdev.io_limit == dev.io_limit
            assert pdev.mem_base == dev.mem_base
            assert pdev.mem_limit == dev.mem_limit
            assert pdev.prefetchable_mem_base == dev.prefetchable_mem_base
            assert pdev.prefetchable_mem_limit == dev.prefetchable_mem_limit
        else:
            bar_cnt = 6

            tb.log.info("Subsystem vendor ID: 0x%04x", pdev.subsystem_vendor_id)
            tb.log.info("Subsystem ID: 0x%04x", pdev.subsystem_id)

            assert pdev.subsystem_vendor_id == dev.subsystem_vendor_id
            assert pdev.subsystem_id == dev.subsystem_id

        # check BARs
        bar = 0
        while bar < bar_cnt:
            if dev.bar_mask[bar] == 0:
                # unused bar
                assert pdev.bar[bar] is None
                assert pdev.bar_raw[bar] == 0
                assert pdev.bar_addr[bar] is None
                assert pdev.bar_size[bar] == 0
                bar += 1
            elif dev.bar[bar] & 1:
                # IO BAR
                tb.log.info("BAR%d: IO BAR addr 0x%08x, size %d", bar, pdev.bar_addr[bar], pdev.bar_size[bar])
                assert pdev.bar[bar] == dev.bar[bar]
                assert pdev.bar_raw[bar] == dev.bar[bar]
                assert pdev.bar_addr[bar] == dev.bar[bar] & ~0x3
                assert pdev.bar_size[bar] == (~dev.bar_mask[bar] & 0xfffffffc)+0x4
                bar += 1
            elif dev.bar[bar] & 4:
                # 64 bit BAR
                tb.log.info("BAR%d: Mem BAR (32 bit) addr 0x%08x, size %d", bar, pdev.bar_addr[bar], pdev.bar_size[bar])
                assert pdev.bar[bar] == dev.bar[bar] | dev.bar[bar+1] << 32
                assert pdev.bar_raw[bar] == dev.bar[bar]
                assert pdev.bar_raw[bar+1] == dev.bar[bar+1]
                assert pdev.bar_addr[bar] == (dev.bar[bar] | dev.bar[bar+1] << 32) & ~0xf
                assert pdev.bar_size[bar] == (~(dev.bar_mask[bar] | dev.bar_mask[bar+1] << 32) & 0xfffffffffffffff0)+0x10
                bar += 2
            else:
                # 32 bit BAR
                tb.log.info("BAR%d: Mem BAR (64 bit) addr 0x%08x, size %d", bar, pdev.bar_addr[bar], pdev.bar_size[bar])
                assert pdev.bar[bar] == dev.bar[bar]
                assert pdev.bar_raw[bar] == dev.bar[bar]
                assert pdev.bar_addr[bar] == dev.bar[bar] & ~0xf
                assert pdev.bar_size[bar] == (~dev.bar_mask[bar] & 0xfffffff0)+0x10
                bar += 1

        if dev.expansion_rom_addr_mask == 0:
            assert pdev.expansion_rom_raw == 0
            assert pdev.expansion_rom_addr is None
            assert pdev.expansion_rom_size == 0
        else:
            assert pdev.expansion_rom_raw & 0xfffff800 == dev.expansion_rom_addr
            assert pdev.expansion_rom_addr == dev.expansion_rom_addr
            assert pdev.expansion_rom_size == (~dev.expansion_rom_addr_mask & 0xfffff800)+0x800

        # TODO capabilities

    for d in all_ep:
        check_dev(d)

    # check settings in enumerated tree
    def check_bus(bus):
        bus_regions = []
        io_regions = []
        mem_regions = []
        prefetchable_mem_regions = []

        for dev in bus.devices:
            tb.log.info("Check device at %s", dev.pcie_id)

            tb.log.info("Header type: 0x%02x", dev.header_type)
            tb.log.info("Vendor ID: 0x%04x", dev.vendor_id)
            tb.log.info("Device ID: 0x%04x", dev.device_id)
            tb.log.info("Revision ID: 0x%02x", dev.revision_id)
            tb.log.info("Class code: 0x%06x", dev.class_code)

            if dev.header_type & 0x7f == 0x00:
                # type 0 header
                tb.log.info("Subsystem vendor ID: 0x%04x", dev.subsystem_vendor_id)
                tb.log.info("Subsystem ID: 0x%04x", dev.subsystem_id)

            # check that BARs are within our apertures
            for bar in range(6):
                if dev.bar[bar] is None:
                    continue
                if dev.bar[bar] & 1:
                    # IO BAR
                    tb.log.info("BAR%d: IO BAR addr 0x%08x, size %d", bar, dev.bar_addr[bar], dev.bar_size[bar])
                    assert (dev.bus.bridge.io_base <= dev.bar_addr[bar]
                        and dev.bar_addr[bar]+dev.bar_size[bar]-1 <= dev.bus.bridge.io_limit)
                    io_regions.append((dev.bar_addr[bar], dev.bar_addr[bar]+dev.bar_size[bar]-1))
                elif dev.bar[bar] > 0xffffffff:
                    # prefetchable BAR
                    tb.log.info("BAR%d: Mem BAR (prefetchable) addr 0x%08x, size %d",
                        bar, dev.bar_addr[bar], dev.bar_size[bar])
                    assert (dev.bus.bridge.prefetchable_mem_base <= dev.bar_addr[bar]
                        and dev.bar_addr[bar]+dev.bar_size[bar]-1 <= dev.bus.bridge.prefetchable_mem_limit)
                    prefetchable_mem_regions.append((dev.bar_addr[bar], dev.bar_addr[bar]+dev.bar_size[bar]-1))
                else:
                    # non-prefetchable BAR
                    tb.log.info("BAR%d: Mem BAR (non-prefetchable) addr 0x%08x, size %d",
                        bar, dev.bar_addr[bar], dev.bar_size[bar])
                    assert (dev.bus.bridge.mem_base <= dev.bar_addr[bar]
                        and dev.bar_addr[bar]+dev.bar_size[bar]-1 <= dev.bus.bridge.mem_limit)
                    mem_regions.append((dev.bar_addr[bar], dev.bar_addr[bar]+dev.bar_size[bar]-1))

            if dev.expansion_rom_addr:
                # expansion ROM BAR
                tb.log.info("Expansion ROM BAR: Mem BAR (non-prefetchable) addr 0x%08x, size %d",
                    dev.expansion_rom_addr, dev.expansion_rom_size)
                assert (dev.bus.bridge.mem_base <= dev.expansion_rom_addr and
                    dev.expansion_rom_addr+dev.expansion_rom_size-1 <= dev.bus.bridge.mem_limit)
                mem_regions.append((dev.expansion_rom_addr, dev.expansion_rom_addr+dev.expansion_rom_size-1))

            if dev.header_type & 0x7f == 0x01:
                # type 1 header

                tb.log.info("Primary bus: %d", dev.pri_bus_num)
                tb.log.info("Secondary bus: %d", dev.sec_bus_num)
                tb.log.info("Subordinate bus: %d", dev.sub_bus_num)
                tb.log.info("IO base: 0x%08x", dev.io_base)
                tb.log.info("IO limit: 0x%08x", dev.io_limit)
                tb.log.info("Mem base: 0x%08x", dev.mem_base)
                tb.log.info("Mem limit: 0x%08x", dev.mem_limit)
                tb.log.info("Prefetchable mem base: 0x%016x", dev.prefetchable_mem_base)
                tb.log.info("Prefetchable mem limit: 0x%016x", dev.prefetchable_mem_limit)

                # check that child switch apertures are within our apertures
                assert dev.bus.bridge.sec_bus_num <= dev.pri_bus_num <= dev.bus.bridge.sub_bus_num
                assert dev.bus.bridge.sec_bus_num <= dev.sec_bus_num and dev.sub_bus_num <= dev.bus.bridge.sub_bus_num
                bus_regions.append((dev.sec_bus_num, dev.sub_bus_num))
                if dev.io_base:
                    assert dev.bus.bridge.io_base <= dev.io_base and dev.io_limit <= dev.bus.bridge.io_limit
                    io_regions.append((dev.io_base, dev.io_limit))
                if dev.mem_base:
                    assert dev.bus.bridge.mem_base <= dev.mem_base and dev.mem_limit <= dev.bus.bridge.mem_limit
                    mem_regions.append((dev.mem_base, dev.mem_limit))
                if dev.prefetchable_mem_base:
                    assert (dev.bus.bridge.prefetchable_mem_base <= dev.prefetchable_mem_base and
                        dev.prefetchable_mem_limit <= dev.bus.bridge.prefetchable_mem_limit)
                    prefetchable_mem_regions.append((dev.prefetchable_mem_base, dev.prefetchable_mem_limit))

        # check for assignment overlaps
        for lst in [bus_regions, io_regions, mem_regions, prefetchable_mem_regions]:
            lst.sort()
            for m in range(1, len(lst)):
                assert lst[m-1][1] <= lst[m][0], "assigned regions overlap"

        # recurse into child nodes
        for child in bus.children:
            check_bus(child)

    check_bus(tb.rc.host_bridge.bus)


async def run_test_ep_mem(dut, ep_index=0):

    tb = TB(dut)

    await tb.rc.enumerate()
    tb.rc.log.setLevel(logging.DEBUG)

    ep = tb.ep[ep_index]
    ep.log.setLevel(logging.DEBUG)
    dev = tb.rc.find_device(ep.pcie_id)
    await dev.enable_device()

    dev_bar0 = dev.bar_window[0]
    dev_bar1 = dev.bar_window[1]
    dev_bar3 = dev.bar_window[3]

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (32-bit BAR) length: %d offset: %d", length, offset)
            test_data = bytearray([x % 256 for x in range(length)])

            await dev_bar0.write(offset, test_data, timeout=1000, timeout_unit='ns')
            # wait for write to complete
            await dev_bar0.read(offset, 0, timeout=1000, timeout_unit='ns')
            assert await ep.read_region(0, offset, length) == test_data

            assert await dev_bar0.read(offset, length, timeout=1000, timeout_unit='ns') == test_data

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (64-bit BAR) length: %d offset: %d", length, offset)
            test_data = bytearray([x % 256 for x in range(length)])

            await dev_bar1.write(offset, test_data, timeout=1000, timeout_unit='ns')
            # wait for write to complete
            await dev_bar1.read(offset, 0, timeout=1000, timeout_unit='ns')
            assert await ep.read_region(1, offset, length) == test_data

            assert await dev_bar1.read(offset, length, timeout=1000, timeout_unit='ns') == test_data

    for length in list(range(0, 8)):
        for offset in list(range(8)):
            tb.log.info("IO operation length: %d offset: %d", length, offset)
            test_data = bytearray([x % 256 for x in range(length)])

            await dev_bar3.write(offset, test_data, timeout=1000, timeout_unit='ns')
            assert await ep.read_region(3, offset, length) == test_data

            assert await dev_bar3.read(offset, length, timeout=1000, timeout_unit='ns') == test_data


async def run_test_p2p_dma(dut, ep1_index=0, ep2_index=1):

    tb = TB(dut)

    await tb.rc.enumerate()
    tb.rc.log.setLevel(logging.DEBUG)

    ep1 = tb.ep[ep1_index]
    ep1.log.setLevel(logging.DEBUG)
    dev1 = tb.rc.find_device(ep1.pcie_id)
    await dev1.enable_device()
    await dev1.set_master()
    ep2 = tb.ep[ep2_index]
    ep2.log.setLevel(logging.DEBUG)
    dev2 = tb.rc.find_device(ep2.pcie_id)
    await dev2.enable_device()

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (32-bit BAR) length: %d offset: %d", length, offset)
            addr = dev2.bar_addr[0]+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await ep1.mem_write(addr, test_data, timeout=1000, timeout_unit='ns')
            # wait for write to complete
            await ep1.mem_read(addr, 0, timeout=1000, timeout_unit='ns')
            assert await ep2.read_region(0, offset, length) == test_data

            assert await ep1.mem_read(addr, length, timeout=1000, timeout_unit='ns') == test_data

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (64-bit BAR) length: %d offset: %d", length, offset)
            addr = dev2.bar_addr[1]+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await ep1.mem_write(addr, test_data, timeout=1000, timeout_unit='ns')
            # wait for write to complete
            await ep1.mem_read(addr, 0, timeout=1000, timeout_unit='ns')
            assert await ep2.read_region(1, offset, length) == test_data

            assert await ep1.mem_read(addr, length, timeout=1000, timeout_unit='ns') == test_data

    for length in list(range(0, 8)):
        for offset in list(range(8)):
            tb.log.info("IO operation length: %d offset: %d", length, offset)
            addr = dev2.bar_addr[3]+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await ep1.io_write(addr, test_data, timeout=1000, timeout_unit='ns')
            assert await ep2.read_region(3, offset, length) == test_data

            assert await ep1.io_read(addr, length, timeout=1000, timeout_unit='ns') == test_data


async def run_test_dma(dut, ep_index=0):

    tb = TB(dut)

    mem = tb.rc.mem_pool.alloc_region(16*1024*1024)
    mem_base = mem.get_absolute_address(0)

    io = tb.rc.io_pool.alloc_region(1024)
    io_base = io.get_absolute_address(0)

    await tb.rc.enumerate()
    tb.rc.log.setLevel(logging.DEBUG)

    ep = tb.ep[ep_index]
    ep.log.setLevel(logging.DEBUG)
    dev = tb.rc.find_device(ep.pcie_id)
    await dev.enable_device()
    await dev.set_master()

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (DMA) length: %d offset: %d", length, offset)
            addr = mem_base+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await ep.mem_write(addr, test_data, timeout=1000, timeout_unit='ns')
            # wait for write to complete
            await ep.mem_read(addr, 0, timeout=1000, timeout_unit='ns')
            assert mem[offset:offset+length] == test_data

            assert await ep.mem_read(addr, length, timeout=1000, timeout_unit='ns') == test_data

    for length in list(range(0, 8)):
        for offset in list(range(8)):
            tb.log.info("IO operation (DMA) length: %d offset: %d", length, offset)
            addr = io_base+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await ep.io_write(addr, test_data, timeout=1000, timeout_unit='ns')
            assert io[offset:offset+length] == test_data

            assert await ep.io_read(addr, length, timeout=1000, timeout_unit='ns') == test_data


async def run_test_msi(dut, ep_index=0):

    tb = TB(dut)

    await tb.rc.enumerate()
    tb.rc.log.setLevel(logging.DEBUG)

    ep = tb.ep[ep_index]
    ep.log.setLevel(logging.DEBUG)
    dev = tb.rc.find_device(ep.pcie_id)
    await dev.enable_device()
    await dev.set_master()
    await dev.alloc_irq_vectors(32, 32)

    for k in range(32):
        tb.log.info("Send MSI %d", k)

        await ep.msi_cap.issue_msi_interrupt(k)

        event = dev.msi_vectors[k].event
        event.clear()
        await event.wait()

if cocotb.SIM_NAME:

    for test in [
                run_test_rc_mem,
                run_test_config,
                run_test_enumerate,
            ]:

        factory = TestFactory(test)
        factory.generate_tests()

    factory = TestFactory(run_test_ep_mem)
    factory.add_option("ep_index", range(4))
    factory.generate_tests()

    factory = TestFactory(run_test_p2p_dma)
    factory.add_option("ep1_index", [0, 1])
    factory.add_option("ep2_index", [2, 3])
    factory.generate_tests()

    factory = TestFactory(run_test_dma)
    factory.add_option("ep_index", range(4))
    factory.generate_tests()

    factory = TestFactory(run_test_msi)
    factory.add_option("ep_index", range(4))
    factory.generate_tests()


# cocotb-test

tests_dir = os.path.dirname(__file__)


def test_pcie(request):
    dut = "test_pcie"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(os.path.dirname(__file__), f"{dut}.v"),
    ]

    sim_build = os.path.join(tests_dir, "sim_build",
        request.node.name.replace('[', '-').replace(']', ''))

    cocotb_test.simulator.run(
        python_search=[tests_dir],
        verilog_sources=verilog_sources,
        toplevel=toplevel,
        module=module,
        sim_build=sim_build,
    )
