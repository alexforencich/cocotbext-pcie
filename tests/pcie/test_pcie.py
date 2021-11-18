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

    await tb.rc.enumerate(enable_bus_mastering=True, configure_msi=True)

    # check that enumerated tree matches devices
    def check_dev(dev):
        tb.log.info("Check device at %s", dev.pcie_id)

        # ensure ID was assigned to device
        assert dev.pcie_id != PcieId(0, 0, 0)

        # get tree item
        ti = tb.rc.tree.find_child_dev(dev.pcie_id)
        assert ti is not None

        # check informational registers
        tb.log.info("Header type: 0x%02x", ti.header_type)
        tb.log.info("Vendor ID: 0x%04x", ti.vendor_id)
        tb.log.info("Device ID: 0x%04x", ti.device_id)
        tb.log.info("Revision ID: 0x%02x", ti.revision_id)
        tb.log.info("Class code: 0x%06x", ti.class_code)

        assert ti.header_type == dev.header_layout | (bool(dev.multifunction_device) << 7)
        assert ti.class_code == dev.class_code
        assert ti.revision_id == dev.revision_id

        assert ti.vendor_id == dev.vendor_id
        assert ti.device_id == dev.device_id

        if ti.header_type & 0x7f == 0x01:
            # bridge
            bar_cnt = 2

            # check bridge registers
            tb.log.info("Primary bus %d", ti.pri_bus_num)
            tb.log.info("Secondary bus %d", ti.sec_bus_num)
            tb.log.info("Subordinate bus %d", ti.sub_bus_num)
            tb.log.info("IO base 0x%08x", ti.io_base)
            tb.log.info("IO limit 0x%08x", ti.io_limit)
            tb.log.info("Mem base 0x%08x", ti.mem_base)
            tb.log.info("Mem limit 0x%08x", ti.mem_limit)
            tb.log.info("Prefetchable mem base 0x%016x", ti.prefetchable_mem_base)
            tb.log.info("Prefetchable mem limit 0x%016x", ti.prefetchable_mem_limit)

            assert ti.sec_bus_num == dev.sec_bus_num
            assert ti.sub_bus_num == dev.sub_bus_num

            assert ti.io_base == dev.io_base
            assert ti.io_limit == dev.io_limit
            assert ti.mem_base == dev.mem_base
            assert ti.mem_limit == dev.mem_limit
            assert ti.prefetchable_mem_base == dev.prefetchable_mem_base
            assert ti.prefetchable_mem_limit == dev.prefetchable_mem_limit
        else:
            bar_cnt = 6

            tb.log.info("Subsystem vendor ID: 0x%04x", ti.subsystem_vendor_id)
            tb.log.info("Subsystem ID: 0x%04x", ti.subsystem_id)

            assert ti.subsystem_vendor_id == dev.subsystem_vendor_id
            assert ti.subsystem_id == dev.subsystem_id

        # check BARs
        bar = 0
        while bar < bar_cnt:
            if d.bar_mask[bar] == 0:
                # unused bar
                assert ti.bar[bar] is None
                assert ti.bar_raw[bar] == 0
                assert ti.bar_addr[bar] is None
                assert ti.bar_size[bar] is None
                bar += 1
            elif d.bar[bar] & 1:
                # IO BAR
                tb.log.info("BAR%d: IO BAR addr 0x%08x, size %d", bar, ti.bar_addr[bar], ti.bar_size[bar])
                assert ti.bar[bar] == d.bar[bar]
                assert ti.bar_raw[bar] == d.bar[bar]
                assert ti.bar_addr[bar] == d.bar[bar] & ~0x3
                assert ti.bar_size[bar] == (~d.bar_mask[bar] & 0xfffffffc)+0x4
                bar += 1
            elif d.bar[bar] & 4:
                # 64 bit BAR
                tb.log.info("BAR%d: Mem BAR (32 bit) addr 0x%08x, size %d", bar, ti.bar_addr[bar], ti.bar_size[bar])
                assert ti.bar[bar] == d.bar[bar] | d.bar[bar+1] << 32
                assert ti.bar_raw[bar] == d.bar[bar]
                assert ti.bar_raw[bar+1] == d.bar[bar+1]
                assert ti.bar_addr[bar] == (d.bar[bar] | d.bar[bar+1] << 32) & ~0xf
                assert ti.bar_size[bar] == (~(d.bar_mask[bar] | d.bar_mask[bar+1] << 32) & 0xfffffffffffffff0)+0x10
                bar += 2
            else:
                # 32 bit BAR
                tb.log.info("BAR%d: Mem BAR (64 bit) addr 0x%08x, size %d", bar, ti.bar_addr[bar], ti.bar_size[bar])
                assert ti.bar[bar] == d.bar[bar]
                assert ti.bar_raw[bar] == d.bar[bar]
                assert ti.bar_addr[bar] == d.bar[bar] & ~0xf
                assert ti.bar_size[bar] == (~d.bar_mask[bar] & 0xfffffff0)+0x10
                bar += 1

        if d.expansion_rom_addr_mask == 0:
            assert ti.expansion_rom_raw == 0
            assert ti.expansion_rom_addr is None
            assert ti.expansion_rom_size is None
        else:
            assert ti.expansion_rom_raw & 0xfffff800 == dev.expansion_rom_addr
            assert ti.expansion_rom_addr == dev.expansion_rom_addr
            assert ti.expansion_rom_size == (~d.expansion_rom_addr_mask & 0xfffff800)+0x800

        # TODO capabilities

    for d in all_ep:
        check_dev(d)

    # check settings in enumerated tree
    def check_tree(ti):
        tb.log.info("Check bridge at %s", ti.pcie_id)

        tb.log.info("Header type: 0x%02x", ti.header_type)
        tb.log.info("Vendor ID: 0x%04x", ti.vendor_id)
        tb.log.info("Device ID: 0x%04x", ti.device_id)
        tb.log.info("Revision ID: 0x%02x", ti.revision_id)
        tb.log.info("Class code: 0x%06x", ti.class_code)

        tb.log.info("Primary bus: %d", ti.pri_bus_num)
        tb.log.info("Secondary bus: %d", ti.sec_bus_num)
        tb.log.info("Subordinate bus: %d", ti.sub_bus_num)
        tb.log.info("IO base: 0x%08x", ti.io_base)
        tb.log.info("IO limit: 0x%08x", ti.io_limit)
        tb.log.info("Mem base: 0x%08x", ti.mem_base)
        tb.log.info("Mem limit: 0x%08x", ti.mem_limit)
        tb.log.info("Prefetchable mem base: 0x%016x", ti.prefetchable_mem_base)
        tb.log.info("Prefetchable mem limit: 0x%016x", ti.prefetchable_mem_limit)

        bus_regions = []
        io_regions = []
        mem_regions = []
        prefetchable_mem_regions = []

        for ci in ti:
            tb.log.info("Check device at %s", ci.pcie_id)

            tb.log.info("Header type: 0x%02x", ci.header_type)
            tb.log.info("Vendor ID: 0x%04x", ci.vendor_id)
            tb.log.info("Device ID: 0x%04x", ci.device_id)
            tb.log.info("Revision ID: 0x%02x", ci.revision_id)
            tb.log.info("Class code: 0x%06x", ci.class_code)

            if ci.header_type & 0x7f == 0x00:
                # type 0 header
                tb.log.info("Subsystem vendor ID: 0x%04x", ci.subsystem_vendor_id)
                tb.log.info("Subsystem ID: 0x%04x", ci.subsystem_id)

            # check that BARs are within our apertures
            for bar in range(6):
                if ci.bar[bar] is None:
                    continue
                if ci.bar[bar] & 1:
                    # IO BAR
                    tb.log.info("BAR%d: IO BAR addr 0x%08x, size %d", bar, ci.bar_addr[bar], ci.bar_size[bar])
                    assert (ti.io_base <= ci.bar_addr[bar] and ci.bar_addr[bar]+ci.bar_size[bar]-1 <= ti.io_limit)
                    io_regions.append((ci.bar_addr[bar], ci.bar_addr[bar]+ci.bar_size[bar]-1))
                elif ci.bar[bar] > 0xffffffff:
                    # prefetchable BAR
                    tb.log.info("BAR%d: Mem BAR (prefetchable) addr 0x%08x, size %d",
                        bar, ci.bar_addr[bar], ci.bar_size[bar])
                    assert (ti.prefetchable_mem_base <= ci.bar_addr[bar]
                        and ci.bar_addr[bar]+ci.bar_size[bar]-1 <= ti.prefetchable_mem_limit)
                    prefetchable_mem_regions.append((ci.bar_addr[bar], ci.bar_addr[bar]+ci.bar_size[bar]-1))
                else:
                    # non-prefetchable BAR
                    tb.log.info("BAR%d: Mem BAR (non-prefetchable) addr 0x%08x, size %d",
                        bar, ci.bar_addr[bar], ci.bar_size[bar])
                    assert (ti.mem_base <= ci.bar_addr[bar]
                        and ci.bar_addr[bar]+ci.bar_size[bar]-1 <= ti.mem_limit)
                    mem_regions.append((ci.bar_addr[bar], ci.bar_addr[bar]+ci.bar_size[bar]-1))

            if ci.expansion_rom_addr:
                # expansion ROM BAR
                tb.log.info("Expansion ROM BAR: Mem BAR (non-prefetchable) addr 0x%08x, size %d",
                    ci.expansion_rom_addr, ci.expansion_rom_size)
                assert (ti.mem_base <= ci.expansion_rom_addr and
                    ci.expansion_rom_addr+ci.expansion_rom_size-1 <= ti.mem_limit)
                mem_regions.append((ci.expansion_rom_addr, ci.expansion_rom_addr+ci.expansion_rom_size-1))

            if ci.header_type & 0x7f == 0x01:
                # type 1 header

                tb.log.info("Primary bus: %d", ci.pri_bus_num)
                tb.log.info("Secondary bus: %d", ci.sec_bus_num)
                tb.log.info("Subordinate bus: %d", ci.sub_bus_num)
                tb.log.info("IO base: 0x%08x", ci.io_base)
                tb.log.info("IO limit: 0x%08x", ci.io_limit)
                tb.log.info("Mem base: 0x%08x", ci.mem_base)
                tb.log.info("Mem limit: 0x%08x", ci.mem_limit)
                tb.log.info("Prefetchable mem base: 0x%016x", ci.prefetchable_mem_base)
                tb.log.info("Prefetchable mem limit: 0x%016x", ci.prefetchable_mem_limit)

                # check that child switch apertures are within our apertures
                assert ti.sec_bus_num <= ci.pri_bus_num <= ti.sub_bus_num
                assert ti.sec_bus_num <= ci.sec_bus_num and ci.sub_bus_num <= ti.sub_bus_num
                bus_regions.append((ci.sec_bus_num, ci.sub_bus_num))
                if ci.io_base:
                    assert ti.io_base <= ci.io_base and ci.io_limit <= ti.io_limit
                    io_regions.append((ci.io_base, ci.io_limit))
                if ci.mem_base:
                    assert ti.mem_base <= ci.mem_base and ci.mem_limit <= ti.mem_limit
                    mem_regions.append((ci.mem_base, ci.mem_limit))
                if ci.prefetchable_mem_base:
                    assert (ti.prefetchable_mem_base <= ci.prefetchable_mem_base and
                        ci.prefetchable_mem_limit <= ti.prefetchable_mem_limit)
                    prefetchable_mem_regions.append((ci.prefetchable_mem_base, ci.prefetchable_mem_limit))

        # check for assignment overlaps
        for lst in [bus_regions, io_regions, mem_regions, prefetchable_mem_regions]:
            lst.sort()
            for m in range(1, len(lst)):
                assert lst[m-1][1] <= lst[m][0], "assigned regions overlap"

        # recurse into child nodes
        for ci in ti:
            if ci.header_type & 0x7f == 0x01:
                tb.log.info("Check bridge at %s (child of bridge at %s)", ci.pcie_id, ti.pcie_id)
                check_tree(ci)

    check_tree(tb.rc.tree)


async def run_test_ep_mem(dut, ep_index=0):

    tb = TB(dut)

    await tb.rc.enumerate(enable_bus_mastering=True, configure_msi=True)
    tb.rc.log.setLevel(logging.DEBUG)

    ep = tb.ep[ep_index]
    ep.log.setLevel(logging.DEBUG)
    ti = tb.rc.tree.find_child_dev(ep.pcie_id)

    dev_bar0 = ti.bar_window[0]
    dev_bar1 = ti.bar_window[1]
    dev_bar3 = ti.bar_window[3]

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (32-bit BAR) length: %d offset: %d", length, offset)
            test_data = bytearray([x % 256 for x in range(length)])

            await dev_bar0.write(offset, test_data, timeout=1000, timeout_unit='ns')
            # wait for write to complete
            await dev_bar0.read(offset, 1, timeout=1000, timeout_unit='ns')
            assert await ep.read_region(0, offset, length) == test_data

            assert await dev_bar0.read(offset, length, timeout=1000, timeout_unit='ns') == test_data

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (64-bit BAR) length: %d offset: %d", length, offset)
            test_data = bytearray([x % 256 for x in range(length)])

            await dev_bar1.write(offset, test_data, timeout=1000, timeout_unit='ns')
            # wait for write to complete
            await dev_bar1.read(offset, 1, timeout=1000, timeout_unit='ns')
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

    await tb.rc.enumerate(enable_bus_mastering=True, configure_msi=True)
    tb.rc.log.setLevel(logging.DEBUG)

    ep1 = tb.ep[ep1_index]
    ep1.log.setLevel(logging.DEBUG)
    ep2 = tb.ep[ep2_index]
    ep2.log.setLevel(logging.DEBUG)
    ti2 = tb.rc.tree.find_child_dev(ep2.pcie_id)

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (32-bit BAR) length: %d offset: %d", length, offset)
            addr = ti2.bar_addr[0]+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await ep1.mem_write(addr, test_data, timeout=1000, timeout_unit='ns')
            # wait for write to complete
            await ep1.mem_read(addr, 1, timeout=1000, timeout_unit='ns')
            assert await ep2.read_region(0, offset, length) == test_data

            assert await ep1.mem_read(addr, length, timeout=1000, timeout_unit='ns') == test_data

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (64-bit BAR) length: %d offset: %d", length, offset)
            addr = ti2.bar_addr[1]+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await ep1.mem_write(addr, test_data, timeout=1000, timeout_unit='ns')
            # wait for write to complete
            await ep1.mem_read(addr, 1, timeout=1000, timeout_unit='ns')
            assert await ep2.read_region(1, offset, length) == test_data

            assert await ep1.mem_read(addr, length, timeout=1000, timeout_unit='ns') == test_data

    for length in list(range(0, 8)):
        for offset in list(range(8)):
            tb.log.info("IO operation length: %d offset: %d", length, offset)
            addr = ti2.bar_addr[3]+offset
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

    await tb.rc.enumerate(enable_bus_mastering=True, configure_msi=True)
    tb.rc.log.setLevel(logging.DEBUG)

    ep = tb.ep[ep_index]
    ep.log.setLevel(logging.DEBUG)

    for length in list(range(0, 32))+[1024]:
        for offset in list(range(8))+list(range(4096-8, 4096)):
            tb.log.info("Memory operation (DMA) length: %d offset: %d", length, offset)
            addr = mem_base+offset
            test_data = bytearray([x % 256 for x in range(length)])

            await ep.mem_write(addr, test_data, timeout=1000, timeout_unit='ns')
            # wait for write to complete
            await ep.mem_read(addr, 1, timeout=1000, timeout_unit='ns')
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

    await tb.rc.enumerate(enable_bus_mastering=True, configure_msi=True)
    tb.rc.log.setLevel(logging.DEBUG)

    ep = tb.ep[ep_index]
    ep.log.setLevel(logging.DEBUG)

    for k in range(32):
        tb.log.info("Send MSI %d", k)

        await ep.msi_cap.issue_msi_interrupt(k)

        event = tb.rc.msi_get_event(ep.pcie_id, k)
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
