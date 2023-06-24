"""

Copyright (c) 2022 Alex Forencich

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

from cocotb.triggers import Timer

from .caps import PciCapId, PciExtCapId
from .utils import PcieId, align


class PciHostBridge:
    def __init__(self, rc):
        self.rc = rc

        self.bus_num = 0

        self.bus = PciBus(None, self, self.bus_num, rc=rc)

        self.pri_bus_num = 0
        self.sec_bus_num = 0
        self.sub_bus_num = 0xff

        self.io_base = 0
        self.io_limit = 0
        self.mem_base = 0
        self.mem_limit = 0
        self.prefetchable_mem_base = 0
        self.prefetchable_mem_limit = 0

        self.max_payload_size = 0
        self.max_payload_size_supported = 5
        self.max_read_request_size = 2

    def find_device(self, pcie_id):
        return self.bus.find_device(pcie_id)

    async def probe(self, timeout=1000, timeout_unit='ns'):
        await self.scan(timeout=timeout, timeout_unit=timeout_unit)
        await self.assign_resources()

    async def scan(self, timeout=1000, timeout_unit='ns'):
        last_bus = await self.bus.scan(timeout=timeout, timeout_unit=timeout_unit)
        self.bus.last_bus_num = last_bus

    async def assign_resources(self):
        await self.bus.assign_resources()

    def to_str(self):
        return self.bus.to_str()


class PciBus:
    def __init__(self, parent, bridge, bus_num, rc=None):
        self.rc = rc

        if parent:
            self.rc = parent.rc
        elif bridge:
            self.rc = bridge.rc

        # parent bus
        self.parent = parent

        # child buses
        self.children = []
        # devices on this bus
        self.devices = []

        # bridge device
        self.bridge = bridge

        if bridge:
            bridge.subordinate = self

        self.primary = 0
        self.bus_num = bus_num
        self.last_bus_num = 0xff

        if parent:
            self.primary = self.parent.bus_num

    def is_root(self):
        return not self.parent

    def find_device(self, pcie_id):
        for dev in self.devices:
            if dev.pcie_id == pcie_id:
                return dev
        for child in self.children:
            dev = child.find_device(pcie_id)
            if dev:
                return dev
        return None

    def only_one_child(self):
        if isinstance(self.bridge, PciHostBridge):
            return False
        if self.bridge.is_pcie() and self.bridge.is_downstream_port():
            return True
        return False

    async def wait_crs(self, dev_id, timeout=1000, timeout_unit='ns'):
        delay = 10
        val = 0xffff0001
        while val == 0xffff0001:
            if delay > 10000:
                self.rc.log.warning("pci %s: not ready after %d us; giving up", dev_id, delay)
                return False

            if delay > 1000:
                self.rc.log.info("pci %s: not ready after %d us; waiting", dev_id, delay)

            await Timer(delay, 'us')
            delay *= 2

            val = await self.rc.config_read_dword(dev_id, 0x000, 'little', timeout, timeout_unit)

        if delay > 1000:
            self.rc.log.info("pci %s: ready after %d us", dev_id, delay)

        return True

    async def scan(self, available_buses=0, timeout=1000, timeout_unit='ns'):
        first_bus = self.bus_num
        last_bus = first_bus

        # scan for devices
        for d in range(32):
            if self.bus_num == 0 and d == 0:
                continue

            dev_id = PcieId(self.bus_num, d, 0)

            self.rc.log.info("Enumerating bus %d device %d", self.bus_num, d)

            # read vendor ID and device ID
            val = await self.rc.config_read_dword(dev_id, 0x000, 'little', timeout, timeout_unit)

            if val in {0, 0xffffffff, 0xffff0000, 0x0000ffff}:
                continue

            if val == 0xffff0001:
                if not await self.wait_crs(dev_id, timeout, timeout_unit):
                    continue

            # valid vendor ID
            self.rc.log.info("Found device at %s", dev_id)

            for f in range(8):
                dev_id = PcieId(self.bus_num, d, f)

                # read vendor ID and device ID
                val = await self.rc.config_read_dword(dev_id, 0x000, 'little', timeout, timeout_unit)

                if val is None or val == 0xffffffff:
                    continue

                dev = PciDevice(self)
                dev.pcie_id = dev_id
                dev.vendor_id = val & 0xffff
                dev.device_id = (val >> 16) & 0xffff
                self.devices.append(dev)

                await dev.setup()

                if not dev.multifunction:
                    # only one function
                    break

            if self.only_one_child():
                break

        # recurse into bridges
        for dev in self.devices:
            if not dev.is_bridge():
                continue

            last_bus = await self.scan_bridge(dev, last_bus, timeout=timeout, timeout_unit=timeout_unit)

        return last_bus

    async def scan_bridge(self, dev, first_bus, available_buses=0, timeout=1000, timeout_unit='ns'):
        last_bus = first_bus

        self.rc.log.info("Scanning bridge %s", dev.pcie_id)

        await dev.enable_crs()

        next_bus = last_bus + 1

        child = PciBus(self, dev, next_bus)
        self.children.append(child)

        buses = await dev.config_read_dword(0x018)

        buses = (buses & 0xff000000) | (child.primary << 0) | (child.bus_num << 8) | (child.last_bus_num << 16)

        await dev.config_write_dword(0x018, buses)

        last_bus = await child.scan(timeout=timeout, timeout_unit=timeout_unit)

        child.last_bus_num = last_bus

        buses = (buses & 0xff000000) | (child.primary << 0) | (child.bus_num << 8) | (child.last_bus_num << 16)

        await dev.config_write_dword(0x018, buses)

        return last_bus

    async def assign_resources(self):
        for dev in self.devices:
            await dev.assign_resources()

            if dev.subordinate:
                dev.io_base = self.bridge.io_limit
                dev.io_limit = dev.io_base
                dev.mem_base = self.bridge.mem_limit
                dev.mem_limit = dev.mem_base
                dev.prefetchable_mem_base = self.bridge.prefetchable_mem_limit
                dev.prefetchable_mem_limit = dev.prefetchable_mem_base

                await dev.subordinate.assign_resources()

                # align limits against bridge registers
                dev.io_limit = align(dev.io_limit, 0xfff)
                dev.mem_limit = align(dev.mem_limit, 0xfffff)
                dev.prefetchable_mem_limit = align(dev.prefetchable_mem_limit, 0xfffff)

                self.bridge.io_limit = dev.io_limit
                self.bridge.mem_limit = dev.mem_limit
                self.bridge.prefetchable_mem_limit = dev.prefetchable_mem_limit

                dev.io_limit -= 1
                dev.mem_limit -= 1
                dev.prefetchable_mem_limit -= 1

                await dev.setup_bridge()

    def to_str(self, prefix=""):
        s = ""

        if self.last_bus_num > self.bus_num:
            s += f"[{self.bus_num:02x}-{self.last_bus_num:02x}]-"
            prefix += " "*8
        else:
            s += f"[{self.bus_num:02x}]-"
            prefix += " "*5

        for i in range(len(self.devices)):
            c = self.devices[i]

            if i > 0:
                s += prefix

            if len(self.devices) == 1:
                s += "-"
            elif len(self.devices)-1 == i:
                s += "\\"
            else:
                s += "+"

            s += f"-{c.device_num:02x}.{c.function_num:x}"

            if c.subordinate:
                if i < len(self.devices)-1:
                    s += "-"+c.subordinate.to_str(prefix+"|"+" "*6).strip()
                else:
                    s += "-"+c.subordinate.to_str(prefix+" "*7).strip()

            s += '\n'

        return s


class PciDevice:
    def __init__(self, bus, rc=None):
        self.rc = rc
        self._pcie_id = PcieId()

        if bus is not None:
            self.rc = bus.rc

        self.bus = bus
        self.subordinate = None

        self.hdr_type = 0
        self.multifunction = False
        self.class_code = 0
        self.revision_id = 0

        self.vendor_id = 0
        self.device_id = 0
        self.subsystem_vendor_id = 0
        self.subsystem_id = 0

        self.pri_bus_num = 0
        self.sec_bus_num = 0
        self.sub_bus_num = 0

        self.bar = [None]*6
        self.bar_raw = [None]*6
        self.bar_addr = [None]*6
        self.bar_size = [None]*6
        self.bar_window = [None]*6

        self.expansion_rom_raw = None
        self.expansion_rom_addr = None
        self.expansion_rom_size = None
        self.expansion_rom_window = None

        self.io_base = 0
        self.io_limit = 0
        self.mem_base = 0
        self.mem_limit = 0
        self.prefetchable_mem_base = 0
        self.prefetchable_mem_limit = 0

        self.capabilities = []
        self.ext_capabilities = []

        self.enable_cnt = 0
        self.is_busmaster = False

        self.pcie_capabilities_reg = 0
        self.pcie_devcap_reg = 0
        self.pcie_mpss = 0

        self.msix_enabled = False
        self.msi_enabled = False
        self.msi_vectors = []

    @property
    def pcie_id(self):
        return self._pcie_id

    @pcie_id.setter
    def pcie_id(self, val):
        self._pcie_id = PcieId(val)

    @property
    def bus_num(self):
        return self._pcie_id.bus

    @bus_num.setter
    def bus_num(self, value):
        self._pcie_id.bus = value

    @property
    def device_num(self):
        return self._pcie_id.device

    @device_num.setter
    def device_num(self, value):
        self._pcie_id.device = value

    @property
    def function_num(self):
        return self._pcie_id.function

    @function_num.setter
    def function_num(self, value):
        self._pcie_id.function = value

    def is_enabled(self):
        return self.enable_cnt > 0

    def is_bridge(self):
        return self.header_type in {0x01, 0x02}

    def is_pcie(self):
        return bool(self.get_capability_offset(PciCapId.EXP))

    def pcie_type(self):
        return (self.pcie_capabilities_reg >> 4) & 0xf

    def is_downstream_port(self):
        return self.pcie_type() in {0x4, 0x6, 0x8}

    def upstream_bridge(self):
        if self.bus.is_root():
            return None
        return self.bus.bridge

    def get_capability_offset(self, cap_id):
        if isinstance(cap_id, PciCapId):
            for c in self.capabilities:
                if c[0] == cap_id:
                    return c[1]
        elif isinstance(cap_id, PciExtCapId):
            for c in self.ext_capabilities:
                if c[0] == cap_id:
                    return c[1]
        return None

    async def config_read(self, addr, length, timeout=0, timeout_unit='ns'):
        return await self.rc.config_read(self.pcie_id, addr, length, timeout, timeout_unit)

    async def config_read_words(self, addr, count, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        data = await self.config_read(addr, count*ws, timeout, timeout_unit)
        words = []
        for k in range(count):
            words.append(int.from_bytes(data[ws*k:ws*(k+1)], byteorder))
        return words

    async def config_read_dwords(self, addr, count, byteorder='little', timeout=0, timeout_unit='ns'):
        return await self.config_read_words(addr, count, byteorder, 4, timeout, timeout_unit)

    async def config_read_qwords(self, addr, count, byteorder='little', timeout=0, timeout_unit='ns'):
        return await self.config_read_words(addr, count, byteorder, 8, timeout, timeout_unit)

    async def config_read_byte(self, addr, timeout=0, timeout_unit='ns'):
        return (await self.config_read(addr, 1, timeout, timeout_unit))[0]

    async def config_read_word(self, addr, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        return (await self.config_read_words(addr, 1, byteorder, ws, timeout, timeout_unit))[0]

    async def config_read_dword(self, addr, byteorder='little', timeout=0, timeout_unit='ns'):
        return (await self.config_read_dwords(addr, 1, byteorder, timeout, timeout_unit))[0]

    async def config_read_qword(self, addr, byteorder='little', timeout=0, timeout_unit='ns'):
        return (await self.config_read_qwords(addr, 1, byteorder, timeout, timeout_unit))[0]

    async def config_write(self, addr, data, timeout=0, timeout_unit='ns'):
        return await self.rc.config_write(self.pcie_id, addr, data, timeout, timeout_unit)

    async def config_write_words(self, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        words = data
        data = bytearray()
        for w in words:
            data.extend(w.to_bytes(ws, byteorder))
        await self.config_write(addr, data, timeout, timeout_unit)

    async def config_write_dwords(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.config_write_words(addr, data, byteorder, 4, timeout, timeout_unit)

    async def config_write_qwords(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.config_write_words(addr, data, byteorder, 8, timeout, timeout_unit)

    async def config_write_byte(self, addr, data, timeout=0, timeout_unit='ns'):
        await self.config_write(addr, [data], timeout, timeout_unit)

    async def config_write_word(self, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        await self.config_write_words(addr, [data], byteorder, ws, timeout, timeout_unit)

    async def config_write_dword(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.config_write_dwords(addr, [data], byteorder, timeout, timeout_unit)

    async def config_write_qword(self, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.config_write_qwords(addr, [data], byteorder, timeout, timeout_unit)

    async def capability_read(self, cap_id, addr, length, timeout=0, timeout_unit='ns'):
        offset = self.get_capability_offset(cap_id)

        if not offset:
            raise Exception("Capability not found")

        return await self.config_read(addr+offset, length, timeout, timeout_unit)

    async def capability_read_words(self, cap_id, addr, count, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        data = await self.capability_read(cap_id, addr, count*ws, timeout, timeout_unit)
        words = []
        for k in range(count):
            words.append(int.from_bytes(data[ws*k:ws*(k+1)], byteorder))
        return words

    async def capability_read_dwords(self, cap_id, addr, count, byteorder='little', timeout=0, timeout_unit='ns'):
        return await self.capability_read_words(cap_id, addr, count, byteorder, 4, timeout, timeout_unit)

    async def capability_read_qwords(self, cap_id, addr, count, byteorder='little', timeout=0, timeout_unit='ns'):
        return await self.capability_read_words(cap_id, addr, count, byteorder, 8, timeout, timeout_unit)

    async def capability_read_byte(self, cap_id, addr, timeout=0, timeout_unit='ns'):
        return (await self.capability_read(cap_id, addr, 1, timeout, timeout_unit))[0]

    async def capability_read_word(self, cap_id, addr, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        return (await self.capability_read_words(cap_id, addr, 1, byteorder, ws, timeout, timeout_unit))[0]

    async def capability_read_dword(self, cap_id, addr, byteorder='little', timeout=0, timeout_unit='ns'):
        return (await self.capability_read_dwords(cap_id, addr, 1, byteorder, timeout, timeout_unit))[0]

    async def capability_read_qword(self, cap_id, addr, byteorder='little', timeout=0, timeout_unit='ns'):
        return (await self.capability_read_qwords(cap_id, addr, 1, byteorder, timeout, timeout_unit))[0]

    async def capability_write(self, cap_id, addr, data, timeout=0, timeout_unit='ns'):
        offset = self.get_capability_offset(cap_id)

        if not offset:
            raise Exception("Capability not found")

        await self.config_write(addr+offset, data, timeout, timeout_unit)

    async def capability_write_words(self, cap_id, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        words = data
        data = bytearray()
        for w in words:
            data.extend(w.to_bytes(ws, byteorder))
        await self.capability_write(cap_id, addr, data, timeout, timeout_unit)

    async def capability_write_dwords(self, cap_id, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.capability_write_words(cap_id, addr, data, byteorder, 4, timeout, timeout_unit)

    async def capability_write_qwords(self, cap_id, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.capability_write_words(cap_id, addr, data, byteorder, 8, timeout, timeout_unit)

    async def capability_write_byte(self, cap_id, addr, data, timeout=0, timeout_unit='ns'):
        await self.capability_write(cap_id, addr, [data], timeout, timeout_unit)

    async def capability_write_word(self, cap_id, addr, data, byteorder='little', ws=2, timeout=0, timeout_unit='ns'):
        await self.capability_write_words(cap_id, addr, [data], byteorder, ws, timeout, timeout_unit)

    async def capability_write_dword(self, cap_id, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.capability_write_dwords(cap_id, addr, [data], byteorder, timeout, timeout_unit)

    async def capability_write_qword(self, cap_id, addr, data, byteorder='little', timeout=0, timeout_unit='ns'):
        await self.capability_write_qwords(cap_id, addr, [data], byteorder, timeout, timeout_unit)

    async def enable_bridge(self):
        bridge = self.upstream_bridge()
        if bridge:
            await bridge.enable_bridge()

        if self.is_enabled():
            if not self.is_busmaster:
                self.set_master()
            return

        await self.enable_device()
        await self.set_master()

    async def enable_device(self):
        self.enable_cnt += 1
        if self.enable_cnt > 1:
            return

        bridge = self.upstream_bridge()
        if bridge:
            await bridge.enable_bridge()

        bars = 0  # TODO

        await self.enable_resources(bars)

    async def enable_resources(self, mask):
        old_cmd = await self.config_read_word(0x04)
        cmd = old_cmd

        cmd |= (1 << 0)  # IO
        cmd |= (1 << 1)  # mem

        if cmd != old_cmd:
            self.rc.log.info("pci %s: enabling device (%04x -> %04x)", self.pcie_id, old_cmd, cmd)
            await self.config_write_word(0x04, cmd)

    async def disable_device(self):
        self.enable_cnt -= 1

        if self.enable_cnt > 0:
            return

        await self.clear_master()

    async def set_master(self, enable=True):
        old_cmd = await self.config_read_word(0x04)

        if enable:
            cmd = old_cmd | 1 << 2
        else:
            cmd = old_cmd & ~(1 << 2)

        if cmd != old_cmd:
            self.rc.log.info("pci %s: %s bus mastering", self.pcie_id, "enabling" if enable else "disabling")
            await self.config_write_word(0x04, cmd)
        self.is_busmaster = enable

    async def clear_master(self):
        await self.set_master(False)

    async def enable_crs(self):
        if not self.is_pcie():
            return

        root_cap = await self.capability_read_dword(PciCapId.EXP, 0x1E)

        if root_cap & 0x00000001:
            old_ctrl = await self.capability_read_word(PciCapId.EXP, 0x1C)

            ctrl = old_ctrl | 0x0010

            if ctrl != old_ctrl:
                await self.capability_write_word(PciCapId.EXP, 0x1C, ctrl)

    async def configure_msi(self):
        await self.rc.configure_msi(self)

    def msi_get_event(self, number=0):
        return self.rc.msi_get_event(self, number)

    def msi_register_callback(self, callback, number=0):
        self.rc.msi_register_callback(self, callback, number)

    async def setup(self):
        # read header type
        val = await self.config_read_byte(0x00e)

        self.header_type = val & 0x7f
        self.multifunction = bool(val & 0x80)

        val = await self.config_read_dword(0x008, 'little')

        self.revision_id = val & 0xff
        self.class_code = val >> 8

        self.rc.log.info("Found function at %s", self.pcie_id)
        self.rc.log.info("Header type: 0x%02x", self.header_type)
        self.rc.log.info("Vendor ID: 0x%04x", self.vendor_id)
        self.rc.log.info("Device ID: 0x%04x", self.device_id)
        self.rc.log.info("Revision ID: 0x%02x", self.revision_id)
        self.rc.log.info("Class code: 0x%06x", self.class_code)

        if self.header_type == 0x00:
            # normal function (type 0 header)
            val = await self.config_read_dword(0x02c)
            self.subsystem_vendor_id = val & 0xffff
            self.subsystem_id = (val >> 16) & 0xffff

            self.rc.log.info("Subsystem vendor ID: 0x%04x", self.subsystem_vendor_id)
            self.rc.log.info("Subsystem ID: 0x%04x", self.subsystem_id)

            await self.read_bars(6, 0x030)
            # await self.assign_bars(6, 0x030)

        elif self.header_type == 0x01:
            # bridge (type 1 header)
            self.rc.log.info("Found bridge at %s", self.pcie_id)

            await self.read_bars(2, 0x038)
            # await self.assign_bars(2, 0x038)

        elif self.header_type == 0x02:
            # cardbus bridge (type 2 header)
            self.rc.log.info("Found cardbus bridge at %s", self.pcie_id)

        else:
            # something else
            self.rc.log.error("pci %s: unknown header type 0x%02x", self.pcie_id, self.header_type)

        await self.walk_capabilities()

        if self.is_pcie():
            self.pcie_capabilities_reg = await self.capability_read_word(PciCapId.EXP, 0x2)
            self.pcie_devcap_reg = await self.capability_read_dword(PciCapId.EXP, 0x4)
            self.pcie_mpss = self.pcie_devcap_reg & 0x7

        await self.configure_device()
        await self.init_capabilities()

    async def walk_capabilities(self):
        self.rc.log.info("Walk capabilities of function %s", self.pcie_id)

        # walk capabilities
        ptr = await self.config_read_byte(0x34)
        ptr = ptr & 0xfc

        while ptr > 0:
            val = await self.config_read(ptr, 2)

            cap_id = val[0]
            next_ptr = val[1] & 0xfc

            self.rc.log.info("pci %s: Found capability ID 0x%02x at offset 0x%02x, next ptr 0x%02x",
                self.pcie_id, cap_id, ptr, next_ptr)

            self.capabilities.append((cap_id, ptr))
            ptr = next_ptr

        # walk extended capabilities
        ptr = 0x100

        while ptr > 0:
            val = await self.config_read_dword(ptr)
            if not val or val == 0xffffffff:
                break

            cap_id = val & 0xffff
            cap_ver = (val >> 16) & 0xf
            next_ptr = (val >> 20) & 0xffc

            self.rc.log.info("pci %s: Found extended capability ID 0x%04x version %d at offset 0x%03x, next ptr 0x%03x",
                self.pcie_id, cap_id, cap_ver, ptr, next_ptr)

            self.ext_capabilities.append((cap_id, ptr))
            ptr = next_ptr

    async def configure_device(self):
        await self.configure_mps()
        await self.configure_extended_tags()
        await self.configure_serr()

    async def configure_mps(self):
        if not self.is_pcie():
            return

        if self.pcie_type() == 0x9:
            # RC integrated endpoint
            await self.set_mps(self.pcie_mpss)
            return

        if self.pcie_type() == 0x4:
            # Root port
            await self.set_mps(self.bus.bridge.max_payload_size)
            return

        bridge = self.upstream_bridge()

        if not bridge or not bridge.is_pcie():
            return

        mps = await self.get_mps()
        parent_mps = await bridge.get_mps()

        if mps == parent_mps:
            return

        if self.pcie_mpss < parent_mps and bridge.pcie_type() == 0x4:
            # adjust root port config
            await bridge.set_mps(min(self.pcie_mpss, bridge.pcie_mpss))
            self.rc.log.info("pci %s: Upstream bridge's Max Payload Size set to %d (was %d, max %x)",
                self.pcie_id, 128 << self.pcie_mpss, 128 << parent_mps, 128 << bridge.pcie_mpss)
            parent_mps = await bridge.get_mps()

        await self.set_mps(min(parent_mps, self.pcie_mpss))

        self.rc.log.info("pci %s: Max Payload Size set to %d (was %d, max %d)",
            self.pcie_id, 128 << parent_mps, 128 << mps, 128 << self.pcie_mpss)

    async def get_readrq(self):
        devctl = await self.capability_read_dword(PciCapId.EXP, 0x8)

        return (devctl >> 12) & 0x7

    async def set_readrq(self, readrq):
        if readrq < 0 or readrq > 5:
            raise ValueError()

        old_devctl = await self.capability_read_dword(PciCapId.EXP, 0x8)

        devctl = old_devctl & ~(0x7000) | (readrq << 12)

        if devctl != old_devctl:
            await self.capability_write_dword(PciCapId.EXP, 0x8, devctl)

    async def get_mps(self):
        devctl = await self.capability_read_dword(PciCapId.EXP, 0x8)

        return (devctl >> 5) & 0x7

    async def set_mps(self, mps):
        if mps < 0 or mps > 5 or mps > self.pcie_mpss:
            raise ValueError()

        old_devctl = await self.capability_read_dword(PciCapId.EXP, 0x8)

        devctl = old_devctl & ~(0x00e0) | (mps << 5)

        if devctl != old_devctl:
            await self.capability_write_dword(PciCapId.EXP, 0x8, devctl)

    async def configure_extended_tags(self):
        if not self.is_pcie():
            return

        if not self.pcie_devcap_reg & (1 << 5):
            return

        devctl = await self.capability_read_dword(PciCapId.EXP, 0x8)

        if not devctl & (1 << 8):
            self.rc.log.info("pci %s: enabling Extended Tags", self.pcie_id)
            await self.capability_write_dword(PciCapId.EXP, 0x8, devctl | (1 << 8))

    async def configure_serr(self):
        if self.header_type != 0x01:
            return

        bridge_ctrl = await self.config_read_word(0x3e)
        if not bridge_ctrl & 0x02:
            await self.config_write_word(0x3e, bridge_ctrl | 0x02)

    async def init_capabilities(self):
        await self.msi_init()
        await self.msix_init()

    async def msi_init(self):
        if not self.get_capability_offset(PciCapId.MSI):
            return

        await self.msi_set_enable(False)

    async def msi_vec_count(self):
        if not self.get_capability_offset(PciCapId.MSI):
            return -1

        ctrl = await self.capability_read_word(PciCapId.MSI, 0x02)
        return 1 << ((ctrl >> 1) & 0x7)

    async def msi_set_enable(self, enable):
        old_ctrl = await self.capability_read_word(PciCapId.MSI, 0x02)
        if enable:
            ctrl = old_ctrl | 0x0001
        else:
            ctrl = old_ctrl & ~0x0001
        if ctrl != old_ctrl:
            await self.capability_write_word(PciCapId.MSI, 0x02, ctrl)
        self.msi_enabled = enable

    async def msi_capability_init(self, nvec):
        self.rc.log.info("pci %s: configuring MSI", self.pcie_id)

        await self.msi_set_enable(False)
        self.msi_enabled = True

        if not self.msi_vectors:
            self.msi_vectors = self.rc.msi_alloc_vectors(32)

        msg_ctrl = await self.capability_read_dword(PciCapId.MSI, 0)

        msi_64bit = (msg_ctrl >> 23) & 1
        msi_mmcap = (msg_ctrl >> 17) & 7

        msi_addr = self.msi_vectors[0].addr
        msi_data = self.msi_vectors[0].data

        # message address
        await self.capability_write_dword(PciCapId.MSI, 4, msi_addr & 0xfffffffc)

        if msi_64bit:
            # 64 bit message address
            # message upper address
            await self.capability_write_dword(PciCapId.MSI, 8, (msi_addr >> 32) & 0xffffffff)
            # message data
            await self.capability_write_dword(PciCapId.MSI, 12, msi_data)

        else:
            # 32 bit message address
            # message data
            await self.capability_write_dword(PciCapId.MSI, 8, msi_data)

        # enable and set enabled messages
        msg_ctrl |= 1 << 16
        msg_ctrl = (msg_ctrl & ~(7 << 20)) | (msi_mmcap << 20)
        await self.capability_write_dword(PciCapId.MSI, 0, msg_ctrl)

        self.rc.log.info("pci %s: MSI count: %d", self.pcie_id, len(self.msi_vectors))
        self.rc.log.info("pci %s: MSI address: 0x%08x", self.pcie_id, msi_addr)
        self.rc.log.info("pci %s: MSI base data: 0x%08x", self.pcie_id, msi_data)

        await self.msi_set_enable(True)
        return 0

    async def enable_msi_range(self, min_vecs, max_vecs):
        if not self.get_capability_offset(PciCapId.MSI):
            return -1

        if self.msix_enabled:
            self.rc.log.info("pci %s: can't enable MSI (MSI-X already enabled)", self.pcie_id)
            return -1

        if max_vecs < min_vecs:
            return -1

        if self.msi_enabled:
            return -1

        nvec = await self.msi_vec_count()
        if nvec < 0:
            return nvec
        if nvec < min_vecs:
            return -1

        if nvec > max_vecs:
            nvec = max_vecs

        rc = await self.msi_capability_init(nvec)
        if rc == 0:
            return nvec
        if rc < 0:
            return rc

        return -1

    async def disable_msi(self):
        if not self.msi_enabled:
            return

        await self.msi_set_enable(False)

    async def msix_init(self):
        if not self.get_capability_offset(PciCapId.MSIX):
            return

        await self.msix_set_enable(False)

    async def msix_vec_count(self):
        if not self.get_capability_offset(PciCapId.MSIX):
            return -1

        ctrl = await self.capability_read_word(PciCapId.MSIX, 0x02)
        return (ctrl & 0x7ff) + 1

    async def msix_set_enable(self, enable):
        old_ctrl = await self.capability_read_word(PciCapId.MSIX, 0x02)
        if enable:
            ctrl = old_ctrl | 0x8000
        else:
            ctrl = old_ctrl & ~0x8000
        if ctrl != old_ctrl:
            await self.capability_write_word(PciCapId.MSIX, 0x02, ctrl)
        self.msix_enabled = enable

    async def msix_capability_init(self, nvec):
        self.rc.log.info("pci %s: configuring MSI-X", self.pcie_id)

        await self.msix_set_enable(False)
        self.msix_enabled = True

        msg_ctrl = await self.capability_read_dword(PciCapId.MSIX, 0)

        table_size = ((msg_ctrl >> 16) & 0x7ff) + 1

        table_offset = await self.capability_read_dword(PciCapId.MSIX, 4)

        table_bir = table_offset & 0x7
        table_offset &= ~0x7

        pba_offset = await self.capability_read_dword(PciCapId.MSIX, 8)

        pba_bir = pba_offset & 0x7
        pba_offset &= ~0x7

        self.rc.log.info("pci %s: MSI-X table size: %d", self.pcie_id, table_size)
        self.rc.log.info("pci %s: MSI-X table BIR: %d", self.pcie_id, table_bir)
        self.rc.log.info("pci %s: MSI-X table offset: 0x%08x", self.pcie_id, table_offset)
        self.rc.log.info("pci %s: MSI-X PBA BIR: %d", self.pcie_id, pba_bir)
        self.rc.log.info("pci %s: MSI-X PBA offset: 0x%08x", self.pcie_id, pba_offset)

        if not self.msi_vectors:
            self.msi_vectors = self.rc.msi_alloc_vectors(table_size)

        # configure vectors
        for k in range(table_size):
            addr = self.msi_vectors[k].addr
            data = self.msi_vectors[k].data
            self.rc.log.info("pci %s: Configure vector %d", self.pcie_id, k)
            await self.bar_window[table_bir].write_dword(table_offset + k*16 + 0, addr & 0xfffffffc)
            await self.bar_window[table_bir].write_dword(table_offset + k*16 + 4, (addr >> 32) & 0xffffffff)
            await self.bar_window[table_bir].write_dword(table_offset + k*16 + 8, data & 0xffffffff)
            await self.bar_window[table_bir].write_dword(table_offset + k*16 + 12, 0x00000000)

        # dummy read
        await self.bar_window[table_bir].read_dword(table_offset)

        # enable MSI-X
        msg_ctrl |= 1 << 31
        await self.capability_write_dword(PciCapId.MSIX, 0, msg_ctrl)

        await self.msix_set_enable(True)
        return 0

    async def enable_msix_range(self, min_vecs, max_vecs, flags):
        if not self.get_capability_offset(PciCapId.MSIX):
            return -1

        if self.msi_enabled:
            self.rc.log.info("pci %s: can't enable MSI-X (MSI already enabled)", self.pcie_id)
            return -1

        if max_vecs < min_vecs:
            return -1

        if self.msix_enabled:
            return -1

        nvec = await self.msix_vec_count()
        if nvec < 0:
            return nvec
        if nvec < min_vecs:
            return -1

        if nvec > max_vecs:
            nvec = max_vecs

        rc = await self.msix_capability_init(nvec)
        if rc == 0:
            return nvec
        if rc < 0:
            return rc

        return -1

    async def disable_msix(self):
        if not self.msix_enabled:
            return

        await self.msix_set_enable(False)

    async def alloc_irq_vectors(self, min_vecs, max_vecs, flags=0):
        nvecs = -1
        if 1:
            nvecs = await self.enable_msix_range(min_vecs, max_vecs, flags)
            if nvecs > 0:
                return nvecs

        if 1:
            nvecs = await self.enable_msi_range(min_vecs, max_vecs)
            if nvecs > 0:
                return nvecs

        return nvecs

    async def free_irq_vectors(self):
        await self.disable_msi()
        await self.disable_msix()

    def request_irq(self, nr, handler):
        self.msi_vectors[nr].cb.append(handler)

    async def assign_resources(self):
        if self.header_type == 0x00:
            # normal function (type 0 header)
            await self.assign_bars(6, 0x030)

        elif self.header_type == 0x01:
            # bridge (type 1 header)
            await self.assign_bars(2, 0x038)

        elif self.header_type == 0x02:
            # cardbus bridge (type 2 header)
            pass

    async def read_bars(self, bar_cnt, rom):
        # disable IO and memory decoding while probing BARs
        old_cmd = await self.config_read_word(0x04)
        cmd = old_cmd & ~((1 << 0) | (1 << 1))
        if cmd != old_cmd:
            await self.config_write_word(0x04, cmd)

        bar = 0
        while bar < bar_cnt:
            # read BAR
            orig_bar = await self.config_read_dword(0x010+bar*4)
            await self.config_write_dword(0x010+bar*4, 0xffffffff)
            val = await self.config_read_dword(0x010+bar*4)
            await self.config_write_dword(0x010+bar*4, orig_bar)

            if val == 0:
                # unimplemented BAR
                self.bar_raw[bar] = 0
                self.bar_size[bar] = 0
                bar += 1
                continue

            self.rc.log.info("Enumerate function %s BAR%d", self.pcie_id, bar)

            if val & 0x1:
                # IO BAR
                mask = (~val & 0xffffffff) | 0x3
                size = mask + 1
                self.rc.log.info("pci %s: IO BAR%d raw: 0x%08x, mask: 0x%08x, size: %d",
                    self.pcie_id, bar, val, mask, size)

                self.bar_raw[bar] = orig_bar
                self.bar_size[bar] = size

                bar += 1

            elif val & 0x4:
                # 64 bit memory BAR
                if bar >= bar_cnt-1:
                    raise Exception("Invalid BAR configuration")

                # read adjacent BAR
                orig_bar2 = await self.config_read_dword(0x010+bar*4)
                await self.config_write_dword(0x010+(bar+1)*4, 0xffffffff)
                val2 = await self.config_read_dword(0x010+(bar+1)*4)
                await self.config_write_dword(0x010+(bar+1)*4, orig_bar2)
                val |= val2 << 32
                mask = (~val & 0xffffffffffffffff) | 0xf
                size = mask + 1
                self.rc.log.info("pci %s: Mem BAR%d (64-bit) raw: 0x%016x, mask: 0x%016x, size: %d",
                    self.pcie_id, bar, val, mask, size)

                self.bar_raw[bar] = orig_bar | (orig_bar2 << 32)
                self.bar_size[bar] = size

                bar += 2

            else:
                # 32 bit memory BAR
                mask = (~val & 0xffffffff) | 0xf
                size = mask + 1
                self.rc.log.info("pci %s: Mem BAR%d (32-bit) raw: 0x%08x, mask: 0x%08x, size: %d",
                    self.pcie_id, bar, val, mask, size)

                self.bar_raw[bar] = orig_bar
                self.bar_size[bar] = size

                bar += 1

        if rom:
            # read register
            orig_bar = await self.config_read_dword(rom)
            await self.config_write_dword(rom, 0xfffff800)
            val = await self.config_read_dword(rom)
            await self.config_write_dword(rom, orig_bar)

            if val:
                self.rc.log.info("Configure function %s expansion ROM", self.pcie_id)

                mask = (~val & 0xffffffff) | 0x7ff
                size = mask + 1
                self.rc.log.info("pci %s: expansion ROM raw: 0x%08x, mask: 0x%08x, size: %d",
                    self.pcie_id, val, mask, size)

                self.expansion_rom_raw = orig_bar
                self.expansion_rom_size = size
            else:
                # not implemented
                self.expansion_rom_raw = 0
                self.expansion_rom_size = 0

    async def assign_bars(self, bar_cnt, rom):
        bar = 0
        while bar < bar_cnt:
            bar_raw = self.bar_raw[bar]
            bar_size = self.bar_size[bar]

            if bar_size == 0:
                # unimplemented BAR
                bar += 1
                continue

            self.rc.log.info("Configure function %s BAR%d", self.pcie_id, bar)

            if bar_raw & 0x1:
                # IO BAR
                self.bus.bridge.io_limit = align(self.bus.bridge.io_limit, bar_size-1)

                addr = self.bus.bridge.io_limit
                self.bus.bridge.io_limit += bar_size

                bar_raw = bar_raw & 0x3 | addr

                self.bar[bar] = bar_raw
                self.bar_raw[bar] = bar_raw
                self.bar_addr[bar] = addr
                self.bar_window[bar] = self.rc.io_address_space.create_window(addr, bar_size)

                self.rc.log.info("pci %s: IO BAR%d allocation: 0x%08x, raw: 0x%08x, size: %d",
                    self.pcie_id, bar, addr, bar_raw, bar_size)

                # write BAR
                await self.config_write_dword(0x010+bar*4, bar_raw)

                bar += 1

            elif bar_raw & 0x4:
                # 64 bit memory BAR
                if bar >= bar_cnt-1:
                    raise Exception("Invalid BAR configuration")

                if bar_raw & 0x8:
                    # prefetchable
                    # align and allocate
                    self.bus.bridge.prefetchable_mem_limit = align(self.bus.bridge.prefetchable_mem_limit, bar_size-1)
                    addr = self.bus.bridge.prefetchable_mem_limit
                    self.bus.bridge.prefetchable_mem_limit += bar_size

                else:
                    # not-prefetchable
                    self.rc.log.info("pci %s: Mem BAR%d (64-bit) marked non-prefetchable, "
                        "allocating from 32-bit non-prefetchable address space", self.pcie_id, bar)
                    # align and allocate
                    self.bus.bridge.mem_limit = align(self.bus.bridge.mem_limit, bar_size-1)
                    addr = self.bus.bridge.mem_limit
                    self.bus.bridge.mem_limit += bar_size

                bar_raw = bar_raw & 0xf | addr

                self.bar[bar] = bar_raw
                self.bar_raw[bar] = bar_raw & 0xffffffff
                self.bar_raw[bar+1] = (bar_raw >> 32) & 0xffffffff
                self.bar_addr[bar] = addr
                self.bar_window[bar] = self.rc.mem_address_space.create_window(addr, bar_size)

                self.rc.log.info("pci %s: Mem BAR%d (64-bit) allocation: 0x%016x, raw: 0x%016x, size: %d",
                    self.pcie_id, bar, addr, bar_raw, bar_size)

                # write BAR
                await self.config_write_dword(0x010+bar*4, bar_raw & 0xffffffff)
                await self.config_write_dword(0x010+(bar+1)*4, (bar_raw >> 32) & 0xffffffff)

                bar += 2

            else:
                # 32 bit memory BAR
                if bar_raw & 0x8:
                    # prefetchable
                    self.rc.log.info("pci %s: Mem BAR%d (32-bit) marked prefetchable, "
                        "but allocating as non-prefetchable", self.pcie_id, bar)

                # align and allocate
                self.bus.bridge.mem_limit = align(self.bus.bridge.mem_limit, bar_size-1)
                addr = self.bus.bridge.mem_limit
                self.bus.bridge.mem_limit += bar_size

                bar_raw = bar_raw & 0xf | addr

                self.bar[bar] = bar_raw
                self.bar_raw[bar] = bar_raw
                self.bar_addr[bar] = addr
                self.bar_window[bar] = self.rc.mem_address_space.create_window(addr, bar_size)

                self.rc.log.info("pci %s: Mem BAR%d (32-bit) allocation: 0x%08x, raw: 0x%08x, size: %d",
                    self.pcie_id, bar, addr, bar_raw, bar_size)

                # write BAR
                await self.config_write_dword(0x010+bar*4, bar_raw)

                bar += 1

        # configure expansion ROM
        if self.expansion_rom_size:
            bar_size = self.expansion_rom_size
            bar_raw = self.expansion_rom_raw

            self.rc.log.info("Configure function %s expansion ROM", self.pcie_id)

            # align and allocate
            self.bus.bridge.mem_limit = align(self.bus.bridge.mem_limit, bar_size-1)
            addr = self.bus.bridge.mem_limit
            self.bus.bridge.mem_limit += bar_size

            bar_raw = bar_raw & 0x7ff | addr

            self.expansion_rom_raw = bar_raw
            self.expansion_rom_addr = addr
            self.expansion_rom_window = self.rc.mem_address_space.create_window(addr, bar_size)

            self.rc.log.info("pci %s: expansion ROM allocation: 0x%08x, raw: 0x%08x, size: %d",
                self.pcie_id, addr, bar_raw, bar_size)

            # write register
            await self.config_write_dword(rom, bar_raw)

    async def setup_bridge(self):
        self.rc.log.info("Set IO base: 0x%08x, limit: 0x%08x", self.io_base, self.io_limit)

        await self.config_write(0x01C, struct.pack('BB',
            (self.io_base >> 8) & 0xf0, (self.io_limit >> 8) & 0xf0))
        await self.config_write(0x030, struct.pack('<HH', self.io_base >> 16, self.io_limit >> 16))

        self.rc.log.info("Set mem base: 0x%08x, limit: 0x%08x", self.mem_base, self.mem_limit)

        await self.config_write(0x020, struct.pack('<HH',
            (self.mem_base >> 16) & 0xfff0, (self.mem_limit >> 16) & 0xfff0))

        self.rc.log.info("Set prefetchable mem base: 0x%016x, limit: 0x%016x",
            self.prefetchable_mem_base, self.prefetchable_mem_limit)

        await self.config_write(0x024, struct.pack('<HH',
            (self.prefetchable_mem_base >> 16) & 0xfff0, (self.prefetchable_mem_limit >> 16) & 0xfff0))
        await self.config_write(0x028, struct.pack('<L', self.prefetchable_mem_base >> 32))
        await self.config_write(0x02c, struct.pack('<L', self.prefetchable_mem_limit >> 32))
