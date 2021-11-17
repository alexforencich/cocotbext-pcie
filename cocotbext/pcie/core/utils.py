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

from collections import namedtuple

from .caps import PcieCapId, PcieExtCapId


def align(val, mask):
    if val & mask:
        return val + mask + 1 - (val & mask)
    else:
        return val


def byte_mask_update(old, mask, new, bitmask=-1):
    new = (new & bitmask) | (old & ~bitmask)
    m1 = 1
    m2 = 0xff
    while mask >= m1:
        if mask & m1:
            old = (old & ~m2) | (new & m2)
        m1 <<= 1
        m2 <<= 8
    return old


class PcieId(namedtuple("PcieId", ["bus", "device", "function"])):
    def __new__(cls, bus=0, device=0, function=0):
        if not isinstance(bus, int):
            bus, device, function = bus

        if bus < 0 or bus > 255:
            raise ValueError("Bus number out of range")
        if device < 0 or device > 31:
            raise ValueError("Device number out of range")
        if function < 0 or function > 7:
            raise ValueError("Function number out of range")

        return super().__new__(cls, bus, device, function)

    @classmethod
    def from_int(cls, val):
        return cls((val >> 8) & 0xff, (val >> 3) & 0x1f, val & 0x7)

    def _replace(self, **kwargs):
        return type(self)(**dict(self._asdict(), **kwargs))

    def __int__(self):
        return ((self.bus & 0xff) << 8) | ((self.device & 0x1f) << 3) | (self.function & 0x7)

    def __str__(self):
        return f"{self.bus:02x}:{self.device:02x}.{self.function:x}"

    def __repr__(self):
        return f"{type(self).__name__}({self.bus}, {self.device}, {self.function})"


class TreeItem:
    def __init__(self):
        self._pcie_id = PcieId()

        self.header_type = 0
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

        self.io_base = 0
        self.io_limit = 0
        self.mem_base = 0
        self.mem_limit = 0
        self.prefetchable_mem_base = 0
        self.prefetchable_mem_limit = 0

        self.capabilities = []
        self.ext_capabilities = []

        self.msi_count = 0
        self.msi_addr = None
        self.msi_data = None

        self.children = []

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

    def find_child_dev(self, dev_id):
        if dev_id == self.pcie_id:
            return self
        for c in self.children:
            res = c.find_child_dev(dev_id)
            if res is not None:
                return res
        return None

    def get_capability_offset(self, cap_id):
        if isinstance(cap_id, PcieCapId):
            for c in self.capabilities:
                if c[0] == cap_id:
                    return c[1]
        elif isinstance(cap_id, PcieExtCapId):
            for c in self.ext_capabilities:
                if c[0] == cap_id:
                    return c[1]
        return None

    def to_str(self, prefix=""):
        s = ""

        if self.sub_bus_num > self.sec_bus_num:
            s += f"[{self.sec_bus_num:02x}-{self.sub_bus_num:02x}]-"
            prefix += " "*8
        else:
            s += f"[{self.sec_bus_num:02x}]-"
            prefix += " "*5

        for i in range(len(self.children)):
            c = self.children[i]

            if i > 0:
                s += prefix

            if len(self.children) == 1:
                s += "-"
            elif len(self.children)-1 == i:
                s += "\\"
            else:
                s += "+"

            s += f"-{c.device_num:02x}.{c.function_num:x}"

            if c.children:
                if i < len(self.children)-1:
                    s += "-"+c.to_str(prefix+"|"+" "*6).strip()
                else:
                    s += "-"+c.to_str(prefix+" "*7).strip()

            s += '\n'

        return s

    def __bool__(self):
        return True

    def __getitem__(self, key):
        return self.children[key]

    def __iter__(self):
        return self.children.__iter__()

    def __len__(self):
        return len(self.children)
