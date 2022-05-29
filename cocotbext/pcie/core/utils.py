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
