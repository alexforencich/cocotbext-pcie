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

from .common import PciCapId, PciCap


class PmCapability(PciCap):
    """Power Management capability"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cap_id = PciCapId.PM
        self.length = 2

        # Power management capability registers
        # Power management capabilities
        self.version = 3
        self.pme_clock = False
        self.immediate_readiness_on_return_to_d0 = False
        self.device_specific_initialization = False
        self.aux_current = False
        self.d1_support = False
        self.d2_support = False
        self.pme_support = 0
        # Power management control/status
        self.power_state = 0
        self.no_soft_reset = False
        self.pme_enable = False
        self.data_select = 0
        self.data_scale = 0
        self.pme_status = False
        # PM data
        self.pm_data = 0

    """
    PCI Power Management Capability

    31                                                                  0
    +---------------------------------+----------------+----------------+
    |         PM Capabilities         |    Next Cap    |     PM Cap     |   0   0x00
    +----------------+----------------+----------------+----------------+
    |    PM Data     |                |        PM Control/Status        |   1   0x04
    +----------------+----------------+---------------------------------+
    """
    async def _read_register(self, reg):
        if reg == 0:
            # Power management capabilities
            val = 3 << 16
            val |= bool(self.pme_clock) << 19
            val |= bool(self.immediate_readiness_on_return_to_d0) << 20
            val |= bool(self.device_specific_initialization) << 21
            val |= (self.aux_current & 0x7) << 22
            val |= bool(self.d1_support) << 25
            val |= bool(self.d2_support) << 26
            val |= (self.pme_support & 0x1f) << 27
            return val
        elif reg == 1:
            # Power management control/status
            val = self.power_state & 0x3
            val |= bool(self.no_soft_reset) << 3
            val |= bool(self.pme_enable) << 8
            val |= (self.data_select & 0xf) << 9
            val |= (self.data_scale & 0x3) << 13
            val |= bool(self.pme_status) << 15
            # PM data
            val |= (self.pm_data & 0xff) << 24
            return val
        else:
            return 0

    async def _write_register(self, reg, data, mask):
        if reg == 1:
            # Power management control/status
            if mask & 0x1:
                self.power_state = data & 0x3
            if mask & 0x2:
                self.pme_enable = bool(data & 1 << 8)
                self.data_select = (data >> 9) & 0xf
                self.data_scale = (data >> 13) & 0x3
                if data & 1 << 15:
                    self.pme_status = False
