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

from .common import PciCapId, PciCap
from ..tlp import TlpAttr, TlpTc
from ..utils import byte_mask_update


class MsiCapability(PciCap):
    """Message-signalled interrupt capability"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cap_id = PciCapId.MSI
        self.length = 6

        # MSI Capability Registers
        self.msi_enable = False
        self.msi_multiple_message_capable = 0
        self.msi_multiple_message_enable = 0
        self.msi_64bit_address_capable = 0
        self.msi_per_vector_mask_capable = 0
        self.msi_extended_message_data_capable = 0
        self.msi_extended_message_data_enable = 0
        self.msi_message_address = 0
        self.msi_message_data = 0
        self.msi_mask_bits = 0
        self.msi_pending_bits = 0

    """
    MSI Capability (32 bit)

    31                                                                  0
    +---------------------------------+----------------+----------------+
    |         Message Control         |    Next Cap    |     Cap ID     |   0   0x00
    +---------------------------------+----------------+----------------+
    |                          Message Address                          |   1   0x04
    +---------------------------------+---------------------------------+
    |      Extended Message Data      |           Message Data          |   2   0x08
    +---------------------------------+---------------------------------+

    MSI Capability (64 bit)

    31                                                                  0
    +---------------------------------+----------------+----------------+
    |         Message Control         |    Next Cap    |     Cap ID     |   0   0x00
    +---------------------------------+----------------+----------------+
    |                          Message Address                          |   1   0x04
    +-------------------------------------------------------------------+
    |                       Message Upper Address                       |   2   0x08
    +---------------------------------+---------------------------------+
    |      Extended Message Data      |           Message Data          |   3   0x0C
    +---------------------------------+---------------------------------+

    MSI Capability (32 bit with per-vector masking)

    31                                                                  0
    +---------------------------------+----------------+----------------+
    |         Message Control         |    Next Cap    |     Cap ID     |   0   0x00
    +---------------------------------+----------------+----------------+
    |                          Message Address                          |   1   0x04
    +-------------------------------------------------------------------+
    |      Extended Message Data      |           Message Data          |   2   0x08
    +---------------------------------+---------------------------------+
    |                             Mask Bits                             |   3   0x0C
    +-------------------------------------------------------------------+
    |                           Pending Bits                            |   4   0x10
    +-------------------------------------------------------------------+

    MSI Capability (64 bit with per-vector masking)

    31                                                                  0
    +---------------------------------+----------------+----------------+
    |         Message Control         |    Next Cap    |     Cap ID     |   0   0x00
    +---------------------------------+----------------+----------------+
    |                          Message Address                          |   1   0x04
    +-------------------------------------------------------------------+
    |                       Message Upper Address                       |   2   0x08
    +---------------------------------+---------------------------------+
    |      Extended Message Data      |           Message Data          |   3   0x0C
    +---------------------------------+---------------------------------+
    |                             Mask Bits                             |   4   0x10
    +-------------------------------------------------------------------+
    |                           Pending Bits                            |   5   0x14
    +-------------------------------------------------------------------+
    """
    async def _read_register(self, reg):
        if reg == 0:
            # Message control
            val = bool(self.msi_enable) << 16
            val |= (self.msi_multiple_message_capable & 0x7) << 17
            val |= (self.msi_multiple_message_enable & 0x7) << 20
            val |= bool(self.msi_64bit_address_capable) << 23
            val |= bool(self.msi_per_vector_mask_capable) << 24
            val |= bool(self.msi_extended_message_data_capable) << 25
            val |= bool(self.msi_extended_message_data_enable) << 26
            return val
        elif reg == 1:
            # Message address
            return self.msi_message_address & 0xfffffffc
        elif reg == 2 and self.msi_64bit_address_capable:
            # Message upper address
            return (self.msi_message_address >> 32) & 0xffffffff
        elif reg == (3 if self.msi_64bit_address_capable else 2):
            # Message data
            if self.msi_extended_message_data_capable:
                return self.msi_message_data & 0xffffffff
            else:
                return self.msi_message_data & 0xffff
        elif reg == (4 if self.msi_64bit_address_capable else 3) and self.msi_per_vector_mask_capable:
            # Mask bits
            return self.msi_mask_bits & 0xffffffff
        elif reg == (5 if self.msi_64bit_address_capable else 4) and self.msi_per_vector_mask_capable:
            # Pending bits
            return self.msi_pending_bits & 0xffffffff

    async def _write_register(self, reg, data, mask):
        if reg == 0:
            # Message control
            if mask & 0x4:
                self.msi_enable = bool(data & 1 << 16)
                self.msi_multiple_message_enable = (data >> 20) & 0x7
                if self.msi_extended_message_data_capable:
                    self.msi_extended_message_data_enable = bool(data & 1 << 16)
        elif reg == 1:
            # Message address
            self.msi_message_address = byte_mask_update(self.msi_message_address, mask, data & 0xfffffffc)
        elif reg == 2 and self.msi_64bit_address_capable:
            # Message upper address
            self.msi_message_address = byte_mask_update(self.msi_message_address, mask << 4, data << 32)
        elif reg == (3 if self.msi_64bit_address_capable else 2):
            # Message data
            if self.msi_extended_message_data_capable:
                self.msi_message_data = byte_mask_update(self.msi_message_data, mask, data) & 0xffffffff
            else:
                self.msi_message_data = byte_mask_update(self.msi_message_data, mask & 0x3, data) & 0xffff
        elif reg == (4 if self.msi_64bit_address_capable else 3) and self.msi_per_vector_mask_capable:
            # Mask bits
            self.msi_mask_bits = byte_mask_update(self.msi_mask_bits, mask, data) & 0xffffffff

    async def issue_msi_interrupt(self, number=0, attr=TlpAttr(0), tc=TlpTc.TC0):
        if not self.msi_enable:
            raise Exception("MSI disabled")
        if number < 0 or number >= 2**min(self.msi_multiple_message_enable, self.msi_multiple_message_capable):
            raise ValueError("MSI message number out of range")

        if self.msi_extended_message_data_capable and self.msi_extended_message_data_enable:
            data = self.msi_message_data
        else:
            data = self.msi_message_data & 0xffff

        data = (data & ~(2**self.msi_multiple_message_enable-1)) | number
        await self.parent.mem_write(self.msi_message_address, struct.pack('<L', data), attr=attr, tc=tc)


class MsixCapability(PciCap):
    """Message-signalled interrupt capability"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cap_id = PciCapId.MSIX
        self.length = 3

        # MSI-X Capability Registers
        self.msix_table_size = 0
        self.msix_function_mask = False
        self.msix_enable = False
        self.msix_table_bar_indicator_register = 0
        self.msix_table_offset = 0
        self.msix_pba_bar_indicator_register = 0
        self.msix_pba_offset = 0

    """
    MSI-X Capability

    31                                                                  0
    +---------------------------------+----------------+----------------+
    |         Message Control         |    Next Cap    |     Cap ID     |   0   0x00
    +---------------------------------+----------------+----------+-----+
    |                         Table Offset                        | BIR |   1   0x04
    +-------------------------------------------------------------+-----+
    |                          PBA Offset                         | BIR |   2   0x08
    +-------------------------------------------------------------+-----+
    """
    async def _read_register(self, reg):
        if reg == 0:
            # Message control
            val = (self.msix_table_size & 0x7ff) << 16
            val |= bool(self.msix_function_mask) << 30
            val |= bool(self.msix_enable) << 31
            return val
        elif reg == 1:
            # Table offset and BIR
            val = self.msix_table_bar_indicator_register & 0x7
            val |= self.msix_table_offset & 0xfffffff8
            return val
        elif reg == 2:
            # Pending bit array offset and BIR
            val = self.msix_pba_bar_indicator_register & 0x7
            val |= self.msix_pba_offset & 0xfffffff8
            return val

    async def _write_register(self, reg, data, mask):
        if reg == 0:
            # Message control
            if mask & 0x8:
                self.msix_function_mask = bool(data & 1 << 30)
                self.msix_enable = bool(data & 1 << 31)

    async def issue_msix_interrupt(self, addr, data, attr=TlpAttr(0), tc=TlpTc.TC0):
        if not self.msix_enable:
            raise Exception("MSI-X disabled")

        await self.parent.mem_write(addr, struct.pack('<L', data), attr=attr, tc=tc)
