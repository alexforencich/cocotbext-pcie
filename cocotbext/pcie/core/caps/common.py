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

import enum


# PCI capability IDs
class PciCapId(enum.IntEnum):
    NULL    = 0x00  # Null capability
    PM      = 0x01  # Power Management
    AGP     = 0x02  # Accelerated Graphics Port
    VPD     = 0x03  # Vital Product Data
    SLOTID  = 0x04  # Slot Identification
    MSI     = 0x05  # Message Signalled Interrupts
    CHSWP   = 0x06  # CompactPCI HotSwap
    PCIX    = 0x07  # PCI-X
    HT      = 0x08  # HyperTransport
    VNDR    = 0x09  # Vendor specific
    DBG     = 0x0A  # Debug port
    CCRC    = 0x0B  # CompactPCI Central Resource Control
    SHPC    = 0x0C  # PCI Standard Hot-Plug Controller
    SSVID   = 0x0D  # Bridge subsystem vendor/device ID
    AGP3    = 0x0E  # AGP Target PCI-PCI bridge
    SEC     = 0x0F  # Secure device
    EXP     = 0x10  # PCI Express
    MSIX    = 0x11  # MSI-X
    SATA    = 0x12  # SATA data/index configuration
    AF      = 0x13  # PCI Advanced Features
    EA      = 0x14  # Enhanced allocation
    FPB     = 0x15  # Flattening portal bridge


class PciExtCapId(enum.IntEnum):
    NULL    = 0x0000  # Null capability
    AER     = 0x0001  # Advanced Error Reporting
    VC      = 0x0002  # Virtual Channel
    DSN     = 0x0003  # Device Serial Number
    PWR     = 0x0004  # Power budgeting capability
    RCLD    = 0x0005  # Root Complex Link Declaration
    RCILC   = 0x0006  # Root Complex Internal Link Control
    RCEC    = 0x0007  # Root Complex Event Collector endpoint association
    MFVC    = 0x0008  # Multi-Function Virtual Channel
    VC2     = 0x0009  # Virtual Channel (alternate ID)
    RCRB    = 0x000A  # Root Complex Register Block
    VSEC    = 0x000B  # Vendor Specific
    CAC     = 0x000C  # Configuration Access Correlation
    ACS     = 0x000D  # Access Control Services
    ARI     = 0x000E  # Alternative Routing ID
    ATS     = 0x000F  # Address Translation Services
    SRIOV   = 0x0010  # Single-Root IO Virtualization (SR-IOV)
    MRIOV   = 0x0011  # Multi-Root IO Virtualization (MR-IOV)
    MCAST   = 0x0012  # Multicast
    PRI     = 0x0013  # Page Request Interface
    RBAR    = 0x0015  # Resizable BAR
    DPA     = 0x0016  # Dynamic power allocation
    TPH     = 0x0017  # TPH requester
    LTR     = 0x0018  # Latency tolerance reporting
    EXP2    = 0x0019  # Secondary PCI express
    PMUX    = 0x001A  # Protocol Multiplexing
    PASID   = 0x001B  # Process address space ID
    LNR     = 0x001C  # LN requester
    DPC     = 0x001D  # Downstream port containment
    L1PM    = 0x001E  # L1 PM substates
    PTM     = 0x001F  # Precision Time Measurement
    MPCIE   = 0x0020  # PCI express over M-PHY
    FRSQ    = 0x0021  # Function readiness status queueing
    RTR     = 0x0022  # Readiness time reporting
    DVSEC   = 0x0023  # Designated vendor-specific
    VFRBAR  = 0x0024  # VF resizable BAR
    DLF     = 0x0025  # Data Link Feature
    PHY16   = 0x0026  # PHY 16.0 GT/s
    LM      = 0x0027  # Lane margining at the receiver
    HID     = 0x0028  # Hierarchy ID
    NPEM    = 0x0029  # Native PCIe enclosure management
    PHY32   = 0x002A  # PHY 32.0 GT/s
    AP      = 0x002B  # Alternate Protocol
    SFI     = 0x002C  # System Firmware Intermediary


class PciCap:
    def __init__(self, *args, **kwargs):
        self.cap_id = PciCapId.NULL
        self.cap_ver = 0
        self.length = 1
        self.offset = None
        self.next_cap = 0
        self.parent = None

        super().__init__(*args, **kwargs)

    async def read_register(self, reg):
        val = await self._read_register(reg)
        if reg == 0:
            val = (val & 0xffff0000) | ((self.next_cap & 0xff) << 8) | (self.cap_id & 0xff)
        return val

    async def write_register(self, reg, data, mask):
        await self._write_register(reg, data, mask)

    async def _read_register(self, reg):
        raise NotImplementedError()

    async def _write_register(self, reg, data, mask):
        raise NotImplementedError()

    def __repr__(self):
        return (
            f"{type(self).__name__}(cap_id={self.cap_id:#x}, "
            f"cap_ver={self.cap_ver}, "
            f"length={self.length}, "
            f"offset={self.offset}, "
            f"next_cap={self.next_cap})"
        )


class PciExtCap(PciCap):
    async def read_register(self, reg):
        if reg == 0:
            return ((self.next_cap & 0xfff) << 20) | ((self.cap_ver & 0xf) << 16) | (self.cap_id & 0xffff)
        return await self._read_register(reg)


class PciCapList:
    def __init__(self):
        self.cap_type = PciCap
        self.list = []
        self.start = 0x10
        self.end = 0x3f

    def find_by_id(self, cap_id):
        for cap in self.list:
            if cap.cap_id == cap_id:
                return cap
        return None

    def find_by_reg(self, reg):
        for cap in self.list:
            if cap.offset <= reg < cap.offset+cap.length:
                return cap
        return None

    async def read_register(self, reg):
        cap = self.find_by_reg(reg)
        if cap:
            return await cap.read_register(reg-cap.offset)
        return 0

    async def write_register(self, reg, data, mask):
        cap = self.find_by_reg(reg)
        if cap:
            await cap.write_register(reg-cap.offset, data, mask)

    def register(self, cap, offset=None):
        if not isinstance(cap, self.cap_type):
            cap = self.find_by_id(cap)
            if not cap:
                raise Exception("Capability not found")

        # remove from list
        if cap in self.list:
            self.list.remove(cap)

        # update parameters
        if offset is not None:
            cap.offset = offset

        bump_list = []

        if cap.offset:
            for c in self.list:
                if c.offset <= cap.offset+cap.length-1 and cap.offset <= c.offset+c.length-1:
                    bump_list.append(c)
            for c in bump_list:
                self.list.remove(c)
        else:
            cap.offset = self.start
            for c in self.list:
                if c.offset < cap.offset+cap.length-1 and cap.offset <= c.offset+c.length-1:
                    cap.offset = c.offset+c.length

        self.list.append(cap)

        self._build_linked_list()

        # re-insert bumped caps
        for c in bump_list:
            c.offset = None
            self.register(c)

    def deregister(self, cap):
        if cap in self.list:
            self.list.remove(cap)

        self._build_linked_list()

    def _build_linked_list(self):
        # sort list by offset
        self.list.sort(key=lambda x: x.offset)

        # update list next cap pointers
        for k in range(1, len(self.list)):
            self.list[k-1].next_cap = self.list[k].offset*4
            self.list[k].next_cap = 0


class PciExtCapList(PciCapList):
    def __init__(self):
        super().__init__()
        self.cap_type = PciExtCap
        self.start = 0x40
        self.end = 0x3ff
