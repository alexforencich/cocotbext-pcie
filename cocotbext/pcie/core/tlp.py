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

import enum
import struct

from .utils import PcieId


# TLP formats
class TlpFmt(enum.Enum):
    THREE_DW       = 0x0
    FOUR_DW        = 0x1
    THREE_DW_DATA  = 0x2
    FOUR_DW_DATA   = 0x3
    TLP_PREFIX     = 0x4


# TLP types
class TlpType(enum.Enum):
    MEM_READ           = (TlpFmt.THREE_DW,      0x00)
    MEM_READ_64        = (TlpFmt.FOUR_DW,       0x00)
    MEM_READ_LOCKED    = (TlpFmt.THREE_DW,      0x01)
    MEM_READ_LOCKED_64 = (TlpFmt.FOUR_DW,       0x01)
    MEM_WRITE          = (TlpFmt.THREE_DW_DATA, 0x00)
    MEM_WRITE_64       = (TlpFmt.FOUR_DW_DATA,  0x00)
    IO_READ            = (TlpFmt.THREE_DW,      0x02)
    IO_WRITE           = (TlpFmt.THREE_DW_DATA, 0x02)
    CFG_READ_0         = (TlpFmt.THREE_DW,      0x04)
    CFG_WRITE_0        = (TlpFmt.THREE_DW_DATA, 0x04)
    CFG_READ_1         = (TlpFmt.THREE_DW,      0x05)
    CFG_WRITE_1        = (TlpFmt.THREE_DW_DATA, 0x05)
    MSG_TO_RC          = (TlpFmt.FOUR_DW,       0x10)
    MSG_ADDR           = (TlpFmt.FOUR_DW,       0x11)
    MSG_ID             = (TlpFmt.FOUR_DW,       0x12)
    MSG_BCAST          = (TlpFmt.FOUR_DW,       0x13)
    MSG_LOCAL          = (TlpFmt.FOUR_DW,       0x14)
    MSG_GATHER         = (TlpFmt.FOUR_DW,       0x15)
    MSG_DATA_TO_RC     = (TlpFmt.FOUR_DW_DATA,  0x10)
    MSG_DATA_ADDR      = (TlpFmt.FOUR_DW_DATA,  0x11)
    MSG_DATA_ID        = (TlpFmt.FOUR_DW_DATA,  0x12)
    MSG_DATA_BCAST     = (TlpFmt.FOUR_DW_DATA,  0x13)
    MSG_DATA_LOCAL     = (TlpFmt.FOUR_DW_DATA,  0x14)
    MSG_DATA_GATHER    = (TlpFmt.FOUR_DW_DATA,  0x15)
    CPL                = (TlpFmt.THREE_DW,      0x0A)
    CPL_DATA           = (TlpFmt.THREE_DW_DATA, 0x0A)
    CPL_LOCKED         = (TlpFmt.THREE_DW,      0x0B)
    CPL_LOCKED_DATA    = (TlpFmt.THREE_DW_DATA, 0x0B)
    FETCH_ADD          = (TlpFmt.THREE_DW_DATA, 0x0C)
    FETCH_ADD_64       = (TlpFmt.FOUR_DW_DATA,  0x0C)
    SWAP               = (TlpFmt.THREE_DW_DATA, 0x0D)
    SWAP_64            = (TlpFmt.FOUR_DW_DATA,  0x0D)
    CAS                = (TlpFmt.THREE_DW_DATA, 0x0E)
    CAS_64             = (TlpFmt.FOUR_DW_DATA,  0x0E)
    PREFIX_MRIOV       = (TlpFmt.TLP_PREFIX,    0x00)
    PREFIX_VENDOR_L0   = (TlpFmt.TLP_PREFIX,    0x0E)
    PREFIX_VENDOR_L1   = (TlpFmt.TLP_PREFIX,    0x0F)
    PREFIX_EXT_TPH     = (TlpFmt.TLP_PREFIX,    0x10)
    PREFIX_VENDOR_E0   = (TlpFmt.TLP_PREFIX,    0x1E)
    PREFIX_VENDOR_E1   = (TlpFmt.TLP_PREFIX,    0x1F)


# Message types
class MsgType(enum.IntEnum):
    UNLOCK         = 0x00
    INVALIDATE_REQ = 0x01
    INVALIDATE_CPL = 0x02
    PAGE_REQ       = 0x04
    PRG_RESP       = 0x05
    LTR            = 0x10
    OBFF           = 0x12
    PM_AS_NAK      = 0x14
    PM_PME         = 0x18
    PME_TO         = 0x19
    PME_TO_ACK     = 0x1A
    ASSERT_INTA    = 0x20
    ASSERT_INTB    = 0x21
    ASSERT_INTC    = 0x22
    ASSERT_INTD    = 0x23
    DEASSERT_INTA  = 0x24
    DEASSERT_INTB  = 0x25
    DEASSERT_INTC  = 0x26
    DEASSERT_INTD  = 0x27
    ERR_COR        = 0x30
    ERR_NONFATAL   = 0x31
    ERR_FATAL      = 0x32
    SET_SPL        = 0x50
    VENDOR_0       = 0x7e
    VENDOR_1       = 0x7f


# AT field
class TlpAt(enum.IntEnum):
    DEFAULT       = 0x0
    TRANSLATE_REQ = 0x1
    TRANSLATED    = 0x2


# Attr field
class TlpAttr(enum.IntFlag):
    NS  = 0x1  # no snoop
    RO  = 0x2  # relaxed ordering
    IDO = 0x4  # ID-based ordering


# TC field
class TlpTc(enum.IntEnum):
    TC0 = 0x0
    TC1 = 0x1
    TC2 = 0x2
    TC3 = 0x3
    TC4 = 0x4
    TC5 = 0x5
    TC6 = 0x6
    TC7 = 0x7


# Completion status
class CplStatus(enum.IntEnum):
    SC  = 0x0  # successful completion
    UR  = 0x1  # unsupported request
    CRS = 0x2  # configuration request retry status
    CA  = 0x4  # completer abort


class Tlp(object):
    def __init__(self, tlp=None):
        self.fmt = 0
        self.type = 0
        self.tc = 0
        self.th = 0
        self.td = 0
        self.ep = 0
        self.attr = 0
        self.at = 0
        self.length = 0
        self.completer_id = PcieId(0, 0, 0)
        self.status = 0
        self.bcm = 0
        self.byte_count = 0
        self.requester_id = PcieId(0, 0, 0)
        self.dest_id = PcieId(0, 0, 0)
        self.tag = 0
        self.first_be = 0
        self.last_be = 0
        self.lower_address = 0
        self.address = 0
        self.register_number = 0
        self.data = []

        if isinstance(tlp, Tlp):
            self.fmt = tlp.fmt
            self.type = tlp.type
            self.tc = tlp.tc
            self.td = tlp.td
            self.ep = tlp.ep
            self.attr = tlp.attr
            self.at = tlp.at
            self.length = tlp.length
            self.completer_id = tlp.completer_id
            self.status = tlp.status
            self.bcm = tlp.bcm
            self.byte_count = tlp.byte_count
            self.requester_id = tlp.requester_id
            self.dest_id = tlp.dest_id
            self.tag = tlp.tag
            self.first_be = tlp.first_be
            self.last_be = tlp.last_be
            self.lower_address = tlp.lower_address
            self.address = tlp.address
            self.register_number = tlp.register_number
            self.data = tlp.data

    @property
    def fmt_type(self):
        return TlpType((self.fmt, self.type))

    @fmt_type.setter
    def fmt_type(self, val):
        if isinstance(val, TlpType):
            self.fmt, self.type = val.value
        else:
            self.fmt, self.type = val

    @property
    def completer_id(self):
        return self._completer_id

    @completer_id.setter
    def completer_id(self, val):
        self._completer_id = PcieId(val)

    @property
    def requester_id(self):
        return self._requester_id

    @requester_id.setter
    def requester_id(self, val):
        self._requester_id = PcieId(val)

    @property
    def dest_id(self):
        return self._dest_id

    @dest_id.setter
    def dest_id(self, val):
        self._dest_id = PcieId(val)

    def check(self):
        """Validate TLP"""
        ret = True
        if self.fmt == TlpFmt.THREE_DW_DATA or self.fmt == TlpFmt.FOUR_DW_DATA:
            if self.length != len(self.data):
                print("TLP validation failed, length field does not match data: %s" % repr(self))
                ret = False
            if 0 > self.length > 1024:
                print("TLP validation failed, length out of range: %s" % repr(self))
                ret = False
        if (self.fmt_type == TlpType.MEM_READ or self.fmt_type == TlpType.MEM_READ_64 or
                self.fmt_type == TlpType.MEM_READ_LOCKED or self.fmt_type == TlpType.MEM_READ_LOCKED_64 or
                self.fmt_type == TlpType.MEM_WRITE or self.fmt_type == TlpType.MEM_WRITE_64):
            if self.length*4 > 0x1000 - (self.address & 0xfff):
                print("TLP validation failed, request crosses 4K boundary: %s" % repr(self))
                ret = False
        if (self.fmt_type == TlpType.IO_READ or self.fmt_type == TlpType.IO_WRITE):
            if self.length != 1:
                print("TLP validation failed, invalid length for IO request: %s" % repr(self))
                ret = False
            if self.last_be != 0:
                print("TLP validation failed, invalid last BE for IO request: %s" % repr(self))
                ret = False
        if (self.fmt_type == TlpType.CPL_DATA):
            if (self.byte_count + (self.lower_address & 3) + 3) < self.length*4:
                print("TLP validation failed, completion byte count too small: %s" % repr(self))
                ret = False
        return ret

    @classmethod
    def create_completion_for_tlp(cls, tlp, completer_id, has_data=False, status=CplStatus.SC):
        """Prepare completion for TLP"""
        cpl = cls()
        if has_data:
            cpl.fmt_type = TlpType.CPL_DATA
        else:
            cpl.fmt_type = TlpType.CPL
        cpl.requester_id = tlp.requester_id
        cpl.completer_id = completer_id
        cpl.status = status
        cpl.attr = tlp.attr
        cpl.tag = tlp.tag
        cpl.tc = tlp.tc
        return cpl

    @classmethod
    def create_completion_data_for_tlp(cls, tlp, completer_id):
        """Prepare completion with data for TLP"""
        return cls.create_completion_for_tlp(tlp, completer_id, True)

    @classmethod
    def create_ur_completion_for_tlp(cls, tlp, completer_id):
        """Prepare unsupported request (UR) completion for TLP"""
        return cls.create_completion_for_tlp(tlp, completer_id, False, CplStatus.UR)

    @classmethod
    def create_crs_completion_for_tlp(cls, tlp, completer_id):
        """Prepare configuration request retry status (CRS) completion for TLP"""
        return cls.create_completion_for_tlp(tlp, completer_id, False, CplStatus.CRS)

    @classmethod
    def create_ca_completion_for_tlp(cls, tlp, completer_id):
        """Prepare completer abort (CA) completion for TLP"""
        return cls.create_completion_for_tlp(tlp, completer_id, False, CplStatus.CA)

    def set_addr_be(self, addr, length):
        """Compute byte enables, DWORD address, and DWORD length from byte address and length"""
        self.address = addr & ~3
        first_pad = addr % 4
        last_pad = 3 - (addr+length-1) % 4
        self.length = (length+first_pad+last_pad+3) // 4
        self.first_be = (0xf << first_pad) & 0xf
        self.last_be = (0xf >> last_pad)
        if self.length == 1:
            self.first_be &= self.last_be
            self.last_be = 0

        return (first_pad, last_pad)

    def set_data(self, data):
        """Set DWORD data from byte data"""
        self.data = []
        for k in range(0, len(data), 4):
            self.data.append(struct.unpack('<L', data[k:k+4])[0])
        self.length = len(self.data)

    def set_addr_be_data(self, addr, data):
        """Set byte enables, DWORD address, DWORD length, and DWORD data from byte address and byte data"""
        self.address = addr & ~3
        first_pad, last_pad = self.set_addr_be(addr, len(data))
        self.set_data(bytearray(first_pad)+data+bytearray(last_pad))

    def get_data(self):
        data = bytearray()
        for dw in self.data:
            data.extend(struct.pack('<L', dw))
        return data

    def get_first_be_offset(self):
        """Offset to first transferred byte from first byte enable"""
        if self.first_be & 0x7 == 0:
            return 3
        elif self.first_be & 0x3 == 0:
            return 2
        elif self.first_be & 0x1 == 0:
            return 1
        else:
            return 0

    def get_last_be_offset(self):
        """Offset after last transferred byte from last byte enable"""
        if self.length == 1:
            be = self.first_be
        else:
            be = self.last_be
        if be & 0xf == 0x1:
            return 3
        elif be & 0xe == 0x2:
            return 2
        elif be & 0xc == 0x4:
            return 1
        else:
            return 0

    def get_be_byte_count(self):
        """Compute byte length from DWORD length and byte enables"""
        return self.length*4 - self.get_first_be_offset() - self.get_last_be_offset()

    def get_lower_address(self):
        """Compute lower address field from address and first byte enable"""
        return self.address & 0x7c + self.get_first_be_offset()

    def get_size(self):
        """Return size of TLP in bytes"""
        if self.fmt == TlpFmt.THREE_DW:
            return 12
        elif self.fmt == TlpFmt.THREE_DW_DATA:
            return 12+len(self.data)*4
        elif self.fmt == TlpFmt.FOUR_DW:
            return 16
        elif self.fmt == TlpFmt.FOUR_DW_DATA:
            return 16+len(self.data)*4

    def get_wire_size(self):
        """Return size of TLP in bytes, including overhead"""
        return self.get_size()+12

    def get_data_credits(self):
        """Return size of TLP in data credits (1 credit per 4 DW)"""
        return (len(self.data)+3)//4

    def pack(self):
        """Pack TLP as DWORD array"""
        pkt = []

        dw = self.length & 0x3ff
        dw |= (self.at & 0x3) << 10
        dw |= (self.attr & 0x3) << 12
        dw |= (self.ep & 1) << 14
        dw |= (self.td & 1) << 15
        dw |= (self.th & 1) << 16
        dw |= (self.attr & 0x4) << 16
        dw |= (self.tc & 0x7) << 20
        dw |= (self.type & 0x1f) << 24
        dw |= (self.fmt & 0x7) << 29
        pkt.append(dw)

        if (self.fmt_type == TlpType.CFG_READ_0 or self.fmt_type == TlpType.CFG_WRITE_0 or
                self.fmt_type == TlpType.CFG_READ_1 or self.fmt_type == TlpType.CFG_WRITE_1 or
                self.fmt_type == TlpType.MEM_READ or self.fmt_type == TlpType.MEM_READ_64 or
                self.fmt_type == TlpType.MEM_READ_LOCKED or self.fmt_type == TlpType.MEM_READ_LOCKED_64 or
                self.fmt_type == TlpType.MEM_WRITE or self.fmt_type == TlpType.MEM_WRITE_64 or
                self.fmt_type == TlpType.IO_READ or self.fmt_type == TlpType.IO_WRITE):
            dw = self.first_be & 0xf
            dw |= (self.last_be & 0xf) << 4
            dw |= (self.tag & 0xff) << 8
            dw |= int(self.requester_id) << 16
            pkt.append(dw)

            if (self.fmt_type == TlpType.CFG_READ_0 or self.fmt_type == TlpType.CFG_WRITE_0 or
                    self.fmt_type == TlpType.CFG_READ_1 or self.fmt_type == TlpType.CFG_WRITE_1):
                dw = (self.register_number & 0x3ff) << 2
                dw |= int(self.dest_id) << 16
                pkt.append(dw)
            else:
                dw = 0
                if self.fmt == TlpFmt.FOUR_DW or self.fmt == TlpFmt.FOUR_DW_DATA:
                    dw |= (self.address >> 32) & 0xffffffff
                    pkt.append(dw)
                dw |= self.address & 0xfffffffc
                pkt.append(dw)
        elif (self.fmt_type == TlpType.CPL or self.fmt_type == TlpType.CPL_DATA or
                self.fmt_type == TlpType.CPL_LOCKED or self.fmt_type == TlpType.CPL_LOCKED_DATA):
            dw = self.byte_count & 0xfff
            dw |= (self.bcm & 1) << 12
            dw |= (self.status & 0x7) << 13
            dw |= int(self.completer_id) << 16
            pkt.append(dw)
            dw = self.lower_address & 0x7f
            dw |= (self.tag & 0xff) << 8
            dw |= int(self.requester_id) << 16
            pkt.append(dw)
        else:
            raise Exception("Unknown TLP type")

        if self.fmt == TlpFmt.THREE_DW_DATA or self.fmt == TlpFmt.FOUR_DW_DATA:
            pkt.extend(self.data)

        return pkt

    @classmethod
    def unpack(cls, pkt):
        """Unpack TLP from DWORD array"""
        tlp = cls()

        tlp.length = pkt[0] & 0x3ff
        tlp.at = (pkt[0] >> 10) & 0x3
        tlp.attr = (pkt[0] >> 12) & 0x3
        tlp.ep = (pkt[0] >> 14) & 1
        tlp.td = (pkt[0] >> 15) & 1
        tlp.th = (pkt[0] >> 16) & 1
        tlp.attr |= (pkt[0] >> 16) & 0x4
        tlp.tc = (pkt[0] >> 20) & 0x7
        tlp.type = (pkt[0] >> 24) & 0x1f
        tlp.fmt = (pkt[0] >> 29) & 0x7

        if tlp.fmt == TlpFmt.THREE_DW_DATA or tlp.fmt == TlpFmt.FOUR_DW_DATA:
            if tlp.length == 0:
                tlp.length = 1024

        if (tlp.fmt_type == TlpType.CFG_READ_0 or tlp.fmt_type == TlpType.CFG_WRITE_0 or
                tlp.fmt_type == TlpType.CFG_READ_1 or tlp.fmt_type == TlpType.CFG_WRITE_1 or
                tlp.fmt_type == TlpType.MEM_READ or tlp.fmt_type == TlpType.MEM_READ_64 or
                tlp.fmt_type == TlpType.MEM_READ_LOCKED or tlp.fmt_type == TlpType.MEM_READ_LOCKED_64 or
                tlp.fmt_type == TlpType.MEM_WRITE or tlp.fmt_type == TlpType.MEM_WRITE_64 or
                tlp.fmt_type == TlpType.IO_READ or tlp.fmt_type == TlpType.IO_WRITE):
            tlp.first_be = pkt[1] & 0xf
            tlp.last_be = (pkt[1] >> 4) & 0xf
            tlp.tag = (pkt[1] >> 8) & 0xff
            tlp.requester_id = PcieId.from_int(pkt[1] >> 16)

            if (tlp.fmt_type == TlpType.CFG_READ_0 or tlp.fmt_type == TlpType.CFG_WRITE_0 or
                    tlp.fmt_type == TlpType.CFG_READ_1 or tlp.fmt_type == TlpType.CFG_WRITE_1):
                tlp.register_number = (pkt[2] >> 2) >> 0x3ff
                tlp.dest_id = PcieId.from_int(pkt[2] >> 16)
            elif tlp.fmt == TlpFmt.THREE_DW or tlp.fmt == TlpFmt.THREE_DW_DATA:
                tlp.address = pkt[2] & 0xfffffffc
            elif tlp.fmt == TlpFmt.FOUR_DW or tlp.fmt == TlpFmt.FOUR_DW_DATA:
                tlp.address = (pkt[2] & 0xffffffff) << 32 | pkt[3] & 0xfffffffc
        elif (tlp.fmt_type == TlpType.CPL or tlp.fmt_type == TlpType.CPL_DATA or
                tlp.fmt_type == TlpType.CPL_LOCKED or tlp.fmt_type == TlpType.CPL_LOCKED_DATA):
            tlp.byte_count = pkt[1] & 0xfff
            tlp.bcm = (pkt[1] >> 12) & 1
            tlp.status = (pkt[1] >> 13) & 0x7
            tlp.completer_id = PcieId.from_int(pkt[1] >> 16)
            tlp.lower_address = pkt[2] & 0x7f
            tlp.tag = (pkt[2] >> 8) & 0xff
            tlp.requester_id = PcieId.from_int(pkt[2] >> 16)

            if tlp.byte_count == 0:
                tlp.byte_count = 4096
        else:
            raise Exception("Unknown TLP type")

        if tlp.fmt == TlpFmt.THREE_DW_DATA:
            tlp.data = pkt[3:]
        elif tlp.fmt == TlpFmt.FOUR_DW_DATA:
            tlp.data = pkt[4:]

        return tlp

    def __eq__(self, other):
        if isinstance(other, Tlp):
            return (
                self.data == other.data and
                self.fmt == other.fmt and
                self.type == other.type and
                self.tc == other.tc and
                self.td == other.td and
                self.ep == other.ep and
                self.attr == other.attr and
                self.at == other.at and
                self.length == other.length and
                self.completer_id == other.completer_id and
                self.status == other.status and
                self.bcm == other.bcm and
                self.byte_count == other.byte_count and
                self.requester_id == other.requester_id and
                self.dest_id == other.dest_id and
                self.tag == other.tag and
                self.first_be == other.first_be and
                self.last_be == other.last_be and
                self.lower_address == other.lower_address and
                self.address == other.address and
                self.register_number == other.register_number
            )
        return False

    def __repr__(self):
        return (
            f"{type(self).__name__}(data=[{', '.join(hex(x) for x in self.data)}], "
            f"fmt_type={self.fmt_type}, "
            f"tc={self.tc:#x}, "
            f"th={self.th:#x}, "
            f"td={self.td:#x}, "
            f"ep={self.ep:#x}, "
            f"attr={self.attr:#x}, "
            f"at={self.at:#x}, "
            f"length={self.length:#x}, "
            f"completer_id={repr(self.completer_id)}, "
            f"status={self.status!s}, "
            f"bcm={self.bcm:#x}, "
            f"byte_count={self.byte_count:#x}, "
            f"requester_id={repr(self.requester_id)}, "
            f"dest_id={repr(self.dest_id)}, "
            f"tag={self.tag:#x}, "
            f"first_be={self.first_be:#x}, "
            f"last_be={self.last_be:#x}, "
            f"lower_address={self.lower_address:#x}, "
            f"address={self.address:#x}, "
            f"register_number={self.register_number:#x})"
        )
