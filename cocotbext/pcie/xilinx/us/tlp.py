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

from cocotbext.pcie.core.tlp import Tlp, TlpFmt, TlpType
from cocotbext.pcie.core.utils import PcieId
from .interface import UsPcieFrame


# req_type field
class ReqType(enum.IntEnum):
    MEM_READ        = 0b0000
    MEM_WRITE       = 0b0001
    IO_READ         = 0b0010
    IO_WRITE        = 0b0011
    MEM_FETCH_ADD   = 0b0100
    MEM_SWAP        = 0b0101
    MEM_CAS         = 0b0110
    MEM_READ_LOCKED = 0b0111
    CFG_READ_0      = 0b1000
    CFG_READ_1      = 0b1001
    CFG_WRITE_0     = 0b1010
    CFG_WRITE_1     = 0b1011
    MSG             = 0b1100
    MSG_VENDOR      = 0b1101
    MSG_ATS         = 0b1110


# error_code field
class ErrorCode(enum.IntEnum):
    NORMAL_TERMINATION = 0b0000
    POISONED           = 0b0001
    BAD_STATUS         = 0b0010
    INVALID_LENGTH     = 0b0011
    MISMATCH           = 0b0100
    INVALID_ADDRESS    = 0b0101
    INVALID_TAG        = 0b0110
    TIMEOUT            = 0b1001
    FLR                = 0b1000


class Tlp_us(Tlp):
    def __init__(self, tlp=None):
        super().__init__(tlp)
        self.bar_id = 0
        self.bar_aperture = 0
        self.completer_id_enable = False
        self.requester_id_enable = False
        self.discontinue = False
        self.seq_num = 0
        self.error_code = ErrorCode.NORMAL_TERMINATION

        if isinstance(tlp, Tlp_us):
            self.bar_id = tlp.bar_id
            self.bar_aperture = tlp.bar_aperture
            self.completer_id_enable = tlp.completer_id_enable
            self.requester_id_enable = tlp.requester_id_enable
            self.discontinue = tlp.discontinue
            self.seq_num = tlp.seq_num
            self.error_code = tlp.error_code

    def pack_us_cq(self):
        pkt = UsPcieFrame()

        if (self.fmt_type == TlpType.IO_READ or self.fmt_type == TlpType.IO_WRITE or
                self.fmt_type == TlpType.MEM_READ or self.fmt_type == TlpType.MEM_READ_64 or
                self.fmt_type == TlpType.MEM_WRITE or self.fmt_type == TlpType.MEM_WRITE_64):
            # Completer Request descriptor
            dw = self.at & 0x3
            dw |= self.address & 0xfffffffc
            pkt.data.append(dw)
            dw = (self.address & 0xffffffff00000000) >> 32
            pkt.data.append(dw)
            dw = self.length & 0x7ff
            if self.fmt_type == TlpType.MEM_READ or self.fmt_type == TlpType.MEM_READ_64:
                dw |= ReqType.MEM_READ << 11
            elif self.fmt_type == TlpType.MEM_WRITE or self.fmt_type == TlpType.MEM_WRITE_64:
                dw |= ReqType.MEM_WRITE << 11
            elif self.fmt_type == TlpType.IO_READ:
                dw |= ReqType.IO_READ << 11
            elif self.fmt_type == TlpType.IO_WRITE:
                dw |= ReqType.IO_WRITE << 11
            elif self.fmt_type == TlpType.FETCH_ADD or self.fmt_type == TlpType.FETCH_ADD_64:
                dw |= ReqType.MEM_FETCH_ADD << 11
            elif self.fmt_type == TlpType.SWAP or self.fmt_type == TlpType.SWAP_64:
                dw |= ReqType.MEM_SWAP << 11
            elif self.fmt_type == TlpType.CAS or self.fmt_type == TlpType.CAS_64:
                dw |= ReqType.MEM_CAS << 11
            elif self.fmt_type == TlpType.MEM_READ_LOCKED or self.fmt_type == TlpType.MEM_READ_LOCKED_64:
                dw |= ReqType.MEM_READ_LOCKED << 11
            dw |= int(self.requester_id) << 16
            pkt.data.append(dw)
            dw = (self.tag & 0xff)
            dw |= (self.completer_id.function & 0xff) << 8
            dw |= (self.bar_id & 0x7) << 16
            dw |= (self.bar_aperture & 0x3f) << 19
            dw |= (self.tc & 0x7) << 25
            dw |= (self.attr & 0x7) << 28
            pkt.data.append(dw)

            pkt.first_be = self.first_be
            pkt.last_be = self.last_be

            pkt.discontinue = self.discontinue

            # payload data
            pkt.data += self.data

            # compute byte enables
            pkt.byte_en = [0]*4

            if len(self.data) >= 1:
                pkt.byte_en += [self.first_be]
            if len(self.data) > 2:
                pkt.byte_en += [0xf] * (len(self.data)-2)
            if len(self.data) > 1:
                pkt.byte_en += [self.last_be]

            # compute parity
            pkt.update_parity()
        else:
            raise Exception(f"Invalid TLP type for interface ({self.fmt_type})")

        return pkt

    @classmethod
    def unpack_us_cq(cls, pkt, check_parity=False):
        tlp = cls()

        req_type = (pkt.data[2] >> 11) & 0xf

        if req_type == ReqType.MEM_READ:
            tlp.fmt_type = TlpType.MEM_READ
        elif req_type == ReqType.MEM_WRITE:
            tlp.fmt_type = TlpType.MEM_WRITE
        elif req_type == ReqType.IO_READ:
            tlp.fmt_type = TlpType.IO_READ
        elif req_type == ReqType.IO_WRITE:
            tlp.fmt_type = TlpType.IO_WRITE
        elif req_type == ReqType.MEM_FETCH_ADD:
            tlp.fmt_type = TlpType.FETCH_ADD
        elif req_type == ReqType.MEM_SWAP:
            tlp.fmt_type = TlpType.SWAP
        elif req_type == ReqType.MEM_CAS:
            tlp.fmt_type = TlpType.CAS
        elif req_type == ReqType.MEM_READ_LOCKED:
            tlp.fmt_type = TlpType.MEM_READ_LOCKED
        else:
            raise Exception("Invalid packet type")

        tlp.length = pkt.data[2] & 0x7ff
        tlp.requester_id = PcieId.from_int(pkt.data[2] >> 16)
        tlp.tag = pkt.data[3] & 0xff
        tlp.tc = (pkt.data[3] >> 25) & 0x7
        tlp.attr = (pkt.data[3] >> 28) & 0x7

        if req_type & 8 == 0:
            # memory, IO, or atomic operation
            tlp.at = pkt.data[0] & 3
            tlp.address = (pkt.data[1] << 32) | (pkt.data[0] & 0xfffffffc)
            if tlp.address > 0xffffffff:
                if tlp.fmt == TlpFmt.THREE_DW:
                    tlp.fmt = TlpFmt.FOUR_DW
                elif tlp.fmt == TlpFmt.THREE_DW_DATA:
                    tlp.fmt = TlpFmt.FOUR_DW_DATA
            tlp.completer_id = PcieId(0, 0, (pkt.data[3] >> 8) & 0xff)
            tlp.bar_id = (pkt.data[3] >> 16) & 7
            tlp.bar_aperture = (pkt.data[3] >> 19) & 0x3f

            tlp.first_be = pkt.first_be
            tlp.last_be = pkt.last_be

            tlp.discontinue = pkt.discontinue

            tlp.data = pkt.data[4:]

            # compute byte enables
            byte_en = [0]*4

            if len(tlp.data) >= 1:
                byte_en += [tlp.first_be]
            if len(tlp.data) > 2:
                byte_en += [0xf] * (len(tlp.data)-2)
            if len(tlp.data) > 1:
                byte_en += [tlp.last_be]

            # check byte enables
            assert byte_en == pkt.byte_en

            # check parity
            if check_parity:
                assert pkt.check_parity()

        return tlp

    def pack_us_cc(self):
        pkt = UsPcieFrame()

        if (self.fmt_type == TlpType.CPL or self.fmt_type == TlpType.CPL_DATA or
                self.fmt_type == TlpType.CPL_LOCKED or self.fmt_type == TlpType.CPL_LOCKED_DATA):
            # Requester Completion descriptor
            dw = self.lower_address & 0x7f
            dw |= (self.at & 3) << 8
            dw |= (self.byte_count & 0x1fff) << 16
            if self.fmt_type == TlpType.CPL_LOCKED or self.fmt_type == TlpType.CPL_LOCKED_DATA:
                # TODO only for completions for locked read requests
                dw |= 1 << 29
            # TODO request completed
            pkt.data.append(dw)
            dw = self.length & 0x7ff
            dw |= (self.status & 0x7) << 11
            # TODO poisoned completion
            dw |= int(self.requester_id) << 16
            pkt.data.append(dw)
            dw = (self.tag & 0xff)
            dw |= int(self.completer_id) << 8
            dw |= bool(self.completer_id_enable) << 24
            dw |= (self.tc & 0x7) << 25
            dw |= (self.attr & 0x7) << 28
            pkt.data.append(dw)

            pkt.discontinue = self.discontinue

            # payload data
            pkt.data += self.data

            # compute parity
            pkt.update_parity()
        else:
            raise Exception(f"Invalid TLP type for interface ({self.fmt_type})")

        return pkt

    @classmethod
    def unpack_us_cc(cls, pkt, check_parity=False):
        tlp = cls()

        tlp.fmt_type = TlpType.CPL

        tlp.lower_address = pkt.data[0] & 0x7f
        tlp.at = (pkt.data[0] >> 8) & 3
        tlp.byte_count = (pkt.data[0] >> 16) & 0x1fff
        if pkt.data[0] & (1 << 29):
            tlp.fmt_type = TlpType.CPL_LOCKED

        tlp.length = pkt.data[1] & 0x7ff
        if tlp.length > 0:
            tlp.fmt = TlpFmt.THREE_DW_DATA
        tlp.status = (pkt.data[1] >> 11) & 7
        tlp.requester_id = PcieId.from_int(pkt.data[1] >> 16)
        tlp.completer_id = PcieId.from_int(pkt.data[2] >> 8)
        tlp.completer_id_enable = pkt.data[2] >> 24 & 1 != 0
        tlp.tag = pkt.data[2] & 0xff
        tlp.completer_id_enable = bool(pkt.data[2] & (1 << 24))
        tlp.tc = (pkt.data[2] >> 25) & 0x7
        tlp.attr = (pkt.data[2] >> 28) & 0x7

        tlp.discontinue = pkt.discontinue

        if tlp.length > 0:
            tlp.data = pkt.data[3:3+tlp.length]

        # check parity
        if check_parity:
            assert pkt.check_parity()

        return tlp

    def pack_us_rq(self):
        pkt = UsPcieFrame()

        if (self.fmt_type == TlpType.IO_READ or self.fmt_type == TlpType.IO_WRITE or
                self.fmt_type == TlpType.MEM_READ or self.fmt_type == TlpType.MEM_READ_64 or
                self.fmt_type == TlpType.MEM_WRITE or self.fmt_type == TlpType.MEM_WRITE_64 or
                self.fmt_type == TlpType.CFG_READ_0 or self.fmt_type == TlpType.CFG_READ_1 or
                self.fmt_type == TlpType.CFG_WRITE_0 or self.fmt_type == TlpType.CFG_WRITE_1):
            # Completer Request descriptor
            if (self.fmt_type == TlpType.IO_READ or self.fmt_type == TlpType.IO_WRITE or
                    self.fmt_type == TlpType.MEM_READ or self.fmt_type == TlpType.MEM_READ_64 or
                    self.fmt_type == TlpType.MEM_WRITE or self.fmt_type == TlpType.MEM_WRITE_64):
                dw = self.at & 0x3
                dw |= self.address & 0xfffffffc
                pkt.data.append(dw)
                dw = (self.address & 0xffffffff00000000) >> 32
                pkt.data.append(dw)
            elif (self.fmt_type == TlpType.CFG_READ_0 or self.fmt_type == TlpType.CFG_READ_1 or
                    self.fmt_type == TlpType.CFG_WRITE_0 or self.fmt_type == TlpType.CFG_WRITE_1):
                dw = (self.register_number & 0x3ff) << 2
                pkt.data.append(dw)
                pkt.data.append(0)
            dw = self.length & 0x7ff
            if self.fmt_type == TlpType.MEM_READ or self.fmt_type == TlpType.MEM_READ_64:
                dw |= ReqType.MEM_READ << 11
            elif self.fmt_type == TlpType.MEM_WRITE or self.fmt_type == TlpType.MEM_WRITE_64:
                dw |= ReqType.MEM_WRITE << 11
            elif self.fmt_type == TlpType.IO_READ:
                dw |= ReqType.IO_READ << 11
            elif self.fmt_type == TlpType.IO_WRITE:
                dw |= ReqType.IO_WRITE << 11
            elif self.fmt_type == TlpType.FETCH_ADD or self.fmt_type == TlpType.FETCH_ADD_64:
                dw |= ReqType.MEM_FETCH_ADD << 11
            elif self.fmt_type == TlpType.SWAP or self.fmt_type == TlpType.SWAP_64:
                dw |= ReqType.MEM_SWAP << 11
            elif self.fmt_type == TlpType.CAS or self.fmt_type == TlpType.CAS_64:
                dw |= ReqType.MEM_CAS << 11
            elif self.fmt_type == TlpType.MEM_READ_LOCKED or self.fmt_type == TlpType.MEM_READ_LOCKED_64:
                dw |= ReqType.MEM_READ_LOCKED << 11
            elif self.fmt_type == TlpType.CFG_READ_0:
                dw |= ReqType.CFG_READ_0 << 11
            elif self.fmt_type == TlpType.CFG_READ_1:
                dw |= ReqType.CFG_READ_1 << 11
            elif self.fmt_type == TlpType.CFG_WRITE_0:
                dw |= ReqType.CFG_WRITE_0 << 11
            elif self.fmt_type == TlpType.CFG_WRITE_1:
                dw |= ReqType.CFG_WRITE_1 << 11
            # TODO poisoned
            dw |= int(self.requester_id) << 16
            pkt.data.append(dw)
            dw = (self.tag & 0xff)
            dw |= int(self.completer_id) << 8
            dw |= bool(self.requester_id_enable) << 24
            dw |= (self.tc & 0x7) << 25
            dw |= (self.attr & 0x7) << 28
            # TODO force ecrc
            pkt.data.append(dw)

            pkt.first_be = self.first_be
            pkt.last_be = self.last_be

            pkt.discontinue = self.discontinue

            pkt.seq_num = self.seq_num

            # payload data
            pkt.data += self.data

            # compute parity
            pkt.update_parity()
        else:
            raise Exception(f"Invalid TLP type for interface ({self.fmt_type})")

        return pkt

    @classmethod
    def unpack_us_rq(cls, pkt, check_parity=False):
        tlp = cls()

        req_type = (pkt.data[2] >> 11) & 0xf

        if req_type == ReqType.MEM_READ:
            tlp.fmt_type = TlpType.MEM_READ
        elif req_type == ReqType.MEM_WRITE:
            tlp.fmt_type = TlpType.MEM_WRITE
        elif req_type == ReqType.IO_READ:
            tlp.fmt_type = TlpType.IO_READ
        elif req_type == ReqType.IO_WRITE:
            tlp.fmt_type = TlpType.IO_WRITE
        elif req_type == ReqType.MEM_FETCH_ADD:
            tlp.fmt_type = TlpType.FETCH_ADD
        elif req_type == ReqType.MEM_SWAP:
            tlp.fmt_type = TlpType.SWAP
        elif req_type == ReqType.MEM_CAS:
            tlp.fmt_type = TlpType.CAS
        elif req_type == ReqType.MEM_READ_LOCKED:
            tlp.fmt_type = TlpType.MEM_READ_LOCKED
        elif req_type == ReqType.CFG_READ_0:
            tlp.fmt_type = TlpType.CFG_READ_0
        elif req_type == ReqType.CFG_READ_1:
            tlp.fmt_type = TlpType.CFG_READ_1
        elif req_type == ReqType.CFG_WRITE_0:
            tlp.fmt_type = TlpType.CFG_WRITE_0
        elif req_type == ReqType.CFG_WRITE_1:
            tlp.fmt_type = TlpType.CFG_WRITE_1
        else:
            raise Exception("Invalid packet type")

        tlp.length = pkt.data[2] & 0x7ff
        # TODO poisoned
        tlp.requester_id = PcieId.from_int(pkt.data[2] >> 16)
        tlp.tag = pkt.data[3] & 0xff
        tlp.tc = (pkt.data[3] >> 25) & 0x7
        tlp.attr = (pkt.data[3] >> 28) & 0x7

        if req_type < 12:
            if req_type < 8:
                # memory, IO, or atomic operation
                tlp.at = pkt.data[0] & 3
                tlp.address = (pkt.data[1] << 32) | (pkt.data[0] & 0xfffffffc)
                if tlp.address > 0xffffffff:
                    if tlp.fmt == TlpFmt.THREE_DW:
                        tlp.fmt = TlpFmt.FOUR_DW
                    elif tlp.fmt == TlpFmt.THREE_DW_DATA:
                        tlp.fmt = TlpFmt.FOUR_DW_DATA
            else:
                tlp.register_number = (pkt.data[0] >> 2) & 0x3ff
            tlp.completer_id = PcieId.from_int(pkt.data[3] >> 8)
            tlp.requester_id_enable = bool(pkt.data[3] & (1 << 24))

            tlp.first_be = pkt.first_be
            tlp.last_be = pkt.last_be

            tlp.discontinue = pkt.discontinue

            tlp.seq_num = pkt.seq_num

            tlp.data = pkt.data[4:]

            # check parity
            if check_parity:
                assert pkt.check_parity()
        else:
            raise Exception("TODO")

        return tlp

    def pack_us_rc(self):
        pkt = UsPcieFrame()

        if (self.fmt_type == TlpType.CPL or self.fmt_type == TlpType.CPL_DATA or
                self.fmt_type == TlpType.CPL_LOCKED or self.fmt_type == TlpType.CPL_LOCKED_DATA):
            # Requester Completion descriptor
            dw = self.lower_address & 0xfff
            dw |= (self.error_code & 0xf) << 12
            dw |= (self.byte_count & 0x1fff) << 16
            if self.fmt_type == TlpType.CPL_LOCKED or self.fmt_type == TlpType.CPL_LOCKED_DATA:
                dw |= 1 << 29
            # TODO request completed
            pkt.data.append(dw)
            dw = self.length & 0x7ff
            dw |= (self.status & 0x7) << 11
            # TODO poisoned completion
            dw |= int(self.requester_id) << 16
            pkt.data.append(dw)
            dw = (self.tag & 0xff)
            dw |= int(self.completer_id) << 8
            dw |= (self.tc & 0x7) << 25
            dw |= (self.attr & 0x7) << 28
            pkt.data.append(dw)

            pkt.discontinue = self.discontinue

            # payload data
            pkt.data += self.data

            # compute byte enables
            pkt.byte_en = [0]*3

            first_be = (0xf << (self.lower_address & 3)) & 0xf
            if self.byte_count+(self.lower_address & 3) > self.length*4:
                last_be = 0xf
            else:
                last_be = 0xf >> ((4-self.byte_count-self.lower_address) & 3)

            if len(self.data) == 1:
                first_be = first_be & last_be
                last_be = 0

            if len(self.data) >= 1:
                pkt.byte_en += [first_be]
            if len(self.data) > 2:
                pkt.byte_en += [0xf] * (len(self.data)-2)
            if len(self.data) > 1:
                pkt.byte_en += [last_be]

            # compute parity
            pkt.update_parity()
        else:
            raise Exception(f"Invalid TLP type for interface ({self.fmt_type})")

        return pkt

    @classmethod
    def unpack_us_rc(cls, pkt, check_parity=False):
        tlp = cls()

        tlp.fmt_type = TlpType.CPL

        tlp.lower_address = pkt.data[0] & 0xfff
        tlp.error_code = (pkt.data[0] >> 12) & 0xf
        tlp.byte_count = (pkt.data[0] >> 16) & 0x1fff
        if pkt.data[0] & (1 << 29):
            tlp.fmt_type = TlpType.CPL_LOCKED

        tlp.length = pkt.data[1] & 0x7ff
        if tlp.length > 0:
            tlp.fmt = TlpFmt.THREE_DW_DATA
        tlp.status = (pkt.data[1] >> 11) & 7
        tlp.requester_id = PcieId.from_int(pkt.data[1] >> 16)
        tlp.completer_id = PcieId.from_int(pkt.data[2] >> 8)
        tlp.tag = pkt.data[2] & 0xff
        tlp.tc = (pkt.data[2] >> 25) & 0x7
        tlp.attr = (pkt.data[2] >> 28) & 0x7

        tlp.discontinue = pkt.discontinue

        if tlp.length > 0:
            tlp.data = pkt.data[3:3+tlp.length]

        # compute byte enables
        byte_en = [0]*3

        first_be = (0xf << (tlp.lower_address & 3)) & 0xf
        if tlp.byte_count+(tlp.lower_address & 3) > tlp.length*4:
            last_be = 0xf
        else:
            last_be = 0xf >> ((4-tlp.byte_count-tlp.lower_address) & 3)

        if len(tlp.data) == 1:
            first_be = first_be & last_be
            last_be = 0

        if len(tlp.data) >= 1:
            byte_en += [first_be]
        if len(tlp.data) > 2:
            byte_en += [0xf] * (len(tlp.data)-2)
        if len(tlp.data) > 1:
            byte_en += [last_be]

        # check byte enables
        assert byte_en == pkt.byte_en

        # check parity
        if check_parity:
            assert pkt.check_parity()

        return tlp

    def __eq__(self, other):
        if isinstance(other, Tlp_us):
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
