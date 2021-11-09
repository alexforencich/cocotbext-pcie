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

from cocotbext.pcie.core.tlp import Tlp, TlpFmt, TlpType, TlpAt, TlpAttr, TlpTc, CplStatus
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


tlp_type_to_req_type = {
    TlpType.MEM_READ:            ReqType.MEM_READ,
    TlpType.MEM_READ_64:         ReqType.MEM_READ,
    TlpType.MEM_READ_LOCKED:     ReqType.MEM_READ_LOCKED,
    TlpType.MEM_READ_LOCKED_64:  ReqType.MEM_READ_LOCKED,
    TlpType.MEM_WRITE:           ReqType.MEM_WRITE,
    TlpType.MEM_WRITE_64:        ReqType.MEM_WRITE,
    TlpType.IO_READ:             ReqType.IO_READ,
    TlpType.IO_WRITE:            ReqType.IO_WRITE,
    TlpType.CFG_READ_0:          ReqType.CFG_READ_0,
    TlpType.CFG_WRITE_0:         ReqType.CFG_WRITE_0,
    TlpType.CFG_READ_1:          ReqType.CFG_READ_1,
    TlpType.CFG_WRITE_1:         ReqType.CFG_WRITE_1,
    TlpType.FETCH_ADD:           ReqType.MEM_FETCH_ADD,
    TlpType.FETCH_ADD_64:        ReqType.MEM_FETCH_ADD,
    TlpType.SWAP:                ReqType.MEM_SWAP,
    TlpType.SWAP_64:             ReqType.MEM_SWAP,
    TlpType.CAS:                 ReqType.MEM_CAS,
    TlpType.CAS_64:              ReqType.MEM_CAS,
}


req_type_to_tlp_type = {
    ReqType.MEM_READ:        TlpType.MEM_READ,
    ReqType.MEM_WRITE:       TlpType.MEM_WRITE,
    ReqType.IO_READ:         TlpType.IO_READ,
    ReqType.IO_WRITE:        TlpType.IO_WRITE,
    ReqType.MEM_FETCH_ADD:   TlpType.FETCH_ADD,
    ReqType.MEM_SWAP:        TlpType.SWAP,
    ReqType.MEM_CAS:         TlpType.CAS,
    ReqType.MEM_READ_LOCKED: TlpType.MEM_READ_LOCKED,
    ReqType.CFG_READ_0:      TlpType.CFG_READ_0,
    ReqType.CFG_READ_1:      TlpType.CFG_READ_1,
    ReqType.CFG_WRITE_0:     TlpType.CFG_WRITE_0,
    ReqType.CFG_WRITE_1:     TlpType.CFG_WRITE_1,
}


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
        self.request_completed = False

        if isinstance(tlp, Tlp_us):
            self.bar_id = tlp.bar_id
            self.bar_aperture = tlp.bar_aperture
            self.completer_id_enable = tlp.completer_id_enable
            self.requester_id_enable = tlp.requester_id_enable
            self.discontinue = tlp.discontinue
            self.seq_num = tlp.seq_num
            self.error_code = tlp.error_code
            self.request_completed == tlp.request_completed

    def pack_us_cq(self):
        pkt = UsPcieFrame()

        if self.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64, TlpType.MEM_READ_LOCKED, TlpType.MEM_READ_LOCKED_64,
                TlpType.MEM_WRITE, TlpType.MEM_WRITE_64, TlpType.IO_READ, TlpType.IO_WRITE, TlpType.FETCH_ADD,
                TlpType.FETCH_ADD_64, TlpType.SWAP, TlpType.SWAP_64, TlpType.CAS, TlpType.CAS_64}:
            # Completer Request descriptor
            dw = self.at & 0x3
            dw |= self.address & 0xfffffffc
            pkt.data.append(dw)
            dw = (self.address & 0xffffffff00000000) >> 32
            pkt.data.append(dw)
            dw = self.length & 0x7ff
            dw |= tlp_type_to_req_type[self.fmt_type] << 11
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
            for k in range(0, len(self.data), 4):
                pkt.data.extend(struct.unpack_from('<L', self.data, k))

            # compute byte enables
            pkt.byte_en = [0]*4

            if self.get_payload_size_dw() >= 1:
                pkt.byte_en += [self.first_be]
            if self.get_payload_size_dw() > 2:
                pkt.byte_en += [0xf] * (self.get_payload_size_dw()-2)
            if self.get_payload_size_dw() > 1:
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

        tlp.fmt_type = req_type_to_tlp_type[req_type]

        tlp.length = pkt.data[2] & 0x7ff
        tlp.requester_id = PcieId.from_int(pkt.data[2] >> 16)
        tlp.tag = pkt.data[3] & 0xff
        tlp.tc = TlpTc((pkt.data[3] >> 25) & 0x7)
        tlp.attr = TlpAttr((pkt.data[3] >> 28) & 0x7)

        if req_type & 8 == 0:
            # memory, IO, or atomic operation
            tlp.at = TlpAt(pkt.data[0] & 3)
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

            for dw in pkt.data[4:]:
                tlp.data.extend(struct.pack('<L', dw))

            # compute byte enables
            byte_en = [0]*4

            if tlp.get_payload_size_dw() >= 1:
                byte_en += [tlp.first_be]
            if tlp.get_payload_size_dw() > 2:
                byte_en += [0xf] * (tlp.get_payload_size_dw()-2)
            if tlp.get_payload_size_dw() > 1:
                byte_en += [tlp.last_be]

            # check byte enables
            assert byte_en == pkt.byte_en

            # check parity
            if check_parity:
                assert pkt.check_parity()

        return tlp

    def pack_us_cc(self):
        pkt = UsPcieFrame()

        if self.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
            # Requester Completion descriptor
            dw = self.lower_address & 0x7f
            dw |= (self.at & 3) << 8
            dw |= (self.byte_count & 0x1fff) << 16
            if self.fmt_type in {TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
                dw |= 1 << 29
            # TODO request completed
            pkt.data.append(dw)
            dw = self.length & 0x7ff
            dw |= (self.status & 0x7) << 11
            dw |= bool(self.ep) << 14
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
            for k in range(0, len(self.data), 4):
                pkt.data.extend(struct.unpack_from('<L', self.data, k))

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
        tlp.at = TlpAt((pkt.data[0] >> 8) & 3)
        tlp.byte_count = (pkt.data[0] >> 16) & 0x1fff
        if pkt.data[0] & (1 << 29):
            tlp.fmt_type = TlpType.CPL_LOCKED

        tlp.length = pkt.data[1] & 0x7ff
        if tlp.length > 0:
            tlp.fmt = TlpFmt.THREE_DW_DATA
        tlp.status = CplStatus((pkt.data[1] >> 11) & 7)
        tlp.ep = bool(pkt.data[1] & 1 << 14)
        tlp.requester_id = PcieId.from_int(pkt.data[1] >> 16)
        tlp.completer_id = PcieId.from_int(pkt.data[2] >> 8)
        tlp.tag = pkt.data[2] & 0xff
        tlp.completer_id_enable = bool(pkt.data[2] & (1 << 24))
        tlp.tc = TlpTc((pkt.data[2] >> 25) & 0x7)
        tlp.attr = TlpAttr((pkt.data[2] >> 28) & 0x7)

        tlp.discontinue = pkt.discontinue

        if tlp.length > 0:
            for dw in pkt.data[3:3+tlp.length]:
                tlp.data.extend(struct.pack('<L', dw))

        # check parity
        if check_parity:
            assert pkt.check_parity()

        return tlp

    def pack_us_rq(self):
        pkt = UsPcieFrame()

        if self.fmt_type in {TlpType.CFG_READ_0, TlpType.CFG_WRITE_0, TlpType.CFG_READ_1, TlpType.CFG_WRITE_1,
                TlpType.MEM_READ, TlpType.MEM_READ_64, TlpType.MEM_READ_LOCKED, TlpType.MEM_READ_LOCKED_64,
                TlpType.MEM_WRITE, TlpType.MEM_WRITE_64, TlpType.IO_READ, TlpType.IO_WRITE, TlpType.FETCH_ADD,
                TlpType.FETCH_ADD_64, TlpType.SWAP, TlpType.SWAP_64, TlpType.CAS, TlpType.CAS_64}:
            # Completer Request descriptor
            if self.fmt_type in {TlpType.CFG_READ_0, TlpType.CFG_WRITE_0, TlpType.CFG_READ_1, TlpType.CFG_WRITE_1}:
                # configuration
                dw = (self.register_number & 0x3ff) << 2
                pkt.data.append(dw)
                pkt.data.append(0)
            else:
                # memory, IO, or atomic operation
                dw = self.at & 0x3
                dw |= self.address & 0xfffffffc
                pkt.data.append(dw)
                dw = (self.address & 0xffffffff00000000) >> 32
                pkt.data.append(dw)
            dw = self.length & 0x7ff
            dw |= (tlp_type_to_req_type[self.fmt_type] & 0xf) << 11
            dw |= bool(self.ep) << 15
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
            for k in range(0, len(self.data), 4):
                pkt.data.extend(struct.unpack_from('<L', self.data, k))

            # compute parity
            pkt.update_parity()
        else:
            raise Exception(f"Invalid TLP type for interface ({self.fmt_type})")

        return pkt

    @classmethod
    def unpack_us_rq(cls, pkt, check_parity=False):
        tlp = cls()

        req_type = (pkt.data[2] >> 11) & 0xf

        tlp.fmt_type = req_type_to_tlp_type[req_type]

        tlp.length = pkt.data[2] & 0x7ff
        tlp.ep = bool(pkt.data[2] & 1 << 15)
        tlp.requester_id = PcieId.from_int(pkt.data[2] >> 16)
        tlp.tag = pkt.data[3] & 0xff
        tlp.tc = TlpTc((pkt.data[3] >> 25) & 0x7)
        tlp.attr = TlpAttr((pkt.data[3] >> 28) & 0x7)

        if req_type < 12:
            if req_type < 8:
                # memory, IO, or atomic operation
                tlp.at = TlpAt(pkt.data[0] & 3)
                tlp.address = (pkt.data[1] << 32) | (pkt.data[0] & 0xfffffffc)
                if tlp.address > 0xffffffff:
                    if tlp.fmt == TlpFmt.THREE_DW:
                        tlp.fmt = TlpFmt.FOUR_DW
                    elif tlp.fmt == TlpFmt.THREE_DW_DATA:
                        tlp.fmt = TlpFmt.FOUR_DW_DATA
            else:
                # configuration
                tlp.register_number = (pkt.data[0] >> 2) & 0x3ff
            tlp.completer_id = PcieId.from_int(pkt.data[3] >> 8)
            tlp.requester_id_enable = bool(pkt.data[3] & (1 << 24))

            tlp.first_be = pkt.first_be
            tlp.last_be = pkt.last_be

            tlp.discontinue = pkt.discontinue

            tlp.seq_num = pkt.seq_num

            for dw in pkt.data[4:]:
                tlp.data.extend(struct.pack('<L', dw))

            # check parity
            if check_parity:
                assert pkt.check_parity()
        else:
            raise Exception("TODO")

        return tlp

    def pack_us_rc(self):
        pkt = UsPcieFrame()

        if self.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
            # Requester Completion descriptor
            dw = self.lower_address & 0xfff
            dw |= (self.error_code & 0xf) << 12
            dw |= (self.byte_count & 0x1fff) << 16
            if self.fmt_type in {TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
                dw |= 1 << 29
            dw |= bool(self.request_completed) << 30
            pkt.data.append(dw)
            dw = self.length & 0x7ff
            dw |= (self.status & 0x7) << 11
            dw |= bool(self.ep) << 14
            dw |= int(self.requester_id) << 16
            pkt.data.append(dw)
            dw = (self.tag & 0xff)
            dw |= int(self.completer_id) << 8
            dw |= (self.tc & 0x7) << 25
            dw |= (self.attr & 0x7) << 28
            pkt.data.append(dw)

            pkt.discontinue = self.discontinue

            # payload data
            for k in range(0, len(self.data), 4):
                pkt.data.extend(struct.unpack_from('<L', self.data, k))

            # compute byte enables
            pkt.byte_en = [0]*3

            first_be = (0xf << (self.lower_address & 3)) & 0xf
            if self.byte_count+(self.lower_address & 3) > self.length*4:
                last_be = 0xf
            else:
                last_be = 0xf >> ((4-self.byte_count-self.lower_address) & 3)

            if self.get_payload_size_dw() == 1:
                first_be = first_be & last_be
                last_be = 0

            if self.get_payload_size_dw() >= 1:
                pkt.byte_en += [first_be]
            if self.get_payload_size_dw() > 2:
                pkt.byte_en += [0xf] * (self.get_payload_size_dw()-2)
            if self.get_payload_size_dw() > 1:
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
        tlp.request_completed = pkt.data[0] & (1 << 30)

        tlp.length = pkt.data[1] & 0x7ff
        if tlp.length > 0:
            tlp.fmt = TlpFmt.THREE_DW_DATA
        tlp.status = CplStatus((pkt.data[1] >> 11) & 7)
        tlp.ep = bool(pkt.data[1] & 1 << 14)
        tlp.requester_id = PcieId.from_int(pkt.data[1] >> 16)
        tlp.completer_id = PcieId.from_int(pkt.data[2] >> 8)
        tlp.tag = pkt.data[2] & 0xff
        tlp.tc = TlpTc((pkt.data[2] >> 25) & 0x7)
        tlp.attr = TlpAttr((pkt.data[2] >> 28) & 0x7)

        tlp.discontinue = pkt.discontinue

        if tlp.length > 0:
            for dw in pkt.data[3:3+tlp.length]:
                tlp.data.extend(struct.pack('<L', dw))

        # compute byte enables
        byte_en = [0]*3

        first_be = (0xf << (tlp.lower_address & 3)) & 0xf
        if tlp.byte_count+(tlp.lower_address & 3) > tlp.length*4:
            last_be = 0xf
        else:
            last_be = 0xf >> ((4-tlp.byte_count-tlp.lower_address) & 3)

        if tlp.get_payload_size_dw() == 1:
            first_be = first_be & last_be
            last_be = 0

        if tlp.get_payload_size_dw() >= 1:
            byte_en += [first_be]
        if tlp.get_payload_size_dw() > 2:
            byte_en += [0xf] * (tlp.get_payload_size_dw()-2)
        if tlp.get_payload_size_dw() > 1:
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
                self.ln == other.ln and
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
                self.ph == other.ph and
                self.register_number == other.register_number
            )
        return False

    def __repr__(self):
        return (
            f"{type(self).__name__}(data={self.data}, "
            f"fmt_type={self.fmt_type}, "
            f"tc={self.tc!s}, "
            f"ln={self.ln}, "
            f"th={self.th}, "
            f"td={self.td}, "
            f"ep={self.ep}, "
            f"attr={self.attr!s}, "
            f"at={self.at!s}, "
            f"length={self.length}, "
            f"completer_id={self.completer_id!r}, "
            f"status={self.status!s}, "
            f"bcm={self.bcm}, "
            f"byte_count={self.byte_count}, "
            f"requester_id={self.requester_id!r}, "
            f"dest_id={self.dest_id!r}, "
            f"tag={self.tag}, "
            f"first_be={self.first_be:#x}, "
            f"last_be={self.last_be:#x}, "
            f"lower_address={self.lower_address:#x}, "
            f"address={self.address:#x}, "
            f"ph={self.ph}, "
            f"register_number={self.register_number:#x})"
        )
