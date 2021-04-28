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
import struct


# DLLP types
class DllpType(enum.IntEnum):
    ACK                = 0b00000000
    MR_INIT            = 0b00000001
    DATA_LINK_FEATURE  = 0b00000010
    NAK                = 0b00010000
    PM_ENTER_L1        = 0b00100000
    PM_ENTER_L23       = 0b00100001
    PM_ACT_ST_REQ_L1   = 0b00100011
    PM_REQ_ACK         = 0b00100100
    VEND               = 0b00110000
    NOP                = 0b00110001
    INIT_FC1_P         = 0b01000000
    INIT_FC1_NP        = 0b01010000
    INIT_FC1_CPL       = 0b01100000
    MR_INIT_FC1        = 0b01110000
    INIT_FC2_P         = 0b11000000
    INIT_FC2_NP        = 0b11010000
    INIT_FC2_CPL       = 0b11100000
    MR_INIT_FC2        = 0b11110000
    UPDATE_FC_P        = 0b10000000
    UPDATE_FC_NP       = 0b10010000
    UPDATE_FC_CPL      = 0b10100000
    MR_UPDATE_FC       = 0b10110000


DLLP_FC_TYPE_MASK = 0b11111000
DLLP_FC_VC_MASK   = 0b00000111


class FcType(enum.Enum):
    P   = 0  # posted
    NP  = 1  # non-posted
    CPL = 2  # completion


dllp_type_fc_type_mapping = {
    DllpType.INIT_FC1_P:     FcType.P,
    DllpType.INIT_FC1_NP:    FcType.NP,
    DllpType.INIT_FC1_CPL:   FcType.CPL,
    DllpType.INIT_FC2_P:     FcType.P,
    DllpType.INIT_FC2_NP:    FcType.NP,
    DllpType.INIT_FC2_CPL:   FcType.CPL,
    DllpType.UPDATE_FC_P:    FcType.P,
    DllpType.UPDATE_FC_NP:   FcType.NP,
    DllpType.UPDATE_FC_CPL:  FcType.CPL,
}


class FcScale(enum.IntEnum):
    DIS  = 0  # scaled FC disabled
    SF1  = 1  # scaled FC enabled with scale factor 1
    SF4  = 2  # scaled FC enabled with scale factor 4
    SF16 = 3  # scaled FC enabled with scale factor 16


def crc16(data, crc=0xFFFF, poly=0xD008):
    for d in data:
        crc = crc ^ d
        for bit in range(0, 8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc = crc >> 1
    return crc


class Dllp:
    def __init__(self, dllp=None):
        self.type = DllpType.NOP
        self.seq = 0
        self.vc = 0
        self.hdr_scale = FcScale(0)
        self.hdr_fc = 0
        self.data_scale = FcScale(0)
        self.data_fc = 0
        self.feature_support = 0
        self.feature_ack = False

        if isinstance(dllp, Dllp):
            self.type = dllp.type
            self.seq = dllp.seq
            self.vc = dllp.vc
            self.hdr_scale = dllp.hdr_scale
            self.hdr_fc = dllp.hdr_fc
            self.data_scale = dllp.data_scale
            self.data_fc = dllp.data_fc
            self.feature_support = dllp.feature_support
            self.feature_ack = dllp.feature_ack

    @classmethod
    def create_ack(cls, seq):
        dllp = cls()
        dllp.type = DllpType.ACK
        dllp.seq = seq
        return dllp

    @classmethod
    def create_nak(cls, seq):
        dllp = cls()
        dllp.type = DllpType.NAK
        dllp.seq = seq
        return dllp

    def get_size(self):
        """Return size of DLLP in bytes"""
        return 6

    def get_wire_size(self):
        """Return size of DLLP in bytes, including overhead"""
        return 8

    def get_fc_type(self):
        return dllp_type_fc_type_mapping[self.type]

    def pack(self):
        """Pack DLLP as bytes"""
        dw = (self.type & 0xff) << 24

        if self.type in {DllpType.ACK, DllpType.NAK}:
            dw |= self.seq & 0xfff
        elif self.type in {DllpType.NOP, DllpType.PM_ENTER_L1, DllpType.PM_ENTER_L23,
                DllpType.PM_ACT_ST_REQ_L1, DllpType.PM_REQ_ACK}:
            pass
        elif self.type == DllpType.DATA_LINK_FEATURE:
            dw |= self.feature_support & 0x7fffff
            dw |= bool(self.feature_ack) << 23
        elif (self.type & DLLP_FC_TYPE_MASK) in {DllpType.INIT_FC1_P, DllpType.INIT_FC1_NP, DllpType.INIT_FC1_CPL,
                DllpType.INIT_FC2_P, DllpType.INIT_FC2_NP, DllpType.INIT_FC2_CPL, DllpType.UPDATE_FC_P,
                DllpType.UPDATE_FC_NP, DllpType.UPDATE_FC_CPL}:
            dw |= (self.vc & DLLP_FC_VC_MASK) << 24
            dw |= self.data_fc & 0xfff
            dw |= (self.data_scale & 0x3) << 12
            dw |= (self.hdr_fc & 0xff) << 14
            dw |= (self.hdr_scale & 0x3) << 22
        else:
            raise Exception("TODO")

        return struct.pack('>L', dw)

    def pack_crc(self):
        """Pack DLLP as bytes with CRC"""

        pkt = self.pack()
        pkt += struct.pack('<H', (~crc16(pkt)) & 0xffff)

        return pkt

    @classmethod
    def unpack(cls, pkt):
        """Unpack DLLP from bytes"""
        dllp = cls()

        dw, = struct.unpack_from('>L', pkt)

        dllp.type = (dw >> 24) & 0xff

        if dllp.type in {DllpType.ACK, DllpType.NAK}:
            dllp.seq = dw & 0xfff
        elif dllp.type in {DllpType.NOP, DllpType.PM_ENTER_L1, DllpType.PM_ENTER_L23,
                DllpType.PM_ACT_ST_REQ_L1, DllpType.PM_REQ_ACK}:
            pass
        elif dllp.type == DllpType.DATA_LINK_FEATURE:
            dllp.feature_support = dw & 0x7fffff
            dllp.feature_ack = bool(dw & 1 << 23)
        elif (dllp.type & DLLP_FC_TYPE_MASK) in {DllpType.INIT_FC1_P, DllpType.INIT_FC1_NP, DllpType.INIT_FC1_CPL,
                DllpType.INIT_FC2_P, DllpType.INIT_FC2_NP, DllpType.INIT_FC2_CPL, DllpType.UPDATE_FC_P,
                DllpType.UPDATE_FC_NP, DllpType.UPDATE_FC_CPL}:
            dllp.type = dllp.type & DLLP_FC_TYPE_MASK
            dllp.vc = (dw >> 24) & DLLP_FC_VC_MASK
            dllp.data_fc = dw & 0xfff
            dllp.data_scale = FcScale((dw >> 12) & 0x3)
            dllp.hdr_fc = (dw >> 14) & 0xff
            dllp.hdr_scale = FcScale((dw >> 22) & 0x3)
        else:
            raise Exception("TODO")

        dllp.type = DllpType(dllp.type)

        return dllp

    @classmethod
    def unpack_crc(cls, pkt):
        """Unpack DLLP from bytes with CRC"""

        if len(pkt) != 6:
            raise Exception("Invalid length")

        if crc16(pkt) != 0x556f:
            raise Exception("Invalid CRC")

        return cls.unpack(pkt[0:4])

    def __eq__(self, other):
        if isinstance(other, Dllp):
            return (
                self.type == other.type and
                self.seq == other.seq and
                self.vc == other.vc and
                self.hdr_scale == other.hdr_scale and
                self.hdr_fc == other.hdr_fc and
                self.data_scale == other.data_scale and
                self.data_fc == other.data_fc and
                self.feature_support == other.feature_support and
                self.feature_ack == other.feature_ack
            )
        return False

    def __repr__(self):
        return (
            f"{type(self).__name__}(type={self.type!s}, "
            f"seq={self.seq}, "
            f"vc={self.vc}, "
            f"hdr_scale={self.hdr_scale!s}, "
            f"hdr_fc={self.hdr_fc}, "
            f"data_scale={self.data_scale!s}, "
            f"data_fc={self.data_fc}, "
            f"feature_support={self.feature_support}, "
            f"feature_ack={self.feature_ack})"
        )

    def __bytes__(self):
        return self.pack()
