"""

Copyright (c) 2026 Anderson Ignacio da Silva

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

import logging
import struct

import cocotb
from cocotb.queue import Queue, QueueFull
from cocotb.triggers import RisingEdge, Timer, First, Event
from cocotb.handle import Immediate
from cocotb_bus.bus import Bus

from cocotbext.pcie.core.tlp import Tlp, TlpType

# NOTE: this models the "single packet per cycle" mode of the Stratix V Hard
# IP for PCI Express, Avalon-ST interface (UG-01097_avst). Only the 128-bit
# and 256-bit Avalon-ST widths are implemented. The 64-bit interface uses a
# dword-granularity byte-enable scheme (rx_st_be/tx_st_be) instead of the
# qword-granularity empty field and is not currently supported.
#
# The Hard IP always aligns the start of the TLP payload to a qword (64-bit)
# boundary: a 3-dword header is padded with an extra (unused) dword, and, in
# this model, an odd-length payload is likewise padded with a trailing unused
# dword so the whole packet always occupies a whole number of qwords. This
# matches the "qword aligned address" data/timing figures in the datasheet.
# The additional dword-shifted layout used for non-qword-aligned addresses
# (i.e. based on address bit 2) is not modeled.


class BaseBus(Bus):

    _signals = ["data"]
    _optional_signals = []

    def __init__(self, entity=None, prefix=None, **kwargs):
        super().__init__(entity, prefix, self._signals, optional_signals=self._optional_signals, **kwargs)

    @classmethod
    def from_entity(cls, entity, **kwargs):
        return cls(entity, **kwargs)

    @classmethod
    def from_prefix(cls, entity, prefix, **kwargs):
        return cls(entity, prefix, **kwargs)


class S5TxBus(BaseBus):
    _signals = ["data", "sop", "eop", "valid", "ready"]
    _optional_signals = ["empty", "err", "parity"]


class S5RxBus(BaseBus):
    _signals = ["data", "sop", "eop", "valid", "ready"]
    _optional_signals = ["empty", "err", "bar", "mask", "parity"]


def dword_parity(d):
    d ^= d >> 4
    d ^= d >> 2
    d ^= d >> 1
    p = d & 0x1
    if d & 0x100:
        p |= 0x2
    if d & 0x10000:
        p |= 0x4
    if d & 0x1000000:
        p |= 0x8
    return p


class S5PcieFrame:
    def __init__(self, frame=None):
        self.data = []
        self.parity = []
        self.bar = 0
        self.err = 0

        if isinstance(frame, Tlp):
            hdr = frame.pack_header()
            hdr_dwords = []
            for k in range(0, len(hdr), 4):
                hdr_dwords.extend(struct.unpack_from('>L', hdr, k))

            data = frame.get_data()

            if data:
                # The Hard IP aligns the payload to a qword boundary measured
                # against the TLP's own low address bit, not against header
                # length alone (UG-01097_avst "qword aligned address"
                # framing): a pad dword follows the header only when the
                # header's own dword parity disagrees with address bit 2.
                # Getting this wrong drops every payload dword silently
                # against a real Stratix V hard IP or RTL that implements it
                # (mate_tlp_rx.sv/mate_tlp_tx.sv/mate_dma_tlp.sv mirror this
                # as `payload_dw = addr[2] ? <hdr_len> : <hdr_len>+1`, and the
                # symmetric case for 4DW headers).
                if frame.fmt_type in {TlpType.CPL, TlpType.CPL_DATA,
                                      TlpType.CPL_LOCKED,
                                      TlpType.CPL_LOCKED_DATA}:
                    addr_bit2 = bool(frame.lower_address & 0x4)
                else:
                    addr_bit2 = bool(frame.address & 0x4)

                if (len(hdr_dwords) % 2) != int(addr_bit2):
                    hdr_dwords.append(0)
            elif len(hdr_dwords) % 2:
                # header-only TLP: no payload placement to get right, pad to
                # qword boundary unconditionally as before
                hdr_dwords.append(0)

            data_dwords = []
            for k in range(0, len(data), 4):
                data_dwords.extend(struct.unpack_from('<L', data, k))
            if len(data_dwords) % 2:
                # pad payload to qword boundary
                data_dwords.append(0)

            self.data = hdr_dwords + data_dwords

            self.update_parity()

        elif isinstance(frame, S5PcieFrame):
            self.data = list(frame.data)
            self.parity = list(frame.parity)
            self.bar = frame.bar
            self.err = frame.err

    @classmethod
    def from_tlp(cls, tlp):
        return cls(tlp)

    def to_tlp(self):
        fmt = (self.data[0] >> 29) & 0b111
        hdr_len = 4 if fmt & 0b001 else 3

        hdr = bytearray()
        for dw in self.data[:hdr_len]:
            hdr.extend(struct.pack('>L', dw))
        tlp = Tlp.unpack_header(hdr)

        if fmt & 0b010:
            # Mirror the address-bit-2 payload shift applied in from_tlp()
            # above, using the address fields already parsed onto `tlp`.
            if tlp.fmt_type in {TlpType.CPL, TlpType.CPL_DATA,
                                TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
                addr_bit2 = bool(tlp.lower_address & 0x4)
            else:
                addr_bit2 = bool(tlp.address & 0x4)

            wire_hdr_len = hdr_len if (hdr_len % 2) == int(addr_bit2) \
                else hdr_len + 1

            for dw in self.data[wire_hdr_len:wire_hdr_len+tlp.length]:
                tlp.data.extend(struct.pack('<L', dw))

        return tlp

    def update_parity(self):
        self.parity = [dword_parity(d) ^ 0xf for d in self.data]

    def check_parity(self):
        return (
            self.parity == [dword_parity(d) ^ 0xf for d in self.data]
        )

    def __eq__(self, other):
        if isinstance(other, S5PcieFrame):
            return (
                self.data == other.data and
                self.parity == other.parity and
                self.bar == other.bar and
                self.err == other.err
            )
        return False

    def __repr__(self):
        return (
            f"{type(self).__name__}(data=[{', '.join(f'{x:#010x}' for x in self.data)}], "
            f"parity=[{', '.join(hex(x) for x in self.parity)}], "
            f"bar={self.bar:#04x}, "
            f"err={self.err})"
        )

    def __len__(self):
        return len(self.data)


class S5PcieTransaction:

    _signals = ["data", "empty", "sop", "eop", "valid", "err", "bar", "parity"]

    def __init__(self, *args, **kwargs):
        for sig in self._signals:
            if sig in kwargs:
                setattr(self, sig, kwargs[sig])
                del kwargs[sig]
            else:
                setattr(self, sig, 0)

        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"{type(self).__name__}({', '.join(f'{s}={int(getattr(self, s))}' for s in self._signals)})"


class S5PcieBase:

    _signal_widths = {"ready": 1}

    _valid_signal = "valid"
    _ready_signal = "ready"

    _transaction_obj = S5PcieTransaction
    _frame_obj = S5PcieFrame

    def __init__(self, bus, clock, reset=None, ready_latency=0, *args, **kwargs):
        self.bus = bus
        self.clock = clock
        self.reset = reset
        self.ready_latency = ready_latency
        if bus._name:
            self.log = logging.getLogger(f"cocotb.{bus._entity._name}.{bus._name}")
        else:
            self.log = logging.getLogger(f"cocotb.{bus._entity._name}")

        super().__init__(*args, **kwargs)

        self.active = False
        self.queue = Queue()
        self.dequeue_event = Event()
        self.idle_event = Event()
        self.idle_event.set()
        self.active_event = Event()

        self.pause = False
        self._pause_generator = None
        self._pause_cr = None

        self.queue_occupancy_bytes = 0
        self.queue_occupancy_frames = 0

        self.width = len(self.bus.data)
        self.byte_size = 32
        self.byte_lanes = self.width // self.byte_size
        self.byte_mask = 2**self.byte_size-1

        self.qword_lanes = self.width // 64
        self.empty_width = (self.qword_lanes-1).bit_length()
        self.empty_mask = 2**self.empty_width-1 if self.empty_width else 0
        self.par_width = self.width // 8

        assert self.width in {128, 256}, "only 128-bit and 256-bit Avalon-ST widths are currently supported"

        if hasattr(self.bus, "empty"):
            # the datasheet declares rx_st_empty/tx_st_empty as [1:0] regardless
            # of interface width, but only the low bits apply for the 128-bit
            # interface, so accept anything wide enough to carry the encoding
            assert self.empty_width <= len(self.bus.empty) <= 2
        if hasattr(self.bus, "bar"):
            assert len(self.bus.bar) == 8
        if hasattr(self.bus, "parity"):
            assert len(self.bus.parity) == self.par_width

    def count(self):
        return self.queue.qsize()

    def empty(self):
        return self.queue.empty()

    def clear(self):
        while not self.queue.empty():
            self.queue.get_nowait()
        self.idle_event.set()
        self.active_event.clear()

    def idle(self):
        raise NotImplementedError()

    async def wait(self):
        raise NotImplementedError()

    def set_pause_generator(self, generator=None):
        if self._pause_cr is not None:
            self._pause_cr.kill()
            self._pause_cr = None

        self._pause_generator = generator

        if self._pause_generator is not None:
            self._pause_cr = cocotb.start_soon(self._run_pause())

    def clear_pause_generator(self):
        self.set_pause_generator(None)

    async def _run_pause(self):
        clock_edge_event = RisingEdge(self.clock)

        for val in self._pause_generator:
            self.pause = val
            await clock_edge_event


class S5PcieSource(S5PcieBase):

    _signal_widths = {"valid": 1, "ready": 1}

    _valid_signal = "valid"
    _ready_signal = "ready"

    _transaction_obj = S5PcieTransaction
    _frame_obj = S5PcieFrame

    def __init__(self, bus, clock, reset=None, ready_latency=0, *args, **kwargs):
        super().__init__(bus, clock, reset, ready_latency, *args, **kwargs)

        self.drive_obj = None
        self.drive_sync = Event()

        self.queue_occupancy_limit_bytes = -1
        self.queue_occupancy_limit_frames = -1

        self.bus.data.value = Immediate(0)
        self.bus.sop.value = Immediate(0)
        self.bus.eop.value = Immediate(0)
        self.bus.valid.value = Immediate(0)

        if hasattr(self.bus, "empty"):
            self.bus.empty.value = Immediate(0)
        if hasattr(self.bus, "err"):
            self.bus.err.value = Immediate(0)
        if hasattr(self.bus, "bar"):
            self.bus.bar.value = Immediate(0)
        if hasattr(self.bus, "parity"):
            self.bus.parity.value = Immediate(0)

        cocotb.start_soon(self._run_source())
        cocotb.start_soon(self._run())

    async def _drive(self, obj):
        if self.drive_obj is not None:
            self.drive_sync.clear()
            await self.drive_sync.wait()

        self.drive_obj = obj

    async def send(self, frame):
        while self.full():
            self.dequeue_event.clear()
            await self.dequeue_event.wait()
        frame = S5PcieFrame(frame)
        await self.queue.put(frame)
        self.idle_event.clear()
        self.queue_occupancy_bytes += len(frame)
        self.queue_occupancy_frames += 1

    def send_nowait(self, frame):
        if self.full():
            raise QueueFull()
        frame = S5PcieFrame(frame)
        self.queue.put_nowait(frame)
        self.idle_event.clear()
        self.queue_occupancy_bytes += len(frame)
        self.queue_occupancy_frames += 1

    def full(self):
        if self.queue_occupancy_limit_bytes > 0 and self.queue_occupancy_bytes > self.queue_occupancy_limit_bytes:
            return True
        elif self.queue_occupancy_limit_frames > 0 and self.queue_occupancy_frames > self.queue_occupancy_limit_frames:
            return True
        else:
            return False

    def idle(self):
        return self.empty() and not self.active

    async def wait(self):
        await self.idle_event.wait()

    async def _run_source(self):
        self.active = False
        ready_delay = []

        clock_edge_event = RisingEdge(self.clock)

        while True:
            await clock_edge_event

            ready_sample = self.bus.ready.value
            valid_sample = self.bus.valid.value

            if self.reset is not None and self.reset.value:
                self.active = False
                self.bus.valid.value = 0
                continue

            if self.ready_latency > 1:
                if len(ready_delay) != (self.ready_latency-1):
                    ready_delay = [0]*(self.ready_latency-1)
                ready_delay.append(ready_sample)
                ready_sample = ready_delay.pop(0)

            if (ready_sample and valid_sample) or not valid_sample or self.ready_latency > 0:
                if self.drive_obj and not self.pause and (ready_sample or self.ready_latency == 0):
                    self.bus.drive(self.drive_obj)
                    self.drive_obj = None
                    self.drive_sync.set()
                    self.active = True
                else:
                    self.bus.valid.value = 0
                    self.active = bool(self.drive_obj)
                    if not self.drive_obj:
                        self.idle_event.set()

    async def _run(self):
        while True:
            frame = await self._get_frame()
            frame_offset = 0
            self.log.info("TX frame: %r", frame)

            while frame_offset < len(frame.data):
                transaction = self._transaction_obj()

                n = min(self.byte_lanes, len(frame.data)-frame_offset)

                data = 0
                parity = 0
                for k in range(n):
                    data |= frame.data[frame_offset+k] << 32*k
                    if frame.parity:
                        parity |= frame.parity[frame_offset+k] << 4*k

                transaction.data = data
                transaction.parity = parity
                transaction.valid = 1
                transaction.bar = frame.bar
                transaction.err = frame.err

                if frame_offset == 0:
                    transaction.sop = 1

                frame_offset += n

                if frame_offset >= len(frame.data):
                    transaction.eop = 1
                    empty_dwords = self.byte_lanes-n
                    transaction.empty = (empty_dwords // 2) & self.empty_mask

                await self._drive(transaction)

    async def _get_frame(self):
        frame = await self.queue.get()
        self.dequeue_event.set()
        self.queue_occupancy_bytes -= len(frame)
        self.queue_occupancy_frames -= 1
        return frame

    def _get_frame_nowait(self):
        frame = self.queue.get_nowait()
        self.dequeue_event.set()
        self.queue_occupancy_bytes -= len(frame)
        self.queue_occupancy_frames -= 1
        return frame


class S5PcieSink(S5PcieBase):

    _signal_widths = {"valid": 1, "ready": 1}

    _valid_signal = "valid"
    _ready_signal = "ready"

    _transaction_obj = S5PcieTransaction
    _frame_obj = S5PcieFrame

    def __init__(self, bus, clock, reset=None, ready_latency=0, *args, **kwargs):
        super().__init__(bus, clock, reset, ready_latency, *args, **kwargs)

        self.sample_obj = None
        self.sample_sync = Event()

        self.queue_occupancy_limit_bytes = -1
        self.queue_occupancy_limit_frames = -1

        self.bus.ready.value = Immediate(0)

        cocotb.start_soon(self._run_sink())
        cocotb.start_soon(self._run())

    def _recv(self, frame):
        if self.queue.empty():
            self.active_event.clear()
        self.queue_occupancy_bytes -= len(frame)
        self.queue_occupancy_frames -= 1
        return frame

    async def recv(self):
        frame = await self.queue.get()
        return self._recv(frame)

    def recv_nowait(self):
        frame = self.queue.get_nowait()
        return self._recv(frame)

    def full(self):
        if self.queue_occupancy_limit_bytes > 0 and self.queue_occupancy_bytes > self.queue_occupancy_limit_bytes:
            return True
        elif self.queue_occupancy_limit_frames > 0 and self.queue_occupancy_frames > self.queue_occupancy_limit_frames:
            return True
        else:
            return False

    def idle(self):
        return not self.active

    async def wait(self, timeout=0, timeout_unit='ns'):
        if not self.empty():
            return
        if timeout:
            await First(self.active_event.wait(), Timer(timeout, timeout_unit))
        else:
            await self.active_event.wait()

    async def _run_sink(self):
        ready_delay = []

        clock_edge_event = RisingEdge(self.clock)

        while True:
            await clock_edge_event

            ready_sample = self.bus.ready.value
            valid_sample = self.bus.valid.value

            if self.reset is not None and self.reset.value:
                self.bus.ready.value = 0
                continue

            if self.ready_latency > 0:
                if len(ready_delay) != self.ready_latency:
                    ready_delay = [0]*self.ready_latency
                ready_delay.append(ready_sample)
                ready_sample = ready_delay.pop(0)

            if valid_sample and ready_sample:
                self.sample_obj = self._transaction_obj()
                self.bus.sample(self.sample_obj)
                self.sample_sync.set()
            elif self.ready_latency > 0:
                assert not valid_sample, "handshake error: valid asserted outside of ready cycle"

            self.bus.ready.value = (not self.full() and not self.pause)

    async def _run(self):
        self.active = False
        frame = None
        err = 0

        while True:
            while not self.sample_obj:
                self.sample_sync.clear()
                await self.sample_sync.wait()

            self.active = True
            sample = self.sample_obj
            self.sample_obj = None

            if int(sample.sop):
                assert frame is None, "framing error: sop asserted in frame"
                frame = S5PcieFrame()
                frame.bar = int(sample.bar)
                err = 0

            assert frame is not None, "framing error: data transferred outside of frame"

            data = int(sample.data)
            parity = int(sample.parity)
            for k in range(self.byte_lanes):
                frame.data.append((data >> 32*k) & 0xffffffff)
                frame.parity.append((parity >> 4*k) & 0xf)

            err |= int(sample.err)

            if int(sample.eop):
                empty_dwords = (int(sample.empty) & self.empty_mask) * 2
                if empty_dwords:
                    del frame.data[-empty_dwords:]
                    del frame.parity[-empty_dwords:]

                frame.err = err

                self.log.info("RX frame: %r", frame)
                self._sink_frame(frame)
                self.active = False
                frame = None

    def _sink_frame(self, frame):
        self.queue_occupancy_bytes += len(frame)
        self.queue_occupancy_frames += 1

        if frame.err:
            self.log.warning("Dropping nullified (tx_st_err) TLP: %r", frame)
            self.queue_occupancy_bytes -= len(frame)
            self.queue_occupancy_frames -= 1
            return

        self.queue.put_nowait(frame)
        self.active_event.set()
