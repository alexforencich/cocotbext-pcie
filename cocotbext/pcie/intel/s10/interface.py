"""

Copyright (c) 2021-2025 Alex Forencich

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
from cocotb_bus.bus import Bus

from cocotbext.pcie.core.tlp import Tlp


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


class S10TxBus(BaseBus):
    _signals = ["data", "sop", "eop", "valid", "ready", "err"]
    _optional_signals = ["parity", "vf_active"]


class S10RxBus(BaseBus):
    _signals = ["data", "empty", "sop", "eop", "valid", "ready", "bar_range"]
    _optional_signals = ["vf_active", "func_num", "vf_num", "parity"]


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


def parity(d):
    d ^= d >> 4
    d ^= d >> 2
    d ^= d >> 1
    b = 0x1
    p = 0
    while d:
        if d & 0x1:
            p |= b
        d >>= 8
        b <<= 1
    return p


class S10PcieFrame:
    def __init__(self, frame=None):
        self.data = []
        self.parity = []
        self.func_num = 0
        self.vf_num = None
        self.bar_range = 0
        self.err = 0

        if isinstance(frame, Tlp):
            hdr = frame.pack_header()
            for k in range(0, len(hdr), 4):
                self.data.extend(struct.unpack_from('>L', hdr, k))

            data = frame.get_data()
            for k in range(0, len(data), 4):
                self.data.extend(struct.unpack_from('<L', data, k))

            self.update_parity()

        elif isinstance(frame, S10PcieFrame):
            self.data = list(frame.data)
            self.parity = list(frame.parity)
            self.func_num = frame.func_num
            self.vf_num = frame.vf_num
            self.bar_range = frame.bar_range
            self.err = frame.err

    @classmethod
    def from_tlp(cls, tlp):
        return cls(tlp)

    def to_tlp(self):
        hdr = bytearray()
        for dw in self.data[:5]:
            hdr.extend(struct.pack('>L', dw))
        tlp = Tlp.unpack_header(hdr)

        for dw in self.data[tlp.get_header_size_dw():]:
            tlp.data.extend(struct.pack('<L', dw))

        return tlp

    def update_parity(self):
        self.parity = [dword_parity(d) ^ 0xf for d in self.data]

    def check_parity(self):
        return (
            self.parity == [dword_parity(d) ^ 0xf for d in self.data]
        )

    def __eq__(self, other):
        if isinstance(other, S10PcieFrame):
            return (
                self.data == other.data and
                self.parity == other.parity and
                self.func_num == other.func_num and
                self.vf_num == other.vf_num and
                self.bar_range == other.bar_range and
                self.err == other.err
            )
        return False

    def __repr__(self):
        return (
            f"{type(self).__name__}(data=[{', '.join(f'{x:#010x}' for x in self.data)}], "
            f"parity=[{', '.join(hex(x) for x in self.parity)}], "
            f"func_num={self.func_num}, "
            f"vf_num={self.vf_num}, "
            f"bar_range={self.bar_range}, "
            f"err={self.err})"
        )

    def __len__(self):
        return len(self.data)


class S10PcieTransaction:

    _signals = ["data", "empty", "sop", "eop", "valid", "err",
        "vf_active", "func_num", "vf_num", "bar_range", "parity"]

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


class S10PcieBase:

    _signal_widths = {"ready": 1}

    _valid_signal = "valid"
    _ready_signal = "ready"

    _transaction_obj = S10PcieTransaction
    _frame_obj = S10PcieFrame

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

        self.seg_count = len(self.bus.valid)
        self.seg_width = self.width // self.seg_count
        self.seg_mask = 2**self.seg_width-1
        self.seg_par_width = self.seg_width // 8
        self.seg_par_mask = 2**self.seg_par_width-1
        self.seg_byte_lanes = self.byte_lanes // self.seg_count
        self.seg_empty_width = (self.seg_byte_lanes-1).bit_length()
        self.seg_empty_mask = 2**self.seg_empty_width-1

        assert self.width in {256, 512}

        assert len(self.bus.data) == self.seg_count*self.seg_width
        assert len(self.bus.sop) == self.seg_count
        assert len(self.bus.eop) == self.seg_count
        assert len(self.bus.valid) == self.seg_count

        if hasattr(self.bus, "empty"):
            assert len(self.bus.empty) == self.seg_count*self.seg_empty_width

        if hasattr(self.bus, "err"):
            assert len(self.bus.err) == self.seg_count
        if hasattr(self.bus, "bar_range"):
            assert len(self.bus.bar_range) == self.seg_count*3

        if hasattr(self.bus, "vf_active"):
            assert len(self.bus.vf_active) == self.seg_count
        if hasattr(self.bus, "func_num"):
            assert len(self.bus.func_num) == self.seg_count*2
        if hasattr(self.bus, "vf_num"):
            assert len(self.bus.vf_num) == self.seg_count*11

        if hasattr(self.bus, "parity"):
            assert len(self.bus.parity) == self.seg_count*self.seg_width//8

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


class S10PcieSource(S10PcieBase):

    _signal_widths = {"valid": 1, "ready": 1}

    _valid_signal = "valid"
    _ready_signal = "ready"

    _transaction_obj = S10PcieTransaction
    _frame_obj = S10PcieFrame

    def __init__(self, bus, clock, reset=None, ready_latency=0, *args, **kwargs):
        super().__init__(bus, clock, reset, ready_latency, *args, **kwargs)

        self.drive_obj = None
        self.drive_sync = Event()

        self.queue_occupancy_limit_bytes = -1
        self.queue_occupancy_limit_frames = -1

        self.bus.data.setimmediatevalue(0)
        self.bus.sop.setimmediatevalue(0)
        self.bus.eop.setimmediatevalue(0)
        self.bus.valid.setimmediatevalue(0)

        if hasattr(self.bus, "empty"):
            self.bus.empty.setimmediatevalue(0)

        if hasattr(self.bus, "err"):
            self.bus.err.setimmediatevalue(0)
        if hasattr(self.bus, "bar_range"):
            self.bus.bar_range.setimmediatevalue(0)

        if hasattr(self.bus, "vf_active"):
            self.bus.vf_active.setimmediatevalue(0)
        if hasattr(self.bus, "func_num"):
            self.bus.func_num.setimmediatevalue(0)
        if hasattr(self.bus, "vf_num"):
            self.bus.vf_num.setimmediatevalue(0)

        if hasattr(self.bus, "parity"):
            self.bus.parity.setimmediatevalue(0)

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
        frame = S10PcieFrame(frame)
        await self.queue.put(frame)
        self.idle_event.clear()
        self.queue_occupancy_bytes += len(frame)
        self.queue_occupancy_frames += 1

    def send_nowait(self, frame):
        if self.full():
            raise QueueFull()
        frame = S10PcieFrame(frame)
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

            # read handshake signals
            ready_sample = self.bus.ready.value
            valid_sample = self.bus.valid.value

            if self.reset is not None and self.reset.value:
                self.active = False
                self.bus.valid.value = 0
                continue

            # ready delay
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
            first = True

            while frame is not None:
                transaction = self._transaction_obj()

                for seg in range(self.seg_count):
                    if frame is None:
                        if not self.empty():
                            frame = self._get_frame_nowait()
                            frame_offset = 0
                            self.log.info("TX frame: %r", frame)
                            first = True
                        else:
                            break

                    if first:
                        first = False

                        transaction.valid |= 1 << seg
                        transaction.sop |= 1 << seg

                    transaction.bar_range |= frame.bar_range << seg*3
                    transaction.func_num |= frame.func_num << seg*3
                    if frame.vf_num is not None:
                        transaction.vf_active |= 1 << seg
                        transaction.vf_num |= frame.vf_num << seg*11
                    transaction.err |= frame.err << seg

                    empty = 0
                    if frame.data:
                        transaction.valid |= 1 << seg

                        for k in range(min(self.seg_byte_lanes, len(frame.data)-frame_offset)):
                            transaction.data |= frame.data[frame_offset] << 32*(k+seg*self.seg_byte_lanes)
                            transaction.parity |= frame.parity[frame_offset] << 4*(k+seg*self.seg_byte_lanes)
                            empty = self.seg_byte_lanes-1-k
                            frame_offset += 1

                    if frame_offset >= len(frame.data):
                        transaction.eop |= 1 << seg
                        transaction.empty |= empty << seg*self.seg_empty_width

                        frame = None

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


class S10PcieSink(S10PcieBase):

    _signal_widths = {"valid": 1, "ready": 1}

    _valid_signal = "valid"
    _ready_signal = "ready"

    _transaction_obj = S10PcieTransaction
    _frame_obj = S10PcieFrame

    def __init__(self, bus, clock, reset=None, ready_latency=0, *args, **kwargs):
        super().__init__(bus, clock, reset, ready_latency, *args, **kwargs)

        self.sample_obj = None
        self.sample_sync = Event()

        self.queue_occupancy_limit_bytes = -1
        self.queue_occupancy_limit_frames = -1

        self.bus.ready.setimmediatevalue(0)

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

            # read handshake signals
            ready_sample = self.bus.ready.value
            valid_sample = self.bus.valid.value

            if self.reset is not None and self.reset.value:
                self.bus.ready.value = 0
                continue

            # ready delay
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
        dword_count = 0

        while True:
            while not self.sample_obj:
                self.sample_sync.clear()
                await self.sample_sync.wait()

            self.active = True
            sample = self.sample_obj
            self.sample_obj = None

            for seg in range(self.seg_count):
                if not int(sample.valid) & (1 << seg):
                    continue

                if int(sample.sop) & (1 << seg):
                    assert frame is None, "framing error: sop asserted in frame"
                    frame = S10PcieFrame()

                    hdr = (int(sample.data) >> (seg*self.seg_width)) & self.seg_mask
                    fmt = (hdr >> 29) & 0b111
                    if fmt & 0b001:
                        dword_count = 4
                    else:
                        dword_count = 3

                    if fmt & 0b010:
                        count = hdr & 0x3ff
                        if count == 0:
                            count = 1024
                        dword_count += count

                    frame.bar_range = (int(sample.bar_range) >> seg*3) & 0x7
                    frame.func_num = (int(sample.func_num) >> seg*3) & 0x7
                    if int(sample.vf_active) & (1 << seg):
                        frame.vf_num = (int(sample.vf_num) >> seg*11) & 0x7ff
                    frame.err = (int(sample.err) >> seg) & 0x1

                assert frame is not None, "framing error: data transferred outside of frame"

                if dword_count > 0:
                    data = (int(sample.data) >> (seg*self.seg_width)) & self.seg_mask
                    parity = (int(sample.parity) >> (seg*self.seg_par_width)) & self.seg_par_mask
                    for k in range(min(self.seg_byte_lanes, dword_count)):
                        frame.data.append((data >> 32*k) & 0xffffffff)
                        frame.parity.append((parity >> 4*k) & 0xf)
                        dword_count -= 1

                if int(sample.eop) & (1 << seg):
                    assert dword_count == 0, "framing error: incorrect length or early eop"
                    self.log.info("RX frame: %r", frame)
                    self._sink_frame(frame)
                    self.active = False
                    frame = None

    def _sink_frame(self, frame):
        self.queue_occupancy_bytes += len(frame)
        self.queue_occupancy_frames += 1

        self.queue.put_nowait(frame)
        self.active_event.set()
