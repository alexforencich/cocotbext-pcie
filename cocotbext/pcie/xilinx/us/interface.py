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

import logging

import cocotb
from cocotb.queue import Queue, QueueFull
from cocotb.triggers import RisingEdge, Timer, First, Event


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


class UsPcieFrame:
    def __init__(self, frame=None):
        self.data = []
        self.byte_en = []
        self.parity = []
        self.first_be = 0
        self.last_be = 0
        self.discontinue = False
        self.seq_num = 0

        if isinstance(frame, UsPcieFrame):
            self.data = list(frame.data)
            self.byte_en = list(frame.byte_en)
            self.parity = list(frame.parity)
            self.first_be = frame.first_be
            self.last_be = frame.last_be
            self.discontinue = frame.discontinue
            self.seq_num = frame.seq_num

    def update_parity(self):
        self.parity = [dword_parity(d) ^ 0xf for d in self.data]

    def check_parity(self):
        return self.parity == [dword_parity(d) ^ 0xf for d in self.data]

    def __eq__(self, other):
        if isinstance(other, UsPcieFrame):
            return (
                self.data == other.data and
                self.byte_en == other.byte_en and
                self.parity == other.parity and
                self.first_be == other.first_be and
                self.last_be == other.last_be and
                self.discontinue == other.discontinue and
                self.seq_num == other.seq_num
            )
        return False

    def __repr__(self):
        return (
            f"{type(self).__name__}(data=[{', '.join(f'{x:#010x}' for x in self.data)}], "
            f"byte_en=[{', '.join(hex(x) for x in self.byte_en)}], "
            f"parity=[{', '.join(hex(x) for x in self.parity)}], "
            f"first_be={self.first_be:#x}, "
            f"last_be={self.last_be:#x}, "
            f"discontinue={self.discontinue}, "
            f"seq_num={self.seq_num})"
        )

    def __len__(self):
        return len(self.data)


class UsPcieTransaction:

    _signals = ["tdata", "tlast", "tkeep", "tuser"]

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


class UsPcieBase:

    _signal_widths = {"tvalid": 1, "tready": 1}

    _valid_signal = "tvalid"
    _ready_signal = "tready"

    _transaction_obj = UsPcieTransaction
    _frame_obj = UsPcieFrame

    def __init__(self, bus, clock, reset=None, *args, **kwargs):
        self.bus = bus
        self.clock = clock
        self.reset = reset
        self.log = logging.getLogger(f"cocotb.{bus._entity._name}.{bus._name}")

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

        self.width = len(self.bus.tdata)
        self.byte_lanes = len(self.bus.tkeep)

        self.byte_size = self.width // self.byte_lanes
        self.byte_mask = 2**self.byte_size-1

        assert self.width in {64, 128, 256, 512}
        assert self.byte_size == 32

    def _init(self):
        pass

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


class UsPcieSource(UsPcieBase):

    _signal_widths = {"tvalid": 1, "tready": 1}

    _valid_signal = "tvalid"
    _ready_signal = "tready"

    _transaction_obj = UsPcieTransaction
    _frame_obj = UsPcieFrame

    def __init__(self, bus, clock, reset=None, *args, **kwargs):
        super().__init__(bus, clock, reset, *args, **kwargs)

        self.drive_obj = None
        self.drive_sync = Event()

        self.queue_occupancy_limit_bytes = -1
        self.queue_occupancy_limit_frames = -1

        self.bus.tdata.setimmediatevalue(0)
        self.bus.tvalid.setimmediatevalue(0)
        self.bus.tlast.setimmediatevalue(0)
        self.bus.tkeep.setimmediatevalue(0)
        self.bus.tuser.setimmediatevalue(0)

        self._init()

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
        frame = UsPcieFrame(frame)
        await self.queue.put(frame)
        self.idle_event.clear()
        self.queue_occupancy_bytes += len(frame)
        self.queue_occupancy_frames += 1

    def send_nowait(self, frame):
        if self.full():
            raise QueueFull()
        frame = UsPcieFrame(frame)
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

        clock_edge_event = RisingEdge(self.clock)

        while True:
            await clock_edge_event

            # read handshake signals
            tready_sample = self.bus.tready.value
            tvalid_sample = self.bus.tvalid.value

            if self.reset is not None and self.reset.value:
                self.active = False
                self.bus.tvalid.value = 0
                continue

            if (tready_sample and tvalid_sample) or not tvalid_sample:
                if self.drive_obj and not self.pause:
                    self.bus.drive(self.drive_obj)
                    self.drive_obj = None
                    self.drive_sync.set()
                    self.bus.tvalid.value = 1
                    self.active = True
                else:
                    self.bus.tvalid.value = 0
                    self.active = bool(self.drive_obj)
                    if not self.drive_obj:
                        self.idle_event.set()

    async def _run(self):
        raise NotImplementedError

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


class UsPcieSink(UsPcieBase):

    _signal_widths = {"tvalid": 1, "tready": 1}

    _valid_signal = "tvalid"
    _ready_signal = "tready"

    _transaction_obj = UsPcieTransaction
    _frame_obj = UsPcieFrame

    def __init__(self, bus, clock, reset=None, *args, **kwargs):
        super().__init__(bus, clock, reset, *args, **kwargs)

        self.sample_obj = None
        self.sample_sync = Event()

        self.queue_occupancy_limit_bytes = -1
        self.queue_occupancy_limit_frames = -1

        self.bus.tready.setimmediatevalue(0)

        self._init()

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
        clock_edge_event = RisingEdge(self.clock)

        while True:
            await clock_edge_event

            # read handshake signals
            tready_sample = self.bus.tready.value
            tvalid_sample = self.bus.tvalid.value

            if self.reset is not None and self.reset.value:
                self.bus.tready.value = 0
                continue

            if tready_sample and tvalid_sample:
                self.sample_obj = self._transaction_obj()
                self.bus.sample(self.sample_obj)
                self.sample_sync.set()

            self.bus.tready.value = (not self.full() and not self.pause)

    async def _run(self):
        raise NotImplementedError()

    def _sink_frame(self, frame):
        self.queue_occupancy_bytes += len(frame)
        self.queue_occupancy_frames += 1

        self.queue.put_nowait(frame)
        self.active_event.set()


class RqSource(UsPcieSource):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 137
        else:
            assert len(self.bus.tuser) in [60, 62]

    async def _run(self):
        while True:
            frame = await self._get_frame()
            frame_offset = 0
            self.log.info(f"TX RQ frame: {frame}")
            first = True

            while frame_offset < len(frame.data):
                transaction = self._transaction_obj()

                if self.width == 512:
                    if first:
                        transaction.tuser |= (frame.first_be & 0xf)
                        transaction.tuser |= (frame.last_be & 0xf) << 8
                        transaction.tuser |= 0b01 << 20  # is_sop
                        transaction.tuser |= 0b00 << 22  # is_sop0_ptr

                    transaction.tuser |= bool(frame.discontinue) << 36
                    transaction.tuser |= (frame.seq_num & 0x3f) << 61

                    last_lane = 0

                    for i in range(self.byte_lanes):
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << i*32
                            transaction.tkeep |= 1 << i
                            transaction.tuser |= frame.parity[frame_offset] << i*4+73
                            last_lane = i
                        else:
                            transaction.tuser |= 0xf << i*4+73

                        frame_offset += 1

                    if frame_offset >= len(frame.data):
                        transaction.tuser |= 0b01 << 26  # is_eop
                        transaction.tuser |= (last_lane & 0xf) << 28  # is_eop0_ptr
                else:
                    if first:
                        transaction.tuser |= (frame.first_be & 0xf)
                        transaction.tuser |= (frame.last_be & 0xf) << 4

                    transaction.tuser |= bool(frame.discontinue) << 11
                    transaction.tuser |= (frame.seq_num & 0xf) << 24

                    if len(self.bus.tuser) == 62:
                        transaction.tuser |= ((frame.seq_num >> 4) & 0x3) << 60

                    for i in range(self.byte_lanes):
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << i*32
                            transaction.tkeep |= 1 << i
                            transaction.tuser |= frame.parity[frame_offset] << i*4+28
                        else:
                            transaction.tuser |= 0xf << i*4+28

                        frame_offset += 1

                    # TODO tph

                first = False
                transaction.tlast = frame_offset >= len(frame.data)
                await self._drive(transaction)


class RqSink(UsPcieSink):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 137
        else:
            assert len(self.bus.tuser) in [60, 62]

    async def _run(self):
        self.active = False
        frame = UsPcieFrame()
        first = True

        while True:
            while not self.sample_obj:
                self.sample_sync.clear()
                await self.sample_sync.wait()

            self.active = True
            sample = self.sample_obj
            self.sample_obj = None

            if self.width == 512:
                if first:
                    frame.first_be = sample.tuser & 0xf
                    frame.last_be = (sample.tuser >> 8) & 0xf
                    frame.seq_num = (sample.tuser >> 61) & 0x3f

                frame.discontinue |= bool(sample.tuser & (1 << 36))

                last_lane = 0

                for i in range(self.byte_lanes):
                    if sample.tkeep & (1 << i):
                        frame.data.append((sample.tdata >> (i*32)) & 0xffffffff)
                        frame.parity.append((sample.tuser >> (i*4+73)) & 0xf)
                        last_lane = i
            else:
                if first:
                    frame.first_be = sample.tuser & 0xf
                    frame.last_be = (sample.tuser >> 4) & 0xf
                    frame.seq_num = (sample.tuser >> 24) & 0xf

                    if len(self.bus.tuser) == 62:
                        frame.seq_num |= ((sample.tuser >> 60) & 0x3) << 4

                frame.discontinue |= bool(sample.tuser & (1 << 11))

                for i in range(self.byte_lanes):
                    if sample.tkeep & (1 << i):
                        frame.data.append((sample.tdata >> (i*32)) & 0xffffffff)
                        frame.parity.append((sample.tuser >> (i*4+28)) & 0xf)

            first = False
            if sample.tlast:
                self.log.info(f"RX RQ frame: {frame}")

                self._sink_frame(frame)

                self.active = False
                frame = UsPcieFrame()
                first = True


class RcSource(UsPcieSource):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 161
        else:
            assert len(self.bus.tuser) == 75

    async def _run(self):
        while True:
            frame = await self._get_frame()
            frame_offset = 0
            self.log.info(f"TX RC frame: {frame}")
            first = True

            while frame_offset < len(frame.data):
                transaction = self._transaction_obj()

                if self.width == 512:
                    if first:
                        transaction.tuser |= 0b0001 << 64  # is_sop
                        transaction.tuser |= 0b00 << 68  # is_sop0_ptr

                    transaction.tuser |= bool(frame.discontinue) << 96

                    last_lane = 0

                    for i in range(self.byte_lanes):
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << i*32
                            transaction.tkeep |= 1 << i
                            transaction.tuser |= frame.byte_en[frame_offset] << i*4
                            transaction.tuser |= frame.parity[frame_offset] << i*4+97
                            last_lane = i
                        else:
                            transaction.tuser |= 0xf << i*4+97

                        frame_offset += 1

                    if frame_offset >= len(frame.data):
                        transaction.tuser |= 0b0001 << 76  # is_eop
                        transaction.tuser |= last_lane << 80  # is_eop0_ptr
                else:
                    if first:
                        transaction.tuser |= 1 << 32  # is_sof_0

                    transaction.tuser |= bool(frame.discontinue) << 42

                    last_lane = 0

                    for i in range(self.byte_lanes):
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << i*32
                            transaction.tkeep |= 1 << i
                            transaction.tuser |= frame.byte_en[frame_offset] << i*4
                            transaction.tuser |= frame.parity[frame_offset] << i*4+43
                            last_lane = i
                        else:
                            transaction.tuser |= 0xf << i*4+43

                        frame_offset += 1

                    if not frame.data:
                        transaction.tuser |= (1 | last_lane << 1) << 34  # is_eof_0

                first = False
                transaction.tlast = frame_offset >= len(frame.data)
                await self._drive(transaction)


class RcSink(UsPcieSink):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 161
        else:
            assert len(self.bus.tuser) == 75

    async def _run(self):
        self.active = False
        frame = UsPcieFrame()
        first = True

        while True:
            while not self.sample_obj:
                self.sample_sync.clear()
                await self.sample_sync.wait()

            self.active = True
            sample = self.sample_obj
            self.sample_obj = None

            if self.width == 512:
                frame.discontinue |= bool(sample.tuser & (1 << 96))

                last_lane = 0

                for i in range(self.byte_lanes):
                    if sample.tkeep & (1 << i):
                        frame.data.append((sample.tdata >> (i*32)) & 0xffffffff)
                        frame.byte_en.append((sample.tuser >> (i*4)) & 0xf)
                        frame.parity.append((sample.tuser >> (i*4+97)) & 0xf)
                        last_lane = i
            else:
                frame.discontinue |= bool(sample.tuser & (1 << 42))

                last_lane = 0

                for i in range(self.byte_lanes):
                    if sample.tkeep & (1 << i):
                        frame.data.append((sample.tdata >> (i*32)) & 0xffffffff)
                        frame.byte_en.append((sample.tuser >> (i*4)) & 0xf)
                        frame.parity.append((sample.tuser >> (i*4+43)) & 0xf)
                        last_lane = i

            first = False
            if sample.tlast:
                self.log.info(f"RX RC frame: {frame}")

                self._sink_frame(frame)

                self.active = False
                frame = UsPcieFrame()
                first = True


class CqSource(UsPcieSource):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 183
        else:
            assert len(self.bus.tuser) in [85, 88]

    async def _run(self):
        while True:
            frame = await self._get_frame()
            frame_offset = 0
            self.log.info(f"TX CQ frame: {frame}")
            first = True

            while frame_offset < len(frame.data):
                transaction = self._transaction_obj()

                if self.width == 512:
                    if first:
                        transaction.tuser |= (frame.first_be & 0xf)
                        transaction.tuser |= (frame.last_be & 0xf) << 8
                        transaction.tuser |= 0b01 << 80  # is_sop
                        transaction.tuser |= 0b00 << 82  # is_sop0_ptr

                    transaction.tuser |= bool(frame.discontinue) << 96

                    last_lane = 0

                    for i in range(self.byte_lanes):
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << i*32
                            transaction.tkeep |= 1 << i
                            transaction.tuser |= frame.byte_en[frame_offset] << i*4+16
                            transaction.tuser |= frame.parity[frame_offset] << i*4+119
                            last_lane = i
                        else:
                            transaction.tuser |= 0xf << i*4+119

                        frame_offset += 1

                    if frame_offset >= len(frame.data):
                        transaction.tuser |= 0b01 << 86  # is_eop
                        transaction.tuser |= (last_lane & 0xf) << 88  # is_eop0_ptr
                else:
                    if first:
                        transaction.tuser |= (frame.first_be & 0xf)
                        transaction.tuser |= (frame.last_be & 0xf) << 4
                        transaction.tuser |= 1 << 40  # sop

                    transaction.tuser |= bool(frame.discontinue) << 41

                    for i in range(self.byte_lanes):
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << i*32
                            transaction.tkeep |= 1 << i
                            transaction.tuser |= frame.byte_en[frame_offset] << i*4+8
                            transaction.tuser |= frame.parity[frame_offset] << i*4+53
                        else:
                            transaction.tuser |= 0xf << i*4+53

                        frame_offset += 1

                first = False
                transaction.tlast = frame_offset >= len(frame.data)
                await self._drive(transaction)


class CqSink(UsPcieSink):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 183
        else:
            assert len(self.bus.tuser) in [85, 88]

    async def _run(self):
        self.active = False
        frame = UsPcieFrame()
        first = True

        while True:
            while not self.sample_obj:
                self.sample_sync.clear()
                await self.sample_sync.wait()

            self.active = True
            sample = self.sample_obj
            self.sample_obj = None

            if self.width == 512:
                if first:
                    frame.first_be = sample.tuser & 0xf
                    frame.last_be = (sample.tuser >> 8) & 0xf

                frame.discontinue |= bool(sample.tuser & (1 << 96))

                last_lane = 0

                for i in range(self.byte_lanes):
                    if sample.tkeep & (1 << i):
                        frame.data.append((sample.tdata >> (i*32)) & 0xffffffff)
                        frame.byte_en.append((sample.tuser >> (i*4+16)) & 0xf)
                        frame.parity.append((sample.tuser >> (i*4+119)) & 0xf)
                        last_lane = i
            else:
                if first:
                    frame.first_be = sample.tuser & 0xf
                    frame.last_be = (sample.tuser >> 4) & 0xf

                frame.discontinue |= bool(sample.tuser & (1 << 41))

                for i in range(self.byte_lanes):
                    if sample.tkeep & (1 << i):
                        frame.data.append((sample.tdata >> (i*32)) & 0xffffffff)
                        frame.byte_en.append((sample.tuser >> (i*4+8)) & 0xf)
                        frame.parity.append((sample.tuser >> (i*4+53)) & 0xf)

            first = False
            if sample.tlast:
                self.log.info(f"RX CQ frame: {frame}")

                self._sink_frame(frame)

                self.active = False
                frame = UsPcieFrame()
                first = True


class CcSource(UsPcieSource):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 81
        else:
            assert len(self.bus.tuser) == 33

    async def _run(self):
        while True:
            frame = await self._get_frame()
            frame_offset = 0
            self.log.info(f"TX CC frame: {frame}")
            first = True

            while frame_offset < len(frame.data):
                transaction = self._transaction_obj()

                if self.width == 512:
                    if first:
                        transaction.tuser |= 0b01 << 0  # is_sop
                        transaction.tuser |= 0b00 << 2  # is_sop0_ptr

                    transaction.tuser |= bool(frame.discontinue) << 16

                    last_lane = 0

                    for i in range(self.byte_lanes):
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << i*32
                            transaction.tkeep |= 1 << i
                            transaction.tuser |= frame.parity[frame_offset] << i*4+17
                            last_lane = i
                        else:
                            transaction.tuser |= 0xf << i*4+17

                        frame_offset += 1

                    if frame_offset >= len(frame.data):
                        transaction.tuser |= 0b01 << 6  # is_eop
                        transaction.tuser |= (last_lane & 0xf) << 8  # is_eop0_ptr
                else:
                    transaction.tuser |= bool(frame.discontinue)

                    for i in range(self.byte_lanes):
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << i*32
                            transaction.tkeep |= 1 << i
                            transaction.tuser |= frame.parity[frame_offset] << i*4+1
                        else:
                            transaction.tuser |= 0xf << i*4+1

                        frame_offset += 1

                first = False
                transaction.tlast = frame_offset >= len(frame.data)
                await self._drive(transaction)


class CcSink(UsPcieSink):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 81
        else:
            assert len(self.bus.tuser) == 33

    async def _run(self):
        self.active = False
        frame = UsPcieFrame()
        first = True

        while True:
            while not self.sample_obj:
                self.sample_sync.clear()
                await self.sample_sync.wait()

            self.active = True
            sample = self.sample_obj
            self.sample_obj = None

            if self.width == 512:
                frame.discontinue |= bool(sample.tuser & (1 << 16))

                last_lane = 0

                for i in range(self.byte_lanes):
                    if sample.tkeep & (1 << i):
                        frame.data.append((sample.tdata >> (i*32)) & 0xffffffff)
                        frame.parity.append((sample.tuser >> (i*4+17)) & 0xf)
                        last_lane = i
            else:
                frame.discontinue |= bool(sample.tuser & 1)

                for i in range(self.byte_lanes):
                    if sample.tkeep & (1 << i):
                        frame.data.append((sample.tdata >> (i*32)) & 0xffffffff)
                        frame.parity.append((sample.tuser >> (i*4+1)) & 0xf)

            first = False
            if sample.tlast:
                self.log.info(f"RX CC frame: {frame}")

                self._sink_frame(frame)

                self.active = False
                frame = UsPcieFrame()
                first = True
