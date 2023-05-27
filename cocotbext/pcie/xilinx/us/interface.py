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

    def __init__(self, bus, clock, reset=None, segments=1, *args, **kwargs):
        self.bus = bus
        self.clock = clock
        self.reset = reset
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
        self.bus_active_event = Event()
        self.wake_event = Event()

        self._pause = False
        self._pause_generator = None
        self._pause_cr = None

        self.queue_occupancy_bytes = 0
        self.queue_occupancy_frames = 0

        self.width = len(self.bus.tdata)
        self.byte_lanes = len(self.bus.tkeep)

        self.byte_size = self.width // self.byte_lanes
        self.byte_mask = 2**self.byte_size-1

        self.seg_count = segments
        self.seg_width = self.width // self.seg_count
        self.seg_mask = 2**self.seg_width-1
        self.seg_byte_lanes = self.byte_lanes // self.seg_count
        self.seg_par_width = self.seg_width // 8
        self.seg_par_mask = 2**self.seg_par_width-1

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

    def _pause_update(self, val):
        pass

    @property
    def pause(self):
        return self._pause

    @pause.setter
    def pause(self, val):
        if self._pause != val:
            self._pause_update(val)
        self._pause = val

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

    def __init__(self, bus, clock, reset=None, segments=1, *args, **kwargs):
        super().__init__(bus, clock, reset, segments, *args, **kwargs)

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
        self.bus_active_event.set()

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
                        self.bus_active_event.clear()

                        await self.bus_active_event.wait()

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

    def __init__(self, bus, clock, reset=None, segments=1, *args, **kwargs):
        super().__init__(bus, clock, reset, segments, *args, **kwargs)

        self.sample_obj = None
        self.sample_sync = Event()

        self.queue_occupancy_limit_bytes = -1
        self.queue_occupancy_limit_frames = -1

        self.bus.tready.setimmediatevalue(0)

        self._init()

        cocotb.start_soon(self._run_sink())
        cocotb.start_soon(self._run())

        if hasattr(self.bus, "tvalid"):
            cocotb.start_soon(self._run_tvalid_monitor())
        if hasattr(self.bus, "tready"):
            cocotb.start_soon(self._run_tready_monitor())

    def _pause_update(self, val):
        self.wake_event.set()

    def _dequeue(self, frame):
        self.wake_event.set()

    def _recv(self, frame):
        if self.queue.empty():
            self.active_event.clear()
        self.queue_occupancy_bytes -= len(frame)
        self.queue_occupancy_frames -= 1
        self._dequeue(frame)
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

    async def _run_tvalid_monitor(self):
        event = RisingEdge(self.bus.tvalid)

        while True:
            await event
            self.wake_event.set()

    async def _run_tready_monitor(self):
        event = RisingEdge(self.bus.tready)

        while True:
            await event
            self.wake_event.set()

    async def _run_sink(self):
        clock_edge_event = RisingEdge(self.clock)

        wake_event = self.wake_event.wait()

        while True:
            pause_sample = self.pause

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

            self.bus.tready.value = (not self.full() and not pause_sample)

            if not tvalid_sample or (self.pause and pause_sample) or self.full():
                self.wake_event.clear()
                await wake_event

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
            assert self.seg_count in {1, 2}
            self.discontinue_offset = 36
            self.parity_offset = 73
        else:
            assert len(self.bus.tuser) in [60, 62]
            assert self.seg_count == 1
            self.discontinue_offset = 11
            self.parity_offset = 28

    async def _run(self):
        while True:
            frame = await self._get_frame()
            frame_offset = 0
            self.log.info("TX RQ frame: %r", frame)
            first = True

            while frame is not None:
                transaction = self._transaction_obj()
                sop_cnt = 0
                eop_cnt = 0

                for seg in range(self.seg_count):
                    if frame is None:
                        if not self.empty():
                            frame = self._get_frame_nowait()
                            frame_offset = 0
                            self.log.info("TX RQ frame: %r", frame)
                            first = True
                        else:
                            break

                    if first:
                        first = False

                        if self.width == 512:
                            transaction.tuser |= (frame.first_be & 0xf) << (sop_cnt*4)
                            transaction.tuser |= (frame.last_be & 0xf) << (sop_cnt*4+8)
                            # addr_offset
                            transaction.tuser |= (frame.seq_num & 0x3f) << (sop_cnt*6+61)

                            # is_sop
                            transaction.tuser |= 1 << 20+sop_cnt
                            # is_sop_ptr
                            transaction.tuser |= (seg*self.seg_byte_lanes//4) << 22+sop_cnt*2
                        else:
                            transaction.tuser |= (frame.first_be & 0xf)
                            transaction.tuser |= (frame.last_be & 0xf) << 4
                            # addr_offset
                            transaction.tuser |= (frame.seq_num & 0xf) << 24

                            if len(self.bus.tuser) == 62:
                                transaction.tuser |= ((frame.seq_num >> 4) & 0x3) << 60

                        sop_cnt += 1

                    if frame.discontinue:
                        transaction.tuser |= 1 << self.discontinue_offset

                    last_lane = 0
                    for k in range(self.seg_byte_lanes):
                        lane = k+seg*self.seg_byte_lanes
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << lane*32
                            transaction.tkeep |= 1 << lane
                            transaction.tuser |= frame.parity[frame_offset] << lane*4+self.parity_offset
                            frame_offset += 1
                            last_lane = lane
                        else:
                            transaction.tuser |= 0xf << lane*4+self.parity_offset

                    if frame_offset >= len(frame.data):
                        # eop
                        if self.width == 512:
                            # is_eop
                            transaction.tuser |= 1 << 26+eop_cnt
                            # is_eop_ptr
                            transaction.tuser |= last_lane << 28+eop_cnt*4

                        eop_cnt += 1

                        if self.seg_count == 1:
                            transaction.tlast = 1

                        frame = None

                await self._drive(transaction)


class RqSink(UsPcieSink):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 137
            assert self.seg_count in {1, 2}
            self.discontinue_offset = 36
            self.parity_offset = 73
        else:
            assert len(self.bus.tuser) in [60, 62]
            assert self.seg_count == 1
            self.discontinue_offset = 11
            self.parity_offset = 28

    async def _run(self):
        self.active = False
        frame = UsPcieFrame()

        while True:
            while not self.sample_obj:
                self.sample_sync.clear()
                await self.sample_sync.wait()

            self.active = True
            sample = self.sample_obj
            self.sample_obj = None

            lane_valid = 2**self.byte_lanes-1
            seg_valid = 2**self.seg_count-1
            seg_sop = 0
            seg_eop = 0
            sop_cnt = 0

            if self.seg_count == 1:
                lane_valid = sample.tkeep
                seg_valid = 1

                if not frame:
                    seg_sop = 1

                if sample.tlast:
                    seg_eop = 1
            elif self.width == 512:
                sop_byte_lane = 0
                eop_byte_lane = 0
                for k in range(self.seg_count):
                    if sample.tuser & (1 << (20+k)):
                        offset = (sample.tuser >> (22+k*2)) & 0x3
                        sop_byte_lane |= 1 << (offset*4)
                    if sample.tuser & (1 << (26+k)):
                        offset = (sample.tuser >> (28+k*4)) & 0xf
                        eop_byte_lane |= 1 << offset
                lane_valid = 0
                seg_valid = 0
                state = 1
                for k in range(self.byte_lanes):
                    mask = 1 << k
                    seg_mask = 1 << (k // self.seg_byte_lanes)
                    if sop_byte_lane & mask:
                        state = 1
                        seg_sop |= seg_mask
                    if state:
                        lane_valid |= mask
                        seg_valid |= seg_mask
                    if eop_byte_lane & mask:
                        state = 0
                        seg_eop |= seg_mask

            for seg in range(self.seg_count):
                if not seg_valid & (1 << seg):
                    continue

                if seg_sop & (1 << seg):
                    frame = UsPcieFrame()

                    if self.width == 512:
                        frame.first_be = (sample.tuser >> (sop_cnt*4)) & 0xf
                        frame.last_be = (sample.tuser >> (sop_cnt*4+8)) & 0xf
                        # addr_offset
                        frame.seq_num = (sample.tuser >> (sop_cnt*6+61)) & 0x3f
                    else:
                        frame.first_be = sample.tuser & 0xf
                        frame.last_be = (sample.tuser >> 4) & 0xf
                        # addr_offset
                        frame.seq_num = (sample.tuser >> 24) & 0xf

                        if len(self.bus.tuser) == 62:
                            frame.seq_num |= ((sample.tuser >> 60) & 0x3) << 4

                    sop_cnt += 1

                if sample.tuser & (1 << self.discontinue_offset):
                    frame.discontinue = True

                for k in range(self.seg_byte_lanes):
                    lane = k+seg*self.seg_byte_lanes
                    if lane_valid & (1 << lane):
                        frame.data.append((sample.tdata >> lane*32) & 0xffffffff)
                        frame.parity.append((sample.tuser >> (lane*4+self.parity_offset)) & 0xf)

                if seg_eop & (1 << seg):
                    self.log.info("RX RQ frame: %r", frame)
                    self._sink_frame(frame)
                    self.active = False
                    frame = None


class RcSource(UsPcieSource):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 161
            assert self.seg_count in {1, 2, 4}
            self.discontinue_offset = 96
            self.parity_offset = 97
        else:
            assert len(self.bus.tuser) == 75
            assert self.seg_count in {1, 2}
            self.discontinue_offset = 42
            self.parity_offset = 43

    async def _run(self):
        while True:
            frame = await self._get_frame()
            frame_offset = 0
            self.log.info("TX RC frame: %r", frame)
            first = True

            while frame is not None:
                transaction = self._transaction_obj()
                sop_cnt = 0
                eop_cnt = 0

                for seg in range(self.seg_count):
                    if frame is None:
                        if not self.empty():
                            frame = self._get_frame_nowait()
                            frame_offset = 0
                            self.log.info("TX RC frame: %r", frame)
                            first = True
                        else:
                            break

                    if first:
                        first = False

                        if self.width == 512:
                            # is_sop
                            transaction.tuser |= 1 << 64+sop_cnt
                            # is_sop_ptr
                            transaction.tuser |= (seg*self.seg_byte_lanes//4) << 68+sop_cnt*2
                        else:
                            # is_sop
                            transaction.tuser |= 1 << 32+sop_cnt

                        sop_cnt += 1

                    if frame.discontinue:
                        transaction.tuser |= 1 << self.discontinue_offset

                    last_lane = 0
                    for k in range(self.seg_byte_lanes):
                        lane = k+seg*self.seg_byte_lanes
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << lane*32
                            transaction.tkeep |= 1 << lane
                            transaction.tuser |= frame.byte_en[frame_offset] << lane*4
                            transaction.tuser |= frame.parity[frame_offset] << lane*4+self.parity_offset
                            frame_offset += 1
                            last_lane = lane
                        else:
                            transaction.tuser |= 0xf << lane*4+self.parity_offset

                    if frame_offset >= len(frame.data):
                        if self.width == 512:
                            # is_eop
                            transaction.tuser |= 1 << 76+eop_cnt
                            # is_eop_ptr
                            transaction.tuser |= last_lane << 80+eop_cnt*4
                        else:
                            # is_eop
                            transaction.tuser |= 1 << 34+eop_cnt*4
                            transaction.tuser |= last_lane << 35+eop_cnt*4

                        eop_cnt += 1

                        if self.seg_count == 1:
                            transaction.tlast = 1

                        frame = None

                await self._drive(transaction)


class RcSink(UsPcieSink):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 161
            assert self.seg_count in {1, 2, 4}
            self.discontinue_offset = 96
            self.parity_offset = 97
        else:
            assert len(self.bus.tuser) == 75
            assert self.seg_count in {1, 2}
            self.discontinue_offset = 42
            self.parity_offset = 43

    async def _run(self):
        self.active = False
        frame = None

        while True:
            while not self.sample_obj:
                self.sample_sync.clear()
                await self.sample_sync.wait()

            self.active = True
            sample = self.sample_obj
            self.sample_obj = None

            lane_valid = 2**self.byte_lanes-1
            seg_valid = 2**self.seg_count-1
            seg_sop = 0
            seg_eop = 0

            if self.seg_count == 1:
                lane_valid = sample.tkeep
                seg_valid = 1

                if not frame:
                    seg_sop = 1

                if sample.tlast:
                    seg_eop = 1
            elif self.width >= 256:
                sop_byte_lane = 0
                eop_byte_lane = 0
                if self.width == 256:
                    if self.seg_count == 1:
                        if sample.tuser & (1 << 32):
                            sop_byte_lane |= 1 << 0
                    else:
                        if sample.tuser & (1 << 32):
                            sop_byte_lane |= 1 << (4 if frame is not None else 0)
                        if sample.tuser & (2 << 32):
                            sop_byte_lane |= 1 << 4
                    for k in range(self.seg_count):
                        if sample.tuser & (1 << (34+k*4)):
                            offset = ((sample.tuser >> (35+k*4)) & 0x7)
                            eop_byte_lane |= 1 << offset
                elif self.width == 512:
                    for k in range(self.seg_count):
                        if sample.tuser & (1 << (64+k)):
                            offset = ((sample.tuser >> (68+k*2)) & 0x3)
                            sop_byte_lane |= 1 << (offset * 4)
                        if sample.tuser & (1 << (76+k)):
                            offset = ((sample.tuser >> (80+k*4)) & 0xf)
                            eop_byte_lane |= 1 << offset
                lane_valid = 0
                seg_valid = 0
                state = 1
                for k in range(self.byte_lanes):
                    mask = 1 << k
                    seg_mask = 1 << (k // self.seg_byte_lanes)
                    if sop_byte_lane & mask:
                        state = 1
                        seg_sop |= seg_mask
                    if state:
                        lane_valid |= mask
                        seg_valid |= seg_mask
                    if eop_byte_lane & mask:
                        state = 0
                        seg_eop |= seg_mask

            for seg in range(self.seg_count):
                if not seg_valid & (1 << seg):
                    continue

                if seg_sop & (1 << seg):
                    frame = UsPcieFrame()

                if sample.tuser & (1 << self.discontinue_offset):
                    frame.discontinue = True

                for k in range(self.seg_byte_lanes):
                    lane = k+seg*self.seg_byte_lanes
                    if lane_valid & (1 << lane):
                        frame.data.append((sample.tdata >> lane*32) & 0xffffffff)
                        frame.byte_en.append((sample.tuser >> (lane*4)) & 0xf)
                        frame.parity.append((sample.tuser >> (lane*4+self.parity_offset)) & 0xf)

                if seg_eop & (1 << seg):
                    self.log.info("RX RC frame: %r", frame)
                    self._sink_frame(frame)
                    self.active = False
                    frame = None


class CqSource(UsPcieSource):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 183
            assert self.seg_count in {1, 2}
            self.byte_en_offset = 16
            self.discontinue_offset = 96
            self.parity_offset = 119
        else:
            assert len(self.bus.tuser) in [85, 88]
            assert self.seg_count == 1
            self.byte_en_offset = 8
            self.discontinue_offset = 41
            self.parity_offset = 53

    async def _run(self):
        while True:
            frame = await self._get_frame()
            frame_offset = 0
            self.log.info("TX CQ frame: %r", frame)
            first = True

            while frame is not None:
                transaction = self._transaction_obj()
                sop_cnt = 0
                eop_cnt = 0

                for seg in range(self.seg_count):
                    if frame is None:
                        if not self.empty():
                            frame = self._get_frame_nowait()
                            frame_offset = 0
                            self.log.info("TX CQ frame: %r", frame)
                            first = True
                        else:
                            break

                    if first:
                        first = False

                        if self.width == 512:
                            transaction.tuser |= (frame.first_be & 0xf) << (seg*4)
                            transaction.tuser |= (frame.last_be & 0xf) << (seg*4+8)

                            # is_sop
                            transaction.tuser |= 1 << 80+sop_cnt
                            # is_sop_ptr
                            transaction.tuser |= (seg*self.seg_byte_lanes//4) << 82+sop_cnt*2
                        else:
                            transaction.tuser |= (frame.first_be & 0xf)
                            transaction.tuser |= (frame.last_be & 0xf) << 4

                            # sop
                            transaction.tuser |= 1 << 40

                        sop_cnt += 1

                    if frame.discontinue:
                        transaction.tuser |= 1 << self.discontinue_offset

                    last_lane = 0
                    for k in range(self.seg_byte_lanes):
                        lane = k+seg*self.seg_byte_lanes
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << lane*32
                            transaction.tkeep |= 1 << lane
                            transaction.tuser |= frame.byte_en[frame_offset] << lane*4+self.byte_en_offset
                            transaction.tuser |= frame.parity[frame_offset] << lane*4+self.parity_offset
                            frame_offset += 1
                            last_lane = lane
                        else:
                            transaction.tuser |= 0xf << lane*4+self.parity_offset

                    if frame_offset >= len(frame.data):
                        # eop
                        if self.width == 512:
                            # is_eop
                            transaction.tuser |= 1 << 86+eop_cnt
                            # is_eop_ptr
                            transaction.tuser |= last_lane << 88+eop_cnt*4

                        eop_cnt += 1

                        if self.seg_count == 1:
                            transaction.tlast = 1

                        frame = None

                await self._drive(transaction)


class CqSink(UsPcieSink):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 183
            assert self.seg_count in {1, 2}
            self.byte_en_offset = 16
            self.discontinue_offset = 96
            self.parity_offset = 119
        else:
            assert len(self.bus.tuser) in [85, 88]
            assert self.seg_count == 1
            self.byte_en_offset = 8
            self.discontinue_offset = 41
            self.parity_offset = 53

    async def _run(self):
        self.active = False
        frame = UsPcieFrame()

        while True:
            while not self.sample_obj:
                self.sample_sync.clear()
                await self.sample_sync.wait()

            self.active = True
            sample = self.sample_obj
            self.sample_obj = None

            lane_valid = 2**self.byte_lanes-1
            seg_valid = 2**self.seg_count-1
            seg_sop = 0
            seg_eop = 0

            if self.seg_count == 1:
                lane_valid = sample.tkeep
                seg_valid = 1

                if not frame:
                    seg_sop = 1

                if sample.tlast:
                    seg_eop = 1
            elif self.width == 512:
                sop_byte_lane = 0
                eop_byte_lane = 0
                for k in range(self.seg_count):
                    if sample.tuser & (1 << (80+k)):
                        offset = (sample.tuser >> (82+k*2)) & 0x3
                        sop_byte_lane |= 1 << (offset*4)
                    if sample.tuser & (1 << (86+k)):
                        offset = (sample.tuser >> (88+k*4)) & 0xf
                        eop_byte_lane |= 1 << offset
                lane_valid = 0
                seg_valid = 0
                state = 1
                for k in range(self.byte_lanes):
                    mask = 1 << k
                    seg_mask = 1 << (k // self.seg_byte_lanes)
                    if sop_byte_lane & mask:
                        state = 1
                        seg_sop |= seg_mask
                    if state:
                        lane_valid |= mask
                        seg_valid |= seg_mask
                    if eop_byte_lane & mask:
                        state = 0
                        seg_eop |= seg_mask

            for seg in range(self.seg_count):
                if not seg_valid & (1 << seg):
                    continue

                if seg_sop & (1 << seg):
                    frame = UsPcieFrame()

                    if self.width == 512:
                        frame.first_be = (sample.tuser >> (seg*4)) & 0xf
                        frame.last_be = (sample.tuser >> (seg*4+8)) & 0xf
                    else:
                        frame.first_be = sample.tuser & 0xf
                        frame.last_be = (sample.tuser >> 4) & 0xf

                if sample.tuser & (1 << self.discontinue_offset):
                    frame.discontinue = True

                for k in range(self.seg_byte_lanes):
                    lane = k+seg*self.seg_byte_lanes
                    if lane_valid & (1 << lane):
                        frame.data.append((sample.tdata >> lane*32) & 0xffffffff)
                        frame.byte_en.append((sample.tuser >> (lane*4+self.byte_en_offset)) & 0xf)
                        frame.parity.append((sample.tuser >> (lane*4+self.parity_offset)) & 0xf)

                if seg_eop & (1 << seg):
                    self.log.info("RX CQ frame: %r", frame)
                    self._sink_frame(frame)
                    self.active = False
                    frame = None


class CcSource(UsPcieSource):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 81
            assert self.seg_count in {1, 2}
            self.discontinue_offset = 16
            self.parity_offset = 17
        else:
            assert len(self.bus.tuser) == 33
            assert self.seg_count == 1
            self.discontinue_offset = 0
            self.parity_offset = 1

    async def _run(self):
        while True:
            frame = await self._get_frame()
            frame_offset = 0
            self.log.info("TX CC frame: %r", frame)
            first = True

            while frame is not None:
                transaction = self._transaction_obj()
                sop_cnt = 0
                eop_cnt = 0

                for seg in range(self.seg_count):
                    if frame is None:
                        if not self.empty():
                            frame = self._get_frame_nowait()
                            frame_offset = 0
                            self.log.info("TX CC frame: %r", frame)
                            first = True
                        else:
                            break

                    if first:
                        first = False

                        if self.width == 512:
                            # is_sop
                            transaction.tuser |= 1 << 0+sop_cnt
                            # is_sop_ptr
                            transaction.tuser |= (seg*self.seg_byte_lanes//4) << 2+sop_cnt*2

                        sop_cnt += 1

                    if frame.discontinue:
                        transaction.tuser |= 1 << self.discontinue_offset

                    last_lane = 0
                    for k in range(self.seg_byte_lanes):
                        lane = k+seg*self.seg_byte_lanes
                        if frame_offset < len(frame.data):
                            transaction.tdata |= frame.data[frame_offset] << lane*32
                            transaction.tkeep |= 1 << lane
                            transaction.tuser |= frame.parity[frame_offset] << lane*4+self.parity_offset
                            frame_offset += 1
                            last_lane = lane
                        else:
                            transaction.tuser |= 0xf << lane*4+self.parity_offset

                    if frame_offset >= len(frame.data):
                        # eop
                        if self.width == 512:
                            # is_eop
                            transaction.tuser |= 1 << 6+eop_cnt
                            # is_eop_ptr
                            transaction.tuser |= last_lane << 8+eop_cnt*4

                        eop_cnt += 1

                        if self.seg_count == 1:
                            transaction.tlast = 1

                        frame = None

                await self._drive(transaction)


class CcSink(UsPcieSink):
    def _init(self):

        if self.width == 512:
            assert len(self.bus.tuser) == 81
            assert self.seg_count in {1, 2}
            self.discontinue_offset = 16
            self.parity_offset = 17
        else:
            assert len(self.bus.tuser) == 33
            assert self.seg_count == 1
            self.discontinue_offset = 0
            self.parity_offset = 1

    async def _run(self):
        self.active = False
        frame = UsPcieFrame()

        while True:
            while not self.sample_obj:
                self.sample_sync.clear()
                await self.sample_sync.wait()

            self.active = True
            sample = self.sample_obj
            self.sample_obj = None

            lane_valid = 2**self.byte_lanes-1
            seg_valid = 2**self.seg_count-1
            seg_sop = 0
            seg_eop = 0

            if self.seg_count == 1:
                lane_valid = sample.tkeep
                seg_valid = 1

                if not frame:
                    seg_sop = 1

                if sample.tlast:
                    seg_eop = 1
            elif self.width == 512:
                sop_byte_lane = 0
                eop_byte_lane = 0
                for k in range(self.seg_count):
                    if sample.tuser & (1 << (0+k)):
                        offset = (sample.tuser >> (2+k*2)) & 0x3
                        sop_byte_lane |= 1 << (offset*4)
                    if sample.tuser & (1 << (6+k)):
                        offset = (sample.tuser >> (8+k*4)) & 0xf
                        eop_byte_lane |= 1 << offset
                lane_valid = 0
                seg_valid = 0
                state = 1
                for k in range(self.byte_lanes):
                    mask = 1 << k
                    seg_mask = 1 << (k // self.seg_byte_lanes)
                    if sop_byte_lane & mask:
                        state = 1
                        seg_sop |= seg_mask
                    if state:
                        lane_valid |= mask
                        seg_valid |= seg_mask
                    if eop_byte_lane & mask:
                        state = 0
                        seg_eop |= seg_mask

            for seg in range(self.seg_count):
                if not seg_valid & (1 << seg):
                    continue

                if seg_sop & (1 << seg):
                    frame = UsPcieFrame()

                if sample.tuser & (1 << self.discontinue_offset):
                    frame.discontinue = True

                for k in range(self.seg_byte_lanes):
                    lane = k+seg*self.seg_byte_lanes
                    if lane_valid & (1 << lane):
                        frame.data.append((sample.tdata >> lane*32) & 0xffffffff)
                        frame.parity.append((sample.tuser >> (lane*4+self.parity_offset)) & 0xf)

                if seg_eop & (1 << seg):
                    self.log.info("RX CC frame: %r", frame)
                    self._sink_frame(frame)
                    self.active = False
                    frame = None
