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
from cocotb.queue import Queue
from cocotb.triggers import Event, First, Timer
import cocotb.utils

from .dllp import Dllp, DllpType
from .tlp import Tlp

PCIE_GEN_RATE = {
    1: 2.5e9*8/10,
    2: 5e9*8/10,
    3: 8e9*128/130,
    4: 16e9*128/130,
    5: 32e9*128/130,
}

PCIE_GEN_SYMB_TIME = {
    1: 10/PCIE_GEN_RATE[1],
    2: 10/PCIE_GEN_RATE[2],
    3: 8/PCIE_GEN_RATE[3],
    4: 8/PCIE_GEN_RATE[4],
    5: 8/PCIE_GEN_RATE[5],
}


class Port:
    """Base port"""
    def __init__(self, *args, **kwargs):
        self.log = logging.getLogger(f"cocotb.pcie.{type(self).__name__}.{id(self)}")
        self.log.name = f"cocotb.pcie.{type(self).__name__}"

        self.parent = None
        self.rx_handler = None

        self.max_link_speed = None
        self.max_link_width = None

        self.tx_queue = Queue(1)
        self.tx_queue_sync = Event()

        self.rx_queue = Queue()

        self.cur_link_speed = None
        self.cur_link_width = None

        self.time_scale = cocotb.utils.get_sim_steps(1, 'sec')

        # ACK/NAK protocol
        # TX
        self.next_transmit_seq = 0x000
        self.ackd_seq = 0xfff
        self.retry_buffer = Queue()

        # RX
        self.next_recv_seq = 0x000
        self.nak_scheduled = False
        self.ack_nak_latency_timer = 0

        self.max_payload_size = 128
        self.max_latency_timer = 0

        self.send_ack = Event()

        self._ack_latency_timer_cr = None

        super().__init__(*args, **kwargs)

        cocotb.fork(self._run_transmit())
        cocotb.fork(self._run_receive())

    async def send(self, pkt):
        await self.tx_queue.put(pkt)
        self.tx_queue_sync.set()

    async def _run_transmit(self):
        while True:
            while self.tx_queue.empty() and not self.send_ack.is_set():
                self.tx_queue_sync.clear()
                await First(self.tx_queue_sync.wait(), self.send_ack.wait())

            pkt = None

            if self.send_ack.is_set():
                self.send_ack.clear()
                if self.nak_scheduled:
                    pkt = Dllp.create_nak((self.next_recv_seq-1) & 0xfff)
                else:
                    pkt = Dllp.create_ack((self.next_recv_seq-1) & 0xfff)

            if pkt is not None:
                self.log.debug("Send DLLP %s", pkt)
            else:
                pkt = await self.tx_queue.get()
                pkt.seq = self.next_transmit_seq
                self.log.debug("Send TLP %s", pkt)
                self.next_transmit_seq = (self.next_transmit_seq + 1) & 0xfff
                self.retry_buffer.put_nowait(pkt)

            await self.handle_tx(pkt)

    async def handle_tx(self, pkt):
        raise NotImplementedError()

    async def ext_recv(self, pkt):
        if isinstance(pkt, Dllp):
            # DLLP
            self.log.debug("Receive DLLP %s", pkt)
            await self.handle_dllp(pkt)
        else:
            # TLP
            self.log.debug("Receive TLP %s", pkt)
            if pkt.seq == self.next_recv_seq:
                # expected seq
                self.next_recv_seq = (self.next_recv_seq + 1) & 0xfff
                self.nak_scheduled = False
                self.start_ack_latency_timer()
                await self.rx_queue.put(Tlp(pkt))
            elif (self.next_recv_seq - pkt.seq) & 0xfff < 2048:
                self.log.warning("Received duplicate TLP, discarding (seq %d, expecting %d)", pkt.seq, self.next_recv_seq)
                self.stop_ack_latency_timer()
                self.send_ack.set()
            else:
                self.log.warning("Received out-of-sequence TLP, sending NAK (seq %d, expecting %d)", pkt.seq, self.next_recv_seq)
                if not self.nak_scheduled:
                    self.nak_scheduled = True
                    self.stop_ack_latency_timer()
                    self.send_ack.set()

    async def _run_receive(self):
        while True:
            tlp = await self.rx_queue.get()
            if self.rx_handler is None:
                raise Exception("Receive handler not set")
            await self.rx_handler(tlp)

    async def handle_dllp(self, dllp):
        if dllp.type == DllpType.NOP:
            # discard NOP
            pass
        elif dllp.type in {DllpType.ACK, DllpType.NAK}:
            # ACK or NAK
            if (((self.next_transmit_seq-1) & 0xfff) - dllp.seq) & 0xfff > 2048:
                self.log.warning("Received ACK/NAK DLLP for future TLP, discarding (seq %d, next TX %d, ACK %d)",
                    dllp.seq, self.next_transmit_seq, self.ackd_seq)
            elif (dllp.seq - self.ackd_seq) & 0xfff > 2048:
                self.log.warning("Received ACK/NAK DLLP for previously-ACKed TLP, discarding (seq %d, next TX %d, ACK %d)",
                    dllp.seq, self.next_transmit_seq, self.ackd_seq)
            else:
                while dllp.seq != self.ackd_seq:
                    # purge TLPs from retry buffer
                    self.retry_buffer.get_nowait()
                    self.ackd_seq = (self.ackd_seq + 1) & 0xfff
                    self.log.debug("ACK TLP seq %d", self.ackd_seq)
                if dllp.type == DllpType.NAK:
                    # retransmit
                    self.log.warning("Got NAK DLLP, start TLP replay")
                    raise Exception("TODO")
        else:
            raise Exception("TODO")

    def start_ack_latency_timer(self):
        if self._ack_latency_timer_cr is not None:
            if not self._ack_latency_timer_cr._finished:
                # already running
                return
        self._ack_latency_timer_cr = cocotb.fork(self._run_ack_latency_timer())

    def stop_ack_latency_timer(self):
        if self._ack_latency_timer_cr is not None:
            self._ack_latency_timer_cr.kill()
            self._ack_latency_timer_cr = None

    async def _run_ack_latency_timer(self):
        d = int(self.time_scale * self.max_latency_timer)
        await Timer(max(d, 1), 'step')
        if not self.nak_scheduled:
            self.send_ack.set()


class SimPort(Port):
    """Port to interconnect simulated PCIe devices"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.other = None

        self.port_delay = 5e-9

        self.link_delay_steps = 0

    def connect(self, other):
        if isinstance(other, SimPort):
            self._connect(other)
        else:
            other.connect(self)

    def _connect(self, port):
        if self.other is not None:
            raise Exception("Already connected")
        port._connect_int(self)
        self._connect_int(port)

    def _connect_int(self, port):
        if self.other is not None:
            raise Exception("Already connected")
        self.other = port
        if self.max_link_speed:
            if port.max_link_speed:
                self.cur_link_speed = min(self.max_link_speed, port.max_link_speed)
            else:
                self.cur_link_speed = self.max_link_speed
        else:
            self.cur_link_speed = port.max_link_speed
        if self.max_link_width:
            if port.max_link_width:
                self.cur_link_width = min(self.max_link_width, port.max_link_width)
            else:
                self.cur_link_width = self.max_link_width
        else:
            self.cur_link_width = port.max_link_width
        if self.cur_link_width is not None and self.cur_link_speed is not None:
            self.max_latency_timer = (self.max_payload_size / self.cur_link_width) * PCIE_GEN_SYMB_TIME[self.cur_link_speed]
            self.link_delay_steps = (self.port_delay + port.port_delay) * self.time_scale
        else:
            self.max_latency_timer = 0
            self.link_delay_steps = 0

    async def handle_tx(self, pkt):
        if self.cur_link_width and self.cur_link_speed:
            d = int(pkt.get_wire_size()*8*self.time_scale / (PCIE_GEN_RATE[self.cur_link_speed]*self.cur_link_width))
        else:
            d = 1
        await Timer(max(d, 1), 'step')
        cocotb.fork(self._transmit(pkt))

    async def _transmit(self, pkt):
        if self.other is None:
            raise Exception("Port not connected")
        await Timer(max(self.link_delay_steps, 1), "step")
        await self.other.ext_recv(pkt)
