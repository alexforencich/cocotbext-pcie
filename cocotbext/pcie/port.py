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

import cocotb
from cocotb.triggers import Event, Timer
import cocotb.utils
from collections import deque

from .tlp import Tlp

PCIE_GEN_RATE = {
    1: 2.5e9*8/10,
    2: 5e9*8/10,
    3: 8e9*128/130,
    4: 16e9*128/130,
    5: 32e9*128/130,
}


class Port(object):
    """Basic port"""
    def __init__(self, parent=None, rx_handler=None):
        self.parent = parent
        self.other = None
        self.rx_handler = rx_handler

        self.tx_queue = deque()
        self.tx_sync = Event()
        self.tx_scheduled = False

        self.max_speed = 3
        self.max_width = 16
        self.port_delay = 5

        self.cur_speed = 1
        self.cur_width = 1
        self.link_delay = 0
        self.link_delay_unit = None

        self.time_scale = 10**cocotb.utils._get_simulator_precision()

        cocotb.fork(self._run_transmit())

    def connect(self, other):
        if isinstance(other, Port):
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
        self.cur_speed = min(self.max_speed, port.max_speed)
        self.cur_width = min(self.max_width, port.max_width)
        self.link_delay = self.port_delay + port.port_delay

    async def send(self, tlp):
        self.tx_queue.append(tlp)
        self.tx_sync.set()

    async def _run_transmit(self):
        while True:
            while not self.tx_queue:
                self.tx_sync.clear()
                await self.tx_sync.wait()

            tlp = self.tx_queue.popleft()
            d = int(tlp.get_wire_size()*8/(PCIE_GEN_RATE[self.cur_speed]*self.cur_width*self.time_scale))
            await Timer(d)
            cocotb.fork(self._transmit(tlp))

    async def _transmit(self, tlp):
        if self.other is None:
            raise Exception("Port not connected")
        await Timer(self.link_delay, self.link_delay_unit)
        await self.other.ext_recv(tlp)

    async def ext_recv(self, tlp):
        if self.rx_handler is None:
            raise Exception("Receive handler not set")
        await self.rx_handler(tlp)


class BusPort(Port):
    """Port for root of bus interconnection, broadcasts TLPs to all connected ports"""
    def __init__(self, parent=None, rx_handler=None):
        super().__init__(parent, rx_handler)

        self.other = []

    def _connect(self, port):
        if port in self.other:
            raise Exception("Already connected")
        port._connect_int(self)
        self._connect_int(port)

    def _connect_int(self, port):
        if port in self.other:
            raise Exception("Already connected")
        self.other.append(port)
        self.cur_speed = min(self.max_speed, port.max_speed)
        self.cur_width = min(self.max_width, port.max_width)
        self.link_delay = self.port_delay + port.port_delay

    async def _transmit(self, tlp):
        if not self.other:
            raise Exception("Port not connected")
        await Timer(self.link_delay, self.link_delay_unit)
        for p in self.other:
            await p.ext_recv(Tlp(tlp))
