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

from .endpoint import Endpoint
from .port import SimPort
from .tlp import Tlp, TlpType
from .utils import PcieId


class Device:
    """PCIe device, container for multiple functions"""
    def __init__(self, eps=None, *args, **kwargs):

        self._bus_num = 0

        self.log = logging.getLogger(f"cocotb.pcie.{type(self).__name__}.{id(self)}")
        self.log.name = f"cocotb.pcie.{type(self).__name__}[{self._bus_num:02x}]"

        self.default_function = Endpoint

        self.functions = []
        self.upstream_port = None

        self.set_port(SimPort(fc_init=[[64, 1024, 64, 64, 0, 0]]*8))

        if eps:
            try:
                for ep in eps:
                    self.append_function(ep)
            except TypeError:
                self.append_function(eps)

        super().__init__(*args, **kwargs)

    @property
    def bus_num(self):
        return self._bus_num

    @bus_num.setter
    def bus_num(self, value):
        if value < 0 or value > 255:
            raise ValueError("Out of range")
        if self._bus_num != value:
            self._bus_num = value
            self.log.name = f"cocotb.pcie.{type(self).__name__}[{self._bus_num:02x}]"

            for f in self.functions:
                f.pcie_id = f.pcie_id._replace(bus=self.bus_num)

    def next_free_function_number(self):
        self.functions.sort(key=lambda x: x.function_num)
        if not self.functions:
            return 0
        for x in range(len(self.functions)):
            if self.functions[x].function_num != x:
                return x
        if len(self.functions) < 8:
            return len(self.functions)
        return None

    def add_function(self, function):
        for f in self.functions:
            if f.function_num == function.function_num:
                raise Exception("Function number already in use")
        function.upstream_tx_handler = self.upstream_send
        self.functions.append(function)
        self.functions.sort(key=lambda x: x.function_num)
        if len(self.functions) > 1:
            for f in self.functions:
                f.multifunction_device = True
        return function

    def append_function(self, function):
        function.pcie_id = PcieId(self.bus_num, 0, self.next_free_function_number())
        return self.add_function(function)

    def make_function(self):
        return self.append_function(self.default_function())

    def set_port(self, port):
        port.log = self.log
        port.parent = self
        port.rx_handler = self.upstream_recv
        self.upstream_port = port

    def connect(self, port):
        self.upstream_port.connect(port)

    async def upstream_recv(self, tlp):
        self.log.debug("Got downstream TLP: %r", tlp)
        assert tlp.check()
        if tlp.fmt_type in {TlpType.CFG_READ_0, TlpType.CFG_WRITE_0}:
            # config type 0

            # capture address information
            self.bus_num = tlp.dest_id.bus

        # pass TLP to function
        for f in self.functions:
            if f.match_tlp(tlp):
                await f.upstream_recv(tlp)
                return

        tlp.release_fc()

        if tlp.fmt_type in {TlpType.CFG_READ_0, TlpType.CFG_WRITE_0}:
            # Config type 0
            self.log.warning("Function not found: failed to route config type 0 TLP: %r", tlp)
        elif tlp.fmt_type in {TlpType.CFG_READ_1, TlpType.CFG_WRITE_1}:
            # Config type 1
            self.log.warning("Malformed TLP: endpoint received config type 1 TLP: %r", tlp)
        elif tlp.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
            # Completion
            self.log.warning("Unexpected completion: failed to route completion to function: %r", tlp)
            return  # no UR response for completion
        elif tlp.fmt_type in {TlpType.IO_READ, TlpType.IO_WRITE}:
            # IO read/write
            self.log.warning("No BAR match: IO request did not match any BARs: %r", tlp)
        elif tlp.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64}:
            # Memory read/write
            self.log.warning("No BAR match: memory read request did not match any BARs: %r", tlp)
        elif tlp.fmt_type in {TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
            # Memory read/write
            self.log.warning("No BAR match: memory write request did not match any BARs: %r", tlp)
            return  # no UR response for write request
        else:
            raise Exception("TODO")

        # Unsupported request
        cpl = Tlp.create_ur_completion_for_tlp(tlp, PcieId(self.bus_num, 0, 0))
        self.log.debug("UR Completion: %r", cpl)
        await self.upstream_send(cpl)

    async def upstream_send(self, tlp):
        self.log.debug("Sending upstream TLP: %r", tlp)
        assert tlp.check()
        await self.upstream_port.send(tlp)

    async def send(self, tlp):
        await self.upstream_send(tlp)
