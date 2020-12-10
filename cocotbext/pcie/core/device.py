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
from .port import Port
from .tlp import Tlp, TlpType
from .utils import PcieId


class Device(object):
    """PCIe device, container for multiple functions"""
    def __init__(self, eps=None, *args, **kwargs):

        self._bus_num = 0
        self._device_num = 0

        self.log = logging.getLogger(f"cocotb.pcie.{type(self).__name__}.{id(self)}")
        self.log.name = f"cocotb.pcie.{type(self).__name__}[{self._bus_num:02x}:{self._device_num:02x}]"

        self.default_function = Endpoint

        self.functions = []
        self.upstream_port = Port(self, self.upstream_recv)

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
            self.log.name = f"cocotb.pcie.{type(self).__name__}[{self._bus_num:02x}:{self._device_num:02x}]"

    @property
    def device_num(self):
        return self._device_num

    @device_num.setter
    def device_num(self, value):
        if value < 0 or value > 31:
            raise ValueError("Out of range")
        if self._device_num != value:
            self._device_num = value
            self.log.name = f"cocotb.pcie.{type(self).__name__}[{self._bus_num:02x}:{self._device_num:02x}]"

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
                f.header_type |= 0x80
        return function

    def append_function(self, function):
        function.pcie_id = PcieId(0, 0, self.next_free_function_number())
        return self.add_function(function)

    def make_function(self):
        return self.append_function(self.default_function())

    def connect(self, port):
        self.upstream_port.connect(port)

    async def upstream_recv(self, tlp):
        self.log.debug("Got downstream TLP: %s", repr(tlp))
        assert tlp.check()
        if tlp.fmt_type == TlpType.CFG_READ_0 or tlp.fmt_type == TlpType.CFG_WRITE_0:
            # config type 0

            if tlp.dest_id.device == self.device_num:
                # capture address information
                self.bus_num = tlp.dest_id.bus

                for f in self.functions:
                    f.pci_id = f.pcie_id._replace(bus=self.bus_num)

                # pass TLP to function
                for f in self.functions:
                    if f.function_num == tlp.dest_id.function:
                        await f.upstream_recv(tlp)
                        return

                self.log.info("Function not found")
            else:
                self.log.info("Device number mismatch")

            # Unsupported request
            cpl = Tlp.create_ur_completion_for_tlp(tlp, PcieId(self.bus_num, self.device_num, 0))
            self.log.debug("UR Completion: %s", repr(cpl))
            await self.upstream_send(cpl)
        elif (tlp.fmt_type == TlpType.CPL or tlp.fmt_type == TlpType.CPL_DATA or
                tlp.fmt_type == TlpType.CPL_LOCKED or tlp.fmt_type == TlpType.CPL_LOCKED_DATA):
            # Completion

            if tlp.requester_id.bus == self.bus_num and tlp.requester_id.device == self.device_num:
                for f in self.functions:
                    if f.function_num == tlp.requester_id.function:
                        await f.upstream_recv(tlp)
                        return

                self.log.info("Function not found")
            else:
                self.log.info("Bus/device number mismatch")
        elif (tlp.fmt_type == TlpType.IO_READ or tlp.fmt_type == TlpType.IO_WRITE):
            # IO read/write

            for f in self.functions:
                if f.match_bar(tlp.address, True):
                    await f.upstream_recv(tlp)
                    return

            self.log.warning("IO request did not match any BARs")

            # Unsupported request
            cpl = Tlp.create_ur_completion_for_tlp(tlp, PcieId(self.bus_num, self.device_num, 0))
            self.log.debug("UR Completion: %s", repr(cpl))
            await self.upstream_send(cpl)
        elif (tlp.fmt_type == TlpType.MEM_READ or tlp.fmt_type == TlpType.MEM_READ_64 or
                tlp.fmt_type == TlpType.MEM_WRITE or tlp.fmt_type == TlpType.MEM_WRITE_64):
            # Memory read/write

            for f in self.functions:
                if f.match_bar(tlp.address):
                    await f.upstream_recv(tlp)
                    return

            self.log.warning("Memory request did not match any BARs")

            if tlp.fmt_type == TlpType.MEM_READ or tlp.fmt_type == TlpType.MEM_READ_64:
                # Unsupported request
                cpl = Tlp.create_ur_completion_for_tlp(tlp, PcieId(self.bus_num, self.device_num, 0))
                self.log.debug("UR Completion: %s", repr(cpl))
                await self.upstream_send(cpl)
        else:
            raise Exception("TODO")

    async def upstream_send(self, tlp):
        self.log.debug("Sending upstream TLP: %s", repr(tlp))
        assert tlp.check()
        await self.upstream_port.send(tlp)

    async def send(self, tlp):
        await self.upstream_send(tlp)
