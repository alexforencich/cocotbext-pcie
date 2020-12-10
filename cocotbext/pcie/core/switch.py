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

from .bridge import SwitchUpstreamPort, SwitchDownstreamPort
from .utils import PcieId


class Switch(object):
    """Switch object, container for switch bridges and associated interconnect"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.log = logging.getLogger(f"cocotb.pcie.{type(self).__name__}.{id(self)}")
        self.log.name = f"cocotb.pcie.{type(self).__name__}"

        self.upstream_bridge = SwitchUpstreamPort()

        self.default_switch_port = SwitchDownstreamPort

        self.min_dev = 1
        self.endpoints = []

    def next_free_device_number(self):
        self.endpoints.sort(key=lambda x: (x.device_num, x.function_num))
        d = self.min_dev
        if not self.endpoints:
            return d
        for ep in self.endpoints:
            if ep.device_num > d:
                return d
            d = ep.device_num + 1
        if d < 32:
            return d
        return None

    def append_endpoint(self, ep):
        ep.upstream_tx_handler = self.upstream_bridge.downstream_recv
        self.endpoints.append(ep)
        self.endpoints.sort(key=lambda x: (x.device_num, x.function_num))
        return ep

    def add_endpoint(self, ep):
        ep.pcie_id = PcieId(0, self.next_free_device_number(), 0)
        return self.append_endpoint(ep)

    def make_port(self):
        port = self.default_switch_port()
        self.upstream_bridge.downstream_port.connect(port.upstream_port)
        port.pri_bus_num = 0
        port.sec_bus_num = 0
        port.sub_bus_num = 0
        return self.add_endpoint(port)

    def connect(self, port):
        self.upstream_bridge.upstream_port.connect(port)
