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

from .function import Function
from .port import SimPort
from .tlp import Tlp, TlpType, CplStatus
from .utils import byte_mask_update, PcieId


class Bridge(Function):
    """PCIe bridge function, implements bridge config space and TLP routing"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # configuration registers
        # Header type
        self.header_layout = 1
        self.multifunction_device = False
        # Base Address Registers
        self.bar = [0]*2
        self.bar_mask = [0]*2
        # Primary bus number
        self.pri_bus_num = 0
        # Secondary bus number
        self.sec_bus_num = 0
        # Subordinate bus number
        self.sub_bus_num = 0
        # Secondary latency timer
        self.sec_lat_timer = 0
        # IO base and limit registers
        self.io_base = 0x0000
        self.io_limit = 0x0fff
        self.io_addr_capability = 0x1
        # Secondary status
        self.sec_master_data_parity_error = False
        self.sec_signaled_target_abort = False
        self.sec_received_target_abort = False
        self.sec_received_master_abort = False
        self.sec_received_system_error = False
        self.sec_detected_parity_error = False
        # Memory and limit registers
        self.mem_base = 0x00000000
        self.mem_limit = 0x000fffff
        self.prefetchable_mem_base = 0x00000000
        self.prefetchable_mem_limit = 0x000fffff
        # Bridge control
        self.bridge_parity_error_response_enable = 0
        self.bridge_serr_enable = 0
        self.secondary_bus_reset = 0

        self.class_code = 0x060400
        self.pcie_cap.pcie_device_type = 0x6

        self.root = False

        self.upstream_tx_handler = None
        self.downstream_tx_handler = None

    """
    Bridge (type 1) config space

    31                                                                  0
    +---------------------------------+---------------------------------+
    |            Device ID            |            Vendor ID            |   0   0x00
    +---------------------------------+---------------------------------+
    |             Status              |             Command             |   1   0x04
    +---------------------------------+----------------+----------------+
    |                    Class Code                    |  Revision ID   |   2   0x08
    +----------------+----------------+----------------+----------------+
    |      BIST      |  Header Type   |    Primary     |   Cache Line   |   3   0x0C
    |                |                | Latency Timer  |      Size      |
    +----------------+----------------+----------------+----------------+
    |                      Base Address Register 0                      |   4   0x10
    +-------------------------------------------------------------------+
    |                      Base Address Register 1                      |   5   0x14
    +----------------+----------------+----------------+----------------+
    | Secondary      | Subordinate    | Secondary      | Primary        |   6   0x18
    | Latency Timer  | Bus Number     | Bus Number     | Bus Number     |
    +----------------+----------------+----------------+----------------+
    |        Secondary Status         |    IO Limit    |    IO Base     |   7   0x1C
    +---------------------------------+----------------+----------------+
    |          Memory Limit           |           Memory Base           |   8   0x20
    +---------------------------------+---------------------------------+
    |    Prefetchable Memory Limit    |    Prefetchable Memory Base     |   9   0x24
    +---------------------------------+---------------------------------+
    |                    Prefetchable Base Upper 32                     |  10   0x28
    +-------------------------------------------------------------------+
    |                    Prefetchable Limit Upper 32                    |  11   0x2C
    +---------------------------------+---------------------------------+
    |         IO Lim Upper 16         |        IO Base Lower 16         |  12   0x30
    +---------------------------------+----------------+----------------+
    |                     Reserved                     |    Cap Ptr     |  13   0x34
    +--------------------------------------------------+----------------+
    |                    Expansion ROM Base Address                     |  14   0x38
    +---------------------------------+----------------+----------------+
    |         Bridge Control          |    Int Pin     |    Int Line    |  15   0x3C
    +---------------------------------+----------------+----------------+

    """
    async def read_config_register(self, reg):
        if reg == 4:
            # Base Address Register 0
            return self.bar[0]
        elif reg == 5:
            # Base Address Register 1
            return self.bar[1]
        elif reg == 6:
            # Primary bus number
            val = self.pri_bus_num & 0xff
            # Secondary bus number
            val |= (self.sec_bus_num & 0xff) << 8
            # Subordinate bus number
            val |= (self.sub_bus_num & 0xff) << 16
            # Secondary latency timer
            val |= (self.sec_lat_timer & 0xff) << 24
            return val
        elif reg == 7:
            # IO base
            val = self.io_addr_capability & 0xf
            val |= (self.io_base & 0xf000) >> 8
            # IO limit
            val |= (self.io_addr_capability & 0xf) << 8
            val |= self.io_limit & 0xf000
            # Secondary status
            val |= bool(self.sec_master_data_parity_error) << 24
            val |= bool(self.sec_signaled_target_abort) << 27
            val |= bool(self.sec_received_target_abort) << 28
            val |= bool(self.sec_received_master_abort) << 29
            val |= bool(self.sec_received_system_error) << 30
            val |= bool(self.sec_detected_parity_error) << 31
            return val
        elif reg == 8:
            # Memory base
            val = (self.mem_base & 0xfff00000) >> 16
            # Memory limit
            val |= self.mem_limit & 0xfff00000
            return val
        elif reg == 9:
            # Prefetchable memory base
            val = (self.prefetchable_mem_base & 0xfff00000) >> 16
            # Prefetchable memory limit
            val |= self.prefetchable_mem_limit & 0xfff00000
            # supports 64 bit addresses
            val |= 0x00010001
            return val
        elif reg == 10:
            # Prefetchable memory base (upper)
            return (self.prefetchable_mem_base >> 32) & 0xffffffff
        elif reg == 11:
            # Prefetchable memory limit (upper)
            return (self.prefetchable_mem_limit >> 32) & 0xffffffff
        elif reg == 12:
            # IO base (upper)
            val = (self.io_base & 0xffff0000) >> 16
            # IO limit (upper)
            val |= self.io_limit & 0xffff0000
            return val
        elif reg == 13:
            # Capabilities pointer
            return self.capabilities_ptr
        elif reg == 14:
            # Expansion ROM Base Address
            val = bool(self.expansion_rom_enable)
            val |= self.expansion_rom_addr & 0xfffff800
            return val
        elif reg == 15:
            # Interrupt line
            val = self.interrupt_line & 0xff
            # Interrupt pin
            val |= (self.interrupt_pin & 0xff) << 8
            # Bridge control
            val |= bool(self.bridge_parity_error_response_enable) << 16
            val |= bool(self.bridge_serr_enable) << 17
            val |= bool(self.secondary_bus_reset) << 22
            return val
        else:
            return await super().read_config_register(reg)

    async def write_config_register(self, reg, data, mask):
        if reg == 4:
            # Base Address Register 0
            self.bar[0] = byte_mask_update(self.bar[0], mask, data, self.bar_mask[0])
        if reg == 5:
            # Base Address Register 1
            self.bar[1] = byte_mask_update(self.bar[1], mask, data, self.bar_mask[1])
        elif reg == 6:
            # Primary bus number
            if mask & 0x1:
                self.pri_bus_num = data & 0xff
            # Secondary bus number
            if mask & 0x2:
                self.sec_bus_num = (data >> 8) & 0xff
            # Subordinate bus number
            if mask & 0x4:
                self.sub_bus_num = (data >> 16) & 0xff
        elif reg == 7:
            # IO base
            if mask & 0x1:
                self.io_base = byte_mask_update(self.io_base, 0x2, data << 8, 0xf000)
            # IO limit
            if mask & 0x2:
                self.io_limit = byte_mask_update(self.io_limit, 0x2, data, 0xf000) | 0xfff
            if mask & 0x8:
                # Secondary status
                if data & 1 << 24:
                    self.sec_master_data_parity_error = False
                if data & 1 << 27:
                    self.sec_signaled_target_abort = False
                if data & 1 << 28:
                    self.sec_received_target_abort = False
                if data & 1 << 29:
                    self.sec_received_master_abort = False
                if data & 1 << 30:
                    self.sec_received_system_error = False
                if data & 1 << 31:
                    self.sec_detected_parity_error = False
        elif reg == 8:
            # Memory base
            self.mem_base = byte_mask_update(self.mem_base, (mask & 0x3) << 2, data << 16, 0xfff00000)
            # Memory limit
            self.mem_limit = byte_mask_update(self.mem_limit, (mask & 0xc), data, 0xfff00000) | 0xfffff
        elif reg == 9:
            # Prefetchable memory base
            self.prefetchable_mem_base = byte_mask_update(self.prefetchable_mem_base,
                (mask & 0x3) << 2, data << 16, 0xfff00000)
            # Prefetchable memory limit
            self.prefetchable_mem_limit = byte_mask_update(self.prefetchable_mem_limit,
                (mask & 0xc), data, 0xfff00000) | 0xfffff
        elif reg == 10:
            # Prefetchable memory base (upper)
            self.prefetchable_mem_base = byte_mask_update(self.prefetchable_mem_base, mask << 4, data << 32)
        elif reg == 11:
            # Prefetchable memory limit (upper)
            self.prefetchable_mem_limit = byte_mask_update(self.prefetchable_mem_limit, mask << 4, data << 32)
        elif reg == 12:
            # IO base (upper)
            self.io_base = byte_mask_update(self.io_base, (mask & 0x3) << 2, data << 16)
            # IO limit (upper)
            self.io_limit = byte_mask_update(self.io_limit, (mask & 0xc), data)
        elif reg == 14:
            # Expansion ROM Base Address
            self.expansion_rom_addr = byte_mask_update(self.expansion_rom_addr,
                mask, data, self.expansion_rom_addr_mask) & 0xfffff800
            if mask & 0x1:
                self.expansion_rom_enable = (data & 1) != 0
        elif reg == 15:
            # Interrupt line
            if mask & 1:
                self.interrupt_line = data & 0xff
            # bridge control
            if mask & 0x4:
                self.bridge_parity_error_response_enable = (data & 1 << 16 != 0)
                self.bridge_serr_enable = (data & 1 << 17 != 0)
                self.secondary_bus_reset = (data & 1 << 22 != 0)
        else:
            await super().write_config_register(reg, data, mask)

    def match_tlp_secondary(self, tlp):
        if tlp.fmt_type in {TlpType.CFG_READ_0, TlpType.CFG_WRITE_0}:
            # Config type 0
            return False
        elif tlp.fmt_type in {TlpType.CFG_READ_1, TlpType.CFG_WRITE_1}:
            # Config type 1
            return self.sec_bus_num <= tlp.dest_id.bus <= self.sub_bus_num and tlp.dest_id != PcieId(0, 0, 0)
        elif tlp.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
            # Completion
            return self.sec_bus_num <= tlp.requester_id.bus <= self.sub_bus_num and tlp.requester_id != PcieId(0, 0, 0)
        elif tlp.fmt_type in {TlpType.MSG_ID, TlpType.MSG_DATA_ID}:
            # ID routed message
            return self.sec_bus_num <= tlp.dest_id.bus <= self.sub_bus_num and tlp.dest_id != PcieId(0, 0, 0)
        elif tlp.fmt_type in {TlpType.IO_READ, TlpType.IO_WRITE}:
            # IO read/write
            return self.io_base <= tlp.address <= self.io_limit
        elif tlp.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64, TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
            # Memory read/write
            return (self.mem_base <= tlp.address <= self.mem_limit
                or self.prefetchable_mem_base <= tlp.address <= self.prefetchable_mem_limit)
        elif tlp.fmt_type in {TlpType.MSG_TO_RC, TlpType.MSG_DATA_TO_RC}:
            # Message to root complex
            return False
        elif tlp.fmt_type in {TlpType.MSG_BCAST, TlpType.MSG_DATA_BCAST}:
            # Message broadcast from root complex
            return True
        elif tlp.fmt_type in {TlpType.MSG_LOCAL, TlpType.MSG_DATA_LOCAL}:
            # Message local to receiver
            return False
        elif tlp.fmt_type in {TlpType.MSG_GATHER, TlpType.MSG_DATA_GATHER}:
            # Message gather to root complex
            return False
        else:
            raise Exception("Unknown/invalid packet type")

    async def upstream_send(self, tlp):
        assert tlp.check()
        if self.parity_error_response_enable and tlp.ep:
            self.log.warning("Sending poisoned TLP on primary interface, reporting master data parity error")
            self.master_data_parity_error = True
        if self.upstream_tx_handler is None:
            raise Exception("Transmit handler not set")
        await self.upstream_tx_handler(tlp)

    async def upstream_recv(self, tlp):
        self.log.debug("Routing downstream TLP: %r", tlp)
        assert tlp.check()
        if self.parity_error_response_enable and tlp.ep:
            self.log.warning("Received poisoned TLP on primary interface, reporting master data parity error")
            self.master_data_parity_error = True

        # TLPs targeting bridge function
        if self.match_tlp(tlp):
            if tlp.is_completion():
                if tlp.status == CplStatus.CA:
                    self.log.warning("Received completion with CA status on primary interface, reporting target abort")
                    self.received_target_abort = True
                elif tlp.status == CplStatus.UR:
                    self.log.warning("Received completion with UR status on primary interface, reporting master abort")
                    self.received_master_abort = True
            await self.handle_tlp(tlp)
            return

        # Route TLPs from primary side to secondary side
        if self.match_tlp_secondary(tlp):

            if tlp.fmt_type in {TlpType.CFG_READ_1, TlpType.CFG_WRITE_1} and tlp.dest_id.bus == self.sec_bus_num:
                # config type 1 targeted to directly connected device; change to type 0
                if tlp.fmt_type == TlpType.CFG_READ_1:
                    tlp.fmt_type = TlpType.CFG_READ_0
                elif tlp.fmt_type == TlpType.CFG_WRITE_1:
                    tlp.fmt_type = TlpType.CFG_WRITE_0

            await self.route_downstream_tlp(tlp, False)
            return

        tlp.release_fc()

        if tlp.fmt_type in {TlpType.CFG_READ_0, TlpType.CFG_WRITE_0}:
            # Config type 0
            self.log.warning("Failed to route config type 0 TLP: %r", tlp)
        elif tlp.fmt_type in {TlpType.CFG_READ_1, TlpType.CFG_WRITE_1}:
            # Config type 1
            self.log.warning("Failed to route config type 1 TLP: %r", tlp)
        elif tlp.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
            # Completion
            self.log.warning("Unexpected completion: failed to route completion: %r", tlp)
            return  # no UR response for completion
        elif tlp.fmt_type in {TlpType.IO_READ, TlpType.IO_WRITE}:
            # IO read/write
            self.log.warning("No address match: IO request did not match secondary bus or any BARs: %r", tlp)
        elif tlp.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64}:
            # Memory read/write
            self.log.warning("No address match: memory read request did not match secondary bus or any BARs: %r", tlp)
        elif tlp.fmt_type in {TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
            # Memory read/write
            self.log.warning("No address match: memory write request did not match secondary bus or any BARs: %r", tlp)
            return  # no UR response for write request
        else:
            raise Exception("TODO")

        # Unsupported request
        cpl = Tlp.create_ur_completion_for_tlp(tlp, self.pcie_id)
        self.log.debug("UR Completion: %r", cpl)
        await self.upstream_send(cpl)

    async def route_downstream_tlp(self, tlp, from_downstream=False):
        await self.downstream_send(tlp)

    async def downstream_send(self, tlp):
        assert tlp.check()
        if self.bridge_parity_error_response_enable and tlp.ep:
            self.log.warning("Sending poisoned TLP on secondary interface, reporting master data parity error")
            self.sec_master_data_parity_error = True
        if self.downstream_tx_handler is None:
            raise Exception("Transmit handler not set")
        await self.downstream_tx_handler(tlp)

    async def downstream_recv(self, tlp):
        self.log.debug("Routing upstream TLP: %r", tlp)
        assert tlp.check()
        if self.bridge_parity_error_response_enable and tlp.ep:
            self.log.warning("Received poisoned TLP on secondary interface, reporting master data parity error")
            self.sec_master_data_parity_error = True

        if tlp.fmt_type in {TlpType.CFG_READ_0, TlpType.CFG_WRITE_0, TlpType.CFG_READ_1, TlpType.CFG_WRITE_1}:
            # error
            pass
        elif not self.root and self.match_tlp(tlp):
            # TLPs targeting bridge function
            if tlp.is_completion():
                if tlp.status == CplStatus.CA:
                    self.log.warning("Received completion with CA status on secondary interface, reporting target abort")
                    self.sec_received_target_abort = True
                elif tlp.status == CplStatus.UR:
                    self.log.warning("Received completion with UR status on secondary interface, reporting master abort")
                    self.sec_received_master_abort = True
            await self.handle_tlp(tlp)
            return
        elif not self.match_tlp_secondary(tlp) or self.root:
            # Route TLPs from secondary side to primary side
            await self.upstream_send(tlp)
            return

        tlp.release_fc()

        if tlp.fmt_type in {TlpType.CFG_READ_0, TlpType.CFG_WRITE_0, TlpType.CFG_READ_1, TlpType.CFG_WRITE_1}:
            # Config type 1
            self.log.warning("Malformed TLP: received configuration request on downstream switch port: %r", tlp)
        elif tlp.fmt_type in {TlpType.CPL, TlpType.CPL_DATA, TlpType.CPL_LOCKED, TlpType.CPL_LOCKED_DATA}:
            # Completion
            self.log.warning("Unexpected completion: completion did not match primary bus: %r", tlp)
            return  # no UR response for completion
        elif tlp.fmt_type in {TlpType.IO_READ, TlpType.IO_WRITE}:
            # IO read/write
            self.log.warning("No address match: IO request did not match primary bus: %r", tlp)
        elif tlp.fmt_type in {TlpType.MEM_READ, TlpType.MEM_READ_64}:
            # Memory read/write
            self.log.warning("No address match: memory read request did not match primary bus: %r", tlp)
        elif tlp.fmt_type in {TlpType.MEM_WRITE, TlpType.MEM_WRITE_64}:
            # Memory read/write
            self.log.warning("No address match: memory write request did not match primary bus: %r", tlp)
            return  # no UR response for write request
        else:
            raise Exception("TODO")

        # Unsupported request
        cpl = Tlp.create_ur_completion_for_tlp(tlp, self.pcie_id)
        self.log.debug("UR Completion: %r", cpl)
        await self.downstream_send(cpl)

    async def send(self, tlp):
        # route local transmissions
        if self.match_tlp_secondary(tlp):
            if tlp.is_completion() and tlp.status == CplStatus.CA:
                self.log.warning("Sending completion with CA status on secondary interface, reporting target abort")
                self.signaled_target_abort = True
            await self.route_downstream_tlp(tlp, False)
        else:
            if tlp.is_completion() and tlp.status == CplStatus.CA:
                self.log.warning("Sending completion with CA status on primary interface, reporting target abort")
                self.signaled_target_abort = True
            await self.upstream_send(tlp)


class SwitchUpstreamPort(Bridge):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.pcie_cap.pcie_device_type = 0x5

        self.vendor_id = 0x1234
        self.device_id = 0x0003

        self.upstream_port = None
        self.upstream_tx_handler = None
        self.set_upstream_port(SimPort(fc_init=[[64, 1024, 64, 64, 64, 1024]]*8))

    def set_upstream_port(self, port):
        port.log = self.log
        port.parent = self
        port.rx_handler = self.upstream_recv
        self.upstream_port = port
        self.upstream_tx_handler = port.send

    def connect(self, port):
        self.upstream_port.connect(port)


class SwitchDownstreamPort(Bridge):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.pcie_cap.pcie_device_type = 0x6

        self.vendor_id = 0x1234
        self.device_id = 0x0004

        self.downstream_port = None
        self.downstream_tx_handler = None
        self.set_downstream_port(SimPort(fc_init=[[64, 1024, 64, 64, 64, 1024]]*8))

    def set_downstream_port(self, port):
        port.log = self.log
        port.parent = self
        port.rx_handler = self.downstream_recv
        self.downstream_port = port
        self.downstream_tx_handler = port.send

    def connect(self, port):
        self.downstream_port.connect(port)


class HostBridge(Bridge):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.pcie_cap.pcie_device_type = 0x5

        self.vendor_id = 0x1234
        self.device_id = 0x0001

        self.pri_bus_num = 0
        self.sec_bus_num = 0
        self.sub_bus_num = 255

        self.class_code = 0x060000

        self.root = True


class RootPort(SwitchDownstreamPort):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.pcie_cap.pcie_device_type = 0x4
        self.pcie_cap.crs_software_visibility = True

        self.vendor_id = 0x1234
        self.device_id = 0x0002
