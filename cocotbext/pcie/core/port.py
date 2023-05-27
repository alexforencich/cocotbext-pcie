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

from functools import partial
import logging

import cocotb
from cocotb.queue import Queue
from cocotb.triggers import Event, First, Timer, NullTrigger
from cocotb.utils import get_sim_time, get_sim_steps

from .dllp import Dllp, DllpType, FcType
from .tlp import Tlp

PCIE_GEN_RATE = {
    1: 2.5e9*8/10,
    2: 5e9*8/10,
    3: 8e9*128/130,
    4: 16e9*128/130,
    5: 32e9*128/130,
}

PCIE_GEN_SYMB_TIME = {
    1: 8/PCIE_GEN_RATE[1],
    2: 8/PCIE_GEN_RATE[2],
    3: 8/PCIE_GEN_RATE[3],
    4: 8/PCIE_GEN_RATE[4],
    5: 8/PCIE_GEN_RATE[5],
}


def get_update_factor(max_payload_size, link_width):
    if max_payload_size <= 256:
        if link_width <= 4:
            return 1.4
        elif link_width == 8:
            return 2.5
        else:
            return 3.0
    else:
        if link_width <= 8:
            return 1.0
        else:
            return 2.0


def get_max_update_latency(max_payload_size, link_width, link_speed):
    uf = get_update_factor(max_payload_size, link_width)
    if link_speed == 1:
        delay = 19
    elif link_speed == 2:
        delay = 70
    else:
        delay = 115
    return (((max_payload_size+28)*uf) / link_width) + delay



class FcStateData:
    def __init__(self, init=0, *args, **kwargs):
        self.__dict__.setdefault('_base_field_size', 16)

        self.tx_field_size = self._base_field_size
        self.tx_field_range = 2**self.tx_field_size
        self.tx_field_mask = self.tx_field_range-1

        self.rx_field_size = self._base_field_size
        self.rx_field_range = 2**self.rx_field_size
        self.rx_field_mask = self.rx_field_range-1

        init = max(init, 0)

        # Initial allocation of credits from receiver
        self.tx_initial_allocation = 0
        # Count of total number of FC units consumed at transmitter
        self.tx_credits_consumed = 0
        # Most recent number of FC units advertised by receiver
        self.tx_credit_limit = 0
        # Initial allocation of credits at receiver
        self.rx_initial_allocation = init
        # Total number of units granted to transmitter
        self.rx_credits_allocated = init
        # Total number of FC units consumed at receiver
        self.rx_credits_received = 0

        if init >= 2**(self._base_field_size-1):
            raise ValueError("Initial credit allocation out of range")

        super().__init__(*args, **kwargs)

    def reset(self):
        self.tx_initial_allocation = 0
        self.tx_credits_consumed = 0
        self.tx_credit_limit = 0
        self.rx_credits_allocated = self.rx_initial_allocation
        self.rx_credits_received = 0

    @property
    def tx_credits_available(self):
        if self.tx_is_infinite():
            return self.tx_field_mask
        else:
            return (self.tx_credit_limit - self.tx_credits_consumed) & self.tx_field_mask

    @property
    def rx_credits_available(self):
        if self.rx_is_infinite():
            return self.rx_field_mask
        else:
            return (self.rx_credits_allocated - self.rx_credits_received) & self.rx_field_mask

    def tx_is_infinite(self):
        return self.tx_initial_allocation == 0

    def rx_is_infinite(self):
        return self.rx_initial_allocation == 0

    def tx_consume_fc(self, fc):
        if not self.tx_is_infinite():
            self.tx_credits_consumed = (self.tx_credits_consumed + fc) & self.tx_field_mask
            # assert self.tx_credits_available < self.tx_field_range // 2

    def rx_consume_fc(self, fc):
        if not self.rx_is_infinite():
            self.rx_credits_received = (self.rx_credits_received + fc) & self.rx_field_mask
            # assert self.rx_credits_available < self.rx_field_range // 2

    def rx_release_fc(self, fc):
        if not self.rx_is_infinite():
            self.rx_credits_allocated = (self.rx_credits_allocated + fc) & self.rx_field_mask


class FcStateHeader(FcStateData):
    def __init__(self, *args, **kwargs):
        self._base_field_size = 12
        super().__init__(*args, **kwargs)


class FcChannelState:
    def __init__(self, init=[0]*6, start_fc_update_timer=None):
        self.ph = FcStateHeader(init[0])
        self.pd = FcStateData(init[1])
        self.nph = FcStateHeader(init[2])
        self.npd = FcStateData(init[3])
        self.cplh = FcStateHeader(init[4])
        self.cpld = FcStateData(init[5])

        self.active = False
        self.fi1 = False
        self.fi1p = False
        self.fi1np = False
        self.fi1cpl = False
        self.fi2 = False
        self.initialized = Event()

        self.fc_p_update = Event()
        self.fc_np_update = Event()
        self.fc_cpl_update = Event()

        self.start_fc_update_timer = start_fc_update_timer

        self.next_fc_p_tx = 0
        self.next_fc_np_tx = 0
        self.next_fc_cpl_tx = 0

        self.rx_release_fc_dict = {}

    def reset(self):
        self.ph.reset()
        self.pd.reset()
        self.nph.reset()
        self.npd.reset()
        self.cplh.reset()
        self.cpld.reset()

        self.active = False
        self.fi1 = False
        self.fi1p = False
        self.fi1np = False
        self.fi1cpl = False
        self.fi2 = False
        self.initialized.clear()

        self.next_fc_p_tx = 0
        self.next_fc_np_tx = 0
        self.next_fc_cpl_tx = 0

        self.rx_release_fc_dict = {}

    def tx_has_credit(self, credit_type, dc=0):
        if credit_type == FcType.P:
            return self.ph.tx_credits_available > 0 and self.pd.tx_credits_available >= dc
        elif credit_type == FcType.NP:
            return self.nph.tx_credits_available > 0 and self.npd.tx_credits_available >= dc
        elif credit_type == FcType.CPL:
            return self.cplh.tx_credits_available > 0 and self.cpld.tx_credits_available >= dc

    def tx_tlp_has_credit(self, tlp):
        return self.tx_has_credit(tlp.get_fc_type(), tlp.get_data_credits())

    def tx_consume_fc(self, credit_type, dc=0):
        if credit_type == FcType.P:
            self.ph.tx_consume_fc(1)
            self.pd.tx_consume_fc(dc)
        elif credit_type == FcType.NP:
            self.nph.tx_consume_fc(1)
            self.npd.tx_consume_fc(dc)
        elif credit_type == FcType.CPL:
            self.cplh.tx_consume_fc(1)
            self.cpld.tx_consume_fc(dc)

    def tx_consume_tlp_fc(self, tlp):
        self.tx_consume_fc(tlp.get_fc_type(), tlp.get_data_credits())

    async def tx_tlp_fc_gate(self, tlp):
        credit_type = tlp.get_fc_type()
        dc = tlp.get_data_credits()
        await self.initialized.wait()
        while not self.tx_has_credit(credit_type, dc):
            if credit_type == FcType.P:
                self.fc_p_update.clear()
                await self.fc_p_update.wait()
            elif credit_type == FcType.NP:
                self.fc_np_update.clear()
                await self.fc_np_update.wait()
            elif credit_type == FcType.CPL:
                self.fc_cpl_update.clear()
                await self.fc_cpl_update.wait()
        self.tx_consume_fc(credit_type, dc)

    def rx_consume_fc(self, credit_type, dc=0):
        if credit_type == FcType.P:
            self.ph.rx_consume_fc(1)
            self.pd.rx_consume_fc(dc)
        elif credit_type == FcType.NP:
            self.nph.rx_consume_fc(1)
            self.npd.rx_consume_fc(dc)
        elif credit_type == FcType.CPL:
            self.cplh.rx_consume_fc(1)
            self.cpld.rx_consume_fc(dc)

    def rx_consume_tlp_fc(self, tlp):
        self.rx_consume_fc(tlp.get_fc_type(), tlp.get_data_credits())

    def rx_release_fc(self, credit_type, dc=0):
        if credit_type == FcType.P:
            self.next_fc_p_tx = 0
            self.ph.rx_release_fc(1)
            self.pd.rx_release_fc(dc)
        elif credit_type == FcType.NP:
            self.next_fc_np_tx = 0
            self.nph.rx_release_fc(1)
            self.npd.rx_release_fc(dc)
        elif credit_type == FcType.CPL:
            self.next_fc_cpl_tx = 0
            self.cplh.rx_release_fc(1)
            self.cpld.rx_release_fc(dc)
        self.start_fc_update_timer()

    def rx_release_tlp_fc(self, tlp):
        self.rx_release_fc(tlp.get_fc_type(), tlp.get_data_credits())

    def rx_release_fc_token(self, token):
        if token in self.rx_release_fc_dict:
            credit_type, dc = self.rx_release_fc_dict.pop(token)
            self.rx_release_fc(credit_type, dc)

    def rx_set_tlp_release_fc_cb(self, tlp):
        credit_type = tlp.get_fc_type()
        dc = tlp.get_data_credits()
        token = object()
        self.rx_release_fc_dict[token] = (credit_type, dc)
        tlp.release_fc_cb = partial(self.rx_release_fc_token, token)

    def rx_process_tlp_fc(self, tlp):
        self.rx_consume_tlp_fc(tlp)
        self.rx_set_tlp_release_fc_cb(tlp)

    def handle_fc_dllp(self, dllp):
        # Handle flow control DLLPs for this VC
        if not self.active:
            return

        if not self.fi1:
            # FC_INIT1
            if dllp.type in {DllpType.INIT_FC1_P, DllpType.INIT_FC1_NP, DllpType.INIT_FC1_CPL,
                    DllpType.INIT_FC2_P, DllpType.INIT_FC2_NP, DllpType.INIT_FC2_CPL}:
                # capture initial credit limit values from InitFC1 and InitFC2 DLLPs
                if dllp.type in {DllpType.INIT_FC1_P, DllpType.INIT_FC2_P}:
                    self.ph.tx_initial_allocation = dllp.hdr_fc
                    self.ph.tx_credit_limit = dllp.hdr_fc
                    self.pd.tx_initial_allocation = dllp.data_fc
                    self.pd.tx_credit_limit = dllp.data_fc
                    self.fi1p = True
                elif dllp.type in {DllpType.INIT_FC1_NP, DllpType.INIT_FC2_NP}:
                    self.nph.tx_initial_allocation = dllp.hdr_fc
                    self.nph.tx_credit_limit = dllp.hdr_fc
                    self.npd.tx_initial_allocation = dllp.data_fc
                    self.npd.tx_credit_limit = dllp.data_fc
                    self.fi1np = True
                elif dllp.type in {DllpType.INIT_FC1_CPL, DllpType.INIT_FC2_CPL}:
                    self.cplh.tx_initial_allocation = dllp.hdr_fc
                    self.cplh.tx_credit_limit = dllp.hdr_fc
                    self.cpld.tx_initial_allocation = dllp.data_fc
                    self.cpld.tx_credit_limit = dllp.data_fc
                    self.fi1cpl = True
                # exit FC_INIT1 once all credit types have been initialized
                self.fi1 = self.fi1p and self.fi1np and self.fi1cpl
        elif not self.fi2:
            # FC_INIT2
            if dllp.type in {DllpType.INIT_FC2_P, DllpType.INIT_FC2_NP, DllpType.INIT_FC2_CPL,
                    DllpType.UPDATE_FC_P, DllpType.UPDATE_FC_NP, DllpType.UPDATE_FC_CPL}:
                # exit FC_INIT2 on receipt of any InitFC2 or UpdateFC DLLP; ignore values
                self.fi2 = True
                self.initialized.set()
        else:
            # normal operation
            # capture new credit limits from UpdateFC DLLPs
            if dllp.type == DllpType.UPDATE_FC_P:
                if self.ph.tx_is_infinite():
                    assert dllp.hdr_fc == 0
                if self.pd.tx_is_infinite():
                    assert dllp.data_fc == 0
                self.ph.tx_credit_limit = dllp.hdr_fc
                self.pd.tx_credit_limit = dllp.data_fc
                self.fc_p_update.set()
            elif dllp.type == DllpType.UPDATE_FC_NP:
                if self.nph.tx_is_infinite():
                    assert dllp.hdr_fc == 0
                if self.npd.tx_is_infinite():
                    assert dllp.data_fc == 0
                self.nph.tx_credit_limit = dllp.hdr_fc
                self.npd.tx_credit_limit = dllp.data_fc
                self.fc_np_update.set()
            elif dllp.type == DllpType.UPDATE_FC_CPL:
                if self.cplh.tx_is_infinite():
                    assert dllp.hdr_fc == 0
                if self.cpld.tx_is_infinite():
                    assert dllp.data_fc == 0
                self.cplh.tx_credit_limit = dllp.hdr_fc
                self.cpld.tx_credit_limit = dllp.data_fc
                self.fc_cpl_update.set()


class Port:
    """Base port"""
    def __init__(self, fc_init=[[0]*6]*8, *args, **kwargs):
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

        self.time_scale = get_sim_steps(1, 'sec')

        # ACK/NAK protocol
        # TX
        self.next_transmit_seq = 0x000
        self.ackd_seq = 0xfff
        self.retry_buffer = Queue()

        # RX
        self.next_recv_seq = 0x000
        self.nak_scheduled = False
        self.ack_nak_latency_timer_steps = 0

        self.max_payload_size = 128
        self.max_latency_timer_steps = 0

        self.send_ack = Event()

        self._ack_latency_timer_cr = None

        # Flow control
        self.send_fc = Event()

        self.fc_state = [FcChannelState(fc_init[k], self.start_fc_update_timer) for k in range(8)]

        self.fc_initialized = False
        self.fc_init_vc = 0
        self.fc_init_type = FcType.P

        self.fc_idle_timer_steps = get_sim_steps(10, 'us')
        self.fc_update_steps = get_sim_steps(30, 'us')

        self._fc_update_timer_cr = None

        super().__init__(*args, **kwargs)

        # VC0 is always active
        self.fc_state[0].active = True

        cocotb.start_soon(self._run_transmit())
        cocotb.start_soon(self._run_receive())
        cocotb.start_soon(self._run_fc_update_idle_timer())

    def classify_tlp_vc(self, tlp):
        return 0

    async def send(self, pkt):
        pkt.release_fc()
        await self.fc_state[self.classify_tlp_vc(pkt)].tx_tlp_fc_gate(pkt)
        await self.tx_queue.put(pkt)
        self.tx_queue_sync.set()

    async def _run_transmit(self):
        await NullTrigger()
        while True:
            while self.tx_queue.empty() and not self.send_ack.is_set() and not self.send_fc.is_set() and self.fc_initialized:
                self.tx_queue_sync.clear()
                await First(self.tx_queue_sync.wait(), self.send_ack.wait(), self.send_fc.wait())

            pkt = None

            if self.send_ack.is_set():
                # Send ACK or NAK DLLP
                # Runs when
                #  - ACK timer expires
                #  - ACK/NAK transmit requested
                self.send_ack.clear()
                if self.nak_scheduled:
                    pkt = Dllp.create_nak((self.next_recv_seq-1) & 0xfff)
                else:
                    pkt = Dllp.create_ack((self.next_recv_seq-1) & 0xfff)
            elif self.send_fc.is_set() or (not self.fc_initialized and self.tx_queue.empty()):
                # Send FC DLLP
                # Runs when
                #  - FC timer expires
                #  - FC update DLLP transmit requested
                #  - FC init is not done AND no TLPs are queued for transmit
                if self.send_fc.is_set():
                    # Send FC update DLLP
                    for fc_ch in self.fc_state:
                        if not fc_ch.active or not fc_ch.fi2:
                            continue

                        sim_time = get_sim_time()
                        if fc_ch.next_fc_p_tx <= sim_time:
                            pkt = Dllp()
                            pkt.vc = self.fc_init_vc
                            pkt.type = DllpType.UPDATE_FC_P
                            pkt.hdr_fc = fc_ch.ph.rx_credits_allocated
                            pkt.data_fc = fc_ch.pd.rx_credits_allocated
                            fc_ch.next_fc_p_tx = sim_time + self.fc_update_steps
                            break
                        if fc_ch.next_fc_np_tx <= sim_time:
                            pkt = Dllp()
                            pkt.vc = self.fc_init_vc
                            pkt.type = DllpType.UPDATE_FC_NP
                            pkt.hdr_fc = fc_ch.nph.rx_credits_allocated
                            pkt.data_fc = fc_ch.npd.rx_credits_allocated
                            fc_ch.next_fc_np_tx = sim_time + self.fc_update_steps
                            break
                        if fc_ch.next_fc_cpl_tx <= sim_time:
                            pkt = Dllp()
                            pkt.vc = self.fc_init_vc
                            pkt.type = DllpType.UPDATE_FC_CPL
                            pkt.hdr_fc = fc_ch.cplh.rx_credits_allocated
                            pkt.data_fc = fc_ch.cpld.rx_credits_allocated
                            fc_ch.next_fc_cpl_tx = sim_time + self.fc_update_steps
                            break

                if not self.fc_initialized and not pkt:
                    # Send FC init DLLP
                    fc_ch = self.fc_state[self.fc_init_vc]
                    pkt = Dllp()
                    pkt.vc = self.fc_init_vc
                    if self.fc_init_type == FcType.P:
                        pkt.type = DllpType.INIT_FC1_P if not fc_ch.fi1 else DllpType.INIT_FC2_P
                        pkt.hdr_fc = fc_ch.ph.rx_credits_allocated
                        pkt.data_fc = fc_ch.pd.rx_credits_allocated
                        self.fc_init_type = FcType.NP
                    elif self.fc_init_type == FcType.NP:
                        pkt.type = DllpType.INIT_FC1_NP if not fc_ch.fi1 else DllpType.INIT_FC2_NP
                        pkt.hdr_fc = fc_ch.nph.rx_credits_allocated
                        pkt.data_fc = fc_ch.npd.rx_credits_allocated
                        self.fc_init_type = FcType.CPL
                    elif self.fc_init_type == FcType.CPL:
                        pkt.type = DllpType.INIT_FC1_CPL if not fc_ch.fi1 else DllpType.INIT_FC2_CPL
                        pkt.hdr_fc = fc_ch.cplh.rx_credits_allocated
                        pkt.data_fc = fc_ch.cpld.rx_credits_allocated
                        self.fc_init_type = FcType.P
                        # find next active VC that hasn't finished FC init
                        for k in range(8):
                            vc = (self.fc_init_vc+1+k) % 8
                            if self.fc_state[vc].active and not self.fc_state[vc].fi2:
                                self.fc_init_vc = vc
                                break

                    # check all active VC and report FC not initialized if any are not complete
                    self.fc_initialized = True
                    for vc in range(8):
                        if self.fc_state[vc].active and not self.fc_state[vc].fi2:
                            self.fc_initialized = False

                if not pkt:
                    # no more DLLPs to send, clear event
                    self.send_fc.clear()

            if pkt is not None:
                self.log.debug("Send DLLP %s", pkt)
            elif not self.tx_queue.empty():
                pkt = self.tx_queue.get_nowait()
                pkt.seq = self.next_transmit_seq
                self.log.debug("Send TLP %s", pkt)
                self.next_transmit_seq = (self.next_transmit_seq + 1) & 0xfff
                self.retry_buffer.put_nowait(pkt)

            if pkt:
                await self.handle_tx(pkt)

    async def handle_tx(self, pkt):
        raise NotImplementedError()

    async def ext_recv(self, pkt):
        if isinstance(pkt, Dllp):
            # DLLP
            self.log.debug("Receive DLLP %s", pkt)
            self.handle_dllp(pkt)
        else:
            # TLP
            self.log.debug("Receive TLP %s", pkt)
            if pkt.seq == self.next_recv_seq:
                # expected seq
                self.next_recv_seq = (self.next_recv_seq + 1) & 0xfff
                self.nak_scheduled = False
                self.start_ack_latency_timer()
                pkt = Tlp(pkt)
                self.fc_state[self.classify_tlp_vc(pkt)].rx_process_tlp_fc(pkt)
                self.rx_queue.put_nowait(pkt)
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

    def handle_dllp(self, dllp):
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
        elif dllp.type in {DllpType.INIT_FC1_P, DllpType.INIT_FC1_NP, DllpType.INIT_FC1_CPL,
                DllpType.INIT_FC2_P, DllpType.INIT_FC2_NP, DllpType.INIT_FC2_CPL,
                DllpType.UPDATE_FC_P, DllpType.UPDATE_FC_NP, DllpType.UPDATE_FC_CPL}:
            # Flow control
            self.fc_state[dllp.vc].handle_fc_dllp(dllp)
        else:
            raise Exception("TODO")

    def start_ack_latency_timer(self):
        if self._ack_latency_timer_cr is not None:
            if not self._ack_latency_timer_cr._finished:
                # already running
                return
        self._ack_latency_timer_cr = cocotb.start_soon(self._run_ack_latency_timer())

    def stop_ack_latency_timer(self):
        if self._ack_latency_timer_cr is not None:
            self._ack_latency_timer_cr.kill()
            self._ack_latency_timer_cr = None

    async def _run_ack_latency_timer(self):
        await Timer(max(self.max_latency_timer_steps, 1), 'step')
        if not self.nak_scheduled:
            self.send_ack.set()

    def start_fc_update_timer(self):
        if self._fc_update_timer_cr is not None:
            if not self._fc_update_timer_cr._finished:
                # already running
                return
        self._fc_update_timer_cr = cocotb.start_soon(self._run_fc_update_timer())

    def stop_fc_update_timer(self):
        if self._fc_update_timer_cr is not None:
            self._fc_update_timer_cr.kill()
            self._fc_update_timer_cr = None

    async def _run_fc_update_timer(self):
        await Timer(max(self.max_latency_timer_steps, 1), 'step')
        self.send_fc.set()

    async def _run_fc_update_idle_timer(self):
        while True:
            await Timer(max(self.fc_idle_timer_steps, 1), 'step')
            self.send_fc.set()


class SimPort(Port):
    """Port to interconnect simulated PCIe devices"""
    def __init__(self, fc_init=[[0]*6]*8, *args, **kwargs):
        super().__init__(*args, fc_init, **kwargs)

        self.other = None

        self.port_delay = 5e-9

        self.symbol_period = 0
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
            self.symbol_period = 8 / (PCIE_GEN_RATE[self.cur_link_speed] * self.cur_link_width)
            self.max_latency_timer_steps = int(get_max_update_latency(self.max_payload_size, self.cur_link_width, self.cur_link_speed) * 8 / PCIE_GEN_RATE[self.cur_link_speed] * self.time_scale)
            self.link_delay_steps = int((self.port_delay + port.port_delay) * self.time_scale)
        else:
            self.symbol_period = 0
            self.max_latency_timer_steps = 0
            self.link_delay_steps = 0

    async def handle_tx(self, pkt):
        await Timer(max(int(pkt.get_wire_size() * self.symbol_period * self.time_scale), 1), 'step')
        cocotb.start_soon(self._transmit(pkt))

    async def _transmit(self, pkt):
        if self.other is None:
            raise Exception("Port not connected")
        await Timer(max(self.link_delay_steps, 1), 'step')
        await self.other.ext_recv(pkt)
