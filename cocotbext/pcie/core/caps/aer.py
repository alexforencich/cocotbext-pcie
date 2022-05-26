"""

Copyright (c) 2021 Alex Forencich

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

from .common import PciExtCapId, PciExtCap


class AerExtendedCapability(PciExtCap):
    """Advanced Error Reporting extended capability"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cap_id = PciExtCapId.AER
        self.cap_ver = 2
        self.length = 11

        # Advanced Error Reporting capability registers
        # Uncorrectable error status
        self.data_link_protocol_error_status = False
        self.surprise_down_error_status = False
        self.poisoned_tlp_received_status = False
        self.flow_control_protocol_error_status = False
        self.completion_timeout_status = False
        self.completer_abort_status = False
        self.unexpected_completion_status = False
        self.receiver_overflow_status = False
        self.malformed_tlp_status = False
        self.ecrc_error_status = False
        self.unsupported_request_error_status = False
        self.acs_violation_status = False
        self.uncorrectable_internal_error_status = False
        self.mc_blocked_tlp_status = False
        self.atomicop_egress_blocked_status = False
        self.tlp_prefix_blocked_error_status = False
        self.poisoned_tlp_egress_blocked_status = False
        # Uncorrectable error mask
        self.data_link_protocol_error_mask = False
        self.surprise_down_error_mask = False
        self.poisoned_tlp_received_mask = False
        self.flow_control_protocol_error_mask = False
        self.completion_timeout_mask = False
        self.completer_abort_mask = False
        self.unexpected_completion_mask = False
        self.receiver_overflow_mask = False
        self.malformed_tlp_mask = False
        self.ecrc_error_mask = False
        self.unsupported_request_error_mask = False
        self.acs_violation_mask = False
        self.uncorrectable_internal_error_mask = True
        self.mc_blocked_tlp_mask = False
        self.atomicop_egress_blocked_mask = False
        self.tlp_prefix_blocked_error_mask = False
        self.poisoned_tlp_egress_blocked_mask = True
        # Uncorrectable error severity
        self.data_link_protocol_error_severity = True
        self.surprise_down_error_severity = True
        self.poisoned_tlp_received_severity = False
        self.flow_control_protocol_error_severity = True
        self.completion_timeout_severity = False
        self.completer_abort_severity = False
        self.unexpected_completion_severity = False
        self.receiver_overflow_severity = True
        self.malformed_tlp_severity = True
        self.ecrc_error_severity = False
        self.unsupported_request_error_severity = False
        self.acs_violation_severity = False
        self.uncorrectable_internal_error_severity = True
        self.mc_blocked_tlp_severity = False
        self.atomicop_egress_blocked_severity = False
        self.tlp_prefix_blocked_error_severity = False
        self.poisoned_tlp_egress_blocked_severity = False
        # Correctable error status
        self.receiver_error_status = False
        self.bad_tlp_status = False
        self.bad_dllp_status = False
        self.replay_num_rollover_status = False
        self.replay_timer_timeout_status = False
        self.advisory_nonfatal_error_status = False
        self.corrected_internal_error_status = False
        self.header_log_overflow_status = False
        # Correctable error mask
        self.receiver_error_mask = False
        self.bad_tlp_mask = False
        self.bad_dllp_mask = False
        self.replay_num_rollover_mask = False
        self.replay_timer_timeout_mask = False
        self.advisory_nonfatal_error_mask = True
        self.corrected_internal_error_mask = True
        self.header_log_overflow_mask = True
        # Advanced error capabilities and control
        self.first_error_pointer = 0
        self.ecrc_generation_capable = False
        self.ecrc_generation_enable = False
        self.ecrc_check_capable = False
        self.ecrc_check_enable = False
        self.multiple_header_recording_capable = False
        self.multiple_header_recording_enable = False
        self.tlp_prefix_log_present = False
        self.completion_timeout_prefix_header_log_capable = False
        # Header log
        self.header_log = [0]*4
        # Root error command
        self.fatal_error_reporting_enable = False
        self.nonfatal_error_reporting_enable = False
        self.correctable_error_reporting_enable = False
        # Root error status
        self.err_cor_received = False
        self.multiple_err_cor_received = False
        self.err_fatal_nonfatal_received = False
        self.multiple_err_fatal_nonfatal_received = False
        self.first_uncorrectable_fatal = False
        self.nonfatal_error_messages_received = False
        self.fatal_error_messages_received = False
        self.advanced_error_interrupt_message_number = 0
        # Error source identification
        self.err_cor_source_identification = 0
        self.err_fatal_nonfatal_source_identification = 0
        # TLP prefix log
        self.tlp_prefix_log = [0]*4

    """
    Advanced Error Reporting extended capability

    31                                                                  0
    +-------------------------+-------+---------------------------------+
    |     Next Cap Offset     |  Ver  |         AER Ext Cap ID          |   0   0x00
    +-------------------------+-------+---------------------------------+
    |                    Uncorrectable error status                     |   1   0x04
    +-------------------------------------------------------------------+
    |                     Uncorrectable error mask                      |   2   0x08
    +-------------------------------------------------------------------+
    |                   Uncorrectable error severity                    |   3   0x0C
    +-------------------------------------------------------------------+
    |                     Correctable error status                      |   4   0x10
    +-------------------------------------------------------------------+
    |                      Correctable error mask                       |   5   0x14
    +-------------------------------------------------------------------+
    |              Advanced error capabilities and control              |   6   0x18
    +-------------------------------------------------------------------+
    |                                                                   |   7   0x1C
    |                            Header log                             |   8   0x20
    |                                                                   |   9   0x24
    |                                                                   |  10   0x28
    +-------------------------------------------------------------------+
    |                        Root error command                         |  11   0x2C
    +-------------------------------------------------------------------+
    |                         Root error status                         |  12   0x30
    +-------------------------------------------------------------------+
    |                    Error source identification                    |  13   0x34
    +-------------------------------------------------------------------+
    |                                                                   |  14   0x38
    |                          TLP prefix log                           |  15   0x3C
    |                                                                   |  16   0x40
    |                                                                   |  17   0x44
    +-------------------------------------------------------------------+
    """
    async def _read_register(self, reg):
        if reg == 1:
            # Uncorrectable error status
            val = bool(self.data_link_protocol_error_status) << 4
            val |= bool(self.surprise_down_error_status) << 5
            val |= bool(self.poisoned_tlp_received_status) << 12
            val |= bool(self.flow_control_protocol_error_status) << 13
            val |= bool(self.completion_timeout_status) << 14
            val |= bool(self.completer_abort_status) << 15
            val |= bool(self.unexpected_completion_status) << 16
            val |= bool(self.receiver_overflow_status) << 17
            val |= bool(self.malformed_tlp_status) << 18
            val |= bool(self.ecrc_error_status) << 19
            val |= bool(self.unsupported_request_error_status) << 20
            val |= bool(self.acs_violation_status) << 21
            val |= bool(self.uncorrectable_internal_error_status) << 22
            val |= bool(self.mc_blocked_tlp_status) << 23
            val |= bool(self.atomicop_egress_blocked_status) << 24
            val |= bool(self.tlp_prefix_blocked_error_status) << 25
            val |= bool(self.poisoned_tlp_egress_blocked_status) << 26
            return val
        elif reg == 2:
            # Uncorrectable error mask
            val = bool(self.data_link_protocol_error_mask) << 4
            val |= bool(self.surprise_down_error_mask) << 5
            val |= bool(self.poisoned_tlp_received_mask) << 12
            val |= bool(self.flow_control_protocol_error_mask) << 13
            val |= bool(self.completion_timeout_mask) << 14
            val |= bool(self.completer_abort_mask) << 15
            val |= bool(self.unexpected_completion_mask) << 16
            val |= bool(self.receiver_overflow_mask) << 17
            val |= bool(self.malformed_tlp_mask) << 18
            val |= bool(self.ecrc_error_mask) << 19
            val |= bool(self.unsupported_request_error_mask) << 20
            val |= bool(self.acs_violation_mask) << 21
            val |= bool(self.uncorrectable_internal_error_mask) << 22
            val |= bool(self.mc_blocked_tlp_mask) << 23
            val |= bool(self.atomicop_egress_blocked_mask) << 24
            val |= bool(self.tlp_prefix_blocked_error_mask) << 25
            val |= bool(self.poisoned_tlp_egress_blocked_mask) << 26
            return val
        elif reg == 3:
            # Uncorrectable error severity
            val = bool(self.data_link_protocol_error_severity) << 4
            val |= bool(self.surprise_down_error_severity) << 5
            val |= bool(self.poisoned_tlp_received_severity) << 12
            val |= bool(self.flow_control_protocol_error_severity) << 13
            val |= bool(self.completion_timeout_severity) << 14
            val |= bool(self.completer_abort_severity) << 15
            val |= bool(self.unexpected_completion_severity) << 16
            val |= bool(self.receiver_overflow_severity) << 17
            val |= bool(self.malformed_tlp_severity) << 18
            val |= bool(self.ecrc_error_severity) << 19
            val |= bool(self.unsupported_request_error_severity) << 20
            val |= bool(self.acs_violation_severity) << 21
            val |= bool(self.uncorrectable_internal_error_severity) << 22
            val |= bool(self.mc_blocked_tlp_severity) << 23
            val |= bool(self.atomicop_egress_blocked_severity) << 24
            val |= bool(self.tlp_prefix_blocked_error_severity) << 25
            val |= bool(self.poisoned_tlp_egress_blocked_severity) << 26
            return val
        elif reg == 4:
            # Correctable error status
            val = bool(self.receiver_error_status)
            val |= bool(self.bad_tlp_status) << 6
            val |= bool(self.bad_dllp_status) << 7
            val |= bool(self.replay_num_rollover_status) << 8
            val |= bool(self.replay_timer_timeout_status) << 12
            val |= bool(self.advisory_nonfatal_error_status) << 13
            val |= bool(self.corrected_internal_error_status) << 14
            val |= bool(self.header_log_overflow_status) << 15
            return val
        elif reg == 5:
            # Correctable error mask
            val = bool(self.receiver_error_mask) << 0
            val |= bool(self.bad_tlp_mask) << 6
            val |= bool(self.bad_dllp_mask) << 7
            val |= bool(self.replay_num_rollover_mask) << 8
            val |= bool(self.replay_timer_timeout_mask) << 12
            val |= bool(self.advisory_nonfatal_error_mask) << 13
            val |= bool(self.corrected_internal_error_mask) << 14
            val |= bool(self.header_log_overflow_mask) << 15
            return val
        elif reg == 6:
            # Advanced error capabilities and control
            val = self.first_error_pointer & 0xf
            val |= bool(self.ecrc_generation_capable) << 5
            val |= bool(self.ecrc_generation_enable) << 6
            val |= bool(self.ecrc_check_capable) << 7
            val |= bool(self.ecrc_check_enable) << 8
            val |= bool(self.multiple_header_recording_capable) << 9
            val |= bool(self.multiple_header_recording_enable) << 10
            val |= bool(self.tlp_prefix_log_present) << 11
            val |= bool(self.completion_timeout_prefix_header_log_capable) << 12
            return val
        elif 7 <= reg <= 10:
            # Header log
            return self.header_log[reg-7] & 0xffffffff
        elif reg == 11:
            # Root error command
            val = bool(self.fatal_error_reporting_enable)
            val |= bool(self.nonfatal_error_reporting_enable) << 1
            val |= bool(self.correctable_error_reporting_enable) << 2
            return val
        elif reg == 12:
            # Root error status
            val = bool(self.err_cor_received) << 0
            val |= bool(self.multiple_err_cor_received) << 1
            val |= bool(self.err_fatal_nonfatal_received) << 2
            val |= bool(self.multiple_err_fatal_nonfatal_received) << 3
            val |= bool(self.first_uncorrectable_fatal) << 4
            val |= bool(self.nonfatal_error_messages_received) << 5
            val |= bool(self.fatal_error_messages_received) << 6
            val |= (self.advanced_error_interrupt_message_number & 0x1f) << 27
            return val
        elif reg == 13:
            # Error source identification
            val = self.err_cor_source_identification & 0xffff
            val |= (self.err_fatal_nonfatal_source_identification & 0xffff) << 16
            return val
        elif 14 <= reg <= 17:
            # TLP prefix log
            return self.tlp_prefix_log[reg-14] & 0xffffffff
        else:
            return 0

    async def _write_register(self, reg, data, mask):
        if reg == 1:
            # Uncorrectable error status
            if mask & 0x1:
                if data & 1 << 4:
                    self.data_link_protocol_error_status = False
                if data & 1 << 5:
                    self.surprise_down_error_status = False
            if mask & 0x2:
                if data & 1 << 12:
                    self.poisoned_tlp_received_status = False
                if data & 1 << 13:
                    self.flow_control_protocol_error_status = False
                if data & 1 << 14:
                    self.completion_timeout_status = False
                if data & 1 << 15:
                    self.completer_abort_status = False
            if mask & 0x4:
                if data & 1 << 16:
                    self.unexpected_completion_status = False
                if data & 1 << 17:
                    self.receiver_overflow_status = False
                if data & 1 << 18:
                    self.malformed_tlp_status = False
                if data & 1 << 19:
                    self.ecrc_error_status = False
                if data & 1 << 20:
                    self.unsupported_request_error_status = False
                if data & 1 << 21:
                    self.acs_violation_status = False
                if data & 1 << 22:
                    self.uncorrectable_internal_error_status = False
                if data & 1 << 23:
                    self.mc_blocked_tlp_status = False
            if mask & 0x8:
                if data & 1 << 24:
                    self.atomicop_egress_blocked_status = False
                if data & 1 << 25:
                    self.tlp_prefix_blocked_error_status = False
                if data & 1 << 26:
                    self.poisoned_tlp_egress_blocked_status = False
        elif reg == 2:
            # Uncorrectable error mask
            if mask & 0x1:
                self.data_link_protocol_error_mask = bool(data & 1 << 4)
                self.surprise_down_error_mask = bool(data & 1 << 5)
            if mask & 0x2:
                self.poisoned_tlp_received_mask = bool(data & 1 << 12)
                self.flow_control_protocol_error_mask = bool(data & 1 << 13)
                self.completion_timeout_mask = bool(data & 1 << 14)
                self.completer_abort_mask = bool(data & 1 << 15)
            if mask & 0x4:
                self.unexpected_completion_mask = bool(data & 1 << 16)
                self.receiver_overflow_mask = bool(data & 1 << 17)
                self.malformed_tlp_mask = bool(data & 1 << 18)
                self.ecrc_error_mask = bool(data & 1 << 19)
                self.unsupported_request_error_mask = bool(data & 1 << 20)
                self.acs_violation_mask = bool(data & 1 << 21)
                self.uncorrectable_internal_error_mask = bool(data & 1 << 22)
                self.mc_blocked_tlp_mask = bool(data & 1 << 23)
            if mask & 0x8:
                self.atomicop_egress_blocked_mask = bool(data & 1 << 24)
                self.tlp_prefix_blocked_error_mask = bool(data & 1 << 25)
                self.poisoned_tlp_egress_blocked_mask = bool(data & 1 << 26)
        elif reg == 3:
            # Uncorrectable error severity
            if mask & 0x1:
                self.data_link_protocol_error_severity = bool(data & 1 << 4)
                self.surprise_down_error_severity = bool(data & 1 << 5)
            if mask & 0x2:
                self.poisoned_tlp_received_severity = bool(data & 1 << 12)
                self.flow_control_protocol_error_severity = bool(data & 1 << 13)
                self.completion_timeout_severity = bool(data & 1 << 14)
                self.completer_abort_severity = bool(data & 1 << 15)
            if mask & 0x4:
                self.unexpected_completion_severity = bool(data & 1 << 16)
                self.receiver_overflow_severity = bool(data & 1 << 17)
                self.malformed_tlp_severity = bool(data & 1 << 18)
                self.ecrc_error_severity = bool(data & 1 << 19)
                self.unsupported_request_error_severity = bool(data & 1 << 20)
                self.acs_violation_severity = bool(data & 1 << 21)
                self.uncorrectable_internal_error_severity = bool(data & 1 << 22)
                self.mc_blocked_tlp_severity = bool(data & 1 << 23)
            if mask & 0x8:
                self.atomicop_egress_blocked_severity = bool(data & 1 << 24)
                self.tlp_prefix_blocked_error_severity = bool(data & 1 << 25)
                self.poisoned_tlp_egress_blocked_severity = bool(data & 1 << 26)
        elif reg == 4:
            # Correctable error status
            if mask & 0x1:
                if data & 1 << 0:
                    self.receiver_error_status = False
                if data & 1 << 6:
                    self.bad_tlp_status = False
                if data & 1 << 7:
                    self.bad_dllp_status = False
            if mask & 0x2:
                if data & 1 << 8:
                    self.replay_num_rollover_status = False
                if data & 1 << 12:
                    self.replay_timer_timeout_status = False
                if data & 1 << 13:
                    self.advisory_nonfatal_error_status = False
                if data & 1 << 14:
                    self.corrected_internal_error_status = False
                if data & 1 << 15:
                    self.header_log_overflow_status = False
        elif reg == 5:
            # Correctable error mask
            if mask & 0x1:
                self.receiver_error_mask = bool(data & 1 << 0)
                self.bad_tlp_mask = bool(data & 1 << 6)
                self.bad_dllp_mask = bool(data & 1 << 7)
            if mask & 0x2:
                self.replay_num_rollover_mask = bool(data & 1 << 8)
                self.replay_timer_timeout_mask = bool(data & 1 << 12)
                self.advisory_nonfatal_error_mask = bool(data & 1 << 13)
                self.corrected_internal_error_mask = bool(data & 1 << 14)
                self.header_log_overflow_mask = bool(data & 1 << 15)
        elif reg == 6:
            # Advanced error capabilities and control
            if mask & 0x1:
                self.ecrc_generation_enable = bool(data & 1 << 6)
            if mask & 0x2:
                self.ecrc_check_enable = bool(data & 1 << 8)
                self.multiple_header_recording_enable = bool(data & 1 << 10)
        elif reg == 11:
            # Root error command
            if mask & 0x1:
                self.fatal_error_reporting_enable = bool(data & 1 << 0)
                self.nonfatal_error_reporting_enable = bool(data & 1 << 1)
                self.correctable_error_reporting_enable = bool(data & 1 << 2)
            pass
        elif reg == 12:
            # Root error status
            if mask & 0x1:
                if data & 1 << 0:
                    self.err_cor_received = False
                if data & 1 << 1:
                    self.multiple_err_cor_received = False
                if data & 1 << 2:
                    self.err_fatal_nonfatal_received = False
                if data & 1 << 3:
                    self.multiple_err_fatal_nonfatal_received = False
                if data & 1 << 4:
                    self.first_uncorrectable_fatal = False
                if data & 1 << 5:
                    self.nonfatal_error_messages_received = False
                if data & 1 << 6:
                    self.fatal_error_messages_received = False
