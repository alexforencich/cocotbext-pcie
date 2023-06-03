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

from .common import PciCapId, PciCap
from .common import PciExtCapId, PciExtCap
from ..utils import byte_mask_update


class PcieCapability(PciCap):
    """PCI Express capability"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cap_id = PciCapId.EXP
        self.length = 15

        # PCIe capability registers
        # PCIe capabilities
        self.pcie_capability_version = 2
        self.pcie_device_type = 0
        self.pcie_slot_implemented = False
        self.interrupt_message_number = 0
        # Device capabilities
        self.max_payload_size_supported = 0x5
        self.phantom_functions_supported = 0
        self.extended_tag_supported = True
        self.endpoint_l0s_acceptable_latency = 0x7
        self.endpoint_l1_acceptable_latency = 0x7
        self.role_based_error_reporting = True  # TODO check ECN
        self.captured_slot_power_limit_value = 0
        self.captured_slot_power_limit_scale = 0
        self.function_level_reset_capability = False
        # Device control
        self.correctable_error_reporting_enable = False
        self.non_fatal_error_reporting_enable = False
        self.fatal_error_reporting_enable = False
        self.unsupported_request_reporting_enable = False
        self.enable_relaxed_ordering = True
        self.max_payload_size = 0x0
        self.extended_tag_field_enable = False
        self.phantom_functions_enable = False
        self.aux_power_pm_enable = False
        self.enable_no_snoop = True
        self.max_read_request_size = 0x2
        # Device status
        self.correctable_error_detected = False
        self.nonfatal_error_detected = False
        self.fatal_error_detected = False
        self.unsupported_request_detected = False
        self.aux_power_detected = False
        self.transactions_pending = False
        self.emergency_power_reduction_detected = False
        # Link capabilities
        self.max_link_speed = 0
        self.max_link_width = 0
        self.aspm_support = 0
        self.l0s_exit_latency = 0
        self.l1_exit_latency = 0
        self.clock_power_management = False
        self.surprise_down_error_reporting_capability = False
        self.data_link_layer_link_active_reporting_capable = False
        self.link_bandwidth_notification_capability = False
        self.aspm_optionality_compliance = False
        self.port_number = 0
        # Link control
        self.aspm_control = 0
        self.read_completion_boundary = False
        self.link_disable = False
        self.common_clock_configuration = False
        self.extended_synch = False
        self.enable_clock_power_management = False
        self.hardware_autonomous_width_disable = False
        self.link_bandwidth_management_interrupt_enable = False
        self.link_autonomous_bandwidth_interrupt_enable = False
        self.drs_signalling_control = 0
        # Link status
        self.current_link_speed = 0
        self.negotiated_link_width = 0
        self.link_training = False
        self.slot_clock_configuration = False
        self.data_link_layer_link_active = False
        self.link_bandwidth_management_status = False
        self.link_autonomous_bandwidth_status = False
        # Slot capabilities
        self.attention_button_present = False
        self.power_controller_present = False
        self.mrl_sensor_present = False
        self.attention_indicator_present = False
        self.power_indicator_present = False
        self.hot_plug_surprise = False
        self.hot_plug_capable = False
        self.slot_power_limit_value = 0
        self.slot_power_limit_scale = 0
        self.electromechanical_interlock_present = False
        self.no_command_completed_support = False
        self.physical_slot_number = 0
        # Slot control
        self.attention_button_pressed_enable = False
        self.power_fault_detected_enable = False
        self.mrl_sensor_changed_enable = False
        self.presence_detect_changed_enable = False
        self.command_completed_interrupt_enable = False
        self.hot_plug_interrupt_enable = False
        self.attention_indicator_control = 0
        self.power_indicator_control = 0
        self.power_controller_control = False
        self.electromechanical_interlock_control = False
        self.data_link_layer_state_changed_enable = False
        self.auto_slot_power_limit_disable = False
        # Slot status
        self.attention_button_pressed = False
        self.power_fault_detected = False
        self.mrl_sensor_changed = False
        self.presence_detect_changed = False
        self.command_completed = False
        self.mrl_sensor_state = False
        self.presence_detect_state = False
        self.electromechanical_interlock_status = False
        self.data_link_layer_state_changed = False
        # Root control
        self.system_error_on_correctable_error_enable = False
        self.system_error_on_non_fatal_error_enable = False
        self.system_error_on_fatal_error_enable = False
        self.pme_interrupt_enable = False
        self.crs_software_visibility_enable = False
        # Root capabilities
        self.crs_software_visibility = False
        # Root status
        self.pme_requester_id = 0
        self.pme_status = False
        self.pme_pending = False
        # Device capabilities 2
        self.completion_timeout_ranges_supported = 0
        self.completion_timeout_disable_supported = False
        self.ari_forwarding_supported = False
        self.atomic_op_forwarding_supported = False
        self.atomic_op_32_bit_completer_supported = False
        self.atomic_op_64_bit_completer_supported = False
        self.cas_128_bit_completer_supported = False
        self.no_ro_enabled_pr_pr_passing = False
        self.ltr_mechanism_supported = False
        self.tph_completer_supported = 0
        self.obff_supported = 0
        self.extended_fmt_field_supported = False
        self.end_end_tlp_prefix_supported = False
        self.max_end_end_tlp_prefix = 0
        self.emergency_power_reduction_supported = 0
        self.emergency_power_reduction_initialization_required = False
        self.frs_supported = False
        # Device control 2
        self.completion_timeout_value = 0
        self.completion_timeout_disable = False
        self.ari_forwarding_enable = False
        self.atomic_op_requester_enable = False
        self.atomic_op_egress_blocking = False
        self.ido_request_enable = False
        self.ido_completion_enable = False
        self.ltr_mechanism_enable = False
        self.emergency_power_reduction_request = False
        self.ten_bit_tag_requester_enable = False
        self.obff_enable = 0
        self.end_end_tlp_prefix_blocking = False
        # Device status 2
        # Link capabilities 2
        self.supported_link_speeds = 0
        self.crosslink_supported = False
        self.lower_skp_os_generation_supported_speeds = 0
        self.lower_skp_os_reception_supported_speeds = 0
        self.retimer_presence_detect_supported = False
        self.two_retimers_presence_detect_supported = False
        self.drs_supported = False
        # Link control 2
        self.target_link_speed = 0
        self.enter_compliance = False
        self.hardware_autonomous_speed_disable = False
        self.selectable_deemphasis = False
        self.transmit_margin = 0
        self.enter_modified_compliance = False
        self.compliance_sos = False
        self.compliance_preset_deemphasis = 0
        # Link status 2
        self.current_deemphasis_level = False
        self.equalization_8gt_complete = False
        self.equalization_8gt_phase_1_successful = False
        self.equalization_8gt_phase_2_successful = False
        self.equalization_8gt_phase_3_successful = False
        self.link_equalization_8gt_request = False
        self.retimer_presence_detected = False
        self.two_retimers_presence_detected = False
        self.crosslink_resolution = 0
        self.downstream_component_presence = 0
        self.drs_message_received = False
        # Slot capabilities 2
        # Slot control 2
        # Slot status 2

    """
    PCIe Capability

    31                                                                  0
    +---------------------------------+----------------+----------------+
    |        PCIe Capabilities        |    Next Cap    |    PCIe Cap    |   0   0x00
    +---------------------------------+----------------+----------------+
    |                        Device Capabilities                        |   1   0x04
    +---------------------------------+---------------------------------+
    |          Device Status          |         Device Control          |   2   0x08
    +---------------------------------+---------------------------------+
    |                         Link Capabilities                         |   3   0x0C
    +---------------------------------+---------------------------------+
    |           Link Status           |          Link Control           |   4   0x10
    +---------------------------------+---------------------------------+
    |                         Slot Capabilities                         |   5   0x14
    +---------------------------------+---------------------------------+
    |           Slot Status           |          Slot Control           |   6   0x18
    +---------------------------------+---------------------------------+
    |        Root Capabilities        |          Root Control           |   7   0x1C
    +---------------------------------+---------------------------------+
    |                            Root status                            |   8   0x20
    +-------------------------------------------------------------------+
    |                       Device Capabilities 2                       |   9   0x24
    +---------------------------------+---------------------------------+
    |         Device Status 2         |        Device Control 2         |  10   0x28
    +---------------------------------+---------------------------------+
    |                        Link Capabilities 2                        |  11   0x2C
    +---------------------------------+---------------------------------+
    |          Link Status 2          |         Link Control 2          |  12   0x30
    +---------------------------------+---------------------------------+
    |                        Slot Capabilities 2                        |  13   0x34
    +---------------------------------+---------------------------------+
    |          Slot Status 2          |         Slot Control 2          |  14   0x38
    +---------------------------------+---------------------------------+
    """
    async def _read_register(self, reg):
        if reg == 0:
            # PCIe capabilities
            val = 2 << 16
            val |= (self.pcie_device_type & 0xf) << 20
            val |= bool(self.pcie_slot_implemented) << 24
            val |= (self.interrupt_message_number & 0x1f) << 25
            return val
        elif reg == 1:
            # Device capabilities
            val = self.max_payload_size_supported & 0x7
            val |= (self.phantom_functions_supported & 0x3) << 3
            val |= bool(self.extended_tag_supported) << 5
            val |= (self.endpoint_l0s_acceptable_latency & 0x7) << 6
            val |= (self.endpoint_l1_acceptable_latency & 7) << 9
            val |= bool(self.role_based_error_reporting) << 15
            val |= (self.captured_slot_power_limit_value & 0xff) << 18
            val |= (self.captured_slot_power_limit_scale & 0x3) << 26
            val |= bool(self.function_level_reset_capability) << 28
            return val
        elif reg == 2:
            # Device control
            val = bool(self.correctable_error_reporting_enable) << 0
            val |= bool(self.non_fatal_error_reporting_enable) << 1
            val |= bool(self.fatal_error_reporting_enable) << 2
            val |= bool(self.unsupported_request_reporting_enable) << 3
            val |= bool(self.enable_relaxed_ordering) << 4
            val |= (self.max_payload_size & 0x7) << 5
            val |= bool(self.extended_tag_field_enable) << 8
            val |= bool(self.phantom_functions_enable) << 9
            val |= bool(self.aux_power_pm_enable) << 10
            val |= bool(self.enable_no_snoop) << 11
            val |= (self.max_read_request_size & 0x7) << 12
            # Device status
            val |= bool(self.correctable_error_detected) << 16
            val |= bool(self.nonfatal_error_detected) << 17
            val |= bool(self.fatal_error_detected) << 18
            val |= bool(self.unsupported_request_detected) << 19
            val |= bool(self.aux_power_detected) << 20
            val |= bool(self.transactions_pending) << 21
            val |= bool(self.emergency_power_reduction_detected) << 22
            return val
        elif reg == 3:
            # Link capabilities
            val = self.max_link_speed & 0xf
            val |= (self.max_link_width & 0x3f) >> 4
            val |= (self.aspm_support & 0x3) >> 10
            val |= (self.l0s_exit_latency & 0x7) >> 12
            val |= (self.l1_exit_latency & 0x7) >> 15
            val |= bool(self.clock_power_management) << 18
            val |= bool(self.surprise_down_error_reporting_capability) << 19
            val |= bool(self.data_link_layer_link_active_reporting_capable) << 20
            val |= bool(self.link_bandwidth_notification_capability) << 21
            val |= bool(self.aspm_optionality_compliance) << 22
            val |= (self.port_number & 0xff) << 24
            return val
        elif reg == 4:
            # Link control
            val = self.aspm_control & 0x3
            val |= bool(self.read_completion_boundary) << 3
            val |= bool(self.link_disable) << 4
            val |= bool(self.common_clock_configuration) << 6
            val |= bool(self.extended_synch) << 7
            val |= bool(self.enable_clock_power_management) << 8
            val |= bool(self.hardware_autonomous_width_disable) << 9
            val |= bool(self.link_bandwidth_management_interrupt_enable) << 10
            val |= bool(self.link_autonomous_bandwidth_interrupt_enable) << 11
            val |= (self.drs_signalling_control & 0x3) << 14
            # Link status
            val |= (self.current_link_speed & 0xf) << 16
            val |= (self.negotiated_link_width & 0x3f) << 20
            val |= bool(self.link_training) << 27
            val |= bool(self.slot_clock_configuration) << 28
            val |= bool(self.data_link_layer_link_active) << 29
            val |= bool(self.link_bandwidth_management_status) << 30
            val |= bool(self.link_autonomous_bandwidth_status) << 31
            return val
        elif reg == 5:
            # Slot capabilities
            val = bool(self.attention_button_present)
            val |= bool(self.power_controller_present) << 1
            val |= bool(self.mrl_sensor_present) << 2
            val |= bool(self.attention_indicator_present) << 3
            val |= bool(self.power_indicator_present) << 4
            val |= bool(self.hot_plug_surprise) << 5
            val |= bool(self.hot_plug_capable) << 6
            val |= (self.slot_power_limit_value & 0xff) << 7
            val |= (self.slot_power_limit_scale & 0x3) << 15
            val |= bool(self.electromechanical_interlock_present) << 17
            val |= bool(self.no_command_completed_support) << 18
            val |= (self.physical_slot_number & 0x1fff) << 19
            return val
        elif reg == 6:
            # Slot control
            val = bool(self.attention_button_pressed_enable) << 0
            val |= bool(self.power_fault_detected_enable) << 1
            val |= bool(self.mrl_sensor_changed_enable) << 2
            val |= bool(self.presence_detect_changed_enable) << 3
            val |= bool(self.command_completed_interrupt_enable) << 4
            val |= bool(self.hot_plug_interrupt_enable) << 5
            val |= (self.attention_indicator_control & 0x3) << 6
            val |= (self.power_indicator_control & 0x3) << 8
            val |= bool(self.power_controller_control) << 10
            val |= bool(self.electromechanical_interlock_control) << 11
            val |= bool(self.data_link_layer_state_changed_enable) << 12
            val |= bool(self.auto_slot_power_limit_disable) << 13
            # Slot status
            val |= bool(self.attention_button_pressed) << 16
            val |= bool(self.power_fault_detected) << 17
            val |= bool(self.mrl_sensor_changed) << 18
            val |= bool(self.presence_detect_changed) << 19
            val |= bool(self.command_completed) << 20
            val |= bool(self.mrl_sensor_state) << 21
            val |= bool(self.presence_detect_state) << 22
            val |= bool(self.electromechanical_interlock_status) << 23
            val |= bool(self.data_link_layer_state_changed) << 24
            return val
        elif reg == 7:
            # Root control
            val = bool(self.system_error_on_correctable_error_enable) << 0
            val |= bool(self.system_error_on_non_fatal_error_enable) << 1
            val |= bool(self.system_error_on_fatal_error_enable) << 2
            val |= bool(self.pme_interrupt_enable) << 3
            val |= bool(self.crs_software_visibility_enable) << 4
            # Root capabilities
            val |= bool(self.crs_software_visibility) << 16
            return val
        elif reg == 8:
            # Root status
            val = self.pme_requester_id & 0xffff
            val |= bool(self.pme_status) << 16
            val |= bool(self.pme_pending) << 17
            return val
        elif reg == 9:
            # Device capabilities 2
            val = self.completion_timeout_ranges_supported & 0xf
            val |= bool(self.completion_timeout_disable_supported) << 4
            val |= bool(self.ari_forwarding_supported) << 5
            val |= bool(self.atomic_op_forwarding_supported) << 6
            val |= bool(self.atomic_op_32_bit_completer_supported) << 7
            val |= bool(self.atomic_op_64_bit_completer_supported) << 8
            val |= bool(self.cas_128_bit_completer_supported) << 9
            val |= bool(self.no_ro_enabled_pr_pr_passing) << 10
            val |= bool(self.ltr_mechanism_supported) << 11
            val |= (self.tph_completer_supported & 0x3) << 12
            val |= (self.obff_supported & 0x3) << 18
            val |= bool(self.extended_fmt_field_supported) << 20
            val |= bool(self.end_end_tlp_prefix_supported) << 21
            val |= (self.max_end_end_tlp_prefix & 0x3) << 22
            val |= (self.emergency_power_reduction_supported & 0x3) << 24
            val |= bool(self.emergency_power_reduction_initialization_required) << 26
            val |= bool(self.frs_supported) << 31
            return val
        elif reg == 10:
            # Device control 2
            val = self.completion_timeout_value & 0xf
            val |= bool(self.completion_timeout_disable) << 4
            val |= bool(self.ari_forwarding_enable) << 5
            val |= bool(self.atomic_op_requester_enable) << 6
            val |= bool(self.atomic_op_egress_blocking) << 7
            val |= bool(self.ido_request_enable) << 8
            val |= bool(self.ido_completion_enable) << 9
            val |= bool(self.ltr_mechanism_enable) << 10
            val |= bool(self.emergency_power_reduction_request) << 11
            val |= bool(self.ten_bit_tag_requester_enable) << 12
            val |= (self.obff_enable & 0x3) << 13
            val |= bool(self.end_end_tlp_prefix_blocking) << 15
            # Device status 2
            return val
        elif reg == 11:
            # Link capabilities 2
            val = (self.supported_link_speeds & 0x7f) << 1
            val |= bool(self.crosslink_supported) << 8
            val |= (self.lower_skp_os_generation_supported_speeds & 0x7f) << 9
            val |= (self.lower_skp_os_reception_supported_speeds & 0x7f) << 16
            val |= bool(self.retimer_presence_detect_supported) << 23
            val |= bool(self.two_retimers_presence_detect_supported) << 24
            val |= bool(self.drs_supported) << 31
            return val
        elif reg == 12:
            # Link control 2
            val = self.target_link_speed & 0xf
            val |= bool(self.enter_compliance) << 4
            val |= bool(self.hardware_autonomous_speed_disable) << 5
            val |= bool(self.selectable_deemphasis) << 6
            val |= (self.transmit_margin & 0x7) << 7
            val |= bool(self.enter_modified_compliance) << 10
            val |= bool(self.compliance_sos) << 11
            val |= (self.compliance_preset_deemphasis & 0xf) << 12
            # Link status 2
            val |= bool(self.current_deemphasis_level) << 16
            val |= bool(self.equalization_8gt_complete) << 17
            val |= bool(self.equalization_8gt_phase_1_successful) << 18
            val |= bool(self.equalization_8gt_phase_2_successful) << 19
            val |= bool(self.equalization_8gt_phase_3_successful) << 20
            val |= bool(self.link_equalization_8gt_request) << 21
            val |= bool(self.retimer_presence_detected) << 22
            val |= bool(self.two_retimers_presence_detected) << 23
            val |= (self.crosslink_resolution & 0x3) << 24
            val |= (self.downstream_component_presence & 0x7) << 27
            val |= bool(self.drs_message_received) << 31
            return val
        else:
            return 0

    async def _write_register(self, reg, data, mask):
        if reg == 2:
            # Device control
            if mask & 0x1:
                self.correctable_error_reporting_enable = bool(data & 1 << 0)
                self.non_fatal_error_reporting_enable = bool(data & 1 << 1)
                self.fatal_error_reporting_enable = bool(data & 1 << 2)
                self.unsupported_request_reporting_enable = bool(data & 1 << 3)
                self.enable_relaxed_ordering = bool(data & 1 << 4)
                self.max_payload_size = (data >> 5) & 0x7
            if mask & 0x2:
                self.extended_tag_field_enable = bool(data & 1 << 8)
                self.phantom_functions_enable = bool(data & 1 << 9)
                self.aux_power_pm_enable = bool(data & 1 << 10)
                self.enable_no_snoop = bool(data & 1 << 11)
                self.max_read_request_size = (data >> 12) & 0x7
                if data & 1 << 15:
                    await self.initiate_function_level_reset()
            # Device status
            if mask & 0x4:
                if data & 1 << 16:
                    self.correctable_error_detected = False
                if data & 1 << 17:
                    self.nonfatal_error_detected = False
                if data & 1 << 18:
                    self.fatal_error_detected = False
                if data & 1 << 19:
                    self.unsupported_request_detected = False
                if data & 1 << 22:
                    self.emergency_power_reduction_detected = False
        elif reg == 4:
            # Link control
            if mask & 0x1:
                self.aspm_control = data & 3
                self.read_completion_boundary = bool(data & 1 << 3)
                self.link_disable = bool(data & 1 << 4)
                if data & 1 << 5:
                    await self.initiate_retrain_link()
                self.common_clock_configuration = bool(data & 1 << 6)
                self.extended_synch = bool(data & 1 << 7)
            if mask & 0x2:
                self.enable_clock_power_management = bool(data & 1 << 8)
                self.hardware_autonomous_width_disable = bool(data & 1 << 9)
                self.link_bandwidth_management_interrupt_enable = bool(data & 1 << 10)
                self.link_autonomous_bandwidth_interrupt_enable = bool(data & 1 << 11)
                self.drs_signalling_control = (data >> 14) & 0x3
            # Link status
            if mask & 0x8:
                if data & 1 << 30:
                    self.link_bandwidth_management_status = False
                if data & 1 << 31:
                    self.link_autonomous_bandwidth_status = False
        elif reg == 6:
            # Slot control
            if mask & 0x1:
                self.attention_button_pressed_enable = bool(data & 1 << 0)
                self.power_fault_detected_enable = bool(data & 1 << 1)
                self.mrl_sensor_changed_enable = bool(data & 1 << 2)
                self.presence_detect_changed_enable = bool(data & 1 << 3)
                self.command_completed_interrupt_enable = bool(data & 1 << 4)
                self.hot_plug_interrupt_enable = bool(data & 1 << 5)
                self.attention_indicator_control = (data >> 6) & 0x3
            if mask & 0x2:
                self.power_indicator_control = (data >> 8) & 0x3
                self.power_controller_control = bool(data & 1 << 10)
                self.electromechanical_interlock_control = bool(data & 1 << 11)
                self.data_link_layer_state_changed_enable = bool(data & 1 << 12)
                self.auto_slot_power_limit_disable = bool(data & 1 << 13)
            # Slot status
            if mask & 0x4:
                if data & 1 << 16:
                    self.attention_button_pressed = False
                if data & 1 << 17:
                    self.power_fault_detected = False
                if data & 1 << 18:
                    self.mrl_sensor_changed = False
                if data & 1 << 19:
                    self.presence_detect_changed = False
                if data & 1 << 20:
                    self.command_completed = False
                if data & 1 << 24:
                    self.data_link_layer_state_changed = False
        elif reg == 7:
            # Root control
            if mask & 0x1:
                self.system_error_on_correctable_error_enable = bool(data & 1 << 0)
                self.system_error_on_non_fatal_error_enable = bool(data & 1 << 1)
                self.system_error_on_fatal_error_enable = bool(data & 1 << 2)
                self.pme_interrupt_enable = bool(data & 1 << 3)
                self.crs_software_visibility_enable = bool(data & 1 << 4)
        elif reg == 8:
            # Root status
            if mask & 0x4:
                if data & 1 << 16:
                    self.pme_status = False
        elif reg == 10:
            # Device control 2
            if mask & 0x1:
                self.completion_timeout_value = data & 0xf
                self.completion_timeout_disable = bool(data & 1 << 4)
                self.ari_forwarding_enable = bool(data & 1 << 5)
                self.atomic_op_requester_enable = bool(data & 1 << 6)
                self.atomic_op_egress_blocking = bool(data & 1 << 7)
            if mask & 0x2:
                self.ido_request_enable = bool(data & 1 << 8)
                self.ido_completion_enable = bool(data & 1 << 9)
                self.ltr_mechanism_enable = bool(data & 1 << 10)
                self.emergency_power_reduction_request = bool(data & 1 << 11)
                self.ten_bit_tag_requester_enable = bool(data & 1 << 12)
                self.obff_enable = (data >> 13) & 0x3
                self.end_end_tlp_prefix_blocking = bool(data & 1 << 15)
            # Device status 2
        elif reg == 12:
            # Link control 2
            if mask & 0x1:
                self.target_link_speed = data & 0xf
                self.enter_compliance = bool(data & 1 << 4)
                self.hardware_autonomous_speed_disable = bool(data & 1 << 5)
                self.transmit_margin = self.transmit_margin & 0x6 | (data >> 7) & 0x1
            if mask & 0x2:
                self.transmit_margin = self.transmit_margin & 0x1 | (data >> 7) & 0x6
                self.enter_modified_compliance = bool(data & 1 << 10)
                self.compliance_sos = bool(data & 1 << 11)
                self.compliance_preset_deemphasis = (data >> 12) & 0xff
            # Link status 2
            if mask & 0x4:
                self.link_equalization_8gt_request = bool(data & 1 << 21)
                if data & 1 << 31:
                    self.drs_message_received = False

    async def initiate_function_level_reset(self):
        pass

    async def initiate_retrain_link(self):
        pass


class PcieExtendedCapability(PciExtCap):
    """Secondary PCI Express extended capability"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cap_id = PciExtCapId.EXP2
        self.cap_ver = 1
        self.length = 4

        # Secondary PCIe extended capability registers
        # Link control 3 register
        self.perform_equalization = False
        self.link_equalization_request_interrupt_enable = False
        self.enable_lower_skp_os_generation = 0
        # Lane error status
        self.lane_error_status = 0
        self.downstream_port_8gt_transmitter_preset = [0]*32
        self.downstream_port_8gt_receiver_preset_hint = [0]*32
        self.upstream_port_8gt_transmitter_preset = [0]*32
        self.upstream_port_8gt_receiver_preset_hint = [0]*32

    """
    Secondary PCIe Extended Capability

    31                                                                  0
    +-------------------------+-------+---------------------------------+
    |     Next Cap Offset     |  Ver  |         PCIe Ext Cap ID         |   0   0x00
    +-------------------------+-------+---------------------------------+
    |                          Link Control 3                           |   1   0x04
    +-------------------------------------------------------------------+
    |                         Lane Error Status                         |   2   0x08
    +-------------------------------------------------------------------+
    |                     Lane Equalization Control                     |   3   0x0C
    +-------------------------------------------------------------------+
    """
    async def _read_register(self, reg):
        if reg == 1:
            # Link Control 3
            val = bool(self.perform_equalization)
            val |= bool(self.link_equalization_request_interrupt_enable) << 1
            val |= (self.enable_lower_skp_os_generation & 0x7f) << 9
            return val
        elif reg == 2:
            # Lane Error Status
            return self.lane_error_status & 0xffffffff
        elif reg < 18:
            # Lane equalization control
            val = self.downstream_port_8gt_transmitter_preset[(reg-2)*2] & 0xf
            val |= (self.downstream_port_8gt_receiver_preset_hint[(reg-2)*2] & 0x7) << 4
            val |= (self.upstream_port_8gt_transmitter_preset[(reg-2)*2] & 0xf) << 8
            val |= (self.upstream_port_8gt_receiver_preset_hint[(reg-2)*2] & 0x7) << 12
            val |= (self.downstream_port_8gt_transmitter_preset[(reg-2)*2+1] & 0xf) << 16
            val |= (self.downstream_port_8gt_receiver_preset_hint[(reg-2)*2+1] & 0x7) << 20
            val |= (self.upstream_port_8gt_transmitter_preset[(reg-2)*2+1] & 0xf) << 24
            val |= (self.upstream_port_8gt_receiver_preset_hint[(reg-2)*2+1] & 0x7) << 28
            return val
        else:
            return 0

    async def _write_register(self, reg, data, mask):
        if reg == 1:
            # Link Control 3
            if mask & 0x1:
                self.perform_equalization = bool(data & 1 << 0)
                self.link_equalization_request_interrupt_enable = bool(data & 1 << 1)
            if mask & 0x2:
                self.enable_lower_skp_os_generation = (data >> 9) & 0x7f
        elif reg == 2:
            # Lane Error Status
            self.lane_error_status = byte_mask_update(self.lane_error_status, mask, self.lane_error_status & ~data) & 0xffffffff
