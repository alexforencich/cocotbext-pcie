from cocotbext.pcie.xilinx.us.tlp import Tlp_us


def test_copy_preserves_request_completed():
    source = Tlp_us()
    source.request_completed = True

    copied = Tlp_us(source)

    assert copied.request_completed is True
