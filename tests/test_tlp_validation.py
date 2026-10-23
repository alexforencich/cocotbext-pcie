import pytest

from cocotbext.pcie.core.tlp import Tlp, TlpType


@pytest.mark.parametrize("fmt_type", [TlpType.IO_READ, TlpType.CFG_READ_0])
def test_check_rejects_invalid_io_and_configuration_request_lengths(fmt_type, capsys):
    tlp = Tlp()
    tlp.fmt_type = fmt_type
    tlp.length = 2

    assert tlp.check() is False
    assert "invalid length for IO or configuration request" in capsys.readouterr().out
