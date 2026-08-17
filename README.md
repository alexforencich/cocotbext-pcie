# PCI express simulation framework for Cocotb

[![Regression Tests](https://github.com/alexforencich/cocotbext-pcie/actions/workflows/regression-tests.yml/badge.svg)](https://github.com/alexforencich/cocotbext-pcie/actions/workflows/regression-tests.yml)
[![codecov](https://codecov.io/gh/alexforencich/cocotbext-pcie/branch/master/graph/badge.svg)](https://codecov.io/gh/alexforencich/cocotbext-pcie)
[![PyPI version](https://badge.fury.io/py/cocotbext-pcie.svg)](https://pypi.org/project/cocotbext-pcie)
[![Downloads](https://pepy.tech/badge/cocotbext-pcie)](https://pepy.tech/project/cocotbext-pcie)

GitHub repository: https://github.com/alexforencich/cocotbext-pcie

## Introduction

PCI express simulation framework for [cocotb](https://github.com/cocotb/cocotb).

## Installation

Installation from pip (release version, stable):

    $ pip install cocotbext-pcie

Installation from git (latest development version, potentially unstable):

    $ pip install https://github.com/alexforencich/cocotbext-pcie/archive/master.zip

Installation for active development:

    $ git clone https://github.com/alexforencich/cocotbext-pcie
    $ pip install -e cocotbext-pcie

## Documentation and usage examples

See the `tests` directory, [taxi](https://github.com/fpganinja/taxi), [verilog-pcie](https://github.com/alexforencich/verilog-pcie), and [corundum](https://github.com/corundum/corundum) for complete testbenches using these modules.

### Core PCIe simulation framework

The core PCIe simulation framework is included in `cocotbext.pcie.core`.  This framework implements an extensive event driven simulation of a complete PCI express system, including root complex, switches, devices, and functions, including support for configuration spaces, capabilities and extended capabilities, and memory and IO operations between devices.  The framework includes code to enumerate the bus, initialize configuration space registers and allocate BARs, route messages between devices, perform memory read and write operations, allocate DMA accessible memory regions in the root complex, and handle message signaled interrupts.  Any module can be connected to a cosimulated design, enabling testing of not only isolated components and host-device communication but also communication between multiple components such as device-to-device DMA and message passing.

### PCIe IP core models

#### Xilinx UltraScale and UltraScale+

Models of the Xilinx UltraScale and UltraScale+ PCIe hard cores are included in `cocotbext.pcie.xilinx.us`.  These modules can be used in combination with the PCIe BFM to test an HDL design that targets Xilinx UltraScale, UltraScale+, or Virtex 7 series FPGAs, up to PCIe gen 3 x16 or PCIe gen 4 x8.  The models currently only support operation as a device, not as a root port.

#### Intel Stratix V

Models of the Intel Stratix V Hard IP for PCI Express (Avalon-ST interface) are included in `cocotbext.pcie.intel.s5`.  These modules can be used in combination with the PCIe BFM to test an HDL design that targets Intel Stratix V GX/GT/GS or Arria V GZ series FPGAs, up to PCIe gen 3 x8.  The models currently only support operation as a device, not as a root port, and only a single physical function is supported (multi-function operation requires the SR-IOV variant of the IP, which multiplexes its configuration space differently).

Only the 128-bit and 256-bit Avalon-ST widths are implemented; the 64-bit width, which uses dword-granular byte enables instead of the qword `empty` field, is not supported.  Because the Application Layer clock frequency is a function of link width, link rate, and interface width, the set of valid configurations is correspondingly restricted &mdash; for example gen1 is only available as x8 at 125 MHz on the 128-bit interface, since every narrower gen1 configuration uses the 64-bit interface.

TLP headers and payload are packed on the wire with qword alignment, matching the aligned-address timing diagrams in the user guide; the additional dword-shifted layout used for non-qword-aligned addresses is not modeled.  The `tl_cfg_ctl` multiplex reproduces the full 16-entry register layout and holds each index for eight `pld_clk` cycles, so the strobe-based sampling logic recommended by the user guide works against the model.  `rx_st_mask` is honored for non-posted requests, but the RX path is modeled as a single queue, so a stalled non-posted request also blocks TLPs queued behind it.

#### Intel Stratix 10 H-Tile/L-Tile

Models of the Intel Stratix 10 H-Tile/L-Tile PCIe hard cores are included in `cocotbext.pcie.intel.s10`.  These modules can be used in combination with the PCIe BFM to test an HDL design that targets Intel Stratix 10 GX, SX, TX, and MX series FPGAs that contain H-Tiles or L-Tiles, up to PCIe gen 3 x16.  The models currently only support operation as a device, not as a root port.

#### Intel P-Tile

Models of the Intel P-Tile PCIe hard cores are included in `cocotbext.pcie.intel.ptile`.  These modules can be used in combination with the PCIe BFM to test an HDL design that targets Intel Stratix 10 DX or Agilex F series FPGAs that contain P-Tiles, up to PCIe gen 4 x16.  The models currently only support operation as a device, not as a root port.
