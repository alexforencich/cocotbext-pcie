# PCI express simulation framework for Cocotb

[![Build Status](https://github.com/alexforencich/cocotbext-pcie/workflows/Regression%20Tests/badge.svg?branch=master)](https://github.com/alexforencich/cocotbext-pcie/actions/)
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

See the `tests` directory, [verilog-pcie](https://github.com/alexforencich/verilog-pcie), and [corundum](https://github.com/corundum/corundum) for complete testbenches using these modules.

### Core PCIe simulation framework

The core PCIe simulation framework is included in `cocotbext.pcie.core`.  This framework implements an extensive event driven simulation of a complete PCI express system, including root complex, switches, devices, and functions, including support for configuration spaces, capabilities and extended capabilities, and memory and IO operations between devices.  The framework includes code to enumerate the bus, initialize configuration space registers and allocate BARs, route messages between devices, perform memory read and write operations, allocate DMA accessible memory regions in the root complex, and handle message signaled interrupts.  Any module can be connected to a cosimulated design, enabling testing of not only isolated components and host-device communication but also communication between multiple components such as device-to-device DMA and message passing.

### PCIe IP core models

#### Xilinx UltraScale and UltraScale+

Models of the Xilinx UltraScale and UltraScale+ PCIe hard cores are included in `cocotbext.pcie.xilinx.us`.  These modules can be used in combination with the PCIe BFM to test an HDL design that targets Xilinx UltraScale, UltraScale+, or Virtex 7 series FPGAs, up to PCIe gen 3 x16 or PCIe gen 4 x8.  The models currently only support operation as a device, not as a root port.

#### Intel Stratix 10 H-Tile/L-Tile

Models of the Intel Stratix 10 H-Tile/L-Tile PCIe hard cores are included in `cocotbext.pcie.intel.s10`.  These modules can be used in combination with the PCIe BFM to test an HDL design that targets Intel Stratix 10 GX, SX, TX, and MX series FPGAs that contain H-Tiles or L-Tiles, up to PCIe gen 3 x16.  The models currently only support operation as a device, not as a root port.

#### Intel P-Tile

Models of the Intel P-Tile PCIe hard cores are included in `cocotbext.pcie.intel.ptile`.  These modules can be used in combination with the PCIe BFM to test an HDL design that targets Intel Stratix 10 DX or Agilex F series FPGAs that contain P-Tiles, up to PCIe gen 4 x16.  The models currently only support operation as a device, not as a root port.
