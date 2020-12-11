# PCIe express simulation framework for Cocotb

[![Build Status](https://github.com/alexforencich/cocotbext-pcie/workflows/Regression%20Tests/badge.svg?branch=master)](https://github.com/alexforencich/cocotbext-pcie/actions/)
[![codecov](https://codecov.io/gh/alexforencich/cocotbext-pcie/branch/master/graph/badge.svg)](https://codecov.io/gh/alexforencich/cocotbext-pcie)
[![PyPI version](https://badge.fury.io/py/cocotbext-pcie.svg)](https://pypi.org/project/cocotbext-pcie)

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

See the `tests` directory and [verilog-pcie](https://github.com/alexforencich/verilog-pcie) for complete testbenches using these modules.

### Core PCIe simulation framework

The core PCIe simulation framework is included in `cocotbext.pcie.core`.  This framework implements an extensive event driven simulation of a complete PCI express system, including root complex, switches, devices, and functions, including support for configuration spaces, capabilities and extended capabilities, and memory and IO operations between devices.  The framework includes code to enumerate the bus, initialize configuration space registers and allocate BARs, route messages between devices, perform memory read and write operations, allocate DMA accessible memory regions in the root complex, and handle message signaled interrupts.  Any module can be connected to a cosimulated design, enabling testing of not only isolated components and host-device communication but also communication between multiple components such as device-to-device DMA and message passing.

### PCIe IP core models

#### Xilinx UltraScale and UltraScale+

Models of the Xilinx UltraScale and UltraScale Plus PCIe hard cores are included in `cocotbext.pcie.xilinx.us`.  These modules can be used in combination with the PCIe BFM to test an HDL design that targets a Xilinx UltraScale or UltraScale Plus FPGA, up to PCIe gen 3 x16 or PCIe gen 4 x8.  The models currently only support operation as a device, not as a root port.
