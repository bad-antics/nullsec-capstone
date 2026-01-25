# Disassembly Framework Guide

## Overview
Using Capstone for multi-architecture disassembly.

## Supported Architectures

### x86/x64
- Real mode
- Protected mode
- Long mode
- Instruction details

### ARM
- ARM mode
- Thumb mode
- Thumb-2
- AArch64

### MIPS
- MIPS32
- MIPS64
- microMIPS
- MIPS16e

### Other
- PowerPC
- SPARC
- SystemZ
- XCore

## API Usage

### Basic Disassembly
- Engine initialization
- Buffer disassembly
- Instruction iteration
- Memory cleanup

### Detailed Mode
- Operand access
- Register details
- Instruction groups
- Implicit registers

## Integration

### Python Bindings
- capstone module
- Cs class usage
- CsInsn details
- Error handling

### C/C++ Usage
- cs_open/cs_close
- cs_disasm
- cs_free
- Options setting

## Analysis Features
- Control flow
- Data references
- String detection
- Pattern matching

## Performance
- Batch processing
- Memory management
- Cache usage
- Diet mode

## Legal Notice
For authorized reverse engineering.
