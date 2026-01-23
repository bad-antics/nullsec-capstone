# NullSec Capstone

**Disassembly Analysis Engine** built with **F#** - A functional approach to binary analysis and security research.

[![Language](https://img.shields.io/badge/F%23-378BBA?style=flat-square&logo=fsharp&logoColor=white)](https://fsharp.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=flat-square)]()
[![NullSec](https://img.shields.io/badge/NullSec-Tool-red?style=flat-square)](https://bad-antics.github.io)

## Overview

NullSec Capstone is a disassembly and binary analysis engine written in F#, designed for security research and malware analysis. Leverages functional programming patterns for reliable, composable analysis pipelines.

## Features

- **Multi-Architecture** - x86, x64, ARM, ARM64, MIPS, PowerPC
- **Pattern Detection** - Shellcode, ROP gadgets, dangerous instructions
- **Functional Pipeline** - Composable analysis stages
- **NOP Sled Detection** - Identify potential shellcode
- **ROP Gadget Finding** - Locate code reuse targets
- **Type Safety** - Discriminated unions for robust modeling
- **Immutable Analysis** - Thread-safe, reproducible results

## Detection Capabilities

| Pattern | Description | Severity |
|---------|-------------|----------|
| NOP Sled | Sequential NOP instructions | High |
| Syscall | Direct system call instructions | Medium |
| INT 0x80 | Linux syscall interrupt | Medium |
| Privileged | Ring 0 instructions | High |
| ROP Gadget | Code reuse primitives | Low |
| GetPC | Position-independent code | Medium |

## Installation

```bash
# Install .NET SDK
# https://dotnet.microsoft.com/download

# Clone and run
git clone https://github.com/bad-antics/nullsec-capstone
cd nullsec-capstone

# Run as script
dotnet fsi capstone.fsx

# Or compile
dotnet new console -lang F# -o build
cp capstone.fsx build/Program.fs
cd build && dotnet run
```

## Usage

### Basic Usage

```bash
# Run demo mode
dotnet fsi capstone.fsx

# Analyze binary
dotnet fsi capstone.fsx binary.exe

# Specify architecture
dotnet fsi capstone.fsx -a x64 shellcode.bin

# Custom base address
dotnet fsi capstone.fsx -b 0x10000000 dump.bin
```

### Options

```
-h, --help     Show help message
-a, --arch     Target architecture (x86, x64, arm, arm64)
-b, --base     Base address in hex (default: 0x00400000)
-j, --json     Output results as JSON
```

### Pipeline Example

```fsharp
// Functional analysis pipeline
bytes
|> Disassembler.disassemble 0x00400000UL
|> Analyzer.detectNopSled
|> List.append (Analyzer.detectRopGadgets instructions)
|> List.sortBy (fun f -> f.Address)
```

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                    Analysis Pipeline                       │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  bytes: byte[]                                            │
│       │                                                   │
│       ▼                                                   │
│  ┌─────────────────────────────────┐                     │
│  │        Disassembler             │                     │
│  │   • Opcode decoding             │                     │
│  │   • Instruction building        │                     │
│  └──────────────┬──────────────────┘                     │
│                 │                                         │
│                 ▼                                         │
│  Instruction list                                         │
│       │                                                   │
│       ├──────────────┬──────────────┐                    │
│       ▼              ▼              ▼                    │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐                │
│  │NOP Sled │   │Dangerous│   │   ROP   │                │
│  │Detector │   │  Instr  │   │ Gadgets │                │
│  └────┬────┘   └────┬────┘   └────┬────┘                │
│       │             │             │                      │
│       └─────────────┼─────────────┘                      │
│                     ▼                                     │
│             Finding list                                  │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

## Type System

### Discriminated Unions

```fsharp
type Architecture =
    | X86 | X64 | ARM | ARM64 | MIPS | PowerPC

type Severity =
    | Critical | High | Medium | Low | Info

type InstructionCategory =
    | DataTransfer | Arithmetic | Logical
    | Control | String | Floating | System
```

### Record Types

```fsharp
type Instruction = {
    Address: uint64
    Bytes: byte array
    Mnemonic: string
    Operands: string
    Category: InstructionCategory
    Size: int
}

type Finding = {
    Severity: Severity
    Address: uint64
    Description: string
    Instruction: Instruction option
    Recommendation: string
}
```

## Output Example

```
Disassembly:

  0x00400000:  90                    nop
  0x00400001:  90                    nop
  0x00400002:  90                    nop
  0x00400003:  90                    nop
  0x00400004:  31 c0                 xor eax, eax
  0x00400006:  50                    push eax
  0x00400007:  cd 80                 int 0x80
  0x00400009:  c3                    ret

Security Findings:

  [High] 0x00400000
    NOP sled detected - possible shellcode
    Instruction: nop
    Investigate surrounding code for shellcode

  [Medium] 0x00400007
    Dangerous instruction: int
    Instruction: int 0x80
    Review privilege level requirements
```

## Why F#?

- **Discriminated Unions** - Perfect for modeling instruction sets
- **Pattern Matching** - Expressive opcode handling
- **Immutability** - Safe concurrent analysis
- **Pipeline Operators** - Clean data flow
- **Type Inference** - Less boilerplate, more safety
- **.NET Ecosystem** - Rich library support

## Dangerous Patterns

```fsharp
let dangerousInstructions = [
    ("int 0x80", "System call via interrupt")
    ("syscall", "Direct system call")
    ("sysenter", "Fast system call entry")
    ("cli", "Disable interrupts")
    ("sti", "Enable interrupts")
    ("hlt", "Halt processor")
    ("lgdt", "Load GDT - ring 0")
    ("lidt", "Load IDT - ring 0")
]
```

## Resources

- [F# Language](https://fsharp.org/)
- [Capstone Engine](http://www.capstone-engine.org/)
- [x86 Instruction Reference](https://www.felixcloutier.com/x86/)
- [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)

## NullSec Toolkit

Part of the **NullSec** security toolkit collection:
- 🌐 [Portal](https://bad-antics.github.io)
- 💬 [Discord](https://discord.gg/killers)
- 📦 [GitHub](https://github.com/bad-antics)

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**NullSec** - *Functional disassembly for security analysis*
