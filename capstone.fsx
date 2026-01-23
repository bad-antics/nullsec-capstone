// NullSec Capstone - Disassembly Engine Interface
// F# security tool demonstrating:
//   - Functional-first programming
//   - Discriminated unions
//   - Pattern matching
//   - Pipeline operators
//   - Immutable by default
//   - Type inference
//
// Author: bad-antics
// License: MIT

namespace NullSec.Capstone

open System
open System.Text
open System.Security.Cryptography

module Colors =
    let red = "\x1b[31m"
    let green = "\x1b[32m"
    let yellow = "\x1b[33m"
    let cyan = "\x1b[36m"
    let gray = "\x1b[90m"
    let reset = "\x1b[0m"
    
    let colored color text = sprintf "%s%s%s" color text reset

module Version =
    let current = "1.0.0"

/// Architecture discriminated union
type Architecture =
    | X86
    | X64
    | ARM
    | ARM64
    | MIPS
    | PowerPC
    
    member this.ToInt() =
        match this with
        | X86 -> 0
        | X64 -> 1
        | ARM -> 2
        | ARM64 -> 3
        | MIPS -> 4
        | PowerPC -> 5
    
    override this.ToString() =
        match this with
        | X86 -> "x86"
        | X64 -> "x86-64"
        | ARM -> "ARM"
        | ARM64 -> "ARM64"
        | MIPS -> "MIPS"
        | PowerPC -> "PowerPC"

/// Instruction category
type InstructionCategory =
    | DataTransfer
    | Arithmetic
    | Logical
    | Control
    | String
    | Floating
    | System
    | Privileged
    | Unknown

/// Security finding severity
type Severity =
    | Critical
    | High
    | Medium
    | Low
    | Info
    
    member this.Color() =
        match this with
        | Critical | High -> Colors.red
        | Medium -> Colors.yellow
        | Low -> Colors.cyan
        | Info -> Colors.gray

/// Disassembled instruction
type Instruction = {
    Address: uint64
    Bytes: byte array
    Mnemonic: string
    Operands: string
    Category: InstructionCategory
    Size: int
}

/// Security finding
type Finding = {
    Severity: Severity
    Address: uint64
    Description: string
    Instruction: Instruction option
    Recommendation: string
}

/// Suspicious patterns for detection
module Patterns =
    // Dangerous x86/x64 instructions
    let dangerousInstructions = [
        ("int 0x80", "System call via interrupt")
        ("syscall", "Direct system call")
        ("sysenter", "Fast system call entry")
        ("int 0x2e", "Windows syscall interrupt")
        ("in ", "Port input operation")
        ("out ", "Port output operation")
        ("cli", "Disable interrupts")
        ("sti", "Enable interrupts")
        ("hlt", "Halt processor")
        ("lgdt", "Load GDT - ring 0")
        ("lidt", "Load IDT - ring 0")
        ("lldt", "Load LDT - ring 0")
        ("ltr", "Load task register")
        ("sgdt", "Store GDT")
        ("sidt", "Store IDT")
    ]
    
    // Shellcode indicators
    let shellcodePatterns = [
        ("\\x90\\x90\\x90\\x90", "NOP sled detected")
        ("\\xcc\\xcc\\xcc\\xcc", "INT3 breakpoints")
        ("\\xeb\\xfe", "Infinite loop (self-jump)")
        ("\\xe8\\x00\\x00\\x00\\x00", "GetPC technique")
        ("\\x64\\xa1\\x30\\x00\\x00\\x00", "PEB access via fs:[0x30]")
        ("\\x65\\x48\\x8b\\x04\\x25", "GS segment access")
    ]
    
    // ROP gadget endings
    let ropEndings = [
        "ret"
        "retf"
        "retn"
        "jmp"
        "call"
    ]

/// Instruction database (mock disassembly)
module Disassembler =
    // Opcode to mnemonic mapping (simplified)
    let opcodeTable = dict [
        (0x90uy, ("nop", 1, InstructionCategory.System))
        (0xCCuy, ("int3", 1, InstructionCategory.System))
        (0xC3uy, ("ret", 1, InstructionCategory.Control))
        (0xCBuy, ("retf", 1, InstructionCategory.Control))
        (0x50uy, ("push eax", 1, InstructionCategory.DataTransfer))
        (0x51uy, ("push ecx", 1, InstructionCategory.DataTransfer))
        (0x52uy, ("push edx", 1, InstructionCategory.DataTransfer))
        (0x53uy, ("push ebx", 1, InstructionCategory.DataTransfer))
        (0x58uy, ("pop eax", 1, InstructionCategory.DataTransfer))
        (0x59uy, ("pop ecx", 1, InstructionCategory.DataTransfer))
        (0x5Auy, ("pop edx", 1, InstructionCategory.DataTransfer))
        (0x5Buy, ("pop ebx", 1, InstructionCategory.DataTransfer))
        (0x31uy, ("xor", 2, InstructionCategory.Logical))
        (0x33uy, ("xor", 2, InstructionCategory.Logical))
        (0x89uy, ("mov", 2, InstructionCategory.DataTransfer))
        (0x8Buy, ("mov", 2, InstructionCategory.DataTransfer))
        (0xE8uy, ("call", 5, InstructionCategory.Control))
        (0xE9uy, ("jmp", 5, InstructionCategory.Control))
        (0xEBuy, ("jmp short", 2, InstructionCategory.Control))
        (0x74uy, ("jz", 2, InstructionCategory.Control))
        (0x75uy, ("jnz", 2, InstructionCategory.Control))
        (0xCDuy, ("int", 2, InstructionCategory.System))
        (0x0Fuy, ("two-byte", 2, InstructionCategory.Unknown))
        (0xFFuy, ("indirect", 2, InstructionCategory.Control))
    ]
    
    /// Disassemble single instruction
    let disassembleOne (bytes: byte array) (offset: int) (baseAddr: uint64) : Instruction option =
        if offset >= bytes.Length then None
        else
            let opcode = bytes.[offset]
            match opcodeTable.TryGetValue(opcode) with
            | true, (mnemonic, size, category) ->
                let actualSize = min size (bytes.Length - offset)
                let instrBytes = bytes.[offset..offset + actualSize - 1]
                Some {
                    Address = baseAddr + uint64 offset
                    Bytes = instrBytes
                    Mnemonic = mnemonic
                    Operands = ""
                    Category = category
                    Size = actualSize
                }
            | false, _ ->
                // Unknown opcode - treat as data
                Some {
                    Address = baseAddr + uint64 offset
                    Bytes = [| bytes.[offset] |]
                    Mnemonic = "db"
                    Operands = sprintf "0x%02x" bytes.[offset]
                    Category = InstructionCategory.Unknown
                    Size = 1
                }
    
    /// Disassemble byte sequence
    let disassemble (bytes: byte array) (baseAddr: uint64) : Instruction list =
        let rec loop offset acc =
            match disassembleOne bytes offset baseAddr with
            | Some instr when offset < bytes.Length ->
                loop (offset + instr.Size) (instr :: acc)
            | _ -> List.rev acc
        loop 0 []

/// Security analyzer
module Analyzer =
    /// Check for NOP sled
    let detectNopSled (instructions: Instruction list) : Finding list =
        let nopSequences = 
            instructions
            |> List.windowed 4
            |> List.filter (List.forall (fun i -> i.Mnemonic = "nop"))
            |> List.map List.head
        
        nopSequences
        |> List.map (fun i -> {
            Severity = Severity.High
            Address = i.Address
            Description = "NOP sled detected - possible shellcode"
            Instruction = Some i
            Recommendation = "Investigate surrounding code for shellcode"
        })
    
    /// Check for dangerous instructions
    let detectDangerousInstructions (instructions: Instruction list) : Finding list =
        instructions
        |> List.filter (fun i ->
            Patterns.dangerousInstructions
            |> List.exists (fun (pattern, _) ->
                i.Mnemonic.StartsWith(pattern.Split(' ').[0])
            )
        )
        |> List.map (fun i -> {
            Severity = Severity.Medium
            Address = i.Address
            Description = sprintf "Dangerous instruction: %s" i.Mnemonic
            Instruction = Some i
            Recommendation = "Review privilege level requirements"
        })
    
    /// Check for ROP gadgets
    let detectRopGadgets (instructions: Instruction list) : Finding list =
        instructions
        |> List.filter (fun i ->
            Patterns.ropEndings
            |> List.exists (fun ending -> i.Mnemonic.StartsWith(ending))
        )
        |> List.map (fun i -> {
            Severity = Severity.Low
            Address = i.Address
            Description = sprintf "Potential ROP gadget ending: %s" i.Mnemonic
            Instruction = Some i
            Recommendation = "Consider ASLR and CFI mitigations"
        })
    
    /// Full analysis
    let analyze (bytes: byte array) (arch: Architecture) : Finding list =
        let instructions = Disassembler.disassemble bytes 0x00400000UL
        
        [
            detectNopSled instructions
            detectDangerousInstructions instructions
            detectRopGadgets instructions
        ]
        |> List.concat
        |> List.sortBy (fun f -> f.Address)

/// Output formatting
module Output =
    let printBanner () =
        printfn ""
        printfn "╔══════════════════════════════════════════════════════════════════╗"
        printfn "║          NullSec Capstone - Disassembly Analysis Engine          ║"
        printfn "╚══════════════════════════════════════════════════════════════════╝"
        printfn ""
    
    let printInstruction (i: Instruction) =
        let bytesHex = i.Bytes |> Array.map (sprintf "%02x") |> String.concat " "
        printfn "  0x%08x:  %-20s  %s %s" 
            i.Address 
            bytesHex 
            i.Mnemonic 
            i.Operands
    
    let printFinding (f: Finding) =
        let severity = Colors.colored (f.Severity.Color()) (sprintf "[%A]" f.Severity)
        printfn ""
        printfn "  %s 0x%08x" severity f.Address
        printfn "    %s" f.Description
        match f.Instruction with
        | Some i -> printfn "    Instruction: %s %s" i.Mnemonic i.Operands
        | None -> ()
        printfn "    %s" (Colors.colored Colors.gray f.Recommendation)
    
    let printStats (instructions: Instruction list) (findings: Finding list) =
        printfn ""
        printfn "%s" (Colors.colored Colors.gray "═══════════════════════════════════════════")
        printfn ""
        printfn "  Statistics:"
        printfn "    Instructions:  %d" instructions.Length
        printfn "    Findings:      %d" findings.Length
        printfn "    Critical:      %d" (findings |> List.filter (fun f -> f.Severity = Critical) |> List.length)
        printfn "    High:          %d" (findings |> List.filter (fun f -> f.Severity = High) |> List.length)
        printfn "    Medium:        %d" (findings |> List.filter (fun f -> f.Severity = Medium) |> List.length)
        printfn "    Low:           %d" (findings |> List.filter (fun f -> f.Severity = Low) |> List.length)

/// Demo mode
module Demo =
    let run () =
        printfn "%s" (Colors.colored Colors.yellow "[Demo Mode]")
        printfn ""
        
        // Sample shellcode-like bytes
        let sampleBytes = [|
            0x90uy; 0x90uy; 0x90uy; 0x90uy  // NOP sled
            0x90uy; 0x90uy; 0x90uy; 0x90uy
            0x31uy; 0xC0uy                   // xor eax, eax
            0x50uy                           // push eax
            0x89uy; 0xE1uy                   // mov ecx, esp
            0xCDuy; 0x80uy                   // int 0x80
            0xC3uy                           // ret
            0xCCuy; 0xCCuy                   // int3 padding
        |]
        
        printfn "%s" (Colors.colored Colors.cyan "Analyzing sample bytes...")
        printfn ""
        
        // Disassemble
        let instructions = Disassembler.disassemble sampleBytes 0x00400000UL
        
        printfn "Disassembly:"
        printfn ""
        instructions |> List.iter Output.printInstruction
        
        // Analyze
        printfn ""
        printfn "Security Findings:"
        
        let findings = Analyzer.analyze sampleBytes Architecture.X86
        findings |> List.iter Output.printFinding
        
        Output.printStats instructions findings

/// Main entry point
module Main =
    [<EntryPoint>]
    let main args =
        Output.printBanner()
        
        match args |> Array.toList with
        | [] | ["-h"] | ["--help"] ->
            printfn "USAGE:"
            printfn "    capstone [OPTIONS] <file>"
            printfn ""
            printfn "OPTIONS:"
            printfn "    -h, --help     Show this help"
            printfn "    -a, --arch     Architecture (x86, x64, arm, arm64)"
            printfn "    -b, --base     Base address (hex)"
            printfn "    -j, --json     JSON output"
            printfn ""
            Demo.run()
            0
        | _ ->
            printfn "File analysis not implemented in demo"
            0
