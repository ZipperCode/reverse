# Windows PE Reverse Engineering & Analysis Guide

This reference outlines the workflow for analyzing Windows Portable Executable (PE) binaries (`.exe`, `.dll`, `.sys`, `.node`). It covers static profiling, Import Address Table (IAT) auditing, IDA Pro native integration (`read-binary`), `radare2` headless fallback, and single-session stateful debugging.

---

## 1. PE Binary Profiling & Security Mitigations

Before disassembly, profile the binary headers and compile-time security mitigations:

| Field / Mitigation | Header Field / Meaning | Reverse Engineering Impact |
| :--- | :--- | :--- |
| **Machine Type** | `IMAGE_FILE_HEADER.Machine` | `0x014c` = x86 (32-bit), `0x8664` = AMD64 (64-bit), `0xaa64` = ARM64 |
| **Subsystem** | `IMAGE_OPTIONAL_HEADER.Subsystem` | `2` = Windows GUI, `3` = Windows CUI (Console), `1` = Native Driver |
| **ASLR** | `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` | Addresses randomize at load time; RVAs/offsets are preferred over fixed VAs |
| **DEP / NX** | `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` | Data execution prevention active; shellcode execution requires ROP/alloc permissions |
| **Control Flow Guard** | `IMAGE_DLLCHARACTERISTICS_GUARD_CF` | Indirect call validation in place |
| **Authenticode** | Security Directory (`IMAGE_DIRECTORY_ENTRY_SECURITY`) | Digital signature present; modifying bytes invalidates signature |

Inspection command (radare2 / dumpbin):
```bash
r2 -qc "iI" target.exe
# Or using objdump / llvm-readobj if r2 is absent
llvm-readobj --file-headers target.exe
```

---

## 2. Primary Toolchain: reverse Native `read-binary` (IDA Pro Integration)

When IDA Pro is configured and available in `reverse`, leverage the high-performance `:selector` virtual URLs via the `read` tool:

### 1. `:overview` — Binary Summary
Retrieve compiler detection, architecture, entrypoint, and section table:
```
read path: "target.exe:overview"
```

### 2. `:imports` & `:exports` — API Surface Audit
Analyze the Import Address Table (IAT) for high-value capability indicators:
```
read path: "target.exe:imports"
read path: "target.dll:exports"
```

**Key Suspicious API Families to Note**:
- **Memory & Injection**: `VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`.
- **Anti-Analysis**: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugStringW`.
- **Cryptography**: `CryptEncrypt`, `CryptDecrypt`, `BCryptOpenAlgorithmProvider`, `BCryptDecrypt`.
- **Process & Registry**: `CreateProcessW`, `ShellExecuteW`, `RegOpenKeyExW`, `RegSetValueExW`.

### 3. `:strings` — Filtered String Extraction
Filter strings to identify endpoints, error messages, and format strings:
```
read path: "target.exe:strings"
```

### 4. `:xrefs:<symbol>` & `:decompile:<func>` — Focused Analysis
Trace callers of sensitive APIs or decompile individual functions without polluting context:
```
read path: "target.exe:xrefs:CryptDecrypt"
read path: "target.exe:decompile:sub_140001050"
```

---

## 3. Fallback Toolchain: `radare2` Headless Analysis

When IDA Pro is absent or unlicensed, use `radare2` (`r2`) for non-interactive command-line extraction:

### 1. Information & Header Extraction
```bash
# Print info (iI), sections (iS), imports (ii), and exported symbols (is)
r2 -qc "iI; iS; ii; is" target.exe
```

### 2. Function Analysis & Listing
```bash
# Analyze all functions (aaa) and list detected function names (afl)
r2 -qc "aaa; afl" target.exe | grep -iE "auth|license|crypto|verify"
```

### 3. Decompile / Disassemble Specific Function
```bash
# Disassemble target function with opcode comments and control flow (pdf)
r2 -qc "aaa; pdf @ sub.license_check_140001050" target.exe

# Or if r2ghidra is installed, emit C pseudocode
r2 -qc "aaa; pdg @ sub.license_check_140001050" target.exe
```

### 4. Cross-Reference (Xrefs) Search
```bash
# Find all code cross-references to a string or API address (axt)
r2 -qc "aaa; axt @ sym.imp.KERNEL32.dll_IsDebuggerPresent" target.exe
```

---

## 4. Managed .NET & CIL Reverse Engineering (`dotnet_inspect`)

For .NET executables (`.exe`) and libraries (`.dll`) compiled to Common Intermediate Language (CIL/MSIL), use the built-in, zero-dependency `dotnet_inspect` tool:

### 1. Metadata & Runtime Verification
```
dotnet_inspect(action: "info", path: "target.dll")
```
Profiles the CLR runtime header (`IMAGE_COR20_HEADER`), ECMA-335 metadata streams (`#~`, `#Strings`, `#US`, `#GUID`, `#Blob`), assembly name, version, culture, public key token, module MVID, and type/method counts.

### 2. Type & Method Discovery
```
dotnet_inspect(action: "types", path: "target.dll", limit: 50)
dotnet_inspect(action: "methods", path: "target.dll", type: "SecurityManager")
```
Extracts declared classes, interfaces, structs, visibility, base classes (`extends`), method signatures, and tokens.

### 3. CIL Disassembly
```
dotnet_inspect(action: "cil", path: "target.dll", method: "ValidateLicense")
dotnet_inspect(action: "cil", path: "target.dll", token: "0x06000004")
```
Disassembles method bodies into formatted CIL bytecode with decoded opcodes (`ldarg.0`, `ldc.i4.s`, `call`, `callvirt`, `ldstr`), branch targets, raw bytes, and resolved member annotations.

---

## 5. Ghidra Headless Bridge (`ghidra_inspect`)

When Ghidra is present on the machine, `ghidra_inspect` coordinates batch headless analysis and C decompilation via `analyzeHeadless`:

```
ghidra_inspect(action: "info", path: "target.exe")
ghidra_inspect(action: "analyze", path: "target.exe", timeout: 120)
ghidra_inspect(action: "decompile", path: "target.exe", symbol: "main", limit: 100)
ghidra_inspect(action: "decompile", path: "target.exe", address: "0x140001050", mode: "fold")
```
All invocations execute without arbitrary shell strings. When Ghidra is absent, the tool returns structured dependency status with catalog install commands and active fallbacks (`r2_inspect`, `ida`, `triage`).

---

## 6. Unpacking & Anti-Analysis Triage

Execute binary unpacking, opcode patching, and anti-debug analysis exclusively on designated test binaries within isolated laboratory environments or hypervisor sandboxes. Preserve original sample binaries strictly read-only, directing unpacked executables and patch artifacts to dedicated output folders (`./artifacts/`).
### 1. UPX Detection and Decompression
If sections are named `UPX0`, `UPX1`, or entrypoint sits in high-entropy block:
```bash
# Decompress packed executable
upx -d -o unpacked_target.exe target.exe
```

### 2. Common PE Anti-Debugging Mechanisms
1. **PEB Inspection**: Direct assembly access to the Process Environment Block:
   - x86: `fs:[0x30] + 0x02` (`BeingDebugged` flag).
   - x64: `gs:[0x60] + 0x02` (`BeingDebugged` flag).
   - NtGlobalFlag: `fs:[0x30] + 0x68` / `gs:[0x60] + 0xbc` (checked for value `0x70` [FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS]).
2. **API Probes**: `IsDebuggerPresent()` returns nonzero; `CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent)` sets boolean flag.
3. **Timing Checks**: `rdtsc` instruction executed before and after a block; high delta indicates single-stepping.
4. **Hardware Breakpoint Detection**: `GetThreadContext()` inspects `Dr0`–`Dr3` and `Dr7` debug registers.

To counter in static patches: NOP out anti-debug branches (`74 xx` [JZ] ➔ `90 90` [NOP NOP]) or force return 0 from wrapper functions.

---

## 5. Stateful Debugging Governance

Attach debuggers exclusively to explicitly authorized processes within isolated laboratory environments, saving memory dumps and execution traces to separate artifact paths. When dynamic verification with a debugger (DAP / x64dbg / r2 debug session) is necessary:
- **Single Stateful Controller**: Coordinate debugging processes through the main agent or a single designated runner to preserve deterministic breakpoint and process state.
- **Breakpoint Hygiene**: Place hardware or software breakpoints selectively on function boundaries and critical validation branches to maintain execution stability.
- **Reproducible Scripting**: Express dynamic memory inspection as scripted CLI operations rather than manual interactive typing whenever possible.
