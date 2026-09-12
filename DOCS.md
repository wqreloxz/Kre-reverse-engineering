# KRE v4 — Complete Reference & Use-Case Guide

---

## Quick Start

```bash
pip install pefile capstone PyQt6
pip install unicorn yara-python         # optional — emulator + YARA
pip install ghidra-bridge               # optional — Ghidra live

python kre.py                           # launch GUI
python kre.py target.exe                # load PE on start
python kre_extensions.py target.elf     # standalone ELF/Mach-O info
```

Drag & drop any binary onto the window. KRE auto-detects PE, ELF, and Mach-O.

---

## What's New in v4

| Feature | Module |
|---------|--------|
| ELF analyzer — sections, segments, symbols | `kre_extensions.py` → `ELFAnalyzer` |
| Mach-O analyzer — load commands, sections | `kre_extensions.py` → `MachOAnalyzer` |
| Universal file loader — auto-detect format | `kre_extensions.py` → `UniversalLoader` |
| ARM / ARM64 / Thumb disassembly | `kre_extensions.py` → `ARMDisassembler` |
| VirusTotal API client | `kre_extensions.py` → `VirusTotalClient` |
| Hardware breakpoints (Dr0–Dr3) | `kre_extensions.py` → `HWBreakpointManager` |
| Anti-anti-debug patches | `kre_extensions.py` → `AntiAntiDebug` |
| CPU emulator (unicorn) | `kre_extensions.py` → `MiniEmulator` |
| Import reconstruction | `kre_extensions.py` → `ImportReconstructor` |
| Markdown report generator | `kre_extensions.py` → `MarkdownReporter` |
| YARA rules database | `kre_extensions.py` → `YaraRulesDB` |

---

## Use-Case Scenarios

### 1. "I have a suspicious .exe — where do I start?"

1. **Open PE** (Ctrl+O) → **Overview** panel loads automatically
2. Check the **Quick Analysis** box — packed? suspicious APIs? compiler?
3. Jump to **Analysis** for the full threat breakdown
4. Check **Network** for embedded URLs/IPs/domains
5. Check **Strings** for readable artifacts (credentials, paths, C2 domains)
6. Copy the SHA256 from **Overview** → paste into **VirusTotal** panel
7. Export a **Markdown Report** with all findings in one click

---

### 2. "How do I find shellcode in a PE?"

```
Sections panel → sort by Entropy → look for entropy > 7.2 (highlighted red)
```

High entropy sections = likely packed/encrypted. Steps:

1. **Sections** panel — double-click the high-entropy section → Hex Editor jumps there
2. **Hex Editor** — look for recognizable shellcode patterns: `\xFC\xE8` (meterpreter), `\x60\xE8\x00\x00\x00\x00` (pusha + call 0), `\x31\xC0\x50\x68` (classic x86)
3. Copy the bytes → **Emulator** panel → paste as hex → Run → trace execution
4. **Pattern Scan** panel → search `FC E8 ?? ?? ?? ?? 60` — finds Meterpreter-style stubs
5. **Code Cave Finder** — locate regions large enough to hold injected shellcode

Plugin shortcut:
```python
# Run the shellcode_finder plugin to automate this
```

---

### 3. "The binary is packed. How do I analyze it?"

1. **Analysis** panel → check packer name (UPX, Themida, ASPack...)
2. If UPX: run `upx -d target.exe` externally, reload in KRE
3. For unknown packers:
   - **Code Cave Finder** → find the OEP (original entry point) region
   - **Debugger** → Launch binary → add breakpoint at EP (`Entry Point` button in Disasm)
   - Run → wait for OEP to be reached after unpacking
   - **Debugger → Memory Viewer** → dump decrypted code from process memory
   - **Import Reconstruction** panel → find the rebuilt IAT calls
4. Check **Overlay** panel — many packers store the original binary there

---

### 4. "How do I debug a binary that checks for a debugger?"

1. **Debugger** panel → Launch the binary
2. Once attached, immediately apply **anti-anti-debug patches**:
   ```
   Debugger panel → Anti-Anti-Debug section → Apply All Patches
   ```
   This patches `IsDebuggerPresent` and `CheckRemoteDebuggerPresent` in-process to always return 0.
3. For `NtQueryInformationProcess` (ProcessDebugPort) bypass:
   - Add a **Hardware Breakpoint** at the NtQueryInformationProcess address
   - Type: Execute → when hit, manually patch the return value in the Registers panel
4. Set breakpoints at suspicious anti-debug API imports:
   ```
   Analysis panel → Anti-Debug APIs → note addresses
   Debugger → Add BP at each address
   ```

---

### 5. "I need to analyze an IoT firmware (ELF / ARM binary)"

```bash
python kre_extensions.py firmware.elf   # standalone mode
```

Or in the GUI — drag the .elf file onto the window:

1. **ELF Panel** auto-appears showing header, sections, segments
2. **Disassembler** auto-detects ARM32/ARM64/Thumb from `e_machine`
3. **Strings** works on any format — search for config strings, IP addresses
4. **Network** panel extracts embedded URLs and IPs from raw bytes
5. **FLIRT Scan** — load ARM-specific signatures for common libc/uClibc functions
6. **YARA DB** — load IoT malware YARA rules and scan

ARM disasm modes available:

```python
from kre_extensions import ARMDisassembler
results = ARMDisassembler.disasm(data, base_addr=0x8000, mode="ARM64")
results = ARMDisassembler.disasm(data, base_addr=0x8000, mode="ARM32")
results = ARMDisassembler.disasm(data, base_addr=0x8000, mode="Thumb")
```

---

### 6. "How do I run shellcode safely?"

1. **Emulator** panel → paste hex bytes of shellcode
2. Choose arch (x86 or x64) → set max instructions → Run
3. The execution trace shows every instruction address and size
4. Registers panel shows final state (EIP/RIP, ESP/RSP, etc.)
5. **Memory Viewer** button → read emulated memory regions
6. Nothing executes on your host — unicorn is fully sandboxed

Example — test a simple NOP sled + return:
```
90 90 90 90 31 C0 C3
```
Expected trace: 5 instructions (4 NOPs + XOR EAX,EAX), stops at RET.

---

### 7. "How do I generate and export a write-up?"

1. Open any binary → **Report** panel
2. Optionally enter a VirusTotal API key in the VT panel first and look up the hash
3. Click **Generate Report** — auto-fills:
   - File hashes + header
   - VirusTotal detections (if looked up)
   - Sections with entropy flags
   - Suspicious + anti-debug APIs
   - Crypto constants
   - Network indicators
   - Overlay data
   - YARA rule
4. Edit the "Analyst Notes" section
5. **Export .md** → saves Markdown file

---

### 8. "How do I scan with custom YARA rules?"

1. **YARA DB** panel
2. Load rules:
   - **Load File** → pick a `.yar` / `.yara` file
   - **Load Dir** → scan entire directory recursively
   - **Add Inline Rule** → paste a rule directly
3. Click **Scan** → results show rule name, tags, source, and match offsets
4. Cross-reference offsets with **Hex Editor** (use Go To offset)

Example inline rule to detect Meterpreter:
```yara
rule Meterpreter_x86 {
    strings:
        $s1 = { FC E8 ?? ?? ?? ?? 60 }
        $s2 = "ReflectiveLoader"
    condition:
        any of them
}
```

---

### 9. "How do I compare a clean and patched version of a binary?"

1. Open the original → **PE Diff** panel
2. Browse to the patched version → **Run Diff**
3. Three tabs:
   - **Sections** — shows which sections changed size or entropy
   - **Imports** — which functions were added or removed
   - **Byte Regions** — exact file offset ranges where bytes differ
4. Take note of modified offset → jump to **Hex Editor** → inspect the change

---

### 10. "How do I find if a binary contacts C2 infrastructure?"

1. **Network** panel → check all four tabs (URLs, IPs, Emails, Domains)
2. **Strings** panel → filter for `.onion`, `dyndns`, `no-ip`, port numbers like `:4444`
3. **Global Search** → search for `http`, `ftp`, `ws://`, `tcp://`
4. **VirusTotal** panel → look up the hash — VT behavior report often includes contacted IPs
5. **Analysis** panel → check for suspicious networking imports:
   ```
   InternetOpenUrl, HttpOpenRequest, WSAConnect, connect, getaddrinfo
   ```

---

## PEAnalyzer — Full Method Reference

### Hashing
| Method | Returns | Notes |
|--------|---------|-------|
| `hashes()` | `List[Tuple[str,str]]` | MD5, SHA1, SHA256, Size, ImpHash |
| `imphash()` | `str` | MD5 of normalised import list |

### Structure
| Method | Returns | Notes |
|--------|---------|-------|
| `header_info()` | `List[Tuple[str,str]]` | Full PE header fields |
| `verify_checksum()` | `Tuple[bool,int,int]` | (valid, stored, calculated) |
| `recalculate_checksum()` | `int` | Patches raw bytes at nt+88 |
| `rich_header()` | `List[Dict]` | MSVC compiler fingerprint |
| `sections()` | `List[Dict]` | All sections with entropy |
| `imports()` | `Dict[str,List[str]]` | DLL → function list |
| `exports()` | `List[Dict]` | Exported symbols |
| `relocations()` | `List[Dict]` | Base relocation entries |
| `tls()` | `List[Tuple[str,str]]` | TLS directory |
| `resources()` | `List[Dict]` | Icons, manifests, etc. |
| `debug_info()` | `List[Dict]` | PDB path extraction |

### Analysis
| Method | Returns | Notes |
|--------|---------|-------|
| `entropy(data)` | `float` | Shannon entropy 0–8 |
| `overlay()` | `Dict` | Data after last section |
| `find_code_caves(n,b)` | `List[Dict]` | Injectable null regions |
| `detect_crypto()` | `List[Dict]` | AES,MD5,SHA,CRC32,Salsa,TEA... |
| `strings(min_len)` | `List[Dict]` | ASCII + UTF-16 |
| `network_indicators()` | `Dict` | URLs, IPs, Emails, Domains |
| `detect_packer()` | `Dict` | Packed bool + packer name + indicators |
| `detect_compiler()` | `List[str]` | MSVC/GCC/Delphi/Go/Rust/.NET... |
| `detect_antidebug()` | `List[str]` | Anti-debug API imports |
| `suspicious_imports()` | `List[str]` | Malware-associated API imports |

### Code
| Method | Returns | Notes |
|--------|---------|-------|
| `disassemble(off,sz)` | `List[Dict]` | x86/x64 via Capstone |
| `ep_offset()` | `Optional[int]` | File offset of entry point |
| `build_cfg(off,sz)` | `List[Dict]` | Basic block CFG |
| `find_function_prologues()` | `List[Dict]` | Heuristic function scanner |

### Patching
| Method | Notes |
|--------|-------|
| `patch_byte(off,new)` | Patch + record in history |
| `undo()` | Undo last patch |
| `redo()` | Redo |
| `undo_all()` | Revert all |
| `save(path)` | Write to disk |
| `inject_section(name,data,chars)` | Add raw section |

### Export
| Method | Returns |
|--------|---------|
| `yara_rule()` | Auto-generated YARA |
| `file_map()` | Visual file regions |

---

## ELFAnalyzer — Method Reference

```python
from kre_extensions import ELFAnalyzer
az = ELFAnalyzer("target.elf")
```

| Method | Returns | Notes |
|--------|---------|-------|
| `hashes()` | `List[Tuple[str,str]]` | MD5, SHA1, SHA256, Size |
| `header_info()` | `List[Tuple[str,str]]` | Class, endian, arch, entry point, section/segment count |
| `sections()` | `List[Dict]` | Name, Type, Address, Offset, Size, Entropy |
| `segments()` | `List[Dict]` | Type, VAddr, FileOffset, Flags (RWX) |
| `strings(min_len)` | `List[Dict]` | ASCII strings |
| `disassemble(off,sz)` | `List[Dict]` | Auto-selects arch (x86/x64/ARM/ARM64/MIPS) |
| `entropy(data)` | `float` | Shannon entropy |
| `file_map()` | `List[Dict]` | Visual region map |
| `ep_offset()` | `Optional[int]` | File offset of entry point |

---

## MachOAnalyzer — Method Reference

```python
from kre_extensions import MachOAnalyzer
az = MachOAnalyzer("target.dylib")
```

| Method | Returns | Notes |
|--------|---------|-------|
| `hashes()` | `List[Tuple[str,str]]` | MD5, SHA1, SHA256, Size |
| `header_info()` | `List[Tuple[str,str]]` | Bits, endian, CPU type, file type, load commands |
| `load_commands()` | `List[Dict]` | All LC_* commands |
| `sections()` | `List[Dict]` | segment,section Name, Address, Offset, Size, Entropy |
| `strings(min_len)` | `List[Dict]` | ASCII strings |
| `disassemble(off,sz)` | `List[Dict]` | Auto-selects arch from cpu_type |
| `entropy(data)` | `float` | Shannon entropy |
| `file_map()` | `List[Dict]` | Visual region map |

---

## UniversalLoader

```python
from kre_extensions import UniversalLoader

fmt = UniversalLoader.detect("target")    # "PE" | "ELF" | "Mach-O" | ...
az, fmt = UniversalLoader.load("target")  # returns appropriate analyzer
```

Detected formats: `PE`, `ELF`, `Mach-O`, `Mach-O (FAT)`, `ZIP/APK/JAR`, `Java Class`, `Unknown`

---

## ARMDisassembler

```python
from kre_extensions import ARMDisassembler

# Disassemble ARM32 code
result = ARMDisassembler.disasm(code_bytes, base_addr=0x8000, mode="ARM32")

# Thumb mode
result = ARMDisassembler.disasm(code_bytes, base_addr=0x8000, mode="Thumb")

# AArch64 / ARM64
result = ARMDisassembler.disasm(code_bytes, base_addr=0x400000, mode="ARM64")

# Each result: {"Address","Bytes","Mnemonic","Operands"}
```

---

## VirusTotalClient

```python
from kre_extensions import VirusTotalClient

vt = VirusTotalClient(api_key="YOUR_64_CHAR_KEY")

# Lookup by SHA256
result = vt.summary("aabbcc...dd")
# Returns:
# {
#   "sha256": "...",
#   "name": "sample.exe",
#   "type": "Win32 EXE",
#   "malicious": 42,
#   "suspicious": 3,
#   "undetected": 27,
#   "total": 72,
#   "verdict": "MALICIOUS",
#   "family": "Emotet",
#   "tags": ["trojan", "downloader"],
#   "first_seen": "1609459200",
#   "detections": {"Engine1": "Trojan.Win32.xxx", ...}
# }
```

Free VT API: 4 requests/minute, 500/day. Get key at virustotal.com.

---

## HWBreakpointManager

```python
from kre_extensions import HWBreakpointManager
from kre import WinDebugger

dbg = WinDebugger()
dbg.launch("target.exe")

hw = HWBreakpointManager(dbg)

# Execute breakpoint at address
hw.set(0x00401234, bp_type=0, bp_len=0)   # Execute, 1 byte

# Write watchpoint — breaks when memory is written
hw.set(0x00403000, bp_type=1, bp_len=3)   # Write, 4 bytes

# Read/Write watchpoint
hw.set(0x00404000, bp_type=3, bp_len=3)   # Read/Write, 4 bytes

# List active
for bp in hw.list_all():
    print(f"Slot {bp['Slot']}: {bp['Type']} @ {bp['Address']}  ({bp['Length']})")

# Remove by slot
hw.clear(0)

# Remove all
hw.clear_all()
```

Hardware breakpoints do not modify code — they use CPU debug registers. Maximum 4 simultaneous.

`bp_type`: `0`=Execute, `1`=Write, `3`=Read/Write
`bp_len`: `0`=1 byte, `1`=2 bytes, `3`=4 bytes

---

## AntiAntiDebug

```python
from kre_extensions import AntiAntiDebug
from kre import WinDebugger

dbg = WinDebugger(); dbg.launch("target.exe")
aad = AntiAntiDebug(dbg)

# Patch IsDebuggerPresent → always returns 0
ok, msg = aad.apply("IsDebuggerPresent")

# Patch CheckRemoteDebuggerPresent
ok, msg = aad.apply("CheckRemoteDebuggerPresent")

# Apply all available patches at once
results = aad.apply_all()
for name, ok, msg in results:
    print(f"{'OK' if ok else 'FAIL'}  {name}: {msg}")
```

---

## MiniEmulator

```python
from kre_extensions import MiniEmulator

emu = MiniEmulator()

# Shellcode as bytes
shellcode = bytes.fromhex("90 90 31 C0 C3".replace(" ",""))

# Setup x86 sandbox
ok, msg = emu.setup(shellcode, arch="x86")

# Run (max 1000 instructions)
ok, msg, trace = emu.run(max_insns=1000)
for line in trace: print(line)

# Read registers after emulation
regs = emu.get_regs()
print(f"EIP = 0x{regs['EIP']:08X}")
print(f"EAX = 0x{regs['EAX']:08X}")

# Read emulated memory
data = emu.read_mem(0x400000, 64)
```

---

## ImportReconstructor

```python
from kre_extensions import ImportReconstructor

az   = PEAnalyzer("packed.exe")
recon = ImportReconstructor(az)

# Find CALL/JMP targeting addresses outside all PE sections
calls = recon.find_suspicious_calls()
for c in calls:
    print(f"{c['Instruction']} @ {c['CallSite']} → {c['Target']}  ({c['Section']})")
```

---

## MarkdownReporter

```python
from kre_extensions import MarkdownReporter

az  = PEAnalyzer("sample.exe")
vt  = VirusTotalClient("YOUR_KEY").summary("sha256_here")

# Generate full report
md = MarkdownReporter.generate(az, vt_summary=vt)

# Save
with open("report.md","w") as f: f.write(md)
```

---

## YaraRulesDB

```python
from kre_extensions import YaraRulesDB

db = YaraRulesDB()
db.load_file("rules/malware.yar")          # single file
db.load_directory("rules/")               # recursive directory
db.add_inline("custom", "rule x { ... }") # inline rule

# Fetch from URL (community rules)
ok, msg = db.fetch_url("https://raw.githubusercontent.com/.../rule.yar")

# Scan binary
az = PEAnalyzer("sample.exe")
hits = db.scan(bytes(az.raw))
for h in hits:
    print(f"MATCH  {h['Rule']}  [{h['Tags']}]  source={h['Source']}")
    for offset, ident in h["Strings"]:
        print(f"  String {ident} @ {offset}")
```

---

## Plugin API — Full Example

```python
"""
Plugin: Full Analysis Report
Demonstrates most PEAnalyzer methods in one plugin.
"""
plugin_info = {
    "name":        "Full Analysis",
    "description": "Comprehensive one-page analysis using all PEAnalyzer methods.",
    "version":     "1.0",
}

def run(analyzer):
    az = analyzer
    lines = ["=" * 60, "  FULL ANALYSIS REPORT", "=" * 60, ""]

    # Hashes
    lines.append("  File Hashes:")
    for k, v in az.hashes(): lines.append(f"    {k:<12} {v}")

    # Headers
    lines += ["", "  PE Headers:"]
    for k, v in az.header_info(): lines.append(f"    {k:<30} {v}")

    # Sections
    lines += ["", f"  Sections  ({len(az.sections())})"]
    for s in az.sections():
        flag = " <-- HIGH ENTROPY" if s["EntropyF"] > 7.2 else ""
        lines.append(f"    {s['Name']:<14} entropy={s['Entropy']}{flag}")

    # Packer
    pck = az.detect_packer()
    lines += ["", f"  Packing: {'YES — ' + (pck['packer'] or '?') if pck['packed'] else 'No'}"]
    for ind in pck["indicators"]: lines.append(f"    {ind}")

    # Compiler
    lines += ["", f"  Compiler: {', '.join(az.detect_compiler())}"]

    # Imports
    sus = az.suspicious_imports(); adb = az.detect_antidebug()
    lines += ["", f"  Suspicious imports ({len(sus)}):"]
    for api in sus: lines.append(f"    {api}")
    lines += ["", f"  Anti-debug imports ({len(adb)}):"]
    for api in adb: lines.append(f"    {api}")

    # Crypto
    cry = az.detect_crypto()
    lines += ["", f"  Crypto constants ({len(cry)}):"]
    seen = set()
    for h in cry:
        if h["Name"] not in seen:
            seen.add(h["Name"]); lines.append(f"    {h['Name']} @ {h['Offset']}")

    # Network
    net = az.network_indicators(); total = sum(len(v) for v in net.values())
    lines += ["", f"  Network indicators ({total}):"]
    for cat, items in net.items():
        if items: lines.append(f"    {cat}: {len(items)}")

    # Overlay
    ov = az.overlay()
    if ov.get("present"):
        lines += ["", f"  Overlay: {ov['size']:,} bytes @ 0x{ov['offset']:08X}  entropy={ov['entropy']:.3f}"]

    lines += ["", "=" * 60]
    return "\n".join(lines)
```

---

## Suspicious APIs Reference

```
CreateRemoteThread      VirtualAllocEx          WriteProcessMemory
ReadProcessMemory       OpenProcess             NtCreateThreadEx
RtlCreateUserThread     SetWindowsHookEx        GetAsyncKeyState
RegSetValueEx           RegCreateKeyEx          SHFileOperation
InternetOpenUrl         InternetOpen            WinExec
ShellExecute            CreateProcessAsUser     AdjustTokenPrivileges
LookupPrivilegeValue    CryptEncrypt            CryptDecrypt
HttpOpenRequest         HttpSendRequest         URLDownloadToFile
FindFirstFile           CreateFileMappingA      MapViewOfFile
QueueUserAPC            NtUnmapViewOfSection
```

## Anti-Debug APIs Reference

```
IsDebuggerPresent           CheckRemoteDebuggerPresent
NtQueryInformationProcess   OutputDebugString
GetTickCount                timeGetTime
QueryPerformanceCounter     NtSetInformationThread
FindWindow                  BlockInput
NtClose                     CsrGetProcessId
```

## Crypto Constants Detected

| Name | Identifier | Description |
|------|-----------|-------------|
| AES S-box | `63 7C 77 7B...` | AES encryption lookup |
| AES Inv S-box | `52 09 6A D5...` | AES decryption lookup |
| MD5 Init | `01234567 EFCDAB89...` | MD5 IV |
| SHA-1 Init | Same + `C3D2E1F0` | SHA-1 IV |
| SHA-256 Init | `6A09E667 BB67AE85` | SHA-256 first constants |
| CRC32 Poly | `0xEDB88320` | Reflected polynomial |
| Salsa20/ChaCha20 | `"expand 32-byte k"` | Sigma constant |
| TEA Delta | `0x9E3779B9` | TEA/XTEA/XXTEA magic |
| Blowfish | `243F6A88 85A308D3` | Pi digits (P-array) |
| DES | `0E 04 0D 01 02 0F 0B 08` | DES S-box 1 |

---

## Requirements

```
pefile>=2023.2.7        PE parsing
capstone>=5.0.1         Disassembly (PE/ELF/Mach-O + ARM/ARM64)
PyQt6>=6.4.0            GUI
unicorn>=2.0.0          CPU emulator (optional)
yara-python>=4.3.0      YARA scanning (optional)
ghidra-bridge>=0.3.0    Ghidra live bridge (optional)
```

Python 3.9+. All optional dependencies degrade gracefully if absent.

---

## Session Format (.kre)

```json
{
  "path": "/absolute/path/to/target.exe",
  "patches": {
    "4096": [144, 144],
    "65535": [0, 255]
  }
}
```

`patches`: `{ "file_offset_decimal": [original_byte, patched_byte] }`
