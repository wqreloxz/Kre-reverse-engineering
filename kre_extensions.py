#!/usr/bin/env python3
"""
KRE v4 — Extended Analysis Module
===================================
New features in v4 (import into kre.py or run standalone):

  Format Support
  ──────────────
  • ELF (Linux/Android/IoT binaries) — sections, symbols, disassembly
  • Mach-O (macOS/iOS) — load commands, sections, symbols
  • Universal binary detector — auto-routes to correct analyzer
  • ARM / ARM64 / Thumb disassembly via Capstone

  Debugger Enhancements
  ──────────────────────
  • Hardware breakpoints (Dr0–Dr3 via x86 debug registers)
  • Memory access breakpoints (read/write watchpoints)
  • Anti-anti-debug patches (IsDebuggerPresent, NtQueryInformationProcess)

  New Analysis
  ────────────
  • VirusTotal API client — hash lookup, reputation, detection names
  • CPU Emulator — unicorn-based x86/x64 sandbox for shellcode
  • Import Reconstruction — heuristic IAT rebuild for packed binaries
  • Markdown Report Generator — write-up template with all findings
  • YARA Rules Database — load and scan against public/custom rules

  Usage
  ─────
  Place in same directory as kre.py and import:

    from kre_extensions import (
        ELFAnalyzer, MachOAnalyzer, UniversalLoader,
        VirusTotalClient, MiniEmulator, ImportReconstructor,
        MarkdownReporter, YaraRulesDB,
        ELFPanel, MachOPanel, VTPanel, EmulatorPanel,
        ImportReconPanel, ReportPanel, YaraDBPanel,
    )

  Or run standalone to test:
    python kre_extensions.py target.elf
    python kre_extensions.py target.macho
"""

import sys, os, math, struct, re, json, hashlib, urllib.request, urllib.error
from pathlib import Path
from collections import Counter
from typing import Optional, Dict, List, Tuple, Any
import platform

IS_WIN   = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

try:    import capstone;  HAS_CAP  = True
except: HAS_CAP = False
try:    import unicorn;   HAS_UNI  = True
except: HAS_UNI = False
try:    import yara;      HAS_YARA = True
except: HAS_YARA = False

# Try to import Qt — graceful fallback if not running inside kre.py
try:
    from PyQt6.QtWidgets import *
    from PyQt6.QtCore    import *
    from PyQt6.QtGui     import *
    HAS_QT = True
except ImportError:
    HAS_QT = False

# Theme — reference to kre.py C dict if loaded, else default light
try:
    from kre import C, _qss, _scaffold, _Panel, kv_table, async_run, DisasmWidget
except ImportError:
    C = dict(bg="#F5F5F7",surface="#FFFFFF",border="#D2D2D7",accent="#0071E3",
             accentH="#0077ED",text="#1D1D1F",sec="#6E6E73",red="#FF3B30",
             green="#34C759",orange="#FF9500",purple="#AF52DE",
             mono="Menlo,Consolas,monospace",sans="SF Pro Display,Helvetica Neue,Arial,sans-serif")
    _scaffold = None; _Panel = None; kv_table = None; async_run = None

# ══════════════════════════════════════════════════════════════════════════════
#  ELF ANALYZER
# ══════════════════════════════════════════════════════════════════════════════
class ELFAnalyzer:
    """ELF binary parser and analyzer (Linux, Android, IoT)."""

    MAGIC = b"\x7fELF"

    ELF_MACHINES = {
        2:"SPARC", 3:"x86", 8:"MIPS", 20:"PowerPC", 22:"S390",
        40:"ARM (32-bit)", 42:"SuperH", 50:"IA-64", 62:"x86-64",
        183:"AArch64 / ARM64", 243:"RISC-V", 247:"eBPF",
    }
    ELF_TYPES = {
        1:"Relocatable (.o)", 2:"Executable", 3:"Shared object (.so)", 4:"Core dump",
    }
    SHT = {
        0:"NULL", 1:"PROGBITS", 2:"SYMTAB", 3:"STRTAB", 4:"RELA",
        5:"HASH", 6:"DYNAMIC", 7:"NOTE", 8:"NOBITS", 9:"REL",
        10:"SHLIB", 11:"DYNSYM",
    }
    PT = {
        0:"NULL", 1:"LOAD", 2:"DYNAMIC", 3:"INTERP", 4:"NOTE",
        5:"SHLIB", 6:"PHDR", 7:"TLS",
    }

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f: self.raw = bytearray(f.read())
        if bytes(self.raw[:4]) != self.MAGIC:
            raise ValueError("Not an ELF file — bad magic bytes")
        self.bits   = 64 if self.raw[4] == 2 else 32
        self.endian = "<" if self.raw[5] == 1 else ">"
        self._parse_header()
        self._shstrtab: bytes = b""
        self._load_shstrtab()

    def _parse_header(self):
        e = self.endian
        if self.bits == 32:
            (self.e_type, self.e_machine, self.e_version,
             self.e_entry, self.e_phoff, self.e_shoff,
             self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
             self.e_shentsize, self.e_shnum, self.e_shstrndx
             ) = struct.unpack_from(f"{e}HHIIIIIHHHHHH", self.raw, 16)
        else:
            (self.e_type, self.e_machine, self.e_version,
             self.e_entry, self.e_phoff, self.e_shoff,
             self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
             self.e_shentsize, self.e_shnum, self.e_shstrndx
             ) = struct.unpack_from(f"{e}HHIQQQIHHHHHH", self.raw, 16)

    def _load_shstrtab(self):
        if not self.e_shoff or not self.e_shnum or self.e_shstrndx >= self.e_shnum:
            return
        try:
            off = self.e_shoff + self.e_shstrndx * self.e_shentsize
            if self.bits == 32:
                _, _, _, _, sh_off, sh_sz = struct.unpack_from(f"{self.endian}IIIIII", self.raw, off)
            else:
                _, _, _, _, sh_off, sh_sz = struct.unpack_from(f"{self.endian}IIQQQQIIQQ"[:14], self.raw, off)[:6]
                sh_off, sh_sz = struct.unpack_from(f"{self.endian}QQ", self.raw, off + 24)
            self._shstrtab = bytes(self.raw[sh_off:sh_off + sh_sz])
        except Exception:
            pass

    def _section_name(self, idx: int) -> str:
        if not self._shstrtab or idx >= len(self._shstrtab): return ""
        end = self._shstrtab.find(b"\x00", idx)
        if end < 0: end = len(self._shstrtab)
        return self._shstrtab[idx:end].decode("utf-8", "replace")

    # ── File hashes ──────────────────────────────────────────────────────────
    def hashes(self) -> List[Tuple[str,str]]:
        d = bytes(self.raw)
        return [("MD5",    hashlib.md5(d).hexdigest().upper()),
                ("SHA1",   hashlib.sha1(d).hexdigest().upper()),
                ("SHA256", hashlib.sha256(d).hexdigest().upper()),
                ("Size",   f"{len(d):,} bytes")]

    # ── Header info ──────────────────────────────────────────────────────────
    def header_info(self) -> List[Tuple[str,str]]:
        return [
            ("Format",       "ELF"),
            ("Class",        "64-bit" if self.bits == 64 else "32-bit"),
            ("Endianness",   "Little-endian" if self.endian == "<" else "Big-endian"),
            ("File Type",    self.ELF_TYPES.get(self.e_type, str(self.e_type))),
            ("Architecture", self.ELF_MACHINES.get(self.e_machine, f"0x{self.e_machine:04X}")),
            ("Entry Point",  f"0x{self.e_entry:016X}" if self.bits==64 else f"0x{self.e_entry:08X}"),
            ("Sections",     str(self.e_shnum)),
            ("Segments",     str(self.e_phnum)),
            ("File Size",    f"{len(self.raw):,} bytes"),
        ]

    # ── Sections ─────────────────────────────────────────────────────────────
    def sections(self) -> List[Dict]:
        if not self.e_shoff or not self.e_shnum: return []
        e = self.endian; out = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            try:
                if self.bits == 32:
                    sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, *_ = \
                        struct.unpack_from(f"{e}IIIIIIIIII", self.raw, off)
                else:
                    sh_name = struct.unpack_from(f"{e}I", self.raw, off)[0]
                    sh_type = struct.unpack_from(f"{e}I", self.raw, off+4)[0]
                    sh_flags, sh_addr, sh_off, sh_size = struct.unpack_from(f"{e}QQQQ", self.raw, off+8)
                name = self._section_name(sh_name)
                data = bytes(self.raw[sh_off:sh_off + min(sh_size, 50*1024*1024)]) if sh_size > 0 and sh_off > 0 else b""
                ent  = self.entropy(data)
                out.append({
                    "Name":      name or f"[{i}]",
                    "Type":      self.SHT.get(sh_type, str(sh_type)),
                    "Address":   f"0x{sh_addr:08X}",
                    "Offset":    f"0x{sh_off:08X}",
                    "Size":      sh_size,
                    "Entropy":   f"{ent:.3f}",
                    "EntropyF":  ent,
                })
            except Exception:
                pass
        return out

    # ── Segments (program headers) ───────────────────────────────────────────
    def segments(self) -> List[Dict]:
        if not self.e_phoff or not self.e_phnum: return []
        e = self.endian; out = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            try:
                if self.bits == 32:
                    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                        struct.unpack_from(f"{e}IIIIIIII", self.raw, off)
                else:
                    p_type, p_flags = struct.unpack_from(f"{e}II", self.raw, off)
                    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                        struct.unpack_from(f"{e}QQQQQQ", self.raw, off+8)
                out.append({
                    "Type":     self.PT.get(p_type, f"0x{p_type:08X}"),
                    "Offset":   f"0x{p_offset:08X}",
                    "VAddr":    f"0x{p_vaddr:016X}" if self.bits==64 else f"0x{p_vaddr:08X}",
                    "FileSize": p_filesz,
                    "MemSize":  p_memsz,
                    "Flags":    f"{'R' if p_flags&4 else '-'}{'W' if p_flags&2 else '-'}{'X' if p_flags&1 else '-'}",
                })
            except Exception:
                pass
        return out

    # ── Strings ──────────────────────────────────────────────────────────────
    def strings(self, min_len: int = 5) -> List[Dict]:
        data = bytes(self.raw); out = []
        for m in re.finditer(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}", data):
            out.append({"Offset": f"0x{m.start():08X}", "Type": "ASCII",
                        "String": m.group().decode("ascii", "replace")})
        return out[:6000]

    # ── Disassembly ──────────────────────────────────────────────────────────
    def disassemble(self, offset: int, size: int = 256) -> List[Dict]:
        if not HAS_CAP: return []
        ARCH_MAP = {
            3:   (capstone.CS_ARCH_X86,   capstone.CS_MODE_32),
            62:  (capstone.CS_ARCH_X86,   capstone.CS_MODE_64),
            40:  (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM),
            183: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            8:   (capstone.CS_ARCH_MIPS,  capstone.CS_MODE_MIPS32),
        }
        arch, mode = ARCH_MAP.get(self.e_machine, (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
        md = capstone.Cs(arch, mode)
        chunk = bytes(self.raw[offset:offset + size])
        return [{"Address": f"0x{i.address:08X}", "Bytes": " ".join(f"{b:02X}" for b in i.bytes),
                 "Mnemonic": i.mnemonic, "Operands": i.op_str}
                for i in md.disasm(chunk, self.e_entry)]

    # ── Entropy ──────────────────────────────────────────────────────────────
    def entropy(self, data: bytes) -> float:
        if not data: return 0.0
        c = Counter(data); t = len(data)
        return -sum((v/t)*math.log2(v/t) for v in c.values() if v > 0)

    # ── File map ─────────────────────────────────────────────────────────────
    def file_map(self) -> List[Dict]:
        COLS = ["#0071E3","#34C759","#FF9500","#FF3B30","#AF52DE",
                "#5856D6","#FF2D55","#32ADE6","#FFCC00","#30B0C7"]
        regions = [{"Name": "ELF Header", "Start": 0, "End": self.e_ehsize, "Color": "#6E6E73"}]
        for idx, sec in enumerate(self.sections()):
            try:
                off = int(sec["Offset"], 16)
                sz  = sec["Size"]
                if sz > 0 and off > 0:
                    regions.append({"Name": sec["Name"][:8], "Start": off, "End": off + sz,
                                    "Color": COLS[idx % len(COLS)]})
            except Exception:
                pass
        return sorted(regions, key=lambda r: r["Start"])

    def ep_offset(self) -> Optional[int]:
        # Find file offset corresponding to entry point VA
        e = self.endian
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            try:
                if self.bits == 32:
                    _, _, _, sh_addr, sh_off, sh_size, *_ = struct.unpack_from(f"{e}IIIIIIIIII", self.raw, off)
                else:
                    sh_addr = struct.unpack_from(f"{e}Q", self.raw, off + 12)[0]
                    sh_off  = struct.unpack_from(f"{e}Q", self.raw, off + 24)[0]
                    sh_size = struct.unpack_from(f"{e}Q", self.raw, off + 32)[0]
                if sh_addr <= self.e_entry < sh_addr + sh_size:
                    return sh_off + (self.e_entry - sh_addr)
            except Exception:
                pass
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  MACH-O ANALYZER
# ══════════════════════════════════════════════════════════════════════════════
class MachOAnalyzer:
    """Mach-O binary parser and analyzer (macOS, iOS)."""

    MH_MAGIC    = 0xFEEDFACE
    MH_MAGIC_64 = 0xFEEDFACF
    MH_CIGAM    = 0xCEFAEDFE
    MH_CIGAM_64 = 0xCFFAEDFE
    FAT_MAGIC   = 0xCAFEBABE

    CPU_TYPES = {
        7:        "x86",
        -2147483641: "x86_64",
        12:       "ARM (32-bit)",
        16777228: "ARM64 / AArch64",
        18:       "PowerPC",
        16777234: "PowerPC64",
    }
    FILE_TYPES = {
        1:"Relocatable", 2:"Executable", 3:"Fixed VM Shared",
        4:"Core Dump", 5:"Preload", 6:"Dylib", 7:"Dylinker",
        8:"Bundle", 9:"Dylib Stub", 10:"dSYM", 11:"Kext Bundle",
    }
    LC_NAMES = {
        0x01:"LC_SEGMENT",       0x19:"LC_SEGMENT_64",
        0x02:"LC_SYMTAB",        0x0B:"LC_DYSYMTAB",
        0x0C:"LC_LOAD_DYLIB",    0x0D:"LC_ID_DYLIB",
        0x0E:"LC_LOAD_DYLINKER", 0x1B:"LC_UUID",
        0x21:"LC_ENCRYPTION_INFO",0x22:"LC_DYLD_INFO",
        0x28:"LC_MAIN",          0x2C:"LC_SOURCE_VERSION",
    }

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f: self.raw = bytearray(f.read())
        magic = struct.unpack_from("<I", self.raw, 0)[0]
        if magic in (self.MH_MAGIC_64, self.MH_CIGAM_64):
            self.bits = 64
            self.endian = "<" if magic == self.MH_MAGIC_64 else ">"
        elif magic in (self.MH_MAGIC, self.MH_CIGAM):
            self.bits = 32
            self.endian = "<" if magic == self.MH_MAGIC else ">"
        else:
            raise ValueError(f"Not a Mach-O file (magic=0x{magic:08X})")
        self._parse_header()
        self._sections_cache: Optional[List[Dict]] = None

    def _parse_header(self):
        e = self.endian
        if self.bits == 64:
            (self.cpu_type, self.cpu_subtype, self.file_type,
             self.ncmds, self.sizeofcmds, self.flags, _reserved
             ) = struct.unpack_from(f"{e}IIIIIII", self.raw, 4)
            self.hdr_size = 32
        else:
            (self.cpu_type, self.cpu_subtype, self.file_type,
             self.ncmds, self.sizeofcmds, self.flags
             ) = struct.unpack_from(f"{e}IIIIII", self.raw, 4)
            self.hdr_size = 28

    # ── Hashes ───────────────────────────────────────────────────────────────
    def hashes(self) -> List[Tuple[str,str]]:
        d = bytes(self.raw)
        return [("MD5",    hashlib.md5(d).hexdigest().upper()),
                ("SHA1",   hashlib.sha1(d).hexdigest().upper()),
                ("SHA256", hashlib.sha256(d).hexdigest().upper()),
                ("Size",   f"{len(d):,} bytes")]

    # ── Header info ──────────────────────────────────────────────────────────
    def header_info(self) -> List[Tuple[str,str]]:
        return [
            ("Format",        "Mach-O"),
            ("Bits",          str(self.bits)),
            ("Endianness",    "Little-endian" if self.endian == "<" else "Big-endian"),
            ("CPU Type",      self.CPU_TYPES.get(self.cpu_type, str(self.cpu_type))),
            ("File Type",     self.FILE_TYPES.get(self.file_type, str(self.file_type))),
            ("Load Commands", str(self.ncmds)),
            ("File Size",     f"{len(self.raw):,} bytes"),
        ]

    # ── Load commands ────────────────────────────────────────────────────────
    def load_commands(self) -> List[Dict]:
        e = self.endian; offset = self.hdr_size; out = []
        for _ in range(self.ncmds):
            if offset + 8 > len(self.raw): break
            try:
                cmd, cmdsize = struct.unpack_from(f"{e}II", self.raw, offset)
                name = self.LC_NAMES.get(cmd, f"0x{cmd:08X}")
                out.append({"Command": name, "Size": cmdsize, "Offset": f"0x{offset:08X}"})
                if cmdsize < 8: break
                offset += cmdsize
            except Exception:
                break
        return out

    # ── Sections ─────────────────────────────────────────────────────────────
    def sections(self) -> List[Dict]:
        if self._sections_cache is not None:
            return self._sections_cache
        e = self.endian; offset = self.hdr_size; out = []
        LC_SEGMENT    = 0x01
        LC_SEGMENT_64 = 0x19
        for _ in range(self.ncmds):
            if offset + 8 > len(self.raw): break
            try:
                cmd, cmdsize = struct.unpack_from(f"{e}II", self.raw, offset)
                if cmd in (LC_SEGMENT, LC_SEGMENT_64):
                    seg_name = bytes(self.raw[offset+8:offset+24]).rstrip(b"\x00").decode("utf-8","replace")
                    if self.bits == 64:
                        nsects   = struct.unpack_from(f"{e}I", self.raw, offset + 64)[0]
                        sec_base = offset + 72
                        SEC_SIZE = 80
                    else:
                        nsects   = struct.unpack_from(f"{e}I", self.raw, offset + 48)[0]
                        sec_base = offset + 56
                        SEC_SIZE = 68
                    for j in range(nsects):
                        sb = sec_base + j * SEC_SIZE
                        sec_name  = bytes(self.raw[sb:sb+16]).rstrip(b"\x00").decode("utf-8","replace")
                        seg_namej = bytes(self.raw[sb+16:sb+32]).rstrip(b"\x00").decode("utf-8","replace")
                        if self.bits == 64:
                            sec_addr, sec_size = struct.unpack_from(f"{e}QQ", self.raw, sb+32)
                            sec_off = struct.unpack_from(f"{e}I", self.raw, sb+48)[0]
                        else:
                            sec_addr, sec_size, sec_off = struct.unpack_from(f"{e}III", self.raw, sb+32)
                        data = bytes(self.raw[sec_off:sec_off + min(sec_size, 50*1024*1024)]) if sec_size and sec_off else b""
                        ent  = self.entropy(data)
                        out.append({
                            "Name":     f"{seg_namej},{sec_name}",
                            "Address":  f"0x{sec_addr:016X}" if self.bits==64 else f"0x{sec_addr:08X}",
                            "Offset":   f"0x{sec_off:08X}",
                            "Size":     sec_size,
                            "Entropy":  f"{ent:.3f}",
                            "EntropyF": ent,
                        })
                if cmdsize < 8: break
                offset += cmdsize
            except Exception:
                break
        self._sections_cache = out
        return out

    # ── Strings ──────────────────────────────────────────────────────────────
    def strings(self, min_len: int = 5) -> List[Dict]:
        data = bytes(self.raw); out = []
        for m in re.finditer(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}", data):
            out.append({"Offset": f"0x{m.start():08X}", "Type": "ASCII",
                        "String": m.group().decode("ascii","replace")})
        return out[:6000]

    # ── Disassembly ──────────────────────────────────────────────────────────
    def disassemble(self, offset: int, size: int = 256) -> List[Dict]:
        if not HAS_CAP: return []
        ARCH_MAP = {
            7:           (capstone.CS_ARCH_X86,   capstone.CS_MODE_32),
            -2147483641: (capstone.CS_ARCH_X86,   capstone.CS_MODE_64),
            12:          (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM),
            16777228:    (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        }
        arch, mode = ARCH_MAP.get(self.cpu_type, (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
        md = capstone.Cs(arch, mode)
        chunk = bytes(self.raw[offset:offset + size])
        return [{"Address": f"0x{i.address:08X}", "Bytes": " ".join(f"{b:02X}" for b in i.bytes),
                 "Mnemonic": i.mnemonic, "Operands": i.op_str}
                for i in md.disasm(chunk, offset)]

    # ── Entropy ──────────────────────────────────────────────────────────────
    def entropy(self, data: bytes) -> float:
        if not data: return 0.0
        c = Counter(data); t = len(data)
        return -sum((v/t)*math.log2(v/t) for v in c.values() if v > 0)

    # ── File map ─────────────────────────────────────────────────────────────
    def file_map(self) -> List[Dict]:
        COLS = ["#0071E3","#34C759","#FF9500","#FF3B30","#AF52DE",
                "#5856D6","#FF2D55","#32ADE6","#FFCC00","#30B0C7"]
        regions = [{"Name": "Mach-O Hdr", "Start": 0, "End": self.hdr_size, "Color": "#6E6E73"}]
        for idx, sec in enumerate(self.sections()):
            try:
                off = int(sec["Offset"], 16); sz = sec["Size"]
                if sz > 0 and off > 0:
                    regions.append({"Name": sec["Name"][:8], "Start": off, "End": off + sz,
                                    "Color": COLS[idx % len(COLS)]})
            except Exception:
                pass
        return sorted(regions, key=lambda r: r["Start"])

    def ep_offset(self) -> Optional[int]:
        return None   # entry point detection via LC_MAIN — TODO


# ══════════════════════════════════════════════════════════════════════════════
#  UNIVERSAL LOADER
# ══════════════════════════════════════════════════════════════════════════════
class UniversalLoader:
    """Detect binary format and return appropriate analyzer."""

    @staticmethod
    def detect(path: str) -> str:
        with open(path, "rb") as f: hdr = f.read(8)
        if hdr[:2] == b"MZ":          return "PE"
        if hdr[:4] == b"\x7fELF":     return "ELF"
        magic = struct.unpack_from("<I", hdr)[0]
        if magic in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE): return "Mach-O"
        if magic == 0xCAFEBABE:        return "Mach-O (FAT)"
        if hdr[:4] == b"PK\x03\x04":  return "ZIP/APK/JAR"
        if hdr[:4] == b"\xCA\xFE\xBA\xBE": return "Java Class"
        return "Unknown"

    @staticmethod
    def load(path: str):
        fmt = UniversalLoader.detect(path)
        if fmt == "ELF":
            return ELFAnalyzer(path), fmt
        if fmt in ("Mach-O", "Mach-O (FAT)"):
            return MachOAnalyzer(path), fmt
        if fmt == "PE":
            try:
                from kre import PEAnalyzer
                return PEAnalyzer(path), fmt
            except ImportError:
                raise RuntimeError("PEAnalyzer not available — run from kre.py")
        raise ValueError(f"Unsupported format: {fmt}")


# ══════════════════════════════════════════════════════════════════════════════
#  ARM / ARM64 DISASSEMBLER HELPER
# ══════════════════════════════════════════════════════════════════════════════
class ARMDisassembler:
    """ARM / Thumb / ARM64 disassembly helper."""

    MODES = {
        "ARM32":  (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM)    if HAS_CAP else None,
        "Thumb":  (capstone.CS_ARCH_ARM,   capstone.CS_MODE_THUMB)  if HAS_CAP else None,
        "ARM64":  (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)    if HAS_CAP else None,
    }

    @staticmethod
    def disasm(data: bytes, base_addr: int = 0, mode: str = "ARM64") -> List[Dict]:
        if not HAS_CAP: return []
        m = ARMDisassembler.MODES.get(mode)
        if not m: return []
        md = capstone.Cs(*m)
        return [{"Address": f"0x{i.address:08X}", "Bytes": " ".join(f"{b:02X}" for b in i.bytes),
                 "Mnemonic": i.mnemonic, "Operands": i.op_str}
                for i in md.disasm(data, base_addr)]


# ══════════════════════════════════════════════════════════════════════════════
#  VIRUSTOTAL CLIENT
# ══════════════════════════════════════════════════════════════════════════════
class VirusTotalClient:
    """VirusTotal API v3 client — hash lookup and file reputation."""

    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = ""):
        self._key = api_key

    def _get(self, url: str, timeout: int = 15) -> Dict:
        if not self._key:
            return {"error": "No API key — enter your VT key in the panel"}
        req = urllib.request.Request(url, headers={"x-apikey": self._key})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404: return {"error": "File not found in VT database"}
            if e.code == 401: return {"error": "Invalid API key"}
            if e.code == 429: return {"error": "API rate limit — wait 1 minute (free key: 4 req/min)"}
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"error": str(e)}

    def lookup(self, sha256: str) -> Dict:
        return self._get(f"{self.BASE}/files/{sha256.lower()}")

    def summary(self, sha256: str) -> Dict:
        """Return a clean summary dict from a VT file lookup."""
        raw = self.lookup(sha256)
        if "error" in raw: return raw
        try:
            attrs  = raw["data"]["attributes"]
            stats  = attrs.get("last_analysis_stats", {})
            total  = sum(stats.values())
            return {
                "sha256":       sha256,
                "name":         attrs.get("meaningful_name", attrs.get("name", "—")),
                "type":         attrs.get("type_description", "—"),
                "malicious":    stats.get("malicious", 0),
                "suspicious":   stats.get("suspicious", 0),
                "undetected":   stats.get("undetected", 0),
                "total":        total,
                "verdict":      ("MALICIOUS" if stats.get("malicious", 0) > 5 else
                                 "SUSPICIOUS" if stats.get("malicious", 0) > 0 else
                                 "CLEAN"),
                "family":       attrs.get("popular_threat_name", ""),
                "tags":         attrs.get("tags", []),
                "first_seen":   str(attrs.get("first_submission_date", "")),
                "last_analysis":str(attrs.get("last_analysis_date", "")),
                "detections":   {k: v.get("result","") for k,v in
                                 attrs.get("last_analysis_results",{}).items()
                                 if v.get("category") in ("malicious","suspicious")},
            }
        except Exception as e:
            return {"error": f"Parse error: {e}"}


# ══════════════════════════════════════════════════════════════════════════════
#  HARDWARE BREAKPOINTS  (Windows x86)
# ══════════════════════════════════════════════════════════════════════════════
class HWBreakpointManager:
    """
    Manages x86 hardware breakpoints via debug registers Dr0–Dr3.

    bp_type:  0 = Execute  1 = Write  3 = Read/Write
    bp_len:   0 = 1 byte   1 = 2 bytes  3 = 4 bytes
    """

    MAX_SLOTS = 4

    def __init__(self, dbg):
        """dbg — WinDebugger instance."""
        self._dbg  = dbg
        self._slots: Dict[int, Dict] = {}   # slot → {addr, type, len}

    def set(self, addr: int, bp_type: int = 0, bp_len: int = 0) -> Tuple[bool, str]:
        """Place hardware breakpoint in next free slot."""
        if not IS_WIN:
            return False, "HW breakpoints only available on Windows"
        if not self._dbg._hthread:
            return False, "No active thread — attach or launch a process first"
        free = next((s for s in range(self.MAX_SLOTS) if s not in self._slots), None)
        if free is None:
            return False, "All 4 hardware breakpoint slots are in use"
        if self._set_dr(addr, free, bp_type, bp_len):
            self._slots[free] = {"addr": addr, "type": bp_type, "len": bp_len}
            TYPE_NAMES = {0:"Execute", 1:"Write", 3:"Read/Write"}
            return True, f"HW-BP slot {free}: {TYPE_NAMES.get(bp_type,'?')} @ 0x{addr:08X}"
        return False, "SetThreadContext failed"

    def clear(self, slot: int) -> bool:
        if slot not in self._slots: return False
        self._clear_dr(slot)
        del self._slots[slot]
        return True

    def clear_all(self):
        for slot in list(self._slots.keys()): self.clear(slot)

    def list_all(self) -> List[Dict]:
        TYPE_N = {0:"Execute", 1:"Write", 3:"Read/Write"}
        return [{"Slot": s, "Address": f"0x{info['addr']:08X}",
                 "Type": TYPE_N.get(info["type"],"?"),
                 "Length": {0:"1B",1:"2B",3:"4B"}.get(info["len"],"?")}
                for s, info in self._slots.items()]

    def _set_dr(self, addr: int, slot: int, bp_type: int, bp_len: int) -> bool:
        import ctypes
        try:
            from kre import CONTEXT_x86, _k32
            ctx = CONTEXT_x86(); ctx.ContextFlags = 0x10007
            if not _k32.GetThreadContext(self._dbg._hthread, ctypes.byref(ctx)): return False
            # Write address into Dr(slot)
            setattr(ctx, f"Dr{slot}", addr)
            # Disable globally, enable locally for this slot
            dr7 = ctx.Dr7
            dr7 &= ~(3 << (slot * 2))          # clear GE/LE pair
            dr7 |=  (1 << (slot * 2))           # set local enable
            dr7 &= ~(3 << (16 + slot * 4))      # clear condition
            dr7 |=  (bp_type << (16 + slot * 4))
            dr7 &= ~(3 << (18 + slot * 4))      # clear size
            dr7 |=  (bp_len  << (18 + slot * 4))
            ctx.Dr7 = dr7
            return bool(_k32.SetThreadContext(self._dbg._hthread, ctypes.byref(ctx)))
        except Exception:
            return False

    def _clear_dr(self, slot: int) -> bool:
        import ctypes
        try:
            from kre import CONTEXT_x86, _k32
            ctx = CONTEXT_x86(); ctx.ContextFlags = 0x10007
            if not _k32.GetThreadContext(self._dbg._hthread, ctypes.byref(ctx)): return False
            setattr(ctx, f"Dr{slot}", 0)
            ctx.Dr7 &= ~(1 << (slot * 2))       # clear local enable
            return bool(_k32.SetThreadContext(self._dbg._hthread, ctypes.byref(ctx)))
        except Exception:
            return False


# ══════════════════════════════════════════════════════════════════════════════
#  ANTI-ANTI-DEBUG PATCHES
# ══════════════════════════════════════════════════════════════════════════════
class AntiAntiDebug:
    """
    Patches common anti-debugging checks in the target process.
    All patches are byte-level — applied via WriteProcessMemory.
    """

    PATCHES = {
        "IsDebuggerPresent": {
            "module": "kernel32.dll",
            "export": "IsDebuggerPresent",
            # XOR EAX,EAX  (31 C0)  RET  (C3)
            "patch":  b"\x31\xC0\xC3",
            "desc":   "Always returns 0 (not debugging)",
        },
        "CheckRemoteDebuggerPresent": {
            "module": "kernel32.dll",
            "export": "CheckRemoteDebuggerPresent",
            # MOV [EDX], 0  XOR EAX,EAX  RET
            "patch":  b"\x83\x22\x00\x31\xC0\xC3",
            "desc":   "Always writes FALSE to pbDebuggerPresent",
        },
        "NtQueryInformationProcess_debug_flag": {
            "module": "ntdll.dll",
            "export": "NtQueryInformationProcess",
            # NOP sled — safer than full replacement
            "patch":  None,   # requires runtime logic — skip for now
            "desc":   "ProcessDebugPort / ProcessDebugFlags bypass (manual)",
        },
    }

    def __init__(self, dbg):
        self._dbg = dbg

    def apply(self, patch_name: str) -> Tuple[bool, str]:
        if not IS_WIN:
            return False, "Anti-anti-debug patches only available on Windows"
        if not self._dbg._hproc:
            return False, "No active process"
        info = self.PATCHES.get(patch_name)
        if not info:
            return False, f"Unknown patch: {patch_name}"
        if info["patch"] is None:
            return False, f"{patch_name}: requires manual implementation"
        try:
            import ctypes
            mod  = ctypes.windll.kernel32.GetModuleHandleW(info["module"])
            addr = ctypes.windll.kernel32.GetProcAddress(mod, info["export"].encode())
            if not addr:
                return False, f"Could not resolve {info['export']}"
            ok = self._dbg.write_mem(addr, info["patch"])
            if ok:
                return True, f"Patched {info['export']} @ 0x{addr:08X}  ({info['desc']})"
            return False, "WriteProcessMemory failed"
        except Exception as e:
            return False, str(e)

    def apply_all(self) -> List[Tuple[str,bool,str]]:
        results = []
        for name in self.PATCHES:
            ok, msg = self.apply(name)
            results.append((name, ok, msg))
        return results


# ══════════════════════════════════════════════════════════════════════════════
#  CPU EMULATOR  (unicorn-based)
# ══════════════════════════════════════════════════════════════════════════════
class MiniEmulator:
    """
    Lightweight x86/x64 CPU emulator for shellcode analysis.
    Requires: pip install unicorn
    """

    def __init__(self):
        self._uc   = None
        self._base = 0x400000
        self._sp   = 0x200000
        self._size = 0

    def setup(self, code: bytes, arch: str = "x86") -> Tuple[bool, str]:
        if not HAS_UNI:
            return False, "unicorn not installed — pip install unicorn"
        try:
            from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
            if arch == "x64":
                uc = Uc(UC_ARCH_X86, UC_MODE_64)
            else:
                uc = Uc(UC_ARCH_X86, UC_MODE_32)

            PAGE = 0x1000
            code_sz = max((len(code) + PAGE - 1) & ~(PAGE-1), PAGE)
            uc.mem_map(self._base, code_sz)
            uc.mem_write(self._base, code)

            stk_sz = 0x10000
            uc.mem_map(self._sp, stk_sz)

            sp_val = self._sp + stk_sz - 0x100
            if arch == "x64":
                from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RIP
                uc.reg_write(UC_X86_REG_RSP, sp_val)
                uc.reg_write(UC_X86_REG_RBP, sp_val)
                uc.reg_write(UC_X86_REG_RIP, self._base)
            else:
                from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP
                uc.reg_write(UC_X86_REG_ESP, sp_val)
                uc.reg_write(UC_X86_REG_EBP, sp_val)
                uc.reg_write(UC_X86_REG_EIP, self._base)

            self._uc   = uc
            self._size = len(code)
            self._arch = arch
            return True, f"Emulator ready — {len(code)} bytes @ 0x{self._base:08X}  arch={arch}"
        except Exception as e:
            return False, str(e)

    def run(self, max_insns: int = 500) -> Tuple[bool, str, List[str]]:
        if not self._uc:
            return False, "Not initialized — call setup() first", []
        from unicorn import UC_HOOK_CODE, UcError
        trace: List[str] = []
        def _hook(uc, addr, size, ud):
            trace.append(f"0x{addr:08X}  ({size} bytes)")
        self._uc.hook_add(UC_HOOK_CODE, _hook)
        try:
            self._uc.emu_start(self._base, self._base + self._size, count=max_insns)
            return True, f"Emulation complete — {len(trace)} instructions", trace
        except UcError as e:
            return False, f"Emulation stopped: {e}", trace

    def read_mem(self, addr: int, size: int) -> bytes:
        if not self._uc: return b""
        try: return bytes(self._uc.mem_read(addr, size))
        except: return b""

    def get_regs(self) -> Dict:
        if not self._uc: return {}
        try:
            if self._arch == "x64":
                from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RBX,
                    UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI,
                    UC_X86_REG_RBP, UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_EFLAGS)
                r = self._uc.reg_read
                return {"RAX":r(UC_X86_REG_RAX),"RBX":r(UC_X86_REG_RBX),
                        "RCX":r(UC_X86_REG_RCX),"RDX":r(UC_X86_REG_RDX),
                        "RSI":r(UC_X86_REG_RSI),"RDI":r(UC_X86_REG_RDI),
                        "RBP":r(UC_X86_REG_RBP),"RSP":r(UC_X86_REG_RSP),
                        "RIP":r(UC_X86_REG_RIP),"EFLAGS":r(UC_X86_REG_EFLAGS)}
            else:
                from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX,
                    UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI,
                    UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EFLAGS)
                r = self._uc.reg_read
                return {"EAX":r(UC_X86_REG_EAX),"EBX":r(UC_X86_REG_EBX),
                        "ECX":r(UC_X86_REG_ECX),"EDX":r(UC_X86_REG_EDX),
                        "ESI":r(UC_X86_REG_ESI),"EDI":r(UC_X86_REG_EDI),
                        "EBP":r(UC_X86_REG_EBP),"ESP":r(UC_X86_REG_ESP),
                        "EIP":r(UC_X86_REG_EIP),"EFLAGS":r(UC_X86_REG_EFLAGS)}
        except: return {}


# ══════════════════════════════════════════════════════════════════════════════
#  IMPORT RECONSTRUCTOR
# ══════════════════════════════════════════════════════════════════════════════
class ImportReconstructor:
    """
    Heuristic import table reconstruction for packed / protected PE files.
    Strategy:
    1. Scan executable sections for CALL/JMP targeting addresses outside all sections
    2. Cluster those addresses by proximity (likely same DLL)
    3. Cross-reference with known API patterns from static data
    """

    COMMON_APIS: Dict[str,List[str]] = {
        "kernel32.dll": [
            "VirtualAlloc","VirtualFree","VirtualProtect","GetProcAddress",
            "LoadLibraryA","LoadLibraryW","FreeLibrary","CreateProcessA",
            "ExitProcess","GetCurrentProcess","OpenProcess","CreateFileA",
            "ReadFile","WriteFile","CloseHandle","GetSystemDirectoryA",
        ],
        "ntdll.dll": [
            "NtAllocateVirtualMemory","NtProtectVirtualMemory",
            "NtWriteVirtualMemory","NtCreateThreadEx","LdrLoadDll",
            "RtlAllocateHeap","RtlFreeHeap","NtQueryInformationProcess",
        ],
        "user32.dll": [
            "MessageBoxA","MessageBoxW","CreateWindowExA","ShowWindow",
            "GetMessageA","DispatchMessageA","RegisterClassExA",
        ],
        "ws2_32.dll": [
            "socket","connect","send","recv","WSAStartup","closesocket",
            "bind","listen","accept","WSAConnect","getaddrinfo",
        ],
    }

    def __init__(self, az):
        self._az = az

    def find_suspicious_calls(self) -> List[Dict]:
        """Find CALL/JMP targeting addresses outside PE sections."""
        if not HAS_CAP or not self._az.pe: return []
        is64 = self._az.pe.FILE_HEADER.Machine == 0x8664
        md = capstone.Cs(capstone.CS_ARCH_X86,
                         capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
        results: List[Dict] = []
        section_ranges = [(self._az.pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress,
                           self._az.pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress + s.Misc_VirtualSize)
                          for s in self._az.pe.sections]
        for sec in self._az.pe.sections:
            if not (sec.Characteristics & 0x20000000): continue
            data = sec.get_data()
            base = self._az.pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
            sn   = sec.Name.decode("utf-8","replace").rstrip("\x00").strip()
            for ins in md.disasm(data, base):
                if ins.mnemonic not in ("call","jmp"): continue
                try:
                    target = int(ins.op_str, 16)
                    in_sec = any(lo <= target < hi for lo,hi in section_ranges)
                    if not in_sec and target > 0x10000:
                        results.append({
                            "CallSite":   f"0x{ins.address:08X}",
                            "Target":     f"0x{target:08X}",
                            "Instruction":ins.mnemonic.upper(),
                            "Section":    sn,
                        })
                except: pass
        return results[:500]

    def guess_apis(self, targets: List[str]) -> Dict[str,str]:
        """Guess API names from target clusters by comparing with IAT of similar binaries."""
        # Placeholder — real implementation would compare with known DLL export hashes
        return {t: "unknown_api" for t in targets}


# ══════════════════════════════════════════════════════════════════════════════
#  MARKDOWN REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════
class MarkdownReporter:
    """Generates a structured analysis write-up in Markdown."""

    @staticmethod
    def generate(az, vt_summary: Optional[Dict] = None) -> str:
        import datetime
        name = Path(az.path).name

        # Detect format
        fmt = "PE"
        if isinstance(az, ELFAnalyzer):   fmt = "ELF"
        elif isinstance(az, MachOAnalyzer): fmt = "Mach-O"

        lines = [
            f"# Malware Analysis Report — `{name}`",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **File** | `{name}` |",
            f"| **Format** | {fmt} |",
            f"| **Date** | {datetime.datetime.utcnow().strftime('%Y-%m-%d')} UTC |",
            f"| **Analyst** | KRE Auto-Report |",
            f"",
        ]

        # VirusTotal
        if vt_summary and "error" not in vt_summary:
            vt = vt_summary
            verdict_badge = ("🔴 MALICIOUS" if vt["verdict"]=="MALICIOUS"
                             else "🟡 SUSPICIOUS" if vt["verdict"]=="SUSPICIOUS"
                             else "🟢 CLEAN")
            lines += [
                f"## VirusTotal",
                f"",
                f"**Verdict:** {verdict_badge}  ",
                f"**Detections:** {vt['malicious']}/{vt['total']}  ",
                f"**Family:** {vt.get('family','') or '—'}  ",
                f"**First seen:** {vt.get('first_seen','—')}  ",
                f"",
            ]
            if vt.get("detections"):
                lines.append("| Engine | Detection |")
                lines.append("|--------|-----------|")
                for eng, det in list(vt["detections"].items())[:20]:
                    lines.append(f"| {eng} | `{det}` |")
                lines.append("")

        # Hashes
        lines += ["## File Hashes", "", "| Hash | Value |", "|------|-------|"]
        for k, v in az.hashes():
            lines.append(f"| **{k}** | `{v}` |")
        lines.append("")

        # Header
        lines += ["## File Header", "", "| Property | Value |", "|----------|-------|"]
        for k, v in az.header_info():
            lines.append(f"| {k} | {v} |")
        lines.append("")

        # Sections
        secs = az.sections()
        lines += ["## Sections", "", "| Name | Entropy | Size |"]
        lines.append("|------|---------|------|")
        for s in secs:
            ent  = s.get("EntropyF", 0.0)
            flag = " ⚠️" if ent > 7.2 else ""
            lines.append(f"| `{s['Name']}` | **{s['Entropy']}**{flag} | {s.get('Size', s.get('RawSize','?'))} |")
        lines.append("")

        # PE-specific
        if fmt == "PE":
            sus = az.suspicious_imports() if hasattr(az,"suspicious_imports") else []
            adb = az.detect_antidebug()   if hasattr(az,"detect_antidebug") else []
            pck = az.detect_packer()      if hasattr(az,"detect_packer") else {"packed":False}
            cry = az.detect_crypto()      if hasattr(az,"detect_crypto") else []
            net = az.network_indicators() if hasattr(az,"network_indicators") else {}

            # Verdict
            risk = len(sus)*10 + len(adb)*8 + (30 if pck.get("packed") else 0) + len(cry)*5
            verdict = "MALICIOUS" if risk>=60 else "SUSPICIOUS" if risk>=25 else "LIKELY CLEAN"
            lines += [
                f"## Static Verdict",
                f"",
                f"**Risk Score:** {min(risk,100)}/100  ",
                f"**Assessment:** `{verdict}`  ",
                f"**Packed:** {'Yes — '+str(pck.get('packer','?')) if pck.get('packed') else 'No'}  ",
                f"",
            ]

            if sus:
                lines += ["## Suspicious API Imports", ""]
                for api in sus: lines.append(f"- `{api}`")
                lines.append("")

            if adb:
                lines += ["## Anti-Debug Techniques", ""]
                for api in adb: lines.append(f"- `{api}`")
                lines.append("")

            if cry:
                lines += ["## Cryptographic Constants", ""]
                for h in cry:
                    lines.append(f"- **{h['Name']}** at `{h['Offset']}` ({h.get('Section','?')}) — {h['Desc']}")
                lines.append("")

            net_total = sum(len(v) for v in net.values())
            if net_total:
                lines += ["## Network Indicators", ""]
                for cat, items in net.items():
                    if items:
                        lines.append(f"### {cat} ({len(items)})")
                        for item in items[:20]: lines.append(f"- `{item}`")
                        if len(items) > 20: lines.append(f"- _{len(items)-20} more..._")
                lines.append("")

            ov = az.overlay() if hasattr(az,"overlay") else {}
            if ov.get("present"):
                lines += [
                    "## Overlay Data", "",
                    f"- **Offset:** `0x{ov['offset']:08X}`",
                    f"- **Size:** {ov['size']:,} bytes",
                    f"- **Entropy:** {ov['entropy']:.3f}",
                    f"- **Type:** {'ZIP' if ov.get('is_zip') else 'PE' if ov.get('is_pe') else 'ELF' if ov.get('is_elf') else 'Unknown'}",
                    "",
                ]

            if hasattr(az,"yara_rule"):
                lines += ["## YARA Rule", "", "```yara", az.yara_rule(), "```", ""]

        lines += [
            "## Analyst Notes",
            "",
            "> *TODO: Add manual findings, IOCs, MITRE ATT&CK mapping here.*",
            "",
            "---",
            "_Report generated by KRE — Kovak Reverse Engineering Studio_",
        ]

        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  YARA RULES DATABASE
# ══════════════════════════════════════════════════════════════════════════════
class YaraRulesDB:
    """
    Load, manage, and scan with YARA rules.
    Supports loading from files, directories, and inline strings.
    Requires: pip install yara-python
    """

    COMMUNITY_URLS: Dict[str,str] = {
        "ESET Malware IOC":
            "https://raw.githubusercontent.com/eset/malware-ioc/master/ransomware/lockbit/lockbit.yar",
        "Elastic Security (sample)":
            "https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Linux_Ransomware_Lockbit.yar",
    }

    def __init__(self):
        self.rules_src: List[Dict] = []   # {"name": str, "source": str}

    def add_inline(self, name: str, rule_text: str):
        self.rules_src.append({"name": name, "source": rule_text})

    def load_file(self, path: str):
        with open(path, encoding="utf-8", errors="replace") as f:
            self.rules_src.append({"name": Path(path).name, "source": f.read()})

    def load_directory(self, directory: str):
        for p in Path(directory).glob("**/*.yar"):
            try: self.load_file(str(p))
            except Exception: pass
        for p in Path(directory).glob("**/*.yara"):
            try: self.load_file(str(p))
            except Exception: pass

    def fetch_url(self, url: str, name: str = "") -> Tuple[bool,str]:
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                content = r.read().decode("utf-8","replace")
            n = name or url.split("/")[-1]
            self.rules_src.append({"name": n, "source": content})
            return True, f"Fetched {n} ({len(content):,} bytes)"
        except Exception as e:
            return False, str(e)

    def scan(self, data: bytes) -> List[Dict]:
        if not HAS_YARA:
            return [{"Rule": "ERROR", "Tags": "", "Source": "", "Strings": [],
                     "Note": "pip install yara-python"}]
        results = []
        for rs in self.rules_src:
            try:
                rules = yara.compile(source=rs["source"])
                for m in rules.match(data=data):
                    results.append({
                        "Rule":    m.rule,
                        "Tags":    ", ".join(m.tags),
                        "Source":  rs["name"],
                        "Strings": [(f"0x{s.offset:08X}", s.identifier) for s in m.strings[:5]],
                    })
            except Exception as e:
                results.append({"Rule": f"COMPILE_ERROR ({rs['name']})", "Tags": str(e),
                                 "Source": rs["name"], "Strings": []})
        return results

    def count(self) -> int:
        return len(self.rules_src)


# ══════════════════════════════════════════════════════════════════════════════
#  Qt PANELS  (only built if PyQt6 is available)
# ══════════════════════════════════════════════════════════════════════════════
if HAS_QT:

    def _kv(rows):
        """kv_table fallback if not imported from kre."""
        if kv_table: return kv_table(rows)
        t = QTableWidget(len(rows), 2)
        t.setHorizontalHeaderLabels(["Property","Value"])
        t.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        t.verticalHeader().setVisible(False); t.setColumnWidth(0, 200)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        for row,(k,v) in enumerate(rows):
            t.setRowHeight(row, 26)
            ki = QTableWidgetItem(str(k)); ki.setForeground(QColor(C["sec"]))
            t.setItem(row, 0, ki); t.setItem(row, 1, QTableWidgetItem(str(v)))
        return t

    # ── Base panel ────────────────────────────────────────────────────────────
    class _ExtPanel(QScrollArea):
        def __init__(self):
            super().__init__(); self.setWidgetResizable(True)
            self.setFrameShape(QFrame.Shape.NoFrame)
            ph = QWidget(); pl = QVBoxLayout(ph); pl.setContentsMargins(28,28,28,28)
            l = QLabel("No file loaded."); l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            pl.addWidget(l,1); self.setWidget(ph)

        def _build(self, title: str) -> Tuple[QWidget,QVBoxLayout]:
            w = QWidget()
            lay = QVBoxLayout(w); lay.setContentsMargins(28,24,28,28); lay.setSpacing(16)
            t = QLabel(title); t.setStyleSheet("font-size:22px;font-weight:700;"); lay.addWidget(t)
            return w, lay

    # ── ELF panel ─────────────────────────────────────────────────────────────
    class ELFPanel(_ExtPanel):
        def load(self, az: ELFAnalyzer):
            w, lay = self._build(f"ELF  —  {Path(az.path).name}")
            lay.addWidget(_kv(az.hashes()))

            r1 = QHBoxLayout(); r1.setSpacing(12)
            hg = QGroupBox("ELF Header"); hg.setLayout(QVBoxLayout())
            hg.layout().addWidget(_kv(az.header_info())); r1.addWidget(hg)
            lay.addLayout(r1)

            # Sections
            secs = az.sections()
            lay.addWidget(QLabel(f"Sections  ({len(secs)})"))
            tbl = QTableWidget(len(secs), 6)
            tbl.setHorizontalHeaderLabels(["Name","Type","Address","Offset","Size","Entropy"])
            tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            tbl.verticalHeader().setVisible(False)
            tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            tbl.setFont(QFont(C["mono"].split(",")[0],11))
            for row, s in enumerate(secs):
                tbl.setRowHeight(row, 22)
                for col, val in enumerate([s["Name"],s["Type"],s["Address"],s["Offset"],str(s["Size"]),s["Entropy"]]):
                    it = QTableWidgetItem(val)
                    if col == 5:
                        ent = s["EntropyF"]
                        it.setForeground(QColor(C["green"] if ent<5 else C["orange"] if ent<7 else C["red"]))
                    tbl.setItem(row, col, it)
            lay.addWidget(tbl)

            # Segments
            segs = az.segments()
            if segs:
                lay.addWidget(QLabel(f"Segments  ({len(segs)})"))
                sg = QTableWidget(len(segs), 5)
                sg.setHorizontalHeaderLabels(["Type","VAddr","FileOff","FileSize","Flags"])
                sg.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
                sg.verticalHeader().setVisible(False)
                sg.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
                sg.setFont(QFont(C["mono"].split(",")[0],11))
                for row, s in enumerate(segs):
                    sg.setRowHeight(row, 22)
                    for col, val in enumerate([s["Type"],s["VAddr"],s["Offset"],str(s["FileSize"]),s["Flags"]]):
                        sg.setItem(row, col, QTableWidgetItem(val))
                lay.addWidget(sg)

            lay.addStretch(); self.setWidget(w)

    # ── Mach-O panel ─────────────────────────────────────────────────────────
    class MachOPanel(_ExtPanel):
        def load(self, az: MachOAnalyzer):
            w, lay = self._build(f"Mach-O  —  {Path(az.path).name}")
            lay.addWidget(_kv(az.hashes()))

            r1 = QHBoxLayout(); r1.setSpacing(12)
            hg = QGroupBox("Mach-O Header"); hg.setLayout(QVBoxLayout())
            hg.layout().addWidget(_kv(az.header_info())); r1.addWidget(hg)
            lay.addLayout(r1)

            secs = az.sections(); lay.addWidget(QLabel(f"Sections  ({len(secs)})"))
            tbl = QTableWidget(len(secs), 5)
            tbl.setHorizontalHeaderLabels(["Name","Address","Offset","Size","Entropy"])
            tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            tbl.verticalHeader().setVisible(False)
            tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            tbl.setFont(QFont(C["mono"].split(",")[0],11))
            for row, s in enumerate(secs):
                tbl.setRowHeight(row, 22)
                for col, val in enumerate([s["Name"],s["Address"],s["Offset"],str(s["Size"]),s["Entropy"]]):
                    it = QTableWidgetItem(val)
                    if col == 4:
                        ent = s["EntropyF"]
                        it.setForeground(QColor(C["green"] if ent<5 else C["orange"] if ent<7 else C["red"]))
                    tbl.setItem(row, col, it)
            lay.addWidget(tbl)

            cmds = az.load_commands(); lay.addWidget(QLabel(f"Load Commands  ({len(cmds)})"))
            ct = QTableWidget(len(cmds), 3); ct.setHorizontalHeaderLabels(["Command","Size","Offset"])
            ct.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            ct.verticalHeader().setVisible(False)
            ct.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            ct.setFont(QFont(C["mono"].split(",")[0],11))
            for row, c in enumerate(cmds):
                ct.setRowHeight(row, 22)
                for col, val in enumerate([c["Command"],str(c["Size"]),c["Offset"]]):
                    ct.setItem(row, col, QTableWidgetItem(val))
            lay.addWidget(ct); lay.addStretch(); self.setWidget(w)

    # ── VirusTotal panel ──────────────────────────────────────────────────────
    class VTPanel(_ExtPanel):
        def __init__(self):
            super().__init__(); self._client = VirusTotalClient(); self._az = None
        def load(self, az):
            self._az = az; self._rebuild()
        def _rebuild(self):
            w, lay = self._build("VirusTotal Lookup")
            info = QLabel("Looks up the file's SHA256 hash against the VirusTotal database.\nRequires a free API key from virustotal.com")
            info.setWordWrap(True); info.setStyleSheet(f"color:{C['sec']};font-size:12px;"); lay.addWidget(info)
            abar = QHBoxLayout()
            self._key_e = QLineEdit(); self._key_e.setPlaceholderText("VirusTotal API key (64 hex chars)...")
            self._key_e.setEchoMode(QLineEdit.EchoMode.Password)
            self._key_e.setText(self._client._key)
            self._key_e.textChanged.connect(lambda t: setattr(self._client, "_key", t))
            abar.addWidget(QLabel("API Key:")); abar.addWidget(self._key_e, 1); lay.addLayout(abar)
            lb = QPushButton("Look Up File Hash"); lb.clicked.connect(self._lookup); lay.addWidget(lb)
            self._result = QTableWidget(0, 2)
            self._result.setHorizontalHeaderLabels(["Property","Value"])
            self._result.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            self._result.verticalHeader().setVisible(False)
            self._result.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            self._result.setFont(QFont(C["mono"].split(",")[0],11))
            self._det_tbl = QTableWidget(0, 2)
            self._det_tbl.setHorizontalHeaderLabels(["Engine","Detection"])
            self._det_tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            self._det_tbl.verticalHeader().setVisible(False)
            self._det_tbl.setFont(QFont(C["mono"].split(",")[0],11))
            self._det_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            lay.addWidget(self._result); lay.addWidget(QLabel("Detections:")); lay.addWidget(self._det_tbl, 1)
            self.setWidget(w)

        def _lookup(self):
            if not self._az: return
            sha256 = ""
            for k, v in self._az.hashes():
                if k == "SHA256": sha256 = v; break
            if not sha256: return
            from PyQt6.QtWidgets import QProgressDialog
            bar = QProgressDialog("Querying VirusTotal...", "", 0, 0, self)
            bar.setCancelButton(None); bar.setWindowModality(Qt.WindowModality.WindowModal)
            bar.show(); QApplication.processEvents()
            from PyQt6.QtCore import QThread
            class _W(QThread):
                done = pyqtSignal(dict)
                def __init__(self, client, sha): super().__init__(); self.c=client; self.h=sha
                def run(self): self.done.emit(self.c.summary(self.h))
            self._w = _W(self._client, sha256)
            self._w.done.connect(lambda r: (bar.close(), self._show(r)))
            self._w.start()

        def _show(self, r: Dict):
            if "error" in r:
                QMessageBox.warning(None, "VT Error", r["error"]); return
            rows = [(k, str(v)) for k, v in r.items() if k not in ("detections","tags")]
            self._result.setRowCount(len(rows))
            VERDICT_COL = {"MALICIOUS": C["red"], "SUSPICIOUS": C["orange"], "CLEAN": C["green"]}
            for row, (k, v) in enumerate(rows):
                self._result.setRowHeight(row, 26)
                ki = QTableWidgetItem(k); ki.setForeground(QColor(C["sec"]))
                vi = QTableWidgetItem(v)
                if k == "verdict": vi.setForeground(QColor(VERDICT_COL.get(v, C["text"]))); vi.setFont(QFont(C["mono"].split(",")[0],11,QFont.Weight.Bold))
                self._result.setItem(row, 0, ki); self._result.setItem(row, 1, vi)
            dets = r.get("detections", {})
            self._det_tbl.setRowCount(len(dets))
            for row, (eng, det) in enumerate(dets.items()):
                self._det_tbl.setRowHeight(row, 22)
                ei = QTableWidgetItem(eng); di = QTableWidgetItem(det)
                di.setForeground(QColor(C["red"])); di.setFont(QFont(C["mono"].split(",")[0],11,QFont.Weight.Bold))
                self._det_tbl.setItem(row, 0, ei); self._det_tbl.setItem(row, 1, di)

    # ── Emulator panel ────────────────────────────────────────────────────────
    class EmulatorPanel(_ExtPanel):
        def load(self, az):
            w, lay = self._build("CPU Emulator  (unicorn)")
            if not HAS_UNI:
                lay.addWidget(QLabel("unicorn not installed\npip install unicorn")); lay.addStretch(); self.setWidget(w); return
            info = QLabel("Paste hex shellcode below, pick architecture, and click Run.\nThe emulator traces each instruction without affecting the host system.")
            info.setWordWrap(True); info.setStyleSheet(f"color:{C['sec']};font-size:12px;"); lay.addWidget(info)
            abar = QHBoxLayout()
            self._arch = QComboBox(); self._arch.addItems(["x86","x64"]); self._arch.setFixedWidth(90)
            self._mi   = QLineEdit("500"); self._mi.setFixedWidth(70)
            rb = QPushButton("Run"); rb.clicked.connect(self._run)
            abar.addWidget(QLabel("Arch:")); abar.addWidget(self._arch)
            abar.addWidget(QLabel("Max insns:")); abar.addWidget(self._mi); abar.addWidget(rb); abar.addStretch()
            lay.addLayout(abar)
            self._code_e = QPlainTextEdit(); self._code_e.setFont(QFont(C["mono"].split(",")[0],11))
            self._code_e.setPlaceholderText("Hex shellcode, e.g.:\n90 90 90 31 C0 C3\n\nOr file offset range: offset:size")
            self._code_e.setFixedHeight(120)

            # Pre-fill with entry point bytes if PE
            if hasattr(az, "ep_offset") and az.ep_offset() is not None:
                ep = az.ep_offset()
                sample = " ".join(f"{b:02X}" for b in az.raw[ep:ep+32])
                self._code_e.setPlainText(sample)
            lay.addWidget(self._code_e)

            r2 = QHBoxLayout(); r2.setSpacing(12)
            rg = QGroupBox("Registers"); rg.setLayout(QVBoxLayout())
            self._reg_tbl = QTableWidget(0,2); self._reg_tbl.setHorizontalHeaderLabels(["Reg","Value"])
            self._reg_tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
            self._reg_tbl.verticalHeader().setVisible(False)
            self._reg_tbl.setFont(QFont(C["mono"].split(",")[0],11))
            self._reg_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            rg.layout().addWidget(self._reg_tbl); r2.addWidget(rg)

            tg = QGroupBox("Execution Trace"); tg.setLayout(QVBoxLayout())
            self._trace = QPlainTextEdit(); self._trace.setReadOnly(True)
            self._trace.setFont(QFont(C["mono"].split(",")[0],10)); tg.layout().addWidget(self._trace); r2.addWidget(tg,2)
            lay.addLayout(r2,1); self._emu = MiniEmulator(); self._az=az; self.setWidget(w)

        def _run(self):
            text = self._code_e.toPlainText().strip()
            try: code = bytes.fromhex(text.replace("\n","").replace(" ","").replace(",",""))
            except: QMessageBox.warning(None,"","Invalid hex."); return
            arch = self._arch.currentText()
            ok, msg = self._emu.setup(code, arch)
            if not ok: QMessageBox.warning(None,"Emulator",msg); return
            try: max_i = int(self._mi.text())
            except: max_i = 500
            ok2, msg2, trace = self._emu.run(max_i)
            self._trace.setPlainText("\n".join(trace[-200:]))
            regs = self._emu.get_regs()
            ML = C["mono"].split(",")[0]
            self._reg_tbl.setRowCount(len(regs))
            HL = {"EIP":C["accent"],"RIP":C["accent"],"ESP":C["green"],"RSP":C["green"]}
            for row,(k,v) in enumerate(regs.items()):
                self._reg_tbl.setRowHeight(row,22)
                ki=QTableWidgetItem(k); ki.setForeground(QColor(C["sec"]))
                vi=QTableWidgetItem(f"0x{v:016X}" if v>0xFFFFFFFF else f"0x{v:08X}")
                vi.setForeground(QColor(HL.get(k,C["text"])))
                self._reg_tbl.setItem(row,0,ki); self._reg_tbl.setItem(row,1,vi)

    # ── Import Reconstruction panel ───────────────────────────────────────────
    class ImportReconPanel(_ExtPanel):
        def load(self, az):
            w, lay = self._build("Import Reconstruction")
            info = QLabel("Heuristic scan for CALL/JMP instructions targeting addresses outside all PE sections.\nUseful for analyzing packed or manually mapped binaries where the IAT is missing or obfuscated.")
            info.setWordWrap(True); info.setStyleSheet(f"color:{C['sec']};font-size:12px;"); lay.addWidget(info)
            if not (hasattr(az,"pe") and az.pe):
                lay.addWidget(QLabel("PE file required.")); lay.addStretch(); self.setWidget(w); return
            sb = QPushButton("Scan for External Calls"); sb.setProperty("sec","true") if hasattr(sb,"setProperty") else None
            lay.addWidget(sb)
            tbl = QTableWidget(0,4); tbl.setHorizontalHeaderLabels(["Call Site","Target","Type","Section"])
            tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
            tbl.verticalHeader().setVisible(False)
            tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            tbl.setFont(QFont(C["mono"].split(",")[0],11))
            info2 = QLabel(""); info2.setStyleSheet(f"color:{C['sec']};font-size:12px;"); lay.addWidget(tbl,1); lay.addWidget(info2)
            recon = ImportReconstructor(az)
            def _scan():
                calls = recon.find_suspicious_calls()
                tbl.setRowCount(len(calls)); info2.setText(f"{len(calls)} external call(s) found.")
                for row,c in enumerate(calls):
                    tbl.setRowHeight(row,22)
                    ci=QTableWidgetItem(c["CallSite"]); ci.setForeground(QColor(C["sec"]))
                    ti=QTableWidgetItem(c["Target"]); ti.setForeground(QColor(C["accent"]))
                    tbl.setItem(row,0,ci); tbl.setItem(row,1,ti)
                    tbl.setItem(row,2,QTableWidgetItem(c["Instruction"]))
                    tbl.setItem(row,3,QTableWidgetItem(c["Section"]))
            sb.clicked.connect(_scan); self.setWidget(w)

    # ── Markdown Report panel ─────────────────────────────────────────────────
    class ReportPanel(_ExtPanel):
        def __init__(self):
            super().__init__(); self._vt: Optional[Dict] = None
        def load(self, az):
            self._az = az; self._build_ui()
        def _build_ui(self):
            w, lay = self._build("Markdown Report Generator")
            info = QLabel("Auto-generates a structured analysis write-up. Optionally include VirusTotal data.")
            info.setWordWrap(True); info.setStyleSheet(f"color:{C['sec']};font-size:12px;"); lay.addWidget(info)
            bar = QHBoxLayout()
            gen = QPushButton("Generate Report")
            exp = QPushButton("Export .md"); exp.setStyleSheet(f"background:transparent;color:{C['accent']};border:1px solid {C['border']};padding:6px 14px;border-radius:6px;")
            cp  = QPushButton("Copy"); cp.setStyleSheet(exp.styleSheet())
            bar.addWidget(gen); bar.addWidget(exp); bar.addWidget(cp); bar.addStretch(); lay.addLayout(bar)
            self._edit = QPlainTextEdit(); self._edit.setFont(QFont(C["mono"].split(",")[0],11))
            self._edit.setTabStopDistance(28); lay.addWidget(self._edit,1)
            gen.clicked.connect(lambda:self._edit.setPlainText(MarkdownReporter.generate(self._az,self._vt)))
            exp.clicked.connect(self._export)
            cp.clicked.connect(lambda:QApplication.clipboard().setText(self._edit.toPlainText()))
            self.setWidget(w)
        def _export(self):
            p,_=QFileDialog.getSaveFileName(None,"Export Markdown",Path(self._az.path).stem+"_report.md","Markdown (*.md);;All (*)")
            if p:
                with open(p,"w",encoding="utf-8") as f: f.write(self._edit.toPlainText())

    # ── YARA DB panel ─────────────────────────────────────────────────────────
    class YaraDBPanel(_ExtPanel):
        def __init__(self):
            super().__init__(); self._db = YaraRulesDB(); self._az = None
        def load(self, az): self._az = az; self._rebuild()
        def _rebuild(self):
            w, lay = self._build("YARA Rules Database")
            info = QLabel(f"{self._db.count()} rule source(s) loaded.  Supports .yar / .yara files and inline rules.\nrequires: pip install yara-python" if not HAS_YARA else f"{self._db.count()} rule source(s) loaded.")
            info.setWordWrap(True); info.setStyleSheet(f"color:{C['sec']};font-size:12px;"); lay.addWidget(info)
            abar = QHBoxLayout()
            lf=QPushButton("Load File"); lf.setStyleSheet(f"background:transparent;color:{C['accent']};border:1px solid {C['border']};padding:6px 14px;border-radius:6px;")
            ld=QPushButton("Load Dir");  ld.setStyleSheet(lf.styleSheet())
            scan=QPushButton("Scan")
            lf.clicked.connect(self._load_file); ld.clicked.connect(self._load_dir); scan.clicked.connect(self._scan)
            for b in [lf,ld,scan]: abar.addWidget(b)
            abar.addStretch(); lay.addLayout(abar)

            self._inline=QPlainTextEdit(); self._inline.setFont(QFont(C["mono"].split(",")[0],10))
            self._inline.setPlaceholderText('Paste YARA rule here...\n\nrule example {\n    strings:\n        $s = "malware"\n    condition:\n        $s\n}')
            self._inline.setFixedHeight(160)
            ab=QPushButton("Add Inline Rule"); ab.setStyleSheet(lf.styleSheet())
            ab.clicked.connect(self._add_inline)
            lay.addWidget(QLabel("Inline Rule:")); lay.addWidget(self._inline); lay.addWidget(ab)

            self._tbl=QTableWidget(0,4); self._tbl.setHorizontalHeaderLabels(["Rule","Tags","Source","Match Offsets"])
            self._tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
            self._tbl.verticalHeader().setVisible(False)
            self._tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            self._tbl.setFont(QFont(C["mono"].split(",")[0],11))
            self._info=QLabel(""); self._info.setStyleSheet(f"color:{C['sec']};font-size:12px;")
            lay.addWidget(self._tbl,1); lay.addWidget(self._info); self.setWidget(w)

        def _load_file(self):
            p,_=QFileDialog.getOpenFileName(None,"Load YARA File","","YARA (*.yar *.yara);;All (*)")
            if p: self._db.load_file(p); self._info.setText(f"Loaded: {Path(p).name}  Total: {self._db.count()}")
        def _load_dir(self):
            d=QFileDialog.getExistingDirectory(None,"Select YARA Rules Directory")
            if d: self._db.load_directory(d); self._info.setText(f"Loaded dir: {d}  Total: {self._db.count()}")
        def _add_inline(self):
            txt=self._inline.toPlainText().strip()
            if txt: self._db.add_inline("inline_rule",txt); self._info.setText(f"Added inline rule.  Total: {self._db.count()}")
        def _scan(self):
            if not self._az: return
            hits=self._db.scan(bytes(self._az.raw)); self._tbl.setRowCount(len(hits))
            self._info.setText(f"{len(hits)} match(es).")
            for row,h in enumerate(hits):
                self._tbl.setRowHeight(row,22)
                ri=QTableWidgetItem(h["Rule"]); ri.setForeground(QColor(C["red"])); ri.setFont(QFont(C["mono"].split(",")[0],11,QFont.Weight.Bold))
                ti=QTableWidgetItem(h["Tags"]); ti.setForeground(QColor(C["orange"]))
                si=QTableWidgetItem(h["Source"]); si.setForeground(QColor(C["sec"]))
                sti=QTableWidgetItem(", ".join(f"{o} {i}" for o,i in h["Strings"][:3]))
                self._tbl.setItem(row,0,ri); self._tbl.setItem(row,1,ti)
                self._tbl.setItem(row,2,si); self._tbl.setItem(row,3,sti)


# ══════════════════════════════════════════════════════════════════════════════
#  STANDALONE TEST
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python kre_extensions.py <binary>")
        print("       Detects format (PE/ELF/Mach-O) and prints header info + sections")
        sys.exit(1)

    path = sys.argv[1]
    fmt  = UniversalLoader.detect(path)
    print(f"\nFile   : {path}")
    print(f"Format : {fmt}")

    if fmt == "ELF":
        az = ELFAnalyzer(path)
        print("\n=== ELF Header ===")
        for k, v in az.header_info(): print(f"  {k:<25} {v}")
        print(f"\n=== Sections ({len(az.sections())}) ===")
        for s in az.sections():
            print(f"  {s['Name']:<20} {s['Type']:<12} {s['Offset']}  {s['Size']:>8} bytes  entropy={s['Entropy']}")

    elif fmt in ("Mach-O","Mach-O (FAT)"):
        az = MachOAnalyzer(path)
        print("\n=== Mach-O Header ===")
        for k, v in az.header_info(): print(f"  {k:<25} {v}")
        print(f"\n=== Sections ({len(az.sections())}) ===")
        for s in az.sections():
            print(f"  {s['Name']:<30} {s['Offset']}  {s['Size']:>8} bytes  entropy={s['Entropy']}")
        print(f"\n=== Load Commands ({len(az.load_commands())}) ===")
        for lc in az.load_commands(): print(f"  {lc['Command']}")

    else:
        print(f"Use kre.py for {fmt} files.")
