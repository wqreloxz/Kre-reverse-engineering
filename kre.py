#!/usr/bin/env python3
"""
KRE — Kovak Reverse Engineering
Full feature set — everything from all sessions:

  Static Analysis
   PE headers (DOS / NT / Optional / File)
  Sections with entropy visualization
 Imports / Exports / Relocations / TLS / Resources / Debug Info
   Rich Header decoder (MSVC compiler fingerprint)
   Overlay Analyzer — data after last section
   Import Hash (ImpHash) — malware family attribution
   Checksum verify + recalculate

  Code Analysis
  ─────────────
  • Disassembler (Capstone x86/x64) with syntax coloring
  • Control Flow Graph — zoomable, pannable QGraphicsView
  • Function Prologue Scanner — heuristic function finder
  • FLIRT-like signature scanner — identify library functions

  Threat Detection
  ────────────────
  • Packer / obfuscation detection + entropy heuristics
  • Compiler fingerprint (MSVC/GCC/Delphi/Go/Rust/.NET ...)
  • Anti-debug API detector
  • Suspicious API import scanner
  • Crypto constant detector (AES, RC4, MD5, SHA, CRC32, Salsa20, TEA, Blowfish, DES)
  • Network indicator extraction (URLs, IPs, Emails, Domains)
  • YARA rule auto-generation

  Hex Editor & Patching
  ─────────────────────
  • Full hex editor — Go To, Find bytes, Edit Mode
  • Per-byte patching with full Undo / Redo stack (10 000-deep)
  • Patch diff panel — every changed byte with delta
  • Save patched binary

  Advanced Tools
  ──────────────
  • Code Cave Finder — injectable null regions
  • Wildcard Pattern Scanner  (4D 5A ?? ?? 90 00)
  • PE Section Injector — add raw sections
  • PE Binary Diff — sections / imports / byte regions
  • Global Search — instant search across all PE data

  Debugger (built-in)
  ───────────────────
  • Windows: Win32 Debug API (CreateProcess / DebugActiveProcess)
  • Linux:   ptrace
  • Launch / Attach / Detach
  • INT3 breakpoints — add, remove, rearm
  • Step Into / Step Over
  • Register view (x86 + x64)
  • Stack view (live)
  • Memory viewer / hex dump of process memory
  • Debug console

  Integrations
  ────────────
  • Ghidra live bridge (ghidra-bridge) — functions, decompile, XRefs
  • Plugin system — drop .py in ./plugins/, run from GUI

  UI / UX
  ───────
  • Apple-inspired light theme (no neon, no emoji)
  • Full dark mode toggle
  • Panel sync — click section → jump to hex editor
  • Async analysis workers — no GUI freeze on large files
  • mmap for files > 50 MB
  • Drag & drop file loading
  • Session save / restore (.kre JSON)

Dependencies:
  pip install pefile capstone PyQt6
  pip install ghidra-bridge   # optional

Usage:
  python kre.py
  python kre.py target.exe
"""

# ══════════════════════════════════════════════════════════════════════════════
#  IMPORTS
# ══════════════════════════════════════════════════════════════════════════════
import sys, os, math, struct, re, json, hashlib, importlib.util, platform
from pathlib import Path
from collections import Counter, deque
from typing import Optional, Dict, List, Tuple, Any, Deque
import ctypes, ctypes.util

try:    import pefile;    HAS_PE  = True
except: HAS_PE  = False
try:    import capstone;  HAS_CAP = True
except: HAS_CAP = False
try:    import ghidra_bridge; HAS_GHI = True
except: HAS_GHI = False

IS_WIN   = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

if IS_WIN:
    from ctypes import wintypes
    _k32 = ctypes.windll.kernel32
if IS_LINUX:
    _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

from PyQt6.QtWidgets import *
from PyQt6.QtCore    import *
from PyQt6.QtGui     import *

# ══════════════════════════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════════════════════════
LIGHT = dict(
    bg="#F5F5F7", sidebar="#E8E8ED", surface="#FFFFFF", border="#D2D2D7",
    accent="#0071E3", accentH="#0077ED", text="#1D1D1F", sec="#6E6E73",
    red="#FF3B30", green="#34C759", orange="#FF9500", yellow="#FFCC00",
    purple="#AF52DE", cyan="#32ADE6",
    mono="Menlo,Consolas,monospace",
    sans="SF Pro Display,Helvetica Neue,Arial,sans-serif",
)
DARK = dict(
    bg="#1C1C1E", sidebar="#2C2C2E", surface="#2C2C2E", border="#3A3A3C",
    accent="#0A84FF", accentH="#148EFF", text="#F2F2F7", sec="#8E8E93",
    red="#FF453A", green="#32D74B", orange="#FF9F0A", yellow="#FFD60A",
    purple="#BF5AF2", cyan="#5AC8FA",
    mono="Menlo,Consolas,monospace",
    sans="SF Pro Display,Helvetica Neue,Arial,sans-serif",
)
C: Dict[str,str] = dict(LIGHT)

def _qss() -> str:
    return f"""
* {{font-family:{C['sans']};font-size:13px;color:{C['text']};}}
QMainWindow,QDialog {{background:{C['bg']};}}
QWidget {{background:transparent;}}
QSplitter::handle {{background:{C['border']};width:1px;height:1px;}}
QListWidget {{background:{C['sidebar']};border:none;outline:none;padding:8px 0;}}
QListWidget::item {{padding:7px 20px;border-radius:6px;margin:1px 8px;color:{C['text']};}}
QListWidget::item:selected {{background:{C['accent']};color:white;}}
QListWidget::item:hover:!selected {{background:rgba(128,128,128,.1);}}
QTableWidget,QTableView {{background:{C['surface']};border:1px solid {C['border']};
  border-radius:10px;gridline-color:{C['border']};outline:none;}}
QTableWidget::item {{padding:3px 8px;background:transparent;}}
QTableWidget::item:selected {{background:rgba(0,113,227,.15);color:{C['text']};}}
QHeaderView::section {{background:{C['sidebar']};color:{C['sec']};font-size:11px;
  font-weight:600;padding:6px 8px;border:none;border-bottom:1px solid {C['border']};}}
QPushButton {{background:{C['accent']};color:white;border:none;
  border-radius:6px;padding:7px 16px;font-weight:500;}}
QPushButton:hover {{background:{C['accentH']};}}
QPushButton:pressed {{background:#005BBE;}}
QPushButton:disabled {{background:rgba(128,128,128,.2);color:{C['sec']};}}
QPushButton[sec="true"] {{background:transparent;color:{C['accent']};
  border:1px solid {C['border']};padding:6px 14px;}}
QPushButton[sec="true"]:hover {{background:rgba(0,113,227,.1);}}
QPushButton[danger="true"] {{background:{C['red']};color:white;}}
QLineEdit,QTextEdit,QPlainTextEdit {{background:{C['surface']};
  border:1px solid {C['border']};border-radius:8px;padding:7px 10px;
  selection-background-color:rgba(0,113,227,.3);color:{C['text']};}}
QLineEdit:focus,QTextEdit:focus,QPlainTextEdit:focus {{border-color:{C['accent']};}}
QScrollBar:vertical {{width:8px;background:transparent;margin:0;}}
QScrollBar::handle:vertical {{background:rgba(128,128,128,.3);border-radius:4px;min-height:24px;}}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{height:0;}}
QScrollBar:horizontal {{height:8px;background:transparent;margin:0;}}
QScrollBar::handle:horizontal {{background:rgba(128,128,128,.3);border-radius:4px;min-width:24px;}}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal {{width:0;}}
QTabWidget::pane {{border:1px solid {C['border']};border-radius:10px;background:{C['surface']};}}
QTabBar::tab {{background:{C['sidebar']};border:1px solid {C['border']};border-bottom:none;
  padding:7px 16px;border-top-left-radius:7px;border-top-right-radius:7px;
  margin-right:2px;color:{C['sec']};font-weight:500;}}
QTabBar::tab:selected {{background:{C['surface']};color:{C['text']};}}
QGroupBox {{background:{C['surface']};border:1px solid {C['border']};
  border-radius:10px;margin-top:12px;padding:8px 12px;}}
QGroupBox::title {{subcontrol-origin:margin;left:12px;padding:0 4px;
  color:{C['sec']};font-size:11px;font-weight:600;}}
QStatusBar {{background:{C['sidebar']};border-top:1px solid {C['border']};
  color:{C['sec']};font-size:12px;padding:2px 8px;}}
QToolBar {{background:{C['surface']};border-bottom:1px solid {C['border']};
  spacing:4px;padding:4px 12px;}}
QComboBox {{background:{C['surface']};border:1px solid {C['border']};
  border-radius:6px;padding:6px 10px;color:{C['text']};}}
QLabel[h="true"] {{font-size:22px;font-weight:700;color:{C['text']};background:transparent;}}
QLabel[sub="true"] {{font-size:12px;color:{C['sec']};background:transparent;}}
QGraphicsView {{border:1px solid {C['border']};border-radius:8px;background:{C['bg']};}}
"""

def apply_theme(app: QApplication, dark: bool):
    C.update(DARK if dark else LIGHT)
    app.setStyleSheet(_qss())

# ══════════════════════════════════════════════════════════════════════════════
#  STATIC DATA
# ══════════════════════════════════════════════════════════════════════════════
SUSPICIOUS_APIS = {
    "CreateRemoteThread","VirtualAllocEx","WriteProcessMemory","ReadProcessMemory",
    "OpenProcess","NtCreateThreadEx","RtlCreateUserThread","SetWindowsHookEx",
    "GetAsyncKeyState","RegSetValueEx","RegCreateKeyEx","SHFileOperation",
    "InternetOpenUrl","InternetOpen","WinExec","ShellExecute","CreateProcessAsUser",
    "AdjustTokenPrivileges","LookupPrivilegeValue","CryptEncrypt","CryptDecrypt",
    "HttpOpenRequest","HttpSendRequest","URLDownloadToFile","FindFirstFile",
    "CreateFileMappingA","MapViewOfFile","QueueUserAPC","NtUnmapViewOfSection",
}
ANTIDEBUG_APIS = {
    "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
    "OutputDebugString","GetTickCount","timeGetTime","QueryPerformanceCounter",
    "NtSetInformationThread","FindWindow","BlockInput","NtClose","CsrGetProcessId",
}
PACKER_SIGS = {
    "UPX":      [b"UPX0",b"UPX1",b"UPX2"],
    "ASPack":   [b".aspack",b"ASPack"],
    "Themida":  [b".themida",b"Themida"],
    "MPRESS":   [b".MPRESS1",b".MPRESS2"],
    "PECompact":[b"PEC2",b"PECompact2"],
    "NSPack":   [b"NS.data"],
    "Petite":   [b".petite"],
}
COMPILER_SIGS = {
    "MSVC":    [b"\x55\x8B\xEC",b"\x40\x55\x48\x81\xEC"],
    "GCC":     [b"\x55\x89\xE5"],
    "Delphi":  [b"Borland",b"FastCode"],
    "Go":      [b"go.buildid",b"/usr/local/go"],
    "Rust":    [b"rustc",b"__rust_"],
    ".NET":    [b"mscoree.dll",b"_CorExeMain"],
    "AutoIt":  [b"AU3!"],
    "Python":  [b"PyInstaller",b"python3"],
}
RESOURCE_TYPES = {
    1:"Cursor",2:"Bitmap",3:"Icon",4:"Menu",5:"Dialog",6:"StringTable",
    7:"FontDir",8:"Font",9:"Accelerator",10:"RCData",11:"MessageTable",
    12:"GroupCursor",14:"GroupIcon",16:"Version",17:"DlgInclude",
    19:"PlugPlay",20:"VXD",21:"ANICursor",22:"ANIIcon",23:"HTML",24:"Manifest",
}
MACHINES = {0x14C:"x86 (32-bit)",0x8664:"x64 (64-bit)",0x1C4:"ARM",0xAA64:"ARM64",0x200:"Itanium"}
SUBSYSTEMS = {1:"Native",2:"Windows GUI",3:"Windows Console",5:"OS/2 CUI",
              7:"POSIX CUI",10:"EFI Application",14:"Xbox",16:"Boot"}
CRYPTO_SIGS: List[Tuple[str,bytes,str]] = [
    ("AES S-box",bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76]),"AES encryption S-box"),
    ("AES Inv S-box",bytes([0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb]),"AES decryption S-box"),
    ("MD5 Init",struct.pack("<IIII",0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476),"MD5 initialization constants"),
    ("SHA-1 Init",struct.pack(">IIIII",0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0),"SHA-1 init constants"),
    ("SHA-256 Init",struct.pack(">II",0x6a09e667,0xbb67ae85),"SHA-256 init constants"),
    ("CRC32 Poly",struct.pack("<I",0xEDB88320),"CRC32 reflected polynomial"),
    ("Salsa20/ChaCha20",b"expand 32-byte k","Salsa20/ChaCha20 sigma constant"),
    ("Salsa20 (16B)",b"expand 16-byte k","Salsa20 tau constant"),
    ("TEA Delta",struct.pack("<I",0x9E3779B9),"TEA/XTEA/XXTEA delta"),
    ("Blowfish P-array",struct.pack(">II",0x243F6A88,0x85A308D3),"Blowfish P-array (pi digits)"),
    ("DES S-box",bytes([0x0e,0x04,0x0d,0x01,0x02,0x0f,0x0b,0x08]),"DES S-box 1 first row"),
]
PROLOGUES: List[Tuple[bytes,str]] = [
    (b"\x55\x8B\xEC",       "push ebp; mov ebp,esp  [MSVC x86]"),
    (b"\x55\x89\xE5",       "push ebp; mov ebp,esp  [GCC x86]"),
    (b"\x48\x89\x5C\x24",   "mov [rsp+N],rbx  [x64 common]"),
    (b"\x48\x83\xEC",       "sub rsp,N  [x64]"),
    (b"\x40\x55",           "push rbp  [x64 MSVC]"),
    (b"\x53\x55\x56\x57",   "push ebx,ebp,esi,edi"),
    (b"\x56\x57\x55",       "push esi,edi,ebp"),
    (b"\x8B\xFF\x55\x8B\xEC","mov edi,edi; push ebp  [thunk]"),
]
BUILTIN_FLIRT: List[Tuple[str,str]] = [
    ("55 8B EC 83 EC 10 56 8B F1",          "malloc"),
    ("55 8B EC 53 56 8B 75 08 57 8B 7D 0C", "memcpy_x86"),
    ("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20","memcpy_x64"),
    ("55 8B EC 83 EC 18 53 56 57",           "operator_new"),
    ("55 8B EC 8B 45 08 85 C0 74",           "free"),
    ("55 8B EC 83 EC 48",                    "__alloca_probe"),
    ("55 8B EC 56 8B 75 08 83 FE FF",        "strlen_x86"),
    ("48 83 EC 28 48 85 C9 74",              "strlen_x64"),
    ("55 8B EC 83 7D 08 00 74",              "strcmp_x86"),
    ("CC CC CC CC 55 8B EC",                 "cdecl_thunk"),
]

# ══════════════════════════════════════════════════════════════════════════════
#  PATCH HISTORY  (undo / redo)
# ══════════════════════════════════════════════════════════════════════════════
class PatchHistory:
    def __init__(self, raw: bytearray):
        self.raw = raw
        self._undo: Deque[Tuple[int,int,int]] = deque(maxlen=10000)
        self._redo: Deque[Tuple[int,int,int]] = deque(maxlen=10000)

    def apply(self, off: int, old: int, new: int):
        self.raw[off] = new
        self._undo.append((off, old, new))
        self._redo.clear()

    def undo(self) -> Optional[Tuple[int,int,int]]:
        if not self._undo: return None
        off, old, new = self._undo.pop()
        self.raw[off] = old
        self._redo.append((off, old, new))
        return off, new, old

    def redo(self) -> Optional[Tuple[int,int,int]]:
        if not self._redo: return None
        off, old, new = self._redo.pop()
        self.raw[off] = new
        self._undo.append((off, old, new))
        return off, old, new

    def undo_all(self):
        for off, old, _ in list(self._undo): self.raw[off] = old
        self._undo.clear(); self._redo.clear()

    @property
    def can_undo(self): return bool(self._undo)
    @property
    def can_redo(self): return bool(self._redo)

    @property
    def patches(self) -> Dict[int,Tuple[int,int]]:
        d: Dict[int,Tuple[int,int]] = {}
        for off, old, new in self._undo:
            d[off] = (d[off][0] if off in d else old, new)
        return d

# ══════════════════════════════════════════════════════════════════════════════
#  WILDCARD SCANNER
# ══════════════════════════════════════════════════════════════════════════════
class WildcardScanner:
    @staticmethod
    def parse(p: str) -> List[Optional[int]]:
        return [None if t in ("??","..","**") else int(t,16) for t in p.strip().split()]

    @staticmethod
    def scan(data: bytes, pat: List[Optional[int]]) -> List[int]:
        pl, dl = len(pat), len(data)
        return [i for i in range(dl-pl+1)
                if all(pb is None or data[i+j]==pb for j,pb in enumerate(pat))]

# ══════════════════════════════════════════════════════════════════════════════
#  FLIRT SCANNER
# ══════════════════════════════════════════════════════════════════════════════
class FlirtScanner:
    def __init__(self):
        self.sigs: List[Tuple[List[Optional[int]],str]] = []
        for pat_s, name in BUILTIN_FLIRT:
            try: self.sigs.append((WildcardScanner.parse(pat_s), name))
            except: pass

    def load_file(self, path: str):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                parts = line.rsplit(None, 1)
                if len(parts) == 2:
                    try: self.sigs.append((WildcardScanner.parse(parts[0]), parts[1]))
                    except: pass

    def scan(self, data: bytes) -> List[Dict]:
        out = []
        for pat, name in self.sigs:
            for off in WildcardScanner.scan(data, pat):
                out.append({"Offset":f"0x{off:08X}","Name":name,"Length":len(pat)})
        return out

# ══════════════════════════════════════════════════════════════════════════════
#  ASYNC WORKER + NAVIGATOR (panel sync)
# ══════════════════════════════════════════════════════════════════════════════
class Worker(QThread):
    done  = pyqtSignal(object)
    error = pyqtSignal(str)
    def __init__(self, fn, *a, **kw):
        super().__init__(); self._fn=fn; self._a=a; self._kw=kw
    def run(self):
        try: self.done.emit(self._fn(*self._a, **self._kw))
        except Exception as e: self.error.emit(str(e))

def async_run(parent, title, fn, *args, on_done=None, **kwargs):
    bar = QProgressDialog(title, "", 0, 0, parent)
    bar.setCancelButton(None); bar.setWindowModality(Qt.WindowModality.WindowModal)
    bar.setMinimumDuration(400)
    w = Worker(fn, *args, **kwargs)
    w.done.connect(lambda r: (bar.close(), on_done(r) if on_done else None))
    w.error.connect(lambda e: (bar.close(), QMessageBox.critical(parent, "Error", e)))
    w.start(); bar.exec(); return w

class _NavSignals(QObject):
    jump_hex    = pyqtSignal(int)
    jump_disasm = pyqtSignal(int)
    _inst: Optional["_NavSignals"] = None
    @classmethod
    def inst(cls):
        if cls._inst is None: cls._inst = cls()
        return cls._inst

Nav = _NavSignals.inst

# ══════════════════════════════════════════════════════════════════════════════
#  WINDOWS DEBUG STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════
if IS_WIN:
    class EXCEPTION_RECORD(ctypes.Structure): pass
    EXCEPTION_RECORD._fields_ = [
        ("ExceptionCode",       ctypes.c_uint32),
        ("ExceptionFlags",      ctypes.c_uint32),
        ("ExceptionRecord",     ctypes.POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress",    ctypes.c_void_p),
        ("NumberParameters",    ctypes.c_uint32),
        ("ExceptionInformation",ctypes.c_size_t * 15),
    ]
    class EXCEPTION_DEBUG_INFO(ctypes.Structure):
        _fields_ = [("ExceptionRecord",EXCEPTION_RECORD),("dwFirstChance",ctypes.c_uint32)]
    class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
        _fields_ = [("hFile",ctypes.c_void_p),("hProcess",ctypes.c_void_p),
                    ("hThread",ctypes.c_void_p),("lpBaseOfImage",ctypes.c_void_p),
                    ("dwDebugInfoFileOffset",ctypes.c_uint32),("nDebugInfoSize",ctypes.c_uint32),
                    ("lpThreadLocalBase",ctypes.c_void_p),("lpStartAddress",ctypes.c_void_p),
                    ("lpImageName",ctypes.c_void_p),("fUnicode",ctypes.c_uint16)]
    class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
        _fields_ = [("dwExitCode",ctypes.c_uint32)]
    class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
        _fields_ = [("hFile",ctypes.c_void_p),("lpBaseOfDll",ctypes.c_void_p),
                    ("dwDebugInfoFileOffset",ctypes.c_uint32),("nDebugInfoSize",ctypes.c_uint32),
                    ("lpImageName",ctypes.c_void_p),("fUnicode",ctypes.c_uint16)]
    class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
        _fields_ = [("lpDebugStringData",ctypes.c_void_p),
                    ("fUnicode",ctypes.c_uint16),("nDebugStringLength",ctypes.c_uint16)]
    class _DBG_UNION(ctypes.Union):
        _fields_ = [("Exception",EXCEPTION_DEBUG_INFO),
                    ("CreateProcessInfo",CREATE_PROCESS_DEBUG_INFO),
                    ("ExitProcess",EXIT_PROCESS_DEBUG_INFO),
                    ("LoadDll",LOAD_DLL_DEBUG_INFO),
                    ("DebugString",OUTPUT_DEBUG_STRING_INFO)]
    class DEBUG_EVENT(ctypes.Structure):
        _fields_ = [("dwDebugEventCode",ctypes.c_uint32),("dwProcessId",ctypes.c_uint32),
                    ("dwThreadId",ctypes.c_uint32),("u",_DBG_UNION)]
    class _FLOAT_SAVE(ctypes.Structure):
        _fields_ = [("ControlWord",ctypes.c_uint32),("StatusWord",ctypes.c_uint32),
                    ("TagWord",ctypes.c_uint32),("ErrorOffset",ctypes.c_uint32),
                    ("ErrorSelector",ctypes.c_uint32),("DataOffset",ctypes.c_uint32),
                    ("DataSelector",ctypes.c_uint32),("RegisterArea",ctypes.c_byte*80),
                    ("Cr0NpxState",ctypes.c_uint32)]
    class CONTEXT_x86(ctypes.Structure):
        _fields_ = [("ContextFlags",ctypes.c_uint32),
                    ("Dr0",ctypes.c_uint32),("Dr1",ctypes.c_uint32),
                    ("Dr2",ctypes.c_uint32),("Dr3",ctypes.c_uint32),
                    ("Dr6",ctypes.c_uint32),("Dr7",ctypes.c_uint32),
                    ("FloatSave",_FLOAT_SAVE),
                    ("SegGs",ctypes.c_uint32),("SegFs",ctypes.c_uint32),
                    ("SegEs",ctypes.c_uint32),("SegDs",ctypes.c_uint32),
                    ("Edi",ctypes.c_uint32),("Esi",ctypes.c_uint32),
                    ("Ebx",ctypes.c_uint32),("Edx",ctypes.c_uint32),
                    ("Ecx",ctypes.c_uint32),("Eax",ctypes.c_uint32),
                    ("Ebp",ctypes.c_uint32),("Eip",ctypes.c_uint32),
                    ("SegCs",ctypes.c_uint32),("EFlags",ctypes.c_uint32),
                    ("Esp",ctypes.c_uint32),("SegSs",ctypes.c_uint32),
                    ("ExtendedRegisters",ctypes.c_byte*512)]
    class STARTUPINFO(ctypes.Structure):
        _fields_ = [("cb",ctypes.c_uint32),("lpReserved",ctypes.c_void_p),
                    ("lpDesktop",ctypes.c_void_p),("lpTitle",ctypes.c_void_p),
                    ("dwX",ctypes.c_uint32),("dwY",ctypes.c_uint32),
                    ("dwXSize",ctypes.c_uint32),("dwYSize",ctypes.c_uint32),
                    ("dwXCountChars",ctypes.c_uint32),("dwYCountChars",ctypes.c_uint32),
                    ("dwFillAttribute",ctypes.c_uint32),("dwFlags",ctypes.c_uint32),
                    ("wShowWindow",ctypes.c_uint16),("cbReserved2",ctypes.c_uint16),
                    ("lpReserved2",ctypes.c_void_p),("hStdInput",ctypes.c_void_p),
                    ("hStdOutput",ctypes.c_void_p),("hStdError",ctypes.c_void_p)]
    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess",ctypes.c_void_p),("hThread",ctypes.c_void_p),
                    ("dwProcessId",ctypes.c_uint32),("dwThreadId",ctypes.c_uint32)]

if IS_LINUX:
    class _user_regs_x64(ctypes.Structure):
        _fields_ = [(r,ctypes.c_ulonglong) for r in
                    ["r15","r14","r13","r12","rbp","rbx","r11","r10","r9","r8",
                     "rax","rcx","rdx","rsi","rdi","orig_rax","rip","cs",
                     "eflags","rsp","ss","fs_base","gs_base","ds","es","fs","gs"]]

# ══════════════════════════════════════════════════════════════════════════════
#  WINDOWS DEBUGGER
# ══════════════════════════════════════════════════════════════════════════════
class WinDebugger(QThread):
    started   = pyqtSignal(int)
    stopped   = pyqtSignal(str)
    bp_hit    = pyqtSignal(int, dict)
    step_done = pyqtSignal(int, dict)
    exc_hit   = pyqtSignal(int, int)
    log       = pyqtSignal(str)
    regs_rdy  = pyqtSignal(dict)
    mod_load  = pyqtSignal(str, int)

    EXC_BP=0x80000003; EXC_SS=0x80000004; EXC_AV=0xC0000005
    DBG_CONT=0x00010002; DBG_EXC=0x80010001; INF=0xFFFFFFFF
    PROC_ALL=0x1F0FFF; THRD_ALL=0x001F03FF; CTX_FULL=0x10007
    EV_EXC=1; EV_CPROC=3; EV_EPROC=5; EV_DLL=6; EV_STR=8
    DEBUG_PROCESS=0x01; DEBUG_ONLY=0x02

    def __init__(self):
        super().__init__()
        self._pid=0; self._hproc=None; self._hthread=None
        self._running=False; self._initial_bp=True
        self._bps: Dict[int,int]={}
        self._lock=QMutex(); self._wait=QWaitCondition(); self._cmd=None
        self._last_bp=None

    def _send(self, cmd): 
        with QMutexLocker(self._lock): self._cmd=cmd; self._wait.wakeAll()
    def cont(self):   self._send("cont")
    def step(self):   self._send("step")
    def detach(self):
        self._running=False
        if self._pid: _k32.DebugActiveProcessStop(self._pid)
        self._send("stop")

    def launch(self, exe: str, args: str="") -> bool:
        si=STARTUPINFO(); si.cb=ctypes.sizeof(si); pi=PROCESS_INFORMATION()
        ok=_k32.CreateProcessW(None,ctypes.create_unicode_buffer(f'"{exe}" {args}'),
                               None,None,False,self.DEBUG_PROCESS|self.DEBUG_ONLY,
                               None,None,ctypes.byref(si),ctypes.byref(pi))
        if not ok: self.log.emit(f"CreateProcess failed: {_k32.GetLastError()}"); return False
        self._pid=pi.dwProcessId; self._hproc=pi.hProcess; self._hthread=pi.hThread
        self._running=True; self.start(); return True

    def attach(self, pid: int) -> bool:
        if not _k32.DebugActiveProcess(pid):
            self.log.emit(f"Attach failed: {_k32.GetLastError()}"); return False
        self._pid=pid; self._hproc=_k32.OpenProcess(self.PROC_ALL,False,pid)
        self._running=True; self.start(); return True

    def add_bp(self, addr: int) -> bool:
        if not self._hproc or addr in self._bps: return False
        orig=ctypes.c_byte()
        if not _k32.ReadProcessMemory(self._hproc,ctypes.c_void_p(addr),ctypes.byref(orig),1,None): return False
        self._bps[addr]=orig.value
        bp=ctypes.c_byte(0xCC); w=ctypes.c_size_t()
        _k32.WriteProcessMemory(self._hproc,ctypes.c_void_p(addr),ctypes.byref(bp),1,ctypes.byref(w))
        _k32.FlushInstructionCache(self._hproc,ctypes.c_void_p(addr),1); return True

    def del_bp(self, addr: int) -> bool:
        if addr not in self._bps: return False
        orig=ctypes.c_byte(self._bps.pop(addr)); w=ctypes.c_size_t()
        _k32.WriteProcessMemory(self._hproc,ctypes.c_void_p(addr),ctypes.byref(orig),1,ctypes.byref(w))
        _k32.FlushInstructionCache(self._hproc,ctypes.c_void_p(addr),1); return True

    def read_mem(self, addr: int, size: int) -> bytes:
        if not self._hproc: return b""
        buf=(ctypes.c_byte*size)(); r=ctypes.c_size_t()
        _k32.ReadProcessMemory(self._hproc,ctypes.c_void_p(addr),buf,size,ctypes.byref(r))
        return bytes(buf[:r.value])

    def write_mem(self, addr: int, data: bytes) -> bool:
        if not self._hproc: return False
        buf=(ctypes.c_byte*len(data))(*data); w=ctypes.c_size_t()
        ok=_k32.WriteProcessMemory(self._hproc,ctypes.c_void_p(addr),buf,len(data),ctypes.byref(w))
        _k32.FlushInstructionCache(self._hproc,ctypes.c_void_p(addr),len(data)); return bool(ok)

    def get_regs(self) -> Dict:
        if not self._hthread: return {}
        ctx=CONTEXT_x86(); ctx.ContextFlags=self.CTX_FULL
        if not _k32.GetThreadContext(self._hthread,ctypes.byref(ctx)): return {}
        return {"EAX":ctx.Eax,"EBX":ctx.Ebx,"ECX":ctx.Ecx,"EDX":ctx.Edx,
                "ESI":ctx.Esi,"EDI":ctx.Edi,"EBP":ctx.Ebp,"ESP":ctx.Esp,
                "EIP":ctx.Eip,"EFLAGS":ctx.EFlags,"CS":ctx.SegCs,"SS":ctx.SegSs}

    def _set_tf(self, on: bool):
        if not self._hthread: return
        ctx=CONTEXT_x86(); ctx.ContextFlags=self.CTX_FULL
        if _k32.GetThreadContext(self._hthread,ctypes.byref(ctx)):
            if on: ctx.EFlags|=0x100
            else:  ctx.EFlags&=~0x100
            _k32.SetThreadContext(self._hthread,ctypes.byref(ctx))

    def _restore_bp(self, addr: int):
        if addr not in self._bps: return
        ctx=CONTEXT_x86(); ctx.ContextFlags=self.CTX_FULL
        if _k32.GetThreadContext(self._hthread,ctypes.byref(ctx)):
            ctx.Eip-=1; _k32.SetThreadContext(self._hthread,ctypes.byref(ctx))
        orig=ctypes.c_byte(self._bps[addr]); w=ctypes.c_size_t()
        _k32.WriteProcessMemory(self._hproc,ctypes.c_void_p(addr),ctypes.byref(orig),1,ctypes.byref(w))

    def _rearm_bp(self, addr: int):
        if addr not in self._bps: return
        bp=ctypes.c_byte(0xCC); w=ctypes.c_size_t()
        _k32.WriteProcessMemory(self._hproc,ctypes.c_void_p(addr),ctypes.byref(bp),1,ctypes.byref(w))

    def _wait_cmd(self):
        with QMutexLocker(self._lock):
            self._cmd=None
            while self._cmd is None and self._running: self._wait.wait(self._lock,100)

    def run(self):
        de=DEBUG_EVENT()
        while self._running:
            if not _k32.WaitForDebugEvent(ctypes.byref(de),100): continue
            code=de.dwDebugEventCode; status=self.DBG_CONT
            ht=_k32.OpenThread(self.THRD_ALL,False,de.dwThreadId)
            if ht: self._hthread=ht
            if code==self.EV_EXC:
                ec=de.u.Exception.ExceptionRecord.ExceptionCode
                ea=de.u.Exception.ExceptionRecord.ExceptionAddress or 0
                if ec==self.EXC_BP:
                    if self._initial_bp:
                        self._initial_bp=False; self.log.emit(f"Process ready @ 0x{ea:08X}")
                        self.started.emit(self._pid)
                    else:
                        self._restore_bp(ea); regs=self.get_regs()
                        self._last_bp=ea; self.bp_hit.emit(ea,regs); self.regs_rdy.emit(regs)
                        self._wait_cmd()
                        if self._cmd=="step": self._set_tf(True)
                        elif self._cmd=="stop": self._running=False; break
                        else: self._set_tf(True)
                elif ec==self.EXC_SS:
                    regs=self.get_regs(); eip=regs.get("EIP",0)
                    if self._last_bp and self._last_bp in self._bps:
                        self._rearm_bp(self._last_bp); self._last_bp=None
                    self.step_done.emit(eip,regs); self.regs_rdy.emit(regs)
                    if self._cmd=="step":
                        self._wait_cmd()
                        if self._cmd=="step": self._set_tf(True)
                        elif self._cmd=="stop": self._running=False; break
                else:
                    status=self.DBG_EXC; self.exc_hit.emit(ea,ec)
                    self.log.emit(f"Exception 0x{ec:08X} @ 0x{ea:08X}")
            elif code==self.EV_CPROC:
                b=de.u.CreateProcessInfo.lpBaseOfImage or 0
                self.log.emit(f"Process @ base 0x{b:08X}")
                if de.u.CreateProcessInfo.hFile: _k32.CloseHandle(de.u.CreateProcessInfo.hFile)
            elif code==self.EV_EPROC:
                ec=de.u.ExitProcess.dwExitCode
                self.log.emit(f"Exited ({ec})"); self.stopped.emit(f"Exit({ec})")
                _k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,status)
                self._running=False; break
            elif code==self.EV_DLL:
                b=de.u.LoadDll.lpBaseOfDll or 0; self.log.emit(f"DLL @ 0x{b:08X}")
                self.mod_load.emit("",b)
                if de.u.LoadDll.hFile: _k32.CloseHandle(de.u.LoadDll.hFile)
            _k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,status)
        self.stopped.emit("Stopped")

# ══════════════════════════════════════════════════════════════════════════════
#  LINUX DEBUGGER
# ══════════════════════════════════════════════════════════════════════════════
class LinuxDebugger(QThread):
    started   = pyqtSignal(int)
    stopped   = pyqtSignal(str)
    bp_hit    = pyqtSignal(int, dict)
    step_done = pyqtSignal(int, dict)
    exc_hit   = pyqtSignal(int, int)
    log       = pyqtSignal(str)
    regs_rdy  = pyqtSignal(dict)
    mod_load  = pyqtSignal(str, int)

    PT_TRACEME=0;PT_PEEKDATA=2;PT_POKEDATA=5;PT_CONT=7
    PT_SINGLESTEP=9;PT_GETREGS=12;PT_SETREGS=13;PT_ATTACH=16;PT_DETACH=17
    PT_SETOPTS=0x4200; SIGTRAP=5

    def __init__(self):
        super().__init__()
        self._pid=0; self._running=False; self._bps: Dict[int,int]={}
        self._lock=QMutex(); self._wait=QWaitCondition(); self._cmd=None; self._last_bp=None

    def _send(self, cmd):
        with QMutexLocker(self._lock): self._cmd=cmd; self._wait.wakeAll()
    def cont(self):  self._send("cont")
    def step(self):  self._send("step")
    def detach(self):
        self._running=False
        if self._pid: _libc.ptrace(self.PT_DETACH,self._pid,0,0)
        self._send("stop")

    def launch(self, exe: str, args: str="") -> bool:
        child=os.fork()
        if child==0:
            _libc.ptrace(self.PT_TRACEME,0,0,0)
            os.execv(exe,[exe]+(args.split() if args else [])); os._exit(1)
        os.waitpid(child,0); self._pid=child
        _libc.ptrace(self.PT_SETOPTS,child,0,0x10)
        self._running=True; self.started.emit(child); self.start(); return True

    def attach(self, pid: int) -> bool:
        if _libc.ptrace(self.PT_ATTACH,pid,0,0)<0:
            self.log.emit(f"ATTACH failed: errno={ctypes.get_errno()}"); return False
        self._pid=pid; os.waitpid(pid,0)
        self._running=True; self.started.emit(pid); self.start(); return True

    def add_bp(self, addr: int) -> bool:
        if addr in self._bps: return False
        orig=_libc.ptrace(self.PT_PEEKDATA,self._pid,addr,0)
        self._bps[addr]=orig; new=(orig&~0xFF)|0xCC
        _libc.ptrace(self.PT_POKEDATA,self._pid,addr,new); return True

    def del_bp(self, addr: int) -> bool:
        if addr not in self._bps: return False
        _libc.ptrace(self.PT_POKEDATA,self._pid,addr,self._bps.pop(addr)); return True

    def read_mem(self, addr: int, size: int) -> bytes:
        out=b""
        for i in range(0,size,8):
            w=_libc.ptrace(self.PT_PEEKDATA,self._pid,addr+i,0)
            out+=struct.pack("<q",ctypes.c_long(w).value)[:min(8,size-i)]
        return out[:size]

    def get_regs(self) -> Dict:
        r=_user_regs_x64()
        if _libc.ptrace(self.PT_GETREGS,self._pid,0,ctypes.byref(r))<0: return {}
        return {"RAX":r.rax,"RBX":r.rbx,"RCX":r.rcx,"RDX":r.rdx,"RSI":r.rsi,"RDI":r.rdi,
                "RBP":r.rbp,"RSP":r.rsp,"RIP":r.rip,"R8":r.r8,"R9":r.r9,"R10":r.r10,
                "R11":r.r11,"R12":r.r12,"EFLAGS":r.eflags}

    def _restore_bp(self, addr: int):
        if addr not in self._bps: return
        _libc.ptrace(self.PT_POKEDATA,self._pid,addr,self._bps[addr])
        r=_user_regs_x64()
        if _libc.ptrace(self.PT_GETREGS,self._pid,0,ctypes.byref(r))>=0:
            r.rip-=1; _libc.ptrace(self.PT_SETREGS,self._pid,0,ctypes.byref(r))

    def _rearm_bp(self, addr: int):
        if addr in self._bps:
            _libc.ptrace(self.PT_POKEDATA,self._pid,addr,(self._bps[addr]&~0xFF)|0xCC)

    def _wait_cmd(self):
        with QMutexLocker(self._lock):
            self._cmd=None
            while self._cmd is None and self._running: self._wait.wait(self._lock,100)

    def run(self):
        last_bp=None
        while self._running:
            try: pid,status=os.waitpid(-1,os.WNOHANG)
            except ChildProcessError: self.stopped.emit("No child"); break
            if pid==0: import time; time.sleep(0.01); continue
            if os.WIFEXITED(status): self.log.emit(f"Exit({os.WEXITSTATUS(status)})"); self.stopped.emit("Exit"); break
            if os.WIFSTOPPED(status):
                sig=os.WSTOPSIG(status); regs=self.get_regs(); rip=regs.get("RIP",0)
                if sig==self.SIGTRAP:
                    bp_addr=rip-1
                    if bp_addr in self._bps:
                        self._restore_bp(bp_addr); last_bp=bp_addr
                        self.bp_hit.emit(bp_addr,regs); self.regs_rdy.emit(regs)
                        self._wait_cmd()
                        if self._cmd=="step": _libc.ptrace(self.PT_SINGLESTEP,self._pid,0,0)
                        elif self._cmd=="stop": break
                        else: _libc.ptrace(self.PT_SINGLESTEP,self._pid,0,0)
                    else:
                        if last_bp: self._rearm_bp(last_bp); last_bp=None
                        self.step_done.emit(rip,regs); self.regs_rdy.emit(regs)
                        if self._cmd=="step":
                            self._wait_cmd()
                            if self._cmd=="step": _libc.ptrace(self.PT_SINGLESTEP,self._pid,0,0)
                            elif self._cmd=="stop": break
                            else: _libc.ptrace(self.PT_CONT,self._pid,0,0)
                        else: _libc.ptrace(self.PT_CONT,self._pid,0,0)
                else:
                    self.exc_hit.emit(rip,sig); self.log.emit(f"Signal {sig} @ 0x{rip:X}")
                    self._wait_cmd()
                    if self._cmd=="stop": break
                    _libc.ptrace(self.PT_CONT,self._pid,0,sig)
        self.stopped.emit("Stopped")

# ══════════════════════════════════════════════════════════════════════════════
#  PE DIFF
# ══════════════════════════════════════════════════════════════════════════════
class PEDiff:
    def __init__(self, a: "PEAnalyzer", b: "PEAnalyzer"):
        self.a=a; self.b=b

    def sections(self) -> List[Dict]:
        s1={s["Name"]:s for s in self.a.sections()}
        s2={s["Name"]:s for s in self.b.sections()}
        out=[]
        for n in sorted(set(s1)|set(s2)):
            st=("Modified" if n in s1 and n in s2 and s1[n]["RawSize"]!=s2[n]["RawSize"]
                else "Same" if n in s1 and n in s2 else "Removed" if n in s1 else "Added")
            out.append({"Section":n,"Status":st,
                        "E1":s1[n]["EntropyF"] if n in s1 else 0,
                        "E2":s2[n]["EntropyF"] if n in s2 else 0,
                        "Sz1":s1[n]["RawSize"] if n in s1 else "—",
                        "Sz2":s2[n]["RawSize"] if n in s2 else "—"})
        return out

    def imports(self) -> Dict:
        def flat(az): return {f"{d}::{f}" for d,fs in az.imports().items() for f in fs}
        i1,i2=flat(self.a),flat(self.b)
        return {"added":sorted(i2-i1),"removed":sorted(i1-i2),"same":len(i1&i2)}

    def byte_regions(self, cap: int=200) -> List[Dict]:
        d1,d2=bytes(self.a.raw),bytes(self.b.raw); ml=min(len(d1),len(d2))
        out=[]; in_diff=False; start=0
        for i in range(ml):
            if d1[i]!=d2[i]:
                if not in_diff: in_diff=True; start=i
            elif in_diff:
                in_diff=False; out.append({"Offset":f"0x{start:08X}","Length":i-start})
                if len(out)>=cap: break
        if in_diff: out.append({"Offset":f"0x{start:08X}","Length":ml-start})
        if len(d1)!=len(d2): out.append({"Offset":f"0x{ml:08X}","Length":abs(len(d1)-len(d2)),"Note":"Size diff"})
        return out

# ══════════════════════════════════════════════════════════════════════════════
#  GHIDRA BRIDGE
# ══════════════════════════════════════════════════════════════════════════════
class GhidraBridge:
    def __init__(self): self._prog=None; self.connected=False

    def connect(self, host="localhost", port=4768) -> Tuple[bool,str]:
        if not HAS_GHI: return False,"pip install ghidra-bridge"
        try:
            import ghidra_bridge as gb
            br=gb.GhidraBridge(server_host=host,server_port=port)
            f=br.get_flat_api(); self._prog=f.getCurrentProgram()
            self.connected=bool(self._prog)
            name=str(self._prog.getName()) if self._prog else "None"
            return self.connected,f"Connected: {name}"
        except Exception as e: self.connected=False; return False,str(e)

    def functions(self) -> List[Dict]:
        if not self._prog: return []
        try:
            fm=self._prog.getFunctionManager()
            return [{"Name":str(f.getName()),"Entry":str(f.getEntryPoint()),
                     "Size":f.getBody().getNumAddresses(),"Params":f.getParameterCount()}
                    for f in fm.getFunctions(True)]
        except: return []

    def decompile(self, name: str) -> str:
        if not self._prog: return "Not connected."
        try:
            from ghidra.app.decompiler import DecompInterface
            fm=self._prog.getFunctionManager()
            tgt=next((f for f in fm.getFunctions(True) if f.getName()==name),None)
            if not tgt: return f"'{name}' not found."
            ifc=DecompInterface(); ifc.openProgram(self._prog)
            r=ifc.decompileFunction(tgt,60,None)
            return str(r.getDecompiledFunction().getC()) if r.decompileCompleted() else "Decompile failed."
        except Exception as e: return f"Error: {e}"

    def xrefs(self, addr: str) -> List[str]:
        if not self._prog: return []
        try:
            a=self._prog.parseAddress(addr)[0]
            return [str(r.getFromAddress()) for r in self._prog.getReferenceManager().getReferencesTo(a)]
        except: return []

# ══════════════════════════════════════════════════════════════════════════════
#  CORE ANALYZER
# ══════════════════════════════════════════════════════════════════════════════
class PEAnalyzer:
    def __init__(self, path: str):
        self.path = path
        if os.path.getsize(path) > 50*1024*1024:
            import mmap
            with open(path,"rb") as f:
                self._mm = mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
            self.raw = bytearray(self._mm)
        else:
            with open(path,"rb") as f: self.raw = bytearray(f.read())
            self._mm = None
        self.pe: Optional[Any] = None
        self.history = PatchHistory(self.raw)
        if HAS_PE:
            try: self.pe = pefile.PE(data=bytes(self.raw))
            except: pass

    # ── Hashing ─────────────────────────────────────────────────────────────
    def hashes(self) -> List[Tuple[str,str]]:
        d=bytes(self.raw)
        return [("MD5",hashlib.md5(d).hexdigest().upper()),
                ("SHA1",hashlib.sha1(d).hexdigest().upper()),
                ("SHA256",hashlib.sha256(d).hexdigest().upper()),
                ("Size",f"{len(d):,} bytes  ({len(d)/1024:.1f} KB)"),
                ("ImpHash",self.imphash() or "N/A")]

    def imphash(self) -> str:
        if not self.pe or not hasattr(self.pe,"DIRECTORY_ENTRY_IMPORT"): return ""
        pts=[]
        for e in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll=e.dll.decode("utf-8","replace").lower().removesuffix(".dll")
            for i in e.imports:
                fn=i.name.decode("utf-8","replace").lower() if i.name else f"ord{i.ordinal}"
                pts.append(f"{dll}.{fn}")
        return hashlib.md5(",".join(pts).encode()).hexdigest() if pts else ""

    # ── PE Headers ──────────────────────────────────────────────────────────
    def header_info(self) -> List[Tuple[str,str]]:
        if not self.pe: return [("Error","pefile not available")]
        import datetime; fh=self.pe.FILE_HEADER; oh=self.pe.OPTIONAL_HEADER; dc=oh.DllCharacteristics
        try: ts=datetime.datetime.utcfromtimestamp(fh.TimeDateStamp).strftime("%Y-%m-%d  %H:%M UTC")
        except: ts=f"0x{fh.TimeDateStamp:08X}"
        return [("Architecture",MACHINES.get(fh.Machine,f"0x{fh.Machine:04X}")),
                ("Subsystem",SUBSYSTEMS.get(oh.Subsystem,str(oh.Subsystem))),
                ("Entry Point RVA",f"0x{oh.AddressOfEntryPoint:08X}"),
                ("Image Base",f"0x{oh.ImageBase:08X}"),
                ("Image Size",f"0x{oh.SizeOfImage:08X}"),
                ("Code Base",f"0x{oh.BaseOfCode:08X}"),
                ("Number of Sections",str(fh.NumberOfSections)),
                ("File Characteristics",f"0x{fh.Characteristics:04X}"),
                ("Linker Version",f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}"),
                ("OS Version",f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}"),
                ("Compile Time",ts),
                ("ASLR","Enabled"  if dc&0x0040 else "Disabled"),
                ("DEP / NX","Enabled"  if dc&0x0100 else "Disabled"),
                ("Safe SEH","Disabled" if dc&0x0400 else "Enabled"),
                ("Control Flow Guard","Enabled" if dc&0x4000 else "Disabled"),
                ("Force Integrity","Enabled" if dc&0x0080 else "Disabled"),
                ("High-Entropy VA","Enabled" if dc&0x0020 else "Disabled")]

    def verify_checksum(self) -> Tuple[bool,int,int]:
        if not self.pe: return False,0,0
        stored=self.pe.OPTIONAL_HEADER.CheckSum
        try: calc=self.pe.generate_checksum(); return stored==calc,stored,calc
        except: return False,stored,0

    def recalculate_checksum(self) -> int:
        if not self.pe: return 0
        try:
            calc=self.pe.generate_checksum()
            nt=struct.unpack_from("<I",self.raw,0x3C)[0]
            struct.pack_into("<I",self.raw,nt+88,calc); return calc
        except: return 0

    # ── Rich Header ─────────────────────────────────────────────────────────
    def rich_header(self) -> List[Dict]:
        try:
            elf=struct.unpack_from("<I",self.raw,0x3C)[0]; rich_off=None
            for i in range(min(elf,len(self.raw))-4,0x80,-4):
                if bytes(self.raw[i:i+4])==b"Rich": rich_off=i; break
            if rich_off is None: return []
            key=struct.unpack_from("<I",self.raw,rich_off+4)[0]; dans=None
            for i in range(rich_off-4,0x7C,-4):
                if struct.unpack_from("<I",self.raw,i)[0]^key==0x536E6144: dans=i; break
            if dans is None: return []
            PROD={1:"Import0",2:"Linker510",34:"MASM",45:"LINK710",
                  101:"VC2003",102:"VC2005",103:"VC2008",104:"VC2010",
                  105:"VC2012",106:"VC2013",107:"VC2015",108:"VC2017",
                  109:"VC2019",110:"VC2022"}
            pos=dans+16; out=[]
            while pos+8<=rich_off:
                ri=struct.unpack_from("<I",self.raw,pos)[0]^key
                rc=struct.unpack_from("<I",self.raw,pos+4)[0]^key
                pid=(ri>>16)&0xFFFF; bld=ri&0xFFFF
                out.append({"ProductID":pid,"Build":bld,"Count":rc,
                             "Name":PROD.get(pid,f"Product_{pid}")}); pos+=8
            return out
        except: return []

    # ── Sections ────────────────────────────────────────────────────────────
    def sections(self) -> List[Dict]:
        if not self.pe: return []
        out=[]
        for s in self.pe.sections:
            n=s.Name.decode("utf-8","replace").rstrip("\x00").strip()
            data=s.get_data(); ent=self.entropy(data)
            out.append({"Name":n or "(unnamed)",
                        "VirtAddr":f"0x{s.VirtualAddress:08X}",
                        "VirtSize":f"0x{s.Misc_VirtualSize:08X}",
                        "RawOffset":f"0x{s.PointerToRawData:08X}",
                        "RawSize":f"0x{s.SizeOfRawData:08X}",
                        "Entropy":f"{ent:.3f}","EntropyF":ent,
                        "R":bool(s.Characteristics&0x40000000),
                        "W":bool(s.Characteristics&0x80000000),
                        "X":bool(s.Characteristics&0x20000000),
                        "Chars":f"0x{s.Characteristics:08X}"})
        return out

    # ── Imports / Exports ────────────────────────────────────────────────────
    def imports(self) -> Dict[str,List[str]]:
        if not self.pe or not hasattr(self.pe,"DIRECTORY_ENTRY_IMPORT"): return {}
        return {e.dll.decode("utf-8","replace"):
                [i.name.decode("utf-8","replace") if i.name else f"Ord#{i.ordinal}" for i in e.imports]
                for e in self.pe.DIRECTORY_ENTRY_IMPORT}

    def exports(self) -> List[Dict]:
        if not self.pe or not hasattr(self.pe,"DIRECTORY_ENTRY_EXPORT"): return []
        return [{"Name":e.name.decode("utf-8","replace") if e.name else f"Ord#{e.ordinal}",
                 "Ordinal":e.ordinal,"RVA":f"0x{e.address:08X}"}
                for e in self.pe.DIRECTORY_ENTRY_EXPORT.symbols]

    # ── Relocations ─────────────────────────────────────────────────────────
    def relocations(self) -> List[Dict]:
        if not self.pe or not hasattr(self.pe,"DIRECTORY_ENTRY_BASERELOC"): return []
        RT={0:"ABSOLUTE",1:"HIGH",2:"LOW",3:"HIGHLOW",4:"HIGHADJ",10:"DIR64"}
        return [{"VirtAddr":f"0x{b.struct.VirtualAddress+e.rva:08X}","Type":RT.get(e.type,str(e.type))}
                for b in self.pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries]

    # ── TLS ─────────────────────────────────────────────────────────────────
    def tls(self) -> List[Tuple[str,str]]:
        if not self.pe or not hasattr(self.pe,"DIRECTORY_ENTRY_TLS"): return []
        t=self.pe.DIRECTORY_ENTRY_TLS.struct
        return [("Start Address of Raw Data",f"0x{t.StartAddressOfRawData:08X}"),
                ("End Address of Raw Data",  f"0x{t.EndAddressOfRawData:08X}"),
                ("Address of Index",         f"0x{t.AddressOfIndex:08X}"),
                ("Address of Callbacks",     f"0x{t.AddressOfCallBacks:08X}"),
                ("Size of Zero Fill",        str(t.SizeOfZeroFill)),
                ("Characteristics",          f"0x{t.Characteristics:08X}")]

    # ── Resources ───────────────────────────────────────────────────────────
    def resources(self) -> List[Dict]:
        if not self.pe or not hasattr(self.pe,"DIRECTORY_ENTRY_RESOURCE"): return []
        out=[]
        for rt in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            tn=RESOURCE_TYPES.get(rt.struct.Id,f"Type_{rt.struct.Id}")
            if hasattr(rt,"directory"):
                for ri in rt.directory.entries:
                    if hasattr(ri,"directory"):
                        for rl in ri.directory.entries:
                            de=rl.data.struct
                            out.append({"Type":tn,"ID":ri.struct.Id,"Lang":rl.struct.Id,
                                        "RVA":f"0x{de.OffsetToData:08X}","Size":de.Size})
        return out

    # ── Debug Info ──────────────────────────────────────────────────────────
    def debug_info(self) -> List[Dict]:
        if not self.pe or not hasattr(self.pe,"DIRECTORY_ENTRY_DEBUG"): return []
        DT={1:"COFF",2:"CodeView",3:"FPO",4:"MISC",9:"Borland",13:"VC Feature",14:"POGO",16:"REPRO"}
        out=[]
        for d in self.pe.DIRECTORY_ENTRY_DEBUG:
            s=d.struct
            e={"Type":DT.get(s.Type,str(s.Type)),"RVA":f"0x{s.AddressOfRawData:08X}","Size":s.SizeOfData,"PDB Path":""}
            if s.Type==2 and s.PointerToRawData:
                try:
                    off=s.PointerToRawData; sig=bytes(self.raw[off:off+4])
                    end=off+s.SizeOfData
                    if sig==b"RSDS": e["PDB Path"]=bytes(self.raw[off+24:end]).split(b"\x00")[0].decode("utf-8","replace")
                    elif sig==b"NB10": e["PDB Path"]=bytes(self.raw[off+16:end]).split(b"\x00")[0].decode("utf-8","replace")
                except: pass
            out.append(e)
        return out

    # ── Entropy ─────────────────────────────────────────────────────────────
    def entropy(self, data: bytes) -> float:
        if not data: return 0.0
        c=Counter(data); t=len(data)
        return -sum((v/t)*math.log2(v/t) for v in c.values() if v>0)

    # ── Overlay ─────────────────────────────────────────────────────────────
    def overlay(self) -> Dict:
        if not self.pe: return {}
        try:
            end=max((s.PointerToRawData+s.SizeOfRawData for s in self.pe.sections),default=0)
            fa=self.pe.OPTIONAL_HEADER.FileAlignment; end=(end+fa-1)&~(fa-1)
            if end>=len(self.raw): return {"present":False,"offset":end,"size":0}
            ov=bytes(self.raw[end:])
            return {"present":True,"offset":end,"size":len(ov),"entropy":self.entropy(ov),
                    "preview":" ".join(f"{b:02X}" for b in ov[:32]),
                    "is_zip":ov[:4]==b"PK\x03\x04","is_pe":ov[:2]==b"MZ","is_elf":ov[:4]==b"\x7fELF"}
        except: return {}

    # ── Code Caves ──────────────────────────────────────────────────────────
    def find_code_caves(self, min_size: int=32, byte: int=0x00) -> List[Dict]:
        caves=[]; data=bytes(self.raw); i=0
        while i<len(data):
            if data[i]==byte:
                j=i
                while j<len(data) and data[j]==byte: j+=1
                if j-i>=min_size:
                    sn="?"; sv=0
                    if self.pe:
                        for s in self.pe.sections:
                            if s.PointerToRawData<=i<s.PointerToRawData+s.SizeOfRawData:
                                sn=s.Name.decode("utf-8","replace").rstrip("\x00").strip()
                                sv=self.pe.OPTIONAL_HEADER.ImageBase+s.VirtualAddress+(i-s.PointerToRawData); break
                    caves.append({"Offset":f"0x{i:08X}","VA":f"0x{sv:08X}","Size":j-i,"Section":sn,"Byte":f"0x{byte:02X}","Usable":j-i>=64})
                i=j
            else: i+=1
        return caves

    # ── Crypto Detection ────────────────────────────────────────────────────
    def detect_crypto(self) -> List[Dict]:
        raw=bytes(self.raw); out=[]
        for name,pat,desc in CRYPTO_SIGS:
            pos=0
            while True:
                idx=raw.find(pat,pos)
                if idx<0: break
                sn="?"
                if self.pe:
                    for s in self.pe.sections:
                        if s.PointerToRawData<=idx<s.PointerToRawData+s.SizeOfRawData:
                            sn=s.Name.decode("utf-8","replace").rstrip("\x00").strip(); break
                out.append({"Name":name,"Offset":f"0x{idx:08X}","Section":sn,"Desc":desc}); pos=idx+1
        return out

    # ── Strings ─────────────────────────────────────────────────────────────
    def strings(self, min_len: int=5) -> List[Dict]:
        data=bytes(self.raw); out=[]
        for m in re.finditer(rb"[\x20-\x7E]{"+str(min_len).encode()+rb",}",data):
            out.append({"Offset":f"0x{m.start():08X}","Type":"ASCII","String":m.group().decode("ascii","replace")})
        for m in re.finditer(rb"(?:[\x20-\x7E]\x00){"+str(min_len).encode()+rb",}",data):
            s=m.group().decode("utf-16-le","replace").rstrip("\x00")
            if len(s)>=min_len: out.append({"Offset":f"0x{m.start():08X}","Type":"UTF-16","String":s})
        return out[:8000]

    # ── Network ─────────────────────────────────────────────────────────────
    def network_indicators(self) -> Dict[str,List[str]]:
        d=self.raw.decode("latin-1")
        return {"URLs":sorted(set(re.findall(r"https?://[^\s\x00\"'<>]{4,100}",d))),
                "IPs":sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",d))),
                "Emails":sorted(set(re.findall(r"[\w.+\-]+@[\w\-]+\.[\w.]{2,}",d))),
                "Domains":sorted(set(re.findall(r"(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|ru|xyz|info|gov|edu)\b",d)))}

    # ── Packer / Compiler / Anti-Debug / Suspicious ──────────────────────────
    def detect_packer(self) -> Dict:
        r={"packed":False,"packer":None,"indicators":[]}
        raw=bytes(self.raw).lower()
        for n,sigs in PACKER_SIGS.items():
            for s in sigs:
                if s.lower() in raw: r["packed"]=True; r["packer"]=n; r["indicators"].append(f"Sig: {s.decode('latin-1')}"); break
        if self.pe:
            for s in self.pe.sections:
                ent=self.entropy(s.get_data())
                if ent>7.2:
                    nm=s.Name.decode("utf-8","replace").rstrip("\x00").strip()
                    r["packed"]=True; r["indicators"].append(f"High entropy: {nm} ({ent:.2f})")
            if hasattr(self.pe,"DIRECTORY_ENTRY_IMPORT"):
                ai=[i.name.decode("utf-8","replace") for e in self.pe.DIRECTORY_ENTRY_IMPORT for i in e.imports if i.name]
                if len(ai)<5: r["packed"]=True; r["indicators"].append(f"Very few imports: {len(ai)}")
        return r

    def detect_compiler(self) -> List[str]:
        raw=bytes(self.raw).lower()
        return [n for n,ss in COMPILER_SIGS.items() if any(s.lower() in raw for s in ss)] or ["Unknown"]

    def detect_antidebug(self) -> List[str]:
        if not self.pe or not hasattr(self.pe,"DIRECTORY_ENTRY_IMPORT"): return []
        return sorted({i.name.decode("utf-8","replace") for e in self.pe.DIRECTORY_ENTRY_IMPORT
                       for i in e.imports if i.name and i.name.decode("utf-8","replace") in ANTIDEBUG_APIS})

    def suspicious_imports(self) -> List[str]:
        if not self.pe or not hasattr(self.pe,"DIRECTORY_ENTRY_IMPORT"): return []
        return sorted({i.name.decode("utf-8","replace") for e in self.pe.DIRECTORY_ENTRY_IMPORT
                       for i in e.imports if i.name and i.name.decode("utf-8","replace") in SUSPICIOUS_APIS})

    # ── Function Prologues ───────────────────────────────────────────────────
    def find_function_prologues(self) -> List[Dict]:
        if not self.pe: return []
        raw=bytes(self.raw); out=[]; seen=set()
        for sec in self.pe.sections:
            if not (sec.Characteristics&0x20000000): continue
            s=sec.PointerToRawData; sd=raw[s:s+sec.SizeOfRawData]
            sn=sec.Name.decode("utf-8","replace").rstrip("\x00").strip()
            for pro,desc in PROLOGUES:
                pos=0
                while True:
                    idx=sd.find(pro,pos)
                    if idx<0: break
                    fo=s+idx
                    if fo not in seen:
                        seen.add(fo); va=self.pe.OPTIONAL_HEADER.ImageBase+sec.VirtualAddress+idx
                        out.append({"Offset":f"0x{fo:08X}","VA":f"0x{va:08X}","Prologue":desc,"Section":sn})
                    pos=idx+1
        out.sort(key=lambda r:r["Offset"]); return out[:2000]

    # ── Disassembler ────────────────────────────────────────────────────────
    def disassemble(self, offset: int, size: int=256) -> List[Dict]:
        if not HAS_CAP: return []
        is64=bool(self.pe and self.pe.FILE_HEADER.Machine==0x8664)
        md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
        chunk=bytes(self.raw[offset:offset+size]); base=0
        if self.pe:
            for s in self.pe.sections:
                if s.PointerToRawData<=offset<s.PointerToRawData+s.SizeOfRawData:
                    base=self.pe.OPTIONAL_HEADER.ImageBase+s.VirtualAddress+(offset-s.PointerToRawData); break
        return [{"Address":f"0x{i.address:08X}","Bytes":" ".join(f"{b:02X}" for b in i.bytes),
                 "Mnemonic":i.mnemonic,"Operands":i.op_str} for i in md.disasm(chunk,base)]

    def ep_offset(self) -> Optional[int]:
        if not self.pe: return None
        try: return self.pe.get_offset_from_rva(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        except: return None

    # ── CFG ─────────────────────────────────────────────────────────────────
    def build_cfg(self, offset: int, max_bytes: int=2048) -> List[Dict]:
        if not HAS_CAP: return []
        is64=bool(self.pe and self.pe.FILE_HEADER.Machine==0x8664)
        md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
        md.detail=True; chunk=bytes(self.raw[offset:offset+max_bytes]); base=0
        if self.pe:
            for s in self.pe.sections:
                if s.PointerToRawData<=offset<s.PointerToRawData+s.SizeOfRawData:
                    base=self.pe.OPTIONAL_HEADER.ImageBase+s.VirtualAddress+(offset-s.PointerToRawData); break
        instrs=list(md.disasm(chunk,base))
        if not instrs: return []
        addrs=[i.address for i in instrs]
        JMP={"jmp","je","jne","jz","jnz","jl","jg","jle","jge","jb","ja","js","jns","jc","jnc","loop"}
        RET={"ret","retn","retf","iret","iretd","iretq"}
        leaders={addrs[0]}
        for ins in instrs:
            mn=ins.mnemonic
            if mn in JMP:
                try: leaders.add(int(ins.op_str,16))
                except: pass
                idx=addrs.index(ins.address)
                if idx+1<len(addrs): leaders.add(addrs[idx+1])
            elif mn in RET:
                idx=addrs.index(ins.address)
                if idx+1<len(addrs): leaders.add(addrs[idx+1])
        blocks=[]; cur=None
        for ins in instrs:
            if ins.address in leaders:
                if cur: blocks.append(cur)
                cur={"addr":ins.address,"instrs":[],"successors":[]}
            if cur:
                cur["instrs"].append({"Address":f"0x{ins.address:08X}",
                                      "Bytes":" ".join(f"{b:02X}" for b in ins.bytes),
                                      "Mnemonic":ins.mnemonic,"Operands":ins.op_str})
                if ins.mnemonic in JMP or ins.mnemonic in RET: blocks.append(cur); cur=None
        if cur: blocks.append(cur)
        for i,b in enumerate(blocks):
            if not b["instrs"]: continue
            last=b["instrs"][-1]; mn=last["Mnemonic"]
            if mn not in RET:
                if mn in JMP:
                    try: b["successors"].append(int(last["Operands"],16))
                    except: pass
                    if mn!="jmp" and i+1<len(blocks): b["successors"].append(blocks[i+1]["addr"])
                elif i+1<len(blocks): b["successors"].append(blocks[i+1]["addr"])
        return blocks

    # ── Section Injector ────────────────────────────────────────────────────
    def inject_section(self, name: str, data: bytes, chars: int=0x60000020) -> Tuple[bool,str]:
        if not self.pe: return False,"pefile not loaded."
        try:
            fa=self.pe.OPTIONAL_HEADER.FileAlignment; sa=self.pe.OPTIONAL_HEADER.SectionAlignment
            nt=struct.unpack_from("<I",self.raw,0x3C)[0]
            nsec=struct.unpack_from("<H",self.raw,nt+6)[0]
            ohsz=struct.unpack_from("<H",self.raw,nt+20)[0]
            st=nt+4+20+ohsz; he=st+nsec*40
            fr=min((s.PointerToRawData for s in self.pe.sections if s.PointerToRawData),default=0)
            if fr-he<40: return False,f"No header space ({fr-he}B available)"
            last=max(self.pe.sections,key=lambda s:s.PointerToRawData+s.SizeOfRawData)
            nr=(last.PointerToRawData+last.SizeOfRawData+fa-1)&~(fa-1)
            nva=(last.VirtualAddress+last.Misc_VirtualSize+sa-1)&~(sa-1)
            rsz=(len(data)+fa-1)&~(fa-1); pad=data+b"\x00"*(rsz-len(data))
            nb=name.encode("ascii")[:8].ljust(8,b"\x00")
            hdr=struct.pack("<8sIIIIIIHHI",nb,len(data),nva,rsz,nr,0,0,0,0,chars)
            self.raw[he:he+40]=hdr
            while len(self.raw)<nr: self.raw.append(0)
            self.raw.extend(pad)
            struct.pack_into("<H",self.raw,nt+6,nsec+1)
            struct.pack_into("<I",self.raw,nt+80,nva+(len(data)+sa-1)&~(sa-1))
            return True,f"Added '{name}'  VA=0x{nva:08X}  Off=0x{nr:08X}  Size={rsz}"
        except Exception as e: return False,str(e)

    # ── Patching ────────────────────────────────────────────────────────────
    def patch_byte(self, off: int, new: int): self.history.apply(off,self.raw[off],new)
    def undo(self): return self.history.undo()
    def redo(self): return self.history.redo()
    def undo_all(self): self.history.undo_all()
    def save(self, path: Optional[str]=None):
        with open(path or self.path,"wb") as f: f.write(bytes(self.raw))

    # ── YARA ────────────────────────────────────────────────────────────────
    def yara_rule(self) -> str:
        name=re.sub(r"[^a-zA-Z0-9_]","_",Path(self.path).stem)
        lines=[f"rule {name} {{","    meta:",
               f'        description = "Auto-generated by KRE"',
               f'        filename    = "{Path(self.path).name}"',
               f'        imphash     = "{self.imphash()}"',"","    strings:"]
        i=1
        if self.pe:
            try:
                off=self.ep_offset()
                if off: lines.append(f"        $ep{i} = {{ {' '.join(f'{b:02X}' for b in self.raw[off:off+12])} }}"); i+=1
            except: pass
        for s in self.strings(min_len=12)[:8]:
            safe=s["String"].replace('"','\\"')[:80]
            if safe.isprintable() and len(safe)>=12: lines.append(f'        $s{i} = "{safe}"'); i+=1
        lines+=["","    condition:",
                f"        uint16(0) == 0x5A4D and filesize < {len(self.raw)*4} and any of them","}}"]
        return "\n".join(lines)

    # ── File Map ────────────────────────────────────────────────────────────
    def file_map(self) -> List[Dict]:
        COLS=["#0071E3","#34C759","#FF9500","#FF3B30","#AF52DE","#5856D6","#FF2D55","#32ADE6","#FFCC00","#30B0C7"]
        r=[{"Name":"DOS Header","Start":0,"End":0x40,"Color":"#6E6E73"}]
        if not self.pe: return r
        try:
            elf=struct.unpack_from("<I",self.raw,0x3C)[0]
            r.append({"Name":"NT Headers","Start":elf,"End":elf+0x108,"Color":"#8E8E93"})
        except: pass
        for idx,s in enumerate(self.pe.sections):
            n=s.Name.decode("utf-8","replace").rstrip("\x00").strip()
            r.append({"Name":n or f"Sec{idx}","Start":s.PointerToRawData,
                      "End":s.PointerToRawData+s.SizeOfRawData,"Color":COLS[idx%len(COLS)]})
        return sorted(r,key=lambda x:x["Start"])

# ══════════════════════════════════════════════════════════════════════════════
#  GUI HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def kv_table(rows: List[Tuple[str,str]]) -> QTableWidget:
    t=QTableWidget(len(rows),2); t.setHorizontalHeaderLabels(["Property","Value"])
    t.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
    t.verticalHeader().setVisible(False); t.setColumnWidth(0,200)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    for row,(k,v) in enumerate(rows):
        t.setRowHeight(row,26); ki=QTableWidgetItem(str(k)); ki.setForeground(QColor(C["sec"]))
        t.setItem(row,0,ki); t.setItem(row,1,QTableWidgetItem(str(v)))
    return t

class EntropyBar(QWidget):
    BH=26; SP=7
    def __init__(self,secs: List[Tuple[str,float]],parent=None):
        super().__init__(parent); self.secs=secs
        self.setMinimumHeight(len(secs)*(self.BH+self.SP)+24)
    def paintEvent(self,_):
        if not self.secs: return
        p=QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w=self.width(); L=95; R=52
        for i,(nm,ent) in enumerate(self.secs):
            y=i*(self.BH+self.SP)+8; bw=w-L-R
            p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(C["border"])); p.drawRoundedRect(L,y,bw,self.BH,5,5)
            col=C["green"] if ent<5 else C["orange"] if ent<7 else C["red"]
            p.setBrush(QColor(col)); p.drawRoundedRect(L,y,max(int(bw*min(ent/8,1)),4),self.BH,5,5)
            p.setPen(QColor(C["text"])); p.setFont(QFont(C["mono"].split(",")[0],11))
            p.drawText(0,y,L-6,self.BH,Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter,nm[:10])
            p.setPen(QColor(col)); p.setFont(QFont(C["mono"].split(",")[0],11,QFont.Weight.Bold))
            p.drawText(w-R+4,y,R-4,self.BH,Qt.AlignmentFlag.AlignVCenter,f"{ent:.2f}")

class FileMapBar(QWidget):
    def __init__(self,regions,total,parent=None):
        super().__init__(parent); self.regions=regions; self.total=total; self.setFixedHeight(72)
    def paintEvent(self,_):
        if not self.regions or not self.total: return
        p=QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w=self.width()-24; H=28; Y=8
        for r in self.regions:
            sx=12+int(r["Start"]/self.total*w); ex=12+int(r["End"]/self.total*w)
            p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(r["Color"])); p.drawRect(sx,Y,max(ex-sx,2),H)
        p.setPen(QPen(QColor(C["border"]),1)); p.setBrush(Qt.BrushStyle.NoBrush); p.drawRoundedRect(12,Y,w,H,4,4)
        lx=12; p.setFont(QFont(C["sans"].split(",")[0],10))
        for r in self.regions[:8]:
            p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(r["Color"])); p.drawRoundedRect(lx,Y+H+6,10,10,2,2)
            p.setPen(QColor(C["sec"])); p.drawText(lx+13,Y+H+4,72,14,0,r["Name"][:8]); lx+=82

# ══════════════════════════════════════════════════════════════════════════════
#  HEX EDITOR WIDGET
# ══════════════════════════════════════════════════════════════════════════════
class HexEditor(QWidget):
    patch_applied = pyqtSignal(int,int,int)
    COLS=16; MAX_ROWS=4096

    def __init__(self, data: bytearray, parent=None):
        super().__init__(parent); self.data=data; self._editing=False; self._voff=0; self._setup()

    def _setup(self):
        lay=QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(6)
        bar=QHBoxLayout()
        self.goto_e=QLineEdit(); self.goto_e.setPlaceholderText("Go to offset (hex)..."); self.goto_e.setFixedWidth(160)
        self.goto_e.returnPressed.connect(self._goto)
        gb=QPushButton("Go"); gb.setFixedWidth(44); gb.clicked.connect(self._goto)
        self.find_e=QLineEdit(); self.find_e.setPlaceholderText("Find bytes  4D 5A 90 00"); self.find_e.setFixedWidth(240)
        self.find_e.returnPressed.connect(self._find)
        fb=QPushButton("Find"); fb.setFixedWidth(44); fb.clicked.connect(self._find)
        self.edit_btn=QPushButton("Edit Mode"); self.edit_btn.setProperty("sec","true")
        self.edit_btn.setCheckable(True); self.edit_btn.toggled.connect(self._toggle_edit)
        self.info_lbl=QLabel(""); self.info_lbl.setProperty("sub","true")
        bar.addWidget(self.goto_e); bar.addWidget(gb); bar.addSpacing(10)
        bar.addWidget(self.find_e); bar.addWidget(fb); bar.addStretch(); bar.addWidget(self.edit_btn)
        lay.addLayout(bar)
        self.tbl=QTableWidget(); self.tbl.setColumnCount(18)
        hdr=["Offset"]+[f"{i:02X}" for i in range(16)]+["ASCII"]
        self.tbl.setHorizontalHeaderLabels(hdr)
        self.tbl.horizontalHeader().setFont(QFont(C["mono"].split(",")[0],10))
        self.tbl.verticalHeader().setVisible(False); self.tbl.setFont(QFont(C["mono"].split(",")[0],11))
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl.setColumnWidth(0,90)
        for c in range(1,17): self.tbl.setColumnWidth(c,30)
        self.tbl.horizontalHeader().setStretchLastSection(True)
        self.tbl.cellChanged.connect(self._on_changed); self._populate()
        lay.addWidget(self.tbl); lay.addWidget(self.info_lbl)

    def _populate(self):
        s=self._voff; e=min(len(self.data),s+self.MAX_ROWS*16)
        vis=self.data[s:e]; rows=math.ceil(len(vis)/16)
        self.tbl.blockSignals(True); self.tbl.setRowCount(rows)
        for row in range(rows):
            self.tbl.setRowHeight(row,20); off=s+row*16
            oi=QTableWidgetItem(f"{off:08X}"); oi.setForeground(QColor(C["sec"]))
            oi.setFlags(oi.flags()&~Qt.ItemFlag.ItemIsEditable); self.tbl.setItem(row,0,oi)
            asc=""
            for col in range(16):
                bi=row*16+col
                if bi<len(vis):
                    bv=vis[bi]; it=QTableWidgetItem(f"{bv:02X}")
                    it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    it.setForeground(QColor(C["sec"] if bv==0 else C["red"] if bv<0x20 or bv>0x7E else C["text"]))
                    self.tbl.setItem(row,col+1,it); asc+=chr(bv) if 0x20<=bv<=0x7E else "."
                else:
                    ei=QTableWidgetItem(""); ei.setFlags(ei.flags()&~Qt.ItemFlag.ItemIsEditable)
                    self.tbl.setItem(row,col+1,ei)
            ai=QTableWidgetItem(asc); ai.setFlags(ai.flags()&~Qt.ItemFlag.ItemIsEditable)
            self.tbl.setItem(row,17,ai)
        self.tbl.blockSignals(False)

    def update_data(self, data: bytearray): self.data=data; self._populate()

    def jump_to(self, off: int):
        self.goto_e.setText(f"{off:X}"); self._goto()

    def _toggle_edit(self, on: bool):
        self._editing=on
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked if on else QAbstractItemView.EditTrigger.NoEditTriggers)
        self.edit_btn.setStyleSheet(f"background:{C['orange']};color:white;border:none;border-radius:6px;padding:7px 16px;" if on else "")

    def _on_changed(self, row, col):
        if not self._editing or col in(0,17): return
        it=self.tbl.item(row,col)
        if not it: return
        try:
            val=max(0,min(255,int(it.text(),16))); off=self._voff+row*16+(col-1)
            if off<len(self.data):
                old=self.data[off]; self.data[off]=val
                self.tbl.blockSignals(True); it.setText(f"{val:02X}")
                ai=self.tbl.item(row,17)
                if ai: ai.setText("".join(chr(b) if 0x20<=b<=0x7E else "." for b in self.data[self._voff+row*16:self._voff+(row+1)*16]))
                self.tbl.blockSignals(False); self.patch_applied.emit(off,old,val)
        except:
            off=self._voff+row*16+(col-1)
            if off<len(self.data):
                self.tbl.blockSignals(True); it.setText(f"{self.data[off]:02X}"); self.tbl.blockSignals(False)

    def _goto(self):
        try:
            off=int(self.goto_e.text().strip().lstrip("0x") or "0",16)
            off=max(0,min(off,len(self.data)-1))
            self._voff=max(0,(off//16-(self.MAX_ROWS//2))*16); self._populate()
            row=(off-self._voff)//16; col=(off%16)+1
            if 0<=row<self.tbl.rowCount():
                self.tbl.scrollToItem(self.tbl.item(row,0)); self.tbl.setCurrentCell(row,col)
            self.info_lbl.setText(f"View from 0x{self._voff:08X}")
        except: self.info_lbl.setText("Invalid offset.")

    def _find(self):
        try:
            needle=bytes.fromhex(self.find_e.text().replace(" ",""))
            idx=bytes(self.data).find(needle)
            if idx>=0: self.goto_e.setText(f"{idx:X}"); self._goto(); self.info_lbl.setText(f"Found 0x{idx:08X}")
            else: self.info_lbl.setText("Not found.")
        except: self.info_lbl.setText("Invalid pattern.")

# ══════════════════════════════════════════════════════════════════════════════
#  DISASSEMBLER WIDGET
# ══════════════════════════════════════════════════════════════════════════════
class DisasmWidget(QWidget):
    JUMPS={"jmp","je","jne","jz","jnz","jl","jg","jle","jge","jb","ja","js","jns","jc","jnc","jp","jnp"}

    def __init__(self, parent=None):
        super().__init__(parent); self.az=None; self._setup()

    def _setup(self):
        lay=QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(6)
        bar=QHBoxLayout()
        self.off_e=QLineEdit("0"); self.off_e.setPlaceholderText("File offset (hex)"); self.off_e.setFixedWidth(150)
        self.sz_e=QLineEdit("512"); self.sz_e.setFixedWidth(70)
        ep=QPushButton("Entry Point"); ep.setProperty("sec","true"); ep.clicked.connect(self._ep)
        go=QPushButton("Disassemble"); go.clicked.connect(self._run)
        bar.addWidget(QLabel("Offset:")); bar.addWidget(self.off_e)
        bar.addWidget(QLabel("Bytes:")); bar.addWidget(self.sz_e)
        bar.addWidget(ep); bar.addStretch(); bar.addWidget(go)
        lay.addLayout(bar)
        if not HAS_CAP:
            l=QLabel("capstone not installed\npip install capstone"); l.setProperty("sub","true"); lay.addWidget(l); return
        self.tbl=QTableWidget(); self.tbl.setColumnCount(4)
        self.tbl.setHorizontalHeaderLabels(["Address","Bytes","Mnemonic","Operands"])
        self.tbl.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeMode.Stretch)
        self.tbl.setColumnWidth(0,105); self.tbl.setColumnWidth(1,175); self.tbl.setColumnWidth(2,105)
        self.tbl.verticalHeader().setVisible(False); self.tbl.setFont(QFont(C["mono"].split(",")[0],11))
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        lay.addWidget(self.tbl)

    def set_analyzer(self, az): self.az=az
    def jump_to(self, off: int): self.off_e.setText(f"{off:X}"); self._run()

    def _ep(self):
        if self.az:
            off=self.az.ep_offset()
            if off is not None: self.off_e.setText(f"{off:X}"); self._run()

    def _run(self):
        if not self.az or not HAS_CAP or not hasattr(self,"tbl"): return
        try: off=int(self.off_e.text().strip() or "0",16)
        except: off=0
        try: sz=int(self.sz_e.text())
        except: sz=512
        ins=self.az.disassemble(off,sz); self.tbl.setRowCount(len(ins))
        for row,i in enumerate(ins):
            self.tbl.setRowHeight(row,20); mn=i["Mnemonic"]
            MONO=C["mono"].split(",")[0]
            ai=QTableWidgetItem(i["Address"]); ai.setForeground(QColor(C["sec"]))
            bi=QTableWidgetItem(i["Bytes"]); bi.setForeground(QColor(C["green"]))
            mi=QTableWidgetItem(mn)
            if mn=="call": mi.setForeground(QColor(C["orange"])); mi.setFont(QFont(MONO,11,QFont.Weight.Bold))
            elif mn in self.JUMPS: mi.setForeground(QColor(C["accent"]))
            elif mn in("ret","retn","retf","iret"): mi.setForeground(QColor(C["red"])); mi.setFont(QFont(MONO,11,QFont.Weight.Bold))
            elif mn=="nop": mi.setForeground(QColor(C["sec"]))
            else: mi.setForeground(QColor(C["text"]))
            oi=QTableWidgetItem(i["Operands"]); oi.setForeground(QColor(C["text"]))
            for col,it in enumerate([ai,bi,mi,oi]): self.tbl.setItem(row,col,it)

# ══════════════════════════════════════════════════════════════════════════════
#  CFG VIEW
# ══════════════════════════════════════════════════════════════════════════════
class CFGView(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent); self._sc=QGraphicsScene(self); self.setScene(self._sc)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setRenderHints(QPainter.RenderHint.Antialiasing|QPainter.RenderHint.TextAntialiasing)
        self.setBackgroundBrush(QBrush(QColor(C["bg"])))

    def wheelEvent(self,e):
        f=1.15 if e.angleDelta().y()>0 else 1/1.15; self.scale(f,f)

    def set_blocks(self, blocks: List[Dict]):
        self._sc.clear()
        if not blocks: return
        MONO=C["mono"].split(",")[0]; BFONT=QFont(MONO,9)
        fm=QFontMetrics(BFONT); LH=fm.height()+2; PAD=8; BW=320
        for i,b in enumerate(blocks):
            nh=len(b["instrs"])*LH+2*PAD+22
            b["_x"]=40+(i%3)*(BW+60); b["_y"]=40+(i//3)*(max(nh,60)+60); b["_w"]=BW; b["_h"]=nh
        ab={b["addr"]:b for b in blocks}
        for b in blocks:
            bx,by,bw,bh=b["_x"],b["_y"],b["_w"],b["_h"]
            for ki,sa in enumerate(b.get("successors",[])):
                tb=ab.get(sa)
                if not tb: continue
                tx,ty,tw=tb["_x"],tb["_y"],tb["_w"]
                sx2,sy2=bx+bw/2,by+bh; dx,dy=tx+tw/2,ty
                pen=QPen(QColor(C["accent"] if ki==0 else C["sec"]),1.5)
                self._sc.addLine(sx2,sy2,dx,dy,pen)
                ang=math.atan2(dy-sy2,dx-sx2); al=8
                p1=QPointF(dx-al*math.cos(ang-0.4),dy-al*math.sin(ang-0.4))
                p2=QPointF(dx-al*math.cos(ang+0.4),dy-al*math.sin(ang+0.4))
                self._sc.addPolygon(QPolygonF([QPointF(dx,dy),p1,p2]),pen,QBrush(QColor(C["accent"] if ki==0 else C["sec"])))
        for b in blocks:
            bx,by,bw,bh=b["_x"],b["_y"],b["_w"],b["_h"]
            last=b["instrs"][-1] if b["instrs"] else None
            is_ret=last and last["Mnemonic"] in("ret","retn","retf","iret")
            rect=QGraphicsRectItem(bx,by,bw,bh); rect.setBrush(QBrush(QColor(C["surface"])))
            rect.setPen(QPen(QColor(C["border"]),1.5)); rect.setZValue(1); self._sc.addItem(rect)
            hdr=QGraphicsRectItem(bx,by,bw,22)
            hdr.setBrush(QBrush(QColor(C["red"]+"30" if is_ret else C["accent"]+"20")))
            hdr.setPen(QPen(Qt.PenStyle.NoPen)); hdr.setZValue(2); self._sc.addItem(hdr)
            at=self._sc.addText(f"0x{b['addr']:08X}" if isinstance(b["addr"],int) else str(b["addr"]),QFont(MONO,9,QFont.Weight.Bold))
            at.setDefaultTextColor(QColor(C["accent"])); at.setPos(bx+PAD,by+3); at.setZValue(3)
            iy=by+22+PAD
            for ins in b["instrs"]:
                mn=ins["Mnemonic"]
                col=C["orange"] if mn=="call" else C["accent"] if mn.startswith("j") else C["red"] if mn in("ret","retn") else C["text"]
                ti=self._sc.addText(f"{mn:<8} {ins['Operands']}",BFONT)
                ti.setDefaultTextColor(QColor(col)); ti.setPos(bx+PAD,iy); ti.setZValue(3); iy+=LH
        self._sc.setSceneRect(self._sc.itemsBoundingRect().adjusted(-40,-40,40,40))

# ══════════════════════════════════════════════════════════════════════════════
#  BASE PANEL
# ══════════════════════════════════════════════════════════════════════════════
def _scaffold(title: str) -> Tuple[QWidget,QVBoxLayout]:
    w=QWidget(); w.setStyleSheet(f"background:{C['bg']};")
    lay=QVBoxLayout(w); lay.setContentsMargins(28,24,28,28); lay.setSpacing(16)
    t=QLabel(title); t.setProperty("h","true"); lay.addWidget(t)
    return w,lay

class _Panel(QScrollArea):
    def __init__(self):
        super().__init__(); self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame); self.setStyleSheet(f"background:{C['bg']};")
        ph=QWidget(); ph.setStyleSheet(f"background:{C['bg']};")
        pl=QVBoxLayout(ph); pl.setContentsMargins(28,28,28,28)
        l=QLabel("Open a PE file  (Ctrl+O)"); l.setProperty("sub","true")
        l.setAlignment(Qt.AlignmentFlag.AlignCenter); pl.addWidget(l,1); self.setWidget(ph)
    def load(self, az: PEAnalyzer): pass  # override in each panel

# ══════════════════════════════════════════════════════════════════════════════
#  PANELS
# ══════════════════════════════════════════════════════════════════════════════
class OverviewPanel(_Panel):
    def load(self, az):
        w,lay=_scaffold("Overview"); lay.addWidget(QLabel(az.path))
        lay.addWidget(FileMapBar(az.file_map(),len(az.raw)))
        r1=QHBoxLayout(); r1.setSpacing(12)
        hg=QGroupBox("Hashes"); hg.setLayout(QVBoxLayout()); hg.layout().addWidget(kv_table(az.hashes())); r1.addWidget(hg)
        hdg=QGroupBox("Headers"); hdg.setLayout(QVBoxLayout()); hdg.layout().addWidget(kv_table(az.header_info())); r1.addWidget(hdg)
        lay.addLayout(r1)
        r2=QHBoxLayout(); r2.setSpacing(12)
        sus=az.suspicious_imports(); adb=az.detect_antidebug(); pck=az.detect_packer(); cmp=az.detect_compiler()
        ag=QGroupBox("Quick Analysis"); ag.setLayout(QVBoxLayout())
        rows=[("Packed",f"Yes — {pck['packer'] or '?'}" if pck["packed"] else "No"),
              ("Compiler",", ".join(cmp)),("Suspicious APIs",str(len(sus))),
              ("Anti-Debug APIs",str(len(adb))),("ImpHash",(az.imphash() or "N/A")[:32])]
        for ind in pck["indicators"][:3]: rows.append(("Indicator",ind))
        ag.layout().addWidget(kv_table(rows)); r2.addWidget(ag)
        eg=QGroupBox("Section Entropy"); eg.setLayout(QVBoxLayout())
        sa=QScrollArea(); sa.setWidgetResizable(True); sa.setFrameShape(QFrame.Shape.NoFrame)
        sa.setWidget(EntropyBar([(s["Name"],s["EntropyF"]) for s in az.sections()])); eg.layout().addWidget(sa); r2.addWidget(eg)
        lay.addLayout(r2); lay.addStretch(); self.setWidget(w)

class HeadersPanel(_Panel):
    def load(self, az):
        w,lay=_scaffold("PE Headers")
        ok,stored,calc=az.verify_checksum()
        cg=QGroupBox("Checksum"); cg.setLayout(QVBoxLayout())
        cg.layout().addWidget(kv_table([("Stored",f"0x{stored:08X}"),("Calculated",f"0x{calc:08X}"),("Valid","Yes" if ok else "NO — recalculate")]))
        rb=QPushButton("Recalculate & Patch"); rb.setProperty("sec","true")
        rb.clicked.connect(lambda:az.recalculate_checksum() or self.load(az))
        cg.layout().addWidget(rb); lay.addWidget(cg)
        lay.addWidget(kv_table(az.header_info()),1); self.setWidget(w)

class SectionsPanel(_Panel):
    def load(self, az):
        secs=az.sections(); w,lay=_scaffold(f"Sections  ({len(secs)})")
        tbl=QTableWidget(len(secs),9); tbl.setHorizontalHeaderLabels(["Name","Virt Addr","Virt Size","Raw Off","Raw Size","Entropy","R","W","X"])
        tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11))
        for row,s in enumerate(secs):
            tbl.setRowHeight(row,26)
            for col,val in enumerate([s["Name"],s["VirtAddr"],s["VirtSize"],s["RawOffset"],s["RawSize"],s["Entropy"]]):
                it=QTableWidgetItem(str(val))
                if col==5:
                    ent=s["EntropyF"]; it.setForeground(QColor(C["green"] if ent<5 else C["orange"] if ent<7 else C["red"]))
                    it.setFont(QFont(C["mono"].split(",")[0],11,QFont.Weight.Bold))
                tbl.setItem(row,col,it)
            for ci,flag in enumerate([s["R"],s["W"],s["X"]]):
                fi=QTableWidgetItem("Y" if flag else "—"); fi.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                fi.setForeground(QColor(C["green"] if flag else C["sec"])); tbl.setItem(row,6+ci,fi)
        def _dbl(idx):
            if idx.row()<len(secs): Nav().jump_hex.emit(int(secs[idx.row()]["RawOffset"],16))
        tbl.doubleClicked.connect(_dbl)
        lay.addWidget(tbl)
        eg=QGroupBox("Entropy Visualization"); eg.setLayout(QVBoxLayout())
        sa=QScrollArea(); sa.setWidgetResizable(True); sa.setFrameShape(QFrame.Shape.NoFrame)
        sa.setWidget(EntropyBar([(s["Name"],s["EntropyF"]) for s in secs])); eg.layout().addWidget(sa); lay.addWidget(eg)
        lay.addStretch(); self.setWidget(w)

class ImportsPanel(_Panel):
    def load(self, az):
        imps=az.imports(); sus=set(az.suspicious_imports()); adb=set(az.detect_antidebug())
        total=sum(len(v) for v in imps.values()); w,lay=_scaffold(f"Imports  ({total} functions  /  {len(imps)} DLLs)")
        bar=QHBoxLayout(); fe=QLineEdit(); fe.setPlaceholderText("Filter DLL or function..."); bar.addWidget(fe); bar.addStretch(); lay.addLayout(bar)
        rows=[(dll,fn,"Suspicious" if fn in sus else "Anti-Debug" if fn in adb else "") for dll,fns in imps.items() for fn in fns]
        tbl=QTableWidget(len(rows),3); tbl.setHorizontalHeaderLabels(["DLL","Function","Flag"])
        tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        tbl.setColumnWidth(0,220); tbl.setColumnWidth(2,110); tbl.verticalHeader().setVisible(False)
        tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11)); tbl.setSortingEnabled(True)
        for row,(dll,fn,tag) in enumerate(rows):
            tbl.setRowHeight(row,22)
            di=QTableWidgetItem(dll); di.setForeground(QColor(C["sec"]))
            fi=QTableWidgetItem(fn)
            if tag: fi.setForeground(QColor(C["red"] if tag=="Suspicious" else C["orange"])); fi.setFont(QFont(C["mono"].split(",")[0],11,QFont.Weight.Bold))
            ti=QTableWidgetItem(tag); ti.setForeground(QColor(C["red"] if tag=="Suspicious" else C["orange"] if tag else C["sec"])); ti.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            tbl.setItem(row,0,di); tbl.setItem(row,1,fi); tbl.setItem(row,2,ti)
        fe.textChanged.connect(lambda t:[tbl.setRowHidden(r,bool(t and (not tbl.item(r,0) or t.lower() not in tbl.item(r,0).text().lower()) and (not tbl.item(r,1) or t.lower() not in tbl.item(r,1).text().lower()))) for r in range(tbl.rowCount())])
        lay.addWidget(tbl,1); self.setWidget(w)

class ExportsPanel(_Panel):
    def load(self, az):
        exp=az.exports(); w,lay=_scaffold(f"Exports  ({len(exp)})")
        tbl=QTableWidget(len(exp),3); tbl.setHorizontalHeaderLabels(["Name","Ordinal","RVA"])
        tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11))
        for row,e in enumerate(exp):
            tbl.setRowHeight(row,22)
            ni=QTableWidgetItem(e["Name"]); oi=QTableWidgetItem(str(e["Ordinal"])); oi.setForeground(QColor(C["sec"]))
            ri=QTableWidgetItem(e["RVA"]); ri.setForeground(QColor(C["accent"]))
            tbl.setItem(row,0,ni); tbl.setItem(row,1,oi); tbl.setItem(row,2,ri)
        lay.addWidget(tbl,1); self.setWidget(w)

class RelocsPanel(_Panel):
    def load(self, az):
        rels=az.relocations(); w,lay=_scaffold(f"Relocations  ({len(rels)})")
        tbl=QTableWidget(len(rels),2); tbl.setHorizontalHeaderLabels(["Virtual Address","Type"])
        tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11))
        for row,r in enumerate(rels):
            tbl.setRowHeight(row,20); tbl.setItem(row,0,QTableWidgetItem(r["VirtAddr"])); tbl.setItem(row,1,QTableWidgetItem(r["Type"]))
        lay.addWidget(tbl,1); self.setWidget(w)

class TLSPanel(_Panel):
    def load(self, az):
        data=az.tls(); w,lay=_scaffold("Thread Local Storage  (TLS)")
        info=QLabel("TLS callbacks run before the entry point. Often abused for anti-debugging and obfuscation.")
        info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
        if data: lay.addWidget(kv_table(data))
        else: lay.addWidget(QLabel("No TLS directory found in this PE."))
        lay.addStretch(); self.setWidget(w)

class ResourcesPanel(_Panel):
    def load(self, az):
        res=az.resources(); w,lay=_scaffold(f"Resources  ({len(res)})")
        tbl=QTableWidget(len(res),5); tbl.setHorizontalHeaderLabels(["Type","ID","Language","RVA","Size (bytes)"])
        tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11))
        for row,r in enumerate(res):
            tbl.setRowHeight(row,22)
            for col,val in enumerate([r["Type"],str(r["ID"]),str(r["Lang"]),r["RVA"],str(r["Size"])]):
                it=QTableWidgetItem(val)
                if col==0: it.setForeground(QColor(C["accent"]))
                tbl.setItem(row,col,it)
        lay.addWidget(tbl,1); self.setWidget(w)

class DebugInfoPanel(_Panel):
    def load(self, az):
        dbg=az.debug_info(); w,lay=_scaffold(f"Debug Info  ({len(dbg)} entries)")
        info=QLabel("Debug directory entries — CodeView entries include PDB file paths revealing build system details.")
        info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
        tbl=QTableWidget(len(dbg),4); tbl.setHorizontalHeaderLabels(["Type","RVA","Size","PDB Path"])
        tbl.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeMode.Stretch)
        tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11))
        for row,d in enumerate(dbg):
            tbl.setRowHeight(row,22)
            tbl.setItem(row,0,QTableWidgetItem(d.get("Type",""))); tbl.setItem(row,1,QTableWidgetItem(d.get("RVA","")))
            tbl.setItem(row,2,QTableWidgetItem(str(d.get("Size","")))); 
            pi=QTableWidgetItem(d.get("PDB Path","")); pi.setForeground(QColor(C["orange"])); tbl.setItem(row,3,pi)
        lay.addWidget(tbl,1); self.setWidget(w)

class RichHeaderPanel(_Panel):
    def load(self, az):
        rh=az.rich_header(); w,lay=_scaffold("Rich Header  —  MSVC Compiler Fingerprint")
        info=QLabel("The Microsoft Rich header is embedded between the DOS stub and NT headers in MSVC-compiled binaries. Each entry reveals which compiler component built which parts.")
        info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
        if not rh: lay.addWidget(QLabel("No Rich header — not MSVC compiled, or it was stripped.")); lay.addStretch(); self.setWidget(w); return
        tbl=QTableWidget(len(rh),4); tbl.setHorizontalHeaderLabels(["Product Name","Product ID","Build #","Object Count"])
        tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11))
        for row,e in enumerate(rh):
            tbl.setRowHeight(row,22)
            ni=QTableWidgetItem(e["Name"]); ni.setForeground(QColor(C["accent"]))
            tbl.setItem(row,0,ni); tbl.setItem(row,1,QTableWidgetItem(str(e["ProductID"])))
            tbl.setItem(row,2,QTableWidgetItem(str(e["Build"]))); tbl.setItem(row,3,QTableWidgetItem(str(e["Count"])))
        lay.addWidget(tbl,1); self.setWidget(w)

class OverlayPanel(_Panel):
    def load(self, az):
        ov=az.overlay(); w,lay=_scaffold("Overlay Analyzer")
        info=QLabel("Overlay = data appended after the last PE section. Common in self-extractors, installers, malware droppers, and UPX-packed binaries.")
        info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
        if not ov or not ov.get("present"): lay.addWidget(QLabel("No overlay detected.")); lay.addStretch(); self.setWidget(w); return
        rows=[("Detected","Yes"),("File Offset",f"0x{ov['offset']:08X}"),
              ("Size",f"{ov['size']:,} bytes  ({ov['size']/1024:.1f} KB)"),
              ("Entropy",f"{ov['entropy']:.3f}  {'→ likely encrypted/packed' if ov['entropy']>7 else ''}"),
              ("Overlay is ZIP",str(ov.get("is_zip"))),("Overlay is PE",str(ov.get("is_pe"))),
              ("Overlay is ELF",str(ov.get("is_elf"))),("First 32 bytes",ov.get("preview",""))]
        lay.addWidget(kv_table(rows))
        if ov["size"]<20*1024*1024:
            xb=QPushButton("Extract Overlay to File"); xb.setProperty("sec","true")
            xb.clicked.connect(lambda:self._extract(az,ov)); lay.addWidget(xb)
        lay.addStretch(); self.setWidget(w)
    def _extract(self, az, ov):
        p,_=QFileDialog.getSaveFileName(None,"Save Overlay","overlay.bin","Binary (*.bin);;All (*)")
        if p:
            with open(p,"wb") as f: f.write(bytes(az.raw[ov["offset"]:]))

class CryptoPanel(_Panel):
    def load(self, az):
        def _scan(): return az.detect_crypto()
        def _show(hits):
            w,lay=_scaffold(f"Crypto Constant Detector  ({len(hits)} hits)")
            info=QLabel("Scans raw binary for known cryptographic constants: AES S-boxes, MD5/SHA init vectors, CRC32 polynomial, Salsa20/ChaCha, TEA delta, Blowfish, DES S-box, and more.")
            info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
            if not hits: lay.addWidget(QLabel("No crypto constants detected.")); lay.addStretch(); self.setWidget(w); return
            tbl=QTableWidget(len(hits),4); tbl.setHorizontalHeaderLabels(["Algorithm","File Offset","Section","Description"])
            tbl.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeMode.Stretch)
            tbl.setColumnWidth(0,160); tbl.setColumnWidth(1,110); tbl.setColumnWidth(2,90)
            tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            tbl.setFont(QFont(C["mono"].split(",")[0],11))
            for row,h in enumerate(hits):
                tbl.setRowHeight(row,22)
                ni=QTableWidgetItem(h["Name"]); ni.setForeground(QColor(C["purple"])); ni.setFont(QFont(C["mono"].split(",")[0],11,QFont.Weight.Bold))
                tbl.setItem(row,0,ni); tbl.setItem(row,1,QTableWidgetItem(h["Offset"]))
                tbl.setItem(row,2,QTableWidgetItem(h["Section"])); tbl.setItem(row,3,QTableWidgetItem(h["Desc"]))
            lay.addWidget(tbl,1); self.setWidget(w)
        async_run(self,"Scanning for crypto constants...",_scan,on_done=_show)

class CodeCavePanel(_Panel):
    def load(self, az):
        w,lay=_scaffold("Code Cave Finder")
        info=QLabel("Finds contiguous same-byte regions — large enough to inject shellcode, hooks, or trampoline stubs. Usable = 64+ bytes.")
        info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
        bar=QHBoxLayout()
        me=QLineEdit("32"); me.setFixedWidth(70); be=QLineEdit("00"); be.setFixedWidth(50); sb=QPushButton("Scan")
        bar.addWidget(QLabel("Min size:")); bar.addWidget(me); bar.addWidget(QLabel("Byte 0x")); bar.addWidget(be); bar.addWidget(sb); bar.addStretch()
        lay.addLayout(bar)
        tbl=QTableWidget(); tbl.setColumnCount(5); tbl.setHorizontalHeaderLabels(["File Offset","VA","Size","Section","Usable (64+)"])
        tbl.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeMode.Stretch)
        tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11)); lay.addWidget(tbl,1)
        def _scan():
            try: ms=int(me.text()); bv=int(be.text(),16)
            except: return
            caves=az.find_code_caves(ms,bv); tbl.setRowCount(len(caves))
            for row,c in enumerate(caves):
                tbl.setRowHeight(row,22)
                for col,val in enumerate([c["Offset"],c["VA"],str(c["Size"]),c["Section"]]): tbl.setItem(row,col,QTableWidgetItem(val))
                ui=QTableWidgetItem("Yes" if c["Usable"] else "—"); ui.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                ui.setForeground(QColor(C["green"] if c["Usable"] else C["sec"])); tbl.setItem(row,4,ui)
        sb.clicked.connect(_scan); _scan(); self.setWidget(w)

class ProloguesPanel(_Panel):
    def load(self, az):
        w,lay=_scaffold("Function Prologue Scanner")
        info=QLabel("Heuristic scan for function entry points in executable sections. Works without symbols.")
        info.setProperty("sub","true"); lay.addWidget(info)
        sb=QPushButton("Scan"); sb.setProperty("sec","true"); lay.addWidget(sb)
        tbl=QTableWidget(); tbl.setColumnCount(4); tbl.setHorizontalHeaderLabels(["File Offset","VA","Prologue","Section"])
        tbl.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeMode.Stretch)
        tbl.setColumnWidth(0,110); tbl.setColumnWidth(1,110); tbl.setColumnWidth(3,80)
        tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11)); lay.addWidget(tbl,1)
        def _show(hits):
            tbl.setRowCount(len(hits))
            for row,h in enumerate(hits):
                tbl.setRowHeight(row,22)
                fi=QTableWidgetItem(h["Offset"]); fi.setForeground(QColor(C["sec"]))
                vi=QTableWidgetItem(h["VA"]); vi.setForeground(QColor(C["accent"]))
                tbl.setItem(row,0,fi); tbl.setItem(row,1,vi)
                tbl.setItem(row,2,QTableWidgetItem(h["Prologue"])); tbl.setItem(row,3,QTableWidgetItem(h["Section"]))
        sb.clicked.connect(lambda:async_run(self,"Scanning prologues...",az.find_function_prologues,on_done=_show))
        self.setWidget(w)

class HexPanel(_Panel):
    def __init__(self): super().__init__(); self.hex_editor=None; self.az=None
    def load(self, az):
        self.az=az; w,lay=_scaffold("Hex Editor")
        info=QLabel(f"{len(az.raw):,} bytes  ·  Enable Edit Mode → double-click any cell to patch  ·  Undo Ctrl+Z  /  Redo Ctrl+Y")
        info.setProperty("sub","true"); lay.addWidget(info)
        self.hex_editor=HexEditor(az.raw); self.hex_editor.patch_applied.connect(self._on_patch)
        Nav().jump_hex.connect(self.hex_editor.jump_to)
        lay.addWidget(self.hex_editor,1); self.setWidget(w)
    def _on_patch(self, off, old, new):
        if self.az: self.az.history.apply(off,old,new)

class DisasmPanel(_Panel):
    def __init__(self): super().__init__(); self._dw=None
    def load(self, az):
        w,lay=_scaffold("Disassembler")
        self._dw=DisasmWidget(); self._dw.set_analyzer(az)
        Nav().jump_disasm.connect(self._dw.jump_to)
        lay.addWidget(self._dw,1); self.setWidget(w)

class CFGPanel(_Panel):
    def load(self, az):
        w,lay=_scaffold("Control Flow Graph")
        bar=QHBoxLayout()
        off_e=QLineEdit("0"); off_e.setPlaceholderText("File offset (hex)"); off_e.setFixedWidth(150)
        sz_e=QLineEdit("1024"); sz_e.setFixedWidth(70)
        ep_b=QPushButton("Entry Point"); ep_b.setProperty("sec","true")
        go_b=QPushButton("Build CFG")
        bar.addWidget(QLabel("Offset:")); bar.addWidget(off_e); bar.addWidget(QLabel("Bytes:")); bar.addWidget(sz_e)
        bar.addWidget(ep_b); bar.addStretch(); bar.addWidget(go_b); lay.addLayout(bar)
        if not HAS_CAP: lay.addWidget(QLabel("pip install capstone")); lay.addStretch(); self.setWidget(w); return
        view=CFGView(); lay.addWidget(view,1)
        def _ep():
            off=az.ep_offset()
            if off is not None: off_e.setText(f"{off:X}"); _build()
        def _build():
            try: off=int(off_e.text().strip() or "0",16)
            except: off=0
            try: sz=int(sz_e.text())
            except: sz=1024
            async_run(self,"Building CFG...",az.build_cfg,off,sz,on_done=view.set_blocks)
        ep_b.clicked.connect(_ep); go_b.clicked.connect(_build); self.setWidget(w)

class PatchesPanel(_Panel):
    def load(self, az):
        patches=az.history.patches; w,lay=_scaffold(f"Patches  ({len(patches)})")
        if not patches: lay.addWidget(QLabel("No patches yet.\nUse Hex Editor in Edit Mode → double-click a byte.")); lay.addStretch(); self.setWidget(w); return
        tbl=QTableWidget(len(patches),4); tbl.setHorizontalHeaderLabels(["File Offset","Original","Patched","Delta"])
        tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11))
        for row,(off,(old,new)) in enumerate(sorted(patches.items())):
            tbl.setRowHeight(row,22); tbl.setItem(row,0,QTableWidgetItem(f"0x{off:08X}"))
            oi=QTableWidgetItem(f"{old:02X}"); oi.setForeground(QColor(C["sec"]))
            ni=QTableWidgetItem(f"{new:02X}"); ni.setForeground(QColor(C["orange"])); ni.setFont(QFont(C["mono"].split(",")[0],11,QFont.Weight.Bold))
            di=QTableWidgetItem(f"{new-old:+d}"); di.setForeground(QColor(C["green"] if new>old else C["red"]))
            tbl.setItem(row,1,oi); tbl.setItem(row,2,ni); tbl.setItem(row,3,di)
        lay.addWidget(tbl,1); self.setWidget(w)

class StringsPanel(_Panel):
    def load(self, az):
        w,lay=_scaffold("Strings")
        bar=QHBoxLayout(); fe=QLineEdit(); fe.setPlaceholderText("Filter strings...")
        ml=QLineEdit("5"); ml.setFixedWidth(55); rb=QPushButton("Refresh"); rb.setProperty("sec","true")
        bar.addWidget(fe); bar.addWidget(QLabel("Min len:")); bar.addWidget(ml); bar.addWidget(rb); bar.addStretch(); lay.addLayout(bar)
        tbl=QTableWidget(0,3); tbl.setHorizontalHeaderLabels(["Offset","Encoding","String"])
        tbl.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeMode.Stretch)
        tbl.setColumnWidth(0,105); tbl.setColumnWidth(1,70)
        tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11)); lay.addWidget(tbl,1)
        def fill(data):
            tbl.setRowCount(len(data))
            for row,s in enumerate(data):
                tbl.setRowHeight(row,20); tbl.setItem(row,0,QTableWidgetItem(s["Offset"]))
                ti=QTableWidgetItem(s["Type"]); ti.setForeground(QColor(C["sec"]))
                tbl.setItem(row,1,ti); tbl.setItem(row,2,QTableWidgetItem(s["String"]))
        async_run(self,"Extracting strings...",lambda:az.strings(int(ml.text() or "5")),on_done=fill)
        fe.textChanged.connect(lambda t:[tbl.setRowHidden(r,bool(t and tbl.item(r,2) and t.lower() not in tbl.item(r,2).text().lower())) for r in range(tbl.rowCount())])
        rb.clicked.connect(lambda:async_run(self,"Extracting strings...",lambda:az.strings(int(ml.text() or "5")),on_done=fill))
        self.setWidget(w)

class NetworkPanel(_Panel):
    def load(self, az):
        net=az.network_indicators(); w,lay=_scaffold("Network Indicators"); tabs=QTabWidget()
        for key,items in net.items():
            pg=QWidget(); pl=QVBoxLayout(pg); pl.setContentsMargins(8,8,8,8)
            te=QPlainTextEdit("\n".join(items) if items else "(none found)"); te.setReadOnly(True); te.setFont(QFont(C["mono"].split(",")[0],11))
            pl.addWidget(te,1); tabs.addTab(pg,f"{key}  ({len(items)})")
        lay.addWidget(tabs,1); self.setWidget(w)

class AnalysisPanel(_Panel):
    def load(self, az):
        w,lay=_scaffold("Threat Analysis")
        pck=az.detect_packer(); cmp=az.detect_compiler(); sus=az.suspicious_imports(); adb=az.detect_antidebug()
        pg=QGroupBox("Packing / Obfuscation"); pg.setLayout(QVBoxLayout())
        pr=[("Status","PACKED — "+(pck["packer"] or "Unknown") if pck["packed"] else "Clean — no packing detected")]
        for i in pck["indicators"]: pr.append(("Indicator",i))
        pg.layout().addWidget(kv_table(pr)); lay.addWidget(pg)
        cg=QGroupBox("Compiler Fingerprint"); cg.setLayout(QVBoxLayout())
        cg.layout().addWidget(kv_table([("Detected",", ".join(cmp))])); lay.addWidget(cg)
        for gtitle,lst,col in [("Suspicious API Imports",sus,C["red"]),("Anti-Debug APIs",adb,C["orange"])]:
            g=QGroupBox(f"{gtitle}  ({len(lst)})"); g.setLayout(QVBoxLayout())
            if lst:
                t=QTableWidget(len(lst),1); t.setHorizontalHeaderLabels(["API Name"])
                t.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
                t.verticalHeader().setVisible(False); t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
                t.setFont(QFont(C["mono"].split(",")[0],11))
                for row,api in enumerate(lst):
                    t.setRowHeight(row,22); it=QTableWidgetItem(api); it.setForeground(QColor(col)); t.setItem(row,0,it)
                g.layout().addWidget(t)
            else: g.layout().addWidget(QLabel("None detected."))
            lay.addWidget(g)
        lay.addStretch(); self.setWidget(w)

class YaraPanel(_Panel):
    def load(self, az):
        w,lay=_scaffold("YARA Rule Generator")
        info=QLabel("Auto-generated from entry point bytes, extracted strings, and ImpHash. Edit freely before exporting.")
        info.setProperty("sub","true"); lay.addWidget(info)
        self._re=QPlainTextEdit(az.yara_rule()); self._re.setFont(QFont(C["mono"].split(",")[0],12)); self._re.setTabStopDistance(28)
        lay.addWidget(self._re,1)
        bar=QHBoxLayout()
        cp=QPushButton("Copy to Clipboard"); cp.clicked.connect(lambda:QApplication.clipboard().setText(self._re.toPlainText()))
        rg=QPushButton("Regenerate"); rg.setProperty("sec","true"); rg.clicked.connect(lambda:self._re.setPlainText(az.yara_rule()))
        bar.addWidget(cp); bar.addWidget(rg); bar.addStretch(); lay.addLayout(bar); self.setWidget(w)

class GlobalSearchPanel(_Panel):
    def load(self, az):
        w,lay=_scaffold("Global Search")
        info=QLabel("Instant search across strings, imports, exports, section names, and network indicators.")
        info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
        bar=QHBoxLayout()
        self._q=QLineEdit(); self._q.setPlaceholderText("Search everything..."); self._q.returnPressed.connect(lambda:self._search(az))
        sb=QPushButton("Search"); sb.clicked.connect(lambda:self._search(az))
        bar.addWidget(self._q,1); bar.addWidget(sb); lay.addLayout(bar)
        self._tbl=QTableWidget(); self._tbl.setColumnCount(3); self._tbl.setHorizontalHeaderLabels(["Category","Location","Match"])
        self._tbl.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeMode.Stretch)
        self._tbl.setColumnWidth(0,110); self._tbl.setColumnWidth(1,160)
        self._tbl.verticalHeader().setVisible(False); self._tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tbl.setFont(QFont(C["mono"].split(",")[0],11))
        self._info=QLabel(""); self._info.setProperty("sub","true")
        lay.addWidget(self._tbl,1); lay.addWidget(self._info); self._az=az; self.setWidget(w)

    def _search(self, az):
        q=self._q.text().strip().lower()
        if not q: return
        results=[]
        for s in az.strings(min_len=4):
            if q in s["String"].lower(): results.append(("String",s["Offset"],s["String"][:80]))
        for dll,fns in az.imports().items():
            if q in dll.lower(): results.append(("Import DLL",dll,""))
            for fn in fns:
                if q in fn.lower(): results.append(("Import",dll,fn))
        for e in az.exports():
            if q in e["Name"].lower(): results.append(("Export",e["RVA"],e["Name"]))
        for s in az.sections():
            if q in s["Name"].lower(): results.append(("Section",s["RawOffset"],s["Name"]))
        net=az.network_indicators()
        for cat,items in net.items():
            for item in items:
                if q in item.lower(): results.append((f"Net/{cat}","",item))
        self._tbl.setRowCount(min(len(results),2000)); self._info.setText(f"{len(results)} results")
        CAT_COL={"String":C["text"],"Import":C["red"],"Import DLL":C["orange"],"Export":C["accent"],"Section":C["green"]}
        for row,(cat,loc,match) in enumerate(results[:2000]):
            self._tbl.setRowHeight(row,20)
            ci=QTableWidgetItem(cat); ci.setForeground(QColor(CAT_COL.get(cat,C["sec"])))
            li=QTableWidgetItem(str(loc)); li.setForeground(QColor(C["sec"]))
            self._tbl.setItem(row,0,ci); self._tbl.setItem(row,1,li); self._tbl.setItem(row,2,QTableWidgetItem(match))

class FlirtPanel(_Panel):
    def __init__(self): super().__init__(); self._scanner=FlirtScanner()
    def load(self, az):
        w,lay=_scaffold("FLIRT Signature Scanner")
        info=QLabel(f"{len(self._scanner.sigs)} built-in patterns  ·  Load custom .sig files (one pattern + name per line) to extend.")
        info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
        bar=QHBoxLayout()
        lb=QPushButton("Load .sig File"); lb.setProperty("sec","true")
        lb.clicked.connect(lambda:self._load_sig())
        sb=QPushButton("Scan"); bar.addWidget(lb); bar.addWidget(sb); bar.addStretch(); lay.addLayout(bar)
        tbl=QTableWidget(); tbl.setColumnCount(3); tbl.setHorizontalHeaderLabels(["Offset","Function Name","Match Length"])
        tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        tbl.setColumnWidth(0,110); tbl.setColumnWidth(2,120)
        tbl.verticalHeader().setVisible(False); tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.setFont(QFont(C["mono"].split(",")[0],11)); self._info2=QLabel(""); self._info2.setProperty("sub","true")
        lay.addWidget(tbl,1); lay.addWidget(self._info2)
        def _do(): return self._scanner.scan(bytes(az.raw))
        def _show(hits):
            tbl.setRowCount(len(hits)); self._info2.setText(f"{len(hits)} matches found.")
            for row,h in enumerate(hits):
                tbl.setRowHeight(row,22)
                oi=QTableWidgetItem(h["Offset"]); oi.setForeground(QColor(C["sec"]))
                ni=QTableWidgetItem(h["Name"]); ni.setForeground(QColor(C["accent"])); ni.setFont(QFont(C["mono"].split(",")[0],11,QFont.Weight.Bold))
                tbl.setItem(row,0,oi); tbl.setItem(row,1,ni); tbl.setItem(row,2,QTableWidgetItem(str(h["Length"])))
        sb.clicked.connect(lambda:async_run(self,"Scanning signatures...",_do,on_done=_show)); self.setWidget(w)
    def _load_sig(self):
        p,_=QFileDialog.getOpenFileName(None,"Load Signature File","","Sig (*.sig *.txt);;All (*)")
        if p: self._scanner.load_file(p)

class DiffPanel(_Panel):
    def __init__(self): super().__init__(); self._az=None
    def load(self, az): self._az=az; self._build()
    def _build(self):
        w,lay=_scaffold("PE Binary Diff")
        info=QLabel("Compare this file against another PE binary — sections, imports, and byte-level regions.")
        info.setProperty("sub","true"); lay.addWidget(info)
        bar=QHBoxLayout()
        self._p2=QLineEdit(); self._p2.setPlaceholderText("Second file path...")
        br=QPushButton("Browse"); br.setProperty("sec","true")
        br.clicked.connect(lambda:self._p2.setText(QFileDialog.getOpenFileName(None,"Second PE","","PE Files (*.exe *.dll *.sys);;All (*)")[0]))
        db=QPushButton("Run Diff"); bar.addWidget(self._p2,1); bar.addWidget(br); bar.addWidget(db); lay.addLayout(bar)
        self._tabs=QTabWidget(); lay.addWidget(self._tabs,1); db.clicked.connect(self._run); self.setWidget(w)
    def _run(self):
        p=self._p2.text().strip()
        if not p or not os.path.isfile(p): return
        try: az2=PEAnalyzer(p)
        except: return
        diff=PEDiff(self._az,az2); self._tabs.clear()
        secs=diff.sections(); st=QTableWidget(len(secs),5)
        st.setHorizontalHeaderLabels(["Section","Status","Entropy 1","Entropy 2","Size 2"])
        st.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch); st.verticalHeader().setVisible(False)
        st.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        SC={"Same":C["green"],"Modified":C["orange"],"Removed":C["red"],"Added":C["accent"]}
        for row,s in enumerate(secs):
            st.setRowHeight(row,22); ni=QTableWidgetItem(s["Section"]); si=QTableWidgetItem(s["Status"])
            si.setForeground(QColor(SC.get(s["Status"],C["sec"])))
            st.setItem(row,0,ni); st.setItem(row,1,si)
            st.setItem(row,2,QTableWidgetItem(f"{s['E1']:.3f}" if isinstance(s["E1"],float) else str(s["E1"])))
            st.setItem(row,3,QTableWidgetItem(f"{s['E2']:.3f}" if isinstance(s["E2"],float) else str(s["E2"])))
            st.setItem(row,4,QTableWidgetItem(str(s["Sz2"])))
        sp=QWidget(); sl=QVBoxLayout(sp); sl.addWidget(st); self._tabs.addTab(sp,"Sections")
        imp=diff.imports(); ip=QWidget(); il=QVBoxLayout(ip)
        il.addWidget(QLabel(f"Added: {len(imp['added'])}  Removed: {len(imp['removed'])}  Same: {imp['same']}"))
        it=QPlainTextEdit("ADDED:\n"+"\n".join(imp["added"][:300])+"\n\nREMOVED:\n"+"\n".join(imp["removed"][:300]))
        it.setReadOnly(True); it.setFont(QFont(C["mono"].split(",")[0],11)); il.addWidget(it,1); self._tabs.addTab(ip,"Imports")
        regs=diff.byte_regions(); bt=QTableWidget(len(regs),3)
        bt.setHorizontalHeaderLabels(["Offset","Length","Note"]); bt.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        bt.verticalHeader().setVisible(False); bt.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        bt.setFont(QFont(C["mono"].split(",")[0],11))
        for row,r in enumerate(regs): bt.setRowHeight(row,22); bt.setItem(row,0,QTableWidgetItem(r["Offset"])); bt.setItem(row,1,QTableWidgetItem(str(r["Length"]))); bt.setItem(row,2,QTableWidgetItem(r.get("Note","")))
        bp=QWidget(); bl=QVBoxLayout(bp); bl.addWidget(bt); self._tabs.addTab(bp,f"Byte Regions ({len(regs)})")

class ScannerPanel(_Panel):
    def load(self, az):
        w,lay=_scaffold("Wildcard Pattern Scanner")
        info=QLabel("Scan raw binary for byte patterns. Use ?? as wildcards.\nExample:  55 8B EC ?? ?? 6A 00  matches MSVC prologue with any 2 bytes at positions 3-4.")
        info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
        bar=QHBoxLayout(); self._pe=QLineEdit(); self._pe.setPlaceholderText("e.g.  4D 5A ?? ?? 90 00")
        sb=QPushButton("Scan"); self._pe.returnPressed.connect(sb.click)
        bar.addWidget(self._pe,1); bar.addWidget(sb); lay.addLayout(bar)
        self._tbl=QTableWidget(); self._tbl.setColumnCount(3); self._tbl.setHorizontalHeaderLabels(["File Offset","VA","Matched Bytes"])
        self._tbl.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeMode.Stretch)
        self._tbl.verticalHeader().setVisible(False); self._tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tbl.setFont(QFont(C["mono"].split(",")[0],11))
        self._sl=QLabel(""); self._sl.setProperty("sub","true")
        lay.addWidget(self._tbl,1); lay.addWidget(self._sl)
        def _do():
            try: pat=WildcardScanner.parse(self._pe.text())
            except: return []
            return WildcardScanner.scan(bytes(az.raw),pat)
        def _show(hits):
            hits=hits[:5000]; pl=len(WildcardScanner.parse(self._pe.text())) if self._pe.text().strip() else 0
            self._tbl.setRowCount(len(hits)); self._sl.setText(f"{len(hits)} match(es).")
            for row,off in enumerate(hits):
                self._tbl.setRowHeight(row,22)
                fi=QTableWidgetItem(f"0x{off:08X}"); fi.setForeground(QColor(C["sec"]))
                va=0
                if az.pe:
                    for s in az.pe.sections:
                        if s.PointerToRawData<=off<s.PointerToRawData+s.SizeOfRawData:
                            va=az.pe.OPTIONAL_HEADER.ImageBase+s.VirtualAddress+(off-s.PointerToRawData); break
                vi=QTableWidgetItem(f"0x{va:08X}"); vi.setForeground(QColor(C["accent"]))
                self._tbl.setItem(row,0,fi); self._tbl.setItem(row,1,vi)
                self._tbl.setItem(row,2,QTableWidgetItem(" ".join(f"{b:02X}" for b in az.raw[off:off+pl])))
        sb.clicked.connect(lambda:async_run(self,"Scanning...",_do,on_done=_show)); self.setWidget(w)

class SectionInjectorPanel(_Panel):
    def load(self, az):
        w,lay=_scaffold("PE Section Injector")
        info=QLabel("Add a new raw section to the PE binary. Requires padding space in the header area between the last section header and first section's raw data.")
        info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
        g=QGroupBox("New Section Parameters"); g.setLayout(QFormLayout())
        ne=QLineEdit(".inject"); ce=QLineEdit("60000020")
        de=QPlainTextEdit(); de.setPlaceholderText("Hex bytes of payload\ne.g.  90 90 90 CC  (3× NOP + INT3)")
        de.setFont(QFont(C["mono"].split(",")[0],11)); de.setFixedHeight(120)
        g.layout().addRow("Name (max 8 chars):",ne); g.layout().addRow("Characteristics (hex):",ce); g.layout().addRow("Payload (hex bytes):",de)
        lay.addWidget(g)
        self._res=QLabel(""); self._res.setWordWrap(True)
        ib=QPushButton("Inject Section")
        def _do():
            try: data=bytes.fromhex(de.toPlainText().replace("\n"," ").replace(","," ").replace(" ","")); chars=int(ce.text(),16)
            except Exception as e: self._res.setText(f"Parse error: {e}"); return
            ok,msg=az.inject_section(ne.text(),data,chars)
            self._res.setText(("Success: " if ok else "Failed: ")+msg)
            self._res.setStyleSheet(f"color:{C['green'] if ok else C['red']};font-family:{C['mono'].split(',')[0]};font-size:12px;")
        ib.clicked.connect(_do); lay.addWidget(ib); lay.addWidget(self._res); lay.addStretch(); self.setWidget(w)

class GhidraPanel(_Panel):
    def __init__(self): super().__init__(); self._bridge=GhidraBridge()
    def load(self, az):
        w,lay=_scaffold("Ghidra Live Integration")
        info=QLabel("Connect to a running Ghidra instance with the GhidraBridge server.\nIn Ghidra → Script Manager → run StartServer.py from the ghidra-bridge package.")
        info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
        cbar=QHBoxLayout(); he=QLineEdit("localhost"); he.setFixedWidth(140); pe2=QLineEdit("4768"); pe2.setFixedWidth(70)
        cb=QPushButton("Connect"); self._sl=QLabel("Not connected"); self._sl.setProperty("sub","true")
        cbar.addWidget(QLabel("Host:")); cbar.addWidget(he); cbar.addWidget(QLabel("Port:")); cbar.addWidget(pe2)
        cbar.addWidget(cb); cbar.addWidget(self._sl); cbar.addStretch(); lay.addLayout(cbar)
        tabs=QTabWidget(); lay.addWidget(tabs,1)
        self._ft=QTableWidget(); self._ft.setColumnCount(4); self._ft.setHorizontalHeaderLabels(["Name","Entry","Size","Params"])
        self._ft.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch); self._ft.verticalHeader().setVisible(False)
        self._ft.setFont(QFont(C["mono"].split(",")[0],11)); self._ft.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        fp=QWidget(); fl=QVBoxLayout(fp); fl.addWidget(self._ft); tabs.addTab(fp,"Functions")
        dp=QWidget(); dl=QVBoxLayout(dp); dl.setContentsMargins(8,8,8,8)
        dbar2=QHBoxLayout(); self._dn=QLineEdit(); self._dn.setPlaceholderText("Function name..."); db2=QPushButton("Decompile")
        dbar2.addWidget(self._dn,1); dbar2.addWidget(db2)
        self._do2=QPlainTextEdit(); self._do2.setReadOnly(True); self._do2.setFont(QFont(C["mono"].split(",")[0],11))
        dl.addLayout(dbar2); dl.addWidget(self._do2,1); tabs.addTab(dp,"Decompiler")
        xp=QWidget(); xl=QVBoxLayout(xp); xl.setContentsMargins(8,8,8,8)
        xbar=QHBoxLayout(); self._xa=QLineEdit(); self._xa.setPlaceholderText("Address (hex) e.g. 0x401000"); xb=QPushButton("Get XRefs")
        xbar.addWidget(self._xa,1); xbar.addWidget(xb)
        self._xo=QPlainTextEdit(); self._xo.setReadOnly(True); self._xo.setFont(QFont(C["mono"].split(",")[0],11))
        xl.addLayout(xbar); xl.addWidget(self._xo,1); tabs.addTab(xp,"XRefs")
        def _conn():
            ok,msg=self._bridge.connect(he.text(),int(pe2.text() or "4768"))
            self._sl.setText(msg); self._sl.setStyleSheet(f"color:{C['green'] if ok else C['red']};")
            if ok:
                fns=self._bridge.functions(); self._ft.setRowCount(len(fns))
                for row,f in enumerate(fns):
                    self._ft.setRowHeight(row,22)
                    for col,k in enumerate(["Name","Entry","Size","Params"]):
                        it=QTableWidgetItem(str(f.get(k,""))); 
                        if col==0: it.setForeground(QColor(C["accent"]))
                        self._ft.setItem(row,col,it)
        self._ft.doubleClicked.connect(lambda i:self._dn.setText(self._ft.item(i.row(),0).text() if self._ft.item(i.row(),0) else ""))
        cb.clicked.connect(_conn)
        db2.clicked.connect(lambda:self._do2.setPlainText(self._bridge.decompile(self._dn.text().strip())))
        xb.clicked.connect(lambda:self._xo.setPlainText("\n".join(self._bridge.xrefs(self._xa.text().strip()))))
        if not HAS_GHI: self._sl.setText("pip install ghidra-bridge")
        self.setWidget(w)

# ══════════════════════════════════════════════════════════════════════════════
#  DEBUGGER PANEL  (standalone QWidget — not a scroll area)
# ══════════════════════════════════════════════════════════════════════════════
class DebuggerPanel(QWidget):
    def __init__(self):
        super().__init__(); self._dbg=None; self._bps: Dict[int,bool]={}
        self.setStyleSheet(f"background:{C['bg']};"); self._setup()

    def _setup(self):
        ML=C["mono"].split(",")[0]
        lay=QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)

        # ── Top bar ──
        tb=QWidget(); tb.setStyleSheet(f"background:{C['surface']};border-bottom:1px solid {C['border']};")
        tbl=QHBoxLayout(tb); tbl.setContentsMargins(12,6,12,6); tbl.setSpacing(8)
        self._exe=QLineEdit(); self._exe.setPlaceholderText("Executable path  or  PID to attach...")
        br=QPushButton("Browse"); br.setProperty("sec","true")
        br.clicked.connect(lambda:self._exe.setText(QFileDialog.getOpenFileName(None,"Executable","","All (*)")[0]))
        self._args=QLineEdit(); self._args.setPlaceholderText("Args..."); self._args.setFixedWidth(130)
        self._lb=QPushButton("Launch");  self._lb.clicked.connect(self._launch)
        self._ab=QPushButton("Attach");  self._ab.setProperty("sec","true"); self._ab.clicked.connect(self._attach)
        self._db=QPushButton("Detach");  self._db.setProperty("danger","true"); self._db.clicked.connect(self._detach); self._db.setEnabled(False)
        self._st=QLabel("Stopped"); self._st.setStyleSheet(f"color:{C['red']};font-weight:600;padding:0 8px;")
        for w2 in [self._exe,br,self._args,self._lb,self._ab,self._db,self._st]: tbl.addWidget(w2)
        tbl.addStretch(); lay.addWidget(tb)

        # ── Control bar ──
        cb=QWidget(); cb.setStyleSheet(f"background:{C['sidebar']};border-bottom:1px solid {C['border']};")
        cbl=QHBoxLayout(cb); cbl.setContentsMargins(12,6,12,6); cbl.setSpacing(8)
        self._rb=self._cbtn("Run F5","F5",self._run)
        self._sb=self._cbtn("Step F7","F7",self._step)
        self._ob=self._cbtn("Over F8","F8",self._step)
        self._bpe=QLineEdit(); self._bpe.setPlaceholderText("Add BP at VA (hex)..."); self._bpe.setFixedWidth(200); self._bpe.returnPressed.connect(self._add_bp)
        abtn=QPushButton("+BP"); abtn.setProperty("sec","true"); abtn.clicked.connect(self._add_bp)
        for w2 in [self._rb,self._sb,self._ob]: cbl.addWidget(w2)
        cbl.addSpacing(16); cbl.addWidget(self._bpe); cbl.addWidget(abtn); cbl.addStretch(); lay.addWidget(cb)

        # ── Main splitter ──
        sp=QSplitter(Qt.Orientation.Horizontal)

        # Left: registers + breakpoints
        lw=QWidget(); ll=QVBoxLayout(lw); ll.setContentsMargins(0,0,0,0)
        rg=QGroupBox("Registers"); rg.setLayout(QVBoxLayout())
        self._rt=QTableWidget(0,2); self._rt.setHorizontalHeaderLabels(["Reg","Value"])
        self._rt.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        self._rt.verticalHeader().setVisible(False); self._rt.setFont(QFont(ML,11))
        self._rt.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); rg.layout().addWidget(self._rt); ll.addWidget(rg)
        bg=QGroupBox("Breakpoints"); bg.setLayout(QVBoxLayout())
        self._bt=QTableWidget(0,2); self._bt.setHorizontalHeaderLabels(["Address","State"])
        self._bt.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        self._bt.verticalHeader().setVisible(False); self._bt.setFont(QFont(ML,11))
        self._bt.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); bg.layout().addWidget(self._bt)
        rm=QPushButton("Remove Selected"); rm.setProperty("sec","true"); rm.clicked.connect(self._del_bp)
        bg.layout().addWidget(rm); ll.addWidget(bg); sp.addWidget(lw)

        # Center: disasm + memory
        cw=QWidget(); cl=QVBoxLayout(cw); cl.setContentsMargins(0,0,0,0)
        dg=QGroupBox("Disassembly at Current IP"); dg.setLayout(QVBoxLayout())
        self._dt=QTableWidget(0,4); self._dt.setHorizontalHeaderLabels(["Address","Bytes","Mnemonic","Operands"])
        self._dt.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeMode.Stretch)
        self._dt.setColumnWidth(0,105); self._dt.setColumnWidth(1,155); self._dt.setColumnWidth(2,100)
        self._dt.verticalHeader().setVisible(False); self._dt.setFont(QFont(ML,11))
        self._dt.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); dg.layout().addWidget(self._dt); cl.addWidget(dg)
        mg=QGroupBox("Memory Viewer"); mg.setLayout(QVBoxLayout())
        mbar=QHBoxLayout(); self._ma=QLineEdit(); self._ma.setPlaceholderText("Address (hex)..."); self._ma.setFixedWidth(160)
        self._msz=QLineEdit("256"); self._msz.setFixedWidth(60); mrb=QPushButton("Read"); mrb.clicked.connect(self._read_mem)
        mbar.addWidget(self._ma); mbar.addWidget(QLabel("Size:")); mbar.addWidget(self._msz); mbar.addWidget(mrb); mbar.addStretch()
        self._mo=QPlainTextEdit(); self._mo.setReadOnly(True); self._mo.setFont(QFont(ML,10)); self._mo.setMaximumHeight(170)
        mg.layout().addLayout(mbar); mg.layout().addWidget(self._mo); cl.addWidget(mg); sp.addWidget(cw)

        # Right: stack
        sg=QGroupBox("Stack"); sg.setLayout(QVBoxLayout())
        self._sk=QTableWidget(0,2); self._sk.setHorizontalHeaderLabels(["Address","Value"])
        self._sk.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        self._sk.verticalHeader().setVisible(False); self._sk.setFont(QFont(ML,11))
        self._sk.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); sg.layout().addWidget(self._sk); sp.addWidget(sg)

        sp.setSizes([220,700,220]); lay.addWidget(sp,1)

        # Console
        cog=QGroupBox("Debug Console"); cog.setMaximumHeight(190); cog.setLayout(QVBoxLayout())
        self._con=QPlainTextEdit(); self._con.setReadOnly(True); self._con.setFont(QFont(ML,10)); self._con.setMaximumHeight(160)
        cog.layout().addWidget(self._con); lay.addWidget(cog)
        self._set_active(False)

    def _cbtn(self, label, sc, fn):
        b=QPushButton(label); b.setProperty("sec","true")
        if sc: b.setShortcut(sc)
        b.clicked.connect(fn); return b

    def load(self, az):
        if az: self._exe.setText(az.path)

    def _make_dbg(self):
        if IS_WIN: return WinDebugger()
        if IS_LINUX: return LinuxDebugger()
        QMessageBox.critical(None,"Debugger","No debugger available for this platform.\n(Windows and Linux supported)"); return None

    def _wire(self, dbg):
        dbg.log.connect(self._con.appendPlainText)
        dbg.stopped.connect(lambda r:(self._st.setText(f"Stopped: {r}"),self._st.setStyleSheet(f"color:{C['red']};font-weight:600;padding:0 8px;"),self._set_active(False)))
        dbg.bp_hit.connect(lambda a,r:(self._st.setText(f"BP @ 0x{a:08X}"),self._st.setStyleSheet(f"color:{C['orange']};font-weight:600;padding:0 8px;"),self._on_break(a,r)))
        dbg.step_done.connect(lambda a,r:self._on_break(a,r))
        dbg.regs_rdy.connect(self._update_regs)
        dbg.started.connect(lambda pid:(self._st.setText(f"Running  PID {pid}"),self._st.setStyleSheet(f"color:{C['green']};font-weight:600;padding:0 8px;"),self._set_active(True),self._db.setEnabled(True)))

    def _launch(self):
        exe=self._exe.text().strip()
        if not exe or not os.path.isfile(exe): QMessageBox.warning(None,"","File not found."); return
        self._dbg=self._make_dbg()
        if not self._dbg: return
        self._wire(self._dbg); self._con.clear(); self._dbg.launch(exe,self._args.text()); self._db.setEnabled(True)

    def _attach(self):
        try: pid=int(self._exe.text().strip())
        except: QMessageBox.warning(None,"","Enter a PID in the path field."); return
        self._dbg=self._make_dbg()
        if not self._dbg: return
        self._wire(self._dbg); self._con.clear(); self._dbg.attach(pid); self._db.setEnabled(True)

    def _detach(self):
        if self._dbg: self._dbg.detach(); self._dbg=None; self._set_active(False)

    def _run(self):
        if self._dbg: self._dbg.cont()
    def _step(self):
        if self._dbg: self._dbg.step()

    def _add_bp(self):
        if not self._dbg: return
        try: addr=int(self._bpe.text().strip().lstrip("0x"),16)
        except: return
        if self._dbg.add_bp(addr):
            self._bps[addr]=True; self._bpe.clear(); self._refresh_bps()
            self._con.appendPlainText(f"BP set @ 0x{addr:08X}")

    def _del_bp(self):
        if not self._dbg: return
        for it in self._bt.selectedItems():
            if it.column()==0:
                try: addr=int(it.text(),16)
                except: continue
                self._dbg.del_bp(addr); self._bps.pop(addr,None)
        self._refresh_bps()

    def _refresh_bps(self):
        self._bt.setRowCount(len(self._bps))
        ML=C["mono"].split(",")[0]
        for row,(addr,active) in enumerate(self._bps.items()):
            self._bt.setRowHeight(row,22)
            ai=QTableWidgetItem(f"0x{addr:08X}"); ai.setForeground(QColor(C["red"])); ai.setFont(QFont(ML,11,QFont.Weight.Bold))
            si=QTableWidgetItem("Active" if active else "—"); si.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            si.setForeground(QColor(C["green"] if active else C["sec"]))
            self._bt.setItem(row,0,ai); self._bt.setItem(row,1,si)

    def _on_break(self, addr, regs):
        ML=C["mono"].split(",")[0]
        if HAS_CAP and self._dbg:
            mem=self._dbg.read_mem(addr,64)
            if mem:
                is64="RIP" in regs
                md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
                ins=list(md.disasm(mem,addr))[:16]; self._dt.setRowCount(len(ins))
                JMP={"jmp","je","jne","jz","jnz","jl","jg","jle","jge","jb","ja"}
                for row,i in enumerate(ins):
                    self._dt.setRowHeight(row,20)
                    is_cur=i.address==addr
                    ai=QTableWidgetItem(f"0x{i.address:08X}")
                    if is_cur: ai.setForeground(QColor(C["accent"])); ai.setFont(QFont(ML,11,QFont.Weight.Bold))
                    else: ai.setForeground(QColor(C["sec"]))
                    bi=QTableWidgetItem(" ".join(f"{b:02X}" for b in i.bytes)); bi.setForeground(QColor(C["green"]))
                    mn=i.mnemonic; mi=QTableWidgetItem(mn)
                    if mn=="call": mi.setForeground(QColor(C["orange"]))
                    elif mn in JMP: mi.setForeground(QColor(C["accent"]))
                    elif mn in("ret","retn"): mi.setForeground(QColor(C["red"]))
                    oi=QTableWidgetItem(i.op_str)
                    for col,it in enumerate([ai,bi,mi,oi]): self._dt.setItem(row,col,it)
        sp_k="RSP" if "RSP" in regs else "ESP" if "ESP" in regs else None
        if sp_k and self._dbg:
            spv=regs[sp_k]; is64="RSP" in regs; psz=8 if is64 else 4; self._sk.setRowCount(16)
            for i in range(16):
                self._sk.setRowHeight(i,20); sa=spv+i*psz; mem=self._dbg.read_mem(sa,psz)
                ai=QTableWidgetItem(f"0x{sa:08X}"); ai.setForeground(QColor(C["sec"]))
                vi=QTableWidgetItem(mem.hex().upper() if mem else "??")
                self._sk.setItem(i,0,ai); self._sk.setItem(i,1,vi)

    def _update_regs(self, regs):
        ML=C["mono"].split(",")[0]; self._rt.setRowCount(len(regs))
        HL={"EIP":C["accent"],"RIP":C["accent"],"ESP":C["green"],"RSP":C["green"],"EBP":C["orange"],"RBP":C["orange"],"EFLAGS":C["purple"]}
        for row,(k,v) in enumerate(regs.items()):
            self._rt.setRowHeight(row,22)
            ki=QTableWidgetItem(k); ki.setForeground(QColor(C["sec"]))
            vi=QTableWidgetItem(f"0x{v:016X}" if v>0xFFFFFFFF else f"0x{v:08X}")
            col=HL.get(k,C["text"]); vi.setForeground(QColor(col))
            if k in HL: vi.setFont(QFont(ML,11,QFont.Weight.Bold))
            self._rt.setItem(row,0,ki); self._rt.setItem(row,1,vi)

    def _read_mem(self):
        if not self._dbg: return
        try: addr=int(self._ma.text().strip().lstrip("0x"),16)
        except: return
        try: sz=int(self._msz.text())
        except: sz=256
        data=self._dbg.read_mem(addr,sz); lines=[]
        ML=C["mono"].split(",")[0]
        for i in range(0,len(data),16):
            chunk=data[i:i+16]
            lines.append(f"{addr+i:08X}:  {' '.join(f'{b:02X}' for b in chunk):<47}  {''.join(chr(b) if 0x20<=b<=0x7E else '.' for b in chunk)}")
        self._mo.setPlainText("\n".join(lines))

    def _set_active(self, on):
        for b in [self._rb,self._sb,self._ob]: b.setEnabled(on)

# ══════════════════════════════════════════════════════════════════════════════
#  PLUGIN SYSTEM
# ══════════════════════════════════════════════════════════════════════════════
PLUGIN_DIR = Path("./plugins")

class PluginManager:
    @staticmethod
    def scan() -> List[Dict]:
        PLUGIN_DIR.mkdir(exist_ok=True); out=[]
        for p in sorted(PLUGIN_DIR.glob("*.py")):
            try:
                sp=importlib.util.spec_from_file_location(p.stem,p)
                m=importlib.util.module_from_spec(sp); sp.loader.exec_module(m)  # type:ignore
                info=getattr(m,"plugin_info",{"name":p.stem,"description":"No description.","version":"?"})
                info["_m"]=m; out.append(info)
            except Exception as e: out.append({"name":p.stem,"description":f"Error: {e}","version":"?","_m":None})
        return out

    @staticmethod
    def run(info: Dict, az: PEAnalyzer) -> str:
        m=info.get("_m")
        if not m: return "Plugin not loaded."
        try: fn=getattr(m,"run",None); return "No run(analyzer)." if not fn else str(fn(az))
        except Exception as e: return f"Error: {e}"

class PluginsPanel(_Panel):
    def __init__(self): super().__init__(); self._az=None; self._out=None
    def load(self, az):
        self._az=az; plugins=PluginManager.scan()
        w,lay=_scaffold(f"Plugins  ({len(plugins)} found)")
        info=QLabel(f"Plugin directory: {PLUGIN_DIR.resolve()}\nEach .py file needs plugin_info dict + run(analyzer) function.")
        info.setProperty("sub","true"); info.setWordWrap(True); lay.addWidget(info)
        bar=QHBoxLayout()
        ref=QPushButton("Scan Again"); ref.setProperty("sec","true"); ref.clicked.connect(lambda:self.load(self._az))
        bar.addWidget(ref); bar.addStretch(); lay.addLayout(bar)
        for p in plugins:
            card=QGroupBox(f"{p.get('name','?')}   v{p.get('version','?')}"); card.setLayout(QHBoxLayout())
            dl=QLabel(p.get("description","")); dl.setWordWrap(True)
            rb=QPushButton("Run"); rb.clicked.connect(lambda _,pi=p:self._run(pi))
            card.layout().addWidget(dl,1); card.layout().addWidget(rb); lay.addWidget(card)
        if not plugins: lay.addWidget(QLabel("No plugins found. Drop .py files in ./plugins/ and click Scan Again."))
        self._out=QPlainTextEdit(); self._out.setReadOnly(True)
        self._out.setFont(QFont(C["mono"].split(",")[0],11)); self._out.setFixedHeight(200)
        self._out.setPlaceholderText("Plugin output appears here...")
        lay.addWidget(self._out); lay.addStretch(); self.setWidget(w)
    def _run(self, info):
        if not self._az and self._out: self._out.setPlainText("No PE file loaded."); return
        if self._out: self._out.setPlainText(PluginManager.run(info,self._az))

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    NAV = [
        ("Overview",      "overview"),  ("Headers",       "headers"),
        ("Sections",      "sections"),  ("Imports",       "imports"),
        ("Exports",       "exports"),   ("Relocations",   "relocs"),
        ("TLS",           "tls"),       ("Resources",     "resources"),
        ("Debug Info",    "debug"),
        (None, None),
        ("Rich Header",   "rich"),      ("Overlay",       "overlay"),
        ("Crypto",        "crypto"),    ("Code Caves",    "caves"),
        ("Prologues",     "prologues"),
        (None, None),
        ("Hex Editor",    "hex"),       ("Disassembler",  "disasm"),
        ("CFG",           "cfg"),       ("Patches",       "patches"),
        (None, None),
        ("Strings",       "strings"),   ("Network",       "network"),
        ("Analysis",      "analysis"),  ("YARA",          "yara"),
        (None, None),
        ("Global Search", "search"),    ("FLIRT Scan",    "flirt"),
        ("PE Diff",       "diff"),      ("Pattern Scan",  "scanner"),
        ("Section Inject","inject"),
        (None, None),
        ("Debugger",      "dbg"),       ("Ghidra",        "ghidra"),
        (None, None),
        ("Plugins",       "plugins"),
    ]

    def __init__(self):
        super().__init__(); self.az: Optional[PEAnalyzer] = None; self._dark=False
        self.setWindowTitle("KRE  ·  Kovak Reverse Engineering Studio")
        self.resize(1560,960); self.setAcceptDrops(True); self._setup()

    def _setup(self):
        tb=self.addToolBar("Main"); tb.setMovable(False)
        def act(l,sc,fn):
            a=QAction(l,self)
            if sc: a.setShortcut(sc)
            a.triggered.connect(fn); return a
        tb.addAction(act("Open PE...","Ctrl+O",self._open))
        tb.addAction(act("Save Patched...","Ctrl+Shift+S",self._save))
        tb.addSeparator()
        tb.addAction(act("Undo","Ctrl+Z",self._undo))
        tb.addAction(act("Redo","Ctrl+Y",self._redo))
        tb.addAction(act("Undo All","Ctrl+Shift+Z",self._undo_all))
        tb.addAction(act("Reload","Ctrl+R",self._reload))
        tb.addSeparator()
        tb.addAction(act("Export YARA...",None,self._exp_yara))
        tb.addAction(act("Export Strings...",None,self._exp_strings))
        tb.addAction(act("Export JSON Report...",None,self._exp_json))
        tb.addAction(act("Save Session...",None,self._save_sess))
        tb.addAction(act("Load Session...",None,self._load_sess))
        tb.addSeparator()
        da=QAction("Dark Mode",self); da.setCheckable(True); da.toggled.connect(self._dark_toggle); tb.addAction(da)

        c=QWidget(); c.setStyleSheet(f"background:{C['bg']};"); self.setCentralWidget(c)
        ml=QHBoxLayout(c); ml.setContentsMargins(0,0,0,0); ml.setSpacing(0)
        sp=QSplitter(Qt.Orientation.Horizontal)

        sb=QWidget(); sb.setFixedWidth(214)
        sb.setStyleSheet(f"background:{C['sidebar']};border-right:1px solid {C['border']};")
        sbl=QVBoxLayout(sb); sbl.setContentsMargins(0,8,0,8); sbl.setSpacing(0)
        self._fl=QLabel("No file loaded")
        self._fl.setStyleSheet(f"color:{C['sec']};font-size:11px;padding:6px 16px 10px;border-bottom:1px solid {C['border']};background:{C['sidebar']};")
        self._fl.setWordWrap(True); sbl.addWidget(self._fl)
        self.nav=QListWidget(); self.nav.setStyleSheet(f"background:{C['sidebar']};")
        self._nids: List[Optional[str]]=[]
        for label,id_ in self.NAV:
            if label is None:
                sep=QListWidgetItem(); sep.setFlags(Qt.ItemFlag.NoItemFlags); sep.setSizeHint(QSize(0,10))
                self.nav.addItem(sep); self._nids.append(None)
            else: self.nav.addItem(label); self._nids.append(id_)
        self.nav.currentRowChanged.connect(self._nav_changed); sbl.addWidget(self.nav); sp.addWidget(sb)

        self.stack=QStackedWidget(); self.stack.setStyleSheet(f"background:{C['bg']};")
        self._panels: Dict[str,QWidget]={
            "overview": OverviewPanel(),    "headers":  HeadersPanel(),
            "sections": SectionsPanel(),    "imports":  ImportsPanel(),
            "exports":  ExportsPanel(),     "relocs":   RelocsPanel(),
            "tls":      TLSPanel(),         "resources":ResourcesPanel(),
            "debug":    DebugInfoPanel(),
            "rich":     RichHeaderPanel(),  "overlay":  OverlayPanel(),
            "crypto":   CryptoPanel(),      "caves":    CodeCavePanel(),
            "prologues":ProloguesPanel(),
            "hex":      HexPanel(),         "disasm":   DisasmPanel(),
            "cfg":      CFGPanel(),         "patches":  PatchesPanel(),
            "strings":  StringsPanel(),     "network":  NetworkPanel(),
            "analysis": AnalysisPanel(),    "yara":     YaraPanel(),
            "search":   GlobalSearchPanel(),"flirt":    FlirtPanel(),
            "diff":     DiffPanel(),        "scanner":  ScannerPanel(),
            "inject":   SectionInjectorPanel(),
            "dbg":      DebuggerPanel(),    "ghidra":   GhidraPanel(),
            "plugins":  PluginsPanel(),
        }
        for panel in self._panels.values(): self.stack.addWidget(panel)
        sp.addWidget(self.stack); sp.setSizes([214,1346]); ml.addWidget(sp)
        self.statusBar().showMessage("Ready  ·  Ctrl+O to open a PE file  ·  Drag & drop supported")
        self.nav.setCurrentRow(0)

    def _nav_changed(self, row):
        if 0<=row<len(self._nids):
            id_=self._nids[row]
            if id_ and id_ in self._panels: self.stack.setCurrentWidget(self._panels[id_])

    def _open(self):
        p,_=QFileDialog.getOpenFileName(self,"Open PE File","","PE Files (*.exe *.dll *.sys *.ocx *.efi *.scr *.drv);;All Files (*.*)")
        if p: self._load(p)

    def _load(self, path):
        try: az=PEAnalyzer(path)
        except Exception as e: QMessageBox.critical(self,"Load Error",str(e)); return
        self.az=az; name=Path(path).name
        self._fl.setText(name)
        self.statusBar().showMessage(f"Loaded  {name}  ·  {len(az.raw):,} bytes  ·  {'pefile OK' if az.pe else 'pefile unavailable'}")
        for id_,panel in self._panels.items():
            try: panel.load(az)
            except Exception: pass

    def _save(self):
        if not self.az: return
        p,_=QFileDialog.getSaveFileName(self,"Save Patched Binary",Path(self.az.path).stem+"_patched.exe","Executables (*.exe *.dll *.sys);;All Files (*.*)")
        if p: self.az.save(p); self.statusBar().showMessage(f"Saved  →  {p}")

    def _undo(self):
        if not self.az: return
        r=self.az.undo()
        if r: self._refresh_hex(); self._panels["patches"].load(self.az)
        self.statusBar().showMessage("Undone." if r else "Nothing to undo.")

    def _redo(self):
        if not self.az: return
        r=self.az.redo()
        if r: self._refresh_hex(); self._panels["patches"].load(self.az)
        self.statusBar().showMessage("Redone." if r else "Nothing to redo.")

    def _undo_all(self):
        if not self.az: return
        self.az.undo_all(); self._refresh_hex(); self._panels["patches"].load(self.az)
        self.statusBar().showMessage("All patches undone.")

    def _refresh_hex(self):
        hp=self._panels.get("hex")
        if isinstance(hp,HexPanel) and hp.hex_editor: hp.hex_editor.update_data(self.az.raw)

    def _reload(self):
        if self.az: self._load(self.az.path)

    def _exp_yara(self):
        if not self.az: return
        p,_=QFileDialog.getSaveFileName(self,"Export YARA Rule",Path(self.az.path).stem+".yar","YARA (*.yar *.yara);;All (*.*)")
        if p:
            with open(p,"w",encoding="utf-8") as f: f.write(self.az.yara_rule())
            self.statusBar().showMessage(f"YARA  →  {p}")

    def _exp_strings(self):
        if not self.az: return
        p,_=QFileDialog.getSaveFileName(self,"Export Strings",Path(self.az.path).stem+"_strings.txt","Text (*.txt);;All (*.*)")
        if p:
            strs=self.az.strings()
            with open(p,"w",encoding="utf-8") as f:
                f.writelines(f"{s['Offset']}\t{s['Type']}\t{s['String']}\n" for s in strs)
            self.statusBar().showMessage(f"Strings ({len(strs)})  →  {p}")

    def _exp_json(self):
        if not self.az: return
        p,_=QFileDialog.getSaveFileName(self,"Export JSON Report",Path(self.az.path).stem+"_report.json","JSON (*.json);;All (*.*)")
        if p:
            az=self.az
            rpt={"file":Path(az.path).name,"hashes":dict(az.hashes()),
                 "headers":dict(az.header_info()),"sections":az.sections(),
                 "imports":az.imports(),"exports":az.exports(),
                 "relocations":az.relocations(),"tls":dict(az.tls()),
                 "resources":az.resources(),"debug_info":az.debug_info(),
                 "rich_header":az.rich_header(),"overlay":az.overlay(),
                 "packer":az.detect_packer(),"compiler":az.detect_compiler(),
                 "antidebug":az.detect_antidebug(),"suspicious":az.suspicious_imports(),
                 "crypto":az.detect_crypto(),"network":az.network_indicators(),
                 "patches":{str(k):list(v) for k,v in az.history.patches.items()}}
            with open(p,"w",encoding="utf-8") as f: json.dump(rpt,f,indent=2,default=str)
            self.statusBar().showMessage(f"JSON report  →  {p}")

    def _save_sess(self):
        if not self.az: return
        p,_=QFileDialog.getSaveFileName(self,"Save Session","session.kre","KRE Session (*.kre);;JSON (*.json);;All (*.*)")
        if p:
            with open(p,"w") as f:
                json.dump({"path":self.az.path,
                           "patches":{str(k):list(v) for k,v in self.az.history.patches.items()}},f,indent=2)
            self.statusBar().showMessage(f"Session saved  →  {p}")

    def _load_sess(self):
        p,_=QFileDialog.getOpenFileName(self,"Load Session","","KRE Session (*.kre);;JSON (*.json);;All (*.*)")
        if not p: return
        try:
            with open(p) as f: s=json.load(f)
            self._load(s["path"])
            if self.az:
                for off_s,(old,new) in s.get("patches",{}).items(): self.az.history.apply(int(off_s),old,new)
                self.statusBar().showMessage(f"Session loaded  ·  {len(s.get('patches',{}))} patches restored")
        except Exception as e: QMessageBox.critical(self,"Session Error",str(e))

    def _dark_toggle(self, dark):
        self._dark=dark; apply_theme(QApplication.instance(),dark)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls(): e.acceptProposedAction()
    def dropEvent(self, e):
        urls=e.mimeData().urls()
        if urls: self._load(urls[0].toLocalFile())

# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("KRE")
    app.setApplicationDisplayName("KRE  ·  Kovak Reverse Engineering Studio")
    app.setStyleSheet(_qss())
    font = QFont("SF Pro Display,Helvetica Neue,Arial"); font.setPointSize(13)
    app.setFont(font)
    win = MainWindow()
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]): win._load(sys.argv[1])
    win.show()
    sys.exit(app.exec())
