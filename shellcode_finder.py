"""
KRE Plugin Shellcode Finder
Locates injectable code cave regions and scans for common shellcode signatures.
"""
plugin_info = {
    "name":        "Shellcode Finder",
    "description": "Finds code caves, detects shellcode signatures, and reports injectable regions by size.",
    "version":     "1.0",
}

# Known shellcode signature patterns (hex, with ?? wildcards represented as None)
# Each entry: (name, first_bytes_hex)
SHELLCODE_SIGS = [
    ("Meterpreter x86",    "FC E8"),
    ("Meterpreter x64",    "FC 48 83"),
    ("NOP sled",           "90 90 90 90"),
    ("Classic x86 stub",   "60 E8 00 00 00 00"),
    ("pusha+call",         "60 E8"),
    ("GetPC x86",          "E8 00 00 00 00 58"),
    ("GetPC x64",          "E8 00 00 00 00 48"),
    ("CMD stub",           "31 C0 50 68 2E 65 78 65"),
    ("Reverse shell stub", "31 DB 53 89 E3"),
    ("XOR decoder",        "EB ?? 5E 31 C9"),
    ("LoadLibrary pattern","68 ?? ?? ?? ?? FF 15"),
    ("CALL EDX thunk",     "FF D2"),
    ("CALL EAX thunk",     "FF D0"),
    ("JMP ESP",            "FF E4"),
    ("JMP EAX",            "FF E0"),
]


def _find_sig(data: bytes, sig_hex: str) -> list:
    #Find a signature (supports ?? wildcards) in data.
    tokens = sig_hex.split()
    pat = []
    for t in tokens:
        pat.append(None if t == "??" else int(t, 16))
    hits = []
    pl = len(pat)
    for i in range(len(data) - pl + 1):
        if all(pb is None or data[i+j] == pb for j, pb in enumerate(pat)):
            hits.append(i)
    return hits


def run(analyzer):
    raw = bytes(analyzer.raw)
    lines = [
        "  SHELLCODE FINDER"
    ]
    # 1. Code caves
    caves = analyzer.find_code_caves(min_size=64, byte=0x00)
    cc_lines = [f"  Code Caves  ({len(caves)} usable regions ≥ 64 bytes)", "  " + "-" * 56]
    if not caves:
        cc_lines.append("  No code caves found.")
    else:
        for c in sorted(caves, key=lambda x: x["Size"], reverse=True)[:20]:
            flag = "  *** LARGE ***" if c["Size"] >= 256 else ""
            cc_lines.append(
                f"  {c['Offset']}  VA:{c['VA']}  {c['Size']:>6} bytes  [{c['Section']}]{flag}"
            )
    lines += cc_lines
    lines.append("")

    # 2. Shellcode signature scan
    lines.append(f"  Shellcode Signature Scan  ({len(SHELLCODE_SIGS)} patterns)")
    lines.append("  " + "-" * 56)
    total_hits = 0
    for name, sig in SHELLCODE_SIGS:
        hits = _find_sig(raw, sig)
        if hits:
            total_hits += len(hits)
            offsets = "  ".join(f"0x{h:08X}" for h in hits[:5])
            more = f"  (+{len(hits)-5} more)" if len(hits) > 5 else ""
            lines.append(f"  [{name}]")
            lines.append(f"    Hits: {len(hits)}   Offsets: {offsets}{more}")
    if total_hits == 0:
        lines.append("  No known shellcode signatures matched.")
    lines.append("")

    # 3. Executable section entropy
    lines.append("  Executable Sections — Entropy")
    lines.append("  " + "-" * 5)
    for s in analyzer.sections():
        if not s.get("X"): continue
        ent = s["EntropyF"]
        bar = "#" * int(ent / 8 * 24) + "." * (24 - int(ent / 8 * 24))
        flag = "  <-- POSSIBLY PACKED/ENCODED" if ent > 7.0 else ""
        lines.append(f"  {s['Name']:<12} [{bar}] {ent:.3f}{flag}")
    lines.append("")

    lines += [
        f"  Total shellcode pattern hits : {total_hits}",
        f"  Total injectable cave regions : {len(caves)}"
    ]
    return "\n".join(lines)
