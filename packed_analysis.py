"""
KRE Plugin Packed Binary Analysis
Full analysis workflow for packed / protected executables.
"""
plugin_info = {
    "name":        "Packed Analysis",
    "description": "Deep analysis for packed binaries: packer ID, OEP heuristics, overlay, import stub scan.",
    "version":     "1.0",
}

import struct


def _entropy(data: bytes) -> float:
    import math
    from collections import Counter
    if not data: return 0.0
    c = Counter(data); t = len(data)
    return -sum((v/t)*math.log2(v/t) for v in c.values() if v > 0)


def _find_oep_candidates(analyzer) -> list:
    """
    Heuristic OEP candidates:
    - Entry point in an unusual section (not .text / code)
    - First bytes of EP look like a decompression stub
    """
    candidates = []
    if not analyzer.pe: return candidates
    ep_rva = analyzer.pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_off = analyzer.ep_offset()
    if ep_off is None: return candidates

    # Check which section contains EP
    for s in analyzer.pe.sections:
        va = s.VirtualAddress
        sz = s.Misc_VirtualSize
        if va <= ep_rva < va + sz:
            name = s.Name.decode("utf-8","replace").rstrip("\x00").strip()
            data = s.get_data()
            ent  = _entropy(data)
            candidates.append({
                "section": name,
                "ep_rva":  f"0x{ep_rva:08X}",
                "ep_off":  f"0x{ep_off:08X}",
                "entropy": f"{ent:.3f}",
                "is_standard": name in (".text","CODE","code",".code"),
                "is_high_ent": ent > 7.0,
            })
            break
    return candidates


def _tail_bytes(data: bytes, n: int = 16) -> str:
    chunk = data[-n:]
    return " ".join(f"{b:02X}" for b in chunk)


def run(analyzer):
    lines = [
        "  PACKED BINARY ANALYSIS"
    ]

    # 1. Packer detection
    pck = analyzer.detect_packer()
    lines.append("  PACKER IDENTIFICATION")
    lines.append("  " + "-" * 5)
    lines.append(f"  Packed        : {'YES' if pck['packed'] else 'NO'}")
    lines.append(f"  Packer        : {pck['packer'] or 'Unknown / Custom'}")
    for ind in pck["indicators"]:
        lines.append(f"  Indicator     : {ind}")
    lines.append("")

    # 2. Entry point analysis
    oep = _find_oep_candidates(analyzer)
    lines.append("  ENTRY POINT ANALYSIS")
    lines.append("  " + "-" * 5)
    if oep:
        c = oep[0]
        lines.append(f"  EP RVA        : {c['ep_rva']}")
        lines.append(f"  EP File Offset: {c['ep_off']}")
        lines.append(f"  Section       : {c['section']}")
        lines.append(f"  Entropy       : {c['entropy']}")
        lines.append(f"  Standard sect : {'Yes' if c['is_standard'] else 'NO — unusual EP location'}")
        if c["is_high_ent"]:
            lines.append("  WARNING       : High entropy at EP — likely stub code")
        # First 32 bytes at EP
        ep_off = analyzer.ep_offset()
        if ep_off is not None:
            chunk = bytes(analyzer.raw[ep_off:ep_off+32])
            lines.append(f"  First 32 bytes: {' '.join(f'{b:02X}' for b in chunk)}")
    else:
        lines.append("  Could not determine EP section.")
    lines.append("")

    # 3. Section entropy map
    lines.append("  SECTION ENTROPY MAP")
    lines.append("  " + "-" * 5)
    for s in analyzer.sections():
        ent  = s["EntropyF"]
        bar  = "#" * int(ent/8*20) + "." * (20-int(ent/8*20))
        risk = "HIGH   " if ent>7.2 else "MEDIUM " if ent>5.5 else "LOW    "
        lines.append(f"  {s['Name']:<12} [{bar}] {ent:.3f}  {risk}  {s['RawSize']}")
    lines.append("")

    # 4. Overlay check
    ov = analyzer.overlay()
    lines.append("  OVERLAY ANALYSIS")
    lines.append("  " + "-" * 5)
    if ov.get("present"):
        lines.append(f"  Overlay found : YES")
        lines.append(f"  Offset        : 0x{ov['offset']:08X}")
        lines.append(f"  Size          : {ov['size']:,} bytes")
        lines.append(f"  Entropy       : {ov['entropy']:.3f}")
        lines.append(f"  Type hints    : {'ZIP ' if ov.get('is_zip') else ''}{'PE ' if ov.get('is_pe') else ''}{'ELF ' if ov.get('is_elf') else ''}{'(unknown)' if not any([ov.get('is_zip'),ov.get('is_pe'),ov.get('is_elf')]) else ''}")
        lines.append(f"  First bytes   : {ov.get('preview','')}")
    else:
        lines.append("  No overlay data.")
    lines.append("")

    # 5. Import pattern
    lines.append("  IMPORT PATTERN")
    lines.append("  " + "-" * 58)
    imps = analyzer.imports()
    total_fns = sum(len(v) for v in imps.values())
    lines.append(f"  DLL count     : {len(imps)}")
    lines.append(f"  Function count: {total_fns}")
    if total_fns < 5:
        lines.append("  WARNING       : Very few imports — typical of packed binary")
    # Check for loader-only pattern
    loader_apis = {"VirtualAlloc","VirtualProtect","LoadLibraryA","LoadLibraryW","GetProcAddress"}
    found_loader = set()
    for dll, fns in imps.items():
        for fn in fns:
            if fn in loader_apis: found_loader.add(fn)
    if found_loader:
        lines.append(f"  Loader APIs   : {', '.join(sorted(found_loader))}")
        lines.append("  NOTE          : Loader-only imports suggest runtime unpacking")
    for dll, fns in imps.items():
        lines.append(f"  [{dll}]")
        for fn in fns[:8]: lines.append(f"    {fn}")
        if len(fns) > 8: lines.append(f"    ... ({len(fns)-8} more)")
    lines.append("")

    # 6. Recommendations
    lines.append("  RECOMMENDATIONS")
    lines.append("  " + "-" * 58)
    if pck["packer"] == "UPX":
        lines.append("  → Run: upx -d target.exe  (free decompression)")
    elif pck["packed"]:
        lines.append("  → Use Debugger panel: Launch → add BP at EP → run until OEP")
        lines.append("  → Dump process memory at OEP using Debugger → Memory Viewer")
        lines.append("  → Use Import Reconstruction panel after dump")
    if ov.get("present") and ov.get("is_pe"):
        lines.append("  → Extract overlay (Overlay panel) — may be the original PE")
    if total_fns < 5:
        lines.append("  → Use Import Reconstruction panel to rebuild IAT")

    lines += ["", "=" * 2]
    return "\n".join(lines)
