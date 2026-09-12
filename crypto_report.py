"""
KRE Plugin Crypto Report
Detailed crypto constant scan grouped by algorithm.
"""
plugin_info = {
    "name":        "Crypto Report",
    "description": "Scans for crypto constants (AES, SHA, MD5, CRC32, Salsa20, TEA, Blowfish, DES) and groups results by algorithm.",
    "version":     "1.0",
}

def run(analyzer):
    hits = analyzer.detect_crypto()
    if not hits:
        return "No cryptographic constants detected."

    by_algo = {}
    for h in hits:
        by_algo.setdefault(h["Name"], []).append(h)

    lines = [
        f"  CRYPTO REPORT   {len(hits)} hit(s) across {len(by_algo)} algorithm(s)"
    ]

    for algo, entries in sorted(by_algo.items()):
        lines.append(f"  [{algo}]")
        lines.append(f"  Description : {entries[0]['Desc']}")
        lines.append(f"  Hits        : {len(entries)}")
        for e in entries:
            lines.append(f"    Offset {e['Offset']}   Section: {e['Section']}")
        lines.append("")

    lines += [
        "  Tip: multiple crypto families in one binary often",
        "  indicates a packer or custom encryption layer."
    ]
    return "\n".join(lines)
