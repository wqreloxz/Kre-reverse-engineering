"""
KRE Plugin Entropy Scanner
Visual entropy report per section with risk ratings.
"""
plugin_info = {
    "name":        "Entropy Scanner",
    "description": "Rates each section by entropy. Flags possible packing or encryption.",
    "version":     "1.0",
}

def run(analyzer):
    secs = analyzer.sections()
    if not secs:
        return "No sections found."

    lines = [
        "  ENTROPY SCANNER",
        "  Scale: 0.0 = empty/constant   8.0 = random/encrypted"
    ]

    for s in secs:
        ent  = s["EntropyF"]
        bar  = "#" * int(ent / 8.0 * 32) + "." * (32 - int(ent / 8.0 * 32))
        risk = "LOW    " if ent < 5.0 else "MEDIUM " if ent < 7.0 else "HIGH   "
        flag = "  <-- POSSIBLE PACKING" if ent > 7.2 else ""
        lines.append(f"  {s['Name']:<12} [{bar}]  {ent:.3f}  {risk}{flag}")

    packed = [s for s in secs if s["EntropyF"] > 7.2]
    lines += [
        f"  Sections above 7.2 entropy : {len(packed)}",
        f"  {'Likely packed/encrypted.' if packed else 'No high-entropy sections detected.'}"
    ]
    return "\n".join(lines)
