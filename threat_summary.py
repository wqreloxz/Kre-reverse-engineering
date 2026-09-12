"""
KRE Plugin Threat Summary
One page threat assessment combining all analysis modules.
"""
plugin_info = {
    "name":        "Threat Summary",
    "description": "One-page threat assessment: packing, compiler, anti-debug, suspicious APIs, crypto, network.",
    "version":     "1.0",
}

def _score(pck, sus, adb, cry, net_total):
    score = 0
    if pck["packed"]:    score += 30
    if len(sus) >= 3:    score += 25
    elif len(sus) >= 1:  score += 15
    if len(adb) >= 2:    score += 20
    elif len(adb) >= 1:  score += 10
    if len(cry) >= 2:    score += 15
    elif len(cry) >= 1:  score += 8
    if net_total >= 3:   score += 10
    elif net_total >= 1: score += 5
    return min(score, 100)

def run(analyzer):
    pck  = analyzer.detect_packer()
    cmp  = analyzer.detect_compiler()
    sus  = analyzer.suspicious_imports()
    adb  = analyzer.detect_antidebug()
    cry  = analyzer.detect_crypto()
    net  = analyzer.network_indicators()
    net_total = sum(len(v) for v in net.values())

    score = _score(pck, sus, adb, cry, net_total)
    rating = ("CLEAN   " if score < 20 else
              "LOW     " if score < 40 else
              "MEDIUM  " if score < 60 else
              "HIGH    " if score < 80 else
              "CRITICAL")

    lines = [
        f"  THREAT SUMMARY",
        f"  Risk Score  : {score}/100   [{rating}]",
        f"  Packing     : {'YES — ' + (pck['packer'] or 'Unknown packer') if pck['packed'] else 'No'}",
        f"  Compiler    : {', '.join(cmp)}",
        f"  ImpHash     : {analyzer.imphash() or 'N/A'}",
        "",
        f"  Suspicious APIs ({len(sus)}):",
    ]

    for api in sus[:10]:
        lines.append(f"    {api}")
    if len(sus) > 10:
        lines.append(f"    ... and {len(sus) - 10} more")

    lines += ["", f"  Anti-Debug APIs ({len(adb)}):"]
    for api in adb[:8]:
        lines.append(f"    {api}")

    lines += ["", f"  Crypto Constants ({len(cry)} unique hits):"]
    seen = set()
    for h in cry:
        if h["Name"] not in seen:
            seen.add(h["Name"])
            lines.append(f"    {h['Name']}  —  {h['Desc']}")

    lines += ["", f"  Network Indicators: {net_total} total"]
    for cat, items in net.items():
        if items:
            lines.append(f"    {cat}: {len(items)}")

    for ind in pck["indicators"][:5]:
        lines.append(f"  Indicator   : {ind}")

    lines += ["", "=" * 1]
    return "\n".join(lines)
