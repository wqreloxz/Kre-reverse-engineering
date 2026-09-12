"""
KRE Plugin — Network Indicator Report
Extracts and formats all network indicators found in the binary.
"""
plugin_info = {
    "name":        "Network Indicator Report",
    "description": "Extracts URLs, IPs, email addresses, and domain names from raw binary.",
    "version":     "1.0",
}

def run(analyzer):
    net = analyzer.network_indicators()
    total = sum(len(v) for v in net.values())

    if total == 0:
        return "No network indicators found."

    lines = [
        "=" * 58,
        f"  NETWORK INDICATORS   {total} total",
        "=" * 58, "",
    ]

    for category, items in net.items():
        if not items:
            continue
        lines.append(f"  [{category}]  {len(items)} found")
        for item in items[:100]:
            lines.append(f"    {item}")
        if len(items) > 100:
            lines.append(f"    ... and {len(items) - 100} more")
        lines.append("")

    return "\n".join(lines)
