"""
KRE Plugin — Hash Report
Shows all file hashes, ImpHash, and section-level hashes.
"""
plugin_info = {
    "name":        "Hash Report",
    "description": "Full hash report: file hashes, ImpHash, and MD5 of each section's raw data.",
    "version":     "1.0",
}

import hashlib

def run(analyzer):
    lines = [
        "=" * 58,
        "  HASH REPORT",
        "=" * 58, "",
        "  File Hashes",
        "  " + "-" * 54,
    ]

    for k, v in analyzer.hashes():
        lines.append(f"  {k:<12}  {v}")

    lines += ["", "  Section Hashes", "  " + "-" * 54]

    for s in analyzer.sections():
        if analyzer.pe:
            try:
                raw_off = int(s["RawOffset"], 16)
                raw_sz  = int(s["RawSize"],   16)
                data    = bytes(analyzer.raw[raw_off:raw_off + raw_sz])
                md5     = hashlib.md5(data).hexdigest().upper()
                sha1    = hashlib.sha1(data).hexdigest().upper()
                lines.append(f"  {s['Name']:<12}")
                lines.append(f"    MD5  : {md5}")
                lines.append(f"    SHA1 : {sha1}")
                lines.append(f"    Size : {raw_sz:,} bytes")
                lines.append("")
            except Exception:
                lines.append(f"  {s['Name']:<12}  (error reading data)")

    return "\n".join(lines)
