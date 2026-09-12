"""
KRE Plugin — MITRE ATT&CK Mapper
Maps detected APIs and behaviors to MITRE ATT&CK techniques.
"""
plugin_info = {
    "name":        "MITRE ATT&CK Mapper",
    "description": "Maps suspicious APIs, anti-debug calls, and behaviors to MITRE ATT&CK techniques (T-codes).",
    "version":     "1.0",
}

# API → (Technique ID, Technique Name, Tactic)
TECHNIQUE_MAP = {
    # Defense Evasion / Anti-Debug
    "IsDebuggerPresent":              ("T1622",   "Debugger Evasion",                    "Defense Evasion"),
    "CheckRemoteDebuggerPresent":     ("T1622",   "Debugger Evasion",                    "Defense Evasion"),
    "NtQueryInformationProcess":      ("T1622",   "Debugger Evasion",                    "Defense Evasion"),
    "FindWindow":                     ("T1622",   "Debugger Evasion",                    "Defense Evasion"),
    "OutputDebugString":              ("T1622",   "Debugger Evasion",                    "Defense Evasion"),
    "GetTickCount":                   ("T1622",   "Debugger Evasion (timing)",            "Defense Evasion"),
    "QueryPerformanceCounter":        ("T1622",   "Debugger Evasion (timing)",            "Defense Evasion"),
    "NtSetInformationThread":         ("T1622",   "Debugger Evasion (thread hiding)",     "Defense Evasion"),
    "BlockInput":                     ("T1562",   "Impair Defenses",                     "Defense Evasion"),

    # Process Injection
    "VirtualAllocEx":                 ("T1055",   "Process Injection",                   "Defense Evasion / Privilege Escalation"),
    "WriteProcessMemory":             ("T1055",   "Process Injection",                   "Defense Evasion / Privilege Escalation"),
    "CreateRemoteThread":             ("T1055.003","Thread Execution Hijacking",          "Defense Evasion / Privilege Escalation"),
    "NtCreateThreadEx":               ("T1055.003","Thread Execution Hijacking",          "Defense Evasion / Privilege Escalation"),
    "RtlCreateUserThread":            ("T1055.003","Thread Execution Hijacking",          "Defense Evasion / Privilege Escalation"),
    "QueueUserAPC":                   ("T1055.004","Asynchronous Procedure Call",         "Defense Evasion / Privilege Escalation"),
    "SetWindowsHookEx":               ("T1056.004","Credential API Hooking",              "Collection / Credential Access"),
    "NtUnmapViewOfSection":           ("T1055.012","Process Hollowing",                   "Defense Evasion / Privilege Escalation"),
    "CreateFileMappingA":             ("T1055.015","ListPlanting / Shared Section",       "Defense Evasion"),
    "MapViewOfFile":                  ("T1055.015","ListPlanting / Shared Section",       "Defense Evasion"),

    # Privilege Escalation
    "AdjustTokenPrivileges":          ("T1134.001","Token Impersonation/Theft",           "Privilege Escalation"),
    "LookupPrivilegeValue":           ("T1134.001","Token Impersonation/Theft",           "Privilege Escalation"),
    "CreateProcessAsUser":            ("T1134.002","Create Process with Token",           "Privilege Escalation"),
    "OpenProcess":                    ("T1057",   "Process Discovery / Injection",        "Discovery / Lateral Movement"),

    # Persistence
    "RegSetValueEx":                  ("T1547.001","Registry Run Keys",                  "Persistence"),
    "RegCreateKeyEx":                 ("T1547.001","Registry Run Keys",                  "Persistence"),
    "SHFileOperation":                ("T1036",   "Masquerading",                        "Defense Evasion"),

    # Command & Control / Network
    "InternetOpen":                   ("T1071.001","Web Protocols (C2)",                  "Command and Control"),
    "InternetOpenUrl":                ("T1071.001","Web Protocols (C2)",                  "Command and Control"),
    "HttpOpenRequest":                ("T1071.001","Web Protocols (C2)",                  "Command and Control"),
    "HttpSendRequest":                ("T1071.001","Web Protocols (C2)",                  "Command and Control"),
    "URLDownloadToFile":              ("T1105",   "Ingress Tool Transfer",               "Command and Control"),

    # Execution
    "WinExec":                        ("T1059",   "Command and Scripting Interpreter",   "Execution"),
    "ShellExecute":                   ("T1059",   "Command and Scripting Interpreter",   "Execution"),

    # Credential Access
    "GetAsyncKeyState":               ("T1056.001","Keylogging",                          "Collection / Credential Access"),

    # Collection
    "FindFirstFile":                  ("T1083",   "File and Directory Discovery",        "Discovery"),

    # Encryption / Evasion
    "CryptEncrypt":                   ("T1560.001","Archive via Custom Encryption",       "Collection / Exfiltration"),
    "CryptDecrypt":                   ("T1140",   "Deobfuscate/Decode Files or Info",    "Defense Evasion"),
}


def run(analyzer):
    sus = analyzer.suspicious_imports()
    adb = analyzer.detect_antidebug()
    all_apis = list(set(sus + adb))

    lines = [
        "=" * 66,
        "  MITRE ATT&CK TECHNIQUE MAPPER",
        "=" * 66, "",
    ]

    if not all_apis:
        lines.append("  No suspicious or anti-debug APIs detected.")
        lines.append("  Nothing to map to ATT&CK techniques.")
        return "\n".join(lines)

    # Group by tactic
    by_tactic: dict = {}
    unmatched = []
    for api in sorted(all_apis):
        if api in TECHNIQUE_MAP:
            tid, tname, tactic = TECHNIQUE_MAP[api]
            key = tactic
            by_tactic.setdefault(key, []).append((api, tid, tname))
        else:
            unmatched.append(api)

    for tactic, entries in sorted(by_tactic.items()):
        lines.append(f"  TACTIC: {tactic}")
        lines.append("  " + "-" * 62)
        seen_tech = set()
        for api, tid, tname in entries:
            if tid not in seen_tech:
                seen_tech.add(tid)
                lines.append(f"    {tid}  {tname}")
            lines.append(f"          → {api}")
        lines.append("")

    if unmatched:
        lines.append("  Detected APIs (no direct ATT&CK mapping):")
        for api in unmatched:
            lines.append(f"    {api}")
        lines.append("")

    # Summary
    all_tids = set()
    for entries in by_tactic.values():
        for _, tid, _ in entries: all_tids.add(tid)

    lines += [
        "=" * 66,
        f"  Total ATT&CK Techniques matched : {len(all_tids)}",
        f"  Total Tactics covered           : {len(by_tactic)}",
        f"  APIs without mapping            : {len(unmatched)}",
        "",
        "  Reference: https://attack.mitre.org/techniques/",
        "=" * 66,
    ]
    return "\n".join(lines)
