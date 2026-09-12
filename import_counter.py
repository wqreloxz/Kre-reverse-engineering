"""
KRE Plugin — Import Counter
Lists all DLLs and functions. Flags suspicious and anti-debug APIs.
"""
plugin_info = {
    "name":        "Import Counter",
    "description": "Lists every DLL and function. Flags suspicious and anti-debug APIs in red.",
    "version":     "1.1",
}

SUSPICIOUS = {
    "CreateRemoteThread","VirtualAllocEx","WriteProcessMemory","ReadProcessMemory",
    "OpenProcess","NtCreateThreadEx","RtlCreateUserThread","SetWindowsHookEx",
    "GetAsyncKeyState","RegSetValueEx","RegCreateKeyEx","SHFileOperation",
    "InternetOpenUrl","InternetOpen","WinExec","ShellExecute","CreateProcessAsUser",
    "CryptEncrypt","CryptDecrypt","HttpOpenRequest","URLDownloadToFile",
    "CreateFileMappingA","MapViewOfFile","QueueUserAPC","NtUnmapViewOfSection",
}
ANTIDEBUG = {
    "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
    "OutputDebugString","GetTickCount","QueryPerformanceCounter",
    "NtSetInformationThread","FindWindow","BlockInput","NtClose",
}

def run(analyzer):
    imports   = analyzer.imports()
    total_fns = sum(len(v) for v in imports.values())
    sus_found = []
    adb_found = []

    lines = [
        "=" * 58,
        f"  IMPORT COUNTER   {len(imports)} DLLs  /  {total_fns} functions",
        "=" * 58, "",
    ]

    for dll, fns in imports.items():
        sus = [f for f in fns if f in SUSPICIOUS]
        adb = [f for f in fns if f in ANTIDEBUG]
        sus_found.extend(sus)
        adb_found.extend(adb)
        flags = ""
        if sus: flags += f"  [{len(sus)} suspicious]"
        if adb: flags += f"  [{len(adb)} anti-debug]"
        lines.append(f"  [{dll}]  {len(fns)} function(s){flags}")
        for fn in fns:
            tag = ""
            if fn in SUSPICIOUS: tag = "  <-- SUSPICIOUS"
            elif fn in ANTIDEBUG: tag = "  <-- ANTI-DEBUG"
            lines.append(f"      {fn}{tag}")
        lines.append("")

    lines += [
        "=" * 58,
        f"  Suspicious APIs : {len(sus_found)}",
        f"  Anti-debug APIs : {len(adb_found)}",
        f"  ImpHash         : {analyzer.imphash() or 'N/A'}",
        "=" * 58,
    ]
    return "\n".join(lines)
