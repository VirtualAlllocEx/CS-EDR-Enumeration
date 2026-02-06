/*
 * svc_enum_bof.c - Service & Driver Enumeration Beacon Object File
 * For use with edr_enum.cna edr_services_bof command
 *
 * Enumerates running Windows services AND/OR loaded kernel drivers via
 * OpenSCManagerW + EnumServicesStatusExW. Supports three modes via
 * a packed short argument:
 *
 *   Mode 0 (default): Both services + drivers  (SERVICE_NAME + DRIVER_NAME)
 *   Mode 1:           Services only             (SERVICE_NAME only)
 *   Mode 2:           Drivers only              (DRIVER_NAME only)
 *
 * Outputs names as narrow strings in a format compatible with the
 * edr_enum.cna blob matcher.
 *
 * Compile (place beacon.h in the same directory):
 *   x64:  x86_64-w64-mingw32-gcc -c svc_enum_bof.c -o svc_enum_bof.x64.o
 *   x86:  i686-w64-mingw32-gcc -c svc_enum_bof.c -o svc_enum_bof.x86.o
 *
 * OPSEC: * MINIMAL - in-process, zero child processes, no AMSI/CLR/ETW
 */

#include <windows.h>
#include "beacon.h"

/*
 * Explicit constant definitions.
 * BOF compilation with MinGW may not resolve all winsvc.h enums
 * depending on include paths and _WIN32_WINNT. Define explicitly.
 */
#ifndef SC_MANAGER_ENUMERATE_SERVICE
#define SC_MANAGER_ENUMERATE_SERVICE 0x0004
#endif

#ifndef SERVICE_WIN32
#define SERVICE_WIN32 0x00000030
#endif

/*
 * SERVICE_DRIVER = SERVICE_KERNEL_DRIVER (0x01) |
 *                  SERVICE_FILE_SYSTEM_DRIVER (0x02) |
 *                  SERVICE_RECOGNIZER_DRIVER (0x08)
 *
 * Enumerates all driver types registered in the SCM: kernel drivers
 * (e.g. csagent.sys, WdFilter), file system minifilters (e.g. SysmonDrv,
 * CbDefenseFilter), and boot-start recognizer drivers.
 */
#ifndef SERVICE_DRIVER
#define SERVICE_DRIVER 0x0000000B
#endif

#ifndef SERVICE_ACTIVE
#define SERVICE_ACTIVE 0x00000001
#endif

#ifndef SC_ENUM_PROCESS_INFO
#define SC_ENUM_PROCESS_INFO 0
#endif

#ifndef HEAP_ZERO_MEMORY
#define HEAP_ZERO_MEMORY 0x00000008
#endif

/* Enumeration modes */
#define MODE_BOTH        0
#define MODE_SVC_ONLY    1
#define MODE_DRV_ONLY    2


/* ---------------------------------------------------------------
 * Dynamic Function Resolution (DFR) declarations
 * --------------------------------------------------------------- */

/* advapi32.dll */
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(
    LPCWSTR lpMachineName,
    LPCWSTR lpDatabaseName,
    DWORD   dwDesiredAccess
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$EnumServicesStatusExW(
    SC_HANDLE hSCManager,
    DWORD     InfoLevel,
    DWORD     dwServiceType,
    DWORD     dwServiceState,
    LPBYTE    lpServices,
    DWORD     cbBufSize,
    LPDWORD   pcbBytesNeeded,
    LPDWORD   lpServicesReturned,
    LPDWORD   lpResumeHandle,
    LPCWSTR   pszGroupName
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(
    SC_HANDLE hSCObject
);

/* kernel32.dll */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(
    HANDLE hHeap,
    DWORD  dwFlags,
    SIZE_T dwBytes
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(
    HANDLE hHeap,
    DWORD  dwFlags,
    LPVOID lpMem
);

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(
    UINT    CodePage,
    DWORD   dwFlags,
    LPCWSTR lpWideCharStr,
    int     cchWideChar,
    LPSTR   lpMultiByteStr,
    int     cbMultiByte,
    LPCSTR  lpDefaultChar,
    LPBOOL  lpUsedDefaultChar
);


/* ---------------------------------------------------------------
 * Helper: enumerate a service type and append to format buffer
 *
 * Performs the two-call EnumServicesStatusExW pattern (size then
 * enumerate) for a given dwServiceType. Appends results to an
 * already-allocated formatp buffer using the specified line prefix
 * ("SERVICE_NAME" or "DRIVER_NAME").
 *
 * Returns the number of entries enumerated, or 0 on failure.
 * On failure, emits a BeaconPrintf error with context but does
 * NOT abort -- the caller can continue with the other phase.
 * --------------------------------------------------------------- */
static DWORD enum_scm_type(
    SC_HANDLE hSCM,
    HANDLE    hHeap,
    DWORD     dwServiceType,
    formatp  *fp,
    char     *linePrefix,       /* "SERVICE_NAME" or "DRIVER_NAME" */
    char     *phaseLabel        /* "services" or "drivers" for error msgs */
)
{
    DWORD     dwBytesNeeded      = 0;
    DWORD     dwServicesReturned = 0;
    DWORD     dwResumeHandle     = 0;
    DWORD     dwBufSize          = 0;
    LPBYTE    lpBuffer           = NULL;
    DWORD     i;
    char      name[512];

    ENUM_SERVICE_STATUS_PROCESSW *pEntries = NULL;

    /* First call: get required buffer size */
    ADVAPI32$EnumServicesStatusExW(
        hSCM,
        (DWORD)SC_ENUM_PROCESS_INFO,
        dwServiceType,
        (DWORD)SERVICE_ACTIVE,
        NULL, 0,
        &dwBytesNeeded,
        &dwServicesReturned,
        &dwResumeHandle,
        NULL
    );

    if (dwBytesNeeded == 0)
    {
        BeaconPrintf(CALLBACK_ERROR,
            "EnumServicesStatusExW sizing for %s failed: %lu",
            phaseLabel, KERNEL32$GetLastError());
        return 0;
    }

    /* Allocate with margin */
    dwBufSize = dwBytesNeeded + 8192;
    lpBuffer = (LPBYTE)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufSize);
    if (lpBuffer == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR,
            "HeapAlloc for %s failed: %lu bytes", phaseLabel, dwBufSize);
        return 0;
    }

    /* Second call: enumerate */
    dwResumeHandle     = 0;
    dwServicesReturned = 0;
    if (!ADVAPI32$EnumServicesStatusExW(
        hSCM,
        (DWORD)SC_ENUM_PROCESS_INFO,
        dwServiceType,
        (DWORD)SERVICE_ACTIVE,
        lpBuffer,
        dwBufSize,
        &dwBytesNeeded,
        &dwServicesReturned,
        &dwResumeHandle,
        NULL))
    {
        BeaconPrintf(CALLBACK_ERROR,
            "EnumServicesStatusExW for %s failed: %lu",
            phaseLabel, KERNEL32$GetLastError());
        KERNEL32$HeapFree(hHeap, 0, lpBuffer);
        return 0;
    }

    if (dwServicesReturned == 0)
    {
        /* Not necessarily an error -- log but don't treat as failure. */
        BeaconFormatPrintf(fp, "--- %s: 0 found ---\n", phaseLabel);
        KERNEL32$HeapFree(hHeap, 0, lpBuffer);
        return 0;
    }

    /*
     * Append entries to the shared format buffer.
     * CRITICAL: BeaconFormatPrintf does NOT support %S (wide string).
     * Must convert each wide name to narrow via WideCharToMultiByte
     * and use %s (narrow string) format specifier.
     */
    pEntries = (ENUM_SERVICE_STATUS_PROCESSW *)lpBuffer;

    BeaconFormatPrintf(fp, "--- %s (%lu entries) ---\n",
        phaseLabel, dwServicesReturned);

    for (i = 0; i < dwServicesReturned; i++)
    {
        name[0] = '\0';
        KERNEL32$WideCharToMultiByte(
            65001,      /* CP_UTF8 */
            0,
            pEntries[i].lpServiceName,
            -1,
            name,
            sizeof(name) - 1,
            NULL,
            NULL
        );
        name[sizeof(name) - 1] = '\0';

        BeaconFormatPrintf(fp, "%s: %s\n", linePrefix, name);
    }

    KERNEL32$HeapFree(hHeap, 0, lpBuffer);
    return dwServicesReturned;
}


/* ---------------------------------------------------------------
 * BOF entry point
 *
 * Accepts one packed short argument: mode
 *   0 = both services + drivers (default / backward-compatible)
 *   1 = services only
 *   2 = drivers only
 *
 * If no argument is provided (alen == 0), defaults to mode 0.
 * --------------------------------------------------------------- */
void go(char *args, int alen)
{
    SC_HANDLE hSCM     = NULL;
    HANDLE    hHeap    = NULL;
    formatp   fp;
    int       outLen   = 0;
    char     *outBuf   = NULL;
    DWORD     nSvc     = 0;
    DWORD     nDrv     = 0;
    short     mode     = MODE_BOTH;
    datap     parser;

    /* Always initialize parser (suppresses -Wunused-parameter).
     * BeaconDataParse with alen=0 is safe — creates an empty parser. */
    BeaconDataParse(&parser, args, alen);

    /* Read mode argument if provided */
    if (alen > 0)
    {
        mode = BeaconDataShort(&parser);
    }

    /* Validate mode */
    if (mode < MODE_BOTH || mode > MODE_DRV_ONLY)
    {
        BeaconPrintf(CALLBACK_ERROR,
            "Invalid mode %d. Use: 0=both, 1=svc, 2=drv", mode);
        return;
    }

    /* Open local SCM -- one handle for both phases */
    hSCM = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCM == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR,
            "OpenSCManagerW failed: %lu", KERNEL32$GetLastError());
        return;
    }

    hHeap = KERNEL32$GetProcessHeap();

    /*
     * Single format buffer for both phases.
     * 512 KB accommodates systems with 300+ services and 200+ drivers.
     */
    BeaconFormatAlloc(&fp, 512 * 1024);

    if (mode == MODE_BOTH)
        BeaconFormatPrintf(&fp,
            "--- BOF Service & Driver Enumeration ---\n");
    else if (mode == MODE_SVC_ONLY)
        BeaconFormatPrintf(&fp,
            "--- BOF Service Enumeration ---\n");
    else
        BeaconFormatPrintf(&fp,
            "--- BOF Driver Enumeration ---\n");

    /* -------------------------------------------------------
     * Phase 1: Win32 services (user-mode)
     * Output prefix: SERVICE_NAME
     * Backward compatible with existing CNA parser.
     * ------------------------------------------------------- */
    if (mode == MODE_BOTH || mode == MODE_SVC_ONLY)
    {
        nSvc = enum_scm_type(
            hSCM, hHeap,
            SERVICE_WIN32,
            &fp,
            "SERVICE_NAME",
            "services"
        );
    }

    /* -------------------------------------------------------
     * Phase 2: Kernel drivers
     * Output prefix: DRIVER_NAME
     * Includes: kernel drivers (Type 1), file system drivers
     * (Type 2), and recognizer drivers (Type 8).
     *
     * Catches EDR kernel components that may still be loaded
     * even when their user-mode service is stopped, renamed,
     * or absent from the service signature DB.
     * ------------------------------------------------------- */
    if (mode == MODE_BOTH || mode == MODE_DRV_ONLY)
    {
        nDrv = enum_scm_type(
            hSCM, hHeap,
            SERVICE_DRIVER,
            &fp,
            "DRIVER_NAME",
            "drivers"
        );
    }

    BeaconFormatPrintf(&fp,
        "--- END (services: %lu, drivers: %lu) ---\n",
        nSvc, nDrv);

    /* Send as single CALLBACK_OUTPUT.
     * CRITICAL: Must split into two statements. C does not guarantee
     * argument evaluation order -- if the compiler evaluates outLen
     * (3rd arg) before BeaconFormatToString (2nd arg), outLen is
     * still 0 and BeaconOutput sends nothing. */
    outLen = 0;
    outBuf = BeaconFormatToString(&fp, &outLen);
    BeaconOutput(CALLBACK_OUTPUT, outBuf, outLen);

    /* Cleanup */
    BeaconFormatFree(&fp);
    ADVAPI32$CloseServiceHandle(hSCM);
}