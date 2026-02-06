/*
 * beacon.h - Cobalt Strike Beacon Object File API
 *
 * This header declares the Beacon API functions available to BOFs
 * when executed via beacon_inline_execute(). These functions are
 * resolved at runtime by the Beacon loader.
 *
 * Reference: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm
 */

#ifndef _BEACON_H_
#define _BEACON_H_

#include <windows.h>

/* ---------------------------------------------------------------
 * Data Parsing API
 *
 * Used to parse arguments passed from Aggressor via bof_pack().
 * The datap structure tracks position within a packed argument
 * buffer. Use BeaconDataParse to initialize, then extract values
 * with the type-specific functions.
 * --------------------------------------------------------------- */

typedef struct {
    char *original;   /* pointer to start of buffer       */
    char *buffer;     /* current read position             */
    int   length;     /* total bytes in buffer              */
    int   size;       /* bytes remaining from current pos   */
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap *parser);
DECLSPEC_IMPORT char   *BeaconDataExtract(datap *parser, int *size);

/* ---------------------------------------------------------------
 * Output Formatting API
 *
 * Used to build a single output buffer from multiple printf-style
 * calls. Critical for BOFs that produce multi-line output: building
 * one blob and sending it via BeaconOutput ensures the Aggressor
 * on beacon_output callback receives a single contiguous string
 * rather than many small fragments.
 *
 * Usage:
 *   formatp fp;
 *   int len = 0;
 *   char *out = NULL;
 *   BeaconFormatAlloc(&fp, 64 * 1024);
 *   BeaconFormatPrintf(&fp, "Line 1: %s\n", str);
 *   BeaconFormatPrintf(&fp, "Line 2: %d\n", num);
 *   out = BeaconFormatToString(&fp, &len);   // populates len
 *   BeaconOutput(CALLBACK_OUTPUT, out, len);  // len now correct
 *   BeaconFormatFree(&fp);
 *
 * WARNING: Do NOT combine BeaconFormatToString and BeaconOutput in a
 * single call. C does not guarantee argument evaluation order, so the
 * compiler may read len (still 0) before BeaconFormatToString writes it:
 *   BeaconOutput(type, BeaconFormatToString(&fp, &len), len); // BROKEN
 * Always split into two statements as shown above.
 * --------------------------------------------------------------- */

typedef struct {
    char *original;   /* pointer to start of allocated buffer */
    char *buffer;     /* current write position                */
    int   length;     /* total allocated size                   */
    int   size;       /* bytes remaining                        */
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp *format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp *format);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp *format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp *format, char *text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp *format, char *fmt, ...);
DECLSPEC_IMPORT char   *BeaconFormatToString(formatp *format, int *size);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp *format, int value);

/* ---------------------------------------------------------------
 * Output API
 *
 * BeaconPrintf  - Send a single formatted string to the operator.
 *                 Each call generates a separate callback message.
 * BeaconOutput  - Send a raw buffer. Use with BeaconFormatToString
 *                 to send pre-built multi-line output as one blob.
 *
 * Callback types control how the output appears in the CS console:
 *   CALLBACK_OUTPUT       - Normal output (white text)
 *   CALLBACK_OUTPUT_OEM   - OEM codepage output (for cmd.exe output)
 *   CALLBACK_ERROR        - Error output (red text, prefixed with [-])
 *   CALLBACK_OUTPUT_UTF8  - UTF-8 encoded output
 * --------------------------------------------------------------- */

#define CALLBACK_OUTPUT      0x00
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

DECLSPEC_IMPORT void    BeaconPrintf(int type, char *fmt, ...);
DECLSPEC_IMPORT void    BeaconOutput(int type, char *data, int len);

/* ---------------------------------------------------------------
 * Token & Process API
 *
 * BeaconUseToken       - Apply a token handle for subsequent BOF calls
 * BeaconRevertToken    - Drop impersonation, revert to original token
 * BeaconIsAdmin        - Check if Beacon is running elevated
 * BeaconGetSpawnTo     - Get the current spawnto process (x86/x64)
 * BeaconInjectProcess  - Inject shellcode into a remote process
 * BeaconSpawnTemporaryProcess - Spawn sacrificial process for injection
 * BeaconInjectTemporaryProcess - Inject into a spawned temp process
 * BeaconCleanupProcess - Clean up a PROCESS_INFORMATION struct
 * --------------------------------------------------------------- */

DECLSPEC_IMPORT BOOL    BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void    BeaconRevertToken(void);
DECLSPEC_IMPORT BOOL    BeaconIsAdmin(void);
DECLSPEC_IMPORT void    BeaconGetSpawnTo(BOOL x86, char *buffer, int length);
DECLSPEC_IMPORT void    BeaconInjectProcess(HANDLE hProc, int pid, char *payload, int p_len, int p_offset, char *arg, int a_len);
DECLSPEC_IMPORT void    BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pInfo, char *payload, int p_len, int p_offset, char *arg, int a_len);
DECLSPEC_IMPORT BOOL    BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO *si, PROCESS_INFORMATION *pInfo);
DECLSPEC_IMPORT void    BeaconCleanupProcess(PROCESS_INFORMATION *pInfo);

/* ---------------------------------------------------------------
 * Utility API
 * --------------------------------------------------------------- */

DECLSPEC_IMPORT BOOL    toWideChar(char *src, wchar_t *dst, int max);

#endif /* _BEACON_H_ */