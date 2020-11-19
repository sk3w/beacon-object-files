#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$RtlGetVersion(PRTL_OSVERSIONINFOW);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);

void go(char * args, int alen) {
    PRTL_OSVERSIONINFOW pVer;
    if (NTDLL$RtlGetVersion(pVer) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Major: %d\nMinor: %d\nBuild: %d",
                     pVer->dwMajorVersion,
                     pVer->dwMinorVersion,
                     pVer->dwBuildNumber);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed: %d", KERNEL32$GetLastError());
    }
}
