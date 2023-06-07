#ifndef NT_API_DEF_ENABLE
#define NT_API_DEF_ENABLE 1 

#include "Struct.h"

NTSTATUS NTAPI NtOpenSection
(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
);


NTSTATUS NTAPI NtMapViewOfSection
(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
);

NTSTATUS NTAPI NtClose
(
	HANDLE Handle
);

NTSTATUS NTAPI NtUnmapViewOfSection
(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
);


NTSTATUS NTAPI NtReadVirtualMemory
(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN SIZE_T NumberOfBytesToRead,
	OUT PSIZE_T NumberOfBytesRead
);

NTSTATUS
NTAPI
NtQuerySystemInformation
(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID               SystemInformation,
	IN ULONG                SystemInformationLength,
	OUT PULONG              ReturnLength OPTIONAL
);

#endif 