//
// Created by kali on 19/09/23.
//

#ifndef PSINLINE_COMMON_H
#define PSINLINE_COMMON_H
#include <windows.h>
#include "Native.h"
//MSVCRT
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBASEAPI void* WINAPI MSVCRT$free(VOID*);
WINBASEAPI void* __cdecl MSVCRT$strcat(char*_Dst,char*_Src);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict _Dst, const void* __restrict _Src, size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char* _Str1, const char* _Str2);
WINBASEAPI SIZE_T WINAPI MSVCRT$strlen(const char* str);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char* s, size_t n, const char* fmt, ...);
WINBASEAPI errno_t __cdecl MSVCRT$mbstowcs_s(size_t* pReturnValue, wchar_t* wcstr, size_t sizeInWords, const char* mbstr, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI char* WINAPI MSVCRT$_strlwr(char * str);
WINBASEAPI char* WINAPI MSVCRT$strrchr(char * str);
WINBASEAPI int __cdecl MSVCRT$_open_osfhandle (intptr_t osfhandle, int flags);
WINBASEAPI int __cdecl MSVCRT$_dup2( int fd1, int fd2 );
WINBASEAPI int __cdecl MSVCRT$_close(int fd);
WINBASEAPI int __cdecl MSVCRT$rand(void);
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA (HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
WINADVAPI LONG WINAPI ADVAPI32$RegSaveKeyA (HKEY, LPCSTR, LPSECURITY_ATTRIBUTES);
WINBASEAPI BOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE, DWORD, PHANDLE);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (void);
WINBASEAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA (LPCSTR, LPCSTR, PLUID);
WINBASEAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (void);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle (HANDLE);
WINBASEAPI LPSTR WINAPI SHLWAPI$PathCombineA(LPSTR,LPCSTR,LPCSTR);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread (VOID);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenThreadToken (HANDLE ThreadHandle, DWORD DesiredAccess, WINBOOL OpenAsSelf, PHANDLE TokenHandle);
WINBASEAPI PVOID WINAPI KERNEL32$AddVectoredExceptionHandler (ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
WINBASEAPI ULONG WINAPI KERNEL32$RemoveVectoredExceptionHandler (PVOID Handle);
//KERNEL32
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR lpString);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateMailslotA(LPCSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
WINBASEAPI BOOL WINAPI KERNEL32$GetMailslotInfo(HANDLE  hMailslot, LPDWORD lpMaxMessageSize, LPDWORD lpNextSize, LPDWORD lpMessageCount, LPDWORD lpReadTimeout);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalFree(HGLOBAL hMem);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect (PVOID, DWORD, DWORD, PDWORD);
//SHELL32
WINBASEAPI LPWSTR* WINAPI SHELL32$CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs);
//MSCOREE
WINBASEAPI HRESULT WINAPI MSCOREE$CLRCreateInstance(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);
//OLEAUT32
WINBASEAPI SAFEARRAY* WINAPI OLEAUT32$SafeArrayCreateVector(VARTYPE vt, LONG lLbound, ULONG   cElements);
WINBASEAPI SAFEARRAY* WINAPI OLEAUT32$SafeArrayCreate(VARTYPE vt, UINT cDims, SAFEARRAYBOUND* rgsabound);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayAccessData(SAFEARRAY* psa, void HUGEP** ppvData);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayUnaccessData(SAFEARRAY* psa);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayPutElement(SAFEARRAY* psa, LONG* rgIndices, void* pv);
WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayDestroy(SAFEARRAY* psa);
WINBASEAPI HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG* pvarg);
WINBASEAPI BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR* psz);

WINBASEAPI HANDLE WINAPI KERNEL32$CreateNamedPipeA (LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
WINBASEAPI WINBOOL WINAPI KERNEL32$SetStdHandle (DWORD nStdHandle, HANDLE hHandle);
WINBASEAPI HANDLE WINAPI KERNEL32$GetStdHandle (DWORD nStdHandle);
WINBASEAPI WINBOOL WINAPI KERNEL32$AllocConsole(VOID);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetThreadContext (HANDLE hThread, LPCONTEXT lpContext);
WINBASEAPI WINBOOL WINAPI KERNEL32$SetThreadContext (HANDLE hThread, CONST CONTEXT *lpContext);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenThread (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwThreadId);
WINBASEAPI HWND WINAPI KERNEL32$GetConsoleWindow(VOID);
WINUSERAPI WINBOOL WINAPI USER32$ShowWindow(HWND hWnd,int nCmdShow);
WINBASEAPI WINBOOL WINAPI KERNEL32$SetStdHandle (DWORD nStdHandle, HANDLE hHandle);
WINBASEAPI WINBOOL WINAPI KERNEL32$FreeConsole(VOID);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateMutexA (LPSECURITY_ATTRIBUTES lpMutexAttributes, WINBOOL bInitialOwner, LPCSTR lpName);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI WINBOOL WINAPI KERNEL32$ReleaseMutex (HANDLE hMutex);

WINIMPM WINBOOL WINAPI CRYPT32$CryptBinaryToStringA (CONST BYTE *pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD *pcchString);


typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);//NtWriteVirtualMemory
typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE, PVOID, PULONG, ULONG, PULONG);//NtProtectVirtualMemory
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
//#define STATUS_SUCCESS 0x0
#endif //PSINLINE_COMMON_H
