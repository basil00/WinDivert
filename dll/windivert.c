/*
 * windivert.c
 * (C) 2019, all rights reserved,
 *
 * This file is part of WinDivert.
 *
 * WinDivert is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * WinDivert is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef UNICODE
#define UNICODE
#endif

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>

#include <stdio.h>
#include <stdlib.h>

#ifndef WINDIVERTEXPORT
#define WINDIVERTEXPORT extern
#endif
#include "windivert.h"
#include "windivert_device.h"

#define WINDIVERT_DRIVER_NAME           L"WinDivert"
#define WINDIVERT_DRIVER32_SYS          L"\\" WINDIVERT_DRIVER_NAME L"32.sys"
#define WINDIVERT_DRIVER64_SYS          L"\\" WINDIVERT_DRIVER_NAME L"64.sys"
#define WINDIVERT_VERSION_MAJOR_MIN     2

#ifndef ERROR_DRIVER_FAILED_PRIOR_UNLOAD
#define ERROR_DRIVER_FAILED_PRIOR_UNLOAD    ((DWORD)654)
#endif

static BOOLEAN WinDivertIsDigit(char c);
static BOOLEAN WinDivertIsXDigit(char c);
static BOOLEAN WinDivertIsSpace(char c);
static BOOLEAN WinDivertIsAlNum(char c);
static char WinDivertToLower(char c);
static BOOLEAN WinDivertStrLen(const wchar_t *s, size_t maxlen,
    size_t *lenptr);
static BOOLEAN WinDivertStrCpy(wchar_t *dst, size_t dstlen,
    const wchar_t *src);
static int WinDivertStrCmp(const char *s, const char *t);
static BOOLEAN WinDivertAToI(const char *str, char **endptr, UINT32 *intptr,
    UINT size);
static BOOLEAN WinDivertAToX(const char *str, char **endptr, UINT32 *intptr,
    UINT size, BOOL prefix);
static UINT32 WinDivertDivTen128(UINT32 *a);

/*
 * Misc.
 */
#ifndef UINT8_MAX
#define UINT8_MAX       0xFF
#endif
#ifndef UINT16_MAX
#define UINT16_MAX      0xFFFF
#endif
#ifndef UINT32_MAX
#define UINT32_MAX      0xFFFFFFFF
#endif

#define IPPROTO_MH      135

#ifdef _MSC_VER

#pragma intrinsic(memcpy)
#pragma function(memcpy)
void *memcpy(void *dst, const void *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        ((UINT8 *)dst)[i] = ((const UINT8 *)src)[i];
    return dst;
}

#pragma intrinsic(memset)
#pragma function(memset)
void *memset(void *dst, int c, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        ((UINT8 *)dst)[i] = (UINT8)c;
    return dst;
}

#define WINDIVERT_INLINE    __forceinline

#else       /* _MSC_VER */

#define WINDIVERT_INLINE    __attribute__((__always_inline__)) inline

#endif      /* _MSC_VER */

/*
 * Filter interpreter config.
 */
static BOOL WinDivertGetData(const VOID *packet, UINT packet_len, INT min,
    INT max, INT idx, PVOID data, UINT size);
#define WINDIVERT_GET_DATA(packet, packet_len, min, max, index, data, size) \
    WinDivertGetData((packet), (packet_len), (min), (max), (index), (data), \
        (size))

/*
 * Prototypes.
 */
static BOOLEAN WinDivertUse32Bit(void);
static BOOLEAN WinDivertGetDriverFileName(LPWSTR sys_str);
static BOOLEAN WinDivertDriverInstall(VOID);

/*
 * Include the helper API implementation.
 */
#include "windivert_shared.c"
#include "windivert_helper.c"

/*
 * Thread local.
 */
static DWORD windivert_tls_idx;

/*
 * Current DLL hmodule.
 */
static HMODULE module = NULL;

/*
 * Dll Entry
 */
BOOL APIENTRY WinDivertDllEntry(HANDLE module0, DWORD reason, LPVOID reserved)
{
    HANDLE event;
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            module = module0;
            if ((windivert_tls_idx = TlsAlloc()) == TLS_OUT_OF_INDEXES)
            {
                return FALSE;
            }
            // Fallthrough
        case DLL_THREAD_ATTACH:
            event = CreateEvent(NULL, FALSE, FALSE, NULL);
            if (event == NULL)
            {
                return FALSE;
            }
            TlsSetValue(windivert_tls_idx, (LPVOID)event);
            break;

        case DLL_PROCESS_DETACH:
            event = (HANDLE)TlsGetValue(windivert_tls_idx);
            if (event != (HANDLE)NULL)
            {
                CloseHandle(event);
            }
            TlsFree(windivert_tls_idx);
            break;

        case DLL_THREAD_DETACH:
            event = (HANDLE)TlsGetValue(windivert_tls_idx);
            if (event != (HANDLE)NULL)
            {
                CloseHandle(event);
            }
            break;
    }
    return TRUE;
}

/*
 * Test if we should use the 32-bit or 64-bit driver.
 */
static BOOLEAN WinDivertUse32Bit(void)
{
    BOOL is_wow64;

    if (sizeof(void *) == sizeof(UINT64))
    {
        return FALSE;
    }
    if (!IsWow64Process(GetCurrentProcess(), &is_wow64))
    {
        // Just guess:
        return FALSE;
    }
    return (is_wow64? FALSE: TRUE);
}

/*
 * Locate the WinDivert driver files.
 */
static BOOLEAN WinDivertGetDriverFileName(LPWSTR sys_str)
{
    size_t dir_len, sys_len;
    BOOLEAN is_32bit;

    is_32bit = WinDivertUse32Bit();

    if (is_32bit)
    {
        if (!WinDivertStrLen(WINDIVERT_DRIVER32_SYS, MAX_PATH, &sys_len))
        {
            SetLastError(ERROR_BAD_PATHNAME);
            return FALSE;
        }
    }
    else
    {
        if (!WinDivertStrLen(WINDIVERT_DRIVER64_SYS, MAX_PATH, &sys_len))
        {
            SetLastError(ERROR_BAD_PATHNAME);
            return FALSE;
        }
    }

    dir_len = (size_t)GetModuleFileName(module, sys_str, MAX_PATH);
    if (dir_len == 0)
    {
        return FALSE;
    }
    for (; dir_len > 0 && sys_str[dir_len] != L'\\'; dir_len--)
        ;
    if (sys_str[dir_len] != L'\\' || dir_len + sys_len + 1 >= MAX_PATH)
    {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }
    if (!WinDivertStrCpy(sys_str + dir_len, MAX_PATH-dir_len-1,
            (is_32bit? WINDIVERT_DRIVER32_SYS: WINDIVERT_DRIVER64_SYS)))
    {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }

    return TRUE;
}

/*
 * Register event log.  It is not an error if this function fails.
 */
static void WinDivertRegisterEventSource(const wchar_t *windivert_sys)
{
    HKEY key;
    size_t len;
    DWORD types = 7;

    if (!WinDivertStrLen(windivert_sys, MAX_PATH, &len))
    {
        return;
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
            "System\\CurrentControlSet\\Services\\EventLog\\System\\WinDivert",
            0, NULL, REG_OPTION_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL)
                != ERROR_SUCCESS)
    {
        return;
    }
    RegSetValueExW(key, L"EventMessageFile", 0, REG_SZ, (LPBYTE)windivert_sys,
            (len + 1) * sizeof(wchar_t));
    RegSetValueExA(key, "TypesSupported", 0, REG_DWORD, (LPBYTE)&types,
            sizeof(types));
    RegCloseKey(key);
}

/*
 * Install the WinDivert driver.
 */
static BOOLEAN WinDivertDriverInstall(VOID)
{
    DWORD err;
    SC_HANDLE manager = NULL, service = NULL;
    wchar_t windivert_sys[MAX_PATH+1];
    HANDLE mutex = NULL;
    BOOL success = TRUE;

    // Create & lock a named mutex.  This is to stop two processes trying
    // to start the driver at the same time.
    mutex = CreateMutex(NULL, FALSE, L"WinDivertDriverInstallMutex");
    if (mutex == NULL)
    {
        return FALSE;
    }
    switch (WaitForSingleObject(mutex, INFINITE))
    {
        case WAIT_OBJECT_0: case WAIT_ABANDONED:
            break;
        default:
            return FALSE;
    }

    // Open the service manager:
    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (manager == NULL)
    {
        goto WinDivertDriverInstallExit;
    }

    // Check if the WinDivert service already exists; if so, start it.
    service = OpenService(manager, WINDIVERT_DEVICE_NAME, SERVICE_ALL_ACCESS);
    if (service != NULL)
    {
        goto WinDivertDriverInstallExit;
    }

    // Get driver file:
    if (!WinDivertGetDriverFileName(windivert_sys))
    {
        goto WinDivertDriverInstallExit;
    }

    // Create the service:
    service = CreateService(manager, WINDIVERT_DEVICE_NAME,
        WINDIVERT_DEVICE_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, windivert_sys, NULL, NULL,
        NULL, NULL, NULL);
    if (service == NULL)
    {
        if (GetLastError() == ERROR_SERVICE_EXISTS) 
        {
            service = OpenService(manager, WINDIVERT_DEVICE_NAME,
                SERVICE_ALL_ACCESS);
        }
        goto WinDivertDriverInstallExit;
    }

    // Register event logging:
    WinDivertRegisterEventSource(windivert_sys);

WinDivertDriverInstallExit:

    success = (service != NULL);
    if (service != NULL)
    {
        // Start the service:
        success = StartService(service, 0, NULL);
        if (!success)
        {
            success = (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING);
        }
        else
        {
            // Mark the service for deletion.  This will cause the driver to
            // unload if (1) there are no more open handles, and (2) the
            // service is STOPPED or on system reboot.
            (VOID)DeleteService(service);
        }
    }

    err = GetLastError();
    if (manager != NULL)
    {
        CloseServiceHandle(manager);
    }
    if (service != NULL)
    {
        CloseServiceHandle(service);
    }
    ReleaseMutex(mutex);
    CloseHandle(mutex);
    SetLastError(err);

    return success;
}

/*
 * Perform an (overlapped) DeviceIoControl.
 */
static BOOL WinDivertIoControlEx(HANDLE handle, DWORD code,
    PWINDIVERT_IOCTL ioctl, PVOID buf, UINT len, UINT *iolen,
    LPOVERLAPPED overlapped)
{
    BOOL result;
    DWORD iolen0;

    result = DeviceIoControl(handle, code, ioctl, sizeof(WINDIVERT_IOCTL), buf,
        (DWORD)len, &iolen0, overlapped);
    if (result && iolen != NULL)
    {
        *iolen = (UINT)iolen0;
    }
    return result;
}

/*
 * Perform a DeviceIoControl.
 */
static BOOL WinDivertIoControl(HANDLE handle, DWORD code,
    PWINDIVERT_IOCTL ioctl, PVOID buf, UINT len, UINT *iolen)
{
    OVERLAPPED overlapped;
    DWORD iolen0;
    HANDLE event;

    event = (HANDLE)TlsGetValue(windivert_tls_idx);
    if (event == (HANDLE)NULL)
    {
        event = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (event == NULL)
        {
            return FALSE;
        }
        TlsSetValue(windivert_tls_idx, (LPVOID)event);
    }

    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = event;
    if (!WinDivertIoControlEx(handle, code, ioctl, buf, len, iolen,
            &overlapped))
    {
        if (GetLastError() != ERROR_IO_PENDING ||
            !GetOverlappedResult(handle, &overlapped, &iolen0, TRUE))
        {
            return FALSE;
        }
        if (iolen != NULL)
        {
            *iolen = (UINT)iolen0;
        }
    }
    return TRUE;
}

/*
 * Open a WinDivert handle.
 */
HANDLE WinDivertOpen(const char *filter, WINDIVERT_LAYER layer, INT16 priority,
    UINT64 flags)
{
    WINDIVERT_FILTER *object;
    UINT obj_len;
    ERROR comp_err;
    DWORD err;
    HANDLE handle, pool;
    UINT64 filter_flags;
    WINDIVERT_IOCTL ioctl;
    WINDIVERT_VERSION version;

    // Static checks (should be compiled away if TRUE):
    if (sizeof(WINDIVERT_ADDRESS) != 80 ||
        sizeof(WINDIVERT_DATA_NETWORK) != 8 ||
        offsetof(WINDIVERT_DATA_FLOW, Protocol) != 56 ||
        offsetof(WINDIVERT_DATA_SOCKET, Protocol) != 56 ||
        offsetof(WINDIVERT_DATA_REFLECT, Priority) != 24 ||
        sizeof(WINDIVERT_FILTER) != 24 ||
        offsetof(WINDIVERT_ADDRESS, Reserved3) != 16)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    // Parameter checking:
    switch (layer)
    {
        case WINDIVERT_LAYER_NETWORK:
        case WINDIVERT_LAYER_NETWORK_FORWARD:
        case WINDIVERT_LAYER_FLOW:
        case WINDIVERT_LAYER_SOCKET:
        case WINDIVERT_LAYER_REFLECT:
            break;
        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            return INVALID_HANDLE_VALUE;
    }
    if (!WINDIVERT_FLAGS_VALID(flags))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    if (priority < WINDIVERT_PRIORITY_MIN ||
        priority > WINDIVERT_PRIORITY_MAX)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    // Compile & analyze the filter:
    pool = HeapCreate(HEAP_NO_SERIALIZE, WINDIVERT_MIN_POOL_SIZE,
        WINDIVERT_MAX_POOL_SIZE);
    if (pool == NULL)
    {
        return FALSE;
    }
    object = HeapAlloc(pool, 0,
        WINDIVERT_FILTER_MAXLEN * sizeof(WINDIVERT_FILTER));
    if (object == NULL)
    {
        err = GetLastError();
        HeapDestroy(pool);
        SetLastError(err);
        return FALSE;
    }
    comp_err = WinDivertCompileFilter(filter, pool, layer, object, &obj_len);
    if (IS_ERROR(comp_err))
    {
        HeapDestroy(pool);
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    filter_flags = WinDivertAnalyzeFilter(layer, object, obj_len);

    // Attempt to open the WinDivert device:
    handle = CreateFile(L"\\\\.\\" WINDIVERT_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, INVALID_HANDLE_VALUE);
    if (handle == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND)
        {
            HeapDestroy(pool);
            SetLastError(err);
            return INVALID_HANDLE_VALUE;
        }

        // Open failed because the device isn't installed; install it now.
        if ((flags & WINDIVERT_FLAG_NO_INSTALL) != 0)
        {
            HeapDestroy(pool);
            SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
            return INVALID_HANDLE_VALUE;
        }
        SetLastError(0);
        if (!WinDivertDriverInstall())
        {
            err = GetLastError();
            err = (err == 0? ERROR_OPEN_FAILED: err);
            HeapDestroy(pool);
            SetLastError(err);
            return INVALID_HANDLE_VALUE;
        }
        handle = CreateFile(L"\\\\.\\" WINDIVERT_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            INVALID_HANDLE_VALUE);
        if (handle == INVALID_HANDLE_VALUE)
        {
            err = GetLastError();
            HeapDestroy(pool);
            SetLastError(err);
            return INVALID_HANDLE_VALUE;
        }
    }

    // Initialize the handle:
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.initialize.layer    = layer;
    ioctl.initialize.priority = (INT32)priority + WINDIVERT_PRIORITY_MAX;
    ioctl.initialize.flags    = flags;
    memset(&version, 0, sizeof(version));
    version.magic             = WINDIVERT_MAGIC_DLL;
    version.major             = WINDIVERT_VERSION_MAJOR;
    version.minor             = WINDIVERT_VERSION_MINOR;
    version.bits              = 8 * sizeof(void *);
    if (!WinDivertIoControl(handle, IOCTL_WINDIVERT_INITIALIZE, &ioctl,
            &version, sizeof(version), NULL))
    {
        err = GetLastError();
        CloseHandle(handle);
        HeapDestroy(pool);
        SetLastError(err);
        return INVALID_HANDLE_VALUE;
    }
    if (version.magic != WINDIVERT_MAGIC_SYS ||
        version.major < WINDIVERT_VERSION_MAJOR_MIN)
    {
        CloseHandle(handle);
        HeapDestroy(pool);
        SetLastError(ERROR_DRIVER_FAILED_PRIOR_UNLOAD);
        return INVALID_HANDLE_VALUE;
    }

    // Start the filter:
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.startup.flags = filter_flags;
    if (!WinDivertIoControl(handle, IOCTL_WINDIVERT_STARTUP, &ioctl,
            object, obj_len * sizeof(WINDIVERT_FILTER), NULL))
    {
        err = GetLastError();
        CloseHandle(handle);
        HeapDestroy(pool);
        SetLastError(err);
        return INVALID_HANDLE_VALUE;
    }
    HeapDestroy(pool);

    // Success!
    return handle;
}

/*
 * Receive a WinDivert packet.
 */
BOOL WinDivertRecv(HANDLE handle, PVOID pPacket, UINT packetLen, UINT *readLen,
    PWINDIVERT_ADDRESS addr)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.recv.addr = (UINT64)(ULONG_PTR)addr;
    ioctl.recv.addr_len_ptr = (UINT64)(ULONG_PTR)NULL;
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_RECV, &ioctl,
        pPacket, packetLen, readLen);
}

/*
 * Receive a WinDivert packet.
 */
BOOL WinDivertRecvEx(HANDLE handle, PVOID pPacket, UINT packetLen,
    UINT *readLen, UINT64 flags, PWINDIVERT_ADDRESS addr, UINT *pAddrLen,
    LPOVERLAPPED overlapped)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.recv.addr = (UINT64)(ULONG_PTR)addr;
    ioctl.recv.addr_len_ptr = (UINT64)(ULONG_PTR)pAddrLen;
    if (flags != 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (overlapped == NULL)
    {
        return WinDivertIoControl(handle, IOCTL_WINDIVERT_RECV, &ioctl,
            pPacket, packetLen, readLen);
    }
    else
    {
        return WinDivertIoControlEx(handle, IOCTL_WINDIVERT_RECV, &ioctl,
            pPacket, packetLen, readLen, overlapped);
    }
}

/*
 * Send a WinDivert packet.
 */
BOOL WinDivertSend(HANDLE handle, const VOID *pPacket, UINT packetLen,
    UINT *writeLen, const WINDIVERT_ADDRESS *addr)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.send.addr = (UINT64)(ULONG_PTR)addr;
    ioctl.send.addr_len = sizeof(WINDIVERT_ADDRESS);
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_SEND, &ioctl,
        (PVOID)pPacket, packetLen, writeLen);
}

/*
 * Send a WinDivert packet.
 */
BOOL WinDivertSendEx(HANDLE handle, const VOID *pPacket, UINT packetLen,
    UINT *writeLen, UINT64 flags, const WINDIVERT_ADDRESS *addr, UINT addrLen,
    LPOVERLAPPED overlapped)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.send.addr = (UINT64)(ULONG_PTR)addr;
    ioctl.send.addr_len = addrLen;
    if (flags != 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (overlapped == NULL)
    {
        return WinDivertIoControl(handle, IOCTL_WINDIVERT_SEND, &ioctl,
            (PVOID)pPacket, packetLen, writeLen);
    }
    else
    {
        return WinDivertIoControlEx(handle, IOCTL_WINDIVERT_SEND, &ioctl,
            (PVOID)pPacket, packetLen, writeLen, overlapped);
    }
}

/*
 * Shutdown a WinDivert handle.
 */
BOOL WinDivertShutdown(HANDLE handle, WINDIVERT_SHUTDOWN how)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.shutdown.how = (UINT32)how;
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_SHUTDOWN, &ioctl, NULL,
        0, NULL);
}

/*
 * Close a WinDivert handle.
 */
BOOL WinDivertClose(HANDLE handle)
{
    return CloseHandle(handle);
}

/*
 * Set a WinDivert parameter.
 */
BOOL WinDivertSetParam(HANDLE handle, WINDIVERT_PARAM param, UINT64 value)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.set_param.param = (UINT32)param;
    ioctl.set_param.val   = value;
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_SET_PARAM, &ioctl, NULL,
        0, NULL);
}

/*
 * Get a WinDivert parameter.
 */
BOOL WinDivertGetParam(HANDLE handle, WINDIVERT_PARAM param, UINT64 *pValue)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.get_param.param = (UINT32)param;
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_GET_PARAM, &ioctl,
        pValue, sizeof(UINT64), NULL);
}

/*****************************************************************************/
/* REPLACEMENTS                                                              */
/*****************************************************************************/

static BOOLEAN WinDivertIsDigit(char c)
{
    return (c >= '0' && c <= '9');
}

static BOOLEAN WinDivertIsXDigit(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static BOOLEAN WinDivertIsSpace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
            c == '\v');
}

static BOOLEAN WinDivertIsAlNum(char c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

static char WinDivertToLower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return 'a' + (c - 'A');
    return c;
}

static BOOLEAN WinDivertStrLen(const wchar_t *s, size_t maxlen,
    size_t *lenptr)
{
    size_t i;
    for (i = 0; s[i]; i++)
    {
        if (i > maxlen)
        {
            return FALSE;
        }
    }
    *lenptr = i;
    return TRUE;
}

static BOOLEAN WinDivertStrCpy(wchar_t *dst, size_t dstlen, const wchar_t *src)
{
    size_t i;
    for (i = 0; src[i]; i++)
    {
        if (i > dstlen)
        {
            return FALSE;
        }
        dst[i] = src[i];
    }
    if (i > dstlen)
    {
        return FALSE;
    }
    dst[i] = src[i];
    return TRUE;
}

static int WinDivertStrCmp(const char *s, const char *t)
{
    int cmp;
    size_t i;
    for (i = 0; ; i++)
    {
        cmp = s[i] - t[i];
        if (cmp != 0)
        {
            return cmp;
        }
        if (s[i] == '\0')
        {
            return 0;
        }
    }
}

static BOOLEAN WinDivertMul128(UINT32 *n, UINT32 m)
{
    UINT64 n64 = (UINT64)n[0] * (UINT64)m;
    n[0] = (UINT32)n64;
    n64 = (UINT64)n[1] * (UINT64)m + (n64 >> 32);
    n[1] = (UINT32)n64;
    n64 = (UINT64)n[2] * (UINT64)m + (n64 >> 32);
    n[2] = (UINT32)n64;
    n64 = (UINT64)n[3] * (UINT64)m + (n64 >> 32);
    n[3] = (UINT32)n64;
    return ((n64 >> 32) == 0);
}

static BOOLEAN WinDivertAdd128(UINT32 *n, UINT32 a)
{
    UINT64 n64 = (UINT64)n[0] + (UINT64)a;
    n[0] = (UINT32)n64;
    n64 = (UINT64)n[1] + (n64 >> 32);
    n[1] = (UINT32)n64;
    n64 = (UINT64)n[2] + (n64 >> 32);
    n[2] = (UINT32)n64;
    n64 = (UINT64)n[3] + (n64 >> 32);
    n[3] = (UINT32)n64;
    return ((n64 >> 32) == 0);
}

static BOOLEAN WinDivertAToI(const char *str, char **endptr, UINT32 *intptr,
    UINT size)
{
    size_t i = 0;
    UINT32 n[4] = {0};
    BOOLEAN result = TRUE;
    for (; str[i] && WinDivertIsDigit(str[i]); i++)
    {
        if (!WinDivertMul128(n, 10) || !WinDivertAdd128(n, str[i] - '0'))
        {
            return FALSE;
        }
    }
    if (i == 0)
    {
        return FALSE;
    }
    if (endptr != NULL)
    {
        *endptr = (char *)str + i;
    }
    for (i = 0; i < size; i++)
    {
        intptr[i] = n[i];
    }
    for (; result && i < size && i < 4; i++)
    {
        result = result && (n[i] == 0);
    }
    return result;
}

static BOOLEAN WinDivertAToX(const char *str, char **endptr, UINT32 *intptr,
    UINT size, BOOL prefix)
{
    size_t i = 0;
    UINT32 n[4] = {0}, dig;
    BOOLEAN result = TRUE;
    if (prefix)
    {
        if (str[i] == '0' && str[i+1] == 'x')
        {
            i += 2;
        }
        else
        {
            return FALSE;
        }
    }
    for (; str[i] && WinDivertIsXDigit(str[i]); i++)
    {
        if (WinDivertIsDigit(str[i]))
        {
            dig = (UINT32)(str[i] - '0');
        }
        else
        {
            dig = (UINT32)(WinDivertToLower(str[i]) - 'a') + 0x0A;
        }
        if (!WinDivertMul128(n, 16) || !WinDivertAdd128(n, dig))
        {
            return FALSE;
        }
    }
    if (i == 0)
    {
        return FALSE;
    }
    if (endptr != NULL)
    {
        *endptr = (char *)str + i;
    }
    for (i = 0; i < size; i++)
    {
        intptr[i] = n[i];
    }
    for (; result && i < size && i < 4; i++)
    {
        result = result && (n[i] == 0);
    }
    return result;
}

/*
 * Divide by 10 and return the remainder.
 */
#define WINDIVERT_BIG_MUL_ROUND(a, c, r, i)                                 \
    do {                                                                    \
        UINT64 t = WINDIVERT_MUL64((UINT64)(a), (UINT64)(c));               \
        UINT k;                                                             \
        for (k = (i); k < 9 && t != 0; k++)                                 \
        {                                                                   \
            UINT64 s = (UINT64)(r)[k] + (t & 0xFFFFFFFF);                   \
            (r)[k] = (UINT32)s;                                             \
            t = (t >> 32) + (s >> 32);                                      \
        }                                                                   \
    } while (FALSE)
static UINT32 WinDivertDivTen128(UINT32 *a)
{
    const UINT32 c[5] =
    {
        0x9999999A, 0x99999999, 0x99999999, 0x99999999, 0x19999999
    };
    UINT32 r[9] = {0}, m[6] = {0};
    UINT i, j;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 5; j++)
        {
            WINDIVERT_BIG_MUL_ROUND(a[i], c[j], r, i+j);
        }
    }

    a[0] = r[5];
    a[1] = r[6];
    a[2] = r[7];
    a[3] = r[8];
    
    for (i = 0; i < 5; i++)
    {
        WINDIVERT_BIG_MUL_ROUND(r[i], 10, m, i);
    }
    
    return m[5];
}

