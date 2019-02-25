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

#define WINDIVERTEXPORT
#include "windivert.h"
#include "windivert_device.h"

#define WINDIVERT_DRIVER_NAME           L"WinDivert"
#define WINDIVERT_DRIVER32_SYS          L"\\" WINDIVERT_DRIVER_NAME L"32.sys"
#define WINDIVERT_DRIVER64_SYS          L"\\" WINDIVERT_DRIVER_NAME L"64.sys"
#define WINDIVERT_VERSION_MAJOR_MIN     2

#ifndef ERROR_DRIVER_FAILED_PRIOR_UNLOAD
#define ERROR_DRIVER_FAILED_PRIOR_UNLOAD    ((DWORD)654)
#endif

static BOOLEAN WinDivertIsXDigit(char c);
static BOOLEAN WinDivertIsSpace(char c);
static BOOLEAN WinDivertIsAlNum(char c);
static char WinDivertToLower(char c);
static BOOLEAN WinDivertStrLen(const wchar_t *s, size_t maxlen,
    size_t *lenptr);
static BOOLEAN WinDivertStrCpy(wchar_t *dst, size_t dstlen,
    const wchar_t *src);
static int WinDivertStrCmp(const char *s, const char *t);
static BOOLEAN WinDivertAToI(const char *str, char **endptr, UINT32 *intptr);
static BOOLEAN WinDivertAToX(const char *str, char **endptr, UINT32 *intptr);

/*
 * Misc.
 */
#ifndef UINT8_MAX
#define UINT8_MAX       0xFF
#endif
#ifndef UINT32_MAX
#define UINT32_MAX      0xFFFFFFFF
#endif

/*
 * Prototypes.
 */
static BOOLEAN WinDivertUse32Bit(void);
static BOOLEAN WinDivertGetDriverFileName(LPWSTR sys_str);
static SC_HANDLE WinDivertDriverInstall(VOID);

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
extern BOOL APIENTRY WinDivertDllEntry(HANDLE module0, DWORD reason,
    LPVOID reserved)
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
 * Install the WinDivert driver.
 */
static SC_HANDLE WinDivertDriverInstall(VOID)
{
    DWORD err, retries = 2;
    SC_HANDLE manager = NULL, service = NULL;
    wchar_t windivert_sys[MAX_PATH+1];
    SERVICE_STATUS status;

    // Open the service manager:
    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (manager == NULL)
    {
        goto WinDivertDriverInstallExit;
    }

    // Check if the WinDivert service already exists; if so, start it.
WinDivertDriverInstallReTry:
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
            if (retries != 0)
            {
                retries--;
                goto WinDivertDriverInstallReTry;
            }
        }
        goto WinDivertDriverInstallExit;
    }

WinDivertDriverInstallExit:

    if (service != NULL)
    {
        // Start the service:
        if (!StartService(service, 0, NULL))
        {
            err = GetLastError();
            if (err == ERROR_SERVICE_ALREADY_RUNNING)
            {
                SetLastError(0);
            }
            else
            {
                // Failed to start service; clean-up:
                ControlService(service, SERVICE_CONTROL_STOP, &status);
                DeleteService(service);
                CloseServiceHandle(service);
                service = NULL;
                SetLastError(err);
            }
        }
    }

    err = GetLastError();
    if (manager != NULL)
    {
        CloseServiceHandle(manager);
    }
    SetLastError(err);
    
    return service;
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
extern HANDLE WinDivertOpen(const char *filter, WINDIVERT_LAYER layer,
    INT16 priority, UINT64 flags)
{
    WINDIVERT_FILTER object[WINDIVERT_FILTER_MAXLEN];
    UINT obj_len;
    ERROR comp_err;
    DWORD err;
    BOOL sniff;
    HANDLE handle;
    SC_HANDLE service;
    UINT64 filter_flags;
    WINDIVERT_IOCTL ioctl;
    WINDIVERT_VERSION version;
 
    // Parameter checking.
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
    comp_err = WinDivertCompileFilter(filter, layer, object, &obj_len);
    if (IS_ERROR(comp_err))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    sniff = ((flags & WINDIVERT_FLAG_SNIFF) != 0);
    filter_flags = WinDivertAnalyzeFilter(layer, sniff, object, obj_len);

    // Attempt to open the WinDivert device:
    handle = CreateFile(L"\\\\.\\" WINDIVERT_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, INVALID_HANDLE_VALUE);
    if (handle == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND)
        {
            return INVALID_HANDLE_VALUE;
        }

        // Open failed because the device isn't installed; install it now.
        if ((flags & WINDIVERT_FLAG_NO_INSTALL) != 0)
        {
            SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
            return INVALID_HANDLE_VALUE;
        }
        SetLastError(0);
        service = WinDivertDriverInstall();
        if (service == NULL)
        {
            if (GetLastError() == 0)
            {
                SetLastError(ERROR_OPEN_FAILED);
            }
            return INVALID_HANDLE_VALUE;
        }
        handle = CreateFile(L"\\\\.\\" WINDIVERT_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            INVALID_HANDLE_VALUE);

        // Schedule the service to be deleted (once all handles are closed).
        DeleteService(service);
        CloseServiceHandle(service);

        if (handle == INVALID_HANDLE_VALUE)
        {
            return INVALID_HANDLE_VALUE;
        }
    }

    // Initialize the handle:
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.initialize.layer    = layer;
    ioctl.initialize.priority = (INT32)priority + WINDIVERT_PRIORITY_MAX;
    ioctl.initialize.flags    = flags;
    version.magic             = WINDIVERT_MAGIC_DLL;
    version.major             = WINDIVERT_VERSION_MAJOR;
    version.minor             = WINDIVERT_VERSION_MINOR;
    memset(version.reserved, 0, sizeof(version.reserved));
    if (!WinDivertIoControl(handle, IOCTL_WINDIVERT_INITIALIZE, &ioctl,
            &version, sizeof(version), NULL))
    {
        CloseHandle(handle);
        return INVALID_HANDLE_VALUE;
    }
    if (version.magic != WINDIVERT_MAGIC_SYS ||
        version.major < WINDIVERT_VERSION_MAJOR_MIN)
    {
        CloseHandle(handle);
        SetLastError(ERROR_DRIVER_FAILED_PRIOR_UNLOAD);
        return INVALID_HANDLE_VALUE;
    }

    // Start the filter:
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.startup.flags = filter_flags;
    if (!WinDivertIoControl(handle, IOCTL_WINDIVERT_STARTUP, &ioctl,
            object, obj_len * sizeof(WINDIVERT_FILTER), NULL))
    {
        CloseHandle(handle);
        return INVALID_HANDLE_VALUE;
    }

    // Success!
    return handle;
}

/*
 * Receive a WinDivert packet.
 */
extern BOOL WinDivertRecv(HANDLE handle, PVOID pPacket, UINT packetLen,
    PWINDIVERT_ADDRESS addr, UINT *readlen)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.recv.addr = addr;
    ioctl.recv.addr_len_ptr = NULL;
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_RECV, &ioctl,
        pPacket, packetLen, readlen);
}

/*
 * Receive a WinDivert packet.
 */
extern BOOL WinDivertRecvEx(HANDLE handle, PVOID pPacket, UINT packetLen,
    UINT *readLen, UINT64 flags, PWINDIVERT_ADDRESS addr, UINT *pAddrLen,
    LPOVERLAPPED overlapped)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.recv.addr = addr;
    ioctl.recv.addr_len_ptr = pAddrLen;
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
extern BOOL WinDivertSend(HANDLE handle, const VOID *pPacket, UINT packetLen,
    const WINDIVERT_ADDRESS *addr, UINT *writelen)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.send.addr = addr;
    ioctl.send.addr_len = sizeof(WINDIVERT_ADDRESS);
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_SEND, &ioctl,
        (PVOID)pPacket, packetLen, writelen);
}

/*
 * Send a WinDivert packet.
 */
extern BOOL WinDivertSendEx(HANDLE handle, const VOID *pPacket, UINT packetLen,
    UINT *writeLen, UINT64 flags, const WINDIVERT_ADDRESS *addr, UINT addrLen,
    LPOVERLAPPED overlapped)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.send.addr = addr;
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
extern BOOL WinDivertShutdown(HANDLE handle, WINDIVERT_SHUTDOWN how)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.shutdown.how = how;
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_SHUTDOWN, &ioctl, NULL,
        0, NULL);
}

/*
 * Close a WinDivert handle.
 */
extern BOOL WinDivertClose(HANDLE handle)
{
    return CloseHandle(handle);
}

/*
 * Set a WinDivert parameter.
 */
extern BOOL WinDivertSetParam(HANDLE handle, WINDIVERT_PARAM param,
    UINT64 value)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.set_param.param = param;
    ioctl.set_param.val   = value;
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_SET_PARAM, &ioctl, NULL,
        0, NULL);
}

/*
 * Get a WinDivert parameter.
 */
extern BOOL WinDivertGetParam(HANDLE handle, WINDIVERT_PARAM param,
    UINT64 *pValue)
{
    WINDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.get_param.param = param;
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_GET_PARAM, &ioctl,
        pValue, sizeof(UINT64), NULL);
}

/*****************************************************************************/
/* REPLACEMENTS                                                              */
/*****************************************************************************/

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

static BOOLEAN WinDivertAToI(const char *str, char **endptr, UINT32 *intptr)
{
    size_t i = 0;
    UINT32 num = 0, num0;
    if (str[i] == '\0')
    {
        return FALSE;
    }
    for (; str[i] && isdigit(str[i]); i++)
    {
        num0 = num;
        num *= 10;
        num += (UINT32)(str[i] - '0');
        if (num0 > num)
        {
            return FALSE;
        }
    }
    if (endptr != NULL)
    {
        *endptr = (char *)str + i;
    }
    *intptr = num;
    return TRUE;
}

static BOOLEAN WinDivertAToX(const char *str, char **endptr, UINT32 *intptr)
{
    size_t i = 0;
    UINT32 num = 0, num0;
    if (str[i] == '\0')
    {
        return FALSE;
    }
    if (str[i] == '0' && str[i+1] == 'x')
    {
        i += 2;
    }
    for (; str[i] && WinDivertIsXDigit(str[i]); i++)
    {
        num0 = num;
        num *= 16;
        if (isdigit(str[i]))
        {
            num += (UINT32)(str[i] - '0');
        }
        else
        {
            num += (UINT32)(WinDivertToLower(str[i]) - 'a') + 0x0A;
        }
        if (num0 > num)
        {
            return FALSE;
        }
    }
    if (endptr != NULL)
    {
        *endptr = (char *)str + i;
    }
    *intptr = num;
    return TRUE;
}

