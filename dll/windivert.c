/*
 * windivert.c
 * (C) 2016, all rights reserved,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef UNICODE
#define UNICODE
#endif

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#define WINDIVERTEXPORT
#include "windivert.h"
#include "windivert_device.h"

#define WINDIVERT_DRIVER_NAME           L"WinDivert"
#define WINDIVERT_DRIVER32_SYS          L"\\" WINDIVERT_DRIVER_NAME L"32.sys"
#define WINDIVERT_DRIVER64_SYS          L"\\" WINDIVERT_DRIVER_NAME L"64.sys"

/*
 * Definitions to remove (some) external dependencies:
 */
#define BYTESWAP16(x)                   \
    ((((x) >> 8) & 0x00FF) | (((x) << 8) & 0xFF00))
#define BYTESWAP32(x)                   \
    ((((x) >> 24) & 0x000000FF) | (((x) >> 8) & 0x0000FF00) | \
     (((x) << 8) & 0x00FF0000) | (((x) << 24) & 0xFF000000))
#define ntohs(x)                        BYTESWAP16(x)
#define htons(x)                        BYTESWAP16(x)
#define ntohl(x)                        BYTESWAP32(x)
#define htonl(x)                        BYTESWAP32(x)

static BOOLEAN WinDivertStrLen(const wchar_t *s, size_t maxlen,
    size_t *lenptr);
static BOOLEAN WinDivertStrCpy(wchar_t *dst, size_t dstlen,
    const wchar_t *src);
static BOOLEAN WinDivertAToI(const char *str, char **endptr, UINT32 *intptr);
static BOOLEAN WinDivertAToX(const char *str, char **endptr, UINT32 *intptr);

/*
 * IPv4/IPv6 pseudo headers.
 */
typedef struct
{
    UINT32 SrcAddr;
    UINT32 DstAddr;
    UINT8  Zero;
    UINT8  Protocol;
    UINT16 Length;
} WINDIVERT_PSEUDOHDR, *PWINDIVERT_PSEUDOHDR;

typedef struct
{
    UINT32 SrcAddr[4];
    UINT32 DstAddr[4];
    UINT32 Length;
    UINT32 Zero:24;
    UINT32 NextHdr:8;
} WINDIVERT_PSEUDOV6HDR, *PWINDIVERT_PSEUDOV6HDR;

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
static BOOL WinDivertIoControl(HANDLE handle, DWORD code, UINT8 arg8,
    UINT64 arg, PVOID buf, UINT len, UINT *iolen);
static BOOL WinDivertIoControlEx(HANDLE handle, DWORD code, UINT8 arg8,
    UINT64 arg, PVOID buf, UINT len, UINT *iolen, LPOVERLAPPED overlapped);
static UINT8 WinDivertSkipExtHeaders(UINT8 proto, UINT8 **header, UINT *len);

#ifdef WINDIVERT_DEBUG
static void WinDivertFilterDump(windivert_ioctl_filter_t filter, UINT16 len);
#endif

/*
 * Include the helper API implementation.
 */
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
 * Perform a DeviceIoControl.
 */
static BOOL WinDivertIoControl(HANDLE handle, DWORD code, UINT8 arg8,
    UINT64 arg, PVOID buf, UINT len, UINT *iolen)
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
    if (!WinDivertIoControlEx(handle, code, arg8, arg, buf, len, iolen,
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
 * Perform an (overlapped) DeviceIoControl.
 */
static BOOL WinDivertIoControlEx(HANDLE handle, DWORD code, UINT8 arg8,
    UINT64 arg, PVOID buf, UINT len, UINT *iolen, LPOVERLAPPED overlapped)
{
    struct windivert_ioctl_s ioctl;
    BOOL result;
    DWORD iolen0;

    ioctl.version = WINDIVERT_IOCTL_VERSION;
    ioctl.magic   = WINDIVERT_IOCTL_MAGIC;
    ioctl.arg8    = arg8;
    ioctl.arg     = arg;
    result = DeviceIoControl(handle, code, &ioctl, sizeof(ioctl), buf,
        (DWORD)len, &iolen0, overlapped);
    if (result && iolen != NULL)
    {
        *iolen = (UINT)iolen0;
    }
    return result;
}

/*
 * Open a WinDivert handle.
 */
extern HANDLE WinDivertOpen(const char *filter, WINDIVERT_LAYER layer,
    INT16 priority, UINT64 flags)
{
    struct windivert_ioctl_filter_s object[WINDIVERT_FILTER_MAXLEN];
    UINT obj_len;
    ERROR comp_err;
    DWORD err;
    HANDLE handle;
    SC_HANDLE service;
    UINT32 priority32;

    // Parameter checking.
    if (!WINDIVERT_FLAGS_VALID(flags) || layer > WINDIVERT_LAYER_MAX)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    priority32 = WINDIVERT_PRIORITY(priority);
    if (priority32 < WINDIVERT_PRIORITY_MIN ||
        priority32 > WINDIVERT_PRIORITY_MAX)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    // Compile the filter:
    comp_err = WinDivertCompileFilter(filter, layer, object, &obj_len);
    if (IS_ERROR(comp_err))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

#ifdef WINDIVERT_DEBUG
    WinDivertFilterDump(object, obj_len);
#endif

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

    // Set the layer:
    if (layer != WINDIVERT_LAYER_DEFAULT)
    {
        if (!WinDivertIoControl(handle, IOCTL_WINDIVERT_SET_LAYER, 0,
                (UINT64)layer, NULL, 0, NULL))
        {
            CloseHandle(handle);
            return INVALID_HANDLE_VALUE;
        }
    }

    // Set the flags:
    if (flags != 0)
    {
        if (!WinDivertIoControl(handle, IOCTL_WINDIVERT_SET_FLAGS, 0,
                (UINT64)flags, NULL, 0, NULL))
        {
            CloseHandle(handle);
            return INVALID_HANDLE_VALUE;
        }
    }

    // Set the priority:
    if (priority32 != WINDIVERT_PRIORITY_DEFAULT)
    {
        if (!WinDivertIoControl(handle, IOCTL_WINDIVERT_SET_PRIORITY, 0,
                (UINT64)priority32, NULL, 0, NULL))
        {
            CloseHandle(handle);
            return INVALID_HANDLE_VALUE;
        }
    }

    // Start the filter:
    if (!WinDivertIoControl(handle, IOCTL_WINDIVERT_START_FILTER, 0, 0,
            object, obj_len*sizeof(struct windivert_ioctl_filter_s), NULL))
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
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_RECV, 0, (UINT64)addr,
        pPacket, packetLen, readlen);
}

/*
 * Receive a WinDivert packet.
 */
extern BOOL WinDivertRecvEx(HANDLE handle, PVOID pPacket, UINT packetLen,
    UINT64 flags, PWINDIVERT_ADDRESS addr, UINT *readlen,
    LPOVERLAPPED overlapped)
{
    if (flags != 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (overlapped == NULL)
    {
        return WinDivertIoControl(handle, IOCTL_WINDIVERT_RECV, 0,
            (UINT64)addr, pPacket, packetLen, readlen);
    }
    else
    {
        return WinDivertIoControlEx(handle, IOCTL_WINDIVERT_RECV, 0,
            (UINT64)addr, pPacket, packetLen, readlen, overlapped);
    }
}

/*
 * Send a WinDivert packet.
 */
extern BOOL WinDivertSend(HANDLE handle, PVOID pPacket, UINT packetLen,
    PWINDIVERT_ADDRESS addr, UINT *writelen)
{
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_SEND, 0, (UINT64)addr,
        pPacket, packetLen, writelen);
}

/*
 * Send a WinDivert packet.
 */
extern BOOL WinDivertSendEx(HANDLE handle, PVOID pPacket, UINT packetLen,
    UINT64 flags, PWINDIVERT_ADDRESS addr, UINT *writelen,
    LPOVERLAPPED overlapped)
{
    if (flags != 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (overlapped == NULL)
    {
        return WinDivertIoControl(handle, IOCTL_WINDIVERT_SEND, 0,
            (UINT64)addr, pPacket, packetLen, writelen);
    }
    else
    {
        return WinDivertIoControlEx(handle, IOCTL_WINDIVERT_SEND, 0,
            (UINT64)addr, pPacket, packetLen, writelen, overlapped);
    }
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
    switch ((int)param)
    {
        case WINDIVERT_PARAM_QUEUE_LEN:
            if (value < WINDIVERT_PARAM_QUEUE_LEN_MIN ||
                value > WINDIVERT_PARAM_QUEUE_LEN_MAX)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            break;
        case WINDIVERT_PARAM_QUEUE_TIME:
            if (value < WINDIVERT_PARAM_QUEUE_TIME_MIN ||
                value > WINDIVERT_PARAM_QUEUE_TIME_MAX)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            break;
        case WINDIVERT_PARAM_QUEUE_SIZE:
            if (value < WINDIVERT_PARAM_QUEUE_SIZE_MIN ||
                value > WINDIVERT_PARAM_QUEUE_SIZE_MAX)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            break;
        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
    }
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_SET_PARAM, (UINT8)param,
        value, NULL, 0, NULL);
}

/*
 * Get a WinDivert parameter.
 */
extern BOOL WinDivertGetParam(HANDLE handle, WINDIVERT_PARAM param,
    UINT64 *pValue)
{
    switch ((int)param)
    {
        case WINDIVERT_PARAM_QUEUE_LEN: case WINDIVERT_PARAM_QUEUE_TIME:
            break;
        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
    }
    return WinDivertIoControl(handle, IOCTL_WINDIVERT_GET_PARAM, (UINT8)param,
        0, pValue, sizeof(UINT64), NULL);
}

/*****************************************************************************/
/* REPLACEMENTS                                                              */
/*****************************************************************************/

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
    for (; str[i] && isxdigit(str[i]); i++)
    {
        num0 = num;
        num *= 16;
        if (isdigit(str[i]))
        {
            num += (UINT32)(str[i] - '0');
        }
        else
        {
            num += (UINT32)(tolower(str[i]) - 'a') + 0x0A;
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

/***************************************************************************/
/* DEBUGGING                                                               */
/***************************************************************************/

#ifdef WINDIVERT_DEBUG
/*
 * Print a filter (debugging).
 */
static void WinDivertFilterDump(windivert_ioctl_filter_t filter, UINT16 len)
{
    UINT16 i;

    for (i = 0; i < len; i++)
    {
        printf("label_%u:\n\tif (", i);
        switch (filter[i].field)
        {
            case WINDIVERT_FILTER_FIELD_ZERO:
                printf("zero ");
                break;
            case WINDIVERT_FILTER_FIELD_INBOUND:
                printf("inbound ");
                break;
            case WINDIVERT_FILTER_FIELD_OUTBOUND:
                printf("outbound ");
                break;
            case WINDIVERT_FILTER_FIELD_IFIDX:
                printf("ifIdx ");
                break;
            case WINDIVERT_FILTER_FIELD_SUBIFIDX:
                printf("subIfIdx ");
                break;
            case WINDIVERT_FILTER_FIELD_IP:
                printf("ip ");
                break;
            case WINDIVERT_FILTER_FIELD_IPV6:
                printf("ipv6 ");
                break;
            case WINDIVERT_FILTER_FIELD_ICMP:
                printf("icmp ");
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6:
                printf("icmpv6 ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP:
                printf("tcp ");
                break;
            case WINDIVERT_FILTER_FIELD_UDP:
                printf("udp ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_HDRLENGTH:
                printf("ip.HdrLength ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_TOS:
                printf("ip.TOS ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_LENGTH:
                printf("ip.Length ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_ID:
                printf("ip.Id ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_DF:
                printf("ip.DF ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_MF:
                printf("ip.MF ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_FRAGOFF:
                printf("ip.FragOff ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_TTL:
                printf("ip.TTL ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_PROTOCOL:
                printf("ip.Protocol ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_CHECKSUM:
                printf("ip.Checksum ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_SRCADDR:
                printf("ip.SrcAddr ");
                break;
            case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
                printf("ip.DstAddr ");
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
                printf("ipv6.TrafficClass ");
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
                printf("ipv6.FlowLabel ");
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_LENGTH:
                printf("ipv6.Length ");
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
                printf("ipv6.NextHdr ");
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
                printf("ipv6.HopLimit ");
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
                printf("ipv6.SrcAddr ");
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
                printf("ipv6.DstAddr ");
                break;
            case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
                printf("icmp.Type ");
                break;
            case WINDIVERT_FILTER_FIELD_ICMP_CODE:
                printf("icmp.Code ");
                break;
            case WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
                printf("icmp.Checksum ");
                break;
            case WINDIVERT_FILTER_FIELD_ICMP_BODY:
                printf("icmp.Body ");
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
                printf("icmpv6.Type ");
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
                printf("icmpv6.Code ");
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
                printf("icmpv6.Checksum ");
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6_BODY:
                printf("icmpv6.Body ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_SRCPORT:
                printf("tcp.SrcPort ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_DSTPORT:
                printf("tcp.DstPort ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_SEQNUM:
                printf("tcp.SeqNum ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_ACKNUM:
                printf("tcp.AckNum ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
                printf("tcp.HdrLength ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_URG:
                printf("tcp.Urg ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_ACK:
                printf("tcp.Ack ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_PSH:
                printf("tcp.Psh ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_RST:
                printf("tcp.Rst ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_SYN:
                printf("tcp.Syn ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_FIN:
                printf("tcp.Fin ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_WINDOW:
                printf("tcp.Window ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_CHECKSUM:
                printf("tcp.Checksum ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_URGPTR:
                printf("tcp.UrgPtr ");
                break;
            case WINDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
                printf("tcp.PayloadLength " );
                break;
            case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
                printf("udp.SrcPort ");
                break;
            case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
                printf("udp.DstPort ");
                break;
            case WINDIVERT_FILTER_FIELD_UDP_LENGTH:
                printf("udp.Length ");
                break;
            case WINDIVERT_FILTER_FIELD_UDP_CHECKSUM:
                printf("udp.Checksum ");
                break;
            case WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                printf("udp.PayloadLength ");
                break;
            default:
                printf("unknown.Field ");       
                break;
        }
        switch (filter[i].test)
        {
            case WINDIVERT_FILTER_TEST_EQ:
                printf("== ");
                break;
            case WINDIVERT_FILTER_TEST_NEQ:
                printf("!= ");
                break;
            case WINDIVERT_FILTER_TEST_LT:
                printf("< ");
                break;
            case WINDIVERT_FILTER_TEST_LEQ:
                printf("<= ");
                break;
            case WINDIVERT_FILTER_TEST_GT:
                printf("> ");
                break;
            case WINDIVERT_FILTER_TEST_GEQ:
                printf(">= ");
                break;
            default:
                printf("?? ");
                break;
        }
        printf("%u)\n", filter[i].arg[0]);
        switch (filter[i].success)
        {
            case WINDIVERT_FILTER_RESULT_ACCEPT:
                printf("\t\treturn ACCEPT;\n");
                break;
            case WINDIVERT_FILTER_RESULT_REJECT:
                printf("\t\treturn REJECT;\n");
                break;
            default:
                printf("\t\tgoto label_%u;\n", filter[i].success);
                break;
        }
        printf("\telse\n");
        switch (filter[i].failure)
        {
            case WINDIVERT_FILTER_RESULT_ACCEPT:
                printf("\t\treturn ACCEPT;\n");
                break;
            case WINDIVERT_FILTER_RESULT_REJECT:
                printf("\t\treturn REJECT;\n");
                break;
            default:
                printf("\t\tgoto label_%u;\n", filter[i].failure);
                break;
        }
    }
}

#endif      /* WINDIVERT_DEBUG */

