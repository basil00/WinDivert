/*
 * windivert.c
 * (C) 2013, all rights reserved,
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
#include <string.h>

#ifdef __MINGW32__
#define wcscpy_s(s1, l, s2)     windivert_wcscpy_s((s1), (l), (s2))
static int windivert_wcscpy_s(wchar_t *dst, size_t len, wchar_t *src)
{
    wcscpy(dst, src);
    return 0;
}
#endif      /* __MINGW32__ */

/*
 * From wdfinstaller.h
 */
typedef struct _WDF_COINSTALLER_INSTALL_OPTIONS
{
    ULONG Size;
    BOOL  ShowRebootPrompt;
} WDF_COINSTALLER_INSTALL_OPTIONS, *PWDF_COINSTALLER_INSTALL_OPTIONS;

VOID FORCEINLINE WDF_COINSTALLER_INSTALL_OPTIONS_INIT(
        PWDF_COINSTALLER_INSTALL_OPTIONS ClientOptions)
{
    RtlZeroMemory(ClientOptions, sizeof(WDF_COINSTALLER_INSTALL_OPTIONS));
    ClientOptions->Size = sizeof(WDF_COINSTALLER_INSTALL_OPTIONS);
}
typedef ULONG (WINAPI *PFN_WDFPREDEVICEINSTALLEX)(
        LPCWSTR inf_path,
        LPCWSTR inf_sec_name,
        PWDF_COINSTALLER_INSTALL_OPTIONS options
    );
typedef ULONG (WINAPI *PFN_WDFPOSTDEVICEINSTALL)(
        LPCWSTR inf_path,
        LPCWSTR inf_sec_name
    );
typedef ULONG (WINAPI *PFN_WDFPREDEVICEREMOVE)(
        LPCWSTR inf_path,
        LPCWSTR inf_sec_name
    );
typedef ULONG (WINAPI *PFN_WDFPOSTDEVICEREMOVE)(
        LPCWSTR inf_path,
        LPCWSTR inf_sec_name
    );

// #define WINDIVERT_DEBUG

#define WINDIVERTEXPORT
#include "windivert.h"
#include "windivert_device.h"

#define WINDIVERT_DRIVER_NAME              L"WinDivert"
#define WINDIVERT_DRIVER_SYS               L"\\" WINDIVERT_DRIVER_NAME L".sys"
#define WINDIVERT_DRIVER_INF               L"\\" WINDIVERT_DRIVER_NAME L".inf"
#define WINDIVERT_DRIVER_SECTION           L"windivert.NT.Wdf"
#define WINDIVERT_DRIVER_MATCH_DLL         L"\\WdfCoInstaller*.dll"

/*
 * ntoh and hton implementation to remove winsock dependency.
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

/*
 * Filter parsing.
 */
typedef enum
{
    FILTER_TOKEN_ICMP,
    FILTER_TOKEN_ICMP_BODY,
    FILTER_TOKEN_ICMP_CHECKSUM, 
    FILTER_TOKEN_ICMP_CODE,
    FILTER_TOKEN_ICMP_TYPE,
    FILTER_TOKEN_ICMPV6,
    FILTER_TOKEN_ICMPV6_BODY,
    FILTER_TOKEN_ICMPV6_CHECKSUM,
    FILTER_TOKEN_ICMPV6_CODE,
    FILTER_TOKEN_ICMPV6_TYPE,
    FILTER_TOKEN_IP,
    FILTER_TOKEN_IP_CHECKSUM,
    FILTER_TOKEN_IP_DF,
    FILTER_TOKEN_IP_DST_ADDR,
    FILTER_TOKEN_IP_FRAG_OFF,
    FILTER_TOKEN_IP_HDR_LENGTH,
    FILTER_TOKEN_IP_ID,
    FILTER_TOKEN_IP_LENGTH,
    FILTER_TOKEN_IP_MF,
    FILTER_TOKEN_IP_PROTOCOL,
    FILTER_TOKEN_IP_SRC_ADDR,
    FILTER_TOKEN_IP_TOS,
    FILTER_TOKEN_IP_TTL,
    FILTER_TOKEN_IPV6,
    FILTER_TOKEN_IPV6_DST_ADDR,
    FILTER_TOKEN_IPV6_FLOW_LABEL,
    FILTER_TOKEN_IPV6_HOP_LIMIT,
    FILTER_TOKEN_IPV6_LENGTH,
    FILTER_TOKEN_IPV6_NEXT_HDR,
    FILTER_TOKEN_IPV6_SRC_ADDR,
    FILTER_TOKEN_IPV6_TRAFFIC_CLASS,
    FILTER_TOKEN_TCP,
    FILTER_TOKEN_TCP_ACK,
    FILTER_TOKEN_TCP_ACK_NUM,
    FILTER_TOKEN_TCP_CHECKSUM,
    FILTER_TOKEN_TCP_DST_PORT,
    FILTER_TOKEN_TCP_FIN,
    FILTER_TOKEN_TCP_HDR_LENGTH,
    FILTER_TOKEN_TCP_PAYLOAD_LENGTH,
    FILTER_TOKEN_TCP_PSH,
    FILTER_TOKEN_TCP_RST,
    FILTER_TOKEN_TCP_SEQ_NUM,
    FILTER_TOKEN_TCP_SRC_PORT,
    FILTER_TOKEN_TCP_SYN,
    FILTER_TOKEN_TCP_URG,
    FILTER_TOKEN_TCP_URG_PTR,
    FILTER_TOKEN_TCP_WINDOW,
    FILTER_TOKEN_UDP,
    FILTER_TOKEN_UDP_CHECKSUM,
    FILTER_TOKEN_UDP_DST_PORT,
    FILTER_TOKEN_UDP_LENGTH,
    FILTER_TOKEN_UDP_PAYLOAD_LENGTH,
    FILTER_TOKEN_UDP_SRC_PORT,
    FILTER_TOKEN_TRUE,
    FILTER_TOKEN_FALSE,
    FILTER_TOKEN_INBOUND,
    FILTER_TOKEN_OUTBOUND,
    FILTER_TOKEN_IF_IDX,
    FILTER_TOKEN_SUB_IF_IDX,
    FILTER_TOKEN_OPEN,
    FILTER_TOKEN_CLOSE,
    FILTER_TOKEN_EQ,
    FILTER_TOKEN_NEQ,
    FILTER_TOKEN_LT,
    FILTER_TOKEN_LEQ,
    FILTER_TOKEN_GT,
    FILTER_TOKEN_GEQ,
    FILTER_TOKEN_NOT,
    FILTER_TOKEN_AND,
    FILTER_TOKEN_OR,
    FILTER_TOKEN_NUMBER,
    FILTER_TOKEN_END,
} FILTER_TOKEN_KIND;

typedef struct
{
    FILTER_TOKEN_KIND kind;
    UINT32 val[4];
} FILTER_TOKEN;

#define FILTER_TOKEN_MAXLEN             32      // Fits longest IPv6

typedef struct
{
    char *name;
    FILTER_TOKEN_KIND kind;
} FILTER_TOKEN_NAME, *PFILTER_TOKEN_NAME;

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
    UINT32 NextHdr:8;
    UINT32 Zero:24;
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
#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17
#define IPPROTO_ICMPV6  58

/*
 * Driver installed?
 */
static BOOLEAN installed = FALSE;

/*
 * Prototypes.
 */
static HMODULE WinDivertLoadCoInstaller(LPWSTR windivert_dll);
static BOOLEAN WinDivertDriverFiles(LPWSTR *dir_str_ptr, LPWSTR *sys_str_ptr,
    LPWSTR *inf_str_ptr, LPWSTR *dll_str_ptr);
static BOOLEAN WinDivertDriverInstall(VOID);
static BOOLEAN WinDivertDriverUnInstall(VOID);
static BOOL WinDivertIoControl(HANDLE handle, DWORD code, UINT8 arg8,
    UINT64 arg, PVOID buf, UINT len, UINT *iolen);
static BOOL WinDivertIoControlEx(HANDLE handle, DWORD code, UINT8 arg8,
    UINT64 arg, PVOID buf, UINT len, UINT *iolen, LPOVERLAPPED overlapped);
static BOOL WinDivertCompileFilter(const char *filter_str,
    WINDIVERT_LAYER layer, windivert_ioctl_filter_t filter, UINT16 *fp);
static int __cdecl WinDivertFilterTokenNameCompare(const void *a,
    const void *b);
static BOOL WinDivertTokenizeFilter(const char *filter, WINDIVERT_LAYER layer,
    FILTER_TOKEN *tokens, UINT tokensmax);
static BOOL WinDivertParseFilter(FILTER_TOKEN *tokens, UINT16 *tp,
    windivert_ioctl_filter_t filter, UINT16 *fp, FILTER_TOKEN_KIND op);
static void WinDivertFilterUpdate(windivert_ioctl_filter_t filter, UINT16 s,
    UINT16 e, UINT16 success, UINT16 failure);
static void WinDivertInitPseudoHeader(PWINDIVERT_IPHDR ip_header,
    PWINDIVERT_PSEUDOHDR pseudo_header, UINT8 protocol, UINT len);
static void WinDivertInitPseudoHeaderV6(PWINDIVERT_IPV6HDR ipv6_header,
    PWINDIVERT_PSEUDOV6HDR pseudov6_header, UINT8 protocol, UINT len);
static UINT16 WinDivertHelperCalcChecksum(PVOID pseudo_header,
    UINT16 pseudo_header_len, PVOID data, UINT len);

#ifdef WINDIVERT_DEBUG
static void WinDivertFilterDump(windivert_ioctl_filter_t filter, UINT16 len);
#endif

/*
 * Co-installer functions.
 */
PFN_WDFPREDEVICEINSTALLEX pfnWdfPreDeviceInstallEx = NULL;
PFN_WDFPOSTDEVICEINSTALL pfnWdfPostDeviceInstall = NULL;
PFN_WDFPREDEVICEREMOVE pfnWdfPreDeviceRemove = NULL;
PFN_WDFPOSTDEVICEREMOVE pfnWdfPostDeviceRemove = NULL;

/*
 * Thread local.
 */
static DWORD windivert_tls_idx;

/*
 * Dll Entry
 */
extern BOOL APIENTRY WinDivertDllEntry(HANDLE module, DWORD reason,
    LPVOID reserved)
{
    HANDLE event;
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
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
            WinDivertDriverUnInstall();
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
 * Load the co-installer functions.
 */
static HMODULE WinDivertLoadCoInstaller(LPWSTR windivert_dll)
{
    static HMODULE library = NULL;
    
    if (library != NULL)
    {
        return library;
    }
    
    library = LoadLibrary(windivert_dll);
    if (library == NULL)
    {
        return NULL;
    }

    pfnWdfPreDeviceInstallEx = (PFN_WDFPREDEVICEINSTALLEX)GetProcAddress(
        library, "WdfPreDeviceInstallEx");
    if (pfnWdfPreDeviceInstallEx == NULL)
    {
        goto WinDivertLoadInstallerError;
    }
    pfnWdfPostDeviceInstall = (PFN_WDFPOSTDEVICEINSTALL)GetProcAddress(
        library, "WdfPostDeviceInstall");
    if (pfnWdfPostDeviceInstall == NULL)
    {
        goto WinDivertLoadInstallerError;
    }
    pfnWdfPreDeviceRemove = (PFN_WDFPREDEVICEREMOVE)GetProcAddress(
        library, "WdfPreDeviceRemove");
    if (pfnWdfPreDeviceRemove == NULL)
    {
        goto WinDivertLoadInstallerError;
    }
    pfnWdfPostDeviceRemove = (PFN_WDFPOSTDEVICEREMOVE)GetProcAddress(
        library, "WdfPostDeviceRemove");
    if (pfnWdfPostDeviceRemove == NULL)
    {
        goto WinDivertLoadInstallerError;
    }

    return library;

WinDivertLoadInstallerError:

    FreeLibrary(library);
    pfnWdfPreDeviceInstallEx = NULL;
    pfnWdfPostDeviceInstall = NULL;
    pfnWdfPreDeviceRemove = NULL;
    pfnWdfPostDeviceRemove = NULL;
    return NULL;
}

/*
 * Locate the WinDivert driver files.
 */
static BOOLEAN WinDivertDriverFiles(LPWSTR *dir_str_ptr, LPWSTR *sys_str_ptr,
    LPWSTR *inf_str_ptr, LPWSTR *dll_str_ptr)
{
    DWORD err;
    HANDLE find;
    WIN32_FIND_DATA find_data;
    LPWSTR dir_str = NULL, sys_str = NULL, inf_str = NULL, dll_str = NULL;
    size_t dir_len, sys_len, inf_len, dll_len;

    SetLastError(0);

    // Construct the filenames from the current directory name
    dir_len = GetCurrentDirectory(0, NULL);
    if (dir_len == 0)
    {
        goto WinDivertDriverFilesError;
    }
    dir_len--;
    sys_len = dir_len + wcslen(WINDIVERT_DRIVER_SYS);
    inf_len = dir_len + wcslen(WINDIVERT_DRIVER_INF);
    dll_len = dir_len + wcslen(WINDIVERT_DRIVER_MATCH_DLL);
    dir_str = (WCHAR *)malloc((dir_len+1)*sizeof(WCHAR));
    if (dir_str == NULL)
    {
        goto WinDivertDriverFilesError;
    }
    if (GetCurrentDirectory(dir_len+1, dir_str) != dir_len)
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        goto WinDivertDriverFilesError;
    }
    sys_str = (WCHAR *)malloc((sys_len+1)*sizeof(WCHAR));
    if (sys_str == NULL)
    {
        goto WinDivertDriverFilesError;
    }
    inf_str = (WCHAR *)malloc((inf_len+1)*sizeof(WCHAR));
    if (inf_str == NULL)
    {
        goto WinDivertDriverFilesError;
    }
    dll_str = (WCHAR *)malloc((dll_len+1)*sizeof(WCHAR));
    if (dll_str == NULL)
    {
        goto WinDivertDriverFilesError;
    }
    if (wcscpy_s(sys_str, sys_len+1, dir_str) != 0 ||
        wcscpy_s(inf_str, inf_len+1, dir_str) != 0 ||
        wcscpy_s(dll_str, dll_len+1, dir_str) != 0 ||
        wcscpy_s(sys_str + dir_len, sys_len+1-dir_len,
            WINDIVERT_DRIVER_SYS) != 0 ||
        wcscpy_s(inf_str + dir_len, inf_len+1-dir_len,
            WINDIVERT_DRIVER_INF) != 0 ||
        wcscpy_s(dll_str + dir_len, dll_len+1-dir_len,
            WINDIVERT_DRIVER_MATCH_DLL))
    {
        goto WinDivertDriverFilesError;
    }

    // Check the the files exist; and find the co-installer filename.
    find = FindFirstFile(sys_str, &find_data);
    if (find == INVALID_HANDLE_VALUE)
    {
        goto WinDivertDriverFilesError;
    }
    FindClose(find);
    find = FindFirstFile(inf_str, &find_data);
    if (find == INVALID_HANDLE_VALUE)
    {
        goto WinDivertDriverFilesError;
    }
    FindClose(find);
    find = FindFirstFile(dll_str, &find_data);
    free(dll_str);
    dll_str = NULL;
    if (find == INVALID_HANDLE_VALUE)
    {
        goto WinDivertDriverFilesError;
    }
    FindClose(find);
    dll_len = dir_len + 1 + wcslen(find_data.cFileName) + 1;
    dll_str = (WCHAR *)malloc((dll_len+1)*sizeof(WCHAR));
    if (dll_str == NULL)
    {
        goto WinDivertDriverFilesError;
    }
    if (wcscpy_s(dll_str, dll_len+1, dir_str) != 0)
    {
        goto WinDivertDriverFilesError;
    }
    dll_str[dir_len] = L'\\';
    if (wcscpy_s(dll_str + dir_len + 1, dll_len+1-dir_len-1,
            find_data.cFileName) != 0)
    {
        goto WinDivertDriverFilesError;
    }

    *dir_str_ptr = dir_str;
    *sys_str_ptr = sys_str;
    *inf_str_ptr = inf_str;
    *dll_str_ptr = dll_str;
    return TRUE;

WinDivertDriverFilesError:
    err = GetLastError();
    free(dir_str);
    free(sys_str);
    free(inf_str);
    free(dll_str);
    if (err != 0)
        SetLastError(err);
    else
        SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

/*
 * Install the WinDivert driver.
 */
static BOOLEAN WinDivertDriverInstall(VOID)
{
    DWORD err;
    SC_HANDLE manager = NULL, service = NULL;
    WDF_COINSTALLER_INSTALL_OPTIONS client_options;
    LPWSTR windivert_dir = NULL, windivert_sys = NULL, windivert_inf = NULL,
        windivert_dll = NULL;

    // Do nothing if the driver is already installed:
    if (installed)
    {
        return TRUE;
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
        if (!StartService(service, 0, NULL))
        {
            err = GetLastError();
            installed = (err == ERROR_SERVICE_ALREADY_RUNNING);
            goto WinDivertDriverInstallExit;
        }
        installed = TRUE;
        goto WinDivertDriverInstallExit;
    }

    // Get driver files:
    if (!WinDivertDriverFiles(&windivert_dir, &windivert_sys, &windivert_inf,
            &windivert_dll))
    {
        return FALSE;
    }

    // Load the co-installer:
    if (WinDivertLoadCoInstaller(windivert_dll) == NULL)
    {
        return FALSE;
    }

    // Pre-install:
    WDF_COINSTALLER_INSTALL_OPTIONS_INIT(&client_options);
    err = pfnWdfPreDeviceInstallEx(windivert_inf, WINDIVERT_DRIVER_SECTION,
        &client_options);
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
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
            installed = TRUE;
        }
        goto WinDivertDriverInstallExit;
    }

    // Post-install:
    err = pfnWdfPostDeviceInstall(windivert_inf, NULL);
    if (err == ERROR_INVALID_PARAMETER)
    {
        // We ignore ERROR_INVALID_PARAMETER.  WdfPostDeviceInstall sometimes
        // returns this error for no obvious reason, and when ignored the
        // driver seems to still work perfectly.
        err = ERROR_SUCCESS;
    }
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        goto WinDivertDriverInstallExit;
    }

    // Start the service:
    if (!StartService(service, 0, NULL))
    {
        err = GetLastError();
        installed = (err == ERROR_SERVICE_ALREADY_RUNNING);
        goto WinDivertDriverInstallExit;
    }
    
    installed = TRUE;

WinDivertDriverInstallExit:
    err = GetLastError();
    free(windivert_dir);
    free(windivert_sys);
    free(windivert_inf);
    free(windivert_dll);
    if (service != NULL)
    {
        CloseServiceHandle(service);
    }
    if (manager != NULL)
    {
        CloseServiceHandle(manager);
    }
    SetLastError(err);
    return installed;
}

/*
 * Uninstall the WinDivert driver.
 */
static BOOLEAN WinDivertDriverUnInstall(VOID)
{
    DWORD err;
    SC_HANDLE manager = NULL, service = NULL;
    LPWSTR windivert_dir = NULL, windivert_sys = NULL, windivert_inf = NULL,
        windivert_dll = NULL;

    // Do nothing if the driver is not installed:
    if (!installed)
    {
        return FALSE;
    }

    // Get driver files:
    if (!WinDivertDriverFiles(&windivert_dir, &windivert_sys, &windivert_inf,
            &windivert_dll))
    {
        return FALSE;
    }

    // Load the co-installer:
    if (WinDivertLoadCoInstaller(windivert_dll) == NULL)
    {
        return FALSE;
    }

    // Pre-uninstall:
    err = pfnWdfPreDeviceRemove(windivert_inf, WINDIVERT_DRIVER_SECTION);
    if (err != ERROR_SUCCESS)
    {
        goto WinDivertDriverUnInstallExit;
    }

    // Open the service manager:
    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (manager == NULL)
    {
        goto WinDivertDriverUnInstallExit;
    }

    // Open the service:
    service = OpenService(manager, WINDIVERT_DEVICE_NAME, SERVICE_ALL_ACCESS);
    if (service == NULL)
    {
        goto WinDivertDriverUnInstallExit;
    }

    // Delete the service:
    if (!DeleteService(service))
    {
        goto WinDivertDriverUnInstallExit;
    }

    // Post-uninstall:
    err = pfnWdfPostDeviceRemove(windivert_inf, WINDIVERT_DRIVER_SECTION);
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        goto WinDivertDriverUnInstallExit;
    }

    installed = FALSE;

WinDivertDriverUnInstallExit:
    free(windivert_dir);
    free(windivert_sys);
    free(windivert_inf);
    free(windivert_dll);
    if (service != NULL)
    {
        CloseServiceHandle(service);
    }
    if (manager != NULL)
    {
        CloseServiceHandle(manager);
    }
    return !installed;
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

    overlapped.Offset     = 0;
    overlapped.OffsetHigh = 0;
    overlapped.hEvent     = event;
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
    struct windivert_ioctl_filter_s ioctl_filter[WINDIVERT_FILTER_MAXLEN];
    UINT16 filter_len;
    DWORD err;
    HANDLE handle;
    UINT32 priority32;

    // Parameter checking.
    if (!WINDIVERT_FLAGS_VALID(flags) || layer > WINDIVERT_LAYER_MAX)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    // Parse the filter:
    if (!WinDivertCompileFilter(filter, layer, ioctl_filter, &filter_len))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

#ifdef WINDIVERT_DEBUG
    WinDivertFilterDump(ioctl_filter, filter_len);
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
        if (!WinDivertDriverInstall())
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
        if (handle == INVALID_HANDLE_VALUE)
        {
            return INVALID_HANDLE_VALUE;
        }
    }
    else
    {
        installed = TRUE;
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
    priority32 = WINDIVERT_PRIORITY(priority);
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
            ioctl_filter, filter_len*sizeof(struct windivert_ioctl_filter_s),
            NULL))
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

/*
 * Compile a filter.
 */
static BOOL WinDivertCompileFilter(const char *filter_str,
    WINDIVERT_LAYER layer, windivert_ioctl_filter_t filter, UINT16 *fp)
{
    FILTER_TOKEN tokens[WINDIVERT_FILTER_MAXLEN*3];
    UINT16 tp;

    if (!WinDivertTokenizeFilter(filter_str, layer, tokens,
            WINDIVERT_FILTER_MAXLEN*3-1))
    {
        return FALSE;
    }

    tp = 0;
    *fp = 0;
    if (!WinDivertParseFilter(tokens, &tp, filter, fp, FILTER_TOKEN_AND))
    {
        return FALSE;
    }
    if (tokens[tp].kind != FILTER_TOKEN_END)
    {
        return FALSE;
    }
    return TRUE;
}

/*
 * Compare two FILTER_TOKEN_NAMEs.
 */
static int __cdecl WinDivertFilterTokenNameCompare(const void *a,
    const void *b)
{
    PFILTER_TOKEN_NAME na = (PFILTER_TOKEN_NAME)a;
    PFILTER_TOKEN_NAME nb = (PFILTER_TOKEN_NAME)b;
    return strcmp(na->name, nb->name);
}

/*
 * Tokenize the given filter string.
 */
static BOOL WinDivertTokenizeFilter(const char *filter, WINDIVERT_LAYER layer,
    FILTER_TOKEN *tokens, UINT tokensmax)
{
    static const FILTER_TOKEN_NAME token_names[] =
    {
        {"and",                 FILTER_TOKEN_AND},
        {"false",               FILTER_TOKEN_FALSE},
        {"icmp",                FILTER_TOKEN_ICMP},
        {"icmp.Body",           FILTER_TOKEN_ICMP_BODY},
        {"icmp.Checksum",       FILTER_TOKEN_ICMP_CHECKSUM},
        {"icmp.Code",           FILTER_TOKEN_ICMP_CODE},
        {"icmp.Type",           FILTER_TOKEN_ICMP_TYPE},
        {"icmpv6",              FILTER_TOKEN_ICMPV6},
        {"icmpv6.Body",         FILTER_TOKEN_ICMPV6_BODY},
        {"icmpv6.Checksum",     FILTER_TOKEN_ICMPV6_CHECKSUM},
        {"icmpv6.Code",         FILTER_TOKEN_ICMPV6_CODE},
        {"icmpv6.Type",         FILTER_TOKEN_ICMPV6_TYPE},
        {"ifIdx",               FILTER_TOKEN_IF_IDX},
        {"inbound",             FILTER_TOKEN_INBOUND},
        {"ip",                  FILTER_TOKEN_IP},
        {"ip.Checksum",         FILTER_TOKEN_IP_CHECKSUM},
        {"ip.DF",               FILTER_TOKEN_IP_DF},
        {"ip.DstAddr",          FILTER_TOKEN_IP_DST_ADDR},
        {"ip.FragOff",          FILTER_TOKEN_IP_FRAG_OFF},
        {"ip.HdrLength",        FILTER_TOKEN_IP_HDR_LENGTH},
        {"ip.Id",               FILTER_TOKEN_IP_ID},
        {"ip.Length",           FILTER_TOKEN_IP_LENGTH},
        {"ip.MF",               FILTER_TOKEN_IP_MF},
        {"ip.Protocol",         FILTER_TOKEN_IP_PROTOCOL},
        {"ip.SrcAddr",          FILTER_TOKEN_IP_SRC_ADDR},
        {"ip.TOS",              FILTER_TOKEN_IP_TOS},
        {"ip.TTL",              FILTER_TOKEN_IP_TTL},
        {"ipv6",                FILTER_TOKEN_IPV6},
        {"ipv6.DstAddr",        FILTER_TOKEN_IPV6_DST_ADDR},
        {"ipv6.FlowLabel",      FILTER_TOKEN_IPV6_FLOW_LABEL},
        {"ipv6.HopLimit",       FILTER_TOKEN_IPV6_HOP_LIMIT},
        {"ipv6.Length",         FILTER_TOKEN_IPV6_LENGTH},
        {"ipv6.NextHdr",        FILTER_TOKEN_IPV6_NEXT_HDR},
        {"ipv6.SrcAddr",        FILTER_TOKEN_IPV6_SRC_ADDR},
        {"ipv6.TrafficClass",   FILTER_TOKEN_IPV6_TRAFFIC_CLASS},
        {"not",                 FILTER_TOKEN_NOT},
        {"or",                  FILTER_TOKEN_OR},
        {"outbound",            FILTER_TOKEN_OUTBOUND},
        {"subIfIdx",            FILTER_TOKEN_SUB_IF_IDX},
        {"tcp",                 FILTER_TOKEN_TCP},
        {"tcp.Ack",             FILTER_TOKEN_TCP_ACK},
        {"tcp.AckNum",          FILTER_TOKEN_TCP_ACK_NUM},
        {"tcp.Checksum",        FILTER_TOKEN_TCP_CHECKSUM},
        {"tcp.DstPort",         FILTER_TOKEN_TCP_DST_PORT},
        {"tcp.Fin",             FILTER_TOKEN_TCP_FIN},
        {"tcp.HdrLength",       FILTER_TOKEN_TCP_HDR_LENGTH},
        {"tcp.PayloadLength",   FILTER_TOKEN_TCP_PAYLOAD_LENGTH},
        {"tcp.Psh",             FILTER_TOKEN_TCP_PSH},
        {"tcp.Rst",             FILTER_TOKEN_TCP_RST},
        {"tcp.SeqNum",          FILTER_TOKEN_TCP_SEQ_NUM},
        {"tcp.SrcPort",         FILTER_TOKEN_TCP_SRC_PORT},
        {"tcp.Syn",             FILTER_TOKEN_TCP_SYN},
        {"tcp.Urg",             FILTER_TOKEN_TCP_URG},
        {"tcp.UrgPtr",          FILTER_TOKEN_TCP_URG_PTR},
        {"tcp.Window",          FILTER_TOKEN_TCP_WINDOW},
        {"true",                FILTER_TOKEN_TRUE},
        {"udp",                 FILTER_TOKEN_UDP},
        {"udp.Checksum",        FILTER_TOKEN_UDP_CHECKSUM},
        {"udp.DstPort",         FILTER_TOKEN_UDP_DST_PORT},
        {"udp.Length",          FILTER_TOKEN_UDP_LENGTH},
        {"udp.PayloadLength",   FILTER_TOKEN_UDP_PAYLOAD_LENGTH},
        {"udp.SrcPort",         FILTER_TOKEN_UDP_SRC_PORT},
    };
    FILTER_TOKEN_NAME key, *result;
    char c;
    char token[FILTER_TOKEN_MAXLEN];
    UINT i = 0, j;
    UINT tp = 0;

    while (TRUE)
    {
        if (tp >= tokensmax-1)
        {
            return FALSE;
        }
        memset(tokens[tp].val, 0, sizeof(tokens[tp].val));
        while (isspace(filter[i]))
        {
            i++;
        }
        c = filter[i++];
        switch (c)
        {
            case '\0':
                tokens[tp].kind = FILTER_TOKEN_END;
                return TRUE;
            case '(':
                tokens[tp++].kind = FILTER_TOKEN_OPEN;
                continue;
            case ')':
                tokens[tp++].kind = FILTER_TOKEN_CLOSE;
                continue;
            case '!':
                if (filter[i] == '=')
                {
                    i++;
                    tokens[tp++].kind = FILTER_TOKEN_NEQ;
                }
                else
                {
                    tokens[tp++].kind = FILTER_TOKEN_NOT;
                }
                continue;
            case '=':
                if (filter[i] == '=')
                {
                    i++;
                }
                tokens[tp++].kind = FILTER_TOKEN_EQ;
                continue;
            case '<':
                if (filter[i] == '=')
                {
                    i++;
                    tokens[tp++].kind = FILTER_TOKEN_LEQ;
                }
                else
                {
                    tokens[tp++].kind = FILTER_TOKEN_LT;
                }
                continue;
            case '>':
                if (filter[i] == '=')
                {
                    i++;
                    tokens[tp++].kind = FILTER_TOKEN_GEQ;
                }
                else
                {
                    tokens[tp++].kind = FILTER_TOKEN_GT;
                }
                continue;
            case '&':
                if (filter[i++] != '&')
                {
                    return FALSE;
                }
                tokens[tp++].kind = FILTER_TOKEN_AND;
                continue;
            case '|':
                if (filter[i++] != '|')
                {
                    return FALSE;
                }
                tokens[tp++].kind = FILTER_TOKEN_OR;
                continue;
            default:
                break;
        }
        token[0] = c;
        if (isalnum(c) || c == '.' || c == ':')
        {
            UINT32 num;
            char *end;
            for (j = 1; j < FILTER_TOKEN_MAXLEN && (isalnum(filter[i]) ||
                    filter[i] == '.' || filter[i] == ':'); j++, i++)
            {
                token[j] = filter[i];
            }
            if (j >= FILTER_TOKEN_MAXLEN)
            {
                return FALSE;
            }
            token[j] = '\0';

            // Check for symbol:
            key.name = token;
            result = (PFILTER_TOKEN_NAME)bsearch((const void *)&key,
                token_names, sizeof(token_names) / sizeof(FILTER_TOKEN_NAME),
                sizeof(FILTER_TOKEN_NAME), WinDivertFilterTokenNameCompare);
            if (result != NULL)
            {
                switch (layer)
                {
                    case WINDIVERT_LAYER_NETWORK_FORWARD:
                        if (result->kind == FILTER_TOKEN_INBOUND ||
                            result->kind == FILTER_TOKEN_OUTBOUND)
                        {
                            return FALSE;
                        }
                        break;
                    default:
                        break;
                }
                tokens[tp++].kind = result->kind;
                continue;
            }

            // Check for base 10 number:
            errno = 0;
            num = strtoul(token, &end, 10);
            if (errno == 0 && *end == '\0')
            {
                tokens[tp].kind   = FILTER_TOKEN_NUMBER;
                tokens[tp].val[0] = num;
                tp++;
                continue;
            }

            // Check for base 16 number:
            errno = 0;
            num = strtoul(token, &end, 16);
            if (errno == 0 && *end == '\0')
            {
                tokens[tp].kind   = FILTER_TOKEN_NUMBER;
                tokens[tp].val[0] = num;
                tp++;
                continue;
            }

            // Check for IPv4 address:
            if (WinDivertHelperParseIPv4Address(token, tokens[tp].val))
            {
                tokens[tp].kind = FILTER_TOKEN_NUMBER;
                tp++;
                continue;
            }

            // Check for IPv6 address:
            SetLastError(0);
            if (WinDivertHelperParseIPv6Address(token, tokens[tp].val))
            {
                tokens[tp].kind = FILTER_TOKEN_NUMBER;
                tp++;
                continue;
            }

            return FALSE;
        }
        else
        {
            return FALSE;
        }
    }
}

/*
 * Parse the given filter.
 */
static BOOL WinDivertParseFilter(FILTER_TOKEN *tokens, UINT16 *tp,
    windivert_ioctl_filter_t filter, UINT16 *fp, FILTER_TOKEN_KIND op)
{
    BOOL testop, fused, result, negate;
    FILTER_TOKEN token;
    UINT16 f, s;
    s = *fp;

WinDivertParseFilterNext:

    testop = TRUE;
    fused = TRUE;
    negate = FALSE;
    token = tokens[*tp];

    *tp = *tp + 1;
    f = *fp;
    if (f >= WINDIVERT_FILTER_MAXLEN)
    {
        return FALSE;
    }
    filter[f].success = WINDIVERT_FILTER_RESULT_ACCEPT;
    filter[f].failure = WINDIVERT_FILTER_RESULT_REJECT;
    filter[f].arg[1] = 0;
    filter[f].arg[2] = 0;
    filter[f].arg[3] = 0;
    if (token.kind == FILTER_TOKEN_NOT)
    {
        negate = TRUE;
        token = tokens[*tp];
        *tp = *tp + 1;
    }
    switch (token.kind)
    {
        case FILTER_TOKEN_OPEN:
            result = WinDivertParseFilter(tokens, tp, filter, fp,
                FILTER_TOKEN_AND);
            result = (result? (tokens[*tp].kind == FILTER_TOKEN_CLOSE): FALSE);
            if (!result)
            {
                return FALSE;
            }
            *tp = *tp + 1;
            testop = FALSE;
            fused = FALSE;
            break;
        case FILTER_TOKEN_TRUE: case FILTER_TOKEN_FALSE:
            filter[f].field  = WINDIVERT_FILTER_FIELD_ZERO;
            filter[f].test   = WINDIVERT_FILTER_TEST_EQ;
            filter[f].arg[0] = (token.kind == FILTER_TOKEN_FALSE);
            testop = FALSE;
            break;
        case FILTER_TOKEN_OUTBOUND:
            filter[f].field = WINDIVERT_FILTER_FIELD_OUTBOUND;
            break;
        case FILTER_TOKEN_INBOUND:
            filter[f].field = WINDIVERT_FILTER_FIELD_INBOUND;
            break;
        case FILTER_TOKEN_IF_IDX:
            filter[f].field = WINDIVERT_FILTER_FIELD_IFIDX;
            break;
        case FILTER_TOKEN_SUB_IF_IDX:
            filter[f].field = WINDIVERT_FILTER_FIELD_SUBIFIDX;
            break;
        case FILTER_TOKEN_IP:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP;
            break;
        case FILTER_TOKEN_IPV6:
            filter[f].field = WINDIVERT_FILTER_FIELD_IPV6;
            break;
        case FILTER_TOKEN_ICMP:
            filter[f].field = WINDIVERT_FILTER_FIELD_ICMP;
            break;
        case FILTER_TOKEN_ICMPV6:
            filter[f].field = WINDIVERT_FILTER_FIELD_ICMPV6;
            break;
        case FILTER_TOKEN_TCP:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP;
            break;
        case FILTER_TOKEN_UDP:
            filter[f].field = WINDIVERT_FILTER_FIELD_UDP;
            break;
        case FILTER_TOKEN_IP_HDR_LENGTH:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_HDRLENGTH;
            break;
        case FILTER_TOKEN_IP_TOS:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_TOS;
            break;
        case FILTER_TOKEN_IP_LENGTH:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_LENGTH;
            break;
        case FILTER_TOKEN_IP_ID:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_ID;
            break;
        case FILTER_TOKEN_IP_DF:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_DF;
            break;
        case FILTER_TOKEN_IP_MF:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_MF;
            break;
        case FILTER_TOKEN_IP_FRAG_OFF:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_FRAGOFF;
            break;
        case FILTER_TOKEN_IP_TTL:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_TTL;
            break;
        case FILTER_TOKEN_IP_PROTOCOL:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_PROTOCOL;
            break;
        case FILTER_TOKEN_IP_CHECKSUM:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_CHECKSUM;
            break;
        case FILTER_TOKEN_IP_SRC_ADDR:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_SRCADDR;
            break;
        case FILTER_TOKEN_IP_DST_ADDR:
            filter[f].field = WINDIVERT_FILTER_FIELD_IP_DSTADDR;
            break;
        case FILTER_TOKEN_IPV6_TRAFFIC_CLASS:
            filter[f].field = WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS;
            break;
        case FILTER_TOKEN_IPV6_FLOW_LABEL:
            filter[f].field = WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL;
            break;
        case FILTER_TOKEN_IPV6_LENGTH:
            filter[f].field = WINDIVERT_FILTER_FIELD_IPV6_LENGTH;
            break;
        case FILTER_TOKEN_IPV6_NEXT_HDR:
            filter[f].field = WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR;
            break;
        case FILTER_TOKEN_IPV6_HOP_LIMIT:
            filter[f].field = WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT;
            break;
        case FILTER_TOKEN_IPV6_SRC_ADDR:
            filter[f].field = WINDIVERT_FILTER_FIELD_IPV6_SRCADDR;
            break;
        case FILTER_TOKEN_IPV6_DST_ADDR:
            filter[f].field = WINDIVERT_FILTER_FIELD_IPV6_DSTADDR;
            break;
        case FILTER_TOKEN_ICMP_TYPE:
            filter[f].field = WINDIVERT_FILTER_FIELD_ICMP_TYPE;
            break;
        case FILTER_TOKEN_ICMP_CODE:
            filter[f].field = WINDIVERT_FILTER_FIELD_ICMP_CODE;
            break;
        case FILTER_TOKEN_ICMP_CHECKSUM:
            filter[f].field = WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM;
            break;
        case FILTER_TOKEN_ICMP_BODY:
            filter[f].field = WINDIVERT_FILTER_FIELD_ICMP_BODY;
            break;
        case FILTER_TOKEN_ICMPV6_TYPE:
            filter[f].field = WINDIVERT_FILTER_FIELD_ICMPV6_TYPE;
            break;
        case FILTER_TOKEN_ICMPV6_CODE:
            filter[f].field = WINDIVERT_FILTER_FIELD_ICMPV6_CODE;
            break;
        case FILTER_TOKEN_ICMPV6_CHECKSUM:
            filter[f].field = WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM;
            break;
        case FILTER_TOKEN_ICMPV6_BODY:
            filter[f].field = WINDIVERT_FILTER_FIELD_ICMPV6_BODY;
            break;
        case FILTER_TOKEN_TCP_SRC_PORT:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_SRCPORT;
            break;
        case FILTER_TOKEN_TCP_DST_PORT:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_DSTPORT;
            break;
        case FILTER_TOKEN_TCP_SEQ_NUM:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_SEQNUM;
            break;
        case FILTER_TOKEN_TCP_ACK_NUM:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_ACKNUM;
            break;
        case FILTER_TOKEN_TCP_HDR_LENGTH:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH;
            break;
        case FILTER_TOKEN_TCP_URG:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_URG;
            break;
        case FILTER_TOKEN_TCP_ACK:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_ACK;
            break;
        case FILTER_TOKEN_TCP_PSH:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_PSH;
            break;
        case FILTER_TOKEN_TCP_RST:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_RST;
            break;
        case FILTER_TOKEN_TCP_SYN:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_SYN;
            break;
        case FILTER_TOKEN_TCP_FIN:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_FIN;
            break;
        case FILTER_TOKEN_TCP_WINDOW:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_WINDOW;
            break;
        case FILTER_TOKEN_TCP_CHECKSUM:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_CHECKSUM;
            break;
        case FILTER_TOKEN_TCP_URG_PTR:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_URGPTR;
            break;
        case FILTER_TOKEN_TCP_PAYLOAD_LENGTH:
            filter[f].field = WINDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH;
            break;
        case FILTER_TOKEN_UDP_SRC_PORT:
            filter[f].field = WINDIVERT_FILTER_FIELD_UDP_SRCPORT;
            break;
        case FILTER_TOKEN_UDP_DST_PORT:
            filter[f].field = WINDIVERT_FILTER_FIELD_UDP_DSTPORT;
            break;
        case FILTER_TOKEN_UDP_LENGTH:
            filter[f].field = WINDIVERT_FILTER_FIELD_UDP_LENGTH;
            break;
        case FILTER_TOKEN_UDP_CHECKSUM:
            filter[f].field = WINDIVERT_FILTER_FIELD_UDP_CHECKSUM;
            break;
        case FILTER_TOKEN_UDP_PAYLOAD_LENGTH:
            filter[f].field = WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH;
            break;
        default:
            return FALSE;
    }

    if (fused)
    {
        *fp = f+1;
    }

    if (testop)
    {
        token = tokens[*tp];
        if (!negate)
        {
            switch (token.kind)
            {
                case FILTER_TOKEN_EQ:
                    filter[f].test = WINDIVERT_FILTER_TEST_EQ;
                    break;
                case FILTER_TOKEN_NEQ:
                    filter[f].test = WINDIVERT_FILTER_TEST_NEQ;
                    break;
                case FILTER_TOKEN_LT:
                    filter[f].test = WINDIVERT_FILTER_TEST_LT;
                    break;
                case FILTER_TOKEN_LEQ:
                    filter[f].test = WINDIVERT_FILTER_TEST_LEQ;
                    break;
                case FILTER_TOKEN_GT:
                    filter[f].test = WINDIVERT_FILTER_TEST_GT;
                    break;
                case FILTER_TOKEN_GEQ:
                    filter[f].test = WINDIVERT_FILTER_TEST_GEQ;
                    break;
                default:
                    filter[f].test = WINDIVERT_FILTER_TEST_NEQ;
                    filter[f].arg[0] = 0;
                    testop = FALSE;
                    break;
            }
        }
        else
        {
            switch (token.kind)
            {
                case FILTER_TOKEN_EQ:
                    filter[f].test = WINDIVERT_FILTER_TEST_NEQ;
                    break;
                case FILTER_TOKEN_NEQ:
                    filter[f].test = WINDIVERT_FILTER_TEST_EQ;
                    break;
                case FILTER_TOKEN_LT:
                    filter[f].test = WINDIVERT_FILTER_TEST_GEQ;
                    break;
                case FILTER_TOKEN_LEQ:
                    filter[f].test = WINDIVERT_FILTER_TEST_GT;
                    break;
                case FILTER_TOKEN_GT:
                    filter[f].test = WINDIVERT_FILTER_TEST_LEQ;
                    break;
                case FILTER_TOKEN_GEQ:
                    filter[f].test = WINDIVERT_FILTER_TEST_LT;
                    break;
                default:
                    filter[f].test = WINDIVERT_FILTER_TEST_EQ;
                    filter[f].arg[0] = 0;
                    testop = FALSE;
                    break;
            }
        }

        if (testop)
        {
            *tp = *tp + 1;
            token = tokens[*tp];
            *tp = *tp + 1;
            if (token.kind != FILTER_TOKEN_NUMBER)
            {
                return FALSE;
            }
            filter[f].arg[0] = token.val[0];
            filter[f].arg[1] = token.val[1];
            filter[f].arg[2] = token.val[2];
            filter[f].arg[3] = token.val[3];
        }
    }

    token = tokens[*tp];
    if (token.kind != FILTER_TOKEN_AND && token.kind != FILTER_TOKEN_OR)
    {
        return TRUE;
    }
    if (op < token.kind)
    {
        op = token.kind;
        f = s;
    }
    *tp = *tp + 1;
    switch (token.kind)
    {
        case FILTER_TOKEN_AND:
            WinDivertFilterUpdate(filter, f, *fp, *fp,
                WINDIVERT_FILTER_RESULT_REJECT);
            goto WinDivertParseFilterNext;
        case FILTER_TOKEN_OR:
            WinDivertFilterUpdate(filter, f, *fp,
                WINDIVERT_FILTER_RESULT_ACCEPT, *fp);
            goto WinDivertParseFilterNext;
        default:
            break;
    }
    return TRUE;
}

/*
 * Update success.
 */
static void WinDivertFilterUpdate(windivert_ioctl_filter_t filter, UINT16 s,
    UINT16 e, UINT16 success, UINT16 failure)
{
    UINT16 i;

    for (i = s; i < e; i++)
    {
        switch (filter[i].success)
        {
            case WINDIVERT_FILTER_RESULT_ACCEPT:
                filter[i].success = success;
                break;
            case WINDIVERT_FILTER_RESULT_REJECT:
                filter[i].success = failure;
                break;
        }
        switch (filter[i].failure)
        {
            case WINDIVERT_FILTER_RESULT_ACCEPT:
                filter[i].failure = success;
                break;
            case WINDIVERT_FILTER_RESULT_REJECT:
                filter[i].failure = failure;
                break;
        }
    }
}

/****************************************************************************/
/* WINDIVERT HELPER IMPLEMENTATION                                          */
/****************************************************************************/

/*
 * Parse IPv4/IPv6/ICMP/ICMPv6/TCP/UDP headers from a raw packet.
 */
extern BOOL WinDivertHelperParsePacket(PVOID pPacket, UINT packetLen,
    PWINDIVERT_IPHDR *ppIpHdr, PWINDIVERT_IPV6HDR *ppIpv6Hdr,
    PWINDIVERT_ICMPHDR *ppIcmpHdr, PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
    PWINDIVERT_TCPHDR *ppTcpHdr, PWINDIVERT_UDPHDR *ppUdpHdr, PVOID *ppData,
    UINT *pDataLen)
{
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_IPV6HDR ipv6_header = NULL;
    PWINDIVERT_ICMPHDR icmp_header = NULL;
    PWINDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PWINDIVERT_TCPHDR tcp_header = NULL;
    PWINDIVERT_UDPHDR udp_header = NULL;
    UINT16 header_len;
    UINT8 trans_proto;
    PVOID data = NULL;
    UINT data_len = 0;
    BOOL success;

    if (pPacket == NULL || packetLen < sizeof(UINT8))
    {
        goto WinDivertHelperParsePacketExit;
    }
    data = pPacket;
    data_len = packetLen;

    ip_header = (PWINDIVERT_IPHDR)data;
    switch (ip_header->Version)
    {
        case 4:
            if (data_len < sizeof(WINDIVERT_IPHDR) ||
                ip_header->HdrLength < 5 ||
                data_len < ip_header->HdrLength*sizeof(UINT32) ||
                ntohs(ip_header->Length) != data_len)
            {
                ip_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            trans_proto = ip_header->Protocol;
            header_len = ip_header->HdrLength*sizeof(UINT32); 
            data = (PVOID)((UINT8 *)data + header_len);
            data_len -= header_len;
            break;
        case 6:
            ip_header = NULL;
            ipv6_header = (PWINDIVERT_IPV6HDR)data;
            if (data_len < sizeof(WINDIVERT_IPV6HDR) ||
                ntohs(ipv6_header->Length) !=
                    data_len - sizeof(WINDIVERT_IPV6HDR))
            {
                ipv6_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            trans_proto = ipv6_header->NextHdr;
            data = (PVOID)((UINT8 *)data + sizeof(WINDIVERT_IPV6HDR));
            data_len -= sizeof(WINDIVERT_IPV6HDR);
            break;
        default:
            ip_header = NULL;
            goto WinDivertHelperParsePacketExit;
    }

    switch (trans_proto)
    {
        case IPPROTO_TCP:
            tcp_header = (PWINDIVERT_TCPHDR)data;
            if (data_len < sizeof(WINDIVERT_TCPHDR) ||
                tcp_header->HdrLength < 5 ||
                data_len < tcp_header->HdrLength*sizeof(UINT32))
            {
                tcp_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            header_len = tcp_header->HdrLength*sizeof(UINT32);
            data = ((UINT8 *)data + header_len);
            data_len -= header_len;
            break;
        case IPPROTO_UDP:
            udp_header = (PWINDIVERT_UDPHDR)data;
            if (data_len < sizeof(WINDIVERT_UDPHDR) ||
                ntohs(udp_header->Length) != data_len)
            {
                udp_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            data = ((UINT8 *)data + sizeof(WINDIVERT_UDPHDR));
            data_len -= sizeof(WINDIVERT_UDPHDR);
            break;
        case IPPROTO_ICMP:
            icmp_header = (PWINDIVERT_ICMPHDR)data;
            if (ip_header == NULL ||
                data_len < sizeof(WINDIVERT_ICMPHDR))
            {
                icmp_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            data = ((UINT8 *)data + sizeof(WINDIVERT_ICMPHDR));
            data_len -= sizeof(WINDIVERT_ICMPHDR);
            break;
        case IPPROTO_ICMPV6:
            icmpv6_header = (PWINDIVERT_ICMPV6HDR)data;
            if (ipv6_header == NULL ||
                data_len < sizeof(WINDIVERT_ICMPV6HDR))
            {
                icmpv6_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            data = ((UINT8 *)data + sizeof(WINDIVERT_ICMPV6HDR));
            data_len -= sizeof(WINDIVERT_ICMPV6HDR);
            break;
        default:
            break;
    }

    if (data_len == 0)
    {
        data = NULL;
    }

WinDivertHelperParsePacketExit:
    success = TRUE;
    if (ppIpHdr != NULL)
    {
        *ppIpHdr = ip_header;
        success = success && (ip_header != NULL);
    }
    if (ppIpv6Hdr != NULL)
    {
        *ppIpv6Hdr = ipv6_header;
        success = success && (ipv6_header != NULL);
    }
    if (ppIcmpHdr != NULL)
    {
        *ppIcmpHdr = icmp_header;
        success = success && (icmp_header != NULL);
    }
    if (ppIcmpv6Hdr != NULL)
    {
        *ppIcmpv6Hdr = icmpv6_header;
        success = success && (icmpv6_header != NULL);
    }
    if (ppTcpHdr != NULL)
    {
        *ppTcpHdr = tcp_header;
        success = success && (tcp_header != NULL);
    }
    if (ppUdpHdr != NULL)
    {
        *ppUdpHdr = udp_header;
        success = success && (udp_header != NULL);
    }
    if (ppData != NULL)
    {
        *ppData = data;
        success = success && (data != NULL);
    }
    if (pDataLen != NULL)
    {
        *pDataLen = data_len;
    }
    return success;
}

/*
 * Calculate IPv4/IPv6/ICMP/ICMPv6/TCP/UDP checksums.
 */
extern UINT WinDivertHelperCalcChecksums(PVOID pPacket, UINT packetLen,
    UINT64 flags)
{
    WINDIVERT_PSEUDOHDR pseudo_header;
    WINDIVERT_PSEUDOV6HDR pseudov6_header;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_ICMPHDR icmp_header;
    PWINDIVERT_ICMPV6HDR icmpv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;
    UINT payload_len, checksum_len;
    UINT count = 0;

    WinDivertHelperParsePacket(pPacket, packetLen, &ip_header, &ipv6_header,
        &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL,
        &payload_len);

    if (ip_header != NULL && !(flags & WINDIVERT_HELPER_NO_IP_CHECKSUM))
    {
        ip_header->Checksum = 0;
        ip_header->Checksum = WinDivertHelperCalcChecksum(NULL, 0,
            ip_header, ip_header->HdrLength*sizeof(UINT32));
        count++;
    }

    if (icmp_header != NULL)
    {
        if (flags & WINDIVERT_HELPER_NO_ICMP_CHECKSUM)
        {
            return count;
        }
        icmp_header->Checksum = 0;
        icmp_header->Checksum = WinDivertHelperCalcChecksum(NULL, 0,
            icmp_header, payload_len + sizeof(WINDIVERT_ICMPHDR));
        count++;
        return count;
    }

    if (icmpv6_header != NULL)
    {
        if (flags & WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM)
        {
            return count;
        }
        checksum_len = payload_len + sizeof(WINDIVERT_ICMPV6HDR);
        WinDivertInitPseudoHeaderV6(ipv6_header, &pseudov6_header,
            IPPROTO_ICMPV6, checksum_len);
        icmpv6_header->Checksum = 0;
        icmpv6_header->Checksum = WinDivertHelperCalcChecksum(&pseudov6_header,
            sizeof(pseudov6_header), icmpv6_header, checksum_len);
        count++;
        return count;
    }

    if (tcp_header != NULL)
    {
        if (flags & WINDIVERT_HELPER_NO_TCP_CHECKSUM)
        {
            return count;
        }
        checksum_len = payload_len + tcp_header->HdrLength*sizeof(UINT32);
        if (ip_header != NULL)
        {
            WinDivertInitPseudoHeader(ip_header, &pseudo_header, IPPROTO_TCP,
                checksum_len);
            tcp_header->Checksum = 0;
            tcp_header->Checksum = WinDivertHelperCalcChecksum(&pseudo_header,
                sizeof(pseudo_header), tcp_header, checksum_len);
        }
        else
        {
            WinDivertInitPseudoHeaderV6(ipv6_header, &pseudov6_header,
                IPPROTO_TCP, checksum_len);
            tcp_header->Checksum = 0;
            tcp_header->Checksum = WinDivertHelperCalcChecksum(&pseudov6_header,
                sizeof(pseudov6_header), tcp_header, checksum_len);
        }
        count++;
        return count;
    }

    if (udp_header != NULL)
    {
        if (flags & WINDIVERT_HELPER_NO_UDP_CHECKSUM)
        {
            return count;
        }
        checksum_len = payload_len + sizeof(WINDIVERT_UDPHDR);
        if (ip_header != NULL)
        {
            WinDivertInitPseudoHeader(ip_header, &pseudo_header, IPPROTO_UDP, 
                checksum_len);
            udp_header->Checksum = 0;
            udp_header->Checksum = WinDivertHelperCalcChecksum(&pseudo_header,
                sizeof(pseudo_header), udp_header, checksum_len);
            if (udp_header->Checksum == 0)
            {
                udp_header->Checksum = 0xFFFF;
            }
        }
        else
        {
            WinDivertInitPseudoHeaderV6(ipv6_header, &pseudov6_header,
                IPPROTO_UDP, checksum_len);
            udp_header->Checksum = 0;
            udp_header->Checksum = WinDivertHelperCalcChecksum(&pseudov6_header,
                sizeof(pseudov6_header), udp_header, checksum_len);
        }
        count++;
    }
    return count;
}

/*
 * Initialize the IP pseudo header.
 */
static void WinDivertInitPseudoHeader(PWINDIVERT_IPHDR ip_header,
    PWINDIVERT_PSEUDOHDR pseudo_header, UINT8 protocol, UINT len)
{
    pseudo_header->SrcAddr  = ip_header->SrcAddr;
    pseudo_header->DstAddr  = ip_header->DstAddr;
    pseudo_header->Zero     = 0;
    pseudo_header->Protocol = protocol;
    pseudo_header->Length   = htons((UINT16)len);
}

/*
 * Initialize the IPv6 pseudo header.
 */
static void WinDivertInitPseudoHeaderV6(PWINDIVERT_IPV6HDR ipv6_header,
    PWINDIVERT_PSEUDOV6HDR pseudov6_header, UINT8 protocol, UINT len)
{
    memcpy(pseudov6_header->SrcAddr, ipv6_header->SrcAddr,
        sizeof(pseudov6_header->SrcAddr));
    memcpy(pseudov6_header->DstAddr, ipv6_header->DstAddr,
        sizeof(pseudov6_header->DstAddr));
    pseudov6_header->Length  = htonl((UINT32)len);
    pseudov6_header->NextHdr = protocol;
    pseudov6_header->Zero    = 0;
}

/*
 * Generic checksum computation.
 */
static UINT16 WinDivertHelperCalcChecksum(PVOID pseudo_header,
    UINT16 pseudo_header_len, PVOID data, UINT len)
{
    register const UINT16 *data16 = (const UINT16 *)pseudo_header;
    register size_t len16 = pseudo_header_len >> 1;
    register UINT32 sum = 0;
    size_t i;

    // Pseudo header:
    for (i = 0; i < len16; i++)
    {
        sum += (UINT32)data16[i];
    }

    // Main data:
    data16 = (const UINT16 *)data;
    len16 = len >> 1;
    for (i = 0; i < len16; i++)
    {
        sum += (UINT32)data16[i];
    }

    if (len & 0x1)
    {
        const UINT8 *data8 = (const UINT8 *)data;
        sum += (UINT16)data8[len-1];
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    sum = ~sum;
    return (UINT16)sum;
}

/*
 * Parse an IPv4 address.
 */
extern BOOL WinDivertHelperParseIPv4Address(const char *str, UINT32 *addr_ptr)
{
    UINT32 addr = 0;
    UINT part, i;

    errno = 0;
    for (i = 0; i < 4; i++)
    {
        part = strtoul(str, (char **)&str, 10);
        if (errno != 0 || part > UINT8_MAX)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if (i != 3 && *str++ != '.')
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        addr |= part << (8*(3-i));
    }
    if (*str != '\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (addr_ptr != NULL)
    {
        *addr_ptr = addr;
    }
    return TRUE;
}

/*
 * Parse an IPv6 address.
 */
extern BOOL WinDivertHelperParseIPv6Address(const char *str, UINT32 *addr_ptr)
{
    UINT16 addr[8] = {0};
    UINT part;
    UINT i, j, k;
    BOOL end = FALSE;
    char part_str[5];

    if (*str == ':')
    {
        str++;
        if (*str != ':')
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        end = TRUE;
        str++;
    }

    for (i = 0, j = 7; i < 8; i++)
    {
        if (*str == ':')
        {
            if (end)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            end = TRUE;
            str++;
            if (*str == '\0')
            {
                break;
            }
        }
        for (k = 0; k < 4 && isxdigit(*str); k++)
        {
            part_str[k] = *str;
            str++;
        }
        if (k == 0)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        part_str[k] = '\0';
        if (*str != ':' && *str != '\0')
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        part = strtoul(part_str, NULL, 16);
        if (!end)
        {
            addr[i] = (UINT16)ntohs(part);
        }
        else
        {
            addr[j--] = (UINT16)ntohs(part);
        }
        if (*str == '\0')
        {
            if (end)
            {
                break;
            }
            if (i == 7)
            {
                break;
            }
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        str++;
    }

    if (*str != '\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (end)
    {
        j++;
        for (i = 7; j < i; j++, i--)
        {
            UINT16 tmp = addr[i];
            addr[i] = addr[j];
            addr[j] = tmp;
        }
    }
    if (addr_ptr != NULL)
    {
        memcpy(addr_ptr, addr, sizeof(addr));
    }

    return TRUE;
}

/***************************************************************************/
/* LEGACY                                                                  */
/***************************************************************************/

/*
 * Legacy functions.
 */
extern HANDLE DivertOpen(const char *filter, DIVERT_LAYER layer,
    INT16 priority, UINT64 flags)
{
    return WinDivertOpen(filter, layer, priority, flags);
}
extern BOOL DivertRecv(HANDLE handle, PVOID pPacket, UINT packetLen,
    PDIVERT_ADDRESS addr, UINT *readlen)
{
    return WinDivertRecv(handle, pPacket, packetLen, addr, readlen);
}
extern BOOL DivertSend(HANDLE handle, PVOID pPacket, UINT packetLen,
    PDIVERT_ADDRESS addr, UINT *writelen)
{
    return WinDivertSend(handle, pPacket, packetLen, addr, writelen);
}
extern BOOL DivertClose(HANDLE handle)
{
    return WinDivertClose(handle);
}
extern BOOL DivertSetParam(HANDLE handle, DIVERT_PARAM param, UINT64 value)
{
    return WinDivertSetParam(handle, param, value);
}
extern BOOL DivertGetParam(HANDLE handle, DIVERT_PARAM param, UINT64 *pValue)
{
    return WinDivertGetParam(handle, param, pValue);
}
extern BOOL DivertHelperParsePacket(PVOID pPacket, UINT packetLen,
    PDIVERT_IPHDR *ppIpHdr, PDIVERT_IPV6HDR *ppIpv6Hdr,
    PDIVERT_ICMPHDR *ppIcmpHdr, PDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
    PDIVERT_TCPHDR *ppTcpHdr, PDIVERT_UDPHDR *ppUdpHdr, PVOID *ppData,
    UINT *pDataLen)
{
    return WinDivertHelperParsePacket(pPacket, packetLen, ppIpHdr, ppIpv6Hdr,
        ppIcmpHdr, ppIcmpv6Hdr, ppTcpHdr, ppUdpHdr, ppData, pDataLen);
}
extern UINT DivertHelperCalcChecksums(PVOID pPacket, UINT packetLen,
    UINT64 flags)
{
    return WinDivertHelperCalcChecksums(pPacket, packetLen, flags);
}
extern BOOL DivertHelperParseIPv4Address(const char *str, UINT32 *addr_ptr)
{
    return WinDivertHelperParseIPv4Address(str, addr_ptr);
}
extern BOOL DivertHelperParseIPv6Address(const char *str, UINT32 *addr_ptr)
{
    return WinDivertHelperParseIPv6Address(str, addr_ptr);
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

