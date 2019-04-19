/*
 * windivertctl.c
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

/*
 * DESCRIPTION:
 *
 * usage: windivertctl.exe list
 */

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define MAX_PACKET          0xFFFF
#define MAX_FILTER_LEN      30000

/*
 * Modes.
 */
typedef enum
{
    LIST,
    WATCH,
    KILL,
    UNINSTALL
} MODE;

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    HANDLE handle, process, console, mutex;
    INT16 priority = -333;      // Arbitrary.
    UINT packet_len;
    static UINT8 packet[MAX_PACKET];
    static char path[MAX_PATH+1];
    static char filter_str[MAX_FILTER_LEN];
    DWORD path_len;
    BOOL or;
    WINDIVERT_ADDRESS addr;
    ULONGLONG freq, start_count;
    LARGE_INTEGER li;
    MODE mode;
    SC_HANDLE manager = NULL, service = NULL;
    SERVICE_STATUS status;
    const char *filter = "true";
    const char *err_str = NULL;

    if (argc != 2 && argc != 3)
    {
usage:
        fprintf(stderr, "usage: %s (list|watch|kill) [filter]\n", argv[0]);
        fprintf(stderr, "       %s uninstall\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if (strcmp(argv[1], "list") == 0)
    {
        mode = LIST;
    }
    else if (strcmp(argv[1], "watch") == 0)
    {
        mode = WATCH;
    }
    else if (strcmp(argv[1], "kill") == 0)
    {
        mode = KILL;
    }
    else if (strcmp(argv[1], "uninstall") == 0)
    {
        if (argc != 2)
        {
            goto usage;
        }
        mode = UNINSTALL;
    }
    else
    {
        goto usage;
    }
    if (argc == 3)
    {
        filter = argv[2];
    }

    // Time management
    QueryPerformanceFrequency(&li);
    freq = li.QuadPart;
    QueryPerformanceCounter(&li);
    start_count = li.QuadPart;

    // Open WinDivert REFLECT handle:
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_REFLECT, priority, 
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY |
            (mode == WATCH? 0: WINDIVERT_FLAG_NO_INSTALL));
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (mode != WATCH && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            // WinDivert driver is not running, so no open handles.
            return 0;
        }
        if (GetLastError() == ERROR_INVALID_PARAMETER &&
            !WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_REFLECT,
                NULL, 0, &err_str, NULL))
        {
            fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        return EXIT_FAILURE;
    }
    if (mode != WATCH && !WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH))
    {
        fprintf(stderr, "error: failed to shutdown WinDivert handle (%d)\n",
            GetLastError());
        return EXIT_FAILURE;
    }
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH,
            WINDIVERT_PARAM_QUEUE_LENGTH_MAX) ||
        !WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE,
            WINDIVERT_PARAM_QUEUE_SIZE_MAX) ||
        !WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME,
            WINDIVERT_PARAM_QUEUE_TIME_MAX))
    {
        fprintf(stderr, "error: failed to set WinDivert handle params (%d)\n",
            GetLastError());
        return EXIT_FAILURE;
    }

    // Main loop:
    console = GetStdHandle(STD_OUTPUT_HANDLE);
    while (TRUE)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
        {
            if (mode != WATCH && GetLastError() == ERROR_NO_DATA)
            {
                break;
            }
            fprintf(stderr, "failed to receive event (%d)\n", GetLastError());
            continue;
        }

        switch (addr.Event)
        {
            case WINDIVERT_EVENT_REFLECT_OPEN:
                // Open handle:
                if (mode == KILL || mode == UNINSTALL)
                {
                    SetConsoleTextAttribute(console, FOREGROUND_RED);
                    fputs("KILL", stdout);
                }
                else
                {
                    SetConsoleTextAttribute(console, FOREGROUND_GREEN);
                    fputs("OPEN", stdout);
                }
                break;

            case WINDIVERT_EVENT_REFLECT_CLOSE:
                // Close handle:
                if (mode != WATCH)
                {
                    continue;
                }
                SetConsoleTextAttribute(console, FOREGROUND_RED);
                fputs("CLOSE", stdout);
                break;
            
            default:
                fputs("???", stdout);
                break;
        }
        process = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            FALSE, addr.Reflect.ProcessId);
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        fputs(" time=", stdout);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        printf("%.3fs", (double)(addr.Reflect.Timestamp - (INT64)start_count) /
            (double)freq);
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        fputs(" pid=", stdout);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        printf("%u", addr.Reflect.ProcessId);
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        fputs(" exe=", stdout);
        path_len = 0;
        if (process != NULL)
        {
            path_len = GetProcessImageFileName(process, path, sizeof(path));
            if (mode == KILL || mode == UNINSTALL)
            {
                TerminateProcess(process, 0);
            }
            CloseHandle(process);
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        printf("%s", (path_len != 0? path: "???"));
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        fputs(" layer=", stdout);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        switch (addr.Reflect.Layer)
        {
            case WINDIVERT_LAYER_NETWORK:
                fputs("NETWORK", stdout);
                break;
            case WINDIVERT_LAYER_NETWORK_FORWARD:
                fputs("NETWORK_FORWARD", stdout);
                break;
            case WINDIVERT_LAYER_FLOW:
                fputs("FLOW", stdout);
                break;
            case WINDIVERT_LAYER_SOCKET:
                fputs("SOCKET", stdout);
                break;
            case WINDIVERT_LAYER_REFLECT:
                fputs("REFLECT", stdout);
                break;
            default:
                fputs("???", stdout);
                break;
        }
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        fputs(" flags=", stdout);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        if (addr.Reflect.Flags == 0)
        {
            fputs("0", stdout);
        }
        else
        {
            or = FALSE;
            if ((addr.Reflect.Flags & WINDIVERT_FLAG_SNIFF) != 0)
            {
                fputs("SNIFF", stdout);
                or = TRUE;
            }
            if ((addr.Reflect.Flags & WINDIVERT_FLAG_DROP) != 0)
            {
                printf("%sDROP", (or? "|": ""));
                or = TRUE;
            }
            if ((addr.Reflect.Flags & WINDIVERT_FLAG_RECV_ONLY) != 0)
            {
                printf("%sRECV_ONLY", (or? "|": ""));
                or = TRUE;
            }
            if ((addr.Reflect.Flags & WINDIVERT_FLAG_SEND_ONLY) != 0)
            {
                printf("%sSEND_ONLY", (or? "|": ""));
                or = TRUE;
            }
            if ((addr.Reflect.Flags & WINDIVERT_FLAG_NO_INSTALL) != 0)
            {
                printf("%sNO_INSTALL", (or? "|": ""));
                or = TRUE;
            }
        }
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        fputs(" priority=", stdout);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        printf("%d", addr.Reflect.Priority);
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        fputs(" filter=", stdout);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        if (WinDivertHelperFormatFilter((char *)packet, addr.Reflect.Layer,
            filter_str, sizeof(filter_str)))
        {
            printf("\"%s\"", filter_str);
        }
        else
        {
            printf("\"%s\"", (char *)packet);
        }
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        putchar('\n');
    }

    if (!WinDivertClose(handle))
    {
        fprintf(stderr, "error: failed to close WinDivert handle (%d)\n",
            GetLastError());
        return EXIT_FAILURE;
    }

    if (mode == UNINSTALL)
    {
        // Stop & delete the WinDivert service:
        mutex = CreateMutex(NULL, FALSE, "WinDivertDriverInstallMutex");
        if (mutex == NULL)
        {
            fprintf(stderr, "error: failed to create WinDivert driver "
                "install mutex (%d)\n", GetLastError());
            return EXIT_FAILURE;
        }
        switch (WaitForSingleObject(mutex, INFINITE))
        {
            case WAIT_OBJECT_0: case WAIT_ABANDONED:
                break;
            default:
                fprintf(stderr, "error: failed to acquire WinDivert driver "
                    "install mutex (%d)\n", GetLastError());
                return EXIT_FAILURE;
        }
        manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (manager == NULL)
        {
            fprintf(stderr, "error: failed to open service manager (%d)\n",
                GetLastError());
            return EXIT_FAILURE;
        }
        service = OpenService(manager, "WinDivert", SERVICE_ALL_ACCESS);
        if (service == NULL)
        {
            fprintf(stderr, "error: failed to open WinDivert service (%d)\n",
                GetLastError());
            return EXIT_FAILURE;
        }
        if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
        {
            fprintf(stderr, "error: failed to stop WinDivert service (%d)\n",
                GetLastError());
            return EXIT_FAILURE;
        }
        if (status.dwCurrentState != SERVICE_STOPPED)
        {
            fprintf(stderr, "error: failed to stop WinDivert service");
            return EXIT_FAILURE;
        }
        CloseServiceHandle(service);
        CloseServiceHandle(manager);

        SetConsoleTextAttribute(console, FOREGROUND_GREEN);
        fputs("UNINSTALL", stdout);
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        puts(" WinDivert");

        ReleaseMutex(mutex);
        CloseHandle(mutex);
    }

    return 0;
}

