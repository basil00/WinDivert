/*
 * windivertctl.c
 * (C) 2018, all rights reserved,
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
 * Process info.
 */
typedef struct INFO
{
    UINT32 process_id;
    UINT32 ref_count;
    HANDLE process;
    struct INFO *next;
} INFO, *PINFO;

static INFO *open = NULL;       // All open handles

/*
 * Modes.
 */
typedef enum
{
    LIST,
    WATCH,
    KILLALL
} MODE;

/*
 * Add a new process.
 */
static HANDLE add_process(UINT32 process_id)
{
    PINFO info = open;
    HANDLE process;

    while (info != NULL)
    {
        if (info->process_id == process_id)
        {
            info->ref_count++;
            return info->process;
        }
        info = info->next;
    }

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
        FALSE, process_id);
    info = (INFO *)malloc(sizeof(INFO));
    if (info == NULL)
    {
        fprintf(stderr, "error: failed to allocate memory (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }
    info->process_id = process_id;
    info->process    = process;
    info->ref_count  = 1;
    info->next       = open;
    open = info;
    return process;
}

/*
 * Lookup a process.
 */
static HANDLE lookup_process(UINT32 process_id)
{
    PINFO info = open;

    while (info != NULL)
    {
        if (info->process_id == process_id)
        {
            return info->process;
        }
        info = info->next;
    }
}

/*
 * Remove an old process.
 */
static void remove_process(UINT32 process_id)
{
    PINFO info = open, prev = NULL;

    while (info != NULL)
    {
        if (info->process_id == process_id)
        {
            info->ref_count--;
            if (info->ref_count > 0)
            {
                return;
            }
            break;
        }
        prev = info;
        info = info->next;
    }

    if (info->process != NULL)
    {
        CloseHandle(info->process);
    }
    if (prev != NULL)
    {
        prev->next = info->next;
    }
    else
    {
        open = info->next;
    }
    free(info);
}

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    HANDLE handle, process, console;
    INT16 priority = -333;      // Arbitrary.
    UINT packet_len;
    static UINT8 packet[MAX_PACKET];
    static char path[MAX_PATH+1];
    static char filter_str[MAX_FILTER_LEN];
    PVOID object;
    DWORD path_len;
    BOOL or;
    WINDIVERT_ADDRESS addr;
    ULONGLONG freq, start_count;
    LARGE_INTEGER li;
    MODE mode;
    const char *filter = "true";
    const char *err_str = NULL;

    if (argc != 2 && argc != 3)
    {
usage:
        fprintf(stderr, "usage: %s (list|watch|killall) [filter]\n", argv[0]);
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
    else if (strcmp(argv[1], "killall") == 0)
    {
        mode = KILLALL;
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
            !WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_FLOW,
                NULL, 0, &err_str, NULL))
        {
            fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        return EXIT_FAILURE;
    }

    // Main loop:
    console = GetStdHandle(STD_OUTPUT_HANDLE);
    while (TRUE)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
        {
            fprintf(stderr, "failed to event (%d)\n", GetLastError());
            continue;
        }

        switch (addr.Event)
        {
            case WINDIVERT_EVENT_REFLECT_ESTABLISHED:
            case WINDIVERT_EVENT_REFLECT_OPEN:
                // Open handle:
                process = add_process(addr.Reflect.ProcessId);
                if (mode == KILLALL)
                {
                    SetConsoleTextAttribute(console, FOREGROUND_RED);
                    fputs("KILL", stdout);
                    TerminateProcess(process, 0);
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
                process = lookup_process(addr.Reflect.ProcessId);
                SetConsoleTextAttribute(console, FOREGROUND_RED);
                fputs("CLOSE", stdout);
                break;
            
            default:
                fputs("???", stdout);
                break;
        }
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
            if ((addr.Reflect.Flags & WINDIVERT_FLAG_DEBUG) != 0)
            {
                printf("%sDEBUG", (or? "|": ""));
                or = TRUE;
            }
            if ((addr.Reflect.Flags & WINDIVERT_FLAG_PARTIAL) != 0)
            {
                printf("%sPARTIAL", (or? "|": ""));
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
        WinDivertHelperParsePacket(packet, packet_len, NULL, NULL, NULL, NULL,
            NULL, NULL, &object, NULL);
        if (WinDivertHelperFormatFilter((char *)object, addr.Reflect.Layer,
            filter_str, sizeof(filter_str)))
        {
            printf("\"%s\"", filter_str);
        }
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        putchar('\n');

        if (addr.Event == WINDIVERT_EVENT_REFLECT_CLOSE)
        {
            remove_process(addr.Reflect.ProcessId);
        }
        if (mode != WATCH && addr.Final)
        {
            break;
        }
    }

    return 0;
}

