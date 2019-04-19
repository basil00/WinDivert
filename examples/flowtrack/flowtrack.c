/*
 * flowtrack.c
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
 * usage: flowtrack.exe [filter]
 */

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define MAX_FLOWS           256
#define INET6_ADDRSTRLEN    45

/*
 * Flow tracking.
 */
typedef struct FLOW
{
    WINDIVERT_ADDRESS addr;
    struct FLOW *next;
} FLOW, *PFLOW;

static HANDLE lock;
static PFLOW flows = NULL;

/*
 * Draw flows to console in a delayed loop.
 *
 * This function does minimal error checking.
 */
static DWORD draw(LPVOID arg)
{
    const COORD top_left  = {0, 0};
    HANDLE process, console = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO screen;
    char path[MAX_PATH+1];
    char addr_str[INET6_ADDRSTRLEN+1];
    char *filename;
    const char header[] = "PID        PROGRAM              PROT   FLOW";
    DWORD rows, columns, written, fill_len, path_len, i;
    PFLOW flow;
    WINDIVERT_ADDRESS addrs[MAX_FLOWS], *addr;
    UINT num_addrs;

    while (TRUE)
    {
        GetConsoleScreenBufferInfo(console, &screen);
        SetConsoleCursorPosition(console, top_left); 

        rows = screen.srWindow.Bottom - screen.srWindow.Top + 1;
        columns = screen.srWindow.Right - screen.srWindow.Left + 1;

        // Copy a snapshot of the current flows:
        WaitForSingleObject(lock, INFINITE);
        flow = flows;
        num_addrs = 0;
        for (i = 0; flow != NULL && i < rows && i < MAX_FLOWS; i++)
        {
            memcpy(&addrs[i], &flow->addr, sizeof(addrs[i]));
            num_addrs++;
            flow = flow->next;
        }
        ReleaseMutex(lock);

        // Print the flows:
        SetConsoleTextAttribute(console, BACKGROUND_RED | BACKGROUND_GREEN |
            BACKGROUND_BLUE);
        WriteConsole(console, header, sizeof(header)-1, &written, NULL);
        fill_len = columns - (sizeof(header)-1);
        if (fill_len > 0)
        {
            COORD pos = {sizeof(header)-1, 0};
            FillConsoleOutputCharacterA(console, ' ', fill_len, pos,
                &written);
            FillConsoleOutputAttribute(console,
                BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE,
                fill_len, pos, &written);
        }
        putchar('\n');
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        for (i = 0; i < num_addrs && i < rows-1; i++)
        {
            COORD pos = {0, i+1};
            addr = &addrs[i];
            FillConsoleOutputCharacterA(console, ' ', columns, pos, &written);
            FillConsoleOutputAttribute(console,
                FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE,
                columns, pos, &written);
            SetConsoleCursorPosition(console, pos);
            if (i == rows-2 && (i+1) < num_addrs)
            {
                fputs("...", stdout);
                fflush(stdout);
                continue;
            }

            printf("%-10d ", addr->Flow.ProcessId);

            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                addr->Flow.ProcessId);
            path_len = 0;
            if (process != NULL)
            {
                path_len = GetProcessImageFileName(process, path, sizeof(path));
                CloseHandle(process);
            }
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
            if (path_len != 0)
            {
                filename = PathFindFileName(path);
                printf("%-20.20s ", filename);
            }
            else if (addr->Flow.ProcessId == 4)
            {
                fputs("Windows              ", stdout);
            }
            else
            {
                fputs("???                  ", stdout);
            }
            SetConsoleTextAttribute(console,
                FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            switch (addr->Flow.Protocol)
            {
                case IPPROTO_TCP:
                    SetConsoleTextAttribute(console, FOREGROUND_GREEN);
                    printf("TCP    ");
                    break;
                case IPPROTO_UDP:
                    SetConsoleTextAttribute(console,
                        FOREGROUND_RED | FOREGROUND_GREEN);
                    printf("UDP    ");
                    break;
                case IPPROTO_ICMP:
                    SetConsoleTextAttribute(console, FOREGROUND_RED);
                    printf("ICMP   ");
                    break;
                case IPPROTO_ICMPV6:
                    SetConsoleTextAttribute(console, FOREGROUND_RED);
                    printf("ICMPV6 ");
                    break;
                default:
                    printf("%-6u ", addr->Flow.Protocol);
                    break;
            }
            SetConsoleTextAttribute(console,
                FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            WinDivertHelperFormatIPv6Address(addr->Flow.LocalAddr, addr_str,
                sizeof(addr_str));
            printf("%s:%u %s ", addr_str, addr->Flow.LocalPort,
                (addr->Outbound? "---->": "<----"));
            WinDivertHelperFormatIPv6Address(addr->Flow.RemoteAddr, addr_str,
                sizeof(addr_str));
            printf("%s:%u", addr_str, addr->Flow.RemotePort);
            fflush(stdout);
        }
        for (; i < rows-1; i++)
        {
            COORD pos = {0, i+1};
            FillConsoleOutputCharacterA(console, ' ', columns, pos, &written);
            FillConsoleOutputAttribute(console,
                FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE,
                columns, pos, &written);
        }

        Sleep(1000);
    }
}

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    HANDLE handle, thread;
    INT16 priority = 776;       // Arbitrary.
    const char *filter = "true", *err_str;
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PFLOW flow, prev;

    switch (argc)
    {
        case 1:
            break;
        case 2:
            filter = argv[1];
            break;
        default:
            fprintf(stderr, "usage: %s [filter]\n", argv[0]);
            exit(EXIT_FAILURE);
    }

    // Open WinDivert FLOW handle:
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_FLOW, priority, 
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (handle == INVALID_HANDLE_VALUE)
    {
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

    // Spawn the draw() thread.
    lock = CreateMutex(NULL, FALSE, NULL);
    thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)draw, NULL, 0,
        NULL);
    if (thread == NULL)
    {
        fprintf(stderr, "error: failed to create thread (%d)\n",
            GetLastError());
        return EXIT_FAILURE;
    }
    CloseHandle(thread);

    // Main loop:
    while (TRUE)
    {
        if (!WinDivertRecv(handle, NULL, 0, NULL, &addr))
        {
            fprintf(stderr, "failed to read packet (%d)\n", GetLastError());
            continue;
        }

        switch (addr.Event)
        {
            case WINDIVERT_EVENT_FLOW_ESTABLISHED:

                // Flow established:
                flow = (PFLOW)malloc(sizeof(FLOW));
                if (flow == NULL)
                {
                    fprintf(stderr, "error: failed to allocate memory\n");
                    exit(EXIT_FAILURE);
                }
                memcpy(&flow->addr, &addr, sizeof(flow->addr));
                WaitForSingleObject(lock, INFINITE);
                flow->next = flows;
                flows = flow;
                ReleaseMutex(lock);
                break;

            case WINDIVERT_EVENT_FLOW_DELETED:

                // Flow deleted:
                prev = NULL;
                WaitForSingleObject(lock, INFINITE);
                flow = flows;
                while (flow != NULL)
                {
                    if (memcmp(&addr.Flow, &flow->addr.Flow,
                            sizeof(addr.Flow)) == 0)
                    {
                        if (prev != NULL)
                        {
                            prev->next = flow->next;
                        }
                        else
                        {
                            flows = flow->next;
                        }
                        break;
                    }
                    prev = flow;
                    flow = flow->next;
                }
                ReleaseMutex(lock);
                free(flow);
        }
    }

    return 0;
}

