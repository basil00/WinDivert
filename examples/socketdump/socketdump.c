/*
 * socketdump.c
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
 * usage: socketdump.exe [filter]
 */

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define INET6_ADDRSTRLEN    45

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    HANDLE handle, process, console;
    INT16 priority = 1121;          // Arbitrary.
    const char *filter = "true", *err_str;
    char path[MAX_PATH+1];
    char local_str[INET6_ADDRSTRLEN+1], remote_str[INET6_ADDRSTRLEN+1];
    char *filename;
    DWORD path_len;
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    switch (argc)
    {
        case 1:
            break;
        case 2:
            filter = argv[1];
            break;
        default:
            fprintf(stderr, "usage: %s [filter]\n");
            exit(EXIT_FAILURE);
    }

    // Open WinDivert SOCKET handle:
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_SOCKET, priority, 
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER &&
            !WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_SOCKET,
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
        if (!WinDivertRecv(handle, NULL, 0, &addr, &packet_len))
        {
            fprintf(stderr, "failed to read packet (%d)\n", GetLastError());
            continue;
        }

        SetConsoleTextAttribute(console, FOREGROUND_GREEN);
        switch (addr.Event)
        {
            case WINDIVERT_EVENT_SOCKET_BIND:
                printf("BIND");
                break;
            case WINDIVERT_EVENT_SOCKET_LISTEN:
                printf("LISTEN");
                break;
            case WINDIVERT_EVENT_SOCKET_CONNECT:
                printf("CONNECT");
                break;
            case WINDIVERT_EVENT_SOCKET_ACCEPT:
                printf("ACCEPT");
                break;
            default:
                printf("???");
                break;
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);

        printf(" pid=");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        printf("%u", addr.Socket.ProcessId);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);

        printf(" program=");
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
            addr.Socket.ProcessId);
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
            printf("%s", filename);
        }
        else if (addr.Socket.ProcessId == 4)
        {
            printf("Windows");
        }
        else
        {
            printf("???");
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);

        printf(" protocol=");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        switch (addr.Socket.Protocol)
        {
            case IPPROTO_TCP:
                printf("TCP");
                break;
            case IPPROTO_UDP:
                printf("UDP");
                break;
            case IPPROTO_ICMP:
                printf("ICMP");
                break;
            case IPPROTO_ICMPV6:
                printf("ICMPV6");
                break;
            default:
                printf("%u", addr.Socket.Protocol);
                break;
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);

        WinDivertHelperFormatIPv6Address(addr.Socket.LocalAddr, local_str,
            sizeof(local_str));
        if (addr.Socket.LocalPort != 0 || strcmp(local_str, "::") != 0)
        {
            printf(" local=");
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
            printf("[%s]:%u", local_str, addr.Socket.LocalPort);
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
                FOREGROUND_BLUE);
        }

        WinDivertHelperFormatIPv6Address(addr.Socket.RemoteAddr, remote_str,
            sizeof(remote_str));
        if (addr.Socket.RemotePort != 0 || strcmp(remote_str, "::") != 0)
        {
            printf(" remote=");
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
            printf("[%s]:%u", remote_str, addr.Socket.RemotePort);
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
                FOREGROUND_BLUE);
        }

        putchar('\n');
    }

    return 0;
}

