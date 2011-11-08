/*
 * passthru.c
 * (C) 2011, all rights reserved,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * DESCRIPTION:
 * This program does nothing except divert packets and re-inject them.  This is
 * useful for performance testing.
 *
 * usage: netdump.exe divert-filter num-threads
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "divert.h"

#define MAXBUF  2048

static DWORD passthru(LPVOID arg);

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    int num_threads, i;
    HANDLE handle, thread;

    if (argc != 3)
    {
        fprintf(stderr, "usage: %s filter num-threads\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    num_threads = atoi(argv[2]);
    if (num_threads < 1 || num_threads > 64)
    {
        fprintf(stderr, "error: invalid number of threads\n");
        exit(EXIT_FAILURE);
    }

    // Divert traffic matching the filter:
    handle = DivertOpen(argv[1]);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER)
        {
            fprintf(stderr, "error: filter syntax error\n");
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open Divert device (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Start the threads
    for (i = 1; i < num_threads; i++)
    {
        thread = CreateThread(NULL, 1, passthru, (LPVOID)handle, 0, NULL);
        if (thread == NULL)
        {
            fprintf(stderr, "error: failed to start passthru thread (%u)\n",
                GetLastError());
            exit(EXIT_FAILURE);
        }
    }

    // Main thread:
    passthru((LPVOID)handle);

    return 0;
}

// Passthru thread.
static DWORD passthru(LPVOID arg)
{
    char packet[MAXBUF];
    UINT packet_len;
    DIVERT_ADDRESS addr;
    HANDLE handle = (HANDLE)arg;

    // Main loop:
    while (TRUE)
    {
        // Read a matching packet.
        if (!DivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            continue;
        }
       
        // Re-inject the matching packet.
        if (!DivertSend(handle, packet, packet_len, &addr, NULL))
        {
            fprintf(stderr, "warning: failed to reinject packet (%d)\n",
                GetLastError());
        }
    }
}

