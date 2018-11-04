/*
 * passthru.c
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
 * This program does nothing except divert packets and re-inject them.  This is
 * useful for performance testing.
 *
 * usage: netdump.exe windivert-filter num-threads
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define MAXBUF      400000
#define MAXBATCH    0xFF

static int batch = 1;

static DWORD passthru(LPVOID arg);

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    int num_threads, priority = 0, i;
    HANDLE handle, thread;

    if (argc < 3 || argc > 5)
    {
        fprintf(stderr, "usage: %s filter num-threads [batch] [priority]\n",
            argv[0]);
        exit(EXIT_FAILURE);
    }
    num_threads = atoi(argv[2]);
    if (num_threads < 1 || num_threads > 64)
    {
        fprintf(stderr, "error: invalid number of threads\n");
        exit(EXIT_FAILURE);
    }
    if (argc >= 4)
    {
        batch = atoi(argv[3]);
    }
    if (batch <= 0 || batch > MAXBATCH)
    {
        fprintf(stderr, "error: invalid batch size\n");
        exit(EXIT_FAILURE);
    }
    if (argc >= 5)
    {
        priority = atoi(argv[4]);
    }

    // Divert traffic matching the filter:
    handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, (INT16)priority,
        0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER)
        {
            fprintf(stderr, "error: filter syntax error\n");
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Start the threads
    for (i = 1; i < num_threads; i++)
    {
        thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)passthru,
            (LPVOID)handle, 0, NULL);
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
    UINT8 packet[MAXBUF];
    UINT packet_len, addr_len;
    WINDIVERT_ADDRESS addr[MAXBATCH];
    HANDLE handle = (HANDLE)arg;

    // Main loop:
    while (TRUE)
    {
        // Read a matching packet.
        addr_len = batch * sizeof(WINDIVERT_ADDRESS);
        if (!WinDivertRecvEx(handle, packet, sizeof(packet), &packet_len, 0,
                addr, &addr_len, NULL))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            continue;
        }

        // Re-inject the matching packet.
        if (!WinDivertSendEx(handle, packet, packet_len, NULL, 0, addr,
                addr_len, NULL))
        {
            fprintf(stderr, "warning: failed to reinject packet (%d)\n",
                GetLastError());
        }
    }
}

