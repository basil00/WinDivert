/*
 * passthru.c
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
 * This program does nothing except divert packets and re-inject them.  This is
 * useful for performance testing.
 *
 * usage: passthru.exe [windivert-filter] [num-threads] [batch-size] [priority]
 *                     [layer]
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

static DWORD passthru(LPVOID arg);

/*
 * Options.
 */
static int threads           = 1;
static int batch             = WINDIVERT_BATCH_MAX;
static int priority          = 0;
static WINDIVERT_LAYER layer = WINDIVERT_LAYER_NETWORK;
static int size              = (0x10000 + 4096);

/*
 * Print usage and exit.
 */
static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [OPTIONS] filter-string\n\n", prog);
    fprintf(stderr, "OPTIONS:\n");
    fprintf(stderr, "\t--batch N\n");
    fprintf(stderr, "\t\tSet the batch size to N (default=%u)\n",
        WINDIVERT_BATCH_MAX);
    fprintf(stderr, "\t--layer LAYER\n");
    fprintf(stderr, "\t\tSet the filter layer to LAYER (default=network).\n");
    fprintf(stderr, "\t\tValid values are {ethernet,network,forward}.\n");
    fprintf(stderr, "\t--priority N\n");
    fprintf(stderr, "\t\tSet the filter priority to N (default=0)\n");
    fprintf(stderr, "\t--size N\n");
    fprintf(stderr, "\t\tSet the buffer size to N (default=%u)\n",
        (0x10000 + 4096));
    fprintf(stderr, "\t--threads N\n");
    fprintf(stderr, "\t\tSet the number of threads to be N (default=1)\n");
    exit(EXIT_FAILURE);
}

/*
 * Parse options.
 */
static const char *parse_options(int argc, char **argv)
{
    int i;
    size_t n;
    const char *filter = NULL, *opt, *arg;

    for (i = 1; i < argc; i++)
    {
        opt = argv[i];
        if (opt[0] != '-' || opt[1] != '-')
        {
            if (filter != NULL)
            {
                usage(argv[0]);
            }
            filter = opt;
            continue;
        }
        opt += 2;
        arg = strchr(opt, '=');
        if (arg == NULL)
        {
            i++;
            if (i >= argc)
            {
                usage(argv[0]);
            }
            arg = argv[i];
            n = strlen(opt);
        }
        else
        {
            n = arg - opt;
            arg++;
        }
        if (strncmp(opt, "threads", n) == 0)
        {
            threads = atoi(arg);
        }
        else if (strncmp(opt, "batch", n) == 0)
        {
            batch = atoi(arg);
        }
        else if (strncmp(opt, "priority", n) == 0)
        {
            priority = atoi(arg);
        }
        else if (strncmp(opt, "size", n) == 0)
        {
            size = atoi(arg);
        }
        else if (strncmp(opt, "layer", n) == 0)
        {
            if (strcmp(arg, "ethernet") == 0)
            {
                layer = WINDIVERT_LAYER_ETHERNET;
            }
            else if (strcmp(arg, "network") == 0)
            {
                layer = WINDIVERT_LAYER_NETWORK;
            }
            else if (strcmp(arg, "forward") == 0)
            {
                layer = WINDIVERT_LAYER_NETWORK_FORWARD;
            }
            else
            {
                usage(argv[0]);
            }
        }
        else
        {
            usage(argv[0]);
        }
    }
    return (filter == NULL? "true": filter);
}

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    const char *filter;
    int i;
    HANDLE handle, thread;

    filter = parse_options(argc, argv);

    if (threads < 1 || threads > 64)
    {
        fprintf(stderr, "error: number of threads must be within "
            "the range 1..64, found %d\n", threads);
        exit(EXIT_FAILURE);
    }
    if (batch < 1 || batch > WINDIVERT_BATCH_MAX)
    {
        fprintf(stderr, "error: batch size must be within the range 1..%u, "
            "found %d\n", WINDIVERT_BATCH_MAX, batch);
        exit(EXIT_FAILURE);
    }
    if (priority < WINDIVERT_PRIORITY_LOWEST ||
        priority > WINDIVERT_PRIORITY_HIGHEST)
    {
        fprintf(stderr, "error: priority must be within the range %d..%d, "
            "found %d\n", WINDIVERT_PRIORITY_LOWEST,
            WINDIVERT_PRIORITY_HIGHEST, priority);
        exit(EXIT_FAILURE);
    }
    if (size < 1 || size >= WINDIVERT_BATCH_MAX * WINDIVERT_MTU_MAX)
    {
        fprintf(stderr, "error: buffer size must be within the range 1..%d, "
            "found %d\n", WINDIVERT_BATCH_MAX * WINDIVERT_MTU_MAX,
            size);
        exit(EXIT_FAILURE);
    }

    // Divert traffic matching the filter:
    handle = WinDivertOpen(filter, layer, (INT16)priority, 0);
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
    for (i = 1; i < threads; i++)
    {
        thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)passthru,
            (LPVOID)handle, 0, NULL);
        if (thread == NULL)
        {
            fprintf(stderr, "error: failed to start passthru thread (%d)\n",
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
    UINT8 *packet;
    UINT packet_len, addr_len;
    WINDIVERT_ADDRESS *addr;
    HANDLE handle = (HANDLE)arg;

    packet = (UINT8 *)malloc(size);
    addr = (WINDIVERT_ADDRESS *)malloc(batch * sizeof(WINDIVERT_ADDRESS));
    if (packet == NULL || addr == NULL)
    {
        fprintf(stderr, "error: failed to allocate buffer (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Main loop:
    while (TRUE)
    {
        // Read a matching packet.
        addr_len = batch * sizeof(WINDIVERT_ADDRESS);
        if (!WinDivertRecvEx(handle, packet, size, &packet_len, 0,
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

