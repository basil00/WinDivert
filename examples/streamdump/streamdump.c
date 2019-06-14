/*
 * streamdump.c
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
 * This program demonstrates how to handle streams using WinDivert.
 *
 * The program works by "reflecting" outbound TCP connections into inbound
 * TCP connections that are handled by a simple proxy server.
 *
 * usage: streamdump.exe port
 */

#include <winsock2.h>
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define MAXBUF          WINDIVERT_MTU_MAX
#define PROXY_PORT      34010
#define ALT_PORT        43010
#define MAX_LINE        65

/*
 * Proxy server configuration.
 */
typedef struct
{
    UINT16 proxy_port;
    UINT16 alt_port;
} PROXY_CONFIG, *PPROXY_CONFIG;

typedef struct
{
    SOCKET s;
    UINT16 alt_port;
    struct in_addr dest;
} PROXY_CONNECTION_CONFIG, *PPROXY_CONNECTION_CONFIG;

typedef struct
{
    BOOL inbound;
    SOCKET s;
    SOCKET t;
} PROXY_TRANSFER_CONFIG, *PPROXY_TRANSFER_CONFIG;

/*
 * Lock to sync output.
 */
static HANDLE lock;

/*
 * Prototypes.
 */
static DWORD proxy(LPVOID arg);
static DWORD proxy_connection_handler(LPVOID arg);
static DWORD proxy_transfer_handler(LPVOID arg);

/*
 * Error handling.
 */
static void message(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    WaitForSingleObject(lock, INFINITE);
    vfprintf(stderr, msg, args);
    putc('\n', stderr);
    ReleaseMutex(lock);
    va_end(args);
}
#define error(msg, ...)                         \
    do {                                        \
        message("error: " msg, ## __VA_ARGS__); \
        exit(EXIT_FAILURE);                     \
    } while (FALSE)
#define warning(msg, ...)                       \
    message("warning: " msg, ## __VA_ARGS__)

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    HANDLE handle, thread;
    UINT16 port, proxy_port, alt_port;
    int r;
    char filter[256];
    INT16 priority = 123;       // Arbitrary.
    PPROXY_CONFIG config;
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_TCPHDR tcp_header;
    DWORD len;

    // Init.
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s dest-port\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    port = (UINT16)atoi(argv[1]);
    if (port < 0 || port > 0xFFFF)
    {
        fprintf(stderr, "error: invalid port number (%d)\n", port);
        exit(EXIT_FAILURE);
    }
    proxy_port = (port == PROXY_PORT? PROXY_PORT+1: PROXY_PORT);
    alt_port = (port == ALT_PORT? ALT_PORT+1: ALT_PORT);
    lock = CreateMutex(NULL, FALSE, NULL);
    if (lock == NULL)
    {
        fprintf(stderr, "error: failed to create mutex (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Divert all traffic to/from `port', `proxy_port' and `alt_port'.
    r = snprintf(filter, sizeof(filter),
        "tcp and "
        "(tcp.DstPort == %d or tcp.DstPort == %d or tcp.DstPort == %d or "
         "tcp.SrcPort == %d or tcp.SrcPort == %d or tcp.SrcPort == %d)",
        port, proxy_port, alt_port, port, proxy_port, alt_port);
    if (r < 0 || r >= sizeof(filter))
    {
        error("failed to create filter string");
    }
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        error("failed to open the WinDivert device (%d)", GetLastError());
    }

    // Spawn proxy thread,
    config = (PPROXY_CONFIG)malloc(sizeof(PROXY_CONFIG));
    if (config == NULL)
    {
        error("failed to allocate memory");
    }
    config->proxy_port = proxy_port;
    config->alt_port = alt_port;
    thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)proxy,
        (LPVOID)config, 0, NULL);
    if (thread == NULL)
    {
        error("failed to create thread (%d)", GetLastError());
    }
    CloseHandle(thread);

    // Main loop:
    while (TRUE)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
        {
            warning("failed to read packet (%d)", GetLastError());
            continue;
        }

        WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL,
            NULL, NULL, &tcp_header, NULL, NULL, NULL, NULL, NULL);
        if (ip_header == NULL || tcp_header == NULL)
        {
            warning("failed to parse packet (%d)", GetLastError());
            continue;
        }

        if (addr.Outbound)
        {
            if (tcp_header->DstPort == htons(port))
            {
                // Reflect: PORT ---> PROXY
                UINT32 dst_addr = ip_header->DstAddr;
                tcp_header->DstPort = htons(proxy_port);
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = dst_addr;
                addr.Outbound = FALSE;
            }
            else if (tcp_header->SrcPort == htons(proxy_port))
            {
                // Reflect: PROXY ---> PORT
                UINT32 dst_addr = ip_header->DstAddr;
                tcp_header->SrcPort = htons(port);
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = dst_addr;
                addr.Outbound = FALSE;
            }
            else if (tcp_header->DstPort == htons(alt_port))
            {
                // Redirect: ALT ---> PORT
                tcp_header->DstPort = htons(port);
            }
        }
        else
        {
            if (tcp_header->SrcPort == htons(port))
            {
                // Redirect: PORT ---> ALT
                tcp_header->SrcPort = htons(alt_port);
            }
        }

        WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
        if (!WinDivertSend(handle, packet, packet_len, NULL, &addr))
        {
            warning("failed to send packet (%d)", GetLastError());
            continue;
        }
    }

    return 0;
}

/*
 * Proxy server thread.
 */
static DWORD proxy(LPVOID arg)
{
    PPROXY_CONFIG config = (PPROXY_CONFIG)arg;
    UINT16 proxy_port = config->proxy_port;
    UINT16 alt_port = config->alt_port;
    int on = 1;
    WSADATA wsa_data;
    WORD wsa_version = MAKEWORD(2, 2);
    struct sockaddr_in addr;
    SOCKET s;
    HANDLE thread;
    
    free(config);

    if (WSAStartup(wsa_version, &wsa_data) != 0)
    {
        error("failed to start WSA (%d)", GetLastError());
    }
    
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET)
    {
        error("failed to create socket (%d)", WSAGetLastError());
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(int))
            == SOCKET_ERROR)
    {
        error("failed to re-use address (%d)", GetLastError());
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy_port);
    if (bind(s, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        error("failed to bind socket (%d)", WSAGetLastError());
    }

    if (listen(s, 16) == SOCKET_ERROR)
    {
        error("failed to listen socket (%d)", WSAGetLastError());
    }

    while (TRUE)
    {
        // Wait for a new connection.
        PPROXY_CONNECTION_CONFIG config;
        int size = sizeof(addr);
        SOCKET t = accept(s, (SOCKADDR *)&addr, &size);
        if (t == INVALID_SOCKET)
        {
            warning("failed to accept socket (%d)", WSAGetLastError());
            continue;
        }

        // Spawn proxy connection handler thread.
        config = (PPROXY_CONNECTION_CONFIG)
            malloc(sizeof(PROXY_CONNECTION_CONFIG));
        if (config == NULL)
        {
            error("failed to allocate memory");
        }
        config->s = t;
        config->alt_port = alt_port;
        config->dest = addr.sin_addr;
        thread = CreateThread(NULL, 1,
            (LPTHREAD_START_ROUTINE)proxy_connection_handler,
            (LPVOID)config, 0, NULL);
        if (thread == NULL)
        {
            warning("failed to create thread (%d)", GetLastError());
            closesocket(t);
            free(config);
            continue;
        }
        CloseHandle(thread);
    }
}

/*
 * Proxy connection handler thread.
 */
static DWORD proxy_connection_handler(LPVOID arg)
{
    PPROXY_TRANSFER_CONFIG config1, config2;
    HANDLE thread;
    PPROXY_CONNECTION_CONFIG config = (PPROXY_CONNECTION_CONFIG)arg;
    SOCKET s = config->s, t;
    UINT16 alt_port = config->alt_port;
    struct in_addr dest = config->dest;
    struct sockaddr_in addr;
    
    free(config);

    t = socket(AF_INET, SOCK_STREAM, 0);
    if (t == INVALID_SOCKET)
    {
        warning("failed to create socket (%d)", WSAGetLastError());
        closesocket(s);
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(alt_port);
    addr.sin_addr = dest;
    if (connect(t, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        warning("failed to connect socket (%d)", WSAGetLastError());
        closesocket(s);
        closesocket(t);
        return 0;
    }

    config1 = (PPROXY_TRANSFER_CONFIG)malloc(sizeof(PROXY_TRANSFER_CONFIG));
    config2 = (PPROXY_TRANSFER_CONFIG)malloc(sizeof(PROXY_TRANSFER_CONFIG));
    if (config1 == NULL || config2 == NULL)
    {
        error("failed to allocate memory");
    }
    config1->inbound = FALSE;
    config2->inbound = TRUE;
    config2->t = config1->s = s;
    config2->s = config1->t = t;
    thread = CreateThread(NULL, 1,
        (LPTHREAD_START_ROUTINE)proxy_transfer_handler, (LPVOID)config1, 0,
        NULL);
    if (thread == NULL)
    {
        warning("failed to create thread (%d)", GetLastError());
        closesocket(s);
        closesocket(t);
        free(config1);
        free(config2);
        return 0;
    }
    proxy_transfer_handler((LPVOID)config2);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    closesocket(s);
    closesocket(t);
    return 0;
}

/*
 * Handle the transfer of data from one socket to another.
 */
static DWORD proxy_transfer_handler(LPVOID arg)
{
    PPROXY_TRANSFER_CONFIG config = (PPROXY_TRANSFER_CONFIG)arg;
    BOOL inbound = config->inbound;
    SOCKET s = config->s, t = config->t;
    char buf[8192];
    int len, len2, i;
    HANDLE console;

    free(config);

    while (TRUE)
    {
        // Read data from s.
        len = recv(s, buf, sizeof(buf), 0);
        if (len == SOCKET_ERROR)
        {
            warning("failed to recv from socket (%d)", WSAGetLastError());
            shutdown(s, SD_BOTH);
            shutdown(t, SD_BOTH);
            return 0;
        }
        if (len == 0)
        {
            shutdown(s, SD_RECEIVE);
            shutdown(t, SD_SEND);
            return 0;
        }

        // Dump stream information to the screen.
        console = GetStdHandle(STD_OUTPUT_HANDLE);
        WaitForSingleObject(lock, INFINITE);
        printf("[%.4d] ", len);
        SetConsoleTextAttribute(console,
            (inbound? FOREGROUND_RED: FOREGROUND_GREEN));
        for (i = 0; i < len && i < MAX_LINE; i++)
        {
            putchar((isprint(buf[i])? buf[i]: '.'));
        }
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("%s\n", (len > MAX_LINE? "...": ""));
        ReleaseMutex(lock);

        // Send data to t.
        for (i = 0; i < len; )
        {
            len2 = send(t, buf+i, len-i, 0);
            if (len2 == SOCKET_ERROR)
            {
                warning("failed to send to socket (%d)", WSAGetLastError());
                shutdown(s, SD_BOTH);
                shutdown(t, SD_BOTH);
                return 0;
            }
            i += len2;
        }
    }

    return 0;
}

