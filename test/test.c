/*
 * test.c
 * (C) 2014, all rights reserved,
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

/*
 * WinDivert testing framework.
 */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "windivert.h"

#define MAX_PACKET  2048

/*
 * Packet data.
 */
#include "test_data.c"

/*
 * Test entry.
 */
struct packet
{
    char *packet;
    size_t packet_len;
    char *name;
};

struct test
{
    char *filter;
    struct packet *packet;
    BOOL match;
};

/*
 * Prototypes.
 */
static BOOL run_test(HANDLE inject_handle, const char *filter,
    const char *packet, const size_t packet_len, BOOL match);

/*
 * Test data.
 */
static struct packet pkt_echo_request =
{
    echo_request,
    sizeof(echo_request),
    "ipv4_icmp_echo_req"
};
static struct packet pkt_http_request =
{
    http_request,
    sizeof(http_request),
    "ipv4_tcp_http_req"
};
static struct packet pkt_dns_request =
{
    dns_request,
    sizeof(dns_request),
    "ipv4_udp_dns_req"
};
static struct packet pkt_ipv6_tcp_syn =
{
    ipv6_tcp_syn,
    sizeof(ipv6_tcp_syn),
    "ipv6_tcp_syn"
};
static struct packet pkt_ipv6_echo_reply =
{
    ipv6_echo_reply,
    sizeof(ipv6_echo_reply),
    "ipv6_icmpv6_echo_rep"
};
static struct packet pkt_ipv6_exthdrs_udp =
{
    ipv6_exthdrs_udp,
    sizeof(ipv6_exthdrs_udp),
    "ipv6_exthdrs_udp"
};
static struct test tests[] =
{
    {"outbound and icmp",                      &pkt_echo_request, TRUE},
    {"outbound",                               &pkt_echo_request, TRUE},
    {"icmp",                                   &pkt_echo_request, TRUE},
    {"not icmp",                               &pkt_echo_request, FALSE},
    {"inbound",                                &pkt_echo_request, FALSE},
    {"tcp",                                    &pkt_echo_request, FALSE},
    {"icmp.Type == 8",                         &pkt_echo_request, TRUE},
    {"icmp.Type == 9",                         &pkt_echo_request, FALSE},
    {"tcp",                                    &pkt_http_request, TRUE},
    {"outbound and tcp and tcp.DstPort == 80", &pkt_http_request, TRUE},
    {"outbound and tcp and tcp.DstPort == 81", &pkt_http_request, FALSE},
    {"outbound and tcp and tcp.DstPort != 80", &pkt_http_request, FALSE},
    {"inbound and tcp and tcp.DstPort == 80",  &pkt_http_request, FALSE},
    {"tcp.PayloadLength == 469",               &pkt_http_request, TRUE},
    {"tcp.PayloadLength != 469",               &pkt_http_request, FALSE},
    {"tcp.PayloadLength >= 469",               &pkt_http_request, TRUE},
    {"tcp.PayloadLength <= 469",               &pkt_http_request, TRUE},
    {"tcp.PayloadLength > 469",                &pkt_http_request, FALSE},
    {"tcp.PayloadLength < 469",                &pkt_http_request, FALSE},
    {"udp",                                    &pkt_dns_request, TRUE},
    {"udp && udp.SrcPort > 1 && ipv6",         &pkt_dns_request, FALSE},
    {"udp.DstPort == 53",                      &pkt_dns_request, TRUE},
    {"udp.DstPort > 100",                      &pkt_dns_request, FALSE},
    {"ip.DstAddr = 8.8.4.4",                   &pkt_dns_request, TRUE},
    {"ip.DstAddr = 8.8.8.8",                   &pkt_dns_request, FALSE},
    {"ip.SrcAddr >= 10.0.0.0 && ip.SrcAddr <= 10.255.255.255",
                                               &pkt_dns_request, TRUE},
    {"ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255",
                                               &pkt_dns_request, FALSE},
    {"udp.PayloadLength == 29",                &pkt_dns_request, TRUE},
    {"ipv6",                                   &pkt_ipv6_tcp_syn, TRUE},
    {"ip",                                     &pkt_ipv6_tcp_syn, FALSE},
    {"tcp.Syn",                                &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.Syn == 1 && tcp.Ack == 0",           &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.PayloadLength == 0",                 &pkt_ipv6_tcp_syn, TRUE},
    {"ipv6.SrcAddr == 1234:5678:1::aabb:ccdd", &pkt_ipv6_tcp_syn, TRUE},
    {"ipv6.SrcAddr == aabb:5678:1::1234:ccdd", &pkt_ipv6_tcp_syn, FALSE},
    {"tcp.SrcPort == 50046",                   &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.SrcPort == 0x0000C37E",              &pkt_ipv6_tcp_syn, TRUE},
    {"icmpv6",                                 &pkt_ipv6_echo_reply, TRUE},
    {"icmp",                                   &pkt_ipv6_echo_reply, FALSE},
    {"icmp or icmpv6",                         &pkt_ipv6_echo_reply, TRUE},
    {"not icmp",                               &pkt_ipv6_echo_reply, TRUE},
    {"icmpv6.Type == 129",                     &pkt_ipv6_echo_reply, TRUE},
    {"icmpv6.Code == 0",                       &pkt_ipv6_echo_reply, TRUE},
    {"icmpv6.Body == 0x10720003",              &pkt_ipv6_echo_reply, TRUE},
    {"ipv6.DstAddr >= 1000",                   &pkt_ipv6_echo_reply, FALSE},
    {"ipv6.DstAddr <= 1",                      &pkt_ipv6_echo_reply, TRUE},
    {"true",                                   &pkt_ipv6_exthdrs_udp, TRUE},
    {"udp",                                    &pkt_ipv6_exthdrs_udp, TRUE},
    {"tcp",                                    &pkt_ipv6_exthdrs_udp, FALSE},
    {"ipv6.SrcAddr == ::1",                    &pkt_ipv6_exthdrs_udp, TRUE},
    {"ipv6.SrcAddr == ::2",                    &pkt_ipv6_exthdrs_udp, FALSE},
    {"udp.SrcPort == 4660 and udp.DstPort == 43690",
                                               &pkt_ipv6_exthdrs_udp, TRUE},
    {"udp.SrcPort == 4660 and udp.DstPort == 12345",
                                               &pkt_ipv6_exthdrs_udp, FALSE},
};

/*
 * Main.
 */
int main(void)
{
    HANDLE upper_handle, lower_handle;
    HANDLE console;
    size_t i;

    // Open handles to:
    // (1) stop normal traffic from interacting with the tests; and
    // (2) stop test packets escaping to the Internet or TCP/IP stack.
    upper_handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, -510,
        WINDIVERT_FLAG_DROP);
    lower_handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 510,
        WINDIVERT_FLAG_DROP);
    if (upper_handle == INVALID_HANDLE_VALUE ||
        lower_handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: failed to open WinDivert handle (err = %d)",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    console = GetStdHandle(STD_OUTPUT_HANDLE);

    // Wait for existing packets to flush:
    Sleep(100);

    // Run tests:
    size_t num_tests = sizeof(tests) / sizeof(struct test);
    for (i = 0; i < num_tests; i++)
    {
        char *filter = tests[i].filter;
        char *packet = tests[i].packet->packet;
        size_t packet_len = tests[i].packet->packet_len;
        char *name = tests[i].packet->name;
        BOOL match = tests[i].match;

        // Ensure the correct checksum:
        WinDivertHelperCalcChecksums(packet, packet_len, 0);

        // Run the test:
        BOOL res = run_test(upper_handle, filter, packet, packet_len, match);

        printf("%.2u ", i);
        if (res)
        {
            SetConsoleTextAttribute(console, FOREGROUND_GREEN);
            printf("PASSED");
        }
        else
        {
            SetConsoleTextAttribute(console, FOREGROUND_RED);
            printf("FAILED");
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);
        printf(" p=[");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        printf("%s", name);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);
        printf("] f=[");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        printf("%s", filter);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);
        printf("]\n");
    }

    WinDivertClose(upper_handle);
    WinDivertClose(lower_handle);

    return 0;
}

/*
 * Run a test case.
 */
static BOOL run_test(HANDLE inject_handle, const char *filter,
    const char *packet, const size_t packet_len, BOOL match)
{
    char buf[MAX_PACKET];
    UINT buf_len, i;
    DWORD iolen;
    WINDIVERT_ADDRESS addr;
    OVERLAPPED overlapped;
    HANDLE handle = INVALID_HANDLE_VALUE, handle0 = INVALID_HANDLE_VALUE,
        event = NULL;

    // (1) Open a WinDivert handle to the given filter:
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: failed to open WinDivert handle for filter "
            "\"%s\" (err = %d)\n", filter, GetLastError());
        goto failed;
    }

    if (!match)
    {
        // Catch non-matching packets:
        handle0 = handle;
        handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 33, 0);
        if (handle == INVALID_HANDLE_VALUE)
        {
            fprintf(stderr, "error: failed to open WinDivert handle "
                "(err = %d)\n", GetLastError());
            goto failed;
        }
    }

    // (2) Inject the packet:
    memset(&addr, 0, sizeof(addr));
    addr.Direction = WINDIVERT_DIRECTION_OUTBOUND;
    if (!WinDivertSend(inject_handle, packet, packet_len, &addr, NULL))
    {
        fprintf(stderr, "error: failed to inject test packet (err = %d)\n",
            GetLastError());
        goto failed;
    }

    // (3) Wait for the packet to arrive.
    // NOTE: This may fail, so set a generous time-out of 250ms.
    memset(&overlapped, 0, sizeof(overlapped));
    event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (event == NULL)
    {
        fprintf(stderr, "error: failed to create event (err = %d)\n",
            GetLastError());
        goto failed;
    }
    overlapped.hEvent = event;
    if (!WinDivertRecvEx(handle, buf, sizeof(buf), 0, &addr, &buf_len,
            &overlapped))
    {
        if (GetLastError() != ERROR_IO_PENDING)
        {
read_failed:
            fprintf(stderr, "error: failed to read packet from WinDivert "
                "handle (err = %d)\n", GetLastError());
            goto failed;
        }

        switch (WaitForSingleObject(event, 250))
        {
            case WAIT_OBJECT_0:
                break;
            case WAIT_TIMEOUT:
                fprintf(stderr, "error: failed to read packet from WinDivert "
                    "handle (timeout)\n", GetLastError());
                goto failed;
            default:
                goto read_failed;
        }

        if (!GetOverlappedResult(handle, &overlapped, &iolen, TRUE))
        {
            fprintf(stderr, "error: failed to get the overlapped result from "
                "WinDivert handle (err = %d)\n", GetLastError());
            goto failed;
        }
        buf_len = (UINT)iolen;
    }

    // (4) Verify that the packet is the same.
    if (buf_len != packet_len)
    {
        fprintf(stderr, "error: packet length mis-match, expected (%u), got "
            "(%u)\n", packet_len, buf_len);
        goto failed;
    }
    for (i = 0; i < packet_len; i++)
    {
        if (packet[i] != buf[i])
        {
            fprintf(stderr, "error: packet data mis-match, expected byte #%u "
                "to be (0x%.2X), got (0x%.2X)\n", i, (unsigned char)packet[i],
                (unsigned char)buf[i]);
            for (i = 0; i < packet_len; i++)
            {
                printf("%c", (packet[i] == buf[i]? '.': 'X'));
            }
            putchar('\n');
            goto failed;
        }
    }

    // (5) Clean-up:
    if (!WinDivertClose(handle))
    {
        handle = INVALID_HANDLE_VALUE;
        fprintf(stderr, "error: failed to close WinDivert handle (err = %d)\n",
            GetLastError());
        goto failed;
    }
    if (handle0 != INVALID_HANDLE_VALUE)
    {
        if (!WinDivertClose(handle0))
        {
            handle0 = INVALID_HANDLE_VALUE;
            fprintf(stderr, "error: failed to close WinDivert handle "
                "(err = %d)\n", GetLastError());
            goto failed;
        }
    }
    CloseHandle(event);

    return TRUE;

failed:
    if (handle0 != INVALID_HANDLE_VALUE)
    {
        WinDivertClose(handle0);
    }
    if (handle != INVALID_HANDLE_VALUE)
    {
        WinDivertClose(handle);
    }
    if (event != NULL)
    {
        CloseHandle(event);
    }
    return FALSE;
}

