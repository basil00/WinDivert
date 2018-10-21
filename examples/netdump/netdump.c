/*
 * netdump.c
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
 * This is a simple traffic monitor.  It uses a WinDivert handle in SNIFF mode.
 * The SNIFF mode copies packets and does not block the original.
 *
 * usage: netdump.exe windivert-filter [priority]
 *
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#define MAXBUF  0xFFFF

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    HANDLE handle, console;
    UINT i;
    INT16 priority = 0;
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_ICMPHDR icmp_header;
    PWINDIVERT_ICMPV6HDR icmpv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;
    const char *err_str;
    LARGE_INTEGER base, freq;
    double time_passed;

    // Check arguments.
    switch (argc)
    {
        case 2:
            break;
        case 3:
            priority = (INT16)atoi(argv[2]);
            break;
        default:
            fprintf(stderr, "usage: %s windivert-filter [priority]\n",
                argv[0]);
            fprintf(stderr, "examples:\n");
            fprintf(stderr, "\t%s true\n", argv[0]);
            fprintf(stderr, "\t%s \"outbound and tcp.DstPort == 80\" 1000\n",
                argv[0]);
            fprintf(stderr, "\t%s \"inbound and tcp.Syn\" -400\n", argv[0]);
            exit(EXIT_FAILURE);
    }

    // Get console for pretty colors.
    console = GetStdHandle(STD_OUTPUT_HANDLE);

    // Divert traffic matching the filter:
    handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, priority,
        WINDIVERT_FLAG_SNIFF);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER &&
            !WinDivertHelperCompileFilter(argv[1], WINDIVERT_LAYER_NETWORK,
                NULL, 0, &err_str, NULL))
        {
            fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Max-out the packet queue:
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LEN, 8192))
    {
        fprintf(stderr, "error: failed to set packet queue length (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048))
    {
        fprintf(stderr, "error: failed to set packet queue time (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Set up timing:
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&base);

    // Main loop:
    while (TRUE)
    {
        // Read a matching packet.
        if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            continue;
        }

        // Print info about the matching packet.
        WinDivertHelperParsePacket(packet, packet_len, &ip_header,
            &ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
            &udp_header, NULL, NULL);
        if (ip_header == NULL && ipv6_header == NULL)
        {
            fprintf(stderr, "warning: junk packet\n");
        }

        // Dump packet info: 
        putchar('\n');
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        time_passed = (double)(addr.Timestamp - base.QuadPart) /
            (double)freq.QuadPart;
        printf("Packet [Timestamp=%.8g, Direction=%s IfIdx=%u SubIfIdx=%u "
            "Loopback=%u]\n",
            time_passed, (addr.Outbound?  "outbound": "inbound"),
            addr.Network.IfIdx, addr.Network.SubIfIdx, addr.Loopback);
        if (ip_header != NULL)
        {
            UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
            UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
            SetConsoleTextAttribute(console,
                FOREGROUND_GREEN | FOREGROUND_RED);
            printf("IPv4 [Version=%u HdrLength=%u TOS=%u Length=%u Id=0x%.4X "
                "Reserved=%u DF=%u MF=%u FragOff=%u TTL=%u Protocol=%u "
                "Checksum=0x%.4X SrcAddr=%u.%u.%u.%u DstAddr=%u.%u.%u.%u]\n",
                ip_header->Version, ip_header->HdrLength,
                ntohs(ip_header->TOS), ntohs(ip_header->Length),
                ntohs(ip_header->Id), WINDIVERT_IPHDR_GET_RESERVED(ip_header),
                WINDIVERT_IPHDR_GET_DF(ip_header),
                WINDIVERT_IPHDR_GET_MF(ip_header),
                ntohs(WINDIVERT_IPHDR_GET_FRAGOFF(ip_header)), ip_header->TTL,
                ip_header->Protocol, ntohs(ip_header->Checksum),
                src_addr[0], src_addr[1], src_addr[2], src_addr[3],
                dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
        }
        if (ipv6_header != NULL)
        {
            UINT16 *src_addr = (UINT16 *)&ipv6_header->SrcAddr;
            UINT16 *dst_addr = (UINT16 *)&ipv6_header->DstAddr;
            SetConsoleTextAttribute(console,
                FOREGROUND_GREEN | FOREGROUND_RED);
            printf("IPv6 [Version=%u TrafficClass=%u FlowLabel=%u Length=%u "
                "NextHdr=%u HopLimit=%u SrcAddr=",
                ipv6_header->Version,
                WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(ipv6_header),
                ntohl(WINDIVERT_IPV6HDR_GET_FLOWLABEL(ipv6_header)),
                ntohs(ipv6_header->Length), ipv6_header->NextHdr,
                ipv6_header->HopLimit);
            for (i = 0; i < 8; i++)
            {
                printf("%x%c", ntohs(src_addr[i]), (i == 7? ' ': ':'));
            } 
            fputs("DstAddr=", stdout);
            for (i = 0; i < 8; i++)
            {
                printf("%x", ntohs(dst_addr[i]));
                if (i != 7)
                {
                    putchar(':');
                }
            }
            fputs("]\n", stdout);
        }
        if (icmp_header != NULL)
        {
            SetConsoleTextAttribute(console, FOREGROUND_RED);
            printf("ICMP [Type=%u Code=%u Checksum=0x%.4X Body=0x%.8X]\n",
                icmp_header->Type, icmp_header->Code,
                ntohs(icmp_header->Checksum), ntohl(icmp_header->Body));
        }
        if (icmpv6_header != NULL)
        {
            SetConsoleTextAttribute(console, FOREGROUND_RED);
            printf("ICMPV6 [Type=%u Code=%u Checksum=0x%.4X Body=0x%.8X]\n",
                icmpv6_header->Type, icmpv6_header->Code,
                ntohs(icmpv6_header->Checksum), ntohl(icmpv6_header->Body));
        }
        if (tcp_header != NULL)
        {
            SetConsoleTextAttribute(console, FOREGROUND_GREEN);
            printf("TCP [SrcPort=%u DstPort=%u SeqNum=%u AckNum=%u "
                "HdrLength=%u Reserved1=%u Reserved2=%u Urg=%u Ack=%u "
                "Psh=%u Rst=%u Syn=%u Fin=%u Window=%u Checksum=0x%.4X "
                "UrgPtr=%u]\n",
                ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort),
                ntohl(tcp_header->SeqNum), ntohl(tcp_header->AckNum),
                tcp_header->HdrLength, tcp_header->Reserved1,
                tcp_header->Reserved2, tcp_header->Urg, tcp_header->Ack,
                tcp_header->Psh, tcp_header->Rst, tcp_header->Syn,
                tcp_header->Fin, ntohs(tcp_header->Window),
                ntohs(tcp_header->Checksum), ntohs(tcp_header->UrgPtr));
        }
        if (udp_header != NULL)
        {
            SetConsoleTextAttribute(console, FOREGROUND_GREEN);
            printf("UDP [SrcPort=%u DstPort=%u Length=%u "
                "Checksum=0x%.4X]\n",
                ntohs(udp_header->SrcPort), ntohs(udp_header->DstPort),
                ntohs(udp_header->Length), ntohs(udp_header->Checksum));
        }
        SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_BLUE);
        for (i = 0; i < packet_len; i++)
        {
            if (i % 20 == 0)
            {
                printf("\n\t");
            }
            printf("%.2X", (UINT8)packet[i]);
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_BLUE);
        for (i = 0; i < packet_len; i++)
        {
            if (i % 40 == 0)
            {
                printf("\n\t");
            }
            if (isprint(packet[i]))
            {
                putchar(packet[i]);
            }
            else
            {
                putchar('.');
            }
        }
        putchar('\n');
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
}

