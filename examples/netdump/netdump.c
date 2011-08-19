/*
 * netdump.c
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
 * This is a simple traffic monitor.
 *
 * usage: netdump.exe divert-filter
 *
 * NOTE: Using Divert for this purpose is rather inefficient, as each captured
 *       packet must be reinjected.  For packet sniffing, it's better to use a
 *       package that copies packets, not copies-and-drops such as Divert.
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "divert.h"

#define MAXBUF  2048

/*
 * Entry.
 */
int main(int argc, char **argv)
{
    HANDLE handle, console;
    size_t slen, flen;
    UINT i;
    char filter[MAXBUF];
    char packet[MAXBUF];
    PDIVERT_PACKET ppacket = (PDIVERT_PACKET)packet;
    UINT ppacket_len;
    PDIVERT_IPHDR ip_header;
    PDIVERT_IPV6HDR ipv6_header;
    PDIVERT_ICMPHDR icmp_header;
    PDIVERT_ICMPV6HDR icmpv6_header;
    PDIVERT_TCPHDR tcp_header;
    PDIVERT_UDPHDR udp_header;
    UINT8 *data;
    UINT data_len;

    // Concat all command line args into a filter string.
    flen = 0;
    for (i = 1; (int)i < argc; i++)
    {
        slen = strlen(argv[i]);
        if (flen + slen + 1 >= MAXBUF)
        {
            fprintf(stderr, "error: filter too long\n");
            exit(EXIT_FAILURE);
        }
        strcpy(filter+flen, argv[i]);
        flen += slen;
        filter[flen] = ' ';
        flen++;
    }
    filter[flen] = '\0';

    // Get console for pretty colors.
    console = GetStdHandle(STD_OUTPUT_HANDLE);

    // Divert traffic matching the filter:
    handle = DivertOpen(filter);
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

    // Main loop:
    while (TRUE)
    {
        // Read a matching packet.
        if (!DivertRecv(handle, ppacket, sizeof(packet), &ppacket_len))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            continue;
        }
       
        // Re-inject the matching packet.
        if (!DivertSend(handle, ppacket, ppacket_len, NULL))
        {
            fprintf(stderr, "warning: failed to reinject packet (%d)\n",
                GetLastError());
        }

        // Print info about the matching packet.
        DivertHelperParse(ppacket, ppacket_len, &ip_header, &ipv6_header,
            &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL,
            NULL);
        if (ip_header == NULL && ipv6_header == NULL)
        {
            fprintf(stderr, "warning: junk packet\n");
        }

        // Dump packet info: 
        putchar('\n');
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        printf("Packet [Direction=%u IfIdx=%u SubIfIdx=%u]\n",
            ppacket->Direction, ppacket->IfIdx, ppacket->SubIfIdx);
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
                ntohs(ip_header->Id), DIVERT_IPHDR_GET_RESERVED(ip_header),
                DIVERT_IPHDR_GET_DF(ip_header), DIVERT_IPHDR_GET_MF(ip_header),
                ntohs(DIVERT_IPHDR_GET_FRAGOFF(ip_header)), ip_header->TTL,
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
                DIVERT_IPV6HDR_GET_TRAFFICCLASS(ipv6_header),
                ntohl(DIVERT_IPV6HDR_GET_FLOWLABEL(ipv6_header)),
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
        data = DIVERT_PACKET_DATA(ppacket);
        data_len = ppacket_len - sizeof(DIVERT_PACKET);
        for (i = 0; i < data_len; i++)
        {
            if (i % 20 == 0)
            {
                printf("\n\t");
            }
            printf("%.2X", (unsigned)data[i]);
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_BLUE);
        for (i = 0; i < data_len; i++)
        {
            if (i % 40 == 0)
            {
                printf("\n\t");
            }
            if (isprint(data[i]))
            {
                putchar(data[i]);
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

