/*
 * netdump.c
 * (C) 2023, all rights reserved,
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
 * usage: netdump.exe windivert-filter [priority] [layer]
 *
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#define ntohs(x)            WinDivertHelperNtohs(x)
#define ntohl(x)            WinDivertHelperNtohl(x)

#define MAXBUF              WINDIVERT_MTU_MAX
#define INET6_ADDRSTRLEN    45

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    HANDLE handle, console;
    DWORD err;
    UINT i;
    WINDIVERT_LAYER layer = WINDIVERT_LAYER_NETWORK;
    INT16 priority = 0;
    unsigned char packet[MAXBUF];
    UINT packet_len, arp_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_ETHHDR eth_header;
    PWINDIVERT_ARPHDR arp_header;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_ICMPHDR icmp_header;
    PWINDIVERT_ICMPV6HDR icmpv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;
    UINT8 src_mac[6], dst_mac[6], *mac_ptr;
    UINT32 src_addr[4], dst_addr[4], *ip_ptr;
    UINT64 hash;
    char src_str[INET6_ADDRSTRLEN+1], dst_str[INET6_ADDRSTRLEN+1];
    const char *err_str;
    LARGE_INTEGER base, freq;
    double time_passed;

    // Check arguments.
    switch (argc)
    {
        case 4:
            if (strcmp(argv[3], "network") == 0)
            {
                layer = WINDIVERT_LAYER_NETWORK;
            }
            else if (strcmp(argv[3], "forward") == 0)
            {
                layer = WINDIVERT_LAYER_NETWORK_FORWARD;
            }
            else if (strcmp(argv[3], "ethernet") == 0)
            {
                layer = WINDIVERT_LAYER_ETHERNET;
            }
            else
            {
                goto usage;
            }
            // Fallthrough
        case 3:
            priority = (INT16)atoi(argv[2]);
            // Fallthrough
        case 2:
            break;
        default:
        usage:
            fprintf(stderr, "usage: %s windivert-filter [priority] [layer]\n\n",
                argv[0]);
            fprintf(stderr, "where:\n");
            fprintf(stderr, "\t- priority is an integer between "
                "-30000..30000 (default = %d)\n", (int)priority);
            fprintf(stderr, "\t- layer is one of ethernet/network/forward "
                "(default = network)\n\n");
            fprintf(stderr, "examples:\n");
            fprintf(stderr, "\t%s true\n", argv[0]);
            fprintf(stderr, "\t%s \"outbound and tcp.DstPort == 80\" 1000 "
                "network\n", argv[0]);
            fprintf(stderr, "\t%s \"inbound and tcp.Syn\" -400 ethernet\n",
                argv[0]);
            exit(EXIT_FAILURE);
    }

    // Get console for pretty colors.
    console = GetStdHandle(STD_OUTPUT_HANDLE);

    // Divert traffic matching the filter:
    handle = WinDivertOpen(argv[1], layer, priority, WINDIVERT_FLAG_SNIFF);
    if (handle == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
        if (err == ERROR_INVALID_PARAMETER &&
            !WinDivertHelperCompileFilter(argv[1], layer, NULL, 0, &err_str,
                NULL))
        {
            fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            err);
        exit(EXIT_FAILURE);
    }

    // Max-out the packet queue:
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 
            WINDIVERT_PARAM_QUEUE_LENGTH_MAX))
    {
        fprintf(stderr, "error: failed to set packet queue length (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME,
            WINDIVERT_PARAM_QUEUE_TIME_MAX))
    {
        fprintf(stderr, "error: failed to set packet queue time (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE,
            WINDIVERT_PARAM_QUEUE_SIZE_MAX))
    {
        fprintf(stderr, "error: failed to set packet queue size (%d)\n",
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
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            continue;
        }

        // Print info about the matching packet.
        WinDivertHelperParsePacket(packet, packet_len, addr.Layer,
            &eth_header, &arp_header, &ip_header, &ipv6_header, NULL,
            &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL,
            NULL);

        // Dump packet info: 
        putchar('\n');
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        time_passed = (double)(addr.Timestamp - base.QuadPart) /
            (double)freq.QuadPart;
        hash = WinDivertHelperHashPacket(packet, packet_len, addr.Layer, 0);
        if (eth_header != NULL)
        {
            printf("Packet [Timestamp=%.8g Length=%u Direction=%s IfIdx=%u "
                "SubIfIdx=%u Hash=0x%.16llX]\n",
                time_passed, packet_len, (addr.Outbound? "outbound": "inbound"),
                addr.Ethernet.IfIdx, addr.Ethernet.SubIfIdx, hash);
            WinDivertHelperNtohMACAddress(eth_header->SrcAddr, src_mac);
            WinDivertHelperNtohMACAddress(eth_header->DstAddr, dst_mac);
            WinDivertHelperFormatMACAddress(src_mac, src_str, sizeof(src_str));
            WinDivertHelperFormatMACAddress(dst_mac, dst_str, sizeof(dst_str));
            SetConsoleTextAttribute(console,
                FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("Ethernet [SrcAddr=%s DstAddr=%s Type=0x%.4X]\n",
                src_str, dst_str, ntohs(eth_header->Type));
            if (arp_header != NULL)
            {
                arp_len = packet_len - sizeof(WINDIVERT_ETHHDR);
                SetConsoleTextAttribute(console,
                    FOREGROUND_GREEN);
                printf("ARP [Hardware=%u Protocol=%u HardLength=%u "
                    "ProtLength=%u Opcode=%u",
                    ntohs(arp_header->Hardware), ntohs(arp_header->Protocol),
                    arp_header->HardLength, arp_header->ProtLength,
                    ntohs(arp_header->Opcode));
                mac_ptr = WINDIVERT_ARPHDR_GET_SRCMACADDR_PTR(arp_header,
                    arp_len);
                if (mac_ptr != NULL)
                {
                    WinDivertHelperNtohMACAddress(mac_ptr, src_mac);
                    WinDivertHelperFormatMACAddress(src_mac, src_str,
                        sizeof(src_str));
                    printf(" SrcHardAddr=%s", src_str);
                }
                ip_ptr = WINDIVERT_ARPHDR_GET_SRCIPV4ADDR_PTR(arp_header,
                    arp_len);
                if (ip_ptr != NULL)
                {
                    WinDivertHelperFormatIPv4Address(ntohl(ip_ptr[0]),
                        src_str, sizeof(src_str));
                    printf(" SrcProtAddr=%s", src_str);
                }
                ip_ptr = WINDIVERT_ARPHDR_GET_SRCIPV6ADDR_PTR(arp_header,
                    arp_len);
                if (ip_ptr != NULL)
                {
                    WinDivertHelperNtohIPv6Address(ip_ptr, src_addr);
                    WinDivertHelperFormatIPv6Address(src_addr, src_str,
                        sizeof(src_str));
                    printf(" SrcProtAddr=%s", src_str);
                }
                mac_ptr = WINDIVERT_ARPHDR_GET_DSTMACADDR_PTR(arp_header,
                    arp_len);
                if (mac_ptr != NULL)
                {
                    WinDivertHelperNtohMACAddress(mac_ptr, dst_mac);
                    WinDivertHelperFormatMACAddress(dst_mac, dst_str,
                        sizeof(dst_str));
                    printf(" DstHardAddr=%s", dst_str);
                }
                ip_ptr = WINDIVERT_ARPHDR_GET_DSTIPV4ADDR_PTR(arp_header,
                    arp_len);
                if (ip_ptr != NULL)
                {
                    WinDivertHelperFormatIPv4Address(ntohl(ip_ptr[0]),
                        dst_str, sizeof(dst_str));
                    printf(" DstProtAddr=%s", dst_str);
                }
                ip_ptr = WINDIVERT_ARPHDR_GET_DSTIPV6ADDR_PTR(arp_header,
                    arp_len);
                if (ip_ptr != NULL)
                {
                    WinDivertHelperNtohIPv6Address(ip_ptr, dst_addr);
                    WinDivertHelperFormatIPv6Address(dst_addr, dst_str,
                        sizeof(dst_str));
                    printf(" DstProtAddr=%s", dst_str);
                }
                printf("]\n");
            }
        }
        else
        {
            printf("Packet [Timestamp=%.8g Length=%u Direction=%s IfIdx=%u "
                "SubIfIdx=%u Loopback=%u Hash=0x%.16llX]\n",
                time_passed, packet_len, (addr.Outbound? "outbound": "inbound"),
                addr.Network.IfIdx, addr.Network.SubIfIdx, addr.Loopback,
                hash);
        }
        if (ip_header != NULL)
        {
            WinDivertHelperFormatIPv4Address(ntohl(ip_header->SrcAddr),
                src_str, sizeof(src_str));
            WinDivertHelperFormatIPv4Address(ntohl(ip_header->DstAddr),
                dst_str, sizeof(dst_str));
            SetConsoleTextAttribute(console,
                FOREGROUND_GREEN | FOREGROUND_RED);
            printf("IPv4 [Version=%u HdrLength=%u TOS=%u Length=%u Id=0x%.4X "
                "Reserved=%u DF=%u MF=%u FragOff=%u TTL=%u Protocol=%u "
                "Checksum=0x%.4X SrcAddr=%s DstAddr=%s]\n",
                ip_header->Version, ip_header->HdrLength,
                ntohs(ip_header->TOS), ntohs(ip_header->Length),
                ntohs(ip_header->Id), WINDIVERT_IPHDR_GET_RESERVED(ip_header),
                WINDIVERT_IPHDR_GET_DF(ip_header),
                WINDIVERT_IPHDR_GET_MF(ip_header),
                ntohs(WINDIVERT_IPHDR_GET_FRAGOFF(ip_header)), ip_header->TTL,
                ip_header->Protocol, ntohs(ip_header->Checksum), src_str,
                dst_str);

        }
        if (ipv6_header != NULL)
        {
            WinDivertHelperNtohIPv6Address(ipv6_header->SrcAddr, src_addr);
            WinDivertHelperNtohIPv6Address(ipv6_header->DstAddr, dst_addr);
            WinDivertHelperFormatIPv6Address(src_addr, src_str,
                sizeof(src_str));
            WinDivertHelperFormatIPv6Address(dst_addr, dst_str,
                sizeof(dst_str));
            SetConsoleTextAttribute(console,
                FOREGROUND_GREEN | FOREGROUND_RED);
            printf("IPv6 [Version=%u TrafficClass=%u FlowLabel=%u Length=%u "
                "NextHdr=%u HopLimit=%u SrcAddr=%s DstAddr=%s]\n",
                ipv6_header->Version,
                WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(ipv6_header),
                ntohl(WINDIVERT_IPV6HDR_GET_FLOWLABEL(ipv6_header)),
                ntohs(ipv6_header->Length), ipv6_header->NextHdr,
                ipv6_header->HopLimit, src_str, dst_str);
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

