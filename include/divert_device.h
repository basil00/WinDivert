/*
 * divert_device.h
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
 * NOTE: This file is NOT part of the divert API.  For the divert API, include
 *       "divert.h" instead.
 */

#ifndef __DIVERT_DEVICE_H
#define __DIVERT_DEVICE_H

#define DIVERT_DEVICE_NAME                      L"\\Device\\Divert"
#define DIVERT_DOS_DEVICE_NAME                  L"\\??\\Divert"

#define DIVERT_VERSION                          0
#define DIVERT_MAGIC                            0xF8D3

#define DIVERT_FILTER_FIELD_ZERO                0
#define DIVERT_FILTER_FIELD_INBOUND             1
#define DIVERT_FILTER_FIELD_OUTBOUND            2
#define DIVERT_FILTER_FIELD_IFIDX               3
#define DIVERT_FILTER_FIELD_SUBIFIDX            4
#define DIVERT_FILTER_FIELD_IP                  5
#define DIVERT_FILTER_FIELD_IPV6                6
#define DIVERT_FILTER_FIELD_ICMP                7
#define DIVERT_FILTER_FIELD_TCP                 8
#define DIVERT_FILTER_FIELD_UDP                 9
#define DIVERT_FILTER_FIELD_ICMPV6              10
#define DIVERT_FILTER_FIELD_IP_HDRLENGTH        11
#define DIVERT_FILTER_FIELD_IP_TOS              12
#define DIVERT_FILTER_FIELD_IP_LENGTH           13
#define DIVERT_FILTER_FIELD_IP_ID               14
#define DIVERT_FILTER_FIELD_IP_DF               15
#define DIVERT_FILTER_FIELD_IP_MF               16
#define DIVERT_FILTER_FIELD_IP_FRAGOFF          17
#define DIVERT_FILTER_FIELD_IP_TTL              18
#define DIVERT_FILTER_FIELD_IP_PROTOCOL         19
#define DIVERT_FILTER_FIELD_IP_CHECKSUM         20
#define DIVERT_FILTER_FIELD_IP_SRCADDR          21
#define DIVERT_FILTER_FIELD_IP_DSTADDR          22
#define DIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS   23
#define DIVERT_FILTER_FIELD_IPV6_FLOWLABEL      24
#define DIVERT_FILTER_FIELD_IPV6_LENGTH         25
#define DIVERT_FILTER_FIELD_IPV6_NEXTHDR        26
#define DIVERT_FILTER_FIELD_IPV6_HOPLIMIT       27
#define DIVERT_FILTER_FIELD_IPV6_SRCADDR        28
#define DIVERT_FILTER_FIELD_IPV6_DSTADDR        29
#define DIVERT_FILTER_FIELD_ICMP_TYPE           30
#define DIVERT_FILTER_FIELD_ICMP_CODE           31
#define DIVERT_FILTER_FIELD_ICMP_CHECKSUM       32
#define DIVERT_FILTER_FIELD_ICMP_BODY           33
#define DIVERT_FILTER_FIELD_ICMPV6_TYPE         34
#define DIVERT_FILTER_FIELD_ICMPV6_CODE         35
#define DIVERT_FILTER_FIELD_ICMPV6_CHECKSUM     36
#define DIVERT_FILTER_FIELD_ICMPV6_BODY         37
#define DIVERT_FILTER_FIELD_TCP_SRCPORT         38
#define DIVERT_FILTER_FIELD_TCP_DSTPORT         39
#define DIVERT_FILTER_FIELD_TCP_SEQNUM          40
#define DIVERT_FILTER_FIELD_TCP_ACKNUM          41
#define DIVERT_FILTER_FIELD_TCP_HDRLENGTH       42
#define DIVERT_FILTER_FIELD_TCP_URG             43
#define DIVERT_FILTER_FIELD_TCP_ACK             44
#define DIVERT_FILTER_FIELD_TCP_PSH             45
#define DIVERT_FILTER_FIELD_TCP_RST             46
#define DIVERT_FILTER_FIELD_TCP_SYN             47
#define DIVERT_FILTER_FIELD_TCP_FIN             48
#define DIVERT_FILTER_FIELD_TCP_WINDOW          49
#define DIVERT_FILTER_FIELD_TCP_CHECKSUM        50
#define DIVERT_FILTER_FIELD_TCP_URGPTR          51
#define DIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH   52
#define DIVERT_FILTER_FIELD_UDP_SRCPORT         53
#define DIVERT_FILTER_FIELD_UDP_DSTPORT         54
#define DIVERT_FILTER_FIELD_UDP_LENGTH          55
#define DIVERT_FILTER_FIELD_UDP_CHECKSUM        56
#define DIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH   57
#define DIVERT_FILTER_FIELD_MAX                 \
    DIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH

#define DIVERT_FILTER_TEST_EQ                   0
#define DIVERT_FILTER_TEST_NEQ                  1
#define DIVERT_FILTER_TEST_LT                   2
#define DIVERT_FILTER_TEST_LEQ                  3
#define DIVERT_FILTER_TEST_GT                   4
#define DIVERT_FILTER_TEST_GEQ                  5
#define DIVERT_FILTER_TEST_MAX                  DIVERT_FILTER_TEST_GEQ

#define DIVERT_FILTER_MAXLEN                    64

#define DIVERT_FILTER_RESULT_ACCEPT             (DIVERT_FILTER_MAXLEN+1)
#define DIVERT_FILTER_RESULT_REJECT             (DIVERT_FILTER_MAXLEN+2)

/*
 * Packet definitions.
 */
#ifndef DIVERT_PACKET_DIRECTION_OUTBOUND
#define DIVERT_PACKET_DIRECTION_OUTBOUND        0
#define DIVERT_PACKET_DIRECTION_INBOUND         1
#endif      /* DIVERT_PACKET_DIRECTION_OUTBOUND */

/*
 * Message definitions.
 */
struct divert_message_s
{
    UINT16 magic;                   // DIVERT_MAGIC
    UINT8  version;                 // DIVERT_VERSION
    UINT8  reserved;                // Reserved (set to 0x0)
};
typedef struct divert_message_s *divert_message_t;

/*
 * IOCTL structures.
 */
struct divert_ioctl_filter_s
{
    UINT8  field;                   // DIVERT_FILTER_FIELD_IP_*
    UINT8  test;                    // DIVERT_FILTER_TEST_*
    UINT8  success;                 // Success continuation.
    UINT8  failure;                 // Fail continuation.
    UINT32 arg[4];                  // Argument.
};
typedef struct divert_ioctl_filter_s *divert_ioctl_filter_t;

/*
 * IOCTL codes.
 */
#define IOCTL_DIVERT_SET_FILTER     \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90A, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif      // __DIVERT_DEVICE_H
