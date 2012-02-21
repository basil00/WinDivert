/*
 * divert_device.h
 * (C) 2012, all rights reserved,
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

#ifndef __DIVERT_DEVICE_H
#define __DIVERT_DEVICE_H

/*
 * NOTE: This is the low-level interface to the divert device driver.
 *       This interface should not be used directly, instead use he high-level
 *       interface provided by the divert API.
 */

#define DIVERT_KERNEL
#include "divert.h"

#define DIVERT_VERSION                          1
#define DIVERT_VERSION_MINOR                    0

#define DIVERT_STR2(s)                          #s
#define DIVERT_STR(s)                           DIVERT_STR2(s)
#define DIVERT_LSTR2(s)                         L ## #s
#define DIVERT_LSTR(s)                          DIVERT_LSTR2(s)

#define DIVERT_VERSION_LSTR                     \
    DIVERT_LSTR(DIVERT_VERSION) L"." DIVERT_LSTR(DIVERT_VERSION_MINOR)

#define DIVERT_DEVICE_NAME                      \
    L"WinDivert" DIVERT_VERSION_LSTR

#define DIVERT_IOCTL_VERSION                    2
#define DIVERT_IOCTL_MAGIC                      0xE8D3

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

#define DIVERT_FILTER_MAXLEN                    512

#define DIVERT_FILTER_RESULT_ACCEPT             (DIVERT_FILTER_MAXLEN+1)
#define DIVERT_FILTER_RESULT_REJECT             (DIVERT_FILTER_MAXLEN+2)

/*
 * Divert layers.
 */
#define DIVERT_LAYER_DEFAULT                    DIVERT_LAYER_NETWORK
#define DIVERT_LAYER_MAX                        DIVERT_LAYER_NETWORK_FORWARD

/*
 * Divert flags.
 */
#define DIVERT_FLAGS_MAX                        \
    (DIVERT_FLAG_SNIFF | DIVERT_FLAG_DROP)

/*
 * Divert priorities.
 */
#define DIVERT_PRIORITY(priority16)             \
    ((UINT32)((INT32)(priority16) + 0x7FFF + 1))
#define DIVERT_PRIORITY_DEFAULT                 DIVERT_PRIORITY(0)
#define DIVERT_PRIORITY_MAX                     DIVERT_PRIORITY(1000)

/*
 * Divert parameters.
 */
#define DIVERT_PARAM_QUEUE_LEN_DEFAULT          512
#define DIVERT_PARAM_QUEUE_LEN_MIN              1
#define DIVERT_PARAM_QUEUE_LEN_MAX              8192
#define DIVERT_PARAM_QUEUE_TIME_DEFAULT         256
#define DIVERT_PARAM_QUEUE_TIME_MIN             32
#define DIVERT_PARAM_QUEUE_TIME_MAX             1024

/*
 * Message definitions.
 */
#pragma pack(push, 1)
struct divert_ioctl_s
{
    UINT16 magic;                   // DIVERT_IOCTL_MAGIC
    UINT8  version;                 // DIVERT_IOCTL_VERSION
    UINT8  arg8;                    // 8-bit argument
    UINT64 arg;                     // 64-bit argument
};
typedef struct divert_ioctl_s *divert_ioctl_t;

/*
 * IOCTL structures.
 */
struct divert_ioctl_filter_s
{
    UINT8  field;                   // DIVERT_FILTER_FIELD_IP_*
    UINT8  test;                    // DIVERT_FILTER_TEST_*
    UINT16 success;                 // Success continuation.
    UINT16 failure;                 // Fail continuation.
    UINT32 arg[4];                  // Argument.
};
typedef struct divert_ioctl_filter_s *divert_ioctl_filter_t;
#pragma pack(pop)

/*
 * IOCTL codes.
 */
#define IOCTL_DIVERT_RECV               \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x908, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_DIVERT_SEND               \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x909, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_DIVERT_START_FILTER       \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90A, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_DIVERT_SET_LAYER          \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90B, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_DIVERT_SET_PRIORITY       \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90C, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_DIVERT_SET_FLAGS          \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90D, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_DIVERT_SET_PARAM          \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90E, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_DIVERT_GET_PARAM          \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90F, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#endif      // __DIVERT_DEVICE_H
