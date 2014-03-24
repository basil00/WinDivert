/*
 * windivert_device.h
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

#ifndef __WINDIVERT_DEVICE_H
#define __WINDIVERT_DEVICE_H

/*
 * NOTE: This is the low-level interface to the divert device driver.
 *       This interface should not be used directly, instead use the high-level
 *       interface provided by the divert API.
 */

#define WINDIVERT_KERNEL
#include "windivert.h"

#define WINDIVERT_VERSION                           1
#define WINDIVERT_VERSION_MINOR                     1

#define WINDIVERT_STR2(s)                           #s
#define WINDIVERT_STR(s)                            WINDIVERT_STR2(s)
#define WINDIVERT_LSTR2(s)                          L ## #s
#define WINDIVERT_LSTR(s)                           WINDIVERT_LSTR2(s)

#define WINDIVERT_VERSION_LSTR                                              \
    WINDIVERT_LSTR(WINDIVERT_VERSION) L"."                                  \
        WINDIVERT_LSTR(WINDIVERT_VERSION_MINOR)

#define WINDIVERT_DEVICE_NAME                                               \
    L"WinDivert" WINDIVERT_VERSION_LSTR

#define WINDIVERT_IOCTL_VERSION                     3
#define WINDIVERT_IOCTL_MAGIC                       0xE8D3

#define WINDIVERT_FILTER_FIELD_ZERO                 0
#define WINDIVERT_FILTER_FIELD_INBOUND              1
#define WINDIVERT_FILTER_FIELD_OUTBOUND             2
#define WINDIVERT_FILTER_FIELD_IFIDX                3
#define WINDIVERT_FILTER_FIELD_SUBIFIDX             4
#define WINDIVERT_FILTER_FIELD_IP                   5
#define WINDIVERT_FILTER_FIELD_IPV6                 6
#define WINDIVERT_FILTER_FIELD_ICMP                 7
#define WINDIVERT_FILTER_FIELD_TCP                  8
#define WINDIVERT_FILTER_FIELD_UDP                  9
#define WINDIVERT_FILTER_FIELD_ICMPV6               10
#define WINDIVERT_FILTER_FIELD_IP_HDRLENGTH         11
#define WINDIVERT_FILTER_FIELD_IP_TOS               12
#define WINDIVERT_FILTER_FIELD_IP_LENGTH            13
#define WINDIVERT_FILTER_FIELD_IP_ID                14
#define WINDIVERT_FILTER_FIELD_IP_DF                15
#define WINDIVERT_FILTER_FIELD_IP_MF                16
#define WINDIVERT_FILTER_FIELD_IP_FRAGOFF           17
#define WINDIVERT_FILTER_FIELD_IP_TTL               18
#define WINDIVERT_FILTER_FIELD_IP_PROTOCOL          19
#define WINDIVERT_FILTER_FIELD_IP_CHECKSUM          20
#define WINDIVERT_FILTER_FIELD_IP_SRCADDR           21
#define WINDIVERT_FILTER_FIELD_IP_DSTADDR           22
#define WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS    23
#define WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL       24
#define WINDIVERT_FILTER_FIELD_IPV6_LENGTH          25
#define WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR         26
#define WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT        27
#define WINDIVERT_FILTER_FIELD_IPV6_SRCADDR         28
#define WINDIVERT_FILTER_FIELD_IPV6_DSTADDR         29
#define WINDIVERT_FILTER_FIELD_ICMP_TYPE            30
#define WINDIVERT_FILTER_FIELD_ICMP_CODE            31
#define WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM        32
#define WINDIVERT_FILTER_FIELD_ICMP_BODY            33
#define WINDIVERT_FILTER_FIELD_ICMPV6_TYPE          34
#define WINDIVERT_FILTER_FIELD_ICMPV6_CODE          35
#define WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM      36
#define WINDIVERT_FILTER_FIELD_ICMPV6_BODY          37
#define WINDIVERT_FILTER_FIELD_TCP_SRCPORT          38
#define WINDIVERT_FILTER_FIELD_TCP_DSTPORT          39
#define WINDIVERT_FILTER_FIELD_TCP_SEQNUM           40
#define WINDIVERT_FILTER_FIELD_TCP_ACKNUM           41
#define WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH        42
#define WINDIVERT_FILTER_FIELD_TCP_URG              43
#define WINDIVERT_FILTER_FIELD_TCP_ACK              44
#define WINDIVERT_FILTER_FIELD_TCP_PSH              45
#define WINDIVERT_FILTER_FIELD_TCP_RST              46
#define WINDIVERT_FILTER_FIELD_TCP_SYN              47
#define WINDIVERT_FILTER_FIELD_TCP_FIN              48
#define WINDIVERT_FILTER_FIELD_TCP_WINDOW           49
#define WINDIVERT_FILTER_FIELD_TCP_CHECKSUM         50
#define WINDIVERT_FILTER_FIELD_TCP_URGPTR           51
#define WINDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH    52
#define WINDIVERT_FILTER_FIELD_UDP_SRCPORT          53
#define WINDIVERT_FILTER_FIELD_UDP_DSTPORT          54
#define WINDIVERT_FILTER_FIELD_UDP_LENGTH           55
#define WINDIVERT_FILTER_FIELD_UDP_CHECKSUM         56
#define WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH    57
#define WINDIVERT_FILTER_FIELD_MAX                  \
    WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH

#define WINDIVERT_FILTER_TEST_EQ                    0
#define WINDIVERT_FILTER_TEST_NEQ                   1
#define WINDIVERT_FILTER_TEST_LT                    2
#define WINDIVERT_FILTER_TEST_LEQ                   3
#define WINDIVERT_FILTER_TEST_GT                    4
#define WINDIVERT_FILTER_TEST_GEQ                   5
#define WINDIVERT_FILTER_TEST_MAX                   WINDIVERT_FILTER_TEST_GEQ

#define WINDIVERT_FILTER_MAXLEN                     128

#define WINDIVERT_FILTER_RESULT_ACCEPT              (WINDIVERT_FILTER_MAXLEN+1)
#define WINDIVERT_FILTER_RESULT_REJECT              (WINDIVERT_FILTER_MAXLEN+2)

/*
 * WinDivert layers.
 */
#define WINDIVERT_LAYER_DEFAULT                     WINDIVERT_LAYER_NETWORK
#define WINDIVERT_LAYER_MAX                                                 \
    WINDIVERT_LAYER_NETWORK_FORWARD

/*
 * WinDivert flags.
 */
#define WINDIVERT_FLAGS_ALL                                                 \
    (WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_DROP |                           \
     WINDIVERT_FLAG_NO_CHECKSUM)
#define WINDIVERT_FLAGS_EXCLUDE(flags, flag1, flag2)                        \
    (((flags) & ((flag1) | (flag2))) != ((flag1) | (flag2)))
#define WINDIVERT_FLAGS_VALID(flags)                                        \
    ((((flags) & ~WINDIVERT_FLAGS_ALL) == 0) &&                             \
     WINDIVERT_FLAGS_EXCLUDE(flags, WINDIVERT_FLAG_SNIFF,                   \
        WINDIVERT_FLAG_DROP))
/*
 * WinDivert priorities.
 */
#define WINDIVERT_PRIORITY(priority16)                                      \
    ((UINT32)((INT32)(priority16) + 0x7FFF + 1))
#define WINDIVERT_PRIORITY_DEFAULT                  WINDIVERT_PRIORITY(0)
#define WINDIVERT_PRIORITY_MAX                      WINDIVERT_PRIORITY(1000)
#define WINDIVERT_PRIORITY_MIN                      WINDIVERT_PRIORITY(-1000)

/*
 * WinDivert parameters.
 */
#define WINDIVERT_PARAM_QUEUE_LEN_DEFAULT           1024
#define WINDIVERT_PARAM_QUEUE_LEN_MIN               1
#define WINDIVERT_PARAM_QUEUE_LEN_MAX               8192
#define WINDIVERT_PARAM_QUEUE_TIME_DEFAULT          512
#define WINDIVERT_PARAM_QUEUE_TIME_MIN              128
#define WINDIVERT_PARAM_QUEUE_TIME_MAX              2048

/*
 * WinDivert message definitions.
 */
#pragma pack(push, 1)
struct windivert_ioctl_s
{
    UINT16 magic;                   // WINDIVERT_IOCTL_MAGIC
    UINT8  version;                 // WINDIVERT_IOCTL_VERSION
    UINT8  arg8;                    // 8-bit argument
    UINT64 arg;                     // 64-bit argument
};
typedef struct windivert_ioctl_s *windivert_ioctl_t;

/*
 * WinDivert IOCTL structures.
 */
struct windivert_ioctl_filter_s
{
    UINT8  field;                   // WINDIVERT_FILTER_FIELD_IP_*
    UINT8  test;                    // WINDIVERT_FILTER_TEST_*
    UINT16 success;                 // Success continuation.
    UINT16 failure;                 // Fail continuation.
    UINT32 arg[4];                  // Argument.
};
typedef struct windivert_ioctl_filter_s *windivert_ioctl_filter_t;
#pragma pack(pop)

/*
 * IOCTL codes.
 */
#define IOCTL_WINDIVERT_RECV                                                \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x908, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WINDIVERT_SEND                                                \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x909, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WINDIVERT_START_FILTER                                        \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90A, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WINDIVERT_SET_LAYER                                           \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90B, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WINDIVERT_SET_PRIORITY                                        \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90C, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WINDIVERT_SET_FLAGS                                           \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90D, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WINDIVERT_SET_PARAM                                           \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90E, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WINDIVERT_GET_PARAM                                           \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x90F, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#endif      /* __WINDIVERT_DEVICE_H */
