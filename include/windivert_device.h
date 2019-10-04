/*
 * windivert_device.h
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

#ifndef __WINDIVERT_DEVICE_H
#define __WINDIVERT_DEVICE_H

/*
 * NOTE: This is the low-level interface to the WinDivert device driver.
 *       This interface should not be used directly, instead use the high-level
 *       interface provided by the WinDivert API.
 */

#define WINDIVERT_KERNEL
#include "windivert.h"

#define WINDIVERT_VERSION_MAJOR                     2
#define WINDIVERT_VERSION_MINOR                     2

#define WINDIVERT_MAGIC_DLL                         0x4C4C447669645724ull
#define WINDIVERT_MAGIC_SYS                         0x5359537669645723ull

#define WINDIVERT_STR2(s)                           #s
#define WINDIVERT_STR(s)                            WINDIVERT_STR2(s)
#define WINDIVERT_LSTR2(s)                          L ## #s
#define WINDIVERT_LSTR(s)                           WINDIVERT_LSTR2(s)

#define WINDIVERT_VERSION_LSTR                                              \
    WINDIVERT_LSTR(WINDIVERT_VERSION_MAJOR) L"."                            \
        WINDIVERT_LSTR(WINDIVERT_VERSION_MINOR)

#define WINDIVERT_DEVICE_NAME                                               \
    L"WinDivert"
#define WINDIVERT_LAYER_NAME                                                \
    WINDIVERT_DEVICE_NAME WINDIVERT_VERSION_LSTR

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
#define WINDIVERT_FILTER_FIELD_LOOPBACK             58
#define WINDIVERT_FILTER_FIELD_IMPOSTOR             59
#define WINDIVERT_FILTER_FIELD_PROCESSID            60
#define WINDIVERT_FILTER_FIELD_LOCALADDR            61
#define WINDIVERT_FILTER_FIELD_REMOTEADDR           62
#define WINDIVERT_FILTER_FIELD_LOCALPORT            63
#define WINDIVERT_FILTER_FIELD_REMOTEPORT           64
#define WINDIVERT_FILTER_FIELD_PROTOCOL             65
#define WINDIVERT_FILTER_FIELD_ENDPOINTID           66
#define WINDIVERT_FILTER_FIELD_PARENTENDPOINTID     67
#define WINDIVERT_FILTER_FIELD_LAYER                68
#define WINDIVERT_FILTER_FIELD_PRIORITY             69
#define WINDIVERT_FILTER_FIELD_EVENT                70
#define WINDIVERT_FILTER_FIELD_PACKET               71
#define WINDIVERT_FILTER_FIELD_PACKET16             72
#define WINDIVERT_FILTER_FIELD_PACKET32             73
#define WINDIVERT_FILTER_FIELD_TCP_PAYLOAD          74
#define WINDIVERT_FILTER_FIELD_TCP_PAYLOAD16        75
#define WINDIVERT_FILTER_FIELD_TCP_PAYLOAD32        76
#define WINDIVERT_FILTER_FIELD_UDP_PAYLOAD          77
#define WINDIVERT_FILTER_FIELD_UDP_PAYLOAD16        78
#define WINDIVERT_FILTER_FIELD_UDP_PAYLOAD32        79
#define WINDIVERT_FILTER_FIELD_LENGTH               80
#define WINDIVERT_FILTER_FIELD_TIMESTAMP            81
#define WINDIVERT_FILTER_FIELD_RANDOM8              82
#define WINDIVERT_FILTER_FIELD_RANDOM16             83
#define WINDIVERT_FILTER_FIELD_RANDOM32             84
#define WINDIVERT_FILTER_FIELD_FRAGMENT             85
#define WINDIVERT_FILTER_FIELD_MAX                  \
    WINDIVERT_FILTER_FIELD_FRAGMENT

#define WINDIVERT_FILTER_TEST_EQ                    0
#define WINDIVERT_FILTER_TEST_NEQ                   1
#define WINDIVERT_FILTER_TEST_LT                    2
#define WINDIVERT_FILTER_TEST_LEQ                   3
#define WINDIVERT_FILTER_TEST_GT                    4
#define WINDIVERT_FILTER_TEST_GEQ                   5
#define WINDIVERT_FILTER_TEST_MAX                   WINDIVERT_FILTER_TEST_GEQ

#define WINDIVERT_FILTER_MAXLEN                     256

#define WINDIVERT_FILTER_RESULT_ACCEPT              0x7FFE
#define WINDIVERT_FILTER_RESULT_REJECT              0x7FFF

/*
 * WinDivert layers.
 */
#define WINDIVERT_LAYER_MAX                         WINDIVERT_LAYER_REFLECT

/*
 * WinDivert events.
 */
#define WINDIVERT_EVENT_MAX                         \
    WINDIVERT_EVENT_REFLECT_CLOSE

/*
 * WinDivert flags.
 */
#define WINDIVERT_FLAGS_ALL                                                 \
    (WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_DROP | WINDIVERT_FLAG_RECV_ONLY |\
        WINDIVERT_FLAG_SEND_ONLY | WINDIVERT_FLAG_NO_INSTALL |              \
        WINDIVERT_FLAG_FRAGMENTS)
#define WINDIVERT_FLAGS_EXCLUDE(flags, flag1, flag2)                        \
    (((flags) & ((flag1) | (flag2))) != ((flag1) | (flag2)))
#define WINDIVERT_FLAGS_VALID(flags)                                        \
    ((((flags) & ~WINDIVERT_FLAGS_ALL) == 0) &&                             \
     WINDIVERT_FLAGS_EXCLUDE(flags, WINDIVERT_FLAG_SNIFF,                   \
        WINDIVERT_FLAG_DROP) &&                                             \
     WINDIVERT_FLAGS_EXCLUDE(flags, WINDIVERT_FLAG_RECV_ONLY,               \
        WINDIVERT_FLAG_SEND_ONLY))

/*
 * WinDivert filter flags.
 */
#define WINDIVERT_FILTER_FLAG_INBOUND               0x0000000000000010ull
#define WINDIVERT_FILTER_FLAG_OUTBOUND              0x0000000000000020ull
#define WINDIVERT_FILTER_FLAG_IP                    0x0000000000000040ull
#define WINDIVERT_FILTER_FLAG_IPV6                  0x0000000000000080ull
#define WINDIVERT_FILTER_FLAG_EVENT_FLOW_DELETED    0x0000000000000100ull
#define WINDIVERT_FILTER_FLAG_EVENT_SOCKET_BIND     0x0000000000000200ull
#define WINDIVERT_FILTER_FLAG_EVENT_SOCKET_CONNECT  0x0000000000000400ull
#define WINDIVERT_FILTER_FLAG_EVENT_SOCKET_LISTEN   0x0000000000000800ull
#define WINDIVERT_FILTER_FLAG_EVENT_SOCKET_ACCEPT   0x0000000000001000ull
#define WINDIVERT_FILTER_FLAG_EVENT_SOCKET_CLOSE    0x0000000000002000ull

#define WINDIVERT_FILTER_FLAGS_ALL                                          \
    (WINDIVERT_FILTER_FLAG_INBOUND |                                        \
        WINDIVERT_FILTER_FLAG_OUTBOUND |                                    \
        WINDIVERT_FILTER_FLAG_IP |                                          \
        WINDIVERT_FILTER_FLAG_IPV6 |                                        \
        WINDIVERT_FILTER_FLAG_EVENT_FLOW_DELETED |                          \
        WINDIVERT_FILTER_FLAG_EVENT_SOCKET_BIND |                           \
        WINDIVERT_FILTER_FLAG_EVENT_SOCKET_CONNECT |                        \
        WINDIVERT_FILTER_FLAG_EVENT_SOCKET_LISTEN |                         \
        WINDIVERT_FILTER_FLAG_EVENT_SOCKET_ACCEPT |                         \
        WINDIVERT_FILTER_FLAG_EVENT_SOCKET_CLOSE)

/*
 * WinDivert priorities.
 */
#define WINDIVERT_PRIORITY_MAX                      WINDIVERT_PRIORITY_HIGHEST
#define WINDIVERT_PRIORITY_MIN                      WINDIVERT_PRIORITY_LOWEST

/*
 * WinDivert timestamps.
 */
#define WINDIVERT_TIMESTAMP_MAX                     0x7FFFFFFFFFFFFFFFull

/*
 * WinDivert message definitions.
 */
#pragma pack(push, 1)
typedef union
{
    struct
    {
        UINT64 addr;                // WINDIVERT_ADDRESS pointer.
        UINT64 addr_len_ptr;        // sizeof(addr) pointer.
    } recv;
    struct
    {
        UINT64 addr;                // WINDIVERT_ADDRESS pointer.
        UINT64 addr_len;            // sizeof(addr).
    } send;
    struct
    {
        UINT32 layer;               // Handle layer.
        UINT32 priority;            // Handle priority.
        UINT64 flags;               // Handle flags.
    } initialize;
    struct
    {
        UINT64 flags;               // Filter flags.
    } startup;
    struct
    {
        UINT32 how;                 // WINDIVERT_SHUTDOWN_*
    } shutdown;
    struct
    {
        UINT32 param;               // WINDIVERT_PARAM_*
    } get_param;
    struct
    {
        UINT64 val;                 // Value pointer.
        UINT32 param;               // WINDIVERT_PARAM_*
    } set_param;
} WINDIVERT_IOCTL, *PWINDIVERT_IOCTL;

/*
 * WinDivert initialization structure.
 */
typedef struct
{
    UINT64 magic;                   // Magic number (in/out).
    UINT32 major;                   // Driver major version (in/out).
    UINT32 minor;                   // Driver minor version (in/out).
    UINT32 bits;                    // 32 or 64 (in/out).
    UINT32 reserved32[3];
    UINT64 reserved64[4];
} WINDIVERT_VERSION, *PWINDIVERT_VERSION;

/*
 * WinDivert filter structure.
 */
typedef struct
{
    UINT32 field:11;                // WINDIVERT_FILTER_FIELD_*
    UINT32 test:5;                  // WINDIVERT_FILTER_TEST_*
    UINT32 success:16;              // Success continuation.
    UINT32 failure:16;              // Fail continuation.
    UINT32 neg:1;                   // Argument negative?
    UINT32 reserved:15;
    UINT32 arg[4];                  // Argument.
} WINDIVERT_FILTER, *PWINDIVERT_FILTER;
#pragma pack(pop)

/*
 * IOCTL codes.
 */
#define IOCTL_WINDIVERT_INITIALIZE                                          \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x921, METHOD_OUT_DIRECT, FILE_READ_DATA |\
        FILE_WRITE_DATA)
#define IOCTL_WINDIVERT_STARTUP                                             \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x922, METHOD_IN_DIRECT, FILE_READ_DATA | \
        FILE_WRITE_DATA)
#define IOCTL_WINDIVERT_RECV                                                \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x923, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define IOCTL_WINDIVERT_SEND                                                \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x924, METHOD_IN_DIRECT, FILE_READ_DATA | \
        FILE_WRITE_DATA)
#define IOCTL_WINDIVERT_SET_PARAM                                           \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x925, METHOD_IN_DIRECT, FILE_READ_DATA | \
        FILE_WRITE_DATA)
#define IOCTL_WINDIVERT_GET_PARAM                                           \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x926, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define IOCTL_WINDIVERT_SHUTDOWN                                            \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x927, METHOD_IN_DIRECT, FILE_READ_DATA | \
        FILE_WRITE_DATA)

#endif      /* __WINDIVERT_DEVICE_H */
