/*
 * windivert_shared.c
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

#define WINDIVERT_OBJECT_MAXLEN                                         \
    (8 + 4 + 2 + WINDIVERT_FILTER_MAXLEN * (1 + 1 + 2 + 2 + 4*7 + 3 + 3) + 1)

#define MAX(a, b)                               ((a) > (b)? (a): (b))

/*
 * Definitions to remove (some) external dependencies:
 */
#define BYTESWAP16(x)                   \
    ((((x) >> 8) & 0x00FFu) | (((x) << 8) & 0xFF00u))
#define BYTESWAP32(x)                   \
    ((((x) >> 24) & 0x000000FFu) | (((x) >> 8) & 0x0000FF00u) | \
     (((x) << 8) & 0x00FF0000u) | (((x) << 24) & 0xFF000000u))
#define BYTESWAP64(x)                   \
    ((((x) >> 56) & 0x00000000000000FFull) | \
     (((x) >> 40) & 0x000000000000FF00ull) | \
     (((x) >> 24) & 0x0000000000FF0000ull) | \
     (((x) >> 8)  & 0x00000000FF000000ull) | \
     (((x) << 8)  & 0x000000FF00000000ull) | \
     (((x) << 24) & 0x0000FF0000000000ull) | \
     (((x) << 40) & 0x00FF000000000000ull) | \
     (((x) << 56) & 0xFF00000000000000ull))
#define ntohs(x)                        BYTESWAP16(x)
#define htons(x)                        BYTESWAP16(x)
#define ntohl(x)                        BYTESWAP32(x)
#define htonl(x)                        BYTESWAP32(x)

#if defined(WIN32) && defined(_MSC_VER)
#pragma intrinsic(__emulu)
static UINT64 WinDivertMul64(UINT64 a, UINT64 b)
{
    UINT64 r = __emulu((UINT32)a, (UINT32)b);
    r += __emulu((UINT32)(a >> 32), (UINT32)b) << 32;
    r += __emulu((UINT32)a, (UINT32)(b >> 32)) << 32;
    return r;
}
#define WINDIVERT_MUL64(a, b)   WinDivertMul64(a, b)
#else       /* WIN32 */
#define WINDIVERT_MUL64(a, b)   ((a) * (b))
#endif      /* WIN32 */

/*
 * IPv6 fragment header.
 */
typedef struct
{
    UINT8 NextHdr;
    UINT8 Reserved;
    UINT16 FragOff0;
    UINT32 Id;
} WINDIVERT_IPV6FRAGHDR, *PWINDIVERT_IPV6FRAGHDR;
#define WINDIVERT_IPV6FRAGHDR_GET_FRAGOFF(hdr)                          \
    (((hdr)->FragOff0) & 0xF8FF)
#define WINDIVERT_IPV6FRAGHDR_GET_MF(hdr)                               \
    ((((hdr)->FragOff0) & 0x0100) != 0)

#include "windivert_hash.c"

/*
 * IPv4/IPv6 pseudo headers.
 */
typedef struct
{
    UINT32 SrcAddr;
    UINT32 DstAddr;
    UINT8  Zero;
    UINT8  Protocol;
    UINT16 Length;
} WINDIVERT_PSEUDOHDR, *PWINDIVERT_PSEUDOHDR;

typedef struct
{
    UINT32 SrcAddr[4];
    UINT32 DstAddr[4];
    UINT32 Length;
    UINT32 Zero:24;
    UINT32 NextHdr:8;
} WINDIVERT_PSEUDOV6HDR, *PWINDIVERT_PSEUDOV6HDR;

/*
 * Packet info.
 */
typedef struct
{
    UINT32 HeaderLength:17;
    UINT32 FragOff:13;
    UINT32 Fragment:1;
    UINT32 MF:1;
    UINT32 PayloadLength:16;
    UINT32 Protocol:8;
    UINT32 Truncated:1;
    UINT32 Extended:1;
    UINT32 Reserved1:6;
    PWINDIVERT_IPHDR IPHeader;
    PWINDIVERT_IPV6HDR IPv6Header;
    PWINDIVERT_ICMPHDR ICMPHeader;
    PWINDIVERT_ICMPV6HDR ICMPv6Header;
    PWINDIVERT_TCPHDR TCPHeader;
    PWINDIVERT_UDPHDR UDPHeader;
    UINT8 *Payload;
} WINDIVERT_PACKET, *PWINDIVERT_PACKET;

/*
 * Streams.
 */
typedef struct
{
    char *data;
    UINT pos;
    UINT max;
    BOOL overflow;
} WINDIVERT_STREAM, *PWINDIVERT_STREAM;

/*
 * Prototypes.
 */
static UINT16 WinDivertInitPseudoHeader(PWINDIVERT_IPHDR ip_header,
    PWINDIVERT_IPV6HDR ipv6_header, UINT8 protocol, UINT len,
    void *pseudo_header);
static UINT16 WinDivertCalcChecksum(PVOID pseudo_header,
    UINT16 pseudo_header_len, PVOID data, UINT len);

/*
 * Put a char into a stream.
 */
static void WinDivertPutChar(PWINDIVERT_STREAM stream, char c)
{
    if (stream->pos >= stream->max)
    {
        stream->overflow = TRUE;
        return;
    }
    stream->data[stream->pos] = c;
    stream->pos++;
}

/*
 * Put a string into a stream.
 */
static void WinDivertPutString(PWINDIVERT_STREAM stream, const char *str)
{
    while (*str)
    {
        WinDivertPutChar(stream, *str);
        str++;
    }
}

/*
 * Put a NUL character into a stream.
 */
static void WinDivertPutNul(PWINDIVERT_STREAM stream)
{
    if (stream->pos >= stream->max && stream->max > 0)
    {
        stream->data[stream->max-1] = '\0';     // Truncate
    }
    else
    {
        WinDivertPutChar(stream, '\0');
    }
}

/*
 * Encode a digit.
 */
static char WinDivertEncodeDigit(UINT8 dig, BOOL final)
{
    static const char windivert_digits[64+1] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+=";
    return windivert_digits[(dig & 0x1F) + (final? 32: 0)];
}

/*
 * Serialize a number.
 */
static void WinDivertSerializeNumber(PWINDIVERT_STREAM stream, UINT32 val)
{
    UINT32 mask = 0xC0000000;
    UINT dig = 6;
    UINT8 digit;
    BOOL final;

    while ((mask & val) == 0 && dig != 0)
    {
        mask = (dig == 6? 0x3E000000: mask >> 5);
        dig--;
    }
    while (TRUE)
    {
        final = (dig == 0);
        digit = (UINT8)((mask & val) >> (5 * dig));
        WinDivertPutChar(stream, WinDivertEncodeDigit(digit, final));
        if (final)
        {
            break;
        }
        mask = (dig == 6? 0x3E000000: mask >> 5);
        dig--;
    }
}

/*
 * Serialize a label.
 */
static void WinDivertSerializeLabel(PWINDIVERT_STREAM stream, UINT16 label)
{
    switch (label)
    {
        case WINDIVERT_FILTER_RESULT_ACCEPT:
            WinDivertPutChar(stream, 'A');
            break;
        case WINDIVERT_FILTER_RESULT_REJECT:
            WinDivertPutChar(stream, 'X');
            break;
        default:
            WinDivertPutChar(stream, 'L');
            WinDivertSerializeNumber(stream, label);
            break;
    }
}

/*
 * Serialize a test.
 */
static void WinDivertSerializeTest(PWINDIVERT_STREAM stream,
    const WINDIVERT_FILTER *filter)
{
    INT idx;
    UINT i;

    WinDivertPutChar(stream, '_');
    WinDivertSerializeNumber(stream, filter->field);
    WinDivertSerializeNumber(stream, filter->test);
    WinDivertSerializeNumber(stream, filter->neg);
    WinDivertSerializeNumber(stream, filter->arg[0]);
    switch (filter->field)
    {
        case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
        case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
        case WINDIVERT_FILTER_FIELD_LOCALADDR:
        case WINDIVERT_FILTER_FIELD_REMOTEADDR:
            for (i = 1; i < 4; i++)
            {
                WinDivertSerializeNumber(stream, filter->arg[i]);
            }
            break;
        case WINDIVERT_FILTER_FIELD_ENDPOINTID:
        case WINDIVERT_FILTER_FIELD_PARENTENDPOINTID:
        case WINDIVERT_FILTER_FIELD_TIMESTAMP:
            WinDivertSerializeNumber(stream, filter->arg[1]);
            break;
        case WINDIVERT_FILTER_FIELD_PACKET:
        case WINDIVERT_FILTER_FIELD_PACKET16:
        case WINDIVERT_FILTER_FIELD_PACKET32:
        case WINDIVERT_FILTER_FIELD_TCP_PAYLOAD:
        case WINDIVERT_FILTER_FIELD_TCP_PAYLOAD16:
        case WINDIVERT_FILTER_FIELD_TCP_PAYLOAD32:
        case WINDIVERT_FILTER_FIELD_UDP_PAYLOAD:
        case WINDIVERT_FILTER_FIELD_UDP_PAYLOAD16:
        case WINDIVERT_FILTER_FIELD_UDP_PAYLOAD32:
            idx = (INT)filter->arg[1];
            idx += UINT16_MAX;
            WinDivertSerializeNumber(stream, (UINT32)idx);
            break;
        default:
            break;
    }
    WinDivertSerializeLabel(stream, (UINT16)filter->success);
    WinDivertSerializeLabel(stream, (UINT16)filter->failure);
}

/*
 * Serialize a test.
 */
static void WinDivertSerializeFilter(PWINDIVERT_STREAM stream,
    const WINDIVERT_FILTER *filter, UINT8 length)
{
    UINT8 i;
    WinDivertPutString(stream, "@WinDiv_");     // Magic
    WinDivertSerializeNumber(stream, 0);        // Version
    WinDivertSerializeNumber(stream, length);   // Length
    for (i = 0; i < length; i++)
    {
        WinDivertSerializeTest(stream, filter + i);
    }
    WinDivertPutNul(stream);
}

/*
 * Parse IPv4/IPv6/ICMP/ICMPv6/TCP/UDP headers from a raw packet.
 */
static BOOL WinDivertHelperParsePacketEx(const VOID *pPacket, UINT packetLen,
    PWINDIVERT_PACKET pInfo)
{
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_IPV6HDR ipv6_header = NULL;
    PWINDIVERT_ICMPHDR icmp_header = NULL;
    PWINDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PWINDIVERT_TCPHDR tcp_header = NULL;
    PWINDIVERT_UDPHDR udp_header = NULL;
    PWINDIVERT_IPV6FRAGHDR frag_header;
    UINT8 protocol = 0;
    UINT8 *data = NULL;
    UINT packet_len, total_len, header_len, data_len = 0, frag_off = 0;
    BOOL MF = FALSE, fragment = FALSE, is_ext_header;

    if (pPacket == NULL || packetLen < sizeof(WINDIVERT_IPHDR))
    {
        return FALSE;
    }
    data = (UINT8 *)pPacket;
    data_len = packetLen;

    ip_header = (PWINDIVERT_IPHDR)data;
    switch (ip_header->Version)
    {
        case 4:
            if (packetLen < sizeof(WINDIVERT_IPHDR) ||
                ip_header->HdrLength < 5)
            {
                return FALSE;
            }
            total_len  = (UINT)ntohs(ip_header->Length);
            protocol   = ip_header->Protocol;
            header_len = ip_header->HdrLength * sizeof(UINT32);
            if (total_len < header_len || packetLen < header_len)
            {
                return FALSE;
            }
            frag_off   = ntohs(WINDIVERT_IPHDR_GET_FRAGOFF(ip_header));
            MF         = (WINDIVERT_IPHDR_GET_MF(ip_header) != 0);
            fragment   = (MF || frag_off != 0);
            packet_len = (total_len < packetLen? total_len: packetLen);
            data      += header_len;
            data_len   = packet_len - header_len;
            break;

        case 6:
            ip_header   = NULL;
            ipv6_header = (PWINDIVERT_IPV6HDR)data;
            if (packetLen < sizeof(WINDIVERT_IPV6HDR))
            {
                return FALSE;
            }
            protocol   = ipv6_header->NextHdr;
            total_len  = (UINT)ntohs(ipv6_header->Length) +
                sizeof(WINDIVERT_IPV6HDR);
            packet_len = (total_len < packetLen? total_len: packetLen);
            data      += sizeof(WINDIVERT_IPV6HDR);
            data_len   = packet_len - sizeof(WINDIVERT_IPV6HDR);

            while (frag_off == 0 && data_len >= 2)
            {
                header_len = (UINT)data[1];
                is_ext_header = TRUE;
                switch (protocol)
                {
                    case IPPROTO_FRAGMENT:
                        header_len = 8;
                        if (fragment || data_len < header_len)
                        {
                            is_ext_header = FALSE;
                            break;
                        }
                        frag_header = (PWINDIVERT_IPV6FRAGHDR)data;
                        frag_off    = ntohs(
                            WINDIVERT_IPV6FRAGHDR_GET_FRAGOFF(frag_header));
                        MF          = WINDIVERT_IPV6FRAGHDR_GET_MF(frag_header);
                        fragment    = TRUE;
                        break;
                    case IPPROTO_AH:
                        header_len += 2;
                        header_len *= 4;
                        break;
                    case IPPROTO_HOPOPTS:
                    case IPPROTO_DSTOPTS:
                    case IPPROTO_ROUTING:
                    case IPPROTO_MH:
                        header_len++;
                        header_len *= 8;
                        break;
                    default:
                        is_ext_header = FALSE;
                        break;
                }
                if (!is_ext_header || data_len < header_len)
                {
                    break;
                }
                protocol  = data[0];
                data     += header_len;
                data_len -= header_len;
            }
            break;

        default:
            return FALSE;
    }

    if (frag_off != 0)
    {
        goto WinDivertHelperParsePacketExit;
    }
    switch (protocol)
    {
        case IPPROTO_TCP:
            tcp_header = (PWINDIVERT_TCPHDR)data;
            if (data_len < sizeof(WINDIVERT_TCPHDR) ||
                tcp_header->HdrLength < 5)
            {
                tcp_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            header_len = tcp_header->HdrLength * sizeof(UINT32);
            header_len = (header_len > data_len? data_len: header_len);
            break;

        case IPPROTO_UDP:
            if (data_len < sizeof(WINDIVERT_UDPHDR))
            {
                goto WinDivertHelperParsePacketExit;
            }
            udp_header = (PWINDIVERT_UDPHDR)data;
            header_len = sizeof(WINDIVERT_UDPHDR);
            break;

        case IPPROTO_ICMP:
            if (ip_header == NULL ||
                data_len < sizeof(WINDIVERT_ICMPHDR))
            {
                goto WinDivertHelperParsePacketExit;
            }
            icmp_header = (PWINDIVERT_ICMPHDR)data;
            header_len  = sizeof(WINDIVERT_ICMPHDR);
            break;

        case IPPROTO_ICMPV6:
            if (ipv6_header == NULL ||
                data_len < sizeof(WINDIVERT_ICMPV6HDR))
            {
                goto WinDivertHelperParsePacketExit;
            }
            icmpv6_header = (PWINDIVERT_ICMPV6HDR)data;
            header_len    = sizeof(WINDIVERT_ICMPV6HDR);
            break;

        default:
            goto WinDivertHelperParsePacketExit;
    }
    data     += header_len;
    data_len -= header_len;

WinDivertHelperParsePacketExit:
    if (pInfo == NULL)
    {
        return TRUE;
    }
    data                 = (data_len == 0? NULL: data);
    pInfo->Protocol      = (UINT32)protocol;
    pInfo->Fragment      = (fragment? 1: 0);
    pInfo->MF            = (MF? 1: 0);
    pInfo->FragOff       = (UINT32)frag_off;
    pInfo->Truncated     = (total_len < packetLen? 1: 0);
    pInfo->Extended      = (total_len > packetLen? 1: 0);
    pInfo->Reserved1     = 0;
    pInfo->IPHeader      = ip_header;
    pInfo->IPv6Header    = ipv6_header;
    pInfo->ICMPHeader    = icmp_header;
    pInfo->ICMPv6Header  = icmpv6_header;
    pInfo->TCPHeader     = tcp_header;
    pInfo->UDPHeader     = udp_header;
    pInfo->Payload       = data;
    pInfo->HeaderLength  = (UINT32)(packet_len - data_len);
    pInfo->PayloadLength = (UINT32)data_len;
    return TRUE;
}

/*
 * Calculate IPv4/IPv6/ICMP/ICMPv6/TCP/UDP checksums.
 */
extern BOOL WinDivertHelperCalcChecksums(PVOID pPacket, UINT packetLen,
    WINDIVERT_ADDRESS *pAddr, UINT64 flags)
{
    UINT8 pseudo_header[
        MAX(sizeof(WINDIVERT_PSEUDOHDR), sizeof(WINDIVERT_PSEUDOV6HDR))];
    UINT16 pseudo_header_len;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_ICMPHDR icmp_header;
    PWINDIVERT_ICMPV6HDR icmpv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;
    WINDIVERT_PACKET info;
    UINT payload_len, checksum_len;
    BOOL truncated;

    if (!WinDivertHelperParsePacketEx(pPacket, packetLen, &info))
    {
        return FALSE;
    }

    ip_header = info.IPHeader;
    if (ip_header != NULL && !(flags & WINDIVERT_HELPER_NO_IP_CHECKSUM))
    {
        ip_header->Checksum = 0;
        ip_header->Checksum = WinDivertCalcChecksum(NULL, 0, ip_header,
            ip_header->HdrLength * sizeof(UINT32));
        if (pAddr != NULL)
        {
            pAddr->IPChecksum = 1;
        }
    }

    payload_len = info.PayloadLength;
    truncated   = (info.Truncated || info.MF || info.FragOff != 0);
 
    icmp_header = info.ICMPHeader;
    if (icmp_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_ICMP_CHECKSUM) != 0)
        {
            return TRUE;
        }
        if (truncated)
        {
            return FALSE;
        }
        icmp_header->Checksum = 0;
        icmp_header->Checksum = WinDivertCalcChecksum(NULL, 0,
            icmp_header, payload_len + sizeof(WINDIVERT_ICMPHDR));
        return TRUE;
    }

    icmpv6_header = info.ICMPv6Header;
    if (icmpv6_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM) != 0)
        {
            return TRUE;
        }
        if (truncated)
        {
            return FALSE;
        }
        ipv6_header = info.IPv6Header;
        checksum_len = payload_len + sizeof(WINDIVERT_ICMPV6HDR);
        pseudo_header_len = WinDivertInitPseudoHeader(NULL, ipv6_header, 
            IPPROTO_ICMPV6, checksum_len, pseudo_header);
        icmpv6_header->Checksum = 0;
        icmpv6_header->Checksum = WinDivertCalcChecksum(pseudo_header,
            pseudo_header_len, icmpv6_header, checksum_len);
        return TRUE;
    }

    tcp_header = info.TCPHeader;
    if (tcp_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_TCP_CHECKSUM) != 0)
        {
            return TRUE;
        }
        if (truncated)
        {
            return FALSE;
        }
        checksum_len = payload_len + tcp_header->HdrLength * sizeof(UINT32);
        ipv6_header = info.IPv6Header;
        pseudo_header_len = WinDivertInitPseudoHeader(ip_header,
            ipv6_header, IPPROTO_TCP, checksum_len, pseudo_header);
        tcp_header->Checksum = 0;
        tcp_header->Checksum = WinDivertCalcChecksum(
            pseudo_header, pseudo_header_len, tcp_header, checksum_len);
        if (pAddr != NULL)
        {
            pAddr->TCPChecksum = 1;
        }
        return TRUE;
    }

    udp_header = info.UDPHeader;
    if (udp_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_UDP_CHECKSUM) != 0)
        {
            return TRUE;
        }
        if (truncated)
        {
            return FALSE;
        }
        // Full UDP checksum
        checksum_len = payload_len + sizeof(WINDIVERT_UDPHDR);
        ipv6_header = info.IPv6Header;
        pseudo_header_len = WinDivertInitPseudoHeader(ip_header,
            ipv6_header, IPPROTO_UDP, checksum_len, pseudo_header);
        udp_header->Checksum = 0;
        udp_header->Checksum = WinDivertCalcChecksum(
            pseudo_header, pseudo_header_len, udp_header, checksum_len);
        if (udp_header->Checksum == 0)
        {
            udp_header->Checksum = 0xFFFF;
        }
        if (pAddr != NULL)
        {
            pAddr->UDPChecksum = 1;
        }
        return TRUE;
    }

    return TRUE;
}

/*
 * Initialize the IP/IPv6 pseudo header.
 */
static UINT16 WinDivertInitPseudoHeader(PWINDIVERT_IPHDR ip_header,
    PWINDIVERT_IPV6HDR ipv6_header, UINT8 protocol, UINT len,
    void *pseudo_header)
{
    if (ip_header != NULL)
    {
        PWINDIVERT_PSEUDOHDR pseudo_header_v4 =
            (PWINDIVERT_PSEUDOHDR)pseudo_header;
        pseudo_header_v4->SrcAddr  = ip_header->SrcAddr;
        pseudo_header_v4->DstAddr  = ip_header->DstAddr;
        pseudo_header_v4->Zero     = 0;
        pseudo_header_v4->Protocol = protocol;
        pseudo_header_v4->Length   = htons((UINT16)len);
        return sizeof(WINDIVERT_PSEUDOHDR);
    }
    else
    {
        PWINDIVERT_PSEUDOV6HDR pseudo_header_v6 =
            (PWINDIVERT_PSEUDOV6HDR)pseudo_header;
        memcpy(pseudo_header_v6->SrcAddr, ipv6_header->SrcAddr,
            sizeof(pseudo_header_v6->SrcAddr));
        memcpy(pseudo_header_v6->DstAddr, ipv6_header->DstAddr,
            sizeof(pseudo_header_v6->DstAddr));
        pseudo_header_v6->Length  = htonl((UINT32)len);
        pseudo_header_v6->NextHdr = protocol;
        pseudo_header_v6->Zero    = 0;
        return sizeof(WINDIVERT_PSEUDOV6HDR);
    }
}

/*
 * Generic checksum computation.
 */
static UINT16 WinDivertCalcChecksum(PVOID pseudo_header,
    UINT16 pseudo_header_len, PVOID data, UINT len)
{
    register const UINT16 *data16 = (const UINT16 *)pseudo_header;
    register size_t len16 = pseudo_header_len >> 1;
    register UINT32 sum = 0;
    size_t i;

    // Pseudo header:
    for (i = 0; i < len16; i++)
    {
        sum += (UINT32)data16[i];
    }

    // Main data:
    data16 = (const UINT16 *)data;
    len16 = len >> 1;
    for (i = 0; i < len16; i++)
    {
        sum += (UINT32)data16[i];
    }

    if (len & 0x1)
    {
        const UINT8 *data8 = (const UINT8 *)data;
        sum += (UINT16)data8[len-1];
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    sum = ~sum;
    return (UINT16)sum;
}

/*
 * Decrement the TTL.
 */
extern BOOL WinDivertHelperDecrementTTL(VOID *packet, UINT packetLen)
{
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;

    if (packet == NULL || packetLen < sizeof(WINDIVERT_IPHDR))
    {
        return FALSE;
    }

    ip_header = (PWINDIVERT_IPHDR)packet;
    switch (ip_header->Version)
    {
		case 4:
	        if (ip_header->TTL <= 1)
	        {
	            return FALSE;
	        }
	        ip_header->TTL--;
	
	        // Incremental checksum update:
	        if (ip_header->Checksum >= 0xFFFE)
	        {
	            ip_header->Checksum -= 0xFFFE;
	        }
	        else
	        {
	            ip_header->Checksum += 1;
	        }
            return TRUE;

        case 6:
            if (packetLen < sizeof(WINDIVERT_IPV6HDR))
            {
                return FALSE;
            }
            ipv6_header = (PWINDIVERT_IPV6HDR)packet;
            if (ipv6_header->HopLimit <= 1)
            {
                return FALSE;
            }
            ipv6_header->HopLimit--;
            return TRUE;

        default:
            return FALSE;
    }
}

