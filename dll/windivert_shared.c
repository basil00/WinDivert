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
    ((((x) >> 8) & 0x00FF) | (((x) << 8) & 0xFF00))
#define BYTESWAP32(x)                   \
    ((((x) >> 24) & 0x000000FF) | (((x) >> 8) & 0x0000FF00) | \
     (((x) << 8) & 0x00FF0000) | (((x) << 24) & 0xFF000000))
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
    UINT64 mask = 0x00000007C0000000ull;
    UINT dig = 6;
    UINT8 digit;
    UINT64 val64 = (UINT64)val;
    BOOL final;

    while ((mask & val64) == 0 && dig != 0)
    {
        mask >>= 5;
        dig--;
    }
    while (TRUE)
    {
        final = (dig == 0);
        digit = (UINT8)((mask & val64) >> (5 * dig));
        WinDivertPutChar(stream, WinDivertEncodeDigit(digit, final));
        if (final)
        {
            break;
        }
        mask >>= 5;
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
    WinDivertSerializeLabel(stream, filter->success);
    WinDivertSerializeLabel(stream, filter->failure);
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
 * Skip well-known IPv6 extension headers.
 */
static UINT8 WinDivertSkipExtHeaders(UINT8 proto, UINT8 **header, UINT *len)
{
    UINT hdrlen;

    while (TRUE)
    {
        if (*len <= 2)
        {
            return IPPROTO_NONE;
        }

        hdrlen = (UINT)*(*header + 1);
        switch (proto)
        {
            case IPPROTO_FRAGMENT:
                hdrlen = 8;
                break;
            case IPPROTO_AH:
                hdrlen += 2;
                hdrlen *= 4;
                break;
            case IPPROTO_HOPOPTS:
            case IPPROTO_DSTOPTS:
            case IPPROTO_ROUTING:
                hdrlen++;
                hdrlen *= 8;
                break;
            case IPPROTO_NONE:
                return proto;
            default:
                return proto;
        }

        if (hdrlen >= *len)
        {
            return IPPROTO_NONE;
        }

        proto = **header;
        *header += hdrlen;
        *len -= hdrlen;
    }
}

/*
 * Parse IPv4/IPv6/ICMP/ICMPv6/TCP/UDP headers from a raw packet.
 */
extern BOOL WinDivertHelperParsePacket(const VOID *pPacket, UINT packetLen,
    PWINDIVERT_IPHDR *ppIpHdr, PWINDIVERT_IPV6HDR *ppIpv6Hdr, UINT8 *pProtocol,
    PWINDIVERT_ICMPHDR *ppIcmpHdr, PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
    PWINDIVERT_TCPHDR *ppTcpHdr, PWINDIVERT_UDPHDR *ppUdpHdr, PVOID *ppData,
    UINT *pDataLen, PVOID *ppNext, UINT *pNextLen)
{
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_IPV6HDR ipv6_header = NULL;
    PWINDIVERT_ICMPHDR icmp_header = NULL;
    PWINDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PWINDIVERT_TCPHDR tcp_header = NULL;
    PWINDIVERT_UDPHDR udp_header = NULL;
    UINT16 header_len;
    UINT8 protocol = 0;
    PVOID data = NULL, next = NULL;
    UINT data_len = 0, next_len = 0, packet_len;
    BOOL success = FALSE;

    if (pPacket == NULL || packetLen < sizeof(WINDIVERT_IPHDR))
    {
        goto WinDivertHelperParsePacketExit;
    }
    data = (PVOID)pPacket;
    data_len = packetLen;

    ip_header = (PWINDIVERT_IPHDR)data;
    switch (ip_header->Version)
    {
        case 4:
            if (data_len < sizeof(WINDIVERT_IPHDR) ||
                ip_header->HdrLength < 5) 
            {
                ip_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            packet_len = (UINT)ntohs(ip_header->Length);
            header_len = ip_header->HdrLength*sizeof(UINT32);
            protocol = ip_header->Protocol;
            if (data_len < header_len || data_len < packet_len ||
                packet_len < header_len)
            {
                ip_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            else if (packet_len < data_len)
            {
                next = (PVOID)((UINT8 *)data + packet_len);
                next_len = data_len - packet_len;
            }
            data = (PVOID)((UINT8 *)data + header_len);
            data_len = packet_len - header_len;
            break;
        case 6:
            ip_header = NULL;
            ipv6_header = (PWINDIVERT_IPV6HDR)data;
            if (data_len < sizeof(WINDIVERT_IPV6HDR) ||
                data_len < ntohs(ipv6_header->Length) +
                    sizeof(WINDIVERT_IPV6HDR))
            {
                ipv6_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            protocol = ipv6_header->NextHdr;
            packet_len = ntohs(ipv6_header->Length) + sizeof(WINDIVERT_IPV6HDR);
            if (packet_len < data_len)
            {
                next = (PVOID)((UINT8 *)data + packet_len);
                next_len = data_len - packet_len;
            }
            data = (PVOID)((UINT8 *)data + sizeof(WINDIVERT_IPV6HDR));
            data_len = packet_len - sizeof(WINDIVERT_IPV6HDR);
            protocol = WinDivertSkipExtHeaders(protocol, (UINT8 **)&data,
                &data_len);
            break;
        default:
            ip_header = NULL;
            goto WinDivertHelperParsePacketExit;
    }
    data = (data_len == 0? NULL: data);
    success = TRUE;
    switch (protocol)
    {
        case IPPROTO_TCP:
            tcp_header = (PWINDIVERT_TCPHDR)data;
            if (data_len < sizeof(WINDIVERT_TCPHDR) ||
                tcp_header->HdrLength < 5 ||
                data_len < tcp_header->HdrLength*sizeof(UINT32))
            {
                tcp_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            header_len = tcp_header->HdrLength*sizeof(UINT32);
            data = ((UINT8 *)data + header_len);
            data_len -= header_len;
            break;
        case IPPROTO_UDP:
            udp_header = (PWINDIVERT_UDPHDR)data;
            if (data_len < sizeof(WINDIVERT_UDPHDR) ||
                ntohs(udp_header->Length) != data_len)
            {
                udp_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            data = ((UINT8 *)data + sizeof(WINDIVERT_UDPHDR));
            data_len -= sizeof(WINDIVERT_UDPHDR);
            break;
        case IPPROTO_ICMP:
            icmp_header = (PWINDIVERT_ICMPHDR)data;
            if (ip_header == NULL ||
                data_len < sizeof(WINDIVERT_ICMPHDR))
            {
                icmp_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            data = ((UINT8 *)data + sizeof(WINDIVERT_ICMPHDR));
            data_len -= sizeof(WINDIVERT_ICMPHDR);
            break;
        case IPPROTO_ICMPV6:
            icmpv6_header = (PWINDIVERT_ICMPV6HDR)data;
            if (ipv6_header == NULL ||
                data_len < sizeof(WINDIVERT_ICMPV6HDR))
            {
                icmpv6_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            data = ((UINT8 *)data + sizeof(WINDIVERT_ICMPV6HDR));
            data_len -= sizeof(WINDIVERT_ICMPV6HDR);
            break;
        default:
            break;
    }

    if (data_len == 0)
    {
        data = NULL;
    }

WinDivertHelperParsePacketExit:
    if (pProtocol != NULL)
    {
        *pProtocol = protocol;
    }
    if (ppIpHdr != NULL)
    {
        *ppIpHdr = ip_header;
    }
    if (ppIpv6Hdr != NULL)
    {
        *ppIpv6Hdr = ipv6_header;
    }
    if (ppIcmpHdr != NULL)
    {
        *ppIcmpHdr = icmp_header;
    }
    if (ppIcmpv6Hdr != NULL)
    {
        *ppIcmpv6Hdr = icmpv6_header;
    }
    if (ppTcpHdr != NULL)
    {
        *ppTcpHdr = tcp_header;
    }
    if (ppUdpHdr != NULL)
    {
        *ppUdpHdr = udp_header;
    }
    if (ppData != NULL)
    {
        *ppData = data;
    }
    if (pDataLen != NULL)
    {
        *pDataLen = data_len;
    }
    if (ppNext != NULL)
    {
        *ppNext = next;
    }
    if (pNextLen != NULL)
    {
        *pNextLen = next_len;
    }

    if (ppNext == NULL && pNextLen == NULL && next != NULL)
    {
        success = FALSE;
    }

    return success;
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
    UINT payload_len, checksum_len;

    if (!WinDivertHelperParsePacket(pPacket, packetLen, &ip_header,
            &ipv6_header, NULL, &icmp_header, &icmpv6_header, &tcp_header,
            &udp_header, NULL, &payload_len, NULL, NULL))
    {
        return FALSE;
    }

    if (ip_header != NULL && !(flags & WINDIVERT_HELPER_NO_IP_CHECKSUM))
    {
        ip_header->Checksum = 0;
        ip_header->Checksum = WinDivertCalcChecksum(NULL, 0, ip_header,
            ip_header->HdrLength*sizeof(UINT32));
        if (pAddr != NULL)
        {
            pAddr->IPChecksum = 1;
        }
    }
    
    if (icmp_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_ICMP_CHECKSUM) != 0)
        {
            return TRUE;
        }
        icmp_header->Checksum = 0;
        icmp_header->Checksum = WinDivertCalcChecksum(NULL, 0,
            icmp_header, payload_len + sizeof(WINDIVERT_ICMPHDR));
        return TRUE;
    }
    
    if (icmpv6_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM) != 0)
        {
            return TRUE;
        }
        checksum_len = payload_len + sizeof(WINDIVERT_ICMPV6HDR);
        pseudo_header_len = WinDivertInitPseudoHeader(NULL, ipv6_header, 
            IPPROTO_ICMPV6, checksum_len, pseudo_header);
        icmpv6_header->Checksum = 0;
        icmpv6_header->Checksum = WinDivertCalcChecksum(pseudo_header,
            pseudo_header_len, icmpv6_header, checksum_len);
        return TRUE;
    }
    
    if (tcp_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_TCP_CHECKSUM) != 0)
        {
            return TRUE;
        }
        checksum_len = payload_len + tcp_header->HdrLength*sizeof(UINT32);
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
    
    if (udp_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_UDP_CHECKSUM) != 0)
        {
            return TRUE;
        }
        // Full UDP checksum
        checksum_len = payload_len + sizeof(WINDIVERT_UDPHDR);
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

