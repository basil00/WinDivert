/*
 * windivert_shared.c
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

#define WINDIVERT_OBJECT_MAXLEN                                         \
    (8 + 4 + 2 + WINDIVERT_FILTER_MAXLEN * (1 + 2 + 2 + 4*7 + 2 + 2) + 1)

#define MAX(a, b)                               ((a) > (b)? (a): (b))

/*
 * Definitions to remove (some) external dependencies:
 */
#define BYTESWAP16(x)                   \
    ((((x) >> 8) & 0x00FF) | (((x) << 8) & 0xFF00))
#define BYTESWAP32(x)                   \
    ((((x) >> 24) & 0x000000FF) | (((x) >> 8) & 0x0000FF00) | \
     (((x) << 8) & 0x00FF0000) | (((x) << 24) & 0xFF000000))
#define ntohs(x)                        BYTESWAP16(x)
#define htons(x)                        BYTESWAP16(x)
#define ntohl(x)                        BYTESWAP32(x)
#define htonl(x)                        BYTESWAP32(x)

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
 * Serialize a number.
 */
static void WinDivertSerializeNumber(PWINDIVERT_STREAM stream, UINT32 val)
{
    UINT64 mask = 0x00000007C0000000ull;
    UINT dig = 6;
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
        WinDivertPutChar(stream, '!' + (char)((mask & val64) >> (5 * dig)) +
            (final? 32: 0));
        if (final)
        {
            break;
        }
        mask >>= 5;
        dig--;
    }
}

/*
 * Serialize a test.
 */
static void WinDivertSerializeTest(PWINDIVERT_STREAM stream,
    PWINDIVERT_FILTER filter)
{
    INT idx;
    UINT i;

    WinDivertPutChar(stream, '_');
    WinDivertSerializeNumber(stream, filter->field);
    WinDivertSerializeNumber(stream, filter->test);
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
    WinDivertSerializeNumber(stream, (UINT8)(filter->success + 2));
    WinDivertSerializeNumber(stream, (UINT8)(filter->failure + 2));
}

/*
 * Serialize a test.
 */
static void WinDivertSerializeFilter(PWINDIVERT_STREAM stream,
    PWINDIVERT_FILTER filter, UINT8 length)
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
static BOOL WinDivertParsePacket(PVOID pPacket, UINT packetLen,
    PWINDIVERT_IPHDR *ppIpHdr, PWINDIVERT_IPV6HDR *ppIpv6Hdr,
    PWINDIVERT_ICMPHDR *ppIcmpHdr, PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
    PWINDIVERT_TCPHDR *ppTcpHdr, PWINDIVERT_UDPHDR *ppUdpHdr, UINT8 *pProto,
    PVOID *ppData, UINT *pDataLen)
{
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_IPV6HDR ipv6_header = NULL;
    PWINDIVERT_ICMPHDR icmp_header = NULL;
    PWINDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PWINDIVERT_TCPHDR tcp_header = NULL;
    PWINDIVERT_UDPHDR udp_header = NULL;
    UINT16 header_len;
    UINT8 trans_proto = 0;
    PVOID data = NULL;
    UINT data_len = 0;
    BOOL success;

    if (pPacket == NULL || packetLen < sizeof(UINT8))
    {
        goto WinDivertHelperParsePacketExit;
    }
    data = pPacket;
    data_len = packetLen;

    ip_header = (PWINDIVERT_IPHDR)data;
    switch (ip_header->Version)
    {
        case 4:
            if (data_len < sizeof(WINDIVERT_IPHDR) ||
                ip_header->HdrLength < 5 ||
                data_len < ip_header->HdrLength*sizeof(UINT32) ||
                ntohs(ip_header->Length) != data_len)
            {
                ip_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            trans_proto = ip_header->Protocol;
            header_len = ip_header->HdrLength*sizeof(UINT32);
            data = (PVOID)((UINT8 *)data + header_len);
            data_len -= header_len;
            break;
        case 6:
            ip_header = NULL;
            ipv6_header = (PWINDIVERT_IPV6HDR)data;
            if (data_len < sizeof(WINDIVERT_IPV6HDR) ||
                ntohs(ipv6_header->Length) !=
                    data_len - sizeof(WINDIVERT_IPV6HDR))
            {
                ipv6_header = NULL;
                goto WinDivertHelperParsePacketExit;
            }
            trans_proto = ipv6_header->NextHdr;
            data = (PVOID)((UINT8 *)data + sizeof(WINDIVERT_IPV6HDR));
            data_len -= sizeof(WINDIVERT_IPV6HDR);
            trans_proto = WinDivertSkipExtHeaders(trans_proto, (UINT8 **)&data,
                &data_len);
            break;
        default:
            ip_header = NULL;
            goto WinDivertHelperParsePacketExit;
    }
    switch (trans_proto)
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
    success = TRUE;
    if (ppIpHdr != NULL)
    {
        *ppIpHdr = ip_header;
        success = success && (ip_header != NULL);
    }
    if (ppIpv6Hdr != NULL)
    {
        *ppIpv6Hdr = ipv6_header;
        success = success && (ipv6_header != NULL);
    }
    if (ppIcmpHdr != NULL)
    {
        *ppIcmpHdr = icmp_header;
        success = success && (icmp_header != NULL);
    }
    if (ppIcmpv6Hdr != NULL)
    {
        *ppIcmpv6Hdr = icmpv6_header;
        success = success && (icmpv6_header != NULL);
    }
    if (ppTcpHdr != NULL)
    {
        *ppTcpHdr = tcp_header;
        success = success && (tcp_header != NULL);
    }
    if (ppUdpHdr != NULL)
    {
        *ppUdpHdr = udp_header;
        success = success && (udp_header != NULL);
    }
    if (pProto != NULL)
    {
        *pProto = trans_proto;
    }
    if (ppData != NULL)
    {
        *ppData = data;
        success = success && (data != NULL);
    }
    if (pDataLen != NULL)
    {
        *pDataLen = data_len;
    }
    return success;
}

/*
 * Calculate IPv4/IPv6/ICMP/ICMPv6/TCP/UDP checksums.
 */
extern UINT WinDivertHelperCalcChecksums(PVOID pPacket, UINT packetLen,
    PWINDIVERT_ADDRESS pAddr, UINT64 flags)
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
    UINT count = 0;

    WinDivertParsePacket(pPacket, packetLen, &ip_header, &ipv6_header,
        &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL, NULL,
        &payload_len);

    if (ip_header != NULL && !(flags & WINDIVERT_HELPER_NO_IP_CHECKSUM))
    {
        ip_header->Checksum = 0;
        if (pAddr == NULL || pAddr->PseudoIPChecksum == 0)
        {
            ip_header->Checksum = WinDivertCalcChecksum(NULL, 0,
                ip_header, ip_header->HdrLength*sizeof(UINT32));
        }
        count++;
    }

    if (icmp_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_ICMP_CHECKSUM) != 0)
        {
            return count;
        }
        icmp_header->Checksum = 0;
        icmp_header->Checksum = WinDivertCalcChecksum(NULL, 0,
            icmp_header, payload_len + sizeof(WINDIVERT_ICMPHDR));
        count++;
        return count;
    }

    if (icmpv6_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM) != 0)
        {
            return count;
        }
        checksum_len = payload_len + sizeof(WINDIVERT_ICMPV6HDR);
        pseudo_header_len = WinDivertInitPseudoHeader(NULL, ipv6_header, 
            IPPROTO_ICMPV6, checksum_len, pseudo_header);
        icmpv6_header->Checksum = 0;
        icmpv6_header->Checksum = WinDivertCalcChecksum(pseudo_header,
            pseudo_header_len, icmpv6_header, checksum_len);
        count++;
        return count;
    }

    if (tcp_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_TCP_CHECKSUM) != 0)
        {
            return count;
        }
        if (pAddr == NULL || pAddr->PseudoTCPChecksum == 0)
        {
            // Full TCP checksum
            checksum_len = payload_len + tcp_header->HdrLength*sizeof(UINT32);
            pseudo_header_len = WinDivertInitPseudoHeader(ip_header,
                ipv6_header, IPPROTO_TCP, checksum_len, pseudo_header);
            tcp_header->Checksum = 0;
            tcp_header->Checksum = WinDivertCalcChecksum(
                pseudo_header, pseudo_header_len, tcp_header, checksum_len);
        }
        else if (pAddr->Outbound)
        {
            // Pseudo TCP checksum
            tcp_header->Checksum = 0;
        }
        count++;
        return count;
    }

    if (udp_header != NULL)
    {
        if ((flags & WINDIVERT_HELPER_NO_UDP_CHECKSUM) != 0)
        {
            return count;
        }
        if (pAddr == NULL || pAddr->PseudoUDPChecksum == 0)
        {
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
        }
        else if (pAddr->Outbound)
        {
            // Pseudo UDP checksum
            udp_header->Checksum = 0;
        }
        count++;
    }
    return count;
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

