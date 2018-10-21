/*
 * windivert_helper.c
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

/****************************************************************************/
/* WINDIVERT HELPER IMPLEMENTATION                                          */
/****************************************************************************/

/*
 * Protocols.
 */
#define IPPROTO_HOPOPTS     0
#define IPPROTO_ICMP        1
#define IPPROTO_TCP         6
#define IPPROTO_UDP         17
#define IPPROTO_ROUTING     43
#define IPPROTO_FRAGMENT    44
#define IPPROTO_AH          51
#define IPPROTO_ICMPV6      58
#define IPPROTO_NONE        59
#define IPPROTO_DSTOPTS     60

/*
 * Filter tokens.
 */
typedef enum
{
    TOKEN_ICMP,
    TOKEN_ICMP_BODY,
    TOKEN_ICMP_CHECKSUM,
    TOKEN_ICMP_CODE,
    TOKEN_ICMP_TYPE,
    TOKEN_ICMPV6,
    TOKEN_ICMPV6_BODY,
    TOKEN_ICMPV6_CHECKSUM,
    TOKEN_ICMPV6_CODE,
    TOKEN_ICMPV6_TYPE,
    TOKEN_IP,
    TOKEN_IP_CHECKSUM,
    TOKEN_IP_DF,
    TOKEN_IP_DST_ADDR,
    TOKEN_IP_FRAG_OFF,
    TOKEN_IP_HDR_LENGTH,
    TOKEN_IP_ID,
    TOKEN_IP_LENGTH,
    TOKEN_IP_MF,
    TOKEN_IP_PROTOCOL,
    TOKEN_IP_SRC_ADDR,
    TOKEN_IP_TOS,
    TOKEN_IP_TTL,
    TOKEN_IPV6,
    TOKEN_IPV6_DST_ADDR,
    TOKEN_IPV6_FLOW_LABEL,
    TOKEN_IPV6_HOP_LIMIT,
    TOKEN_IPV6_LENGTH,
    TOKEN_IPV6_NEXT_HDR,
    TOKEN_IPV6_SRC_ADDR,
    TOKEN_IPV6_TRAFFIC_CLASS,
    TOKEN_TCP,
    TOKEN_TCP_ACK,
    TOKEN_TCP_ACK_NUM,
    TOKEN_TCP_CHECKSUM,
    TOKEN_TCP_DST_PORT,
    TOKEN_TCP_FIN,
    TOKEN_TCP_HDR_LENGTH,
    TOKEN_TCP_PAYLOAD_LENGTH,
    TOKEN_TCP_PSH,
    TOKEN_TCP_RST,
    TOKEN_TCP_SEQ_NUM,
    TOKEN_TCP_SRC_PORT,
    TOKEN_TCP_SYN,
    TOKEN_TCP_URG,
    TOKEN_TCP_URG_PTR,
    TOKEN_TCP_WINDOW,
    TOKEN_UDP,
    TOKEN_UDP_CHECKSUM,
    TOKEN_UDP_DST_PORT,
    TOKEN_UDP_LENGTH,
    TOKEN_UDP_PAYLOAD_LENGTH,
    TOKEN_UDP_SRC_PORT,
    TOKEN_ZERO,
    TOKEN_TRUE,
    TOKEN_FALSE,
    TOKEN_INBOUND,
    TOKEN_OUTBOUND,
    TOKEN_IF_IDX,
    TOKEN_SUB_IF_IDX,
    TOKEN_LOOPBACK,
    TOKEN_IMPOSTOR,
    TOKEN_PROCESS_ID,
    TOKEN_LOCAL_ADDR,
    TOKEN_REMOTE_ADDR,
    TOKEN_LOCAL_PORT,
    TOKEN_REMOTE_PORT,
    TOKEN_PROTOCOL,
    TOKEN_LAYER,
    TOKEN_FLOW,
    TOKEN_NETWORK,
    TOKEN_NETWORK_FORWARD,
    TOKEN_REFLECT,
    TOKEN_OPEN,
    TOKEN_CLOSE,
    TOKEN_EQ,
    TOKEN_NEQ,
    TOKEN_LT,
    TOKEN_LEQ,
    TOKEN_GT,
    TOKEN_GEQ,
    TOKEN_NOT,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_COLON,
    TOKEN_QUESTION,
    TOKEN_NUMBER,
    TOKEN_END,
} KIND;

typedef struct
{
    KIND kind;
    UINT pos;
    UINT32 val[4];
} TOKEN;
#define TOKEN_MAXLEN             32

typedef struct
{
    char *name;
    KIND kind;
} TOKEN_NAME, *PTOKEN_NAME;

/*
 * Filter expressions.
 */
typedef struct EXPR EXPR;
typedef struct EXPR *PEXPR;
struct EXPR
{
    union
    {
        UINT32 val[4];
        PEXPR arg[3];
    };
    UINT8 kind;
    UINT8 count;
    UINT16 succ;
    UINT16 fail;
};

/*
 * Error handling.
 */
#undef ERROR
typedef UINT64 ERROR, *PERROR;

#define WINDIVERT_ERROR_NONE                    0
#define WINDIVERT_ERROR_NO_MEMORY               1
#define WINDIVERT_ERROR_TOO_DEEP                2
#define WINDIVERT_ERROR_TOO_LONG                3
#define WINDIVERT_ERROR_BAD_TOKEN               4
#define WINDIVERT_ERROR_BAD_TOKEN_FOR_LAYER     5
#define WINDIVERT_ERROR_UNEXPECTED_TOKEN        6
#define WINDIVERT_ERROR_OUTPUT_TOO_SHORT        7
#define WINDIVERT_ERROR_BAD_OBJECT              8
#define WINDIVERT_ERROR_ASSERTION_FAILED        9

#define MAKE_ERROR(code, pos)                   \
    (((ERROR)(code) << 32) | (ERROR)(pos));
#define GET_CODE(err)                           \
    ((UINT)((err) >> 32))
#define GET_POS(err)                            \
    ((UINT)((err) & 0xFFFFFFFF))
#undef IS_ERROR
#define IS_ERROR(err)                           \
    (GET_CODE(err) != WINDIVERT_ERROR_NONE)

#define MAX(a, b)                               ((a) > (b)? (a): (b))
                                
/*
 * Prototypes.
 */
static PEXPR WinDivertParseFilter(HANDLE pool, TOKEN *toks, UINT *i,
    INT depth, BOOL and, PERROR error);
static BOOL WinDivertCondExecFilter(PWINDIVERT_FILTER filter, UINT length,
    UINT8 field, UINT32 arg);
static UINT16 WinDivertInitPseudoHeader(PWINDIVERT_IPHDR ip_header,
    PWINDIVERT_IPV6HDR ipv6_header, UINT8 protocol, UINT len,
    void *pseudo_header);
static UINT16 WinDivertHelperCalcChecksum(PVOID pseudo_header,
    UINT16 pseudo_header_len, PVOID data, UINT len);
static BOOL WinDivertDeserializeFilter(PWINDIVERT_STREAM stream,
    PWINDIVERT_FILTER filter, UINT *length);
static void WinDivertFormatExpr(PWINDIVERT_STREAM stream, PEXPR expr,
    BOOL top_level, BOOL and);

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
extern BOOL WinDivertHelperParsePacket(PVOID pPacket, UINT packetLen,
    PWINDIVERT_IPHDR *ppIpHdr, PWINDIVERT_IPV6HDR *ppIpv6Hdr,
    PWINDIVERT_ICMPHDR *ppIcmpHdr, PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
    PWINDIVERT_TCPHDR *ppTcpHdr, PWINDIVERT_UDPHDR *ppUdpHdr, PVOID *ppData,
    UINT *pDataLen)
{
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_IPV6HDR ipv6_header = NULL;
    PWINDIVERT_ICMPHDR icmp_header = NULL;
    PWINDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PWINDIVERT_TCPHDR tcp_header = NULL;
    PWINDIVERT_UDPHDR udp_header = NULL;
    UINT16 header_len;
    UINT8 trans_proto;
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

    WinDivertHelperParsePacket(pPacket, packetLen, &ip_header, &ipv6_header,
        &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL,
        &payload_len);

    if (ip_header != NULL && !(flags & WINDIVERT_HELPER_NO_IP_CHECKSUM))
    {
        ip_header->Checksum = 0;
        if (pAddr == NULL || pAddr->PseudoIPChecksum == 0)
        {
            ip_header->Checksum = WinDivertHelperCalcChecksum(NULL, 0,
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
        icmp_header->Checksum = WinDivertHelperCalcChecksum(NULL, 0,
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
        icmpv6_header->Checksum = WinDivertHelperCalcChecksum(pseudo_header,
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
            tcp_header->Checksum = WinDivertHelperCalcChecksum(
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
            udp_header->Checksum = WinDivertHelperCalcChecksum(
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
static UINT16 WinDivertHelperCalcChecksum(PVOID pseudo_header,
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
 * Parse an IPv4 address.
 */
extern BOOL WinDivertHelperParseIPv4Address(const char *str, UINT32 *addr_ptr)
{
    UINT32 addr = 0;
    UINT32 part, i;

    if (str == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    for (i = 0; i < 4; i++)
    {
        if (!WinDivertAToI(str, (char **)&str, &part) || part > UINT8_MAX)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if (i != 3 && *str++ != '.')
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        addr |= part << (8*(3-i));
    }
    if (*str != '\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (addr_ptr != NULL)
    {
        *addr_ptr = addr;
    }
    return TRUE;
}

/*
 * Parse an IPv6 address.
 */
extern BOOL WinDivertHelperParseIPv6Address(const char *str, UINT32 *addr_ptr)
{
    UINT16 laddr[8];
    UINT16 raddr[8];
    BOOL left = TRUE;
    UINT i, j, k, l, part;
    char part_str[5];

    memset(laddr, 0, sizeof(laddr));
    memset(raddr, 0, sizeof(raddr));

    if (*str == ':')
    {
        str++;
        if (*str != ':')
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        left = FALSE;
        str++;
    }

    for (i = 0, j = 0, k = 0; k < 8; k++)
    {
        if (*str == ':')
        {
            if (!left)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            left = FALSE;
            str++;
        }
        for (l = 0; l < 4 && WinDivertIsXDigit(*str); l++)
        {
            part_str[l] = *str;
            str++;
        }
        if (l == 0)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        part_str[l] = '\0';
        if (*str != ':' && *str != '\0')
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        WinDivertAToX(part_str, NULL, &part);
        if (left)
        {
            laddr[i++] = (UINT16)part;
        }
        else
        {
            raddr[j++] = (UINT16)part;
        }
        if (*str == '\0')
        {
            if (!left)
            {
                break;
            }
            if (k == 7)
            {
                break;
            }
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        str++;
    }
    if (*str != '\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    if (addr_ptr == NULL)
    {
        return TRUE;
    }
    
    for (i = 0; i < 4; i++)
    {
        k = 2 * i + j;
        l = k + 1;
        k = (k >= 8? k - 8: k);
        l = (l >= 8? l - 8: l);
        addr_ptr[3 - i] =
            (UINT32)laddr[2 * i + 1] |
            (UINT32)laddr[2 * i] << 16 |
            (UINT32)raddr[l] |
            (UINT32)raddr[k] << 16;
    }
    return TRUE;
}

/*
 * Lookup a token.
 */
static PTOKEN_NAME WinDivertTokenLookup(PTOKEN_NAME token_names,
    size_t token_names_len, const char *name)
{
    int lo = 0, hi = (int)token_names_len-1, mid;
    int cmp;
    while (hi >= lo)
    {
        mid = (lo + hi) / 2;
        cmp = WinDivertStrCmp(token_names[mid].name, name);
        if (cmp < 0)
        {
            lo = mid+1;
        }
        else if (cmp > 0)
        {
            hi = mid-1;
        }
        else
        {
            return &token_names[mid];
        }
    }
    return NULL;
}

/*
 * Validate token for layer.
 */
static BOOL WinDivertCheckTokenKindForLayer(WINDIVERT_LAYER layer, KIND kind)
{
    switch (layer)
    {
        case WINDIVERT_LAYER_NETWORK:
        case WINDIVERT_LAYER_NETWORK_FORWARD:
            switch (kind)
            {
                case TOKEN_INBOUND:
                case TOKEN_OUTBOUND:
                    return (layer != WINDIVERT_LAYER_NETWORK_FORWARD);
                case TOKEN_PROCESS_ID:
                case TOKEN_LOCAL_ADDR:
                case TOKEN_REMOTE_ADDR:
                case TOKEN_LOCAL_PORT:
                case TOKEN_REMOTE_PORT:
                case TOKEN_PROTOCOL:
                case TOKEN_LAYER:
                case TOKEN_FLOW:
                case TOKEN_NETWORK:
                case TOKEN_NETWORK_FORWARD:
                case TOKEN_REFLECT:
                    return FALSE;
                default:
                    return TRUE;
            }
        case WINDIVERT_LAYER_FLOW:
            switch (kind)
            {
                case TOKEN_ICMP_BODY:
                case TOKEN_ICMP_CHECKSUM:
                case TOKEN_ICMP_CODE:
                case TOKEN_ICMP_TYPE:
                case TOKEN_ICMPV6_BODY:
                case TOKEN_ICMPV6_CHECKSUM:
                case TOKEN_ICMPV6_CODE:
                case TOKEN_ICMPV6_TYPE:
                case TOKEN_IP_CHECKSUM:
                case TOKEN_IP_DF:
                case TOKEN_IP_DST_ADDR:
                case TOKEN_IP_FRAG_OFF:
                case TOKEN_IP_HDR_LENGTH:
                case TOKEN_IP_ID:
                case TOKEN_IP_LENGTH:
                case TOKEN_IP_MF:
                case TOKEN_IP_PROTOCOL:
                case TOKEN_IP_SRC_ADDR:
                case TOKEN_IP_TOS:
                case TOKEN_IP_TTL:
                case TOKEN_IPV6_DST_ADDR:
                case TOKEN_IPV6_FLOW_LABEL:
                case TOKEN_IPV6_HOP_LIMIT:
                case TOKEN_IPV6_LENGTH:
                case TOKEN_IPV6_NEXT_HDR:
                case TOKEN_IPV6_SRC_ADDR:
                case TOKEN_IPV6_TRAFFIC_CLASS:
                case TOKEN_TCP_ACK:
                case TOKEN_TCP_ACK_NUM:
                case TOKEN_TCP_CHECKSUM:
                case TOKEN_TCP_DST_PORT:
                case TOKEN_TCP_FIN:
                case TOKEN_TCP_HDR_LENGTH:
                case TOKEN_TCP_PAYLOAD_LENGTH:
                case TOKEN_TCP_PSH:
                case TOKEN_TCP_RST:
                case TOKEN_TCP_SEQ_NUM:
                case TOKEN_TCP_SRC_PORT:
                case TOKEN_TCP_SYN:
                case TOKEN_TCP_URG:
                case TOKEN_TCP_URG_PTR:
                case TOKEN_TCP_WINDOW:
                case TOKEN_UDP_CHECKSUM:
                case TOKEN_UDP_DST_PORT:
                case TOKEN_UDP_LENGTH:
                case TOKEN_UDP_PAYLOAD_LENGTH:
                case TOKEN_UDP_SRC_PORT:
                case TOKEN_IF_IDX:
                case TOKEN_SUB_IF_IDX:
                case TOKEN_IMPOSTOR:
                case TOKEN_LAYER:
                case TOKEN_FLOW:
                case TOKEN_NETWORK:
                case TOKEN_NETWORK_FORWARD:
                case TOKEN_REFLECT:
                    return FALSE;
                default:
                    return TRUE;
            }
        case WINDIVERT_LAYER_REFLECT:
            switch (kind)
            {
                case TOKEN_ICMP_BODY:
                case TOKEN_ICMP_CHECKSUM:
                case TOKEN_ICMP_CODE:
                case TOKEN_ICMP_TYPE:
                case TOKEN_ICMPV6_BODY:
                case TOKEN_ICMPV6_CHECKSUM:
                case TOKEN_ICMPV6_CODE:
                case TOKEN_ICMPV6_TYPE:
                case TOKEN_IP_CHECKSUM:
                case TOKEN_IP_DF:
                case TOKEN_IP_DST_ADDR:
                case TOKEN_IP_FRAG_OFF:
                case TOKEN_IP_HDR_LENGTH:
                case TOKEN_IP_ID:
                case TOKEN_IP_LENGTH:
                case TOKEN_IP_MF:
                case TOKEN_IP_PROTOCOL:
                case TOKEN_IP_SRC_ADDR:
                case TOKEN_IP_TOS:
                case TOKEN_IP_TTL:
                case TOKEN_IPV6_DST_ADDR:
                case TOKEN_IPV6_FLOW_LABEL:
                case TOKEN_IPV6_HOP_LIMIT:
                case TOKEN_IPV6_LENGTH:
                case TOKEN_IPV6_NEXT_HDR:
                case TOKEN_IPV6_SRC_ADDR:
                case TOKEN_IPV6_TRAFFIC_CLASS:
                case TOKEN_TCP_ACK:
                case TOKEN_TCP_ACK_NUM:
                case TOKEN_TCP_CHECKSUM:
                case TOKEN_TCP_DST_PORT:
                case TOKEN_TCP_FIN:
                case TOKEN_TCP_HDR_LENGTH:
                case TOKEN_TCP_PAYLOAD_LENGTH:
                case TOKEN_TCP_PSH:
                case TOKEN_TCP_RST:
                case TOKEN_TCP_SEQ_NUM:
                case TOKEN_TCP_SRC_PORT:
                case TOKEN_TCP_SYN:
                case TOKEN_TCP_URG:
                case TOKEN_TCP_URG_PTR:
                case TOKEN_TCP_WINDOW:
                case TOKEN_UDP_CHECKSUM:
                case TOKEN_UDP_DST_PORT:
                case TOKEN_UDP_LENGTH:
                case TOKEN_UDP_PAYLOAD_LENGTH:
                case TOKEN_UDP_SRC_PORT:
                case TOKEN_IP:
                case TOKEN_IPV6:
                case TOKEN_ICMP:
                case TOKEN_ICMPV6:
                case TOKEN_TCP:
                case TOKEN_UDP:
                case TOKEN_LOOPBACK:
                case TOKEN_IF_IDX:
                case TOKEN_SUB_IF_IDX:
                case TOKEN_IMPOSTOR:
                case TOKEN_INBOUND:
                case TOKEN_OUTBOUND:
                case TOKEN_LOCAL_ADDR:
                case TOKEN_REMOTE_ADDR:
                case TOKEN_LOCAL_PORT:
                case TOKEN_REMOTE_PORT:
                case TOKEN_PROTOCOL:
                    return FALSE;
                default:
                    return TRUE;
            }
        default:
            return FALSE;
    }
}

/*
 * Expand a "macro" value.
 */
static BOOL WinDivertExpandMacro(KIND kind, UINT32 *val)
{
    switch (kind)
    {
        case TOKEN_NETWORK:
            *val = WINDIVERT_LAYER_NETWORK;
            return TRUE;
        case TOKEN_NETWORK_FORWARD:
            *val = WINDIVERT_LAYER_NETWORK_FORWARD;
            return TRUE;
        case TOKEN_FLOW:
            *val = WINDIVERT_LAYER_FLOW;
            return TRUE;
        case TOKEN_REFLECT:
            *val = WINDIVERT_LAYER_REFLECT;
            return TRUE;
        default:
            return FALSE;
    }
}

/*
 * Tokenize the given filter string.
 */
static ERROR WinDivertTokenizeFilter(const char *filter, WINDIVERT_LAYER layer,
    TOKEN *tokens, UINT tokensmax)
{
    static const TOKEN_NAME token_names[] =
    {
        {"FLOW",                TOKEN_FLOW},
        {"NETWORK",             TOKEN_NETWORK},
        {"NETWORK_FORWARD",     TOKEN_NETWORK_FORWARD},
        {"REFLECT",             TOKEN_REFLECT},
        {"and",                 TOKEN_AND},
        {"false",               TOKEN_FALSE},
        {"icmp",                TOKEN_ICMP},
        {"icmp.Body",           TOKEN_ICMP_BODY},
        {"icmp.Checksum",       TOKEN_ICMP_CHECKSUM},
        {"icmp.Code",           TOKEN_ICMP_CODE},
        {"icmp.Type",           TOKEN_ICMP_TYPE},
        {"icmpv6",              TOKEN_ICMPV6},
        {"icmpv6.Body",         TOKEN_ICMPV6_BODY},
        {"icmpv6.Checksum",     TOKEN_ICMPV6_CHECKSUM},
        {"icmpv6.Code",         TOKEN_ICMPV6_CODE},
        {"icmpv6.Type",         TOKEN_ICMPV6_TYPE},
        {"ifIdx",               TOKEN_IF_IDX},
        {"impostor",            TOKEN_IMPOSTOR},
        {"inbound",             TOKEN_INBOUND},
        {"ip",                  TOKEN_IP},
        {"ip.Checksum",         TOKEN_IP_CHECKSUM},
        {"ip.DF",               TOKEN_IP_DF},
        {"ip.DstAddr",          TOKEN_IP_DST_ADDR},
        {"ip.FragOff",          TOKEN_IP_FRAG_OFF},
        {"ip.HdrLength",        TOKEN_IP_HDR_LENGTH},
        {"ip.Id",               TOKEN_IP_ID},
        {"ip.Length",           TOKEN_IP_LENGTH},
        {"ip.MF",               TOKEN_IP_MF},
        {"ip.Protocol",         TOKEN_IP_PROTOCOL},
        {"ip.SrcAddr",          TOKEN_IP_SRC_ADDR},
        {"ip.TOS",              TOKEN_IP_TOS},
        {"ip.TTL",              TOKEN_IP_TTL},
        {"ipv6",                TOKEN_IPV6},
        {"ipv6.DstAddr",        TOKEN_IPV6_DST_ADDR},
        {"ipv6.FlowLabel",      TOKEN_IPV6_FLOW_LABEL},
        {"ipv6.HopLimit",       TOKEN_IPV6_HOP_LIMIT},
        {"ipv6.Length",         TOKEN_IPV6_LENGTH},
        {"ipv6.NextHdr",        TOKEN_IPV6_NEXT_HDR},
        {"ipv6.SrcAddr",        TOKEN_IPV6_SRC_ADDR},
        {"ipv6.TrafficClass",   TOKEN_IPV6_TRAFFIC_CLASS},
        {"layer",               TOKEN_LAYER},
        {"localAddr",           TOKEN_LOCAL_ADDR},
        {"localPort",           TOKEN_LOCAL_PORT},
        {"loopback",            TOKEN_LOOPBACK},
        {"not",                 TOKEN_NOT},
        {"or",                  TOKEN_OR},
        {"outbound",            TOKEN_OUTBOUND},
        {"processId",           TOKEN_PROCESS_ID},
        {"protocol",            TOKEN_PROTOCOL},
        {"remoteAddr",          TOKEN_REMOTE_ADDR},
        {"remotePort",          TOKEN_REMOTE_PORT},
        {"subIfIdx",            TOKEN_SUB_IF_IDX},
        {"tcp",                 TOKEN_TCP},
        {"tcp.Ack",             TOKEN_TCP_ACK},
        {"tcp.AckNum",          TOKEN_TCP_ACK_NUM},
        {"tcp.Checksum",        TOKEN_TCP_CHECKSUM},
        {"tcp.DstPort",         TOKEN_TCP_DST_PORT},
        {"tcp.Fin",             TOKEN_TCP_FIN},
        {"tcp.HdrLength",       TOKEN_TCP_HDR_LENGTH},
        {"tcp.PayloadLength",   TOKEN_TCP_PAYLOAD_LENGTH},
        {"tcp.Psh",             TOKEN_TCP_PSH},
        {"tcp.Rst",             TOKEN_TCP_RST},
        {"tcp.SeqNum",          TOKEN_TCP_SEQ_NUM},
        {"tcp.SrcPort",         TOKEN_TCP_SRC_PORT},
        {"tcp.Syn",             TOKEN_TCP_SYN},
        {"tcp.Urg",             TOKEN_TCP_URG},
        {"tcp.UrgPtr",          TOKEN_TCP_URG_PTR},
        {"tcp.Window",          TOKEN_TCP_WINDOW},
        {"true",                TOKEN_TRUE},
        {"udp",                 TOKEN_UDP},
        {"udp.Checksum",        TOKEN_UDP_CHECKSUM},
        {"udp.DstPort",         TOKEN_UDP_DST_PORT},
        {"udp.Length",          TOKEN_UDP_LENGTH},
        {"udp.PayloadLength",   TOKEN_UDP_PAYLOAD_LENGTH},
        {"udp.SrcPort",         TOKEN_UDP_SRC_PORT},
        {"zero",                TOKEN_ZERO},
    };
    TOKEN_NAME *result;
    char c;
    char token[TOKEN_MAXLEN];
    UINT i = 0, j;
    UINT tp = 0;

    while (TRUE)
    {
        if (tp >= tokensmax-1)
        {
            return MAKE_ERROR(WINDIVERT_ERROR_TOO_LONG, i);
        }
        memset(tokens[tp].val, 0, sizeof(tokens[tp].val));
        while (WinDivertIsSpace(filter[i]))
        {
            i++;
        }
        tokens[tp].pos = i;
        c = filter[i++];
        switch (c)
        {
            case '\0':
                tokens[tp].kind = TOKEN_END;
                return MAKE_ERROR(WINDIVERT_ERROR_NONE, 0);
            case '(':
                tokens[tp++].kind = TOKEN_OPEN;
                continue;
            case ')':
                tokens[tp++].kind = TOKEN_CLOSE;
                continue;
            case '!':
                if (filter[i] == '=')
                {
                    i++;
                    tokens[tp++].kind = TOKEN_NEQ;
                }
                else
                {
                    tokens[tp++].kind = TOKEN_NOT;
                }
                continue;
            case '=':
                if (filter[i] == '=')
                {
                    i++;
                }
                tokens[tp++].kind = TOKEN_EQ;
                continue;
            case '<':
                if (filter[i] == '=')
                {
                    i++;
                    tokens[tp++].kind = TOKEN_LEQ;
                }
                else
                {
                    tokens[tp++].kind = TOKEN_LT;
                }
                continue;
            case '>':
                if (filter[i] == '=')
                {
                    i++;
                    tokens[tp++].kind = TOKEN_GEQ;
                }
                else
                {
                    tokens[tp++].kind = TOKEN_GT;
                }
                continue;
            case ':':
                if (filter[i] == ':')
                {
                    break;      // Probably ipv6 address, e.g. ::1.
                }
                tokens[tp++].kind = TOKEN_COLON;
                continue;
            case '?':
                tokens[tp++].kind = TOKEN_QUESTION;
                continue;
            case '&':
                if (filter[i++] != '&')
                {
                    return MAKE_ERROR(WINDIVERT_ERROR_BAD_TOKEN, i-1);
                }
                tokens[tp++].kind = TOKEN_AND;
                continue;
            case '|':
                if (filter[i++] != '|')
                {
                    return MAKE_ERROR(WINDIVERT_ERROR_BAD_TOKEN, i-1);
                }
                tokens[tp++].kind = TOKEN_OR;
                continue;
            default:
                break;
        }
        token[0] = c;
        if (WinDivertIsAlNum(c) || c == '.' || c == ':' || c == '_')
        {
            UINT32 num;
            char *end;
            for (j = 1; j < TOKEN_MAXLEN && (WinDivertIsAlNum(filter[i]) ||
                    filter[i] == '.' || filter[i] == ':' || filter[i] == '_');
                    j++, i++)
            {
                token[j] = filter[i];
            }
            if (j >= TOKEN_MAXLEN)
            {
                return MAKE_ERROR(WINDIVERT_ERROR_BAD_TOKEN, i-j);
            }
            token[j] = '\0';

            // Handle trailing colons:
            if (j >= 1 && token[j-1] == ':')
            {
                if (j == 1 || token[j-2] != ':')
                {
                    token[j-1] = '\0';
                    i--;
                }
            }

            // Check for symbol:
            result = WinDivertTokenLookup((PTOKEN_NAME)token_names,
                sizeof(token_names) / sizeof(TOKEN_NAME), token);
            if (result != NULL)
            {
                if (!WinDivertCheckTokenKindForLayer(layer, result->kind))
                {
                    return MAKE_ERROR(WINDIVERT_ERROR_BAD_TOKEN_FOR_LAYER, i-j);
                }
                if (WinDivertExpandMacro(result->kind, &tokens[tp].val[0]))
                {
                    tokens[tp].kind = TOKEN_NUMBER;
                }
                else
                {
                    tokens[tp].kind = result->kind;
                }
                tp++;
                continue;
            }

            // Check for base 10 number:
            if (WinDivertAToI(token, &end, &num) && *end == '\0')
            {
                tokens[tp].kind   = TOKEN_NUMBER;
                tokens[tp].val[0] = num;
                tp++;
                continue;
            }

            // Check for base 16 number:
            if (WinDivertAToX(token, &end, &num) && *end == '\0')
            {
                tokens[tp].kind   = TOKEN_NUMBER;
                tokens[tp].val[0] = num;
                tp++;
                continue;
            }
            // Check for IPv4 address:
            if (WinDivertHelperParseIPv4Address(token, tokens[tp].val))
            {
                tokens[tp].val[1] = 0x0000FFFF;
                tokens[tp].kind = TOKEN_NUMBER;
                tp++;
                continue;
            }

            // Check for IPv6 address:
            SetLastError(0);
            if (WinDivertHelperParseIPv6Address(token, tokens[tp].val))
            {
                tokens[tp].kind = TOKEN_NUMBER;
                tp++;
                continue;
            }

            return MAKE_ERROR(WINDIVERT_ERROR_BAD_TOKEN, i-j);
        }
        else
        {
            return MAKE_ERROR(WINDIVERT_ERROR_BAD_TOKEN, i);
        }
    }
}

/*
 * Construct a variable/field.
 */
static PEXPR WinDivertMakeVar(KIND kind, PERROR error)
{
    // NOTE: must be in order of kind.
    static const EXPR vars[] =
    {
        {{{0}}, TOKEN_ICMP},
        {{{0}}, TOKEN_ICMP_BODY},
        {{{0}}, TOKEN_ICMP_CHECKSUM},
        {{{0}}, TOKEN_ICMP_CODE},
        {{{0}}, TOKEN_ICMP_TYPE},
        {{{0}}, TOKEN_ICMPV6},
        {{{0}}, TOKEN_ICMPV6_BODY},
        {{{0}}, TOKEN_ICMPV6_CHECKSUM},
        {{{0}}, TOKEN_ICMPV6_CODE},
        {{{0}}, TOKEN_ICMPV6_TYPE},
        {{{0}}, TOKEN_IP},
        {{{0}}, TOKEN_IP_CHECKSUM},
        {{{0}}, TOKEN_IP_DF},
        {{{0}}, TOKEN_IP_DST_ADDR},
        {{{0}}, TOKEN_IP_FRAG_OFF},
        {{{0}}, TOKEN_IP_HDR_LENGTH},
        {{{0}}, TOKEN_IP_ID},
        {{{0}}, TOKEN_IP_LENGTH},
        {{{0}}, TOKEN_IP_MF},
        {{{0}}, TOKEN_IP_PROTOCOL},
        {{{0}}, TOKEN_IP_SRC_ADDR},
        {{{0}}, TOKEN_IP_TOS},
        {{{0}}, TOKEN_IP_TTL},
        {{{0}}, TOKEN_IPV6},
        {{{0}}, TOKEN_IPV6_DST_ADDR},
        {{{0}}, TOKEN_IPV6_FLOW_LABEL},
        {{{0}}, TOKEN_IPV6_HOP_LIMIT},
        {{{0}}, TOKEN_IPV6_LENGTH},
        {{{0}}, TOKEN_IPV6_NEXT_HDR},
        {{{0}}, TOKEN_IPV6_SRC_ADDR},
        {{{0}}, TOKEN_IPV6_TRAFFIC_CLASS},
        {{{0}}, TOKEN_TCP},
        {{{0}}, TOKEN_TCP_ACK},
        {{{0}}, TOKEN_TCP_ACK_NUM},
        {{{0}}, TOKEN_TCP_CHECKSUM},
        {{{0}}, TOKEN_TCP_DST_PORT},
        {{{0}}, TOKEN_TCP_FIN},
        {{{0}}, TOKEN_TCP_HDR_LENGTH},
        {{{0}}, TOKEN_TCP_PAYLOAD_LENGTH},
        {{{0}}, TOKEN_TCP_PSH},
        {{{0}}, TOKEN_TCP_RST},
        {{{0}}, TOKEN_TCP_SEQ_NUM},
        {{{0}}, TOKEN_TCP_SRC_PORT},
        {{{0}}, TOKEN_TCP_SYN},
        {{{0}}, TOKEN_TCP_URG},
        {{{0}}, TOKEN_TCP_URG_PTR},
        {{{0}}, TOKEN_TCP_WINDOW},
        {{{0}}, TOKEN_UDP},
        {{{0}}, TOKEN_UDP_CHECKSUM},
        {{{0}}, TOKEN_UDP_DST_PORT},
        {{{0}}, TOKEN_UDP_LENGTH},
        {{{0}}, TOKEN_UDP_PAYLOAD_LENGTH},
        {{{0}}, TOKEN_UDP_SRC_PORT},
        {{{0}}, TOKEN_ZERO},
        {{{0}}, TOKEN_TRUE},
        {{{0}}, TOKEN_FALSE},
        {{{0}}, TOKEN_INBOUND},
        {{{0}}, TOKEN_OUTBOUND},
        {{{0}}, TOKEN_IF_IDX},
        {{{0}}, TOKEN_SUB_IF_IDX},
        {{{0}}, TOKEN_LOOPBACK},
        {{{0}}, TOKEN_IMPOSTOR},
        {{{0}}, TOKEN_PROCESS_ID},
        {{{0}}, TOKEN_LOCAL_ADDR},
        {{{0}}, TOKEN_REMOTE_ADDR},
        {{{0}}, TOKEN_LOCAL_PORT},
        {{{0}}, TOKEN_REMOTE_PORT},
        {{{0}}, TOKEN_PROTOCOL},
        {{{0}}, TOKEN_LAYER},
    };

    // Binary search:
    UINT lo = 0, hi = sizeof(vars) / sizeof(vars[0]) - 1, mid;
    while (lo <= hi)
    {
        mid = (hi + lo) / 2;
        if (vars[mid].kind < kind)
        {
            lo = mid + 1;
            continue;
        }
        if (vars[mid].kind > kind)
        {
            hi = mid - 1;
            continue;
        }
        return (PEXPR)(vars + mid);
    }
    *error = MAKE_ERROR(WINDIVERT_ERROR_ASSERTION_FAILED, 0);
    return NULL;
}

/*
 * Construct zero.
 */
static PEXPR WinDivertMakeZero(void)
{
    static const EXPR zero = {{{0, 0, 0, 0}}, TOKEN_NUMBER};
    return (PEXPR)&zero;
}

/*
 * Construct a number.
 */
static PEXPR WinDivertMakeNumber(HANDLE pool, UINT32 *val, PERROR error)
{
    PEXPR expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY, sizeof(EXPR));
    if (expr == NULL)
    {
        *error = MAKE_ERROR(WINDIVERT_ERROR_NO_MEMORY, 0);
        return NULL;
    }
    expr->kind = TOKEN_NUMBER;
    expr->val[0] = val[0];
    expr->val[1] = val[1];
    expr->val[2] = val[2];
    expr->val[3] = val[3];
    return expr;
}

/*
 * Construct a binary operator.
 */
static PEXPR WinDivertMakeBinOp(HANDLE pool, KIND kind, PEXPR arg0, PEXPR arg1,
    PERROR error)
{
    PEXPR expr;
    if (arg0 == NULL || arg1 == NULL)
    {
        return NULL;
    }
    expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY, sizeof(EXPR));
    if (expr == NULL)
    {
        *error = MAKE_ERROR(WINDIVERT_ERROR_NO_MEMORY, 0);
        return NULL;
    }
    expr->kind = kind;
    expr->arg[0] = arg0;
    expr->arg[1] = arg1;
    return expr;
}

/*
 * Construct an if-then-else.
 */
static PEXPR WinDivertMakeIfThenElse(HANDLE pool, PEXPR cond, PEXPR th,
    PEXPR el, PERROR error)
{
    PEXPR expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY, sizeof(EXPR));
    if (expr == NULL)
    {
        *error = MAKE_ERROR(WINDIVERT_ERROR_NO_MEMORY, 0);
        return NULL;
    }
    expr->kind = TOKEN_QUESTION;
    expr->arg[0] = cond;
    expr->arg[1] = th;
    expr->arg[2] = el;
    return expr;
}

/*
 * Parse a filter test.
 */
static PEXPR WinDivertParseTest(HANDLE pool, TOKEN *toks, UINT *i, PERROR error)
{
    PEXPR var, val;
    KIND kind;
    BOOL not = FALSE;
    while (toks[*i].kind == TOKEN_NOT)
    {
        not = !not;
        *i = *i + 1;
    }
    switch (toks[*i].kind)
    {
        case TOKEN_ZERO:
        case TOKEN_TRUE:
        case TOKEN_FALSE:
        case TOKEN_OUTBOUND:
        case TOKEN_INBOUND:
        case TOKEN_IF_IDX:
        case TOKEN_SUB_IF_IDX:
        case TOKEN_LOOPBACK:
        case TOKEN_IMPOSTOR:
        case TOKEN_IP:
        case TOKEN_IPV6:
        case TOKEN_ICMP:
        case TOKEN_ICMPV6:
        case TOKEN_TCP:
        case TOKEN_UDP:
        case TOKEN_PROCESS_ID:
        case TOKEN_LOCAL_ADDR:
        case TOKEN_REMOTE_ADDR:
        case TOKEN_LOCAL_PORT:
        case TOKEN_REMOTE_PORT:
        case TOKEN_PROTOCOL:
        case TOKEN_LAYER:
        case TOKEN_IP_HDR_LENGTH:
        case TOKEN_IP_TOS:
        case TOKEN_IP_LENGTH:
        case TOKEN_IP_ID:
        case TOKEN_IP_DF:
        case TOKEN_IP_MF:
        case TOKEN_IP_FRAG_OFF:
        case TOKEN_IP_TTL:
        case TOKEN_IP_PROTOCOL:
        case TOKEN_IP_CHECKSUM:
        case TOKEN_IP_SRC_ADDR:
        case TOKEN_IP_DST_ADDR:
        case TOKEN_IPV6_TRAFFIC_CLASS:
        case TOKEN_IPV6_FLOW_LABEL:
        case TOKEN_IPV6_LENGTH:
        case TOKEN_IPV6_NEXT_HDR:
        case TOKEN_IPV6_HOP_LIMIT:
        case TOKEN_IPV6_SRC_ADDR:
        case TOKEN_IPV6_DST_ADDR:
        case TOKEN_ICMP_TYPE:
        case TOKEN_ICMP_CODE:
        case TOKEN_ICMP_CHECKSUM:
        case TOKEN_ICMP_BODY:
        case TOKEN_ICMPV6_TYPE:
        case TOKEN_ICMPV6_CODE:
        case TOKEN_ICMPV6_CHECKSUM:
        case TOKEN_ICMPV6_BODY:
        case TOKEN_TCP_SRC_PORT:
        case TOKEN_TCP_DST_PORT:
        case TOKEN_TCP_SEQ_NUM:
        case TOKEN_TCP_ACK_NUM:
        case TOKEN_TCP_HDR_LENGTH:
        case TOKEN_TCP_URG:
        case TOKEN_TCP_ACK:
        case TOKEN_TCP_PSH:
        case TOKEN_TCP_RST:
        case TOKEN_TCP_SYN:
        case TOKEN_TCP_FIN:
        case TOKEN_TCP_WINDOW:
        case TOKEN_TCP_CHECKSUM:
        case TOKEN_TCP_URG_PTR:
        case TOKEN_TCP_PAYLOAD_LENGTH:
        case TOKEN_UDP_SRC_PORT:
        case TOKEN_UDP_DST_PORT:
        case TOKEN_UDP_LENGTH:
        case TOKEN_UDP_CHECKSUM:
        case TOKEN_UDP_PAYLOAD_LENGTH:
            break;
        default:
            *error = MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN, toks[*i].pos);
            return NULL;
    }
    var = WinDivertMakeVar(toks[*i].kind, error);
    *i = *i + 1;
    switch (toks[*i].kind)
    {
        case TOKEN_EQ:
        case TOKEN_NEQ:
        case TOKEN_LT:
        case TOKEN_LEQ:
        case TOKEN_GT:
        case TOKEN_GEQ:
            kind = toks[*i].kind;
            break;
        default:
            return WinDivertMakeBinOp(pool, (not? TOKEN_EQ: TOKEN_NEQ), var,
                WinDivertMakeZero(), error);
    }
    if (not)
    {
        switch (kind)
        {
            case TOKEN_EQ:
                kind = TOKEN_NEQ;
                break;
            case TOKEN_NEQ:
                kind = TOKEN_EQ;
                break;
            case TOKEN_LT:
                kind = TOKEN_GEQ;
                break;
            case TOKEN_LEQ:
                kind = TOKEN_GT;
                break;
            case TOKEN_GT:
                kind = TOKEN_LEQ;
                break;
            case TOKEN_GEQ:
                kind = TOKEN_LT;
                break;
            default:
                break;
        }
    }
    *i = *i + 1;
    if (toks[*i].kind != TOKEN_NUMBER)
    {
        *error = MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN, toks[*i].pos);
        return NULL;
    }
    val = WinDivertMakeNumber(pool, toks[*i].val, error);
    *i = *i + 1;
    return WinDivertMakeBinOp(pool, kind, var, val, error);
}

/*
 * Parse a filter argument to an (and) (or) operator.
 */
static PEXPR WinDivertParseArg(HANDLE pool, TOKEN *toks, UINT *i, INT depth,
    PERROR error)
{
    PEXPR arg, th, el;
    if (depth-- < 0)
    {
        *error = MAKE_ERROR(WINDIVERT_ERROR_TOO_DEEP, toks[*i].pos);
        return NULL;
    }
    switch (toks[*i].kind)
    {
        case TOKEN_OPEN:
            *i = *i + 1;
            arg = WinDivertParseFilter(pool, toks, i, depth, FALSE, error);
            if (toks[*i].kind == TOKEN_CLOSE)
            {
                *i = *i + 1;
                return arg;
            }
            if (toks[*i].kind == TOKEN_QUESTION)
            {
                *i = *i + 1;
                th = WinDivertParseFilter(pool, toks, i, depth, FALSE, error);
                if (th == NULL)
                {
                    return NULL;
                }
                if (toks[*i].kind != TOKEN_COLON)
                {
                    *error = MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN,
                        toks[*i].pos);
                    return NULL;
                }
                *i = *i + 1;
                el = WinDivertParseFilter(pool, toks, i, depth, FALSE, error);
                if (el == NULL)
                {
                    return NULL;
                }
                if (toks[*i].kind != TOKEN_CLOSE)
                {
                    *error = MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN,
                        toks[*i].pos);
                    return NULL;
                }
                *i = *i + 1;
                arg = WinDivertMakeIfThenElse(pool, arg, th, el, error);
                return arg;
            }
            *error = MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN, toks[*i].pos);
            return NULL;
        default:
            return WinDivertParseTest(pool, toks, i, error);
    }
}

/*
 * Parse the filter into an expression object.
 */
static PEXPR WinDivertParseFilter(HANDLE pool, TOKEN *toks, UINT *i, INT depth,
    BOOL and, PERROR error)
{
    PEXPR expr, arg;
    if (depth-- < 0)
    {
        *error = MAKE_ERROR(WINDIVERT_ERROR_TOO_DEEP, toks[*i].pos);
        return NULL;
    }
    if (and)
        expr = WinDivertParseArg(pool, toks, i, depth, error);
    else
        expr = WinDivertParseFilter(pool, toks, i, depth, TRUE, error);
    do
    {
        if (expr == NULL)
        {
            return NULL;
        }
        switch (toks[*i].kind)
        {
            case TOKEN_AND:
                *i = *i + 1;
                arg = WinDivertParseArg(pool, toks, i, depth, error);
                expr = WinDivertMakeBinOp(pool, TOKEN_AND, expr, arg, error);
                continue;
            case TOKEN_OR:
                *i = *i + 1;
                arg = WinDivertParseFilter(pool, toks, i, depth, TRUE, error);
                expr = WinDivertMakeBinOp(pool, TOKEN_OR, expr, arg, error);
                continue;
            default:
                return expr;
        }
    }
    while (TRUE);
}

/*
 * Statically evaluate a test if possible.
 */
static BOOL WinDivertEvalTest(PEXPR test, BOOL *res)
{
    PEXPR var = test->arg[0];
    PEXPR val = test->arg[1];
    UINT32 val32 = val->val[0];
    BOOL big = (val->val[1] != 0 || val->val[2] != 0 || val->val[3] != 0);
    UINT32 lb, ub;
    switch (var->kind)
    {
        case TOKEN_ZERO:
            lb = ub = 0;
            break;
        case TOKEN_TRUE:
            lb = ub = 1;
            break;
        case TOKEN_FALSE:
            lb = ub = 0;
            break;
        case TOKEN_LAYER:
            lb = 0; ub = WINDIVERT_LAYER_MAX;
            break;
        case TOKEN_INBOUND:
        case TOKEN_OUTBOUND:
        case TOKEN_IP:
        case TOKEN_IPV6:
        case TOKEN_ICMP:
        case TOKEN_ICMPV6:
        case TOKEN_TCP:
        case TOKEN_UDP:
        case TOKEN_IP_DF:
        case TOKEN_IP_MF:
        case TOKEN_TCP_URG:
        case TOKEN_TCP_ACK:
        case TOKEN_TCP_PSH:
        case TOKEN_TCP_RST:
        case TOKEN_TCP_SYN:
        case TOKEN_TCP_FIN:
            lb = 0; ub = 1;
            break;
        case TOKEN_IP_HDR_LENGTH:
        case TOKEN_TCP_HDR_LENGTH:
            lb = 0; ub = 0x0F;
            break;
        case TOKEN_IP_TTL:
        case TOKEN_IP_PROTOCOL:
        case TOKEN_IPV6_TRAFFIC_CLASS:
        case TOKEN_IPV6_NEXT_HDR:
        case TOKEN_IPV6_HOP_LIMIT:
        case TOKEN_ICMP_TYPE:
        case TOKEN_ICMP_CODE:
        case TOKEN_ICMPV6_TYPE:
        case TOKEN_ICMPV6_CODE:
        case TOKEN_PROTOCOL:
            lb = 0; ub = 0xFF;
            break;
        case TOKEN_IP_FRAG_OFF:
            lb = 0; ub = 0x1FFF;
            break;
        case TOKEN_IP_TOS:
        case TOKEN_IP_LENGTH:
        case TOKEN_IP_ID:
        case TOKEN_IP_CHECKSUM:
        case TOKEN_IPV6_LENGTH:
        case TOKEN_ICMP_CHECKSUM:
        case TOKEN_ICMPV6_CHECKSUM:
        case TOKEN_TCP_SRC_PORT:
        case TOKEN_TCP_DST_PORT:
        case TOKEN_TCP_WINDOW:
        case TOKEN_TCP_CHECKSUM:
        case TOKEN_TCP_URG_PTR:
        case TOKEN_TCP_PAYLOAD_LENGTH:
        case TOKEN_UDP_SRC_PORT:
        case TOKEN_UDP_DST_PORT:
        case TOKEN_UDP_LENGTH:
        case TOKEN_UDP_CHECKSUM:
        case TOKEN_UDP_PAYLOAD_LENGTH:
        case TOKEN_LOCAL_PORT:
        case TOKEN_REMOTE_PORT:
            lb = 0; ub = 0xFFFF;
            break;
        case TOKEN_IPV6_FLOW_LABEL:
            lb = 0; ub = 0x000FFFFF;
            break;
        case TOKEN_IP_SRC_ADDR:
        case TOKEN_IP_DST_ADDR:
        case TOKEN_IPV6_SRC_ADDR:
        case TOKEN_IPV6_DST_ADDR:
        case TOKEN_LOCAL_ADDR:
        case TOKEN_REMOTE_ADDR:
            return FALSE;
        default:
            lb = 0; ub = 0xFFFFFFFF;
    }
    switch (test->kind)
    {
        case TOKEN_EQ:
            if (big || val32 < lb || val32 > ub)
            {
                *res = FALSE;
                return TRUE;
            }
            if (lb == ub && val32 == lb)
            {
                *res = TRUE;
                return TRUE;
            }
            return FALSE;
        case TOKEN_NEQ:
            if (big || val32 < lb || val32 > ub)
            {
                *res = TRUE;
                return TRUE;
            }
            if (lb == ub && val32 == lb)
            {
                *res = FALSE;
                return TRUE;
            }
            return FALSE;
        case TOKEN_LT:
            if (big || val32 > ub)
            {
                *res = TRUE;
                return TRUE;
            }
            if (val32 <= lb)
            {
                *res = FALSE;
                return TRUE;
            }
            return FALSE;
        case TOKEN_LEQ:
            if (big || val32 >= ub)
            {
                *res = TRUE;
                return TRUE;
            }
            if (val32 < lb)
            {
                *res = FALSE;
                return TRUE;
            }
            return FALSE;
        case TOKEN_GT:
            if (big || val32 >= ub)
            {
                *res = FALSE;
                return TRUE;
            }
            if (val32 < lb)
            {
                *res = TRUE;
                return TRUE;
            }
            return FALSE;
        case TOKEN_GEQ:
            if (big || val32 > ub)
            {
                *res = FALSE;
                return TRUE;
            }
            if (val32 <= lb)
            {
                *res = TRUE;
                return TRUE;
            }
            return FALSE;
        default:
            return FALSE;
    }
}

/*
 * Flatten an expression into a sequence of tests and jumps.
 */
static INT16 WinDivertFlattenExpr(PEXPR expr, INT16 *label, INT16 succ,
    INT16 fail, PEXPR *stack)
{
    INT16 succ1, fail1;
    BOOL res;
    if (succ < 0 || fail < 0)
    {
        return -1;
    }
    switch (expr->kind)
    {
        case TOKEN_AND:
            succ = WinDivertFlattenExpr(expr->arg[1], label, succ, fail, stack);
            succ = WinDivertFlattenExpr(expr->arg[0], label, succ, fail, stack);
            return succ;
        case TOKEN_OR:
            fail = WinDivertFlattenExpr(expr->arg[1], label, succ, fail, stack);
            fail = WinDivertFlattenExpr(expr->arg[0], label, succ, fail, stack);
            return fail;
        case TOKEN_QUESTION:
            fail1 = WinDivertFlattenExpr(expr->arg[2], label, succ, fail,
                stack);
            succ1 = WinDivertFlattenExpr(expr->arg[1], label, succ, fail,
                stack);
            succ = WinDivertFlattenExpr(expr->arg[0], label, succ1, fail1,
                stack);
            return succ;
        default:
            if (WinDivertEvalTest(expr, &res))
            {
                return (res? succ: fail);
            }
            if (*label >= WINDIVERT_FILTER_MAXLEN)
            {
                return -1;
            }
            stack[*label] = expr;
            expr->succ = succ;
            expr->fail = fail;
            succ = *label;
            *label = *label + 1;
            return succ;
    }
}

/*
 * Emit a test.
 */
static void WinDivertEmitTest(PEXPR test, UINT16 offset,
    PWINDIVERT_FILTER object)
{
    PEXPR var = test->arg[0], val = test->arg[1];
    switch (test->kind)
    {
        case TOKEN_EQ:
            object->test = WINDIVERT_FILTER_TEST_EQ;
            break;
        case TOKEN_NEQ:
            object->test = WINDIVERT_FILTER_TEST_NEQ;
            break;
        case TOKEN_LT:
            object->test = WINDIVERT_FILTER_TEST_LT;
            break;
        case TOKEN_LEQ:
            object->test = WINDIVERT_FILTER_TEST_LEQ;
            break;
        case TOKEN_GT:
            object->test = WINDIVERT_FILTER_TEST_GT;
            break;
        case TOKEN_GEQ:
            object->test = WINDIVERT_FILTER_TEST_GEQ;
            break;
        default:
            return;
    }
    switch (var->kind)
    {
        case TOKEN_ZERO:
            object->field = WINDIVERT_FILTER_FIELD_ZERO;
            break;
        case TOKEN_OUTBOUND:
            object->field = WINDIVERT_FILTER_FIELD_OUTBOUND;
            break;
        case TOKEN_INBOUND:
            object->field = WINDIVERT_FILTER_FIELD_INBOUND;
            break;
        case TOKEN_IF_IDX:
            object->field = WINDIVERT_FILTER_FIELD_IFIDX;
            break;
        case TOKEN_SUB_IF_IDX:
            object->field = WINDIVERT_FILTER_FIELD_SUBIFIDX;
            break;
        case TOKEN_LOOPBACK:
            object->field = WINDIVERT_FILTER_FIELD_LOOPBACK;
            break;
        case TOKEN_IMPOSTOR:
            object->field = WINDIVERT_FILTER_FIELD_IMPOSTOR;
            break;
        case TOKEN_PROCESS_ID:
            object->field = WINDIVERT_FILTER_FIELD_PROCESSID;
            break;
        case TOKEN_LOCAL_ADDR:
            object->field = WINDIVERT_FILTER_FIELD_LOCALADDR;
            break;
        case TOKEN_REMOTE_ADDR:
            object->field = WINDIVERT_FILTER_FIELD_REMOTEADDR;
            break;
        case TOKEN_LOCAL_PORT:
            object->field = WINDIVERT_FILTER_FIELD_LOCALPORT;
            break;
        case TOKEN_REMOTE_PORT:
            object->field = WINDIVERT_FILTER_FIELD_REMOTEPORT;
            break;
        case TOKEN_PROTOCOL:
            object->field = WINDIVERT_FILTER_FIELD_PROTOCOL;
            break;
        case TOKEN_LAYER:
            object->field = WINDIVERT_FILTER_FIELD_LAYER;
            break;
        case TOKEN_IP:
            object->field = WINDIVERT_FILTER_FIELD_IP;
            break;
        case TOKEN_IPV6:
            object->field = WINDIVERT_FILTER_FIELD_IPV6;
            break;
        case TOKEN_ICMP:
            object->field = WINDIVERT_FILTER_FIELD_ICMP;
            break;
        case TOKEN_ICMPV6:
            object->field = WINDIVERT_FILTER_FIELD_ICMPV6;
            break;
        case TOKEN_TCP:
            object->field = WINDIVERT_FILTER_FIELD_TCP;
            break;
        case TOKEN_UDP:
            object->field = WINDIVERT_FILTER_FIELD_UDP;
            break;
        case TOKEN_IP_HDR_LENGTH:
            object->field = WINDIVERT_FILTER_FIELD_IP_HDRLENGTH;
            break;
        case TOKEN_IP_TOS:
            object->field = WINDIVERT_FILTER_FIELD_IP_TOS;
            break;
        case TOKEN_IP_LENGTH:
            object->field = WINDIVERT_FILTER_FIELD_IP_LENGTH;
            break;
        case TOKEN_IP_ID:
            object->field = WINDIVERT_FILTER_FIELD_IP_ID;
            break;
        case TOKEN_IP_DF:
            object->field = WINDIVERT_FILTER_FIELD_IP_DF;
            break;
        case TOKEN_IP_MF:
            object->field = WINDIVERT_FILTER_FIELD_IP_MF;
            break;
        case TOKEN_IP_FRAG_OFF:
            object->field = WINDIVERT_FILTER_FIELD_IP_FRAGOFF;
            break;
        case TOKEN_IP_TTL:
            object->field = WINDIVERT_FILTER_FIELD_IP_TTL;
            break;
        case TOKEN_IP_PROTOCOL:
            object->field = WINDIVERT_FILTER_FIELD_IP_PROTOCOL;
            break;
        case TOKEN_IP_CHECKSUM:
            object->field = WINDIVERT_FILTER_FIELD_IP_CHECKSUM;
            break;
        case TOKEN_IP_SRC_ADDR:
            object->field = WINDIVERT_FILTER_FIELD_IP_SRCADDR;
            break;
        case TOKEN_IP_DST_ADDR:
            object->field = WINDIVERT_FILTER_FIELD_IP_DSTADDR;
            break;
        case TOKEN_IPV6_TRAFFIC_CLASS:
            object->field = WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS;
            break;
        case TOKEN_IPV6_FLOW_LABEL:
            object->field = WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL;
            break;
        case TOKEN_IPV6_LENGTH:
            object->field = WINDIVERT_FILTER_FIELD_IPV6_LENGTH;
            break;
        case TOKEN_IPV6_NEXT_HDR:
            object->field = WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR;
            break;
        case TOKEN_IPV6_HOP_LIMIT:
            object->field = WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT;
            break;
        case TOKEN_IPV6_SRC_ADDR:
            object->field = WINDIVERT_FILTER_FIELD_IPV6_SRCADDR;
            break;
        case TOKEN_IPV6_DST_ADDR:
            object->field = WINDIVERT_FILTER_FIELD_IPV6_DSTADDR;
            break;
        case TOKEN_ICMP_TYPE:
            object->field = WINDIVERT_FILTER_FIELD_ICMP_TYPE;
            break;
        case TOKEN_ICMP_CODE:
            object->field = WINDIVERT_FILTER_FIELD_ICMP_CODE;
            break;
        case TOKEN_ICMP_CHECKSUM:
            object->field = WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM;
            break;
        case TOKEN_ICMP_BODY:
            object->field = WINDIVERT_FILTER_FIELD_ICMP_BODY;
            break;
        case TOKEN_ICMPV6_TYPE:
            object->field = WINDIVERT_FILTER_FIELD_ICMPV6_TYPE;
            break;
        case TOKEN_ICMPV6_CODE:
            object->field = WINDIVERT_FILTER_FIELD_ICMPV6_CODE;
            break;
        case TOKEN_ICMPV6_CHECKSUM:
            object->field = WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM;
            break;
        case TOKEN_ICMPV6_BODY:
            object->field = WINDIVERT_FILTER_FIELD_ICMPV6_BODY;
            break;
        case TOKEN_TCP_SRC_PORT:
            object->field = WINDIVERT_FILTER_FIELD_TCP_SRCPORT;
            break;
        case TOKEN_TCP_DST_PORT:
            object->field = WINDIVERT_FILTER_FIELD_TCP_DSTPORT;
            break;
        case TOKEN_TCP_SEQ_NUM:
            object->field = WINDIVERT_FILTER_FIELD_TCP_SEQNUM;
            break;
        case TOKEN_TCP_ACK_NUM:
            object->field = WINDIVERT_FILTER_FIELD_TCP_ACKNUM;
            break;
        case TOKEN_TCP_HDR_LENGTH:
            object->field = WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH;
            break;
        case TOKEN_TCP_URG:
            object->field = WINDIVERT_FILTER_FIELD_TCP_URG;
            break;
        case TOKEN_TCP_ACK:
            object->field = WINDIVERT_FILTER_FIELD_TCP_ACK;
            break;
        case TOKEN_TCP_PSH:
            object->field = WINDIVERT_FILTER_FIELD_TCP_PSH;
            break;
        case TOKEN_TCP_RST:
            object->field = WINDIVERT_FILTER_FIELD_TCP_RST;
            break;
        case TOKEN_TCP_SYN:
            object->field = WINDIVERT_FILTER_FIELD_TCP_SYN;
            break;
        case TOKEN_TCP_FIN:
            object->field = WINDIVERT_FILTER_FIELD_TCP_FIN;
            break;
        case TOKEN_TCP_WINDOW:
            object->field = WINDIVERT_FILTER_FIELD_TCP_WINDOW;
            break;
        case TOKEN_TCP_CHECKSUM:
            object->field = WINDIVERT_FILTER_FIELD_TCP_CHECKSUM;
            break;
        case TOKEN_TCP_URG_PTR:
            object->field = WINDIVERT_FILTER_FIELD_TCP_URGPTR;
            break;
        case TOKEN_TCP_PAYLOAD_LENGTH:
            object->field = WINDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH;
            break;
        case TOKEN_UDP_SRC_PORT:
            object->field = WINDIVERT_FILTER_FIELD_UDP_SRCPORT;
            break;
        case TOKEN_UDP_DST_PORT:
            object->field = WINDIVERT_FILTER_FIELD_UDP_DSTPORT;
            break;
        case TOKEN_UDP_LENGTH:
            object->field = WINDIVERT_FILTER_FIELD_UDP_LENGTH;
            break;
        case TOKEN_UDP_CHECKSUM:
            object->field = WINDIVERT_FILTER_FIELD_UDP_CHECKSUM;
            break;
        case TOKEN_UDP_PAYLOAD_LENGTH:
            object->field = WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH;
            break;
        default:
            return;
    }
    object->arg[0] = val->val[0];
    object->arg[1] = val->val[1];
    object->arg[2] = val->val[2];
    object->arg[3] = val->val[3];
    switch (test->succ)
    {
        case WINDIVERT_FILTER_RESULT_ACCEPT:
        case WINDIVERT_FILTER_RESULT_REJECT:
            object->success = test->succ;
            break;
        default:
            object->success = offset - test->succ;
            break;
    }
    switch (test->fail)
    {
        case WINDIVERT_FILTER_RESULT_ACCEPT:
        case WINDIVERT_FILTER_RESULT_REJECT:
            object->failure = test->fail;
            break;
        default:
            object->failure = offset - test->fail;
            break;
    }
    return;
}

/*
 * Emit a filter object.
 */
static void WinDivertEmitFilter(PEXPR *stack, UINT len, UINT16 label,
    PWINDIVERT_FILTER object, UINT *obj_len)
{
    UINT i;
    switch (label)
    {
        case WINDIVERT_FILTER_RESULT_ACCEPT:
        case WINDIVERT_FILTER_RESULT_REJECT:
            object[0].field = WINDIVERT_FILTER_FIELD_ZERO;
            object[0].test = WINDIVERT_FILTER_TEST_EQ;
            object[0].arg[0] = object[0].arg[1] = object[0].arg[2] =
                object[0].arg[3] = 0;
            object[0].success = label;
            object[0].failure = label;
            *obj_len = 1;
            return;
        default:
            break;
    }
    *obj_len = len + 1;
    for (i = 0; i <= len; i++)
    {
        WinDivertEmitTest(stack[len - i], label, object + i);
    }
}

/*
 * Analyze a filter object.
 */
static UINT64 WinDivertAnalyzeFilter(PWINDIVERT_FILTER filter, UINT length)
{
    BOOL result;
    UINT64 flags = 0;

    // False filter?
    result = WinDivertCondExecFilter(filter, length,
        WINDIVERT_FILTER_FIELD_ZERO, 0);
    if (!result)
    {
        return 0;
    }

    // Inbound?
    result = WinDivertCondExecFilter(filter, length,
        WINDIVERT_FILTER_FIELD_INBOUND, 1);
    if (result)
    {
        result = WinDivertCondExecFilter(filter, length,
            WINDIVERT_FILTER_FIELD_OUTBOUND, 0);
    }
    flags |= (result? WINDIVERT_FILTER_FLAG_INBOUND: 0);

    // Outbound?
    result = WinDivertCondExecFilter(filter, length,
        WINDIVERT_FILTER_FIELD_OUTBOUND, 1);
    if (result)
    {
        result = WinDivertCondExecFilter(filter, length,
            WINDIVERT_FILTER_FIELD_INBOUND, 0);
    }
    flags |= (result? WINDIVERT_FILTER_FLAG_OUTBOUND: 0);

    // IPv4? 
    result = WinDivertCondExecFilter(filter, length,
        WINDIVERT_FILTER_FIELD_IP, 1);
    if (result)
    {   
        result = WinDivertCondExecFilter(filter, length,
            WINDIVERT_FILTER_FIELD_IPV6, 0);
    }
    flags |= (result? WINDIVERT_FILTER_FLAG_IP: 0);

    // Ipv6? 
    result = WinDivertCondExecFilter(filter, length,
        WINDIVERT_FILTER_FIELD_IPV6, 1);
    if (result)
    {   
        result = WinDivertCondExecFilter(filter, length,
            WINDIVERT_FILTER_FIELD_IP, 0);
    }
    flags |= (result? WINDIVERT_FILTER_FLAG_IPV6: 0);

    return flags;
}

/*
 * Execute a filter object with respect to an assumption/condition.
 * FALSE = definite reject; TRUE = maybe accept.
 */
static BOOL WinDivertCondExecFilter(PWINDIVERT_FILTER filter, UINT length,
    UINT8 field, UINT32 arg)
{
    INT16 ip;
    UINT8 succ, fail;
    BOOL result[WINDIVERT_FILTER_MAXLEN];
    BOOL result_succ, result_fail, result_test;

    if (length == 0)
    {
        return TRUE;
    }

    for (ip = (INT16)(length-1); ip >= 0; ip--)
    {
        succ = filter[ip].success;
        if (succ == WINDIVERT_FILTER_RESULT_ACCEPT || succ <= ip ||
                succ >= length)
        {
            result_succ = TRUE;
        }
        else if (succ == WINDIVERT_FILTER_RESULT_REJECT)
        {
            result_succ = FALSE;
        }
        else
        {
            result_succ = result[succ];
        }

        fail = filter[ip].failure;
        if (fail == WINDIVERT_FILTER_RESULT_ACCEPT || fail <= ip ||
                fail >= length)
        {
            result_fail = TRUE;
        }
        else if (fail == WINDIVERT_FILTER_RESULT_REJECT)
        {
            result_fail = FALSE;
        }
        else
        {
            result_fail = result[fail];
        }

        if (result_succ && result_fail)
        {
            result[ip] = TRUE;
        }
        else if (!result_succ && !result_fail)
        {
            result[ip] = FALSE;
        }
        else if (filter[ip].field == field)
        {
            switch (filter[ip].test)
            {
                case WINDIVERT_FILTER_TEST_EQ:
                    result_test = (arg == filter[ip].arg[0]);
                    break;
                case WINDIVERT_FILTER_TEST_NEQ:
                    result_test = (arg != filter[ip].arg[0]);
                    break;
                case WINDIVERT_FILTER_TEST_LT:
                    result_test = (arg < filter[ip].arg[0]);
                    break;
                case WINDIVERT_FILTER_TEST_LEQ:
                    result_test = (arg <= filter[ip].arg[0]);
                    break;
                case WINDIVERT_FILTER_TEST_GT:
                    result_test = (arg > filter[ip].arg[0]);
                    break;
                case WINDIVERT_FILTER_TEST_GEQ:
                    result_test = (arg >= filter[ip].arg[0]);
                    break;
                default:
                    return TRUE;    // abort.
            }
            result[ip] = (result_test? result_succ: result_fail);
        }
        else
        {
            result[ip] = TRUE;
        }
    }

    return result[0];
}

/*
 * Compile a filter string into an executable filter object.
 */
static ERROR WinDivertCompileFilter(const char *filter,
    WINDIVERT_LAYER layer, PWINDIVERT_FILTER object, UINT *obj_len)
{
    TOKEN *tokens;
    PEXPR *stack;
    HANDLE pool;
    PEXPR expr;
    UINT i, max_depth;
    INT16 label;
    const SIZE_T min_pool_size = 8192;
    const SIZE_T tokens_size = 5 * WINDIVERT_FILTER_MAXLEN;
    ERROR error;

    // Check for pre-compiled filter object:
    if (filter[0] == '@')
    {
        WINDIVERT_STREAM stream;
        stream.data     = (char *)filter;
        stream.pos      = 0;
        stream.max      = UINT_MAX;
        stream.overflow = FALSE;

        if (!WinDivertDeserializeFilter(&stream, object, obj_len))
        {
            return MAKE_ERROR(WINDIVERT_ERROR_BAD_OBJECT, 0);
        }
        return MAKE_ERROR(WINDIVERT_ERROR_NONE, 0);
    }

    // Allocate memory for the compiler:
    pool = HeapCreate(HEAP_NO_SERIALIZE, min_pool_size, 16 * min_pool_size);
    if (pool == NULL)
    {
        return MAKE_ERROR(WINDIVERT_ERROR_NO_MEMORY, 0);
    }
    tokens = (TOKEN *)HeapAlloc(pool, 0, tokens_size * sizeof(TOKEN));
    stack  = (PEXPR *)HeapAlloc(pool, 0,
        WINDIVERT_FILTER_MAXLEN * sizeof(PEXPR));
    if (tokens == NULL || stack == NULL)
    {
        HeapDestroy(pool);
        return MAKE_ERROR(WINDIVERT_ERROR_NO_MEMORY, 0);
    }

    // Tokenize the filter string:
    error = WinDivertTokenizeFilter(filter, layer, tokens, tokens_size-1);
    if (IS_ERROR(error))
    {
        HeapDestroy(pool);
        return error;
    }

    // Parse the filter into an expression:
    i = 0;
    max_depth = 1024;
    expr = WinDivertParseFilter(pool, tokens, &i, max_depth, FALSE, &error);
    if (expr == NULL)
    {
        HeapDestroy(pool);
        return error;
    }
    if (tokens[i].kind != TOKEN_END)
    {
        HeapDestroy(pool);
        return MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN, tokens[i].pos);
    }

    // Construct the filter tree:
    label = 0;
    label = WinDivertFlattenExpr(expr, &label, WINDIVERT_FILTER_RESULT_ACCEPT,
        WINDIVERT_FILTER_RESULT_REJECT, stack);
    if (label < 0)
    {
        HeapDestroy(pool);
        return MAKE_ERROR(WINDIVERT_ERROR_TOO_LONG, 0);
    }

    // Emit the final object.
    if (object != NULL)
    {
        WinDivertEmitFilter(stack, label, label, object, obj_len);
    }
    HeapDestroy(pool);

    return MAKE_ERROR(WINDIVERT_ERROR_NONE, 0);
}

/*
 * Convert a error code into a user readable string.
 */
static const char *WinDivertErrorString(UINT code)
{
    switch (code)
    {
        case WINDIVERT_ERROR_NONE:
            return "No error";
        case WINDIVERT_ERROR_NO_MEMORY:
            return "Out of memory";
        case WINDIVERT_ERROR_TOO_DEEP:
            return "Filter expression too deep";
        case WINDIVERT_ERROR_TOO_LONG:
            return "Filter expression too long";
        case WINDIVERT_ERROR_BAD_TOKEN:
            return "Filter expression contains a bad token";
        case WINDIVERT_ERROR_BAD_TOKEN_FOR_LAYER:
            return "Filter expression contains a bad token for layer";
        case WINDIVERT_ERROR_UNEXPECTED_TOKEN:
            return "Filter expression parse error";
        case WINDIVERT_ERROR_OUTPUT_TOO_SHORT:
            return "Filter object buffer is too short";
        case WINDIVERT_ERROR_BAD_OBJECT:
            return "Filter object is invalid";
        case WINDIVERT_ERROR_ASSERTION_FAILED:
            return "Internal assertion failed";
        default:
            return "Unknown error";
    }
}

/*
 * Compile the given filter string.
 */
extern BOOL WinDivertHelperCompileFilter(const char *filter_str, 
    WINDIVERT_LAYER layer, char *object, UINT obj_len, const char **error,
    UINT *error_pos)
{
    ERROR err;
    if (filter_str == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS);
    if (object == NULL)
    {
        err = WinDivertCompileFilter(filter_str, layer, NULL, NULL);
    }
    else
    {
        WINDIVERT_FILTER object0[WINDIVERT_FILTER_MAXLEN];
        UINT obj0_len;
        err = WinDivertCompileFilter(filter_str, layer, object0, &obj0_len);
        if (!IS_ERROR(err))
        {
            WINDIVERT_STREAM stream;
            stream.data     = object;
            stream.pos      = 0;
            stream.max      = obj_len;
            stream.overflow = FALSE;
            
            WinDivertSerializeFilter(&stream, object0, obj0_len);
            if (stream.overflow)
            {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                err = MAKE_ERROR(WINDIVERT_ERROR_OUTPUT_TOO_SHORT, 0);
            }
        }
    }
    if (error != NULL)
    {
        *error = WinDivertErrorString(GET_CODE(err));
    }
    if (error_pos != NULL)
    {
        *error_pos = GET_POS(err);
    }
    return !IS_ERROR(err);
}

/*
 * Big number comparison.
 */
static int WinDivertBigNumCompare(const UINT32 *a, const UINT32 *b)
{
    if (a[3] < b[3])
    {
        return -1;
    }
    if (a[3] > b[3])
    {
        return 1;
    }
    if (a[2] < b[2])
    {
        return -1;
    }
    if (a[2] > b[2])
    {
        return 1;
    }
    if (a[1] < b[1])
    {
        return -1;
    }
    if (a[1] > b[1])
    {
        return 1;
    }
    if (a[0] < b[0])
    {
        return -1;
    }
    if (a[0] > b[0])
    {
        return 1;
    }
    return 0;
}

/*
 * Evaluate the given filter with the given packet as input.
 */
extern BOOL WinDivertHelperEvalFilter(const char *filter, PVOID packet,
    UINT packet_len, PWINDIVERT_ADDRESS addr)
{
    UINT16 pc;
    ERROR err;
    PWINDIVERT_IPHDR iphdr = NULL;
    PWINDIVERT_IPV6HDR ipv6hdr = NULL;
    PWINDIVERT_ICMPHDR icmphdr = NULL;
    PWINDIVERT_ICMPV6HDR icmpv6hdr = NULL;
    PWINDIVERT_TCPHDR tcphdr = NULL;
    PWINDIVERT_UDPHDR udphdr = NULL;
    UINT payload_len;
    UINT32 val[4];
    BOOL pass;
    int cmp;
    WINDIVERT_FILTER object[WINDIVERT_FILTER_MAXLEN];
    UINT obj_len;

    if (filter == NULL || addr == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    switch (addr->Layer)
    {
        case WINDIVERT_LAYER_NETWORK:
        case WINDIVERT_LAYER_NETWORK_FORWARD:
            if (packet == NULL)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            WinDivertHelperParsePacket(packet, packet_len, &iphdr, &ipv6hdr,
                &icmphdr, &icmpv6hdr, &tcphdr, &udphdr, NULL, &payload_len);
            if ((addr->IPv6 && ipv6hdr == NULL) ||
                (!addr->IPv6 && iphdr == NULL))
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            break;
        case WINDIVERT_LAYER_FLOW:
            if (packet != NULL)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            break;
        case WINDIVERT_LAYER_REFLECT:
            break;
        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
    }

    err = WinDivertCompileFilter(filter, addr->Layer, object, &obj_len);
    if (IS_ERROR(err))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    pc = 0;
    while (TRUE)
    {
        switch (pc)
        {
            case WINDIVERT_FILTER_RESULT_ACCEPT:
                return TRUE;
            case WINDIVERT_FILTER_RESULT_REJECT:
                return FALSE;
            default:
                if (pc >= obj_len)
                {
                    SetLastError(ERROR_INVALID_PARAMETER);
                    return FALSE;
                }
                break;
        }
        pass = TRUE;
        switch (object[pc].field)
        {
            case WINDIVERT_FILTER_FIELD_IP_HDRLENGTH:
            case WINDIVERT_FILTER_FIELD_IP_TOS:
            case WINDIVERT_FILTER_FIELD_IP_LENGTH:
            case WINDIVERT_FILTER_FIELD_IP_ID:
            case WINDIVERT_FILTER_FIELD_IP_DF:
            case WINDIVERT_FILTER_FIELD_IP_MF:
            case WINDIVERT_FILTER_FIELD_IP_FRAGOFF:
            case WINDIVERT_FILTER_FIELD_IP_TTL:
            case WINDIVERT_FILTER_FIELD_IP_PROTOCOL:
            case WINDIVERT_FILTER_FIELD_IP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_IP_SRCADDR:
            case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
                pass = (iphdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
            case WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
            case WINDIVERT_FILTER_FIELD_IPV6_LENGTH:
            case WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
            case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
            case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
            case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
                pass = (ipv6hdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
            case WINDIVERT_FILTER_FIELD_ICMP_CODE:
            case WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_ICMP_BODY:
                pass = (icmphdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
            case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
            case WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_ICMPV6_BODY:
                pass = (icmpv6hdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_TCP_SRCPORT:
            case WINDIVERT_FILTER_FIELD_TCP_DSTPORT:
            case WINDIVERT_FILTER_FIELD_TCP_SEQNUM:
            case WINDIVERT_FILTER_FIELD_TCP_ACKNUM:
            case WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
            case WINDIVERT_FILTER_FIELD_TCP_URG:
            case WINDIVERT_FILTER_FIELD_TCP_ACK:
            case WINDIVERT_FILTER_FIELD_TCP_PSH:
            case WINDIVERT_FILTER_FIELD_TCP_RST:
            case WINDIVERT_FILTER_FIELD_TCP_SYN:
            case WINDIVERT_FILTER_FIELD_TCP_FIN:
            case WINDIVERT_FILTER_FIELD_TCP_WINDOW:
            case WINDIVERT_FILTER_FIELD_TCP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_TCP_URGPTR:
            case WINDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
                pass = (tcphdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
            case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
            case WINDIVERT_FILTER_FIELD_UDP_LENGTH:
            case WINDIVERT_FILTER_FIELD_UDP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                pass = (udphdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_INBOUND:
            case WINDIVERT_FILTER_FIELD_OUTBOUND:
                pass = (addr->Layer != WINDIVERT_LAYER_NETWORK_FORWARD);
                break;
            case WINDIVERT_FILTER_FIELD_IFIDX:
            case WINDIVERT_FILTER_FIELD_SUBIFIDX:
                pass = (addr->Layer == WINDIVERT_LAYER_NETWORK ||
                        addr->Layer == WINDIVERT_LAYER_NETWORK_FORWARD);
                break;
            case WINDIVERT_FILTER_FIELD_PROCESSID:
            case WINDIVERT_FILTER_FIELD_LOCALADDR:
            case WINDIVERT_FILTER_FIELD_REMOTEADDR:
            case WINDIVERT_FILTER_FIELD_LOCALPORT:
            case WINDIVERT_FILTER_FIELD_REMOTEPORT:
            case WINDIVERT_FILTER_FIELD_PROTOCOL:
                pass = (addr->Layer == WINDIVERT_LAYER_FLOW);
                break;
            default:
                pass = TRUE;
                break;
        }
        if (!pass)
        {
            pc = object[pc].failure;
            continue;
        }
        val[1] = val[2] = val[3] = 0;
        switch (object[pc].field)
        {
            case WINDIVERT_FILTER_FIELD_ZERO:
                val[0] = 0;
                break;
            case WINDIVERT_FILTER_FIELD_INBOUND:
                val[0] = !addr->Outbound;
                break;
            case WINDIVERT_FILTER_FIELD_OUTBOUND:
                val[0] = addr->Outbound;
                break;
            case WINDIVERT_FILTER_FIELD_IFIDX:
                val[0] = addr->Network.IfIdx;
                break;
            case WINDIVERT_FILTER_FIELD_SUBIFIDX:
                val[0] = addr->Network.SubIfIdx;
                break;
            case WINDIVERT_FILTER_FIELD_LOOPBACK:
                val[0] = addr->Loopback;
                break;
            case WINDIVERT_FILTER_FIELD_IMPOSTOR:
                val[0] = addr->Impostor;
                break;
            case WINDIVERT_FILTER_FIELD_IP:
                val[0] = !addr->IPv6;
                break;
            case WINDIVERT_FILTER_FIELD_IPV6:
                val[0] = addr->IPv6;
                break;
            case WINDIVERT_FILTER_FIELD_ICMP:
                val[0] = (addr->Layer == WINDIVERT_LAYER_FLOW?
                    addr->Flow.Protocol == IPPROTO_ICMP: icmphdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6:
                val[0] = (addr->Layer == WINDIVERT_LAYER_FLOW?
                    addr->Flow.Protocol == IPPROTO_ICMPV6: icmpv6hdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_TCP:
                val[0] = (addr->Layer == WINDIVERT_LAYER_FLOW?
                    addr->Flow.Protocol == IPPROTO_TCP: tcphdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_UDP:
                val[0] = (addr->Layer == WINDIVERT_LAYER_FLOW?
                    addr->Flow.Protocol == IPPROTO_UDP: udphdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_IP_HDRLENGTH:
                val[0] = iphdr->HdrLength;
                break;
            case WINDIVERT_FILTER_FIELD_IP_TOS:
                val[0] = iphdr->TOS;
                break;
            case WINDIVERT_FILTER_FIELD_IP_LENGTH:
                val[0] = ntohs(iphdr->Length);
                break;
            case WINDIVERT_FILTER_FIELD_IP_ID:
                val[0] = ntohs(iphdr->Id);
                break;
            case WINDIVERT_FILTER_FIELD_IP_DF:
                val[0] = WINDIVERT_IPHDR_GET_DF(iphdr);
                break;
            case WINDIVERT_FILTER_FIELD_IP_MF:
                val[0] = WINDIVERT_IPHDR_GET_MF(iphdr);
                break;
            case WINDIVERT_FILTER_FIELD_IP_FRAGOFF:
                val[0] = ntohs(WINDIVERT_IPHDR_GET_FRAGOFF(iphdr));
                break;
            case WINDIVERT_FILTER_FIELD_IP_TTL:
                val[0] = iphdr->TTL;
                break;
            case WINDIVERT_FILTER_FIELD_IP_PROTOCOL:
                val[0] = iphdr->Protocol;
                break;
            case WINDIVERT_FILTER_FIELD_IP_CHECKSUM:
                val[0] = ntohs(iphdr->Checksum);
                break;
            case WINDIVERT_FILTER_FIELD_IP_SRCADDR:
                val[1] = 0x0000FFFF;
                val[0] = ntohl(iphdr->SrcAddr);
                break;
            case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
                val[1] = 0x0000FFFF;
                val[0] = ntohl(iphdr->DstAddr);
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
                val[0] = WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(ipv6hdr);
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
                val[0] = ntohl(WINDIVERT_IPV6HDR_GET_FLOWLABEL(ipv6hdr));
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_LENGTH:
                val[0] = ntohs(ipv6hdr->Length);
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
                val[0] = ipv6hdr->NextHdr;
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
                val[0] = ipv6hdr->HopLimit;
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
                val[3] = ntohl(ipv6hdr->SrcAddr[0]);
                val[2] = ntohl(ipv6hdr->SrcAddr[1]);
                val[1] = ntohl(ipv6hdr->SrcAddr[2]);
                val[0] = ntohl(ipv6hdr->SrcAddr[3]);
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
                val[3] = ntohl(ipv6hdr->DstAddr[0]);
                val[2] = ntohl(ipv6hdr->DstAddr[1]);
                val[1] = ntohl(ipv6hdr->DstAddr[2]);
                val[0] = ntohl(ipv6hdr->DstAddr[3]);
                break;
            case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
                val[0] = icmphdr->Type;
                break;
            case WINDIVERT_FILTER_FIELD_ICMP_CODE:
                val[0] = icmphdr->Code;
                break;
            case WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
                val[0] = ntohs(icmphdr->Checksum);
                break;
            case WINDIVERT_FILTER_FIELD_ICMP_BODY:
                val[0] = ntohl(icmphdr->Body);
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
                val[0] = icmpv6hdr->Type;
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
                val[0] = icmpv6hdr->Code;
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
                val[0] = ntohs(icmpv6hdr->Checksum);
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6_BODY:
                val[0] = ntohl(icmpv6hdr->Body);
                break;
            case WINDIVERT_FILTER_FIELD_TCP_SRCPORT:
                val[0] = ntohs(tcphdr->SrcPort);
                break;
            case WINDIVERT_FILTER_FIELD_TCP_DSTPORT:
                val[0] = ntohs(tcphdr->DstPort);
                break;
            case WINDIVERT_FILTER_FIELD_TCP_SEQNUM:
                val[0] = ntohl(tcphdr->SeqNum);
                break;
            case WINDIVERT_FILTER_FIELD_TCP_ACKNUM:
                val[0] = ntohl(tcphdr->AckNum);
                break;
            case WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
                val[0] = tcphdr->HdrLength;
                break;
            case WINDIVERT_FILTER_FIELD_TCP_URG:
                val[0] = tcphdr->Urg;
                break;
            case WINDIVERT_FILTER_FIELD_TCP_ACK:
                val[0] = tcphdr->Ack;
                break;
            case WINDIVERT_FILTER_FIELD_TCP_PSH:
                val[0] = tcphdr->Psh;
                break;
            case WINDIVERT_FILTER_FIELD_TCP_RST:
                val[0] = tcphdr->Rst;
                break;
            case WINDIVERT_FILTER_FIELD_TCP_SYN:
                val[0] = tcphdr->Syn;
                break;
            case WINDIVERT_FILTER_FIELD_TCP_FIN:
                val[0] = tcphdr->Fin;
                break;
            case WINDIVERT_FILTER_FIELD_TCP_WINDOW:
                val[0] = ntohs(tcphdr->Window);
                break;
            case WINDIVERT_FILTER_FIELD_TCP_CHECKSUM:
                val[0] = ntohs(tcphdr->Checksum);
                break;
            case WINDIVERT_FILTER_FIELD_TCP_URGPTR:
                val[0] = ntohs(tcphdr->UrgPtr);
                break;
            case WINDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
                val[0] = payload_len;
                break;
            case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
                val[0] = ntohs(udphdr->SrcPort);
                break;
            case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
                val[0] = ntohs(udphdr->DstPort);
                break;
            case WINDIVERT_FILTER_FIELD_UDP_LENGTH:
                val[0] = ntohs(udphdr->Length);
                break;
            case WINDIVERT_FILTER_FIELD_UDP_CHECKSUM:
                val[0] = ntohs(udphdr->Checksum);
                break;
            case WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                val[0] = payload_len;
                break;
            case WINDIVERT_FILTER_FIELD_PROCESSID:
                val[0] = addr->Flow.ProcessId;
                break;
            case WINDIVERT_FILTER_FIELD_LOCALADDR:
                val[0] = addr->Flow.LocalAddr[0];
                val[1] = addr->Flow.LocalAddr[1];
                val[2] = addr->Flow.LocalAddr[2];
                val[3] = addr->Flow.LocalAddr[3];
                break;
            case WINDIVERT_FILTER_FIELD_REMOTEADDR:
                val[0] = addr->Flow.RemoteAddr[0];
                val[1] = addr->Flow.RemoteAddr[1];
                val[2] = addr->Flow.RemoteAddr[2];
                val[3] = addr->Flow.RemoteAddr[3];
                break;
            case WINDIVERT_FILTER_FIELD_LOCALPORT:
                val[0] = addr->Flow.LocalPort;
                break;
            case WINDIVERT_FILTER_FIELD_REMOTEPORT:
                val[0] = addr->Flow.RemotePort;
                break;
            case WINDIVERT_FILTER_FIELD_PROTOCOL:
                val[0] = addr->Flow.Protocol;
                break;
            default:
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
        }
        cmp = WinDivertBigNumCompare(val, object[pc].arg);
        switch (object[pc].test)
        {
            case WINDIVERT_FILTER_TEST_EQ:
                pass = (cmp == 0);
                break;
            case WINDIVERT_FILTER_TEST_NEQ:
                pass = (cmp != 0);
                break;
            case WINDIVERT_FILTER_TEST_LT:
                pass = (cmp < 0);
                break;
            case WINDIVERT_FILTER_TEST_LEQ:
                pass = (cmp <= 0);
                break;
            case WINDIVERT_FILTER_TEST_GT:
                pass = (cmp > 0);
                break;
            case WINDIVERT_FILTER_TEST_GEQ:
                pass = (cmp >= 0);
                break;
            default:
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
        }
        pc = (pass? object[pc].success: object[pc].failure);
    }
}

/*
 * Get a char from a stream.
 */
static char WinDivertGetChar(PWINDIVERT_STREAM stream)
{
    char c;
    if (stream->pos >= stream->max)
    {
        stream->overflow = TRUE;
        return EOF;
    }
    c = stream->data[stream->pos];
    stream->pos++;
    return c;
}

/*
 * Deserialize a number.
 */
static BOOL WinDivertDeserializeNumber(PWINDIVERT_STREAM stream, UINT max_len,
    UINT32 *result)
{
    UINT32 i, val = 0;
    char c;
    for (i = 0; i < max_len; i++)
    {
        if ((val & 0xF8000000) != 0)
        {
            return FALSE;       // Overflow
        }
        val <<= 5;
        c = WinDivertGetChar(stream);
        if (c >= '!' && c <= '!' + 31)
        {
            val += (UINT32)(c - '!');
        }
        else if (c >= '!' + 32 && c <= '!' + 64)
        {
            val += (UINT32)(c - '!' - 32);
            *result = val;
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }
    return FALSE;
}

/*
 * Deserialize a test.
 */
static BOOL WinDivertDeserializeTest(PWINDIVERT_STREAM stream,
    PWINDIVERT_FILTER filter)
{
    UINT32 val;
    UINT i;

    if (WinDivertGetChar(stream) != '_')
    {
        return FALSE;
    }

    if (!WinDivertDeserializeNumber(stream, 2, &val) ||
            val > WINDIVERT_FILTER_FIELD_MAX)
    {
        return FALSE;
    }
    filter->field = (UINT8)val;

    if (!WinDivertDeserializeNumber(stream, 2, &val) ||
            val > WINDIVERT_FILTER_TEST_MAX)
    {
        return FALSE;
    }
    filter->test = (UINT8)val;

    if (!WinDivertDeserializeNumber(stream, 7, &filter->arg[0]))
    {
        return FALSE;
    }

    switch (filter->field)
    {
        case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
        case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
        case WINDIVERT_FILTER_FIELD_LOCALADDR:
        case WINDIVERT_FILTER_FIELD_REMOTEADDR:
            for (i = 1; i < 4; i++)
            {
                if (!WinDivertDeserializeNumber(stream, 7, &filter->arg[i]))
                {
                    return FALSE;
                }
            }
            break;
        case WINDIVERT_FILTER_FIELD_IP_SRCADDR:
        case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
            filter->arg[1] = 0x0000FFFF;
            filter->arg[2] = filter->arg[3] = 0;
            break;
        default:
            filter->arg[1] = filter->arg[2] = filter->arg[3] = 0;
            break;
    }

    if (!WinDivertDeserializeNumber(stream, 2, &val) || val > UINT8_MAX)
    {
        return FALSE;
    }
    filter->success = (UINT8)val - 2;

    if (!WinDivertDeserializeNumber(stream, 2, &val) || val > UINT8_MAX)
    {
        return FALSE;
    }
    filter->failure = (UINT8)val - 2;

    return TRUE;
}

/*
 * Deserialize a filter header.
 */
static BOOL WinDivertDeserializeFilterHeader(PWINDIVERT_STREAM stream,
    UINT *length)
{
    UINT32 version, length32;

    if (WinDivertGetChar(stream) != '@' ||
        WinDivertGetChar(stream) != 'W' ||
        WinDivertGetChar(stream) != 'i' ||
        WinDivertGetChar(stream) != 'n' ||
        WinDivertGetChar(stream) != 'D' ||
        WinDivertGetChar(stream) != 'i' ||
        WinDivertGetChar(stream) != 'v' ||
        WinDivertGetChar(stream) != '_')
    {
        return FALSE;
    }

    if (!WinDivertDeserializeNumber(stream, 4, &version) || (version != 0))
    {
        return FALSE;
    }

    if (!WinDivertDeserializeNumber(stream, 2, &length32) ||
            length32 == 0 || length32 > WINDIVERT_FILTER_MAXLEN)
    {
        return FALSE;
    }
    *length = length32;

    return TRUE;
}

/*
 * Deserialize a filter.
 */
static BOOL WinDivertDeserializeFilter(PWINDIVERT_STREAM stream,
    PWINDIVERT_FILTER filter, UINT *length)
{
    UINT i;

    if (!WinDivertDeserializeFilterHeader(stream, length))
    {
        return FALSE;
    }

    for (i = 0; i < *length; i++)
    {
        if (!WinDivertDeserializeTest(stream, filter + i))
        {
            return FALSE;
        }
    }

    if (WinDivertGetChar(stream) != '\0')
    {
        return FALSE;
    }

    return TRUE;
}

/*
 * Decompile a test into an expression.
 */
static PEXPR WinDivertDecompileTest(HANDLE pool, PWINDIVERT_FILTER test)
{
    KIND kind;
    PEXPR var, val, expr;
    ERROR error;

    switch (test->field)
    {
        case WINDIVERT_FILTER_FIELD_ZERO:
            kind = TOKEN_ZERO; break;
        case WINDIVERT_FILTER_FIELD_INBOUND:
            kind = TOKEN_INBOUND; break;
        case WINDIVERT_FILTER_FIELD_OUTBOUND:
            kind = TOKEN_OUTBOUND; break;
        case WINDIVERT_FILTER_FIELD_IFIDX:
            kind = TOKEN_IF_IDX; break;
        case WINDIVERT_FILTER_FIELD_SUBIFIDX:
            kind = TOKEN_SUB_IF_IDX; break;
        case WINDIVERT_FILTER_FIELD_IP:
            kind = TOKEN_IP; break;
        case WINDIVERT_FILTER_FIELD_IPV6:
            kind = TOKEN_IPV6; break;
        case WINDIVERT_FILTER_FIELD_ICMP:
            kind = TOKEN_ICMP; break;
        case WINDIVERT_FILTER_FIELD_TCP:
            kind = TOKEN_TCP; break;
        case WINDIVERT_FILTER_FIELD_UDP:
            kind = TOKEN_UDP; break;
        case WINDIVERT_FILTER_FIELD_ICMPV6:
            kind = TOKEN_ICMPV6; break;
        case WINDIVERT_FILTER_FIELD_IP_HDRLENGTH:
            kind = TOKEN_IP_HDR_LENGTH; break;
        case WINDIVERT_FILTER_FIELD_IP_TOS:
            kind = TOKEN_IP_TOS; break;
        case WINDIVERT_FILTER_FIELD_IP_LENGTH:
            kind = TOKEN_IP_LENGTH; break;
        case WINDIVERT_FILTER_FIELD_IP_ID:
            kind = TOKEN_IP_ID; break;
        case WINDIVERT_FILTER_FIELD_IP_DF:
            kind = TOKEN_IP_DF; break;
        case WINDIVERT_FILTER_FIELD_IP_MF:
            kind = TOKEN_IP_MF; break;
        case WINDIVERT_FILTER_FIELD_IP_FRAGOFF:
            kind = TOKEN_IP_FRAG_OFF; break;
        case WINDIVERT_FILTER_FIELD_IP_TTL:
            kind = TOKEN_IP_TTL; break;
        case WINDIVERT_FILTER_FIELD_IP_PROTOCOL:
            kind = TOKEN_IP_PROTOCOL; break;
        case WINDIVERT_FILTER_FIELD_IP_CHECKSUM:
            kind = TOKEN_IP_CHECKSUM; break;
        case WINDIVERT_FILTER_FIELD_IP_SRCADDR:
            kind = TOKEN_IP_SRC_ADDR; break;
        case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
            kind = TOKEN_IP_DST_ADDR; break;
        case WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
            kind = TOKEN_IPV6_TRAFFIC_CLASS; break;
        case WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
            kind = TOKEN_IPV6_FLOW_LABEL; break;
        case WINDIVERT_FILTER_FIELD_IPV6_LENGTH:
            kind = TOKEN_IPV6_LENGTH; break;
        case WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
            kind = TOKEN_IPV6_NEXT_HDR; break;
        case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
            kind = TOKEN_IPV6_HOP_LIMIT; break;
        case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
            kind = TOKEN_IPV6_SRC_ADDR; break;
        case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
            kind = TOKEN_IPV6_DST_ADDR; break;
        case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
            kind = TOKEN_ICMP_TYPE; break;
        case WINDIVERT_FILTER_FIELD_ICMP_CODE:
            kind = TOKEN_ICMP_CODE; break;
        case WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
            kind = TOKEN_ICMP_CHECKSUM; break;
        case WINDIVERT_FILTER_FIELD_ICMP_BODY:
            kind = TOKEN_ICMP_BODY; break;
        case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
            kind = TOKEN_ICMPV6_TYPE; break;
        case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
            kind = TOKEN_ICMPV6_CODE; break;
        case WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
            kind = TOKEN_ICMPV6_CHECKSUM; break;
        case WINDIVERT_FILTER_FIELD_ICMPV6_BODY:
            kind = TOKEN_ICMPV6_BODY; break;
        case WINDIVERT_FILTER_FIELD_TCP_SRCPORT:
            kind = TOKEN_TCP_SRC_PORT; break;
        case WINDIVERT_FILTER_FIELD_TCP_DSTPORT:
            kind = TOKEN_TCP_DST_PORT; break;
        case WINDIVERT_FILTER_FIELD_TCP_SEQNUM:
            kind = TOKEN_TCP_SEQ_NUM; break;
        case WINDIVERT_FILTER_FIELD_TCP_ACKNUM:
            kind = TOKEN_TCP_ACK_NUM; break;
        case WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
            kind = TOKEN_TCP_HDR_LENGTH; break;
        case WINDIVERT_FILTER_FIELD_TCP_URG:
            kind = TOKEN_TCP_URG; break;
        case WINDIVERT_FILTER_FIELD_TCP_ACK:
            kind = TOKEN_TCP_ACK; break;
        case WINDIVERT_FILTER_FIELD_TCP_PSH:
            kind = TOKEN_TCP_PSH; break;
        case WINDIVERT_FILTER_FIELD_TCP_RST:
            kind = TOKEN_TCP_RST; break;
        case WINDIVERT_FILTER_FIELD_TCP_SYN:
            kind = TOKEN_TCP_SYN; break;
        case WINDIVERT_FILTER_FIELD_TCP_FIN:
            kind = TOKEN_TCP_FIN; break;
        case WINDIVERT_FILTER_FIELD_TCP_WINDOW:
            kind = TOKEN_TCP_WINDOW; break;
        case WINDIVERT_FILTER_FIELD_TCP_CHECKSUM:
            kind = TOKEN_TCP_CHECKSUM; break;
        case WINDIVERT_FILTER_FIELD_TCP_URGPTR:
            kind = TOKEN_TCP_URG_PTR; break;
        case WINDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
            kind = TOKEN_TCP_PAYLOAD_LENGTH; break;
        case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
            kind = TOKEN_UDP_SRC_PORT; break;
        case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
            kind = TOKEN_UDP_DST_PORT; break;
        case WINDIVERT_FILTER_FIELD_UDP_LENGTH:
            kind = TOKEN_UDP_LENGTH; break;
        case WINDIVERT_FILTER_FIELD_UDP_CHECKSUM:
            kind = TOKEN_UDP_CHECKSUM; break;
        case WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
            kind = TOKEN_UDP_PAYLOAD_LENGTH; break;
        case WINDIVERT_FILTER_FIELD_LOOPBACK:
            kind = TOKEN_LOOPBACK; break;
        case WINDIVERT_FILTER_FIELD_IMPOSTOR:
            kind = TOKEN_IMPOSTOR; break;
        case WINDIVERT_FILTER_FIELD_PROCESSID:
            kind = TOKEN_PROCESS_ID; break;
        case WINDIVERT_FILTER_FIELD_LOCALADDR:
            kind = TOKEN_LOCAL_ADDR; break;
        case WINDIVERT_FILTER_FIELD_REMOTEADDR:
            kind = TOKEN_REMOTE_ADDR; break;
        case WINDIVERT_FILTER_FIELD_LOCALPORT:
            kind = TOKEN_LOCAL_PORT; break;
        case WINDIVERT_FILTER_FIELD_REMOTEPORT:
            kind = TOKEN_REMOTE_PORT; break;
        case WINDIVERT_FILTER_FIELD_PROTOCOL:
            kind = TOKEN_PROTOCOL; break;
        case WINDIVERT_FILTER_FIELD_LAYER:
            kind = TOKEN_LAYER; break;
        default:
            return NULL;
    }

    var = WinDivertMakeVar(kind, &error);
    if (var == NULL)
    {
        return NULL;
    }
    val = WinDivertMakeNumber(pool, test->arg, &error);
    if (val == NULL)
    {
        return NULL;
    }
    
    switch (test->test)
    {
        case WINDIVERT_FILTER_TEST_EQ:
            kind = TOKEN_EQ; break;
        case WINDIVERT_FILTER_TEST_NEQ:
            kind = TOKEN_NEQ; break;
        case WINDIVERT_FILTER_TEST_LT:
            kind = TOKEN_LT; break;
        case WINDIVERT_FILTER_TEST_LEQ:
            kind = TOKEN_LEQ; break;
        case WINDIVERT_FILTER_TEST_GT:
            kind = TOKEN_GT; break;
        case WINDIVERT_FILTER_TEST_GEQ:
            kind = TOKEN_GEQ; break;
        default:
            return NULL;
    }

    expr = WinDivertMakeBinOp(pool, kind, var, val, &error);
    if (expr == NULL)
    {
        return NULL;
    }
    expr->succ = test->success;
    expr->fail = test->failure;
    return expr;
}

/*
 * Dereference an expression.
 */
static void WinDivertDerefExpr(PEXPR *exprs, UINT8 i)
{
    switch (i)
    {
        case WINDIVERT_FILTER_RESULT_ACCEPT:
        case WINDIVERT_FILTER_RESULT_REJECT:
            return;
        default:
            exprs[i]->count--;
            if (exprs[i]->count == 0)
            {
                exprs[i] = NULL;
            }
            return;
    }
}

/*
 * Apply an and/or simplification for WinDivertCoalesceAndOr().
 */
static PEXPR WinDivertSimplifyAndOr(HANDLE pool, PEXPR *exprs, PEXPR expr,
    BOOL and, UINT8 next, UINT8 other)
{
    PEXPR next_expr = exprs[next], new_expr;
    ERROR error;

    new_expr = WinDivertMakeBinOp(pool, (and? TOKEN_AND: TOKEN_OR), expr,
        next_expr, &error);
    if (new_expr == NULL)
    {
        return NULL;
    }
    new_expr->succ   = next_expr->succ;
    new_expr->fail   = next_expr->fail;
    new_expr->count  = expr->count;
    WinDivertDerefExpr(exprs, next);
    WinDivertDerefExpr(exprs, other);
    return new_expr;
}

/*
 * Detect and coalesce and/or (& (?:)) expression patterns.
 */
static PEXPR WinDivertCoalesceAndOr(HANDLE pool, PEXPR *exprs, UINT8 i,
    ERROR *error)
{
    PEXPR expr, next_expr, new_expr;
    BOOL singleton;
    static const EXPR true_expr  = {{{0}}, TOKEN_TRUE};
    
    expr = exprs[i];
    while (TRUE)
    {
        if (expr == NULL || expr->count == 0)
        {
            return NULL;
        }

        singleton = FALSE;
        switch (expr->succ)
        {
            case WINDIVERT_FILTER_RESULT_ACCEPT:
            case WINDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                next_expr = exprs[expr->succ];
                if (next_expr->count != 1)
                {
                    break;
                }
                singleton = TRUE;
                if (next_expr->fail == expr->fail)
                {
                    expr = WinDivertSimplifyAndOr(pool, exprs, expr,
                        /*and=*/TRUE, expr->succ, expr->fail);
                    continue;
                }
                else if (next_expr->succ == expr->fail)
                {
                    new_expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY,
                        sizeof(EXPR));
                    if (new_expr == NULL)
                    {
                        return NULL;
                    }
                    new_expr->kind   = TOKEN_QUESTION;
                    new_expr->arg[0] = expr;
                    new_expr->arg[1] = next_expr;
                    new_expr->arg[2] = (PEXPR)&true_expr;
                    new_expr->succ   = next_expr->succ;
                    new_expr->fail   = next_expr->fail;
                    new_expr->count  = expr->count;
                    WinDivertDerefExpr(exprs, expr->succ);
                    WinDivertDerefExpr(exprs, expr->fail);
                    expr = new_expr;
                    continue;
                }
                break;
        }
        switch (expr->fail)
        {
            case WINDIVERT_FILTER_RESULT_ACCEPT:
            case WINDIVERT_FILTER_RESULT_REJECT:
                singleton = FALSE;
                break;
            default:
                next_expr = exprs[expr->fail];
                if (next_expr->count != 1)
                {
                    singleton = FALSE;
                    break;
                }
                if (next_expr->succ == expr->succ)
                {
                    expr = WinDivertSimplifyAndOr(pool, exprs, expr,
                        /*and=*/FALSE, expr->fail, expr->succ);
                    continue;
                }
                else if (next_expr->fail == expr->succ)
                {
                    expr = WinDivertSimplifyAndOr(pool, exprs, expr,
                        /*and=*/TRUE, expr->fail, expr->succ);
                    continue;
                }
                break;
        }

        if (singleton)
        {
            // Both branches have count==1; simplify into a (?:) expression:
            PEXPR succ_expr, fail_expr;
            succ_expr = exprs[expr->succ];
            fail_expr = exprs[expr->fail];
            if (succ_expr->succ != fail_expr->succ ||
                succ_expr->fail != fail_expr->fail)
            {
                break;
            }
            new_expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY, sizeof(EXPR));
            if (new_expr == NULL)
            {
                return NULL;
            }
            new_expr->kind = TOKEN_QUESTION;
            new_expr->arg[0] = expr;
            new_expr->arg[1] = succ_expr;
            new_expr->arg[2] = fail_expr;
            new_expr->succ   = succ_expr->succ;
            new_expr->fail   = fail_expr->fail;
            new_expr->count  = expr->count;
            WinDivertDerefExpr(exprs, expr->succ);
            WinDivertDerefExpr(exprs, expr->fail);
            WinDivertDerefExpr(exprs, new_expr->succ);
            WinDivertDerefExpr(exprs, new_expr->fail);
            expr = new_expr;
            continue;
        }

        // No simplifications, so we are done.
        break;
    }

    exprs[i] = expr;
    return expr;
}

/*
 * Coalesce all remaining expressions.
 */
static PEXPR WinDivertCoalesceExpr(HANDLE pool, PEXPR *exprs, UINT8 i)
{
    PEXPR expr, succ_expr, fail_expr, new_expr;
    static const EXPR true_expr  = {{{0}}, TOKEN_TRUE};
    static const EXPR false_expr = {{{0}}, TOKEN_FALSE};

    switch (i)
    {
        case WINDIVERT_FILTER_RESULT_ACCEPT:
            return (PEXPR)&true_expr;
        case WINDIVERT_FILTER_RESULT_REJECT:
            return (PEXPR)&false_expr;
        default:
            break;
    }
    
    expr = exprs[i];
    if (expr == NULL)
    {
        return NULL;
    }

    if (expr->succ == expr->fail)
    {
        return WinDivertCoalesceExpr(pool, exprs, expr->succ);
    }

    succ_expr = WinDivertCoalesceExpr(pool, exprs, expr->succ);
    fail_expr = WinDivertCoalesceExpr(pool, exprs, expr->fail);
    if (succ_expr == NULL || fail_expr == NULL)
    {
        return NULL;
    }
    if (succ_expr->kind == TOKEN_TRUE && fail_expr->kind == TOKEN_FALSE)
    {
        return expr;
    }

    new_expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY, sizeof(EXPR));
    if (new_expr == NULL)
    {
        return NULL;
    }

    new_expr->kind = TOKEN_QUESTION;
    new_expr->arg[0] = expr;
    new_expr->arg[1] = succ_expr;
    new_expr->arg[2] = fail_expr;
    return new_expr;
}

/*
 * Format a decimal number.
 */
static void WinDivertFormatNumber(PWINDIVERT_STREAM stream, UINT32 val)
{
    UINT64 r = 1000000000, dig;
    BOOL zeroes = FALSE;

    while (r != 0)
    {
        dig = val / r;
        val = val % r;
        r = r / 10;
        if (dig == 0 && !zeroes && r != 0)
        {
            continue;
        }
        WinDivertPutChar(stream, '0' + dig);
        zeroes = TRUE;
    }
}

/*
 * Format a hexidecimal number.
 */
static void WinDivertFormatHexNumber(PWINDIVERT_STREAM stream, UINT32 val)
{
    INT s = 28;
    UINT32 dig;
    BOOL zeroes = FALSE;

    while (s >= 0)
    {
        dig = (val & ((UINT32)0xF << s)) >> s;
        s -= 4;
        if (dig == 0 && !zeroes && s >= 0)
        {
            continue;
        }
        WinDivertPutChar(stream, (dig <= 9? '0' + dig: 'a' + (dig - 10)));
        zeroes = TRUE;
    }
}

/*
 * Format an IPv4 address.
 */
static void WinDivertFormatIPv4Addr(PWINDIVERT_STREAM stream, UINT32 addr)
{
    WinDivertFormatNumber(stream, (addr & 0xFF000000) >> 24);
    WinDivertPutChar(stream, '.');
    WinDivertFormatNumber(stream, (addr & 0x00FF0000) >> 16);
    WinDivertPutChar(stream, '.');
    WinDivertFormatNumber(stream, (addr & 0x0000FF00) >> 8);
    WinDivertPutChar(stream, '.');
    WinDivertFormatNumber(stream, (addr & 0x000000FF) >> 0);
}

/*
 * Format an IPv6 address.
 */
static void WinDivertFormatIPv6Addr(PWINDIVERT_STREAM stream,
    const UINT32 *addr32)
{
    INT i, z_curr, z_count, z_start, z_max;
    UINT16 addr[8];

    // IPv4 special case:
    if (addr32[3] == 0 && addr32[2] == 0 && addr32[1] == 0x0000FFFF)
    {
        WinDivertFormatIPv4Addr(stream, addr32[0]);
        return;
    }

    // Find zeroes:
    memcpy(addr, addr32, sizeof(addr));
    z_curr = 7;
    z_count = 0;
    z_start = z_max = -1;
    for (i = 7; i >= 0; i--)
    {
        if (addr[i] == 0)
        {
            z_count++;
            z_start = (z_count > z_max? z_curr: z_start);
            z_max = (z_count > z_max? z_count: z_max);
        }
        else
        {
            z_curr = i-1;
            z_count = 0;
        }
    }

    // Format address:
    for (i = 7; i >= 0; i--)
    {
        if (i == z_start)
        {
            WinDivertPutString(stream, (i == 7? "::": ":"));
            i -= (z_max-1);
            continue;
        }
        WinDivertFormatHexNumber(stream, addr[i]);
        WinDivertPutString(stream, (i != 0? ":": ""));
    }
}

/*
 * Format a test expression.
 */
static void WinDivertFormatTestExpr(PWINDIVERT_STREAM stream, PEXPR expr)
{
    PEXPR field = expr->arg[0], val = expr->arg[1];
    BOOL ipv4_addr = FALSE, ipv6_addr = FALSE, layer = FALSE;

    switch (field->kind)
    {
        case TOKEN_ZERO:
        case TOKEN_INBOUND:
        case TOKEN_OUTBOUND:
        case TOKEN_IP:
        case TOKEN_IPV6:
        case TOKEN_ICMP:
        case TOKEN_TCP:
        case TOKEN_UDP:
        case TOKEN_ICMPV6:
        case TOKEN_IP_DF:
        case TOKEN_IP_MF:
        case TOKEN_TCP_URG:
        case TOKEN_TCP_ACK:
        case TOKEN_TCP_PSH:
        case TOKEN_TCP_RST:
        case TOKEN_TCP_SYN:
        case TOKEN_TCP_FIN:
        case TOKEN_LOOPBACK:
        case TOKEN_IMPOSTOR:
            if (val->val[1] != 0 || val->val[2] != 0 || val->val[3] != 0 ||
                val->val[0] > 1)
            {
                break;
            }
            switch (expr->kind)
            {
                case TOKEN_EQ:
                    WinDivertPutString(stream, (val->val[0] == 0? "not ": ""));
                    WinDivertFormatExpr(stream, field, /*top_level=*/FALSE,
                        /*and=*/FALSE);
                    return;
                case TOKEN_NEQ:
                    WinDivertPutString(stream, (val->val[0] != 0? "not ": ""));
                    WinDivertFormatExpr(stream, field, /*top_level=*/FALSE,
                        /*and=*/FALSE);
                    return;
                default:
                    break;
            }
            break;
        case TOKEN_IP_SRC_ADDR:
        case TOKEN_IP_DST_ADDR:
            ipv4_addr = TRUE;
            break;
        case TOKEN_IPV6_SRC_ADDR:
        case TOKEN_IPV6_DST_ADDR:
        case TOKEN_LOCAL_ADDR:
        case TOKEN_REMOTE_ADDR:
            ipv6_addr = TRUE;
            break;
        case TOKEN_LAYER:
            layer = TRUE;
            break;
        default:
            break;
    }

    WinDivertFormatExpr(stream, field, /*top_level=*/FALSE, /*and=*/FALSE);
    switch (expr->kind)
    {
        case TOKEN_EQ:
            WinDivertPutString(stream, " = "); break;
        case TOKEN_NEQ:
            WinDivertPutString(stream, " != "); break;
        case TOKEN_LT:
            WinDivertPutString(stream, " < "); break;
        case TOKEN_LEQ:
            WinDivertPutString(stream, " <= "); break;
        case TOKEN_GT:
            WinDivertPutString(stream, " > "); break;
        case TOKEN_GEQ:
            WinDivertPutString(stream, " >= "); break;
    }
    if (ipv4_addr)
    {
        WinDivertFormatIPv4Addr(stream, val->val[0]);
    }
    else if (ipv6_addr)
    {
        WinDivertFormatIPv6Addr(stream, val->val);
    }
    else if (layer)
    {
        switch (val->val[0])
        {
            case WINDIVERT_LAYER_NETWORK:
                WinDivertPutString(stream, "NETWORK"); break;
            case WINDIVERT_LAYER_NETWORK_FORWARD:
                WinDivertPutString(stream, "NETWORK_FORWARD"); break;
            case WINDIVERT_LAYER_FLOW:
                WinDivertPutString(stream, "FLOW"); break;
            case WINDIVERT_LAYER_REFLECT:
                WinDivertPutString(stream, "REFLECT"); break;
            default:
                WinDivertFormatNumber(stream, val->val[0]); break;
        }
    }
    else
    {
        WinDivertFormatNumber(stream, val->val[0]);
    }
}

/*
 * Format an expression.
 */
static void WinDivertFormatExpr(PWINDIVERT_STREAM stream, PEXPR expr,
    BOOL top_level, BOOL and)
{
    if (stream->pos >= stream->max)
    {
        return;
    }

    switch (expr->kind)
    {
        case TOKEN_AND:
            if (!top_level && !and)
            {
                WinDivertPutChar(stream, '(');
            }
            WinDivertFormatExpr(stream, expr->arg[0], /*top_level=*/FALSE,
                /*and=*/TRUE);
            WinDivertPutString(stream, " and ");
            WinDivertFormatExpr(stream, expr->arg[1], /*top_level=*/FALSE,
                /*and=*/TRUE);
            if (!top_level && !and)
            {
                WinDivertPutChar(stream, ')');
            }
            return;
        case TOKEN_OR:
            if (!top_level && and)
            {
                WinDivertPutChar(stream, '(');
            }
            WinDivertFormatExpr(stream, expr->arg[0], /*top_level=*/FALSE,
                /*and=*/FALSE);
            WinDivertPutString(stream, " or ");
            WinDivertFormatExpr(stream, expr->arg[1], /*top_level=*/FALSE,
                /*and=*/FALSE);
            if (!top_level && and)
            {
                WinDivertPutChar(stream, ')');
            }
            return;
        case TOKEN_QUESTION:
            WinDivertPutChar(stream, '(');
            WinDivertFormatExpr(stream, expr->arg[0], /*top_level=*/TRUE,
                /*and=*/FALSE);
            WinDivertPutString(stream, "? ");
            WinDivertFormatExpr(stream, expr->arg[1], /*top_level=*/TRUE,
                /*and=*/FALSE);
            WinDivertPutString(stream, ": ");
            WinDivertFormatExpr(stream, expr->arg[2], /*top_level=*/TRUE,
                /*and=*/FALSE);
            WinDivertPutChar(stream, ')');
            return;
        case TOKEN_TRUE:
            WinDivertPutString(stream, "true");
            return;
        case TOKEN_FALSE:
            WinDivertPutString(stream, "false");
            return;
        case TOKEN_EQ:
        case TOKEN_NEQ:
        case TOKEN_LT:
        case TOKEN_LEQ:
        case TOKEN_GT:
        case TOKEN_GEQ:
            WinDivertFormatTestExpr(stream, expr);
            return;
        case TOKEN_ZERO:
            WinDivertPutString(stream, "zero"); return;
        case TOKEN_INBOUND:
            WinDivertPutString(stream, "inbound"); return;
        case TOKEN_OUTBOUND:
            WinDivertPutString(stream, "outbound"); return;
        case TOKEN_IF_IDX:
            WinDivertPutString(stream, "ifIdx"); return;
        case TOKEN_SUB_IF_IDX:
            WinDivertPutString(stream, "subIfIdx"); return;
        case TOKEN_IP:
            WinDivertPutString(stream, "ip"); return;
        case TOKEN_IPV6:
            WinDivertPutString(stream, "ipv6"); return;
        case TOKEN_ICMP:
            WinDivertPutString(stream, "icmp"); return;
        case TOKEN_TCP:
            WinDivertPutString(stream, "tcp"); return;
        case TOKEN_UDP:
            WinDivertPutString(stream, "udp"); return;
        case TOKEN_ICMPV6:
            WinDivertPutString(stream, "icmpv6"); return;
        case TOKEN_IP_HDR_LENGTH:
            WinDivertPutString(stream, "ip.HdrLength"); return;
        case TOKEN_IP_TOS:
            WinDivertPutString(stream, "ip.TOS"); return;
        case TOKEN_IP_LENGTH:
            WinDivertPutString(stream, "ip.Length"); return;
        case TOKEN_IP_ID:
            WinDivertPutString(stream, "ip.Id"); return;
        case TOKEN_IP_DF:
            WinDivertPutString(stream, "ip.DF"); return;
        case TOKEN_IP_MF:
            WinDivertPutString(stream, "ip.MF"); return;
        case TOKEN_IP_FRAG_OFF:
            WinDivertPutString(stream, "ip.FragOff"); return;
        case TOKEN_IP_TTL:
            WinDivertPutString(stream, "ip.TTL"); return;
        case TOKEN_IP_PROTOCOL:
            WinDivertPutString(stream, "ip.Protocol"); return;
        case TOKEN_IP_CHECKSUM:
            WinDivertPutString(stream, "ip.Checksum"); return;
        case TOKEN_IP_SRC_ADDR:
            WinDivertPutString(stream, "ip.SrcAddr"); return;
        case TOKEN_IP_DST_ADDR:
            WinDivertPutString(stream, "ip.DstAddr"); return;
        case TOKEN_IPV6_TRAFFIC_CLASS:
            WinDivertPutString(stream, "ipv6.TrafficClass"); return;
        case TOKEN_IPV6_FLOW_LABEL:
            WinDivertPutString(stream, "ipv6.FlowLabel"); return;
        case TOKEN_IPV6_LENGTH:
            WinDivertPutString(stream, "ipv6.Length"); return;
        case TOKEN_IPV6_NEXT_HDR:
            WinDivertPutString(stream, "ipv6.NextHdr"); return;
        case TOKEN_IPV6_HOP_LIMIT:
            WinDivertPutString(stream, "ipv6.HopLimit"); return;
        case TOKEN_IPV6_SRC_ADDR:
            WinDivertPutString(stream, "ipv6.SrcAddr"); return;
        case TOKEN_IPV6_DST_ADDR:
            WinDivertPutString(stream, "ipv6.DstAddr"); return;
        case TOKEN_ICMP_TYPE:
            WinDivertPutString(stream, "icmp.Type"); return;
        case TOKEN_ICMP_CODE:
            WinDivertPutString(stream, "icmp.Code"); return;
        case TOKEN_ICMP_CHECKSUM:
            WinDivertPutString(stream, "icmp.Checksum"); return;
        case TOKEN_ICMP_BODY:
            WinDivertPutString(stream, "icmp.Body"); return;
        case TOKEN_ICMPV6_TYPE:
            WinDivertPutString(stream, "icmpv6.Type"); return;
        case TOKEN_ICMPV6_CODE:
            WinDivertPutString(stream, "icmpv6.Code"); return;
        case TOKEN_ICMPV6_CHECKSUM:
            WinDivertPutString(stream, "icmpv6.Checksum"); return;
        case TOKEN_ICMPV6_BODY:
            WinDivertPutString(stream, "icmpv6.Body"); return;
        case TOKEN_TCP_SRC_PORT:
            WinDivertPutString(stream, "tcp.SrcPort"); return;
        case TOKEN_TCP_DST_PORT:
            WinDivertPutString(stream, "tcp.DstPort"); return;
        case TOKEN_TCP_SEQ_NUM:
            WinDivertPutString(stream, "tcp.SeqNum"); return;
        case TOKEN_TCP_ACK_NUM:
            WinDivertPutString(stream, "tcp.AckNum"); return;
        case TOKEN_TCP_HDR_LENGTH:
            WinDivertPutString(stream, "tcp.HdrLength"); return;
        case TOKEN_TCP_URG:
            WinDivertPutString(stream, "tcp.Urg"); return;
        case TOKEN_TCP_ACK:
            WinDivertPutString(stream, "tcp.Ack"); return;
        case TOKEN_TCP_PSH:
            WinDivertPutString(stream, "tcp.Psh"); return;
        case TOKEN_TCP_RST:
            WinDivertPutString(stream, "tcp.Rst"); return;
        case TOKEN_TCP_SYN:
            WinDivertPutString(stream, "tcp.Syn"); return;
        case TOKEN_TCP_FIN:
            WinDivertPutString(stream, "tcp.Fin"); return;
        case TOKEN_TCP_WINDOW:
            WinDivertPutString(stream, "tcp.Window"); return;
        case TOKEN_TCP_CHECKSUM:
            WinDivertPutString(stream, "tcp.Checksum"); return;
        case TOKEN_TCP_URG_PTR:
            WinDivertPutString(stream, "tcp.UrgPtr"); return;
        case TOKEN_TCP_PAYLOAD_LENGTH:
            WinDivertPutString(stream, "tcp.PayloadLength"); return;
        case TOKEN_UDP_SRC_PORT:
            WinDivertPutString(stream, "udp.SrcPort"); return;
        case TOKEN_UDP_DST_PORT:
            WinDivertPutString(stream, "udp.DstPort"); return;
        case TOKEN_UDP_LENGTH:
            WinDivertPutString(stream, "udp.Length"); return;
        case TOKEN_UDP_CHECKSUM:
            WinDivertPutString(stream, "udp.Checksum"); return;
        case TOKEN_UDP_PAYLOAD_LENGTH:
            WinDivertPutString(stream, "udp.PayloadLength"); return;
        case TOKEN_LOOPBACK:
            WinDivertPutString(stream, "loopback"); return;
        case TOKEN_IMPOSTOR:
            WinDivertPutString(stream, "impostor"); return;
        case TOKEN_PROCESS_ID:
            WinDivertPutString(stream, "processId"); return;
        case TOKEN_LOCAL_ADDR:
            WinDivertPutString(stream, "localAddr"); return;
        case TOKEN_REMOTE_ADDR:
            WinDivertPutString(stream, "remoteAddr"); return;
        case TOKEN_LOCAL_PORT:
            WinDivertPutString(stream, "localPort"); return;
        case TOKEN_REMOTE_PORT:
            WinDivertPutString(stream, "remotePort"); return;
        case TOKEN_PROTOCOL:
            WinDivertPutString(stream, "protocol"); return;
        case TOKEN_LAYER:
            WinDivertPutString(stream, "layer"); return;
        case TOKEN_NUMBER:
            WinDivertFormatNumber(stream, expr->val[0]);
            return;
    }
}

/*
 * Format a filter string.
 */
BOOL WinDivertHelperFormatFilter(const char *filter, WINDIVERT_LAYER layer,
    char *buffer, UINT buflen)
{
    PEXPR exprs[WINDIVERT_FILTER_MAXLEN], expr;
    ERROR err;
    WINDIVERT_FILTER object[WINDIVERT_FILTER_MAXLEN];
    UINT obj_len;
    INT i;
    HANDLE pool;
    WINDIVERT_STREAM stream;
    ERROR error;
    const SIZE_T min_pool_size = 8192;

    if (filter == NULL || buffer == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    err = WinDivertCompileFilter(filter, layer, object, &obj_len);
    if (IS_ERROR(err))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    pool = HeapCreate(HEAP_NO_SERIALIZE, min_pool_size, 16 * min_pool_size);
    if (pool == NULL)
    {
        return FALSE;
    }

    // Decompile all tests:
    for (i = (INT)obj_len-1; i >= 0; i--)
    {
        expr = WinDivertDecompileTest(pool, object + i);
        if (expr == NULL)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        exprs[i] = expr;
        switch (expr->succ)
        {
            case WINDIVERT_FILTER_RESULT_ACCEPT:
            case WINDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                exprs[expr->succ]->count++;
                break;
        }
        switch (expr->fail)
        {
            case WINDIVERT_FILTER_RESULT_ACCEPT:
            case WINDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                exprs[expr->fail]->count++;
                break;
        }
    }
    exprs[0]->count++;

    // Coalesce (unflatten) tests into and/or expressions:
    for (i = (INT)obj_len-1; i >= 0; i--)
    {
        error = MAKE_ERROR(WINDIVERT_ERROR_NONE, 0);
        (PVOID)WinDivertCoalesceAndOr(pool, exprs, i, &error);
        if (IS_ERROR(error))
        {
            HeapDestroy(pool);
            return FALSE;
        }
    }

    // Coalesce remaining expressions:
    expr = WinDivertCoalesceExpr(pool, exprs, 0);
    if (expr == NULL)
    {
        HeapDestroy(pool);
        return FALSE;
    }

    // Format the final expression:
    stream.data     = buffer;
    stream.pos      = 0;
    stream.max      = buflen;
    stream.overflow = FALSE;
    WinDivertFormatExpr(&stream, expr, /*top_level=*/TRUE, /*and=*/FALSE);
    WinDivertPutChar(&stream, '\0');

    // Clean-up:
    HeapDestroy(pool);
    if (!stream.overflow)
    {
        return TRUE;
    }
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return FALSE;
}

