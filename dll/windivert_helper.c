/*
 * windivert_helper.c
 * (C) 2017, all rights reserved,
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
    TOKEN_TRUE,
    TOKEN_FALSE,
    TOKEN_INBOUND,
    TOKEN_OUTBOUND,
    TOKEN_IF_IDX,
    TOKEN_SUB_IF_IDX,
    TOKEN_LOOPBACK,
    TOKEN_IMPOSTOR,
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
    UINT16 succ;
    UINT16 fail;
};

/*
 * Error handling.
 */
#undef ERROR
typedef UINT64 ERROR;

#define WINDIVERT_ERROR_NONE                    0
#define WINDIVERT_ERROR_NO_MEMORY               1
#define WINDIVERT_ERROR_TOO_DEEP                2
#define WINDIVERT_ERROR_TOO_LONG                3
#define WINDIVERT_ERROR_BAD_TOKEN               4
#define WINDIVERT_ERROR_BAD_TOKEN_FOR_LAYER     5
#define WINDIVERT_ERROR_UNEXPECTED_TOKEN        6
#define WINDIVERT_ERROR_OUTPUT_TOO_SHORT        7
#define WINDIVERT_ERROR_ASSERTION_FAILED        8

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
 * Compiler memory pool:
 */
typedef struct POOL
{
    unsigned offset;
    ERROR error;
    char memory[3 * 4096 - 32];
} POOL, *PPOOL;

/*
 * Prototypes.
 */
static PEXPR WinDivertParseFilter(PPOOL pool, TOKEN *toks, UINT *i, INT depth,
    BOOL and);
static UINT16 WinDivertInitPseudoHeader(PWINDIVERT_IPHDR ip_header,
    PWINDIVERT_IPV6HDR ipv6_header, UINT8 protocol, UINT len,
    void *pseudo_header);
static UINT16 WinDivertHelperCalcChecksum(PVOID pseudo_header,
    UINT16 pseudo_header_len, PVOID data, UINT len);

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
        else if (pAddr->Direction == WINDIVERT_DIRECTION_OUTBOUND)
        {
            // Pseudo TCP checksum
            checksum_len = payload_len + tcp_header->HdrLength*sizeof(UINT32);
            pseudo_header_len = WinDivertInitPseudoHeader(ip_header,
                ipv6_header, IPPROTO_TCP, checksum_len, pseudo_header);
            tcp_header->Checksum = ~WinDivertHelperCalcChecksum(
                pseudo_header, pseudo_header_len, NULL, 0);
        }
        else
        {
            // Don't care checksum
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
        else if (pAddr->Direction == WINDIVERT_DIRECTION_OUTBOUND)
        {
            // Pseudo UDP checksum
            checksum_len = payload_len + sizeof(WINDIVERT_UDPHDR);
            pseudo_header_len = WinDivertInitPseudoHeader(ip_header,
                ipv6_header, IPPROTO_UDP, checksum_len, pseudo_header);
            udp_header->Checksum = ~WinDivertHelperCalcChecksum(
                pseudo_header, pseudo_header_len, NULL, 0);
        }
        else
        {
            // Don't care checksum
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
        for (l = 0; l < 4 && isxdigit(*str); l++)
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
        addr_ptr[i] =
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
        cmp = strcmp(token_names[mid].name, name);
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
 * Tokenize the given filter string.
 */
static ERROR WinDivertTokenizeFilter(const char *filter, WINDIVERT_LAYER layer,
    TOKEN *tokens, UINT tokensmax)
{
    static const TOKEN_NAME token_names[] =
    {
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
        {"loopback",            TOKEN_LOOPBACK},
        {"not",                 TOKEN_NOT},
        {"or",                  TOKEN_OR},
        {"outbound",            TOKEN_OUTBOUND},
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
        while (isspace(filter[i]))
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
        if (isalnum(c) || c == '.' || c == ':')
        {
            UINT32 num;
            char *end;
            for (j = 1; j < TOKEN_MAXLEN && (isalnum(filter[i]) ||
                    filter[i] == '.' || filter[i] == ':'); j++, i++)
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
                switch (layer)
                {
                    case WINDIVERT_LAYER_NETWORK_FORWARD:
                        if (result->kind == TOKEN_INBOUND ||
                            result->kind == TOKEN_OUTBOUND)
                        {
                            return MAKE_ERROR(
                                WINDIVERT_ERROR_BAD_TOKEN_FOR_LAYER, i-j);
                        }
                        break;
                    default:
                        break;
                }
                tokens[tp++].kind = result->kind;
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
                tokens[tp].kind = TOKEN_NUMBER;
                tp++;
                continue;
            }

            // Check for IPv6 address:
            SetLastError(0);
            if (WinDivertHelperParseIPv6Address(token, tokens[tp].val))
            {
                // Work-around the different word orderings between the
                // DLL vs SYS.
                UINT32 tmp;
                tmp = tokens[tp].val[0];
                tokens[tp].val[0] = tokens[tp].val[3];
                tokens[tp].val[3] = tmp;
                tmp = tokens[tp].val[1];
                tokens[tp].val[1] = tokens[tp].val[2];
                tokens[tp].val[2] = tmp;

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
 * Pool allocation.
 */
static void *WinDivertAlloc(PPOOL pool, UINT size)
{
    void *ptr;
    if (pool->offset + size >= sizeof(pool->memory))
    {
        pool->error = MAKE_ERROR(WINDIVERT_ERROR_NO_MEMORY, 0);
        return NULL;
    }
    ptr = pool->memory + pool->offset;
    pool->offset += size;
    return ptr;
};

/*
 * Construct a variable/field.
 */
static PEXPR WinDivertMakeVar(PPOOL pool, KIND kind)
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
        {{{0}}, TOKEN_TRUE},
        {{{0}}, TOKEN_FALSE},
        {{{0}}, TOKEN_INBOUND},
        {{{0}}, TOKEN_OUTBOUND},
        {{{0}}, TOKEN_IF_IDX},
        {{{0}}, TOKEN_SUB_IF_IDX},
        {{{0}}, TOKEN_LOOPBACK},
        {{{0}}, TOKEN_IMPOSTOR}
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
    pool->error = MAKE_ERROR(WINDIVERT_ERROR_ASSERTION_FAILED, 0);
    return NULL;
}

/*
 * Construct zero.
 */
static PEXPR WinDivertMakeZero(PPOOL pool)
{
    static const EXPR zero = {{{0, 0, 0, 0}}, TOKEN_NUMBER};
    return (PEXPR)&zero;
}

/*
 * Construct a number.
 */
static PEXPR WinDivertMakeNumber(PPOOL pool, TOKEN *tok)
{
    PEXPR expr;
    if (tok->kind != TOKEN_NUMBER)
    {
        pool->error = MAKE_ERROR(WINDIVERT_ERROR_ASSERTION_FAILED, 0);
        return NULL;
    }
    expr = (PEXPR)WinDivertAlloc(pool, sizeof(EXPR));
    if (expr == NULL)
    {
        return NULL;
    }
    memset(expr, 0, sizeof(EXPR));
    expr->kind = TOKEN_NUMBER;
    expr->val[0] = tok->val[0];
    expr->val[1] = tok->val[1];
    expr->val[2] = tok->val[2];
    expr->val[3] = tok->val[3];
    return expr;
}

/*
 * Construct a binary operator.
 */
static PEXPR WinDivertMakeBinOp(PPOOL pool, KIND kind, PEXPR arg0, PEXPR arg1)
{
    PEXPR expr;
    if (arg0 == NULL || arg1 == NULL)
    {
        return NULL;
    }
    expr = (PEXPR)WinDivertAlloc(pool, sizeof(EXPR));
    if (expr == NULL)
    {
        return NULL;
    }
    memset(expr, 0, sizeof(EXPR));
    expr->kind = kind;
    expr->arg[0] = arg0;
    expr->arg[1] = arg1;
    return expr;
}

/*
 * Construct an if-then-else.
 */
static PEXPR WinDivertMakeIfThenElse(PPOOL pool, PEXPR cond, PEXPR th,
    PEXPR el)
{
    PEXPR expr = (PEXPR)WinDivertAlloc(pool, sizeof(EXPR));
    if (expr == NULL)
    {
        return NULL;
    }
    memset(expr, 0, sizeof(EXPR));
    expr->kind = TOKEN_QUESTION;
    expr->arg[0] = cond;
    expr->arg[1] = th;
    expr->arg[2] = el;
    return expr;
}

/*
 * Parse a filter test.
 */
static PEXPR WinDivertParseTest(PPOOL pool, TOKEN *toks, UINT *i)
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
            pool->error = MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN,
                toks[*i].pos);
            return NULL;
    }
    var = WinDivertMakeVar(pool, toks[*i].kind);
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
                WinDivertMakeZero(pool));
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
        pool->error = MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN,
            toks[*i].pos);
        return NULL;
    }
    val = WinDivertMakeNumber(pool, toks + *i);
    *i = *i + 1;
    return WinDivertMakeBinOp(pool, kind, var, val);
}

/*
 * Parse a filter argument to an (and) (or) operator.
 */
static PEXPR WinDivertParseArg(PPOOL pool, TOKEN *toks, UINT *i, INT depth)
{
    PEXPR arg, th, el;
    if (depth-- < 0)
    {
        pool->error = MAKE_ERROR(WINDIVERT_ERROR_TOO_DEEP, toks[*i].pos);
        return NULL;
    }
    switch (toks[*i].kind)
    {
        case TOKEN_OPEN:
            *i = *i + 1;
            arg = WinDivertParseFilter(pool, toks, i, depth, FALSE);
            if (toks[*i].kind == TOKEN_CLOSE)
            {
                *i = *i + 1;
                return arg;
            }
            if (toks[*i].kind == TOKEN_QUESTION)
            {
                *i = *i + 1;
                th = WinDivertParseFilter(pool, toks, i, depth, FALSE);
                if (th == NULL)
                {
                    return NULL;
                }
                if (toks[*i].kind != TOKEN_COLON)
                {
                    pool->error = MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN,
                        toks[*i].pos);
                    return NULL;
                }
                *i = *i + 1;
                el = WinDivertParseFilter(pool, toks, i, depth, FALSE);
                if (el == NULL)
                {
                    return NULL;
                }
                if (toks[*i].kind != TOKEN_CLOSE)
                {
                    pool->error = MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN,
                        toks[*i].pos);
                    return NULL;
                }
                *i = *i + 1;
                arg = WinDivertMakeIfThenElse(pool, arg, th, el);
                return arg;
            }
            pool->error = MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN,
                toks[*i].pos);
            return NULL;
        default:
            return WinDivertParseTest(pool, toks, i);
    }
}

/*
 * Parse the filter into an expression object.
 */
static PEXPR WinDivertParseFilter(PPOOL pool, TOKEN *toks, UINT *i, INT depth,
    BOOL and)
{
    PEXPR expr, arg;
    if (depth-- < 0)
    {
        pool->error = MAKE_ERROR(WINDIVERT_ERROR_TOO_DEEP, toks[*i].pos);
        return NULL;
    }
    if (and)
        expr = WinDivertParseArg(pool, toks, i, depth);
    else
        expr = WinDivertParseFilter(pool, toks, i, depth, TRUE);
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
                arg = WinDivertParseArg(pool, toks, i, depth);
                expr = WinDivertMakeBinOp(pool, TOKEN_AND, expr, arg);
                continue;
            case TOKEN_OR:
                *i = *i + 1;
                arg = WinDivertParseFilter(pool, toks, i, depth, TRUE);
                expr = WinDivertMakeBinOp(pool, TOKEN_OR, expr, arg);
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
        case TOKEN_TRUE:
            lb = ub = 1;
            break;
        case TOKEN_FALSE:
            lb = ub = 0;
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
            lb = 0; ub = 0xFFFF;
            break;
        case TOKEN_IPV6_FLOW_LABEL:
            lb = 0; ub = 0x000FFFFF;
            break;
        case TOKEN_IPV6_SRC_ADDR:
        case TOKEN_IPV6_DST_ADDR:
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
    windivert_ioctl_filter_t object)
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
    windivert_ioctl_filter_t object, UINT *obj_len)
{
    UINT i;
    switch (label)
    {
        case WINDIVERT_FILTER_RESULT_ACCEPT:
        case WINDIVERT_FILTER_RESULT_REJECT:
            object[0].field = WINDIVERT_FILTER_FIELD_ZERO;
            object[0].test = (label == WINDIVERT_FILTER_RESULT_ACCEPT?
                WINDIVERT_FILTER_TEST_EQ: WINDIVERT_FILTER_TEST_NEQ);
            object[0].arg[0] = object[0].arg[1] = object[0].arg[2] =
                object[0].arg[3] = 0;
            object[0].success = WINDIVERT_FILTER_RESULT_ACCEPT;
            object[0].failure = WINDIVERT_FILTER_RESULT_REJECT;
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
 * Compile a filter string into an executable filter object.
 */
static ERROR WinDivertCompileFilter(const char *filter,
    WINDIVERT_LAYER layer, windivert_ioctl_filter_t object, UINT *obj_len)
{
    TOKEN tokens[WINDIVERT_FILTER_MAXLEN*3];
    PEXPR stack[WINDIVERT_FILTER_MAXLEN];
    PPOOL pool;
    PEXPR expr;
    UINT i, max_depth;
    INT16 label;
    ERROR error;

    // Tokenize the filter string:
    error = WinDivertTokenizeFilter(filter, layer, tokens,
        sizeof(tokens) / sizeof(tokens[0]) - 1);
    if (IS_ERROR(error))
    {
        return error;
    }

    // Allocate memory pool for the compiler:
    pool = (PPOOL)malloc(sizeof(POOL));
    if (pool == NULL)
    {
        return MAKE_ERROR(WINDIVERT_ERROR_NO_MEMORY, 0);
    }
    pool->offset = 0;
    pool->error  = MAKE_ERROR(WINDIVERT_ERROR_NONE, 0);

    // Parse the filter into an expression:
    i = 0;
    max_depth = 1024;
    expr = WinDivertParseFilter(pool, tokens, &i, max_depth, FALSE);
    if (expr == NULL)
    {
        error = pool->error;
        free(pool);
        return error;
    }
    if (tokens[i].kind != TOKEN_END)
    {
        free(pool);
        return MAKE_ERROR(WINDIVERT_ERROR_UNEXPECTED_TOKEN, tokens[i].pos);
    }

    // Construct the filter tree:
    label = 0;
    label = WinDivertFlattenExpr(expr, &label, WINDIVERT_FILTER_RESULT_ACCEPT,
        WINDIVERT_FILTER_RESULT_REJECT, stack);
    if (label < 0)
    {
        free(pool);
        return MAKE_ERROR(WINDIVERT_ERROR_TOO_LONG, 0);
    }

    // Emit the final object.
    if (object != NULL)
    {
        WinDivertEmitFilter(stack, label, label, object, obj_len);
    }
    free(pool);

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
        case WINDIVERT_ERROR_ASSERTION_FAILED:
            return "Internal assertion failed";
        default:
            return "Unknown error";
    }
}

/*
 * Check the given filter string.
 */
extern BOOL WinDivertHelperCheckFilter(const char *filter_str, 
    WINDIVERT_LAYER layer, const char **error, UINT *error_pos)
{
    ERROR err;
    if (filter_str == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    err = WinDivertCompileFilter(filter_str, layer, NULL, NULL);
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
extern BOOL WinDivertHelperEvalFilter(const char *filter,
    WINDIVERT_LAYER layer, PVOID packet, UINT packet_len,
    PWINDIVERT_ADDRESS addr)
{
    UINT16 pc;
    ERROR err;
    PWINDIVERT_IPHDR iphdr;
    PWINDIVERT_IPV6HDR ipv6hdr;
    PWINDIVERT_ICMPHDR icmphdr;
    PWINDIVERT_ICMPV6HDR icmpv6hdr;
    PWINDIVERT_TCPHDR tcphdr;
    PWINDIVERT_UDPHDR udphdr;
    UINT payload_len;
    UINT32 val[4];
    BOOL pass;
    int cmp;
    struct windivert_ioctl_filter_s object[WINDIVERT_FILTER_MAXLEN];
    UINT obj_len;

    if (filter == NULL || packet == NULL || addr == NULL)
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

    WinDivertHelperParsePacket(packet, packet_len, &iphdr, &ipv6hdr, &icmphdr,
        &icmpv6hdr, &tcphdr, &udphdr, NULL, &payload_len);
    
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
                val[0] = (addr->Direction == WINDIVERT_DIRECTION_INBOUND);
                break;
            case WINDIVERT_FILTER_FIELD_OUTBOUND:
                val[0] = (addr->Direction == WINDIVERT_DIRECTION_OUTBOUND);
                break;
            case WINDIVERT_FILTER_FIELD_IFIDX:
                val[0] = addr->IfIdx;
                break;
            case WINDIVERT_FILTER_FIELD_SUBIFIDX:
                val[0] = addr->SubIfIdx;
                break;
            case WINDIVERT_FILTER_FIELD_LOOPBACK:
                val[0] = addr->Loopback;
                break;
            case WINDIVERT_FILTER_FIELD_IMPOSTOR:
                val[0] = addr->Impostor;
                break;
            case WINDIVERT_FILTER_FIELD_IP:
                val[0] = (iphdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_IPV6:
                val[0] = (ipv6hdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_ICMP:
                val[0] = (icmphdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6:
                val[0] = (icmpv6hdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_TCP:
                val[0] = (tcphdr != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_UDP:
                val[0] = (udphdr != NULL);
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
                val[0] = ntohl(iphdr->SrcAddr);
                break;
            case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
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

