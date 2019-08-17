/*
 * windivert_hash.c
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
 *
 * xxHash - Fast Hash algorithm
 * Copyright (C) 2012-2016, Yann Collet
 *
 * BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */

/*
 * This is a modified version of the 64bit xxHash algorithm:
 * - The algorithm is seeded with packet data rather than the single 64bit
 *   "seed" value.
 * - The input sized is fixed to 32bytes (excluding the seed), so there is
 *   only ever a single round.  As such, the algorithm has been specialized.
 */

#define WINDIVERT_ROTL64(x, r)  (((x) << (r)) | ((x) >> (64 - (r))))

static const UINT64 WINDIVERT_PRIME64_1 = 11400714785074694791ull;
static const UINT64 WINDIVERT_PRIME64_2 = 14029467366897019727ull;
static const UINT64 WINDIVERT_PRIME64_3 = 1609587929392839161ull;
static const UINT64 WINDIVERT_PRIME64_4 = 9650029242287828579ull;

static UINT64 WinDivertXXH64Round(UINT64 acc, UINT64 input)
{
    acc += WINDIVERT_MUL64(input, WINDIVERT_PRIME64_2);
    acc  = WINDIVERT_ROTL64(acc, 31);
    acc  = WINDIVERT_MUL64(acc, WINDIVERT_PRIME64_1);
    return acc;
}

static UINT64 WinDivertXXH64MergeRound(UINT64 acc, UINT64 val)
{
    val  = WinDivertXXH64Round(0, val);
    acc ^= val;
    acc  = WINDIVERT_MUL64(acc, WINDIVERT_PRIME64_1) + WINDIVERT_PRIME64_4;
    return acc;
}

static UINT64 WinDivertXXH64Avalanche(UINT64 h64)
{
    h64 ^= h64 >> 33;
    h64  = WINDIVERT_MUL64(h64, WINDIVERT_PRIME64_2);
    h64 ^= h64 >> 29;
    h64  = WINDIVERT_MUL64(h64, WINDIVERT_PRIME64_3);
    h64 ^= h64 >> 32;
    return h64;
}

/*
 * WinDivert packet hash function.
 */
static UINT64 WinDivertHashPacket(UINT64 seed,
    const WINDIVERT_IPHDR *ip_header, const WINDIVERT_IPV6HDR *ipv6_header,
    const WINDIVERT_ICMPHDR *icmp_header,
    const WINDIVERT_ICMPV6HDR *icmpv6_header,
    const WINDIVERT_TCPHDR *tcp_header, const WINDIVERT_UDPHDR *udp_header)
{
    UINT64 h64, v1, v2, v3, v4, v[4];
    const UINT64 *data64;
    const UINT32 *data32;
    UINT i;
    static const UINT64 padding64[] =               // SHA2 IV
    {
        0x428A2F9871374491ull, 0xB5C0FBCFE9B5DBA5ull, 0x3956C25B59F111F1ull,
        0x923F82A4AB1C5ED5ull, 0xD807AA9812835B01ull, 0x243185BE550C7DC3ull,
        0x72BE5D7480DEB1FEull, 0x9BDC06A7C19BF174ull, 0xE49B69C1EFBE4786ull,
    };

    // Set-up seed & data
    v1 = seed ^ padding64[0];
    if (ip_header != NULL)
    {
        data64 = (const UINT64 *)ip_header;
        v2 = data64[0] ^ padding64[1];
        v3 = data64[1] ^ padding64[2];
        data32 = (const UINT32 *)ip_header;
        v4 = (UINT64)data32[4] ^ padding64[3];
        i = 0;
    }
    else if (ipv6_header != NULL)
    {
        data64 = (const UINT64 *)ipv6_header;
        v2 = data64[0] ^ padding64[1];
        v3 = data64[1] ^ padding64[2];
        v4 = data64[2] ^ padding64[3];
        v[0] = data64[3] ^ padding64[4];
        v[1] = data64[4] ^ padding64[5];
        i = 2;
    }
    else
        return 0;

    if (tcp_header != NULL)
    {
        data64 = (const UINT64 *)tcp_header;
        v[i] = data64[0] ^ padding64[i+4]; i++;
        v[i] = data64[1] ^ padding64[i+4]; i++;
        data32 = (const UINT32 *)tcp_header;
        if (i <= 3)
        {
            v[i] = (UINT64)data32[4] ^ padding64[i+4]; i++;
        }
        else
        {
            v2 ^= ((UINT64)data32[4] << 32);
        }
    }
    else
    {
        if (udp_header != NULL)
        {
            data64 = (const UINT64 *)udp_header;
            v[i] = data64[0] ^ padding64[i+4]; i++;
        }
        else if (icmp_header != NULL)
        {
            data64 = (const UINT64 *)icmp_header;
            v[i] = data64[0] ^ padding64[i+4]; i++;
        }
        else if (icmpv6_header != NULL)
        {
            data64 = (const UINT64 *)icmpv6_header;
            v[i] = data64[0] ^ padding64[i+4]; i++;
        }
    }

    while (i <= 3)
    {
        v[i] = seed ^ padding64[i+4]; i++;
    }

    // Hash
    v1 = WinDivertXXH64Round(v[0], v1);
    v2 = WinDivertXXH64Round(v[1], v2);
    v3 = WinDivertXXH64Round(v[2], v3);
    v4 = WinDivertXXH64Round(v[3], v4);
    h64 = WINDIVERT_ROTL64(v1, 1) + WINDIVERT_ROTL64(v2, 7) +
          WINDIVERT_ROTL64(v3, 12) + WINDIVERT_ROTL64(v4, 18);
    h64 = WinDivertXXH64MergeRound(h64, v1);
    h64 = WinDivertXXH64MergeRound(h64, v2);
    h64 = WinDivertXXH64MergeRound(h64, v3);
    h64 = WinDivertXXH64MergeRound(h64, v4); 
    h64 += 32;          // "length"
    h64 = WinDivertXXH64Avalanche(h64);

    return h64;
}

