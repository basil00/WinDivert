/*
 * test.c
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

/*
 * WinDivert testing framework.
 */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "windivert.h"

#define MAX_PACKET  2048
#define MIN(a, b)   ((a) < (b)? (a): (b))

/*
 * Packet data.
 */
#include "test_data.c"

/*
 * Test entry.
 */
struct packet
{
    const char *packet;
    size_t packet_len;
    char *name;
};

struct test
{
    const char *filter;
    const struct packet *packet;
    BOOL match;
};

/*
 * Prototypes.
 */
static BOOL run_test(HANDLE inject_handle, const char *filter,
    const char *packet, const size_t packet_len, BOOL match, INT64 *diff);
static DWORD monitor_worker(LPVOID arg);

/*
 * Test data.
 */
static const struct packet pkt_echo_request =
{
    echo_request,
    sizeof(echo_request),
    "ipv4_icmp_echo_req"
};
static const struct packet pkt_http_request =
{
    http_request,
    sizeof(http_request),
    "ipv4_tcp_http_req"
};
static const struct packet pkt_dns_request =
{
    dns_request,
    sizeof(dns_request),
    "ipv4_udp_dns_req"
};
static const struct packet pkt_ipv6_tcp_syn =
{
    ipv6_tcp_syn,
    sizeof(ipv6_tcp_syn),
    "ipv6_tcp_syn"
};
static const struct packet pkt_ipv6_echo_reply =
{
    ipv6_echo_reply,
    sizeof(ipv6_echo_reply),
    "ipv6_icmpv6_echo_rep"
};
static const struct packet pkt_ipv6_exthdrs_udp =
{
    ipv6_exthdrs_udp,
    sizeof(ipv6_exthdrs_udp),
    "ipv6_exthdrs_udp"
};
static const struct packet pkt_ipv4_fragment_0 =
{
    ipv4_fragment_0,
    sizeof(ipv4_fragment_0),
    "ipv4_fragemnt_0"
};
static const struct packet pkt_ipv4_fragment_1 =
{
    ipv4_fragment_1,
    sizeof(ipv4_fragment_1),
    "ipv4_fragment_1"
};
static const struct packet pkt_ipv6_fragment_0 =
{
    ipv6_fragment_0,
    sizeof(ipv6_fragment_0),
    "ipv6_fragment_0"
};
static const struct packet pkt_ipv6_fragment_1 =
{
    ipv6_fragment_1,
    sizeof(ipv6_fragment_1),
    "ipv6_fragment_1"
};
static const struct test tests[] =
{
    {"event = PACKET",                         &pkt_echo_request, TRUE},
    {"packet[0] == 0x45",                      &pkt_echo_request, TRUE},
    {"packet[0] == 0x33",                      &pkt_echo_request, FALSE},
    {"packet[55] == 0x1b",                     &pkt_echo_request, TRUE},
    {"packet[55b] == 0x1b",                    &pkt_echo_request, TRUE},
    {"packet[1000] <= 0 || packet[-1000] = 7", &pkt_echo_request, FALSE},
    {"packet[-1] == 0x37 && packet[-2] == 0x36 && packet[-3] == 0x35 && "
     "packet[-4] == 0x34",                     &pkt_echo_request, TRUE},
    {"packet16[0] == 0x4500",                  &pkt_echo_request, TRUE},
    {"packet16[0] == 0x0045",                  &pkt_echo_request, FALSE},
    {"packet16[2b] == 0x0054",                 &pkt_echo_request, TRUE},
    {"packet16[1] == 0x0054",                  &pkt_echo_request, TRUE},
    {"packet16[0] == 0x4500 && packet16[1] == 0x0054 && "
     "packet16[-1] == 0x3637",                 &pkt_echo_request, TRUE},
    {"packet32[0b] == 0x45000054 && packet32[3b] == 0x54123440 && "
     "packet32[-4b] == 0x34353637 && packet32[-5b] == 0x33343536",
                                               &pkt_echo_request, TRUE},
    {"random8 < 10",                           &pkt_echo_request, TRUE},
    {"random16 >= 2222",                       &pkt_echo_request, TRUE},
    {"random32 <= 0x80000000",                 &pkt_echo_request, TRUE},
    {"(random8 < 128? icmp: udp)",             &pkt_echo_request, TRUE},
    {"(random8 <= 128? "
        "(random16 <= 0x8000?"
            "(random32 <= 0x80000000? ip: ipv6): "
            "(random32 <= 0x80000000? icmpv6: icmp)): "
        "(random16 <= 0x8000?"
            "(random32 <= 0x80000000? tcp: icmp.Type >= 8): "
            "(random32 <= 0x80000000? outbound: loopback)))",
                                               &pkt_echo_request, TRUE},
    {"outbound and icmp",                      &pkt_echo_request, TRUE},
    {"outbound",                               &pkt_echo_request, TRUE},
    {"outbound and inbound",                   &pkt_echo_request, FALSE},
    {"loopback",                               &pkt_echo_request, FALSE},
    {"impostor",                               &pkt_echo_request, FALSE},
    {"icmp",                                   &pkt_echo_request, TRUE},
    {"not icmp",                               &pkt_echo_request, FALSE},
    {"ip or ipv6",                             &pkt_echo_request, TRUE},
    {"inbound",                                &pkt_echo_request, FALSE},
    {"tcp",                                    &pkt_echo_request, FALSE},
    {"tcp == TRUE",                            &pkt_echo_request, FALSE},
    {"tcp == FALSE",                           &pkt_echo_request, TRUE},
    {"icmp.Type == 8",                         &pkt_echo_request, TRUE},
    {"icmp.Type == 9",                         &pkt_echo_request, FALSE},
    {"(tcp? ip.Checksum == 0: icmp)",          &pkt_echo_request, TRUE},
    {"(udp? icmp: icmp.Body == 5555)",         &pkt_echo_request, FALSE},
    {"(false? false: false)",                  &pkt_echo_request, FALSE},
    {"(true? true: true)",                     &pkt_echo_request, TRUE},
    {"(tcp or udp or icmpv6 or ipv6? true: false)",
                                               &pkt_echo_request, FALSE},
    {"(ip and ipv6 and tcp and udp? false: icmp > 0)",
                                               &pkt_echo_request, TRUE},
    {"(tcp? tcp.DstPort == 80: true) and (udp? udp.DstPort == 80: true)",
                                               &pkt_echo_request, TRUE},
    {"fragment",                               &pkt_echo_request, FALSE},
    {"ip and ip and ip and ip and ip and "     // Max filter length:
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip and ip and ip and "
     "ip and ip and ip",                       &pkt_echo_request, TRUE},
    {"not true or false or not icmp or "       // All fields:
     "icmp.Body == 33 or icmp.Checksum==2 or "
     "icmp.Code == 0x777 or "
     "icmp.Type == 0x333 or icmpv6 or "
     "icmpv6.Body or icmpv6.Checksum or "
     "icmpv6.Code or icmpv6.Type or "
     "ifIdx == 93923 or inbound or "
     "not ip or ip.Checksum == 8 or "
     "not ip.DF or ip.DstAddr == 1.2.3.4 or "
     "ip.FragOff == 4212 or "
     "ip.HdrLength == 2 or ip.Id = 0x0987 or "
     "ip.Length == 788 or ip.MF == 1 or "
     "ip.Protocol == 999 or "
     "ip.SrcAddr == 9.8.7.255 or "
     "ip.TOS == 3 or ip.TTL = 221 or ipv6 or "
     "ipv6.DstAddr or ipv6.FlowLabel or "
     "ipv6.HopLimit or ipv6.Length or "
     "ipv6.NextHdr or ipv6.SrcAddr or "
     "ipv6.TrafficClass or not outbound or "
     "subIfIdx == 888 or tcp or tcp.Ack or "
     "tcp.AckNum or tcp.Checksum or "
     "tcp.DstPort or tcp.Fin or "
     "tcp.HdrLength or tcp.PayloadLength or "
     "tcp.Psh or tcp.Rst or tcp.SeqNum or "
     "tcp.SrcPort or tcp.Syn or tcp.Urg or "
     "tcp.UrgPtr or tcp.Window or udp or "
     "udp.Checksum or udp.DstPort or "
     "udp.Length or udp.PayloadLength or "
     "udp.SrcPort",                            &pkt_echo_request, FALSE},
    {"(true and (true and (true and (true and "// Deep nesting:
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(true and (true and (true and (true and "
     "(((((((((((((((icmp)))))))))))))))))))"
     "))))))))))))))))))))))))))))))))))))))"
     "))))))))))))))))))))))))))))))))))))))", &pkt_echo_request, TRUE},
    {"not not not not not not not not icmp",   &pkt_echo_request, TRUE},
    {"not not not not not not not icmp",       &pkt_echo_request, FALSE},
    {"!!!!!!!icmp",                            &pkt_echo_request, FALSE},
    {"false and true or true",                 &pkt_echo_request, TRUE},
    {"true and false or false",                &pkt_echo_request, FALSE},
    {"true or true and false",                 &pkt_echo_request, TRUE},
    {"false or false and true",                &pkt_echo_request, FALSE},
    {"tcp && icmp || ip",                      &pkt_echo_request, TRUE},
    {"icmp && udp || tcp",                     &pkt_echo_request, FALSE},
    {"ip || icmp && icmpv6",                   &pkt_echo_request, TRUE},
    {"!ip || !icmp && !udp",                   &pkt_echo_request, FALSE},
    {"(((icmp)? (true): (false)) and "
     "(((tcp)? (false): (true)) and "
     "((ipv6)? (false): (true))))",            &pkt_echo_request, TRUE},
    {"((((packet[31] > 0x54 or (packet[46] == 0x12 and "
     "not packet[78] >= 0x32)) and (not packet[79] <= 0x33 and "
     "not packet[81] > 0x35)) and (((not packet[62] <= 0x22 and "
     "not packet[54] <= 0x1A) and (not packet[69] <= 0x29 or "
     "packet[55] > 0x1B)) or ((not packet[78] != 0x32 and "
     "packet[22] != 0x3C)? (not packet[11] <= 0x00? packet[7] >= 0x00: "
     "packet[67] >= 0x27): (packet[1] < 0x00? not packet[49] == 0x15: "
     "not packet[44] != 0x10))))? ((((not packet[11] > 0x00 and "
     "not packet[62] <= 0x22) or (packet[7] < 0x00? packet[23] < 0xD2: "
     "not packet[10] != 0x00)) and not packet[74] != 0x2E) or "
     "packet[43] >= 0x00): ((((packet[3] == 0x54? packet[19] == 0x08: "
     "packet[8] > 0x40) or not packet[80] > 0x34)? ((packet[9] >= 0x01? "
     "packet[5] != 0x34: packet[61] > 0x21) or (packet[44] > 0x10 and "
     "packet[63] < 0x23)): ((packet[80] <= 0x34 or not packet[78] < 0x32)? "
     "(packet[19] != 0x08? packet[40] == 0x00: not packet[71] == 0x2B): "
     "(not packet[39] < 0x00 or packet[38] != 0x0A))) or "
     "(((not packet[81] > 0x35 and packet[22] <= 0x3C)? "
     "(not packet[60] != 0x20? packet[28] < 0x8B: not packet[74] != 0x2E): "
     "packet[8] <= 0x40) or ((packet[60] == 0x20? packet[57] <= 0x1D: "
     "packet[24] >= 0x0D)? (packet[34] > 0x00 or not packet[53] < 0x19): "
     "(packet[11] < 0x00 and packet[35] != 0x00)))))",
                                               &pkt_echo_request, TRUE},
    {"(((((packet[23] <= 0xD2 and not packet[1] >= 0x00)? "
     "(packet[3] != 0x54 or packet[45] >= 0x11): (packet[4] > 0x12 and "
     "packet[2] != 0x00)) or packet[24] > 0x0D) or (((not packet[57] > 0x1D? "
     "packet[62] == 0x22: not packet[12] < 0x0A) or (packet[28] > 0x8B? "
     "not packet[48] > 0x14: not packet[64] > 0x24)) or ((packet[80] >= 0x34? "
     "not packet[3] != 0x54: not packet[26] <= 0x00) and "
     "(packet[68] != 0x28 and packet[32] == 0x00))))? not packet[1] == 0x00: "
     "((((not packet[36] > 0xF9 and not packet[70] == 0x2A) or "
     "(not packet[3] <= 0x54? packet[1] > 0x00: not packet[14] != 0x00)) and "
     "packet[57] <= 0x1D)? packet[38] == 0x0A: (((not packet[59] != 0x1F? "
     "packet[46] < 0x12: not packet[81] < 0x35) and (packet[27] >= 0x01? "
     "not packet[50] > 0x16: not packet[7] <= 0x00))? ((packet[76] >= 0x30 or "
     "not packet[54] >= 0x1A) and packet[64] < 0x24): "
     "((packet[58] <= 0x1E and packet[81] < 0x35)? (packet[20] < 0x08 or "
     "packet[22] <= 0x3C): (not packet[70] >= 0x2A? packet[31] < 0x54: "
     "not packet[69] <= 0x29)))))",            &pkt_echo_request, FALSE},
    {"ip.HdrLength == 5 and ip.TOS == 0 and ip.Length == 84 and "
     "ip.Id == 0x1234 and ip.FragOff == 0 and ip.MF == 0 and ip.DF == 1 and "
     "ip.TTL == 64 and ip.Protocol == 1 and ip.SrcAddr == 0xFFFF0A000001 and "
     "ip.DstAddr == 0xFFFF08080808 and icmp.Type == 8 and icmp.Code == 0 and "
     "icmp.Body == 0x0D560001",                &pkt_echo_request, TRUE},
    {"ip.HdrLength > 5 or ip.TOS > 0 or ip.Length != 84 or ip.Id < 0x1234 or "
     "ip.FragOff != 0 or ip.MF < 0 or ip.DF != 1 or ip.TTL > 64 or "
     "ip.Protocol != 1 or ip.SrcAddr < 0xFFFF0A000001 or "
     "ip.DstAddr < 0xFFFF08080808 or icmp.Type != 8 or icmp.Code != 0 or "
     "icmp.Body != 0x0D560001",                &pkt_echo_request, FALSE},
    {"localAddr == 10.0.0.1 && remoteAddr == 8.8.8.8 && localPort == 8 && "
     "remotePort == 0 && protocol == 1",       &pkt_echo_request, TRUE},
    {"packet[0] == 0x45",                      &pkt_echo_request, TRUE},
    {"ip.MF or ip.FragOff != 0",               &pkt_echo_request, FALSE},
    {"icmp.Body != 123 || icmp.Body == 123",   &pkt_echo_request, TRUE},
    {"length == 84 && ip.Length == 84",        &pkt_echo_request, TRUE},
    {"tcp",                                    &pkt_http_request, TRUE},
    {"protocol == TCP",                        &pkt_http_request, TRUE},
    {"outbound and tcp and tcp.DstPort == 80", &pkt_http_request, TRUE},
    {"outbound and tcp and tcp.DstPort == 81", &pkt_http_request, FALSE},
    {"outbound and tcp and tcp.DstPort != 80", &pkt_http_request, FALSE},
    {"inbound and tcp and tcp.DstPort == 80",  &pkt_http_request, FALSE},
    {"tcp.PayloadLength == 469",               &pkt_http_request, TRUE},
    {"tcp.PayloadLength != 469",               &pkt_http_request, FALSE},
    {"tcp.PayloadLength >= 469",               &pkt_http_request, TRUE},
    {"tcp.PayloadLength <= 469",               &pkt_http_request, TRUE},
    {"tcp.PayloadLength > 469",                &pkt_http_request, FALSE},
    {"tcp.PayloadLength < 469",                &pkt_http_request, FALSE},
    {"(outbound? (ip? (tcp.DstPort == 80? (tcp.PayloadLength > 0? true: "
        "false): false): false): false)",      &pkt_http_request, TRUE},
    {"(outbound? (ip? (tcp.DstPort == 80? (tcp.PayloadLength == 0? true: "
        "false): false): false): false)",      &pkt_http_request, FALSE},
    {"(ipv6? tcp and tcp.DstPort = 1234 and (tcp.SrcPort = 999? !tcp.UrgPtr: "
     "tcp.Syn) or udp: ip and tcp.DstPort == 80)",
                                               &pkt_http_request, TRUE},
    {"packet32[0] = 0x45000209 && packet32[1] = 0x482d4000 && "
     "packet16[8b] = 0x4006 && packet32[3] = 0x0a0a0a0a && "
     "packet32[4] = 0x5db8d877 && packet32[5] = 0xa31a0050 && "
     "packet32[6] = 0x5338ccc2 && packet32[7] = 0x5637b355 && "
     "packet32[8] = 0x80180073 && packet16[38b] = 0x0000 && "
     "packet32[10] = 0x0101080a && packet32[11] = 0x002c851b && "
     "packet32[12] = 0x1b7f3a71 && packet32[13] = 0x47455420 && "
     "packet32[14] = 0x2f204854 && packet32[15] = 0x54502f31 && "
     "packet32[16] = 0x2e310d0a && packet32[17] = 0x486f7374 && "
     "packet32[18] = 0x3a207777 && packet32[19] = 0x772e6578 && "
     "packet32[20] = 0x616d706c && packet32[21] = 0x652e636f && "
     "packet32[22] = 0x6d0d0a43 && packet32[23] = 0x6f6e6e65 && "
     "packet32[24] = 0x6374696f && packet32[25] = 0x6e3a206b && "
     "packet32[26] = 0x6565702d && packet32[27] = 0x616c6976 && "
     "packet32[28] = 0x650d0a43 && packet32[29] = 0x61636865 && "
     "packet32[30] = 0x2d436f6e && packet32[31] = 0x74726f6c && "
     "packet32[32] = 0x3a206d61 && packet32[33] = 0x782d6167 && "
     "packet32[34] = 0x653d300d && packet32[35] = 0x0a416363 && "
     "packet32[36] = 0x6570743a && packet32[37] = 0x20746578 && "
     "packet32[38] = 0x742f6874 && packet32[39] = 0x6d6c2c61 && "
     "packet32[40] = 0x70706c69 && packet32[41] = 0x63617469 && "
     "packet32[42] = 0x6f6e2f78 && packet32[43] = 0x68746d6c && "
     "packet32[44] = 0x2b786d6c && packet32[45] = 0x2c617070 && "
     "packet32[46] = 0x6c696361 && packet32[47] = 0x74696f6e && "
     "packet32[48] = 0x2f786d6c && packet32[49] = 0x3b713d30 && "
     "packet32[50] = 0x2e392c69 && packet32[51] = 0x6d616765 && "
     "packet32[52] = 0x2f776562 && packet32[53] = 0x702c2a2f && "
     "packet32[54] = 0x2a3b713d && packet32[55] = 0x302e380d && "
     "packet32[56] = 0x0a557365 && packet32[57] = 0x722d4167 && "
     "packet32[58] = 0x656e743a && packet32[59] = 0x20585858 && "
     "packet32[60] = 0x58585858 && packet32[61] = 0x58585858 && "
     "packet32[62] = 0x58585858 && packet32[63] = 0x58585858 && "
     "packet32[64] = 0x58585858 && packet32[65] = 0x58585858 && "
     "packet32[66] = 0x58585858 && packet32[67] = 0x58585858 && "
     "packet32[68] = 0x58585858 && packet32[69] = 0x58585858 && "
     "packet32[70] = 0x58585858 && packet32[71] = 0x58585858 && "
     "packet32[72] = 0x58585858 && packet32[73] = 0x58585858 && "
     "packet32[74] = 0x58585858 && packet32[75] = 0x58585858 && "
     "packet32[76] = 0x58585858 && packet32[77] = 0x58585858 && "
     "packet32[78] = 0x58585858 && packet32[79] = 0x58585858 && "
     "packet32[80] = 0x58585858 && packet32[81] = 0x58585858 && "
     "packet32[82] = 0x58585858 && packet32[83] = 0x58585858 && "
     "packet32[84] = 0x58585858 && packet32[85] = 0x58585858 && "
     "packet32[86] = 0x58585858 && packet32[87] = 0x58585858 && "
     "packet32[88] = 0x58585858 && packet32[89] = 0x58585858 && "
     "packet32[90] = 0x58585858 && packet32[91] = 0x58585858 && "
     "packet32[92] = 0x58580d0a && packet32[93] = 0x41636365 && "
     "packet32[94] = 0x70742d45 && packet32[95] = 0x6e636f64 && "
     "packet32[96] = 0x696e673a && packet32[97] = 0x20677a69 && "
     "packet32[98] = 0x702c6465 && packet32[99] = 0x666c6174 && "
     "packet32[100] = 0x652c7364 && packet32[101] = 0x63680d0a && "
     "packet32[102] = 0x41636365 && packet32[103] = 0x70742d4c && "
     "packet32[104] = 0x616e6775 && packet32[105] = 0x6167653a && "
     "packet32[106] = 0x20656e2d && packet32[107] = 0x55532c65 && "
     "packet32[108] = 0x6e3b713d && packet32[109] = 0x302e380d && "
     "packet32[110] = 0x0a49662d && packet32[111] = 0x4e6f6e65 && "
     "packet32[112] = 0x2d4d6174 && packet32[113] = 0x63683a20 && "
     "packet32[114] = 0x22333333 && packet32[115] = 0x33333333 && "
     "packet32[116] = 0x3333220d && packet32[117] = 0x0a49662d && "
     "packet32[118] = 0x4d6f6469 && packet32[119] = 0x66696564 && "
     "packet32[120] = 0x2d53696e && packet32[121] = 0x63653a20 && "
     "packet32[122] = 0x4672692c && packet32[123] = 0x20303320 && "
     "packet32[124] = 0x41756720 && packet32[125] = 0x32303134 && "
     "packet32[126] = 0x2031333a && packet32[127] = 0x33333a33 && "
     "packet32[128] = 0x3320474d && packet32[129] = 0x540d0a0d && "
     "packet[-1] = 0x0a",                      &pkt_http_request, TRUE},
    {"tcp.Payload16[-1] == 0x0d0a",            &pkt_http_request, TRUE},
    {"tcp.Payload32[-2] == 0x20474d54",        &pkt_http_request, TRUE},
    {"(ipv6? true: false) or (udp? udp.DstPort != 53: false) or "
     "(not tcp and not udp? true: false)",     &pkt_http_request, FALSE},
    {"ip and !loopback and (outbound? tcp.DstPort == 80 or"
     " tcp.DstPort == 443 or udp.DstPort == 53 :"
     " icmp.Type == 11 and icmp.Code == 0)",   &pkt_http_request, TRUE},
    {"random8 < 128",                          &pkt_http_request, TRUE},
    {"(random8 < 128? random16 < 0x8000: random32 < 0x80000000)",
                                               &pkt_http_request, TRUE},
    {"(random32 < 0x22223333? packet32[72] == 0x58585858: udp)",
                                               &pkt_http_request, TRUE},
    {"(((((not packet[340] != 0x58? not packet[173] < 0x74: "
     "not packet[376] > 0x70) or not packet[87] != 0x6F) or "
     "not packet[226] > 0x73) and (((not packet[289] <= 0x58 and "
     "not packet[76] > 0x77) and (packet[231] < 0x67 and "
     "not packet[24] < 0x53))? ((packet[365] > 0x58? not packet[91] <= 0x43: "
     "not packet[310] <= 0x58) or (not packet[515] < 0x4D or "
     "packet[518] >= 0x0A)): ((not packet[209] < 0x77? "
     "not packet[237] > 0x58: not packet[286] == 0x58)? "
     "(packet[354] == 0x58 or packet[502] > 0x31): not packet[2] > 0x02)))? "
     "(((packet[520] <= 0x0A? (packet[484] == 0x63 and packet[83] >= 0x6C): "
     "(packet[384] >= 0x69 or packet[245] >= 0x58)) and "
     "(packet[106] > 0x70 or packet[45] != 0x2C))? (((packet[153] == 0x2F or "
     "packet[139] >= 0x0D) and (packet[136] != 0x65? packet[100] == 0x6E: "
     "not packet[128] == 0x3A))? ((not packet[288] != 0x58 or "
     "not packet[309] == 0x58) and packet[350] <= 0x58): "
     "not packet[129] >= 0x20): (not packet[493] != 0x30 and "
     "((packet[465] != 0x33 or not packet[386] >= 0x67)? "
     "(packet[470] >= 0x66 or not packet[259] >= 0x58): "
     "packet[408] != 0x41))): ((((not packet[500] > 0x32 or "
     "not packet[163] < 0x69) and not packet[122] == 0x6F) and "
     "((packet[324] <= 0x58 and packet[481] > 0x53)? "
     "(not packet[17] > 0xB8 and packet[102] != 0x20): (packet[303] > 0x58 or "
     "packet[345] >= 0x58)))? (packet[191] < 0x6E and ((packet[429] <= 0x53? "
     "not packet[239] >= 0x58: packet[258] < 0x58)? packet[382] >= 0x6F: "
     "(packet[443] == 0x2D? not packet[67] < 0x0A: packet[168] <= 0x6F))): "
     "(((packet[34] == 0x00 and not packet[77] != 0x2E)? "
     "(packet[27] != 0xC2? not packet[477] <= 0x69: not packet[472] != 0x4D): "
     "(not packet[157] >= 0x6C or not packet[308] <= 0x58)) or "
     "((not packet[293] == 0x58? not packet[83] != 0x6C: packet[70] > 0x73)? "
     "(not packet[260] < 0x58? packet[98] != 0x69: not packet[226] <= 0x73): "
     "(packet[139] < 0x0D and not packet[171] == 0x78)))))",
                                                &pkt_http_request, FALSE},
    {"(((((packet[307] > 0x58 or packet[437] == 0x2E)? (packet[331] <= 0x58? "
     "packet[39] != 0x00: not packet[503] > 0x34): not packet[248] >= 0x58)? "
     "((not packet[266] >= 0x58? packet[510] != 0x3A: "
     "not packet[343] == 0x58)? (not packet[183] == 0x70 and "
     "not packet[333] <= 0x58): (packet[456] >= 0x22? packet[400] <= 0x65: "
     "not packet[218] <= 0x71)): (packet[482] <= 0x69? "
     "(packet[288] > 0x58 and packet[142] == 0x63): (packet[8] >= 0x40 or "
     "not packet[211] == 0x62))) or ((packet[267] <= 0x58 and "
     "(packet[35] != 0x73? packet[36] == 0x02: not packet[100] > 0x6E)) and "
     "(not packet[170] > 0x2F and (not packet[289] != 0x58 and "
     "not packet[344] < 0x58)))) or ((((not packet[468] > 0x0A and "
     "not packet[372] >= 0x41) and (packet[513] < 0x20 or "
     "packet[306] == 0x58)) or ((not packet[431] <= 0x65 and "
     "not packet[144] < 0x65)? (packet[478] != 0x65? packet[37] <= 0xA4: "
     "not packet[26] < 0xCC): (not packet[269] != 0x58 and "
     "packet[149] != 0x74)))? (((packet[422] <= 0x65 and "
     "not packet[176] > 0x2B) and (not packet[417] > 0x6E? "
     "not packet[451] <= 0x74: packet[348] >= 0x58)) and "
     "packet[284] != 0x58): (((packet[200] < 0x2E and packet[89] < 0x0D) or "
     "(packet[469] == 0x49 and not packet[384] == 0x69))? "
     "((not packet[105] >= 0x65 or packet[128] == 0x3A) or "
     "packet[389] <= 0x67): not packet[271] >= 0x58)))",
                                                &pkt_http_request, TRUE},
    {"(packet[248] != 0x58? ((packet[470] > 0x66 and ((packet[96] < 0x63? "
     "not packet[216] >= 0x2A: packet[261] == 0x58)? "
     "(not packet[166] > 0x74? packet[502] >= 0x31: not packet[387] > 0x3A): "
     "(not packet[387] > 0x3A? not packet[265] < 0x58: "
     "packet[237] < 0x58))) and ((not packet[264] < 0x58 or "
     "(not packet[113] >= 0x0D? not packet[423] == 0x3A: "
     "packet[329] == 0x58)) and (not packet[515] < 0x4D? "
     "(packet[172] >= 0x68? packet[286] != 0x58: not packet[121] != 0x43): "
     "(not packet[160] < 0x70? not packet[322] != 0x58: "
     "not packet[398] < 0x61)))): ((((packet[298] < 0x58 and "
     "packet[268] > 0x58) and (not packet[447] <= 0x65 or "
     "packet[149] >= 0x74)) or ((not packet[517] != 0x0D or "
     "packet[179] < 0x6C)? (not packet[343] > 0x58 or "
     "not packet[186] < 0x63): (not packet[255] > 0x58 or "
     "not packet[487] == 0x20))) and (((not packet[149] < 0x74? "
     "not packet[125] == 0x72: packet[496] < 0x41) and "
     "(not packet[344] == 0x58? not packet[261] != 0x58: "
     "not packet[317] >= 0x58))? (packet[100] == 0x6E? "
     "(not packet[233] == 0x6E? packet[120] >= 0x2D: not packet[186] > 0x63): "
     "(not packet[360] == 0x58 or packet[133] > 0x2D)): "
     "not packet[477] == 0x69)))",              &pkt_http_request, FALSE},
    {"ip.HdrLength == 5 and ip.TOS == 0 and ip.Length == 521 and "
     "ip.Id == 0x482D and ip.FragOff == 0 and ip.MF == 0 and ip.DF == 1 and "
     "ip.TTL == 64 and ip.Protocol == 6 and ip.SrcAddr == 0xFFFF0A0A0A0A and "
     "ip.DstAddr == 0xFFFF5DB8D877 and tcp.SrcPort == 41754 and "
     "tcp.DstPort == 80 and tcp.SeqNum == 1396231362 and "
     "tcp.AckNum == 1446490965 and tcp.HdrLength == 8 and tcp.Fin == 0 and "
     "tcp.Syn == 0 and tcp.Rst == 0 and tcp.Psh == 1 and tcp.Ack == 1 and "
     "tcp.Urg == 0 and tcp.Window == 115 and tcp.UrgPtr == 0",
                                               &pkt_http_request, TRUE},
    {"ip.HdrLength > 5 or ip.TOS < 0 or ip.Length < 521 or ip.Id != 0x482D or "
     "ip.FragOff != 0 or ip.MF != 0 or ip.DF < 1 or ip.TTL < 64 or "
     "ip.Protocol > 6 or ip.SrcAddr != 0xFFFF0A0A0A0A or "
     "ip.DstAddr < 0xFFFF5DB8D877 or tcp.SrcPort < 41754 or "
     "tcp.DstPort < 80 or tcp.SeqNum != 1396231362 or "
     "tcp.AckNum < 1446490965 or tcp.HdrLength < 8 or tcp.Fin != 0 or "
     "tcp.Syn != 0 or tcp.Rst != 0 or tcp.Psh != 1 or tcp.Ack > 1 or "
     "tcp.Urg != 0 or tcp.Window < 115 or tcp.UrgPtr < 0",
                                               &pkt_http_request, FALSE},
    {"localAddr == 10.10.10.10 && remoteAddr == 93.184.216.119 && "
     "localPort == 41754 && remotePort == 80 && protocol == 6",
                                               &pkt_http_request, TRUE},
    {"udp",                                    &pkt_dns_request, TRUE},
    {"udp && udp.SrcPort > 1 && ipv6",         &pkt_dns_request, FALSE},
    {"udp.DstPort == 53",                      &pkt_dns_request, TRUE},
    {"udp.DstPort > 100",                      &pkt_dns_request, FALSE},
    {"zero = 0",                               &pkt_dns_request, TRUE},
    {"zero = 1",                               &pkt_dns_request, FALSE},
    {"ip.DstAddr = 8.8.4.4",                   &pkt_dns_request, TRUE},
    {"ip.DstAddr = 8.8.8.8",                   &pkt_dns_request, FALSE},
    {"ip.DstAddr >= 8.8.0.0 &&"
     "ip.DstAddr <= 8.8.255.255",              &pkt_dns_request, TRUE},
    {"ip.SrcAddr >= 10.0.0.0 && ip.SrcAddr <= 10.255.255.255",
                                               &pkt_dns_request, TRUE},
    {"ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255",
                                               &pkt_dns_request, FALSE},
    {"ip.DstAddr == ::ffff:8.8.4.4",           &pkt_dns_request, TRUE},
    {"ip.DstAddr == ::0:ffff:8.8.4.4",         &pkt_dns_request, TRUE},
    {"remoteAddr == 8.8.4.4",                  &pkt_dns_request, TRUE},
    {"remoteAddr == ::ffff:8.8.4.4",           &pkt_dns_request, TRUE},
    {"protocol == 17",                         &pkt_dns_request, TRUE},
    {"remotePort == 53",                       &pkt_dns_request, TRUE},
    {"(ipv6? true: false) or (udp? udp.DstPort != 53: false) or "
     "(not tcp and not udp? true: false)",     &pkt_dns_request, FALSE},
    {"ipv6 or (not tcp and udp.DstPort != 53)",&pkt_dns_request, FALSE},
    {"udp.PayloadLength == 29",                &pkt_dns_request, TRUE},
    {"udp.Payload16[-1] == 0x0001 && udp.Payload16[-2] == 0x0001",
                                               &pkt_dns_request, TRUE},
    {"packet16[-1] == 0x0001 && packet16[-2] == 0x0001",
                                               &pkt_dns_request, TRUE},
    {"tcp.Payload32[0] > 0",                   &pkt_dns_request, FALSE},
    {"udp.Payload32[1] > 0",                   &pkt_dns_request, TRUE},
    {"length == 57",                           &pkt_dns_request, TRUE},
    {"(length > 57? udp: tcp)",                &pkt_dns_request, FALSE},
    {"protocol == UDP",                        &pkt_dns_request, TRUE},
    {"random8 < 128",                          &pkt_dns_request, TRUE},
    {"(random8 < 128? random16 < 0x8000: random32 < 0x80000000)",
                                               &pkt_dns_request, TRUE},
    {"((((not packet[22] < 0x00 or (packet[14] > 0x00 and "
     "packet[8] <= 0x49))? (not packet[3] > 0x39 and packet[22] <= 0x00): "
     "not packet[1] <= 0x00) and (((packet[27] != 0xA7 or "
     "packet[16] != 0x08) or (packet[3] > 0x39? packet[18] > 0x04: "
     "not packet[32] != 0x00))? ((packet[32] == 0x00? not packet[51] > 0x6D: "
     "packet[54] == 0x01)? (not packet[3] >= 0x39 and packet[7] != 0x00): "
     "not packet[45] >= 0x70): ((not packet[5] != 0x90? packet[52] > 0x00: "
     "packet[49] == 0x63) and (not packet[46] >= 0x6C? packet[15] <= 0x01: "
     "not packet[27] >= 0xA7))))? ((((packet[22] > 0x00? "
     "not packet[36] >= 0x00: packet[0] > 0x45)? (packet[31] != 0x00? "
     "not packet[40] == 0x07: packet[31] >= 0x00): not packet[43] > 0x61) and "
     "((not packet[16] == 0x08 and not packet[13] >= 0x00)? "
     "(packet[24] <= 0x00 or packet[15] != 0x01): "
     "(packet[56] < 0x01? packet[50] > 0x6F: not packet[56] == 0x01)))? "
     "(packet[15] >= 0x01 or ((not packet[14] < 0x00? not packet[39] >= 0x00: "
     "not packet[4] == 0x20)? (packet[12] >= 0x0A and "
     "not packet[25] <= 0x25): packet[2] < 0x00)): "
     "(((not packet[19] <= 0x04 or not packet[25] < 0x25)? "
     "(packet[10] != 0x00 or packet[25] < 0x25): (not packet[46] > 0x6C? "
     "not packet[23] <= 0x35: packet[56] < 0x01))? "
     "((not packet[48] >= 0x03 or not packet[1] == 0x00)? "
     "(packet[47] >= 0x65 and not packet[13] == 0x00): (packet[34] <= 0x00? "
     "packet[22] <= 0x00: packet[43] >= 0x61)): (not packet[6] < 0x00 and "
     "not packet[41] < 0x65))): (((not packet[21] != 0x45 and "
     "(packet[26] < 0x22 or not packet[46] <= 0x6C)) and "
     "((not packet[56] > 0x01? packet[3] == 0x39: not packet[42] >= 0x78)? "
     "(not packet[4] > 0x20 or not packet[8] >= 0x49): "
     "packet[34] > 0x00)) and ((packet[50] >= 0x6F and "
     "(packet[1] != 0x00 and not packet[37] != 0x00)) and "
     "((packet[28] == 0x17 or not packet[11] < 0x00) or (packet[40] == 0x07? "
     "not packet[54] > 0x01: packet[18] < 0x04)))))",
                                               &pkt_dns_request, FALSE},
    {"((((packet[26] > 0x22 or packet[19] != 0x04)? ((not packet[17] > 0x08? "
     "packet[20] != 0xE0: packet[52] < 0x00) and not packet[31] == 0x00): "
     "((not packet[23] == 0x35 and packet[13] < 0x00) and "
     "(not packet[44] > 0x6D and packet[22] <= 0x00)))? "
     "(((not packet[27] >= 0xA7? packet[34] >= 0x00: "
     "not packet[38] < 0x00) and (not packet[37] < 0x00? packet[40] > 0x07: "
     "not packet[50] >= 0x6F)) and packet[36] != 0x00): "
     "(((packet[16] == 0x08? not packet[50] > 0x6F: packet[51] != 0x6D)? "
     "not packet[29] != 0x08: packet[16] <= 0x08)? "
     "((not packet[32] != 0x00 or not packet[26] != 0x22) or "
     "(not packet[27] != 0xA7 and not packet[21] == 0x45)): "
     "((packet[30] >= 0x01 or packet[40] > 0x07) or "
     "(not packet[46] < 0x6C and packet[56] <= 0x01))))? packet[31] <= 0x00: "
     "(not packet[50] >= 0x6F and not packet[9] <= 0x11))",
                                               &pkt_dns_request, TRUE},
    {"packet32[13] <= 0xFFFFFFE",              &pkt_dns_request, TRUE},
    {"packet32[53b] <= 0xFFFFFFE",             &pkt_dns_request, TRUE},
    {"packet32[14] <= 0xFFFFFFE",              &pkt_dns_request, FALSE},
    {"packet32[54b] <= 0xFFFFFFE",             &pkt_dns_request, FALSE},
    {"ip.HdrLength == 5 and ip.TOS == 0 and ip.Length == 57 and "
     "ip.Id == 0x2090 and ip.FragOff == 0 and ip.MF == 0 and ip.DF == 0 and "
     "ip.TTL == 73 and ip.Protocol == 17 and ip.SrcAddr == 0xFFFF0A000001 and "
     "ip.DstAddr == 0xFFFF08080404 and udp.SrcPort == 57413 and "
     "udp.DstPort == 53 and udp.Length == 37", &pkt_dns_request, TRUE},
    {"ip.HdrLength > 5 or ip.TOS > 0 or ip.Length < 57 or ip.Id > 0x2090 or "
     "ip.FragOff != 0 or ip.MF < 0 or ip.DF < 0 or ip.TTL > 73 or "
     "ip.Protocol < 17 or ip.SrcAddr < 0xFFFF0A000001 or "
     "ip.DstAddr > 0xFFFF08080404 or udp.SrcPort > 57413 or "
     "udp.DstPort != 53 or udp.Length < 37",   &pkt_dns_request, FALSE},
    {"localAddr == 10.0.0.1 && remoteAddr == 8.8.4.4 && "
     "localPort == 57413 && remotePort == 53 && protocol == 17",
                                               &pkt_dns_request, TRUE},
    {"ipv6",                                   &pkt_ipv6_tcp_syn, TRUE},
    {"ip",                                     &pkt_ipv6_tcp_syn, FALSE},
    {"tcp.Syn",                                &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.Syn == ::1 && tcp.Syn < ::ffff:aaaa:bbbb:cccc:dddd",
                                               &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.DstPort >= 23 && tcp.DstPort <= 23", &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.Syn and not tcp.Ack",                &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.Syn == 1 && tcp.Ack == 0",           &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.Rst or tcp.Fin",                     &pkt_ipv6_tcp_syn, FALSE},
    {"(tcp.Syn? !tcp.Rst && !tcp.Fin: true)",  &pkt_ipv6_tcp_syn, TRUE},
    {"(tcp.Rst? !tcp.Syn: (tcp.Fin? !tcp.Syn: tcp.Syn))",
                                               &pkt_ipv6_tcp_syn, TRUE},
    {"(tcp.Rst or tcp.Urg or tcp.Psh or tcp.Fin? false: tcp.Syn)",
                                               &pkt_ipv6_tcp_syn, TRUE},
    {"(tcp.Rst and tcp.Urg and tcp.Psh and tcp.Fin? false: tcp.Syn)",
                                               &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.PayloadLength == 0",                 &pkt_ipv6_tcp_syn, TRUE},
    {"ip and !loopback and (outbound? tcp.DstPort == 80 or"
     " tcp.DstPort == 443 or udp.DstPort == 53 :"
     " icmp.Type == 11 and icmp.Code == 0)",   &pkt_ipv6_tcp_syn, FALSE},
    {"ipv6.SrcAddr == 1234:5678:1::aabb:ccdd", &pkt_ipv6_tcp_syn, TRUE},
    {"ipv6.SrcAddr == aabb:5678:1::1234:ccdd", &pkt_ipv6_tcp_syn, FALSE},
    {"tcp.SrcPort == 50046",                   &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.SrcPort == 0x0000C37E",              &pkt_ipv6_tcp_syn, TRUE},
    {"packet32[0b] == 0x60000000 && packet32[1b] == 0x00000000 && "
     "packet32[2b] == 0x00000028 && packet32[3b] == 0x00002806 && "
     "packet32[4b] == 0x00280640 && packet32[5b] == 0x28064012 && "
     "packet32[-4b] == 0x01030307 && packet32[-5b] == 0x00010303",
                                               &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.Payload32[0] > 0",                   &pkt_ipv6_tcp_syn, FALSE},
    {"random8 < 128",                          &pkt_ipv6_tcp_syn, TRUE},
    {"(random8 < 128? random16 < 0x8000: random32 < 0x80000000)",
                                               &pkt_ipv6_tcp_syn, TRUE},
    {"((((packet[56] != 0xC3? not packet[26] > 0x00: (packet[50] <= 0x00? "
     "packet[62] < 0xFF: not packet[43] < 0x17))? not packet[2] > 0x00: "
     "(packet[69] != 0xFF or (not packet[28] >= 0x00 and "
     "not packet[79] > 0x07)))? (((packet[46] < 0xC8 or "
     "packet[47] == 0xAA) or (packet[51] == 0x00 and packet[0] >= 0x60))? "
     "packet[55] == 0xAA: not packet[79] >= 0x07): not packet[53] < 0x02)? "
     "((not packet[65] > 0x02 and ((packet[36] >= 0x00 or "
     "packet[24] < 0x00) and packet[3] != 0x00)) and (not packet[56] < 0xC3? "
     "(not packet[0] <= 0x60 and (not packet[38] == 0x00 and "
     "packet[78] > 0x03)): ((not packet[56] == 0xC3 and "
     "not packet[9] < 0x34) and (packet[21] > 0xBB? not packet[67] < 0x0A: "
     "not packet[75] >= 0x00)))): not packet[5] > 0x28)",
                                                &pkt_ipv6_tcp_syn, FALSE},
    {"(((packet[8] >= 0x12 and ((not packet[36] >= 0x00? "
     "not packet[57] > 0x5E: packet[66] > 0x08) and "
     "(not packet[53] > 0x02? not packet[2] == 0x00: packet[76] < 0x01))) or "
     "(((not packet[26] <= 0x00? not packet[57] <= 0x5E: packet[7] >= 0x40)? "
     "packet[60] > 0x02: not packet[11] <= 0x78) or ((packet[71] != 0x86? "
     "packet[65] > 0x02: not packet[4] > 0x00)? (not packet[2] != 0x00? "
     "not packet[57] < 0x5E: not packet[14] == 0x00): "
     "(not packet[25] != 0x00 or packet[29] >= 0x00)))) or "
     "(not packet[59] <= 0x00 or ((packet[76] < 0x01? not packet[7] < 0x40: "
     "(packet[66] != 0x08 and not packet[30] > 0x00)) or "
     "not packet[20] <= 0xAA)))",               &pkt_ipv6_tcp_syn, TRUE},
    {"((packet[50] >= 0x00? packet[8] != 0x12: (((packet[33] > 0x00? "
     "packet[15] >= 0x00: not packet[21] == 0xBB) or (packet[67] > 0x0A? "
     "packet[9] == 0x34: packet[36] > 0x00)) and (packet[74] < 0x00? "
     "(packet[60] != 0x02 and not packet[26] >= 0x00): "
     "(not packet[29] == 0x00 and not packet[25] < 0x00)))) or "
     "((((not packet[69] != 0xFF or packet[10] >= 0x56)? packet[8] >= 0x12: "
     "(packet[78] < 0x03 and packet[9] >= 0x34))? ((packet[40] <= 0xC3? "
     "not packet[15] > 0x00: not packet[71] != 0x86) and "
     "not packet[45] != 0xD7): ((not packet[50] >= 0x00 or "
     "not packet[1] == 0x00) or not packet[55] >= 0xAA))? "
     "(not packet[32] == 0x00? (not packet[58] <= 0x00 and "
     "not packet[8] > 0x12): (not packet[7] < 0x40 or "
     "not packet[4] >= 0x00)): (((not packet[23] < 0xDD or "
     "packet[68] >= 0xFF) and (packet[50] == 0x00 and "
     "not packet[12] >= 0x00))? packet[48] >= 0x00: ((packet[10] != 0x56 and "
     "not packet[4] == 0x00) and (packet[11] >= 0x78? not packet[18] > 0x00: "
     "not packet[55] == 0xAA)))))",             &pkt_ipv6_tcp_syn, TRUE},
    {"((packet[79] <= 0x07 and not packet[62] == 0xFF) and "
     "((((not packet[20] > 0xAA? packet[20] <= 0xAA: packet[27] <= 0x00) and "
     "(packet[62] > 0xFF? packet[12] == 0x00: not packet[19] == 0x00)) and "
     "((not packet[68] == 0xFF and packet[75] > 0x00)? (packet[6] <= 0x06 or "
     "packet[76] <= 0x01): not packet[50] == 0x00)) and (packet[57] >= 0x5E? "
     "((not packet[75] >= 0x00? packet[75] != 0x00: not packet[63] != 0xC4)? "
     "not packet[1] < 0x00: (packet[30] > 0x00? packet[16] == 0x00: "
     "packet[36] == 0x00)): ((packet[66] < 0x08? not packet[0] < 0x60: "
     "packet[72] != 0x00)? (packet[25] > 0x00 or not packet[13] < 0x01): "
     "(packet[47] <= 0xAA and not packet[15] != 0x00)))))",
                                                &pkt_ipv6_tcp_syn, FALSE},
    {"packet32[-4b] < 0xFFFFFFFE",              &pkt_ipv6_tcp_syn, TRUE},
    {"ipv6.TrafficClass == 0x00000000 and ipv6.FlowLabel == 0x0000 and "
     "ipv6.Length == 40 and ipv6.NextHdr == 6 and ipv6.HopLimit == 64 and "
     "ipv6.SrcAddr == 1234:5678:1:0:0:0:aabb:ccdd and "
     "ipv6.DstAddr == 0:0:0:0:0:0:0:1 and tcp.SrcPort == 50046 and "
     "tcp.DstPort == 23 and tcp.SeqNum == 3789015210 and tcp.AckNum == 0 and "
     "tcp.HdrLength == 10 and tcp.Fin == 0 and tcp.Syn == 1 and "
     "tcp.Rst == 0 and tcp.Psh == 0 and tcp.Ack == 0 and tcp.Urg == 0 and "
     "tcp.Window == 43690 and tcp.UrgPtr == 0",&pkt_ipv6_tcp_syn, TRUE},
    {"ipv6.TrafficClass > 0x00000000 or ipv6.FlowLabel < 0x0000 or "
     "ipv6.Length < 40 or ipv6.NextHdr != 6 or ipv6.HopLimit > 64 or "
     "ipv6.SrcAddr != 1234:5678:1:0:0:0:aabb:ccdd or "
     "ipv6.DstAddr < 0:0:0:0:0:0:0:1 or tcp.SrcPort < 50046 or "
     "tcp.DstPort > 23 or tcp.SeqNum < 3789015210 or tcp.AckNum < 0 or "
     "tcp.HdrLength != 10 or tcp.Fin > 0 or tcp.Syn > 1 or tcp.Rst > 0 or "
     "tcp.Psh > 0 or tcp.Ack != 0 or tcp.Urg != 0 or tcp.Window != 43690 or "
     "tcp.UrgPtr != 0",                        &pkt_ipv6_tcp_syn, FALSE},
    {"localAddr == 1234:5678:1::aabb:ccdd && remoteAddr == ::1 && "
     "localPort == 50046 && remotePort == 23 && protocol == 6",
                                               &pkt_ipv6_tcp_syn, TRUE},
    {"packet[0] == 0x60",                      &pkt_ipv6_tcp_syn, TRUE},
    {"icmpv6",                                 &pkt_ipv6_echo_reply, TRUE},
    {"icmp",                                   &pkt_ipv6_echo_reply, FALSE},
    {"protocol == ICMPV6",                     &pkt_ipv6_echo_reply, TRUE},
    {"protocol == ICMP",                       &pkt_ipv6_echo_reply, FALSE},
    {"icmp or icmpv6",                         &pkt_ipv6_echo_reply, TRUE},
    {"not icmp",                               &pkt_ipv6_echo_reply, TRUE},
    {"icmpv6.Type == 129",                     &pkt_ipv6_echo_reply, TRUE},
    {"icmpv6.Code == 0",                       &pkt_ipv6_echo_reply, TRUE},
    {"icmpv6.Body == 0x10720003",              &pkt_ipv6_echo_reply, TRUE},
    {"ipv6.DstAddr >= 1000",                   &pkt_ipv6_echo_reply, FALSE},
    {"ipv6.DstAddr <= 1",                      &pkt_ipv6_echo_reply, TRUE},
    {"length == 104 && ipv6.Length == 64",     &pkt_ipv6_echo_reply, TRUE},
    {"ip and !loopback and (outbound? tcp.DstPort == 80 or"
     " tcp.DstPort == 443 or udp.DstPort == 53 :"
     " icmp.Type == 11 and icmp.Code == 0)",   &pkt_ipv6_echo_reply, FALSE},
    {"fragment",                               &pkt_ipv6_echo_reply, FALSE},
    {"random8 < 128",                          &pkt_ipv6_echo_reply, TRUE},
    {"(random8 < 128? random16 < 0x8000: random32 < 0x80000000)",
                                               &pkt_ipv6_echo_reply, TRUE},
    {"(((((not packet[68] != 0x44? packet[58] >= 0x00: "
     "not packet[39] >= 0x01) and not packet[101] != 0x55) and "
     "((not packet[70] >= 0x66? not packet[68] > 0x44: "
     "not packet[77] > 0xDD) and (not packet[72] <= 0x88 or "
     "packet[5] >= 0x40)))? (((not packet[88] <= 0x88 and "
     "packet[13] > 0x00) and (packet[52] >= 0x00 and "
     "not packet[96] == 0x00)) or packet[32] < 0x00): "
     "(((packet[57] <= 0x75? not packet[27] == 0x00: packet[0] >= 0x60) or "
     "(packet[90] == 0xAA or packet[62] > 0x00))? "
     "((not packet[39] <= 0x01 and packet[48] != 0xA4) or "
     "packet[86] <= 0x66): not packet[61] >= 0x00)) and "
     "((packet[64] >= 0x00? (not packet[50] != 0x69 or "
     "(not packet[92] != 0xCC? not packet[9] < 0x00: packet[93] >= 0xDD)): "
     "((packet[58] <= 0x00 and not packet[103] != 0x77) or "
     "(not packet[22] < 0x00? not packet[93] <= 0xDD: "
     "not packet[55] < 0x00))) or (packet[87] <= 0x77 and "
     "((packet[70] <= 0x66 and not packet[59] <= 0x00) and "
     "(not packet[8] != 0x00 or packet[82] == 0x22)))))",
                                               &pkt_ipv6_echo_reply, FALSE},
    {"((((packet[14] == 0x00? (packet[102] > 0x66 or packet[16] != 0x00): "
     "(packet[81] >= 0x11 or not packet[35] <= 0x00))? "
     "((packet[88] < 0x88? packet[8] <= 0x00: packet[18] > 0x00) or "
     "(not packet[82] <= 0x22? not packet[13] == 0x00: "
     "not packet[37] == 0x00)): (packet[38] < 0x00 and "
     "not packet[83] < 0x33))? packet[95] >= 0xFF: "
     "(((not packet[96] <= 0x00? packet[84] != 0x44: "
     "not packet[34] <= 0x00) or not packet[47] <= 0x03) or "
     "((packet[78] == 0xEE? packet[101] >= 0x55: not packet[25] >= 0x00) or "
     "packet[9] <= 0x00))) or (packet[59] == 0x00 and ((packet[72] < 0x88 and "
     "(packet[52] == 0x00 or not packet[54] >= 0x00)) or "
     "(packet[13] >= 0x00 or (not packet[93] == 0xDD and "
     "not packet[99] < 0x33)))))",             &pkt_ipv6_echo_reply, TRUE},
    {"ipv6.TrafficClass == 0x00000000 and ipv6.FlowLabel == 0x0000 and "
     "ipv6.Length == 64 and ipv6.NextHdr == 58 and ipv6.HopLimit == 31 and "
     "ipv6.SrcAddr == 0:0:0:0:0:0:0:1 and ipv6.DstAddr == 0:0:0:0:0:0:0:1 and "
     "icmpv6.Type == 129 and icmpv6.Code == 0 and icmpv6.Body == 0x10720003",
                                               &pkt_ipv6_echo_reply, TRUE},
    {"ipv6.TrafficClass != 0x00000000 or ipv6.FlowLabel != 0x0000 or "
     "ipv6.Length < 64 or ipv6.NextHdr > 58 or ipv6.HopLimit != 31 or "
     "ipv6.SrcAddr != 0:0:0:0:0:0:0:1 or ipv6.DstAddr > 0:0:0:0:0:0:0:1 or "
     "icmpv6.Type > 129 or icmpv6.Code > 0 or icmpv6.Body != 0x10720003",
                                               &pkt_ipv6_echo_reply, FALSE},
    {"localAddr == ::1 && remoteAddr == ::1 && localPort == 129 && "
     "remotePort == 0 && protocol == 58",      &pkt_ipv6_echo_reply, TRUE},
    {"true",                                   &pkt_ipv6_exthdrs_udp, TRUE},
    {"false",                                  &pkt_ipv6_exthdrs_udp, FALSE},
    {"protocol == 0",                          &pkt_ipv6_exthdrs_udp, FALSE},
    {"udp",                                    &pkt_ipv6_exthdrs_udp, TRUE},
    {"tcp",                                    &pkt_ipv6_exthdrs_udp, FALSE},
    {"ipv6.SrcAddr == ::",                     &pkt_ipv6_exthdrs_udp, FALSE},
    {"ipv6.SrcAddr == ::1",                    &pkt_ipv6_exthdrs_udp, TRUE},
    {"ipv6.SrcAddr == ::2",                    &pkt_ipv6_exthdrs_udp, FALSE},
    {"ipv6.SrcAddr == ::8.8.4.4",              &pkt_ipv6_exthdrs_udp, FALSE},
    {"ipv6.SrcAddr < abcd::1",                 &pkt_ipv6_exthdrs_udp, TRUE},
    {"ipv6.SrcAddr <= abcd::1",                &pkt_ipv6_exthdrs_udp, TRUE},
    {"ipv6.SrcAddr != abcd::1",                &pkt_ipv6_exthdrs_udp, TRUE},
    {"ipv6.SrcAddr >= abcd::1",                &pkt_ipv6_exthdrs_udp, FALSE},
    {"ipv6.SrcAddr > abcd::1",                 &pkt_ipv6_exthdrs_udp, FALSE},
    {"timestamp > -1",                         &pkt_ipv6_exthdrs_udp, TRUE},
    {"udp.SrcPort == 4660 and udp.DstPort == 43690",
                                               &pkt_ipv6_exthdrs_udp, TRUE},
    {"udp.SrcPort == 4660 and udp.DstPort == 12345",
                                               &pkt_ipv6_exthdrs_udp, FALSE},
    {"localAddr == ::1",                       &pkt_ipv6_exthdrs_udp, TRUE},
    {"localPort == 4660 and remotePort == 43690",
                                               &pkt_ipv6_exthdrs_udp, TRUE},
    {"(outbound and tcp? tcp.DstPort == 0xABAB: false) or "
     "(outbound and udp? udp.DstPort == 0xAAAA: false) or "
     "(inbound and tcp? tcp.SrcPort == 0xABAB: false) or "
     "(inbound and udp? udp.SrcPort == 0xAAAA: false)",
                                               &pkt_ipv6_exthdrs_udp, TRUE},
    {"(ipv6? true: false) or (udp? udp.DstPort != 53: false) or "
     "(not tcp and not udp? true: false)",     &pkt_ipv6_exthdrs_udp, TRUE},
    {"(tcp or udp) and (ip or ipv6) and (icmp or !icmpv6) and "
     "(tcp.Payload16[-1] == 0x1234 or udp.Payload16[-1] == 0x2101)",
                                               &pkt_ipv6_exthdrs_udp, TRUE},
    {"udp.PayloadLength == 13",                &pkt_ipv6_exthdrs_udp, TRUE},
    {"(udp.Length == 13? false: udp.Length == 21)",
                                               &pkt_ipv6_exthdrs_udp, TRUE},
    {"(tcp or icmp or icmpv6 or ip or !udp or ipv6? udp.PayloadLength > 0: "
        "udp.DstPort == 39482)",               &pkt_ipv6_exthdrs_udp, TRUE},
    {"random8 < 128",                          &pkt_ipv6_exthdrs_udp, TRUE},
    {"(random8 < 128? random16 < 0x8000: random32 < 0x80000000)",
                                               &pkt_ipv6_exthdrs_udp, TRUE},
    {"timestamp != -0x8000000000000000",       &pkt_ipv6_exthdrs_udp, TRUE},
    {"timestamp !=  0x7fffffffffffffff",       &pkt_ipv6_exthdrs_udp, TRUE},
    {"timestamp == -0x1deadbeef1234567",       &pkt_ipv6_exthdrs_udp, FALSE},
    {"((packet[2] <= 0x00 or (((packet[29] < 0x00 or "
     "not packet[35] != 0x00) and packet[32] != 0x00) and "
     "((not packet[31] != 0x00 and packet[52] > 0x00) and "
     "(packet[28] < 0x00? not packet[28] <= 0x00: packet[73] == 0x65))))? "
     "((((packet[9] <= 0x00? not packet[28] == 0x00: "
     "not packet[22] >= 0x00) and (not packet[20] != 0x00 and "
     "not packet[22] >= 0x00)) and ((packet[42] > 0x00 and "
     "not packet[12] < 0x00) or packet[66] == 0xAA)) or "
     "(not packet[23] >= 0x01 and (packet[79] > 0x6F and "
     "(not packet[18] > 0x00 or not packet[82] <= 0x64)))): "
     "packet[62] <= 0x00)",
                                               &pkt_ipv6_exthdrs_udp, FALSE},
    {"((packet[56] > 0x11? (((not packet[0] > 0x60? not packet[22] < 0x00: "
     "not packet[15] > 0x00)? (not packet[5] >= 0x2D and packet[18] != 0x00): "
     "packet[45] == 0x00) or ((packet[47] >= 0x00 or not packet[32] >= 0x00)? "
     "(packet[29] >= 0x00 or not packet[20] == 0x00): (packet[32] > 0x00 and "
     "packet[46] > 0x00))): not packet[76] != 0x6F) or "
     "((not packet[32] > 0x00 or (packet[13] == 0x00 or (packet[4] > 0x00 or "
     "packet[21] < 0x00))) or (((packet[55] != 0x00? packet[67] != 0xAA: "
     "not packet[66] >= 0xAA)? (packet[8] > 0x00? not packet[28] > 0x00: "
     "packet[28] <= 0x00): not packet[78] != 0x57)? ((packet[79] == 0x6F or "
     "packet[25] == 0x00) or (packet[68] == 0x00? not packet[50] < 0x00: "
     "not packet[68] < 0x00)): ((not packet[78] > 0x57 and "
     "not packet[8] == 0x00) or packet[32] <= 0x00))))",
                                               &pkt_ipv6_exthdrs_udp, TRUE},
    {"ipv6.TrafficClass == 0x00000000 and ipv6.FlowLabel == 0x0000 and "
     "ipv6.Length == 45 and ipv6.NextHdr == 0 and ipv6.HopLimit == 100 and "
     "ipv6.SrcAddr == 0:0:0:0:0:0:0:1 and ipv6.DstAddr == 0:0:0:0:0:0:0:1 and "
     "udp.SrcPort == 4660 and udp.DstPort == 43690 and udp.Length == 21",
                                               &pkt_ipv6_exthdrs_udp, TRUE},
    {"(ipv6.TrafficClass == 0x00000000 and ipv6.FlowLabel == 0x0000 and "
     "ipv6.Length == 45 and ipv6.NextHdr == 0 and ipv6.HopLimit == 101? false: "
     "(ipv6.SrcAddr == 0:0:0:0:0:0:0:1 and ipv6.DstAddr == 0:0:0:0:0:0:0:1 and "
     "udp.SrcPort == 4660 and udp.DstPort == 43691? false: udp.Length == 22))",
                                               &pkt_ipv6_exthdrs_udp, FALSE},
    {"ipv6.TrafficClass != 0x00000000 or ipv6.FlowLabel > 0x0000 or "
     "ipv6.Length < 45 or ipv6.NextHdr != 0 or ipv6.HopLimit < 100 or "
     "ipv6.SrcAddr > 0:0:0:0:0:0:0:1 or ipv6.DstAddr < 0:0:0:0:0:0:0:1 or "
     "udp.SrcPort > 4660 or udp.DstPort < 43690 or udp.Length > 21",
                                               &pkt_ipv6_exthdrs_udp, FALSE},
    {"localAddr == ::1 and remoteAddr == 1 and localPort == 4660 and "
     "remotePort == 43690 and protocol == 17", &pkt_ipv6_exthdrs_udp, TRUE},
    {"fragment",                               &pkt_ipv4_fragment_0, TRUE},
    {"ip.MF or ip.FragOff != 0",               &pkt_ipv4_fragment_0, TRUE},
    {"icmp",                                   &pkt_ipv4_fragment_0, TRUE},
    {"icmp.Body != 123 || icmp.Body == 123",   &pkt_ipv4_fragment_0, TRUE},
    {"length == 84 || ip.Length == 84",        &pkt_ipv4_fragment_0, FALSE},
    {"ip.HdrLength == 5 and ip.TOS == 0 and ip.Length == 28 and "
     "ip.Id == 0x1234 and ip.FragOff == 0 and ip.MF == 1 and ip.DF == 0 and "
     "ip.TTL == 64 and ip.Protocol == 1 and ip.SrcAddr == 0xFFFF0A000001 and "
     "ip.DstAddr == 0xFFFF08080808 and icmp.Type == 8 and icmp.Code == 0 and "
     "icmp.Body == 0x0D560001",                &pkt_ipv4_fragment_0, TRUE},
    {"fragment",                               &pkt_ipv4_fragment_1, TRUE},
    {"ip.MF or ip.FragOff != 0",               &pkt_ipv4_fragment_1, TRUE},
    {"icmp",                                   &pkt_ipv4_fragment_1, FALSE},
    {"icmp.Body != 123 || icmp.Body == 123",   &pkt_ipv4_fragment_1, FALSE},
    {"length == 84 || ip.Length == 84",        &pkt_ipv4_fragment_1, FALSE},
    {"ip.HdrLength == 5 and ip.TOS == 0 and ip.Length == 76 and "
     "ip.Id == 0x1234 and ip.FragOff == 1 and ip.MF == 0 and ip.DF == 0 and "
     "ip.TTL == 64 and ip.Protocol == 1 and ip.SrcAddr == 0xFFFF0A000001 and "
     "ip.DstAddr == 0xFFFF08080808",           &pkt_ipv4_fragment_1, TRUE},
    {"fragment",                               &pkt_ipv6_fragment_0, TRUE},
    {"icmpv6",                                 &pkt_ipv6_fragment_0, TRUE},
    {"length == 104 || ipv6.Length == 64",     &pkt_ipv6_fragment_0, FALSE},
    {"ipv6.TrafficClass == 0x00000000 and ipv6.FlowLabel == 0x0000 and "
     "ipv6.Length == 32 and ipv6.NextHdr == 44 and ipv6.HopLimit == 31 and "
     "ipv6.SrcAddr == 0:0:0:0:0:0:0:1 and ipv6.DstAddr == 0:0:0:0:0:0:0:1 and "
     "icmpv6.Type == 129 and icmpv6.Code == 0 and icmpv6.Body == 0x10720003",
                                               &pkt_ipv6_fragment_0, TRUE},
    {"fragment",                               &pkt_ipv6_fragment_1, TRUE},
    {"icmpv6",                                 &pkt_ipv6_fragment_1, FALSE},
    {"length == 104 || ipv6.Length == 64",     &pkt_ipv6_fragment_1, FALSE},
    {"ipv6.TrafficClass == 0x00000000 and ipv6.FlowLabel == 0x0000 and "
     "ipv6.Length == 48 and ipv6.NextHdr == 44 and ipv6.HopLimit == 31 and "
     "ipv6.SrcAddr == 0:0:0:0:0:0:0:1 and ipv6.DstAddr == 0:0:0:0:0:0:0:1",
                                               &pkt_ipv6_fragment_1, TRUE},
};

/*
 * Test range.
 */
static size_t lo = 0, hi = UINT_MAX;

/*
 * Main.
 */
int main(int argc, char **argv)
{
    HANDLE upper_handle, lower_handle;
    HANDLE console, monitor;
    BOOL passed[sizeof(tests) / sizeof(struct test)], first;
    DWORD result;
    LARGE_INTEGER freq;
    UINT64 diff;
    size_t i;
    size_t num_tests = sizeof(tests) / sizeof(struct test), passed_tests;

    switch (argc)
    {
        case 1:
            break;
        case 3:
            lo = atoi(argv[1]);
            hi = atoi(argv[2]);
            if (hi >= lo)
            {
                break;
            }
            // Fallthrough
        default:
            fprintf(stderr, "usage: %s [low high]\n", argv[0]);
            exit(EXIT_FAILURE);
    }
    hi = MIN(num_tests, hi);

    // Open handles to:
    // (1) stop normal traffic from interacting with the tests; and
    // (2) stop test packets escaping to the Internet or TCP/IP stack.
    upper_handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 9999,
        WINDIVERT_FLAG_DROP);
    lower_handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, -9999,
        WINDIVERT_FLAG_DROP);
    if (upper_handle == INVALID_HANDLE_VALUE ||
        lower_handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: failed to open WinDivert handle (err = %d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    console = GetStdHandle(STD_OUTPUT_HANDLE);
    QueryPerformanceFrequency(&freq);

    // Spawn monitor thread:
    monitor = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)monitor_worker,
        NULL, 0, NULL);
    if (monitor == NULL)
    {
        fprintf(stderr, "error: failed to spawn monitor thread (err = %d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Wait for existing packets to flush:
    Sleep(150);

    // Run tests:
    passed_tests = 0;
    for (i = lo; i < num_tests && i <= hi; i++)
    {
        const char *filter = tests[i].filter;
        const char *packet = tests[i].packet->packet;
        size_t packet_len = tests[i].packet->packet_len;
        char *name = tests[i].packet->name;
        BOOL match = tests[i].match;

        // Run the test:
        passed[i] = run_test(upper_handle, filter, packet, packet_len, match,
            &diff);
        diff = 1000000 * diff / freq.QuadPart;
        printf("%.3u ", (unsigned)i);
        if (passed[i])
        {
            SetConsoleTextAttribute(console, FOREGROUND_GREEN);
            printf("PASSED");
            passed_tests++;
        }
        else
        {
            SetConsoleTextAttribute(console, FOREGROUND_RED);
            printf("FAILED");
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);
        printf(" %.5llu p=[", diff);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        printf("%s", name);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);
        printf("] f=[");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        printf("%s", filter);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);
        printf("]\n");
    }

    WinDivertClose(upper_handle);
    WinDivertClose(lower_handle);

    result = WaitForSingleObject(monitor, 1000);
    switch (result)
    {
        case WAIT_OBJECT_0:
            break;
        case WAIT_TIMEOUT:
            fprintf(stderr, "error: failed to wait for monitor thread "
                "(timeout)\n");
            exit(EXIT_FAILURE);
        default:
            fprintf(stderr, "error: failed to wait for monitor thread "
                "(err = %d)\n", result);
            exit(EXIT_FAILURE);
    }

    printf("\npassed = %.2f%%\n",
        ((double)passed_tests / (double)(hi - lo)) * 100.0);

    first = TRUE;
    for (i = lo; i < num_tests && i <= hi; i++)
    {
        const char *filter = tests[i].filter;
        char *name = tests[i].packet->name;
 
        if (passed[i])
        {
            continue;
        }
        if (first)
        {
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_BLUE);
            printf("\nFAILED TESTS");
            SetConsoleTextAttribute(console, FOREGROUND_RED |
                FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("\n------------\n\n");
            first = FALSE;
        }
        printf("%.3u ", (unsigned)i);
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        printf("FAILED");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);
        printf(" p=[");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        printf("%s", name);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);
        printf("] f=[");
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        printf("%s", filter);
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN |
            FOREGROUND_BLUE);
        printf("]\n");
    }

    return 0;
}

/*
 * Run a test case.
 */
static BOOL run_test(HANDLE inject_handle, const char *filter,
    const char *packet, const size_t packet_len, BOOL match, INT64 *diff)
{
    static char object[8192];
    char buf[2][MAX_PACKET];
    UINT buf_len[2], i, idx;
    DWORD iolen;
    WINDIVERT_ADDRESS addr[2], addr_send;
    OVERLAPPED overlapped[2];
    const char *err_str;
    UINT err_pos;
    PWINDIVERT_IPHDR iphdr = NULL;
    HANDLE handle[2] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
    HANDLE event[2] = {NULL, NULL};
    BOOL random, result, ipv4;
    LARGE_INTEGER end;
    UINT64 val;

    *diff = 0;

    // (0) Verify the test data:
    if (!WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK,
            object, sizeof(object), &err_str, &err_pos))
    {
        fprintf(stderr, "error: filter string \"%s\" is invalid with error "
            "\"%s\" (position=%u)\n", filter, err_str, err_pos);
        goto failed;
    }

    // (1) Open WinDivert handles:
    handle[0] = WinDivertOpen(object, WINDIVERT_LAYER_NETWORK, 8888, 0);
    if (handle[0] == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: failed to open WinDivert handle for filter "
            "\"%s\" (err = %d)\n", filter, GetLastError());
        goto failed;
    }
    handle[1] = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 7777, 0);
    if (handle[1] == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: failed to open WinDivert handle "
            "(err = %d)\n", GetLastError());
        goto failed;
    }
    if (!WinDivertSetParam(handle[0], WINDIVERT_PARAM_QUEUE_LENGTH,
            WINDIVERT_PARAM_QUEUE_LENGTH_MAX) ||
        !WinDivertGetParam(handle[0], WINDIVERT_PARAM_QUEUE_LENGTH, &val) ||
        val != WINDIVERT_PARAM_QUEUE_LENGTH_MAX)
    {
        fprintf(stderr, "error: failed to set WINDIVERT_PARAM_QUEUE_LENGTH "
            "parameter (err = %d)\n", GetLastError());
        goto failed;
    }
    if (!WinDivertSetParam(handle[0], WINDIVERT_PARAM_QUEUE_SIZE,
            WINDIVERT_PARAM_QUEUE_SIZE_MAX) ||
        !WinDivertGetParam(handle[0], WINDIVERT_PARAM_QUEUE_SIZE, &val) ||
        val != WINDIVERT_PARAM_QUEUE_SIZE_MAX)
    {
        fprintf(stderr, "error: failed to set WINDIVERT_PARAM_QUEUE_SIZE "
            "parameter (err = %d)\n", GetLastError());
        goto failed;
    }
    if (!WinDivertSetParam(handle[0], WINDIVERT_PARAM_QUEUE_TIME,
            WINDIVERT_PARAM_QUEUE_TIME_MAX) ||
        !WinDivertGetParam(handle[0], WINDIVERT_PARAM_QUEUE_TIME, &val) ||
        val != WINDIVERT_PARAM_QUEUE_TIME_MAX)
    {
        fprintf(stderr, "error: failed to set WINDIVERT_PARAM_QUEUE_TIME "
            "parameter (err = %d)\n", GetLastError());
        goto failed;
    }

    // (2) Create pended recv requests:
    event[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
    event[1] = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (event[0] == NULL || event[1] == NULL)
    {
        fprintf(stderr, "error: failed to create event (err = %d)\n",
            GetLastError());
        goto failed;
    }
    memset(&overlapped[0], 0, sizeof(overlapped[0]));
    memset(&overlapped[1], 0, sizeof(overlapped[1]));
    overlapped[0].hEvent = event[0];
    overlapped[1].hEvent = event[1];
    if (WinDivertRecvEx(handle[0], buf[0], sizeof(buf[0]), &buf_len[0], 0,
                &addr[0], NULL, &overlapped[0]) ||
            GetLastError() != ERROR_IO_PENDING ||
        WinDivertRecvEx(handle[1], buf[1], sizeof(buf[1]), &buf_len[1], 0,
                &addr[1], NULL, &overlapped[1]) ||
            GetLastError() != ERROR_IO_PENDING)
    {
        fprintf(stderr, "error: failed to created pended recv from WinDivert "
                "handle (err = %d)\n", GetLastError());
        goto failed;
    }

    // (2) Inject the packet:
    memset(&addr_send, 0, sizeof(addr_send));
    addr_send.Outbound    = TRUE;
    addr_send.IPChecksum  = FALSE;
    addr_send.TCPChecksum = FALSE;
    addr_send.UDPChecksum = FALSE;
    if (!WinDivertSend(inject_handle, (PVOID)packet, packet_len, NULL,
            &addr_send))
    {
        fprintf(stderr, "error: failed to inject test packet (err = %d)\n",
            GetLastError());
        goto failed;
    }

    // (3) Wait for the packet to arrive.
    // NOTE: This may fail, so set a generous time-out of 250ms.
    switch (WaitForMultipleObjects(2, event, FALSE, 250))
    {
        case WAIT_OBJECT_0:
            QueryPerformanceCounter(&end);
            result = TRUE;
            idx = 0;
            break;
        case WAIT_OBJECT_0+1:
            QueryPerformanceCounter(&end);
            result = FALSE;
            idx = 1;
            break;
        case WAIT_TIMEOUT:
            fprintf(stderr, "error: failed to read packet from WinDivert "
                "handle (timeout)\n", GetLastError());
            goto failed;
        default:
            fprintf(stderr, "error: failed to wait for packet (err = %d)\n",
                GetLastError());
            goto failed;
    }
    if (!GetOverlappedResult(handle[idx], &overlapped[idx], &iolen, TRUE))
    {
        fprintf(stderr, "error: failed to get the overlapped result from "
            "WinDivert handle (err = %d)\n", GetLastError());
        goto failed;
    }
    buf_len[idx] = (UINT)iolen;
    *diff = end.QuadPart - addr[idx].Timestamp;

    // (4) Verify that the packet is the same & matches.
    if (buf_len[idx] != packet_len)
    {
        fprintf(stderr, "error: packet length mis-match, expected (%u), got "
            "(%u)\n", (unsigned)packet_len, buf_len[idx]);
        goto failed;
    }
    iphdr = (PWINDIVERT_IPHDR)buf[idx];
    ipv4 = (iphdr->Version == 4);
    for (i = 0; i < packet_len; i++)
    {
        if (ipv4 && i >= offsetof(WINDIVERT_IPHDR, Checksum) &&
                    i < offsetof(WINDIVERT_IPHDR, Checksum) + sizeof(UINT16))
        {
            // The IPv4 checksum can change, so ignore it.
            continue;
        }
        if (packet[i] != buf[idx][i])
        {
            fprintf(stderr, "error: packet data mis-match, expected byte #%u "
                "to be (0x%.2X), got (0x%.2X)\n", i, (unsigned char)packet[i],
                (unsigned char)buf[idx][i]);
            for (i = 0; i < packet_len; i++)
            {
                printf("%c", (packet[i] == buf[idx][i]? '.': 'X'));
            }
            putchar('\n');
            goto failed;
        }
    }

    random = (strstr(filter, "random") != 0);
    // If (random && !result), then we cannot verify since the original
    // non-matching random values have been lost:
    if ((!random &&
            WinDivertHelperEvalFilter(filter, buf[idx], buf_len[idx],
                &addr[idx]) != result) ||
        (random && result && 
            !WinDivertHelperEvalFilter(filter, buf[idx], buf_len[idx],
                &addr[idx])))
    {
        fprintf(stderr, "error: filter \"%s\" does not match the given "
            "packet\n", filter);
        goto failed;
    }
    if (!random && result != match)
    {
        fprintf(stderr, "error: filter \"%s\" does not match the expected "
            "result\n", filter);
        goto failed;
    }

    // (5) Clean-up:
    if (!WinDivertShutdown(handle[0], WINDIVERT_SHUTDOWN_BOTH) ||
        !WinDivertShutdown(handle[1], WINDIVERT_SHUTDOWN_BOTH))
    {
        fprintf(stderr, "error: failed to shutdown WinDivert handle (err = "
            "%d)\n", GetLastError());
        goto failed;
    }
    for (i = 0; i < 1000 && WinDivertRecv(handle[0], NULL, 0, NULL, NULL); i++)
        ;
    if (GetLastError() != ERROR_NO_DATA)
    {
        fprintf(stderr, "error: failed to recv NO_DATA from shutdown "
            "WinDivert handle (err = %d)\n", GetLastError());
        goto failed;
    }
    for (i = 0; i < 1000 && WinDivertRecv(handle[1], NULL, 0, NULL, NULL); i++)
        ;
    if (GetLastError() != ERROR_NO_DATA)
    {
        fprintf(stderr, "error: failed to recv NO_DATA from shutdown "
            "WinDivert handle (err = %d)\n", GetLastError());
        goto failed;
    }
    if (!WinDivertClose(handle[0]) || !WinDivertClose(handle[1]))
    {
        fprintf(stderr, "error: failed to close WinDivert handle (err = %d)\n",
            GetLastError());
        goto failed;
    }
    CloseHandle(event[0]);
    CloseHandle(event[1]);

    return TRUE;

failed:
    for (i = 0; i < 2; i++)
    {
        if (handle[i] != INVALID_HANDLE_VALUE)
        {
            WinDivertClose(handle[i]);
        }
        if (event[i] != NULL)
        {
            CloseHandle(event[i]);
        }
    }
    return FALSE;
}

/*
 * Monitor thread.
 */
static DWORD monitor_worker(LPVOID arg)
{
    char filter[100], packet[4096], object_1[4096], *object_2, filter_2[8192];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR iphdr;
    UINT i;

    snprintf(filter, sizeof(filter), "processId=%d and priority=8888 and "
        "event=OPEN", GetCurrentProcessId());
    HANDLE handle = WinDivertOpen(filter, WINDIVERT_LAYER_REFLECT, 0,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: failed to open reflect handle (err = %d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    size_t num_tests = sizeof(tests) / sizeof(struct test);
    for (i = lo; i < num_tests && i <= hi; i++)
    {
        // (1) Read the reflected filter:
        WinDivertHelperCompileFilter(tests[i].filter, WINDIVERT_LAYER_NETWORK,
            object_1, sizeof(object_1), NULL, NULL);
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
        {
            fprintf(stderr, "error: failed to read OPEN event (err = %d)\n",
                GetLastError());
            exit(EXIT_FAILURE);
        }
        object_2 = packet;
        if (strcmp(object_1, object_2) != 0)
        {
            // Filter is not the same.
            fprintf(stderr, "error: filter object mismatch (%s vs %s)\n",
                object_1, object_2);
            exit(EXIT_FAILURE);
        }

        // (2) Test if formatted filter is equivalent:
        if (!WinDivertHelperFormatFilter(object_1, WINDIVERT_LAYER_NETWORK,
                filter_2, sizeof(filter_2)))
        {
            fprintf(stderr, "error: failed to format filter (err = %d)\n",
                GetLastError());
            exit(EXIT_FAILURE);
        }
        if (!WinDivertHelperCompileFilter(filter_2, WINDIVERT_LAYER_NETWORK,
                object_1, sizeof(object_1), NULL, NULL))
        {
            fprintf(stderr, "error: failed to recompile filter (err = %d)\n",
                GetLastError());
            exit(EXIT_FAILURE);
        }
        if (strcmp(object_1, object_2) == 0)
        {
            // Recompiled filter is exactly the same; test has passed.
            continue;
        }
        if (strstr(filter_2, "random") != NULL)
        {
            // Cannot verify random filters.
            continue;
        }
        iphdr = (PWINDIVERT_IPHDR)tests[i].packet->packet;
        memset(&addr, 0, sizeof(addr));
        addr.Event    = WINDIVERT_EVENT_NETWORK_PACKET;
        addr.Layer    = WINDIVERT_LAYER_NETWORK;
        addr.Outbound = TRUE;
        addr.IPv6     = (iphdr->Version == 4? FALSE: TRUE);
        if (WinDivertHelperEvalFilter(object_1, tests[i].packet->packet,
                tests[i].packet->packet_len, &addr) != tests[i].match)
        {
            fprintf(stderr, "error: failed to match recompiled filter "
                "(test = %.3u, filter = \"%s\" formatted = \"%s\", "
                "err = %d)\n", i, tests[i].filter, filter_2, GetLastError());
            exit(EXIT_FAILURE);
        }
    }

    WinDivertClose(handle);
    return 0;
}

