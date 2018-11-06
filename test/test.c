/*
 * test.c
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

/*
 * WinDivert testing framework.
 */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "windivert.h"

#define MAX_PACKET  2048

/*
 * Packet data.
 */
#include "test_data.c"

/*
 * Test entry.
 */
struct packet
{
    char *packet;
    size_t packet_len;
    char *name;
};

struct test
{
    char *filter;
    struct packet *packet;
    BOOL match;
};

/*
 * Prototypes.
 */
static BOOL run_test(HANDLE inject_handle, const char *filter,
    const char *packet, const size_t packet_len, BOOL match);

/*
 * Test data.
 */
static struct packet pkt_echo_request =
{
    echo_request,
    sizeof(echo_request),
    "ipv4_icmp_echo_req"
};
static struct packet pkt_http_request =
{
    http_request,
    sizeof(http_request),
    "ipv4_tcp_http_req"
};
static struct packet pkt_dns_request =
{
    dns_request,
    sizeof(dns_request),
    "ipv4_udp_dns_req"
};
static struct packet pkt_ipv6_tcp_syn =
{
    ipv6_tcp_syn,
    sizeof(ipv6_tcp_syn),
    "ipv6_tcp_syn"
};
static struct packet pkt_ipv6_echo_reply =
{
    ipv6_echo_reply,
    sizeof(ipv6_echo_reply),
    "ipv6_icmpv6_echo_rep"
};
static struct packet pkt_ipv6_exthdrs_udp =
{
    ipv6_exthdrs_udp,
    sizeof(ipv6_exthdrs_udp),
    "ipv6_exthdrs_udp"
};
static struct test tests[] =
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
    {"tcp",                                    &pkt_http_request, TRUE},
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
    {"udp",                                    &pkt_dns_request, TRUE},
    {"udp && udp.SrcPort > 1 && ipv6",         &pkt_dns_request, FALSE},
    {"udp.DstPort == 53",                      &pkt_dns_request, TRUE},
    {"udp.DstPort > 100",                      &pkt_dns_request, FALSE},
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
    {"udp.PayloadLength == 29",                &pkt_dns_request, TRUE},
    {"udp.Payload16[-1] == 0x0001 && udp.Payload16[-2] == 0x0001",
                                               &pkt_dns_request, TRUE},
    {"packet16[-1] == 0x0001 && packet16[-2] == 0x0001",
                                               &pkt_dns_request, TRUE},
    {"ipv6",                                   &pkt_ipv6_tcp_syn, TRUE},
    {"ip",                                     &pkt_ipv6_tcp_syn, FALSE},
    {"tcp.Syn",                                &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.Syn == 1 && tcp.Ack == 0",           &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.Rst or tcp.Fin",                     &pkt_ipv6_tcp_syn, FALSE},
    {"(tcp.Syn? !tcp.Rst && !tcp.Fin: true)",  &pkt_ipv6_tcp_syn, TRUE},
    {"(tcp.Rst? !tcp.Syn: (tcp.Fin? !tcp.Syn: tcp.Syn))",
                                               &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.PayloadLength == 0",                 &pkt_ipv6_tcp_syn, TRUE},
    {"ipv6.SrcAddr == 1234:5678:1::aabb:ccdd", &pkt_ipv6_tcp_syn, TRUE},
    {"ipv6.SrcAddr == aabb:5678:1::1234:ccdd", &pkt_ipv6_tcp_syn, FALSE},
    {"tcp.SrcPort == 50046",                   &pkt_ipv6_tcp_syn, TRUE},
    {"tcp.SrcPort == 0x0000C37E",              &pkt_ipv6_tcp_syn, TRUE},
    {"icmpv6",                                 &pkt_ipv6_echo_reply, TRUE},
    {"icmp",                                   &pkt_ipv6_echo_reply, FALSE},
    {"icmp or icmpv6",                         &pkt_ipv6_echo_reply, TRUE},
    {"not icmp",                               &pkt_ipv6_echo_reply, TRUE},
    {"icmpv6.Type == 129",                     &pkt_ipv6_echo_reply, TRUE},
    {"icmpv6.Code == 0",                       &pkt_ipv6_echo_reply, TRUE},
    {"icmpv6.Body == 0x10720003",              &pkt_ipv6_echo_reply, TRUE},
    {"ipv6.DstAddr >= 1000",                   &pkt_ipv6_echo_reply, FALSE},
    {"ipv6.DstAddr <= 1",                      &pkt_ipv6_echo_reply, TRUE},
    {"true",                                   &pkt_ipv6_exthdrs_udp, TRUE},
    {"false",                                  &pkt_ipv6_exthdrs_udp, FALSE},
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
    {"udp.SrcPort == 4660 and udp.DstPort == 43690",
                                               &pkt_ipv6_exthdrs_udp, TRUE},
    {"udp.SrcPort == 4660 and udp.DstPort == 12345",
                                               &pkt_ipv6_exthdrs_udp, FALSE},
    {"(outbound and tcp? tcp.DstPort == 0xABAB: false) or "
     "(outbound and udp? udp.DstPort == 0xAAAA: false) or "
     "(inbound and tcp? tcp.SrcPort == 0xABAB: false) or "
     "(inbound and udp? udp.SrcPort == 0xAAAA: false)",
                                               &pkt_ipv6_exthdrs_udp, TRUE},
};

/*
 * Main.
 */
int main(void)
{
    HANDLE upper_handle, lower_handle;
    HANDLE console;
    size_t i;

    // Open handles to:
    // (1) stop normal traffic from interacting with the tests; and
    // (2) stop test packets escaping to the Internet or TCP/IP stack.
    upper_handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, -510,
        WINDIVERT_FLAG_DROP);
    lower_handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 510,
        WINDIVERT_FLAG_DROP);
    if (upper_handle == INVALID_HANDLE_VALUE ||
        lower_handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: failed to open WinDivert handle (err = %d)",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    console = GetStdHandle(STD_OUTPUT_HANDLE);

    // Wait for existing packets to flush:
    Sleep(100);

    // Run tests:
    size_t num_tests = sizeof(tests) / sizeof(struct test), passed_tests = 0;
    for (i = 0; i < num_tests; i++)
    {
        char *filter = tests[i].filter;
        char *packet = tests[i].packet->packet;
        size_t packet_len = tests[i].packet->packet_len;
        char *name = tests[i].packet->name;
        BOOL match = tests[i].match;

        // Ensure the correct checksum:
        WinDivertHelperCalcChecksums(packet, packet_len, NULL, 0);

        // Run the test:
        BOOL res = run_test(upper_handle, filter, packet, packet_len, match);

        printf("%.3u ", i);
        if (res)
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

    WinDivertClose(upper_handle);
    WinDivertClose(lower_handle);

    printf("\npassed = %.2f%%\n",
        ((double)passed_tests / (double)num_tests) * 100.0);

    return 0;
}

/*
 * Run a test case.
 */
static BOOL run_test(HANDLE inject_handle, const char *filter,
    const char *packet, const size_t packet_len, BOOL match)
{
    char buf[MAX_PACKET];
    UINT buf_len, i;
    DWORD iolen;
    WINDIVERT_ADDRESS addr;
    OVERLAPPED overlapped;
    const char *err_str;
    UINT err_pos;
    PWINDIVERT_IPHDR iphdr = NULL;
    HANDLE handle = INVALID_HANDLE_VALUE, handle0 = INVALID_HANDLE_VALUE,
        event = NULL;

    // (0) Verify the test data:
    if (!WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK,
            NULL, 0, &err_str, &err_pos))
    {
        fprintf(stderr, "error: filter string \"%s\" is invalid with error "
            "\"%s\" (position=%u)\n", filter, err_str, err_pos);
        goto failed;
    }
    WinDivertHelperParsePacket((PVOID)packet, packet_len, &iphdr, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL);
    memset(&addr, 0, sizeof(addr));
    addr.Outbound = TRUE;
    addr.Layer    = WINDIVERT_LAYER_NETWORK;
    addr.IPv6     = (iphdr == NULL);
    addr.Event    = WINDIVERT_EVENT_NETWORK_PACKET;
    if (WinDivertHelperEvalFilter(filter, (PVOID)packet, packet_len, &addr)
            != match)
    {
        fprintf(stderr, "error: filter \"%s\" does not match the given "
            "packet\n", filter);
        goto failed;
    }

    // (1) Open a WinDivert handle to the given filter:
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: failed to open WinDivert handle for filter "
            "\"%s\" (err = %d)\n", filter, GetLastError());
        goto failed;
    }

    if (!match)
    {
        // Catch non-matching packets:
        handle0 = handle;
        handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 33, 0);
        if (handle == INVALID_HANDLE_VALUE)
        {
            fprintf(stderr, "error: failed to open WinDivert handle "
                "(err = %d)\n", GetLastError());
            goto failed;
        }
    }

    // (2) Inject the packet:
    if (!WinDivertSend(inject_handle, (PVOID)packet, packet_len, &addr, NULL))
    {
        fprintf(stderr, "error: failed to inject test packet (err = %d)\n",
            GetLastError());
        goto failed;
    }

    // (3) Wait for the packet to arrive.
    // NOTE: This may fail, so set a generous time-out of 250ms.
    memset(&overlapped, 0, sizeof(overlapped));
    event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (event == NULL)
    {
        fprintf(stderr, "error: failed to create event (err = %d)\n",
            GetLastError());
        goto failed;
    }
    overlapped.hEvent = event;
    if (!WinDivertRecvEx(handle, buf, sizeof(buf), &buf_len, 0, &addr, NULL,
            &overlapped))
    {
        if (GetLastError() != ERROR_IO_PENDING)
        {
read_failed:
            fprintf(stderr, "error: failed to read packet from WinDivert "
                "handle (err = %d)\n", GetLastError());
            goto failed;
        }

        switch (WaitForSingleObject(event, 250))
        {
            case WAIT_OBJECT_0:
                break;
            case WAIT_TIMEOUT:
                fprintf(stderr, "error: failed to read packet from WinDivert "
                    "handle (timeout)\n", GetLastError());
                goto failed;
            default:
                goto read_failed;
        }

        if (!GetOverlappedResult(handle, &overlapped, &iolen, TRUE))
        {
            fprintf(stderr, "error: failed to get the overlapped result from "
                "WinDivert handle (err = %d)\n", GetLastError());
            goto failed;
        }
        buf_len = (UINT)iolen;
    }
    if (addr.Outbound)
    {
        WinDivertHelperCalcChecksums(buf, buf_len, NULL, 0);
    }

    // (4) Verify that the packet is the same.
    if (buf_len != packet_len)
    {
        fprintf(stderr, "error: packet length mis-match, expected (%u), got "
            "(%u)\n", packet_len, buf_len);
        goto failed;
    }
    for (i = 0; i < packet_len; i++)
    {
        if (packet[i] != buf[i])
        {
            fprintf(stderr, "error: packet data mis-match, expected byte #%u "
                "to be (0x%.2X), got (0x%.2X)\n", i, (unsigned char)packet[i],
                (unsigned char)buf[i]);
            for (i = 0; i < packet_len; i++)
            {
                printf("%c", (packet[i] == buf[i]? '.': 'X'));
            }
            putchar('\n');
            goto failed;
        }
    }

    // (5) Clean-up:
    if (!WinDivertClose(handle))
    {
        handle = INVALID_HANDLE_VALUE;
        fprintf(stderr, "error: failed to close WinDivert handle (err = %d)\n",
            GetLastError());
        goto failed;
    }
    if (handle0 != INVALID_HANDLE_VALUE)
    {
        if (!WinDivertClose(handle0))
        {
            handle0 = INVALID_HANDLE_VALUE;
            fprintf(stderr, "error: failed to close WinDivert handle "
                "(err = %d)\n", GetLastError());
            goto failed;
        }
    }
    CloseHandle(event);

    return TRUE;

failed:
    if (handle0 != INVALID_HANDLE_VALUE)
    {
        WinDivertClose(handle0);
    }
    if (handle != INVALID_HANDLE_VALUE)
    {
        WinDivertClose(handle);
    }
    if (event != NULL)
    {
        CloseHandle(event);
    }
    return FALSE;
}

