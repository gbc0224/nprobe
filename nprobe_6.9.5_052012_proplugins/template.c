/*
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6
 *
 *       Copyright (C) 2002-11 Luca Deri <deri@ntop.org>
 *
 *                     http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "nprobe.h"

/* ********* NetFlow v9/IPFIX ***************************** */

/*
  Cisco Systems NetFlow Services Export Version 9

  http://www.faqs.org/rfcs/rfc3954.html

  IPFIX - Information Model for IP Flow Information Export
  http://www.faqs.org/rfcs/rfc5102.html

  See http://www.plixer.com/blog/tag/in_bytes/ for IN/OUT directions
*/

#define PROTO_NAME_LEN    16
#define CUSTOM_FIELD_LEN  16

V9V10TemplateElementId ver9_templates[] = {
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   1,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "IN_BYTES", "octetDeltaCount", "Incoming flow bytes (src->core.tuple.dst)" },
  { 0, BOTH_IPV4_IPV6, OPTION_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, 1,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SYSTEM_ID", "", "" }, /* Hack for options template */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   2,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "IN_PKTS", "packetDeltaCount", "Incoming flow packets (src->core.tuple.dst)" },
  { 0, BOTH_IPV4_IPV6, OPTION_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, 2,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "INTERFACE_ID", "", "" }, /* Hack for options template */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   3,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "FLOWS", "<reserved>", "Number of flows" },
  { 0, BOTH_IPV4_IPV6, OPTION_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, 3,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "LINE_CARD", "", "" }, /* Hack for options template */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   4,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "PROTOCOL", "protocolIdentifier", "IP protocol byte" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   0xA0+4, STATIC_FIELD_LEN, CUSTOM_FIELD_LEN, numeric_format, dump_as_ip_proto,  "PROTOCOL_MAP", "", "IP protocol name" },
  { 0, BOTH_IPV4_IPV6, OPTION_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, 4,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "NETFLOW_CACHE", "", "" }, /* Hack for options template */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   5,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "SRC_TOS", "ipClassOfService", "Type of service byte" },
  { 0, BOTH_IPV4_IPV6, OPTION_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, 5,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "TEMPLATE_ID", "", "" }, /* Hack for options template */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   6,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "TCP_FLAGS", "tcpControlBits", "Cumulative of all flow TCP flags" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   7,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "L4_SRC_PORT", "sourceTransportPort", "IPv4 source port" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   0xA0+7, STATIC_FIELD_LEN, CUSTOM_FIELD_LEN, numeric_format, dump_as_ip_port,  "L4_SRC_PORT_MAP", "", "IPv4 source port symbolic name" },
  { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   8,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "IPV4_SRC_ADDR", "sourceIPv4Address", "IPv4 source address" },
  { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   9,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_ipv6_address,  "IPV4_SRC_MASK", "sourceIPv4PrefixLength", "IPv4 source subnet mask (/<bits>)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   10,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "INPUT_SNMP", "ingressInterface", "Input interface SNMP idx" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   11,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "L4_DST_PORT", "destinationTransportPort", "IPv4 destination port" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   0xA0+11, STATIC_FIELD_LEN, CUSTOM_FIELD_LEN, numeric_format, dump_as_ip_port,  "L4_DST_PORT_MAP", "", "IPv4 destination port symbolic name" },
  { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   12,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "IPV4_DST_ADDR", "destinationIPv4Address", "IPv4 destination address" },
  { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   13,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IPV4_DST_MASK", "destinationIPv4PrefixLength", "IPv4 dest subnet mask (/<bits>)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   14,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "OUTPUT_SNMP", "egressInterface", "Output interface SNMP idx" },
  { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   15,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "IPV4_NEXT_HOP", "ipNextHopIPv4Address", "IPv4 next hop address" },

  /* In earlier versions AS were 16 bit in 'modern' NetFlow v9 and later, they are 32 bit */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   16,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SRC_AS", "bgpSourceAsNumber", "Source BGP AS" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   17,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "DST_AS", "bgpDestinationAsNumber", "Destination BGP AS" },
  /*
    { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   18,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "BGP_IPV4_NEXT_HOP", "bgpNexthopIPv4Address", "" },
    { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   19,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "MUL_DST_PKTS", "postMCastPacketDeltaCount", "" },
    { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   20,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "MUL_DST_BYTES", "postMCastOctetDeltaCount", "" },
  */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   21,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "LAST_SWITCHED", "flowEndSysUpTime", "SysUptime (msec) of the last flow pkt" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   22,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "FIRST_SWITCHED", "flowStartSysUpTime", "SysUptime (msec) of the first flow pkt" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   23,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "OUT_BYTES", "postOctetDeltaCount", "Outgoing flow bytes (dst->src)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   24,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "OUT_PKTS", "postPacketDeltaCount", "Outgoing flow packets (dst->src)" },
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   25,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "minimumIpTotalLength", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   26,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "maximumIpTotalLength", "" }, */
  { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   27,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_ipv6_address,  "IPV6_SRC_ADDR", "sourceIPv6Address", "IPv6 source address" },
  { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   28,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_ipv6_address,  "IPV6_DST_ADDR", "destinationIPv6Address", "IPv6 destination address" },
  { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   29,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IPV6_SRC_MASK", "sourceIPv6PrefixLength", "IPv6 source mask" },
  { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   30,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IPV6_DST_MASK", "destinationIPv6PrefixLength", "IPv6 destination mask" },
  /* { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   31,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "IPV6_FLOW_LABEL", "flowLabelIPv6", "" }, */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   32,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "ICMP_TYPE", "icmpTypeCodeIPv4", "ICMP Type * 256 + ICMP code" },
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   33,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "MUL_IGMP_TYPE", "igmpType", "" }, */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   34,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SAMPLING_INTERVAL", "<reserved>", "Sampling rate" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   35,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "SAMPLING_ALGORITHM", "<reserved>", "Sampling type (deterministic/random)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   36,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "FLOW_ACTIVE_TIMEOUT", "flowActiveTimeout", "Activity timeout of flow cache entries" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   37,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "FLOW_INACTIVE_TIMEOUT", "flowIdleTimeout", "Inactivity timeout of flow cache entries" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   38,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "ENGINE_TYPE", "<reserved>", "Flow switching engine" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   39,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "ENGINE_ID", "<reserved>", "Id of the flow switching engine" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   40,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "TOTAL_BYTES_EXP", "exportedOctetTotalCount", "Total bytes exported" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   41,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "TOTAL_PKTS_EXP", "exportedMessageTotalCount", "Total flow packets exported" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   42,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "TOTAL_FLOWS_EXP", "exportedFlowRecordTotalCount", "Total number of exported flows" },
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   43,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "<reserved>", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   44,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "sourceIPv4Prefix", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   45,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "destinationIPv4Prefix", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   46,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "mplsTopLabelType", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   47,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "mplsTopLabelIPv4Address", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   48,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "<reserved>", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   49,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "<reserved>", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   50,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "<reserved>", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   51,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "<reserved>", "" }, */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   52,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "MIN_TTL", "minimumTTL", "Min flow TTL" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   53,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "MAX_TTL", "maximumTTL", "Max flow TTL" },
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   54,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "fragmentIdentification", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   55,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "postIpClassOfService", "" }, */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   56,  STATIC_FIELD_LEN, 6, hex_format, dump_as_mac_address,  "IN_SRC_MAC", "sourceMacAddress", "Source MAC Address" }, 
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   57,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "postDestinationMacAddress", "" }, */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   58,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "SRC_VLAN", "vlanId", "Source VLAN" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   59,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "DST_VLAN", "postVlanId", "Destination VLAN" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   60,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IP_PROTOCOL_VERSION", "ipVersion", "[4=IPv4][6=IPv6]" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   61,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "DIRECTION", "flowDirection", "It indicates where a sample has been taken (always 0)" },
  { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   62,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_ipv6_address,  "IPV6_NEXT_HOP", "ipNextHopIPv6Address", "IPv6 next hop address" },
  /*
    { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   63,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_ipv6_address,  "BPG_IPV6_NEXT_HOP", "bgpNexthopIPv6Address", "" },
    { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   64,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_ipv6_address,  "IPV6_OPTION_HEADERS", "ipv6ExtensionHeaders", "" },
  */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   65,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "<reserved>", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   66,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "<reserved>", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   67,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "<reserved>", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   68,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "<reserved>", "" }, */
  /* { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   69,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "<reserved>", "" }, */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   70,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_1", "mplsTopLabelStackSection", "MPLS label at position 1" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   71,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_2", "mplsLabelStackSection2", "MPLS label at position 2" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   72,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_3", "mplsLabelStackSection3", "MPLS label at position 3" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   73,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_4", "mplsLabelStackSection4", "MPLS label at position 4" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   74,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_5", "mplsLabelStackSection5", "MPLS label at position 5" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   75,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_6", "mplsLabelStackSection6", "MPLS label at position 6" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   76,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_7", "mplsLabelStackSection7", "MPLS label at position 7" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   77,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_8", "mplsLabelStackSection8", "MPLS label at position 8" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   78,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_9", "mplsLabelStackSection9", "MPLS label at position 9" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   79,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_10", "mplsLabelStackSection10", "MPLS label at position 10" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   80,  STATIC_FIELD_LEN, 6, hex_format, dump_as_mac_address,  "OUT_DST_MAC", "destinationMacAddress", "Destination MAC Address" },

  /* Fields not yet fully supported (collection only) */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  102,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "PACKET_SECTION_OFFSET", "<reserved>", "Packet section offset" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  103,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "SAMPLED_PACKET_SIZE", "<reserved>", "Sampled packet size" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  104,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "SAMPLED_PACKET_ID",   "<reserved>", "Sampled packet id" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  130,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "EXPORTER_IPV4_ADDRESS",   "exporterIPv4Address", "Exporter IPv4 Address" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  131,  STATIC_FIELD_LEN, 16, numeric_format, dump_as_uint, "EXPORTER_IPV6_ADDRESS",   "exporterIPv6Address", "Exporter IPv6 Address" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  148, STATIC_FIELD_LEN,  8, numeric_format, dump_as_uint, "FLOW_ID", "flowId", "Serial Flow Identifier" },
  
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  150, STATIC_FIELD_LEN,  4, numeric_format, dump_as_uint, "FLOW_START_SEC", "flowStartSeconds", "Seconds (epoch) of the first flow packet" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  151, STATIC_FIELD_LEN,  4, numeric_format, dump_as_uint, "FLOW_END_SEC",   "flowEndSeconds",   "Seconds (epoch) of the last flow packet" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  152, STATIC_FIELD_LEN,  8, numeric_format, dump_as_uint, "FLOW_START_MILLISECONDS", "flowStartMilliseconds", "Msec (epoch) of the first flow packet" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  153, STATIC_FIELD_LEN,  8, numeric_format, dump_as_uint, "FLOW_END_MILLISECONDS",   "flowEndMilliseconds",   "Msec (epoch) of the last flow packet" },

  /* Fields not yet fully supported (collection only) */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  277, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "OBSERVATION_POINT_TYPE", "<reserved>",  "Observation point type" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  300, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "OBSERVATION_POINT_ID", "<reserved>",  "Observation point id" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  302, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SELECTOR_ID", "<reserved>",  "Selector id" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  304, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SAMPLING_ALGORITHM", "<reserved>",  "Sampling algorithm" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  309, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SAMPLING_SIZE", "<reserved>",  "Number of packets to sample" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  310, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SAMPLING_POPULATION", "<reserved>", "Sampling population" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  312, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "FRAME_LENGTH", "<reserved>", "Original L2 frame length" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  318, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "PACKETS_OBSERVED", "<reserved>", "Tot number of packets seen" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  319, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "PACKETS_SELECTED", "<reserved>", "Number of pkts selected for sampling" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  335, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SELECTOR_NAME", "<reserved>", "Sampler name" },

  /*
    ntop Extensions

    IMPORTANT
    if you change/add constants here/below make sure
    you change them into ntop too.
  */

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+80,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "FRAGMENTS", "", "Number of fragmented flow packets" },
  /* 81 is available */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+82,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "CLIENT_NW_DELAY_SEC", "",  "Network latency client <-> nprobe (sec)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+83,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "CLIENT_NW_DELAY_USEC", "", "Network latency client <-> nprobe (usec)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+84,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SERVER_NW_DELAY_SEC", "",  "Network latency nprobe <-> server (sec)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+85,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SERVER_NW_DELAY_USEC", "", "Network latency nprobe <-> server (usec)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+86,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "APPL_LATENCY_SEC", "", "Application latency (sec)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+87,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "APPL_LATENCY_USEC", "", "Application latency (usec)" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+88,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_UP_TO_128_BYTES", "", "# packets whose size <= 128" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+89,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_128_TO_256_BYTES", "", "# packets whose size > 128 and <= 256" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+90,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_256_TO_512_BYTES", "", "# packets whose size > 256 and < 512" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+91,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_512_TO_1024_BYTES", "", "# packets whose size > 512 and < 1024" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+92,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_1024_TO_1514_BYTES", "", "# packets whose size > 1024 and <= 1514" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+93,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_OVER_1514_BYTES", "", "# packets whose size > 1514" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+94,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "PACKET_VARIANCE", "", "sum(square(packet size / delta(time))) / # packets" },

  /* 99+100 are available */

#ifdef HAVE_GEOIP
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+101, STATIC_FIELD_LEN, 2,  ascii_format, dump_as_ascii, "SRC_IP_COUNTRY", "", "Country where the src IP is located" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+102, STATIC_FIELD_LEN, 16, ascii_format, dump_as_ascii, "SRC_IP_CITY", "", "City where the src IP is located" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+103, STATIC_FIELD_LEN, 2,  ascii_format, dump_as_ascii, "DST_IP_COUNTRY", "", "Country where the dst IP is located" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+104, STATIC_FIELD_LEN, 16, ascii_format, dump_as_ascii, "DST_IP_CITY", "", "City where the dst IP is located" },
#endif
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+105, STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint, "FLOW_PROTO_PORT", "", "L7 port that identifies the flow protocol or 0 if unknown" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+106, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "TUNNEL_ID", "", "Tunnel identifier (e.g. GTP tunnel Id) or 0 if unknown" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+107, STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint, "LONGEST_FLOW_PKT", "", "Longest packet (bytes) of the flow" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+108, STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint, "SHORTEST_FLOW_PKT", "", "Shortest packet (bytes) of the flow" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+109, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "RETRANSMITTED_IN_PKTS", "", "Number of retransmitted TCP flow packets (src->core.tuple.dst)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+110, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "RETRANSMITTED_OUT_PKTS", "", "Number of retransmitted TCP flow packets (dst->src)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+111, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "OOORDER_IN_PKTS", "", "Number of out of order TCP flow packets (dst->src)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+112, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "OOORDER_OUT_PKTS", "", "Number of out of order TCP flow packets (dst->src)" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+113,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "UNTUNNELED_PROTOCOL", "", "Untunneled IP protocol byte" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+114,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "UNTUNNELED_IPV4_SRC_ADDR", "", "Untunneled IPv4 source address" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+115,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "UNTUNNELED_L4_SRC_PORT", "", "Untunneled IPv4 source port" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+116,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "UNTUNNELED_IPV4_DST_ADDR", "", "Untunneled IPv4 destination address" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+117,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "UNTUNNELED_L4_DST_PORT", "", "Untunneled IPv4 destination port" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+118,  STATIC_FIELD_LEN, 2,  numeric_format, dump_as_uint,  "L7_PROTO", "", "Layer 7 protocol (numeric)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+119,  VARIABLE_FIELD_LEN, PROTO_NAME_LEN, ascii_format,   dump_as_ascii, "L7_PROTO_NAME", "", "Layer 7 protocol name" },

  /* That's all folks */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, 0, STATIC_FIELD_LEN, 0, 0, 0, NULL, NULL, NULL }
};

/* ******************************************** */

void printTemplateInfo(V9V10TemplateElementId *templates,
		       u_char show_private_elements) {
  int j = 0;

  while(templates[j].netflowElementName != NULL) {
    if(!templates[j].isOptionTemplate) {
      if(((!show_private_elements)
	  && (templates[j].templateElementLen > 0))
	 || (show_private_elements && (templates[j].templateElementId >= 0xFF))) {

	if(templates[j].templateElementEnterpriseId == NTOP_ENTERPRISE_ID) {
	  printf("[NFv9 %3d][IPFIX %5d.%d] %%%-26s\t%s\n",
		 templates[j].templateElementId,
		 templates[j].templateElementEnterpriseId, templates[j].templateElementId-NTOP_BASE_ID,
		 templates[j].netflowElementName,
		 templates[j].templateElementDescr);
	} else {
	  char ipfixName[64];

	  switch(templates[j].ipfixElementName[0]) {
	  case '\0':
	  case '<':
	    ipfixName[0] = '\0';
	    break;
	  default:
	    snprintf(ipfixName, sizeof(ipfixName), "%%%s", templates[j].ipfixElementName);
	  }

	  printf("[%3d] %%%-26s %-26s\t%s\n",
		 templates[j].templateElementId,
		 templates[j].netflowElementName,
		 ipfixName, templates[j].templateElementDescr);
	}
      }
    }

    j++;
  }
}

/* ******************************************** */

char* getStandardFieldId(u_int id) {
  int i = 0;

  while(ver9_templates[i].netflowElementName != NULL) {
    if(ver9_templates[i].templateElementId == id)
      return((char*)ver9_templates[i].netflowElementName);
    else
      i++;
  }
  
  return("");
}

/* ******************************************** */

/* 
   This function changes as necessary ver9_templates[]
   because some flow elememts have different length in
   IPFIX than on v9
*/
void fixTemplatesToIPFIX(void) {
  int i = 0;
  
  if(readOnlyGlobals.netFlowVersion != 10) return;
     
  while(ver9_templates[i].netflowElementName != NULL) {
    switch(ver9_templates[i].templateElementId) {
    case 10: /* INPUT_SNMP */
    case 14: /* OUTPUT_SNMP */
      ver9_templates[i].templateElementLen = 4;
      break;
    }

    i++;
  }
}

/* ******************************************** */

void sanitizeV4Template(char *str) {
  int i = 0;

  while(str[i] != '\0') {
    if(str[i+1] == '\0') break;

    if((str[i] == 'V') && (str[i+1] == '6')) {
      str[i+1] = '4';
      i++;
    }
    
    i++;
  }
}

/* ******************************************** */

void v4toV6Template(char *str) {
  int i = 0;

  while(str[i] != '\0') {
    if(str[i+1] == '\0') break;

    if((str[i] == 'V') && (str[i+1] == '4')) {
      str[i+1] = '6';
      i++;
    }
    
    i++;
  }
}

/* ******************************************** */

static void copyIpV6(struct in6_addr ipv6, char *outBuffer,
		     uint *outBufferBegin, uint *outBufferMax) {
  copyLen((u_char*)&ipv6, sizeof(ipv6), outBuffer,
	  outBufferBegin, outBufferMax);
}

/* ******************************************** */

static void copyMac(u_char *macAddress, char *outBuffer,
		    uint *outBufferBegin, uint *outBufferMax) {
  copyLen(macAddress, 6 /* lenght of mac address */,
	  outBuffer, outBufferBegin, outBufferMax);
}

/* ******************************************** */

static void copyMplsLabel(struct mpls_labels *mplsInfo, int labelId,
			  char *outBuffer, uint *outBufferBegin,
			  uint *outBufferMax) {
  if(mplsInfo == NULL) {
    int i;

    for(i=0; (i < 3) && (*outBufferBegin < *outBufferMax); i++) {
      outBuffer[*outBufferBegin] = 0;
      (*outBufferBegin)++;
    }
  } else {
    if(((*outBufferBegin)+MPLS_LABEL_LEN) < (*outBufferMax)) {
      memcpy(outBuffer, mplsInfo->mplsLabels[labelId-1], MPLS_LABEL_LEN);
      (*outBufferBegin) += MPLS_LABEL_LEN;
    }
  }
}

/* ******************************************** */

static void handleTemplate(V9V10TemplateElementId *theTemplateElement,
			   u_int8_t ipv4_template,
			   char *outBuffer, uint *outBufferBegin,
			   uint *outBufferMax,
			   char buildTemplate, int *numElements,
			   FlowHashBucket *theFlow, FlowDirection direction,
			   int addTypeLen, int optionTemplate) {
#ifdef HAVE_GEOIP
  GeoIPRecord *geo;
#endif
  
  u_char null_data[128] = { 0 };
  u_char minus_one_data[128] = { -1 };
  char proto_name[PROTO_NAME_LEN+1] = { 0 };
  u_int16_t t16, len;

  if(buildTemplate || addTypeLen) {
    /* Type */
    t16 = theTemplateElement->templateElementId;

    if((readOnlyGlobals.netFlowVersion == 10)
       && (theTemplateElement->templateElementEnterpriseId != STANDARD_ENTERPRISE_ID)) {
      if(theTemplateElement->templateElementEnterpriseId == NTOP_ENTERPRISE_ID)
	t16 -= NTOP_BASE_ID; /* Just to make sure we don't mess-up the template */

      t16 = t16 | 0x8000; /* Enable the PEN bit */
    }

    copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);

    /* Len */
    if((readOnlyGlobals.netFlowVersion == 10)
       && (theTemplateElement->variableFieldLength == VARIABLE_FIELD_LEN)) {
      t16 = 65535; /* Reserved len as specified in rfc5101 */
    } else
      t16 = theTemplateElement->templateElementLen;

    copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);

    if((readOnlyGlobals.netFlowVersion == 10)
       && (theTemplateElement->templateElementEnterpriseId != STANDARD_ENTERPRISE_ID)) {
      /* PEN */
      copyInt32(theTemplateElement->templateElementEnterpriseId,
		outBuffer, outBufferBegin, outBufferMax);
    }
  }

  if(!buildTemplate) {
    if(theTemplateElement->templateElementLen == 0)
      ; /* Nothing to do: all fields have zero length */
    else {
      u_char custom_field[CUSTOM_FIELD_LEN];

#ifdef DEBUG
	traceEvent(TRACE_INFO, "[%d][%s][%d]",
		   theTemplateElement->templateElementId,
		   theTemplateElement->netflowElementName,
		   theTemplateElement->templateElementLen);
#endif

      if(theTemplateElement->isOptionTemplate) {
	copyLen(null_data, theTemplateElement->templateElementLen,
		outBuffer, outBufferBegin, outBufferMax);
      } else {
	/*
	 * IMPORTANT
	 *
	 * Any change below need to be ported also in printRecordWithTemplate()
	 *
	 */
	switch(theTemplateElement->templateElementId) {
	case 1:
	  copyInt32(direction == dst2src_direction ? theFlow->core.tuple.flowCounters.bytesRcvd : theFlow->core.tuple.flowCounters.bytesSent,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 2:
	  copyInt32(direction == dst2src_direction ? theFlow->core.tuple.flowCounters.pktRcvd : theFlow->core.tuple.flowCounters.pktSent,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 4:
	  copyInt8((u_int8_t)theFlow->core.tuple.proto, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 5:
	  copyInt8(direction == src2dst_direction ? theFlow->ext->src2dstTos : theFlow->ext->dst2srcTos,
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 6:
	  copyInt8(direction == src2dst_direction ? theFlow->ext->protoCounters.tcp.src2dstTcpFlags : theFlow->ext->protoCounters.tcp.dst2srcTcpFlags,
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 7:
	  copyInt16(direction == src2dst_direction ? theFlow->core.tuple.sport : theFlow->core.tuple.dport, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 8:
	  if((theFlow->core.tuple.src.ipVersion == 4) && (theFlow->core.tuple.dst.ipVersion == 4))
	    copyInt32(direction == src2dst_direction ? theFlow->core.tuple.src.ipType.ipv4 : theFlow->core.tuple.dst.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 9: /* IPV4_SRC_MASK */
	  copyInt8((direction == src2dst_direction) ? ip2mask(&theFlow->core.tuple.src, &theFlow->ext->srcInfo) : ip2mask(&theFlow->core.tuple.dst, &theFlow->ext->dstInfo),
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 10: /* INPUT_SNMP */
	  if(readOnlyGlobals.netFlowVersion == 10)
	    copyInt32((direction == src2dst_direction) ? theFlow->ext->if_input : theFlow->ext->if_output, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt16((direction == src2dst_direction) ? theFlow->ext->if_input : theFlow->ext->if_output, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 11:
	  copyInt16(direction == src2dst_direction ? theFlow->core.tuple.dport : theFlow->core.tuple.sport, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 12:
	  if((theFlow->core.tuple.src.ipVersion == 4) && (theFlow->core.tuple.dst.ipVersion == 4))
	    copyInt32(direction == src2dst_direction ? theFlow->core.tuple.dst.ipType.ipv4 : theFlow->core.tuple.src.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 13: /* IPV4_DST_MASK */
	  copyInt8((direction == dst2src_direction) ? ip2mask(&theFlow->core.tuple.src, &theFlow->ext->srcInfo)
		   : ip2mask(&theFlow->core.tuple.dst, &theFlow->ext->dstInfo),
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 14: /* OUTPUT_SNMP */
	  if(readOnlyGlobals.netFlowVersion == 10)
	    copyInt32((direction != src2dst_direction) ? theFlow->ext->if_input : theFlow->ext->if_output, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt16((direction != src2dst_direction) ? theFlow->ext->if_input : theFlow->ext->if_output, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 15: /* IPV4_NEXT_HOP */
	  copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 16:
	  copyInt32(direction == src2dst_direction ? getAS(&theFlow->core.tuple.src, &theFlow->ext->srcInfo) : getAS(&theFlow->core.tuple.dst, &theFlow->ext->dstInfo),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 17:
	  copyInt32(direction == src2dst_direction ? getAS(&theFlow->core.tuple.dst, &theFlow->ext->dstInfo) : getAS(&theFlow->core.tuple.src, &theFlow->ext->srcInfo),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 21:
 	  copyInt32(direction == src2dst_direction ? msTimeDiff(&theFlow->core.tuple.flowTimers.lastSeenSent, &readOnlyGlobals.initialSniffTime)
		    : msTimeDiff(&theFlow->core.tuple.flowTimers.lastSeenRcvd, &readOnlyGlobals.initialSniffTime),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 22:
	  copyInt32(direction == src2dst_direction ? msTimeDiff(&theFlow->core.tuple.flowTimers.firstSeenSent, &readOnlyGlobals.initialSniffTime)
		    : msTimeDiff(&theFlow->core.tuple.flowTimers.firstSeenRcvd, &readOnlyGlobals.initialSniffTime),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 23:
	  copyInt32(direction == dst2src_direction ? theFlow->core.tuple.flowCounters.bytesSent : theFlow->core.tuple.flowCounters.bytesRcvd,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 24:
	  copyInt32(direction == src2dst_direction ? theFlow->core.tuple.flowCounters.pktRcvd : theFlow->core.tuple.flowCounters.pktSent,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 27:
	  if((theFlow->core.tuple.src.ipVersion == 6) && (theFlow->core.tuple.dst.ipVersion == 6))
	    copyIpV6(direction == src2dst_direction ? theFlow->core.tuple.src.ipType.ipv6 : theFlow->core.tuple.dst.ipType.ipv6,
		     outBuffer, outBufferBegin, outBufferMax);
	  else {
	    struct in6_addr _ipv6;

	    memset(&_ipv6, 0, sizeof(struct in6_addr));
	    copyIpV6(_ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;
	case 28:
	  if((theFlow->core.tuple.src.ipVersion == 6) && (theFlow->core.tuple.dst.ipVersion == 6))
	    copyIpV6(direction == src2dst_direction ? theFlow->core.tuple.dst.ipType.ipv6 : theFlow->core.tuple.dst.ipType.ipv6,
		     outBuffer, outBufferBegin, outBufferMax);
	  else {
	    struct in6_addr _ipv6;

	    memset(&_ipv6, 0, sizeof(struct in6_addr));
	    copyIpV6(_ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;
	case 29:
	case 30:
	  copyInt8(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 32:
	  copyInt16(direction == src2dst_direction ? theFlow->ext->protoCounters.icmp.src2dstIcmpType : theFlow->ext->protoCounters.icmp.dst2srcIcmpType,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 34: /* SAMPLING INTERVAL */
	  copyInt32(1 /* 1:1 = no sampling */, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 35: /* SAMPLING ALGORITHM */
	  copyInt8(0x01 /* 1=Deterministic Sampling, 0x02=Random Sampling */,
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 36: /* FLOW ACTIVE TIMEOUT */
	  copyInt16(readOnlyGlobals.lifetimeTimeout, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 37: /* FLOW INACTIVE TIMEOUT */
	  copyInt16(readOnlyGlobals.idleTimeout, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 38:
	  copyInt8((u_int8_t)readOnlyGlobals.engineType, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 39:
	  copyInt8((u_int8_t)readOnlyGlobals.engineId, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 40: /* TOTAL_BYTES_EXP */
	  copyInt32(readWriteGlobals->flowExportStats.totExportedBytes, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 41: /* TOTAL_PKTS_EXP */
	  copyInt32(readWriteGlobals->flowExportStats.totExportedPkts, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 42: /* TOTAL_FLOWS_EXP */
	  copyInt32(readWriteGlobals->flowExportStats.totExportedFlows, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 52: /* MIN_TTL */
	  copyInt8(direction == src2dst_direction ? theFlow->ext->src2dstMinTTL : theFlow->ext->dst2srcMinTTL, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 53: /* MAX_TTL */
	  copyInt8(direction == src2dst_direction ? theFlow->ext->src2dstMaxTTL : theFlow->ext->dst2srcMaxTTL, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 56: /* IN_SRC_MAC */
	  copyMac(direction == src2dst_direction ? theFlow->ext->srcInfo.macAddress : theFlow->ext->dstInfo.macAddress, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 58: /* SRC_VLAN */
	  /* no break */
	case 59: /* DST_VLAN */
	  copyInt16(theFlow->core.tuple.vlanId, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 60: /* IP_PROTOCOL_VERSION */
	  copyInt8((theFlow->core.tuple.src.ipVersion == 4) && (theFlow->core.tuple.dst.ipVersion == 4) ? 4 : 6, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 61: /* Direction (it indicates where a sample has been taken) */
	  copyInt8(0 /* Always use zero */, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 62: /* IPV6_NEXT_HOP */
	case 131: /* EXPORTER_IPV6_ADDRESS */
	  {
	    IpAddress addr;

	    memset(&addr, 0, sizeof(addr));
	    copyIpV6(addr.ipType.ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;
	case 70: /* MPLS: label 1 */
	  copyMplsLabel((theFlow->ext == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 1, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 71: /* MPLS: label 2 */
	  copyMplsLabel((theFlow->ext == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 2, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 72: /* MPLS: label 3 */
	  copyMplsLabel((theFlow->ext == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 3, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 73: /* MPLS: label 4 */
	  copyMplsLabel((theFlow->ext == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 4, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 74: /* MPLS: label 5 */
	  copyMplsLabel((theFlow->ext == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 5, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 75: /* MPLS: label 6 */
	  copyMplsLabel((theFlow->ext == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 6, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 76: /* MPLS: label 7 */
	  copyMplsLabel((theFlow->ext == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 7, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 77: /* MPLS: label 8 */
	  copyMplsLabel((theFlow->ext == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 8, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 78: /* MPLS: label 9 */
	  copyMplsLabel((theFlow->ext == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 9, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 79: /* MPLS: label 10 */
	  copyMplsLabel((theFlow->ext == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 10, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 80: /* OUT_DST_MAC */
	  copyMac(direction == src2dst_direction ? theFlow->ext->dstInfo.macAddress : theFlow->ext->srcInfo.macAddress, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case 130: /* EXPORTER_IPV4_ADDRESS */
	  /* We need htonl() as it is already in nw order */
	  copyInt32(htonl(theFlow->ext->srcInfo.ifHost), outBuffer, outBufferBegin, outBufferMax);
	  break;

	  /* NOTE: as of EXPORTER_IPV6_ADDRESS see above on this file */

	case 148: /* FLOW_ID */
	  copyInt64(theFlow->core.tuple.flow_idx, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case 150:
	  if(readOnlyGlobals.collectorInPort > 0)
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(direction == src2dst_direction ? theFlow->core.tuple.flowTimers.firstSeenSent.tv_sec : theFlow->core.tuple.flowTimers.firstSeenRcvd.tv_sec,
		      outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 151:
	  if(readOnlyGlobals.collectorInPort > 0)
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(direction == src2dst_direction ? theFlow->core.tuple.flowTimers.lastSeenSent.tv_sec : theFlow->core.tuple.flowTimers.lastSeenRcvd.tv_sec,
		      outBuffer, outBufferBegin, outBufferMax);
	  break;

	case 152:
	  copyInt64(direction == src2dst_direction ? to_msec(&theFlow->core.tuple.flowTimers.firstSeenSent) : to_msec(&theFlow->core.tuple.flowTimers.firstSeenRcvd),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 153:
	  copyInt64(direction == src2dst_direction ? to_msec(&theFlow->core.tuple.flowTimers.lastSeenSent) : to_msec(&theFlow->core.tuple.flowTimers.lastSeenRcvd),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	  /* ************************************ */

	  /* nProbe Extensions */
	case NTOP_BASE_ID+80:
	  copyInt32(direction == src2dst_direction ? theFlow->ext->flowCounters.sentFragPkts : theFlow->ext->flowCounters.rcvdFragPkts,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
#if 0
	case NTOP_BASE_ID+81:
	  break;
#endif
	case NTOP_BASE_ID+82:
	  copyInt32(nwLatencyComputed(theFlow->ext) ? theFlow->ext->extensions->clientNwDelay.tv_sec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+83:
	  copyInt32(nwLatencyComputed(theFlow->ext) ? theFlow->ext->extensions->clientNwDelay.tv_usec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+84:
	  copyInt32(nwLatencyComputed(theFlow->ext) ? theFlow->ext->extensions->serverNwDelay.tv_sec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+85:
	  copyInt32(nwLatencyComputed(theFlow->ext) ? theFlow->ext->extensions->serverNwDelay.tv_usec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+86:
	  copyInt32(applLatencyComputed(theFlow->ext) ? (direction == src2dst_direction ? theFlow->ext->extensions->src2dstApplLatency.tv_sec
						    : theFlow->ext->extensions->dst2srcApplLatency.tv_sec) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+87:
	  copyInt32(applLatencyComputed(theFlow->ext) ?
		    (direction == src2dst_direction ? theFlow->ext->extensions->src2dstApplLatency.tv_usec :
		     theFlow->ext->extensions->dst2srcApplLatency.tv_usec) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+88:
	  copyInt32(theFlow->ext ?
	    (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_up_to_128_bytes 
	     : theFlow->ext->extensions->etherstats.dst2src.num_pkts_up_to_128_bytes) : 0,
	    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+89:
	  copyInt32(theFlow->ext ?
	    (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_128_to_256_bytes 
	     : theFlow->ext->extensions->etherstats.dst2src.num_pkts_128_to_256_bytes) : 0,
	    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+90:
	  copyInt32(theFlow->ext ?
	    (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_256_to_512_bytes 
	     : theFlow->ext->extensions->etherstats.dst2src.num_pkts_256_to_512_bytes) : 0,
	    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+91:
	  copyInt32(theFlow->ext ?
	    (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_512_to_1024_bytes 
	     : theFlow->ext->extensions->etherstats.dst2src.num_pkts_512_to_1024_bytes) : 0,
	    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+92:
	  copyInt32(theFlow->ext ?
	    (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_1024_to_1514_bytes 
	     : theFlow->ext->extensions->etherstats.dst2src.num_pkts_1024_to_1514_bytes) : 0,
	    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+93:
	  copyInt32(theFlow->ext ?
	    (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_over_1514_bytes 
	     : theFlow->ext->extensions->etherstats.dst2src.num_pkts_over_1514_bytes) : 0,
	    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+94:
	  if(((direction == src2dst_direction) ? theFlow->core.tuple.flowCounters.pktSent : theFlow->core.tuple.flowCounters.pktRcvd) == 0)
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(theFlow->ext ?
		      (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.bytes_time_variance/theFlow->core.tuple.flowCounters.pktSent 
		       : theFlow->ext->extensions->etherstats.dst2src.bytes_time_variance/theFlow->core.tuple.flowCounters.pktRcvd) : 0,
		      outBuffer, outBufferBegin, outBufferMax);
	  break;

	  /* ****************** */

	case NTOP_BASE_ID+98:
	  copyInt32(direction == src2dst_direction ? theFlow->ext->protoCounters.icmp.src2dstIcmpFlags 
		    : theFlow->ext->protoCounters.icmp.dst2srcIcmpFlags,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	  
	case NTOP_BASE_ID+101: /* SRC_IP_COUNTRY */
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->ext->srcInfo.geo : theFlow->ext->dstInfo.geo;
#endif

	  //if(geo) traceEvent(TRACE_ERROR, "SRC_IP_COUNTRY -> %s", (geo && geo->country_code) ? geo->country_code : "???");

	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->country_code) ? geo->country_code :
#endif
			    "  "), 2,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+102: /* SRC_IP_CITY */
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->ext->srcInfo.geo : theFlow->ext->dstInfo.geo;
#endif

	  // if(geo) traceEvent(TRACE_ERROR, "-> %s [%s]", geo->region, geo->country_code);

	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->city) ? geo->city :
#endif
			    "                "), 16,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+103: /* DST_IP_COUNTRY */
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->ext->dstInfo.geo : theFlow->ext->srcInfo.geo;
#endif

	  // if(geo) traceEvent(TRACE_ERROR, "DST_IP_COUNTRY -> %s", (geo && geo->country_code) ? geo->country_code : "???");
	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->country_code) ? geo->country_code :
#endif
			    "  "), 2,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+104: /* DST_IP_CITY */
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->ext->dstInfo.geo : theFlow->ext->srcInfo.geo;
#endif
	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->city) ? geo->city :
#endif
			    "                "), 16,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+105: /* FLOW_PROTO_PORT */
	  t16 = getFlowApplProtocol(theFlow);
	  copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+106: /* TUNNEL_ID */
	  copyInt32(theFlow->ext->tunnel_id, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+107: /* LONGEST_FLOW_PKT */
	  copyInt16(theFlow->ext->flowCounters.pktSize.longest, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+108: /* SHORTEST_FLOW_PKT */
	  copyInt16(theFlow->ext->flowCounters.pktSize.shortest, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+109: /* RETRANSMITTED_IN_PKTS */
	  copyInt32((direction == dst2src_direction) ? theFlow->ext->protoCounters.tcp.rcvdRetransmitted : theFlow->ext->protoCounters.tcp.sentRetransmitted,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+110: /* RETRANSMITTED_OUT_PKTS */
	  copyInt32((direction == src2dst_direction) ? theFlow->ext->protoCounters.tcp.rcvdRetransmitted : theFlow->ext->protoCounters.tcp.sentRetransmitted,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+111: /* OOORDER_IN_PKTS */
	  copyInt32((direction == dst2src_direction) ? theFlow->ext->protoCounters.tcp.rcvdOOOrder : theFlow->ext->protoCounters.tcp.sentOOOrder,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+112: /* OOORDER_OUT_PKTS */
	  copyInt32((direction == src2dst_direction) ? theFlow->ext->protoCounters.tcp.rcvdOOOrder : theFlow->ext->protoCounters.tcp.sentOOOrder,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+113: /* UNTUNNELED_PROTOCOL */
	  copyInt8((theFlow->ext == NULL) ? 0 : (u_int8_t)theFlow->ext->extensions->untunneled.proto, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+114: /* UNTUNNELED_IPV4_SRC_ADDR */
	  if(readOnlyGlobals.tunnel_mode && (theFlow->ext != NULL)
	     && (theFlow->ext->extensions->untunneled.src.ipVersion == 4) && (theFlow->ext->extensions->untunneled.dst.ipVersion == 4))
	    copyInt32(direction == src2dst_direction ? theFlow->ext->extensions->untunneled.src.ipType.ipv4 : theFlow->ext->extensions->untunneled.dst.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+115: /* UNTUNNELED_L4_SRC_PORT */
	  if(readOnlyGlobals.tunnel_mode && (theFlow->ext != NULL))
	    copyInt16(direction == src2dst_direction ? theFlow->ext->extensions->untunneled.sport : theFlow->ext->extensions->untunneled.dport, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt16(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+116: /* UNTUNNELED_IPV4_DST_ADDR */
	     if(readOnlyGlobals.tunnel_mode && (theFlow->ext != NULL)
		&& (theFlow->ext->extensions->untunneled.src.ipVersion == 4) && (theFlow->ext->extensions->untunneled.dst.ipVersion == 4))
	       copyInt32(direction == src2dst_direction ? theFlow->ext->extensions->untunneled.dst.ipType.ipv4 : theFlow->ext->extensions->untunneled.src.ipType.ipv4,
			 outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+117: /* UNTUNNELED_L4_DST_PORT */
	  if(readOnlyGlobals.tunnel_mode && theFlow->ext)
	    copyInt16(direction == src2dst_direction ? theFlow->ext->extensions->untunneled.dport : theFlow->ext->extensions->untunneled.sport, 
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt16(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+118: /* L7_PROTO */
	  copyInt16(theFlow->core.l7.proto, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+119: /* L7_PROTO_NAME */	  
	  snprintf(proto_name, sizeof(proto_name)-1, "%s", getProtoName(theFlow->core.l7.proto));

	  if((readOnlyGlobals.netFlowVersion == 10)
	     && (theTemplateElement->variableFieldLength == VARIABLE_FIELD_LEN)) {
	    len = min(strlen(proto_name), theTemplateElement->templateElementLen);

	    if(len < 255)
	      copyInt8(len, outBuffer, outBufferBegin, outBufferMax);
	    else {
	      copyInt8(255, outBuffer, outBufferBegin, outBufferMax);
	      copyInt16(len, outBuffer, outBufferBegin, outBufferMax);
	    }
	  } else
	    len = theTemplateElement->templateElementLen;

	  memcpy(&outBuffer[*outBufferBegin], proto_name, len);

	  if(readOnlyGlobals.enable_debug)
	    traceEvent(TRACE_INFO, "==> L7_PROTO='%s' [len=%d]", proto_name, len);
	  
	  (*outBufferBegin) += len;
	  break;

	  /* Custom fields */
	case 0xA0+4:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s", proto2name(theFlow->core.tuple.proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 0xA0+7:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s",
		   port2name(direction == src2dst_direction ? theFlow->core.tuple.sport : theFlow->core.tuple.dport, theFlow->core.tuple.proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 0xA0+11:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s", 
		   port2name(direction == src2dst_direction ? theFlow->core.tuple.dport : theFlow->core.tuple.sport, theFlow->core.tuple.proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;

	default:
	  if(checkPluginExport(theTemplateElement, direction, theFlow,
			       outBuffer, outBufferBegin, outBufferMax) == -1) {
	    /*
	      This flow is the one we like, however we need
	      to store some values anyway, so we put an empty value
	    */
	    
	    if((readOnlyGlobals.netFlowVersion == 10)
	       && (theTemplateElement->variableFieldLength == VARIABLE_FIELD_LEN)) {
	      u_int len = 0;
	      copyInt8(len, outBuffer, outBufferBegin, outBufferMax);
	    } else {
	      u_char *what;

	      if(strcmp(theTemplateElement->netflowElementName, "RTP_OUT_PAYLOAD_TYPE") == 0)
		what = minus_one_data;
	      else
		what = null_data;

	      copyLen(what, theTemplateElement->templateElementLen,
		      outBuffer, outBufferBegin, outBufferMax);
	    }
	  }
	}
      }
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, "name=%s/Id=%d/len=%d [len=%d][outBufferMax=%d]\n",
	       theTemplateElement->netflowElementName,
	       theTemplateElement->templateElementId,
	       theTemplateElement->templateElementLen,
	       *outBufferBegin, *outBufferMax);
#endif
  }

  (*numElements) = (*numElements)+1;

  return;
}

/* ******************************************** */

void compileTemplate(char *_fmt, V9V10TemplateElementId **templateList, 
		     int templateElements, u_int8_t isOptionTemplate,
		     u_int8_t isIPv6OnlyTemplate) {
  int idx=0, endIdx, i, templateIdx, len = strlen(_fmt);
  char fmt[1024], tmpChar, found;
  u_int8_t ignored;

  /* Change \n and \r (if any) to space */
  for(i=0; _fmt[i] != '\0'; i++) {
    switch(_fmt[i]) {
    case '\r':
    case '\n':
      _fmt[i] = ' ';
      break;
    }
  }

  templateIdx = 0;
  snprintf(fmt, sizeof(fmt), "%s", _fmt);

  while((idx < len) && (fmt[idx] != '\0')) {	/* scan format string characters */
    switch(fmt[idx]) {
    case '%':	        /* special format follows */
      endIdx = ++idx;
      while(fmt[endIdx] != '\0') {
	if((fmt[endIdx] == ' ') || (fmt[endIdx] == '%'))
	  break;
	else
	  endIdx++;
      }

      if((endIdx == (idx+1)) && (fmt[endIdx] == '\0')) return;
      tmpChar = fmt[endIdx]; fmt[endIdx] = '\0';

      ignored = 0;

      if(strstr(&fmt[idx], "MYSQL")) readOnlyGlobals.enableMySQLPlugin = 1;

      if(strstr(&fmt[idx], "_COUNTRY") || strstr(&fmt[idx], "_CITY")) {
#ifdef HAVE_GEOIP
	if(readOnlyGlobals.geo_ip_city_db == NULL) {
	  traceEvent(TRACE_WARNING, "Geo-location requires --city-list to be specified: ignored %s", &fmt[idx]);
	  ignored = 1;
	}
#else
	ignored = 1;
#endif
      }

#if 0
      traceEvent(TRACE_WARNING, "Checking '%s' [ignored=%d]", &fmt[idx], ignored); 
#endif

      if(!ignored) {
	int duplicate_found = 0;
	char *element = &fmt[idx];

	i = 0, found = 0;

	/* Code used to avoid breaking existing systems */
	if(!strcmp(element, "SRC_MASK")) 
	  element = isIPv6OnlyTemplate ? "IPV6_SRC_MASK" : "IPV4_SRC_MASK";
	else if(!strcmp(element, "DST_MASK"))
	  element = isIPv6OnlyTemplate ? "IPV6_DST_MASK" : "IPV4_DST_MASK";

	while(ver9_templates[i].netflowElementName != NULL) {
#if 0
	      traceEvent(TRACE_WARNING, "===>>>> %s", ver9_templates[i].netflowElementName);
#endif
		if(isOptionTemplate
	     || ((!isOptionTemplate) && (ver9_templates[i].isOptionTemplate == 0))) {
	    if(
	       ((strcmp(element, ver9_templates[i].netflowElementName) == 0) 
		|| (strcmp(element, ver9_templates[i].ipfixElementName) == 0))		 
#if 0
	       ||
	       ((((strlen(ver9_templates[i].netflowElementName) > 0) 
		  && (strncmp(ver9_templates[i].netflowElementName, element, strlen(ver9_templates[i].netflowElementName)) == 0))
		 || ((strlen(ver9_templates[i].ipfixElementName) > 0) 
		     && (strncmp(ver9_templates[i].ipfixElementName, element, strlen(ver9_templates[i].ipfixElementName)) == 0))
		 ) && (ver9_templates[i].variableFieldLength == VARIABLE_FIELD_LEN))
#endif
	       ) {
	      int j;

	      for(j=0; j<templateIdx; j++) {
		if(templateList[j] == &ver9_templates[i]) {
		  traceEvent(TRACE_INFO, "Duplicate template element found %s: skipping", element);
		  duplicate_found = 1;
		  break;
		}
	      }

	      if(!duplicate_found) {
		templateList[templateIdx] = &ver9_templates[i];
		if(ver9_templates[i].useLongSnaplen) readOnlyGlobals.snaplen = PCAP_LONG_SNAPLEN;
		found = 1, templateList[templateIdx]->isInUse = 1;
		templateIdx++;
	      }

	      break;
	    }

#if 0
	    traceEvent(TRACE_WARNING, "Checking [%s][%s][found=%d]", 
		       element, ver9_templates[i].netflowElementName, found);
#endif
	  }

	  i++;
	}

	if(!duplicate_found) {
	  /* traceEvent(TRACE_WARNING, "Checking [%s][found=%d]", &fmt[idx], found); */

	  if(!found) {
	    if((templateList[templateIdx] = getPluginTemplate(&fmt[idx])) != NULL) {
	      if(templateList[templateIdx]->useLongSnaplen) readOnlyGlobals.snaplen = PCAP_LONG_SNAPLEN;
	      templateList[templateIdx]->isInUse = 1;
	      /* traceEvent(TRACE_WARNING, "Added field '%s' with index %d", &fmt[idx], templateIdx); */
	      templateIdx++;
	    } else {
	      traceEvent(TRACE_WARNING, "Unable to locate template '%s'. Discarded.", &fmt[idx]);
	    }
	  }

	  if(templateIdx >= (templateElements-1)) {
	    traceEvent(TRACE_WARNING, "Unable to add further template elements (%d).", templateIdx);
	    break;
	  }
	}
      }

      fmt[endIdx] = tmpChar;
      if(tmpChar == '%')
	idx = endIdx;
      else
	idx = endIdx+1;
      break;

    default:
      idx++;
      break;
    }
  }

  templateList[templateIdx] = NULL;
}

/* ******************************************** */

void flowPrintf(V9V10TemplateElementId **templateList,
		u_int8_t ipv4_template, char *outBuffer,
		uint *outBufferBegin, uint *outBufferMax,
		int *numElements, char buildTemplate,
		FlowHashBucket *theFlow, FlowDirection direction,
		int addTypeLen, int optionTemplate) {
  int idx = 0;

  (*numElements) = 0;

  while(templateList[idx] != NULL) {
    handleTemplate(templateList[idx], ipv4_template,
		   outBuffer, outBufferBegin, outBufferMax,
		   buildTemplate, numElements,
		   theFlow, direction, addTypeLen,
		   optionTemplate);
    idx++;
  }
}



