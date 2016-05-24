/*
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6
 *
 *       Copyright (C) 2002-12 Luca Deri <deri@ntop.org>
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

#ifndef _BUCKET_H_
#define _BUCKET_H_

/* ********************************** */

#define ENABLE_MAGIC

/* ********************************** */

/*
 * fallbacks for essential typedefs
 */
#ifdef WIN32
#ifndef __GNUC__
typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   uint;
typedef unsigned long  u_long;
#endif
typedef u_char  u_int8_t;
typedef u_short u_int16_t;
typedef uint   u_int32_t;
#endif /* WIN32 */

/* ********************************** */

#define NPROBE_FD_SET(n, p)   (*(p) |= (1 << (n)))
#define NPROBE_FD_CLR(n, p)   (*(p) &= ~(1 << (n)))
#define NPROBE_FD_ISSET(n, p) (*(p) & (1 << (n)))
#define NPROBE_FD_ZERO(p)     (*(p) = 0)


#define MAX_PAYLOAD_LEN          1400 /* bytes */

#define FLAG_NW_LATENCY_COMPUTED           1
#define FLAG_APPL_LATENCY_COMPUTED         2
#define FLAG_FRAGMENTED_PACKET_SRC2DST     3
#define FLAG_FRAGMENTED_PACKET_DST2SRC     4


#define NPROBE_UNKNOWN_VALUE              0
#define NPROBE_UNKNOWN_VALUE_STR          "0"

#define nwLatencyComputed(a)          (a && NPROBE_FD_ISSET(FLAG_NW_LATENCY_COMPUTED,   &(a->flags)))
#define applLatencyComputed(a)        (a && NPROBE_FD_ISSET(FLAG_APPL_LATENCY_COMPUTED, &(a->flags)))


#ifdef WIN32

#define _WS2TCPIP_H_ /* Avoid compilation problems */
#define HAVE_SIN6_LEN

/* IPv6 address */
/* Already defined in WS2tcpip.h */
struct win_in6_addr
{
  union
  {
    u_int8_t u6_addr8[16];
    u_int16_t u6_addr16[8];
    u_int32_t u6_addr32[4];
  } in6_u;
#ifdef s6_addr
#undef s6_addr
#endif

#ifdef s6_addr16
#undef s6_addr16
#endif

#ifdef s6_addr32
#undef s6_addr32
#endif

#define s6_addr                 in6_u.u6_addr8
#define s6_addr16               in6_u.u6_addr16
#define s6_addr32               in6_u.u6_addr32

};

#define in6_addr win_in6_addr

struct ip6_hdr
{
  union
  {
    struct ip6_hdrctl
    {
      u_int32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
				   20 bits flow-ID */
      u_int16_t ip6_un1_plen;   /* payload length */
      u_int8_t  ip6_un1_nxt;    /* next header */
      u_int8_t  ip6_un1_hlim;   /* hop limit */
    } ip6_un1;
    u_int8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
  } ip6_ctlun;
  struct in6_addr ip6_src;      /* source address */
  struct in6_addr ip6_dst;      /* destination address */
};

/* Generic extension header.  */
struct ip6_ext
{
  u_int8_t  ip6e_nxt;		/* next header.  */
  u_int8_t  ip6e_len;		/* length in units of 8 octets.  */
};

#else /* WIN32 */

#ifndef s6_addr32
#ifdef linux
#define s6_addr32 in6_u.u6_addr32
#else
#if defined(sun)
#define	s6_addr32	_S6_un._S6_u32
#else
#define s6_addr32 __u6_addr.__u6_addr32
#endif
#endif
#endif
#endif /* WIN32*/

/* ********************************** */

#define MAX_NUM_MPLS_LABELS     10
#define MPLS_LABEL_LEN           3

/* ********************************** */

/*
   NOTE

   whenever you change this datastructure
   please update sortFlowIndex()
*/
typedef struct flow_index {
  u_int8_t vlanId, proto;
  u_int32_t srcHost, dstHost;
  u_int16_t sport, dport;
  u_int8_t tos;
  u_int16_t subflow_id;
} FlowIndex;

/* ********************************** */

typedef struct ipAddress {
  u_int8_t ipVersion; /* Either 4 or 6 */

  union {
    struct in6_addr ipv6;
    u_int32_t ipv4; /* Host byte code */
  } ipType;
} IpAddress;

struct mpls_labels {
  u_short numMplsLabels;
  u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN];
};

struct pluginEntryPoint; /* engine.h */

typedef struct pluginInformation {
  struct pluginEntryPoint *pluginPtr;
  void *pluginData;
  u_int8_t plugin_used;
  struct pluginInformation *next;
} PluginInformation;

/*
 * If the host is local then stats points to a valid
 * memory area, otherwise it points to NULL
 */

typedef struct hostInfo {
  u_char macAddress[6];
  u_int8_t mask;
  u_int16_t ifIdx;
  u_int32_t ifHost, asn;
#ifdef HAVE_GEOIP
  GeoIPRecord *geo; /* GeoIP */
#endif
  u_int8_t aspath_len; /* Number of entries != 0 in aspath */
  u_int32_t *aspath; /* If allocated it will be MAX_AS_PATH_LEN long */
} HostInfo;

/* *************************************** */

typedef enum {
  src2dst_direction = 0,
  dst2src_direction
} FlowDirection;

/* *************************************** */

typedef struct tv {
  u_int32_t tv_sec, tv_usec;
} _tv;

typedef struct {
  u_int32_t num_pkts_up_to_128_bytes, num_pkts_128_to_256_bytes,
    num_pkts_256_to_512_bytes, num_pkts_512_to_1024_bytes,
    num_pkts_1024_to_1514_bytes, num_pkts_over_1514_bytes;
  u_int64_t bytes_time_variance; /* sum(square(packet size / delta(time))) / # packets */
} EtherStats;

typedef struct {
  struct mpls_labels *mplsInfo;

  struct {
    /* This entry is filled only in case of tunneled addresses */
    u_int8_t proto;
    IpAddress src, dst;
    u_int16_t sport, dport;
  } untunneled;

  struct {
    /* This entry is filled only in case of GTP signaling */
    IpAddress server_ip;
  } gtp;

  struct timeval synTime, synAckTime; /* network Latency (3-way handshake) */

  struct {
    EtherStats src2dst, dst2src;
  } etherstats;

  /* TCP Sequence number counters */
  u_int32_t src2dstNextSeqNum, dst2srcNextSeqNum;

  /*
    client <------------> nprobe <-------------------> server
    |<- clientNwDelay ->|        |<- serverNwDelay --------->|
    |<----------- network delay/latency -------------------->|
  */
  struct timeval clientNwDelay; /* The RTT between the client and nprobe */
  struct timeval serverNwDelay; /* The RTT between nprobe and the server */
  struct timeval src2dstApplLatency, dst2srcApplLatency; /* Application Latency */
} FlowHashBucketExtensions;

/* *************************************** */

struct flowHashBucket; /* Forward */

typedef struct {
  struct flowHashBucket *prev, *next;
} CircularList;

/* *************************************** */

#define HTTP_PROTO IPOQUE_PROTOCOL_HTTP
#define HTTPS_PROTO IPOQUE_PROTOCOL_SSL

#if 0
typedef enum {
  UNKNOWN_MAJOR_L7_PROTO = 0,
  HTTP_PROTO,
  HTTPS_PROTO,
  SSL_PROTO,
  SSH_PROTO,
  DNS_PROTO,
  SMTP_PROTO,
  IMAP_PROTO,
  TELNET_PROTO,
  POP_PROTO,
  RADIUS_PROTO,
  NETBIOS_PROTO,
  NBSS_PROTO,
  SNMP_PROTO,
  BOOTP_PROTO,
  SKYPE_PROTO
} L7MajorProtocolId;
#endif

typedef enum {
  UNKNOWN_MINOR_L7_PROTO = 0,
  HTTP_FACEBOOK,
  HTTP_TWITTER,
  HTTP_GMAIL,
  HTTP_GOOGLE_SEARCH,
  HTTP_GOOGLE_MAPS,
  HTTP_GOOGLE,
  HTTP_ITUNES,
} L7MinorProtocolId;

/* *************************************** */

typedef struct flowHashBucketCoreFields {
  u_int32_t flow_idx, flow_hash;

  /* Key */
  u_int8_t proto;          /* protocol (e.g. UDP/TCP..) */
  IpAddress src, dst;
  u_int16_t sport, dport, vlanId;
  
  /* Value */
  struct {
    struct timeval firstSeenSent, lastSeenSent;
    struct timeval firstSeenRcvd, lastSeenRcvd;
  } flowTimers;

  struct {
    u_int32_t bytesSent, pktSent;
    u_int32_t bytesRcvd, pktRcvd;
  } flowCounters;
} FlowHashBucketCoreFields;

/* *************************************** */

typedef struct flowHashMicroBucket {
  FlowHashBucketCoreFields tuple; /* Flow core fields */

  /* L7 protocol */
  struct {
    u_int8_t searched_port_based_protocol, detection_completed;
    u_int16_t proto;
    struct ipoque_flow_struct *flow;
    struct ipoque_id_struct *src, *dst;
  } l7;

  u_int8_t bucket_expired; /* Force bucket to expire */

  CircularList hash; /* Hash collision list pointers */

  /* Expire List (max flow duration) */
  CircularList max_duration;

  /* Idle flows (no traffic [idle]) */
  CircularList no_traffic;
} FlowHashMicroBucket;

/* *************************************** */

typedef struct {
  u_int8_t thread_id;      /* Thread on which the bucket was allocated */
  u_int32_t subflow_id;    /*
			     Usually is 0: user for subflows on UDP-based proto such as DNS
			     or sequence number in GTP
			   */
  u_int8_t swap_flow;      /* 0= don't swap, 1=in case of bidirectional flow send the reverse only */
  u_int8_t sampled_flow;   /* 0=normal flow, 1=sampled flow (i.e. to discard) */
  u_int32_t tunnel_id;     /* E.g. GTP tunnel */

  u_int16_t if_input, if_output;
  u_int8_t src2dstTos, dst2srcTos;
  u_int8_t src2dstMinTTL, dst2srcMinTTL, src2dstMaxTTL, dst2srcMaxTTL;

  HostInfo srcInfo, dstInfo; /* src and dst host metadata information */

  FlowHashBucketExtensions *extensions;

  /* **************** */

  struct {
    u_int32_t sentFragPkts, rcvdFragPkts;
    
    struct {
      u_int16_t longest, shortest;
    } pktSize; /* bytes */
  } flowCounters;

  union {
    struct {
      u_int32_t sentRetransmitted, rcvdRetransmitted;
      u_int32_t sentOOOrder, rcvdOOOrder;
      u_int16_t src2dstTcpFlags, dst2srcTcpFlags;
    } tcp;

    struct {
      u_int32_t src2dstIcmpFlags, dst2srcIcmpFlags;  /* ICMP bitmask */
      u_int16_t src2dstIcmpType, dst2srcIcmpType;    /* ICMP type */
    } icmp;
  } protoCounters;

  FlowDirection lastPktDirection;     /* Direction of the last flow packet */
  FlowDirection terminationInitiator; /* src2dst = client, dst2src = server [Future Use] */
  u_int32_t flags;                    /* bitmask (internal) */

  PluginInformation *plugin;

  pthread_rwlock_t src2dstLock, dst2srcLock;
} FlowHashExtendedBucket;

/* *************************************** */

typedef struct flowHashBucket {
#ifdef ENABLE_MAGIC
  u_char magic;
#endif

  FlowHashMicroBucket core;
  FlowHashExtendedBucket *ext;
} FlowHashBucket;

#endif /* _BUCKET_H_ */
