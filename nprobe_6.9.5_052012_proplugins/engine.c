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

#include "nprobe.h"

/* ****************************************************** */

void allocateFlowHash(int thread_id) {
  u_int mallocSize = sizeof(FlowHashBucket*)*readOnlyGlobals.flowHashSize;

  readWriteGlobals->theFlowHash[thread_id] = (FlowHashBucket**)calloc(1, mallocSize);
  if(readWriteGlobals->theFlowHash[thread_id] == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory");
    exit(-1);
  }

  readWriteGlobals->expireFlowListHead[thread_id] = NULL, readWriteGlobals->expireFlowListTail[thread_id] = NULL;
  readWriteGlobals->idleFlowListHead[thread_id] = NULL, readWriteGlobals->idleFlowListTail[thread_id] = NULL;

  pthread_rwlock_init(&readWriteGlobals->idleCheckLock[thread_id], NULL);
}

/* ****************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  uint byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ****************************** */

char* _intoa(IpAddress addr, char* buf, u_short bufLen) {
  if(addr.ipVersion == 4)
    return(_intoaV4(addr.ipType.ipv4, buf, bufLen));
  else {
    char *ret;
    int len;

#if 0
    ret = (char*)inet_ntop(AF_INET6, &addr.ipType.ipv6, &buf[1], bufLen-2);
#else
    ret = (char*)inet_ntop(AF_INET6, &addr.ipType.ipv6, buf, bufLen);
#endif

    if(ret == NULL) {
      traceEvent(TRACE_WARNING, "Internal error (buffer too short)");
      buf[0] = '\0';
    } else {
      len = strlen(ret);

#if 0
      buf[0] = '[';
      buf[len+1] = ']';
      buf[len+2] = '\0';
#endif
    }

    ret = buf;

    return(ret);
  }
}

/* ****************************************************** */

char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if (numBits < 1048576) {
    snprintf(buf, 32, "%.0f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.0f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
	snprintf(buf, 32, "%.0f G%c", tmpMBits, unit);
      } else {
	snprintf(buf, 32, "%.0f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}

/* ****************************************************** */

char* formatPackets(float numPkts, char *buf) {
  if(numPkts < 1000) {
    snprintf(buf, 32, "%.3f", numPkts);
  } else if(numPkts < 1000000) {
    snprintf(buf, 32, "%.3f K", numPkts/1000);
  } else {
    numPkts /= 1000000;
    snprintf(buf, 32, "%.3f M", numPkts);
  }

  return(buf);
}

/* ******************************************************** */

void setPayload(FlowHashBucket *bkt, const struct pcap_pkthdr *h, u_char *p,
		u_int16_t ip_offset, u_char *payload, int payloadLen, FlowDirection direction) {
  u_int max_pkts = 20;

  if(bkt->core.l7.detection_completed || (!readOnlyGlobals.enable_l7_protocol_discovery))
    return;

  /* Initial bytes only please */
  if((bkt->core.tuple.flowCounters.pktSent+bkt->core.tuple.flowCounters.pktRcvd) < max_pkts) {
    if(!bkt->core.l7.searched_port_based_protocol) {
      bkt->core.l7.proto = ntop_find_port_based_protocol(bkt->core.tuple.proto,
							 bkt->core.tuple.src.ipType.ipv4, bkt->core.tuple.sport,
							 bkt->core.tuple.dst.ipType.ipv4, bkt->core.tuple.dport);
      bkt->core.l7.searched_port_based_protocol = 1;
    }

    if((bkt->core.l7.proto == IPOQUE_PROTOCOL_UNKNOWN) && bkt->core.l7.flow) {
      u_int64_t when = ((u_int64_t) h->ts.tv_sec) * 1000 /* detection_tick_resolution */
	+ h->ts.tv_usec / 1000 /* (1000000 / detection_tick_resolution) */;

      // traceEvent(TRACE_NORMAL, "[caplen=%u/len=%u][ip_offset=%u][payloadLen=%u][diff=%d]", h->caplen, h->len, ip_offset, payloadLen, h->caplen-ip_offset);
      bkt->core.l7.proto = ipoque_detection_process_packet(readOnlyGlobals.l7.l7handler, bkt->core.l7.flow, (u_int8_t *)&p[ip_offset],
							   h->caplen-ip_offset, when, bkt->core.l7.src, bkt->core.l7.dst);
      // if(bkt->core.l7.proto != 0) traceEvent(TRACE_INFO, "Found protocol %u", bkt->core.l7.proto);

      if(bkt->core.l7.proto != IPOQUE_PROTOCOL_UNKNOWN)
	bkt->core.l7.detection_completed = 1;
    }
  } else
    bkt->core.l7.detection_completed = 1;
}

/* ************************************************* */

void updateApplLatency(u_short proto, FlowHashBucket *bkt,
		       FlowDirection direction, struct timeval *stamp) {
  if((!readOnlyGlobals.enableLatencyStats)
     || (bkt->ext == NULL)
     || (bkt->ext->extensions == NULL)
     )
    return;

  if(!applLatencyComputed(bkt->ext)) {
    /*
      src ---------> dst -+
      | Application
      | Latency
      <--------      -+

      NOTE:
      1. Application latency is calculated as the time passed since the first
      packet sent the first packet on the opposite direction is received.
      2. Application latency is calculated only on the first packet

    */

    if(direction == src2dst_direction) {
      /* src->dst */
      if(bkt->ext->extensions->src2dstApplLatency.tv_sec == 0)
	bkt->ext->extensions->src2dstApplLatency.tv_sec = stamp->tv_sec, bkt->ext->extensions->src2dstApplLatency.tv_usec = stamp->tv_usec;

      if(bkt->ext->extensions->dst2srcApplLatency.tv_sec != 0) {
	bkt->ext->extensions->dst2srcApplLatency.tv_sec  = bkt->ext->extensions->src2dstApplLatency.tv_sec-bkt->ext->extensions->dst2srcApplLatency.tv_sec;

	if((bkt->ext->extensions->src2dstApplLatency.tv_usec-bkt->ext->extensions->dst2srcApplLatency.tv_usec) < 0) {
	  bkt->ext->extensions->dst2srcApplLatency.tv_usec = 1000000 + bkt->ext->extensions->src2dstApplLatency.tv_usec - bkt->ext->extensions->dst2srcApplLatency.tv_usec;
	  if(bkt->ext->extensions->dst2srcApplLatency.tv_usec > 1000000) bkt->ext->extensions->dst2srcApplLatency.tv_usec = 1000000;
	  bkt->ext->extensions->dst2srcApplLatency.tv_sec--;
	} else
	  bkt->ext->extensions->dst2srcApplLatency.tv_usec = bkt->ext->extensions->src2dstApplLatency.tv_usec-bkt->ext->extensions->dst2srcApplLatency.tv_usec;

	bkt->ext->extensions->src2dstApplLatency.tv_sec = 0, bkt->ext->extensions->src2dstApplLatency.tv_usec = 0;
	NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->ext->flags));
      }
    } else {
      /* dst -> src */
      if(bkt->ext->extensions->dst2srcApplLatency.tv_sec == 0)
	bkt->ext->extensions->dst2srcApplLatency.tv_sec = stamp->tv_sec, bkt->ext->extensions->dst2srcApplLatency.tv_usec = stamp->tv_usec;

      if(bkt->ext->extensions->src2dstApplLatency.tv_sec != 0) {
	bkt->ext->extensions->src2dstApplLatency.tv_sec  = bkt->ext->extensions->dst2srcApplLatency.tv_sec-bkt->ext->extensions->src2dstApplLatency.tv_sec;

	if((bkt->ext->extensions->dst2srcApplLatency.tv_usec-bkt->ext->extensions->src2dstApplLatency.tv_usec) < 0) {
	  bkt->ext->extensions->src2dstApplLatency.tv_usec = 1000000 + bkt->ext->extensions->dst2srcApplLatency.tv_usec - bkt->ext->extensions->src2dstApplLatency.tv_usec;
	  if(bkt->ext->extensions->src2dstApplLatency.tv_usec > 1000000) bkt->ext->extensions->src2dstApplLatency.tv_usec = 1000000;
	  bkt->ext->extensions->src2dstApplLatency.tv_sec--;
	} else
	  bkt->ext->extensions->src2dstApplLatency.tv_usec = bkt->ext->extensions->dst2srcApplLatency.tv_usec-bkt->ext->extensions->src2dstApplLatency.tv_usec;

	bkt->ext->extensions->dst2srcApplLatency.tv_sec = 0, bkt->ext->extensions->dst2srcApplLatency.tv_usec = 0;
	NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->ext->flags));
      }
    }

#if 0
    if(applLatencyComputed(bkt)) {
      char buf[64], buf1[64];

      if(bkt->ext->extensions->src2dstApplLatency.tv_sec || bkt->ext->extensions->src2dstApplLatency.tv_usec)
	printf("[Appl: %.2f ms (%s->%s)]", (float)(bkt->ext->extensions->src2dstApplLatency.tv_sec*1000
						   +(float)bkt->ext->extensions->src2dstApplLatency.tv_usec/1000),
	       _intoa(bkt->src, buf, sizeof(buf)), _intoa(bkt->dst, buf1, sizeof(buf1)));
      else
	printf("[Appl: %.2f ms (%s->%s)]", (float)(bkt->ext->extensions->dst2srcApplLatency.tv_sec*1000
						   +(float)bkt->ext->extensions->dst2srcApplLatency.tv_usec/1000),
	       _intoa(bkt->dst, buf, sizeof(buf)), _intoa(bkt->src, buf1, sizeof(buf1)));
    }
#endif
  }
}

/* ****************************************************** */

inline void updatePktLenStats(FlowHashBucket *bkt,
			      FlowDirection direction,
			      struct timeval *when,
			      u_int pkt_len) {
  if(pkt_len > bkt->ext->flowCounters.pktSize.longest)
    bkt->ext->flowCounters.pktSize.longest = pkt_len;

  if((bkt->ext->flowCounters.pktSize.shortest == 0)
     || (pkt_len < bkt->ext->flowCounters.pktSize.shortest))
    bkt->ext->flowCounters.pktSize.shortest = pkt_len;

  if(bkt->ext->extensions && readOnlyGlobals.enablePacketStats) {
    EtherStats *eth = (direction == src2dst_direction) ? &bkt->ext->extensions->etherstats.src2dst : &bkt->ext->extensions->etherstats.dst2src;
    struct timeval delta;
    u_int32_t value;
    double diff;

    if(pkt_len <= 128)       eth->num_pkts_up_to_128_bytes++;
    else if(pkt_len <= 256)  eth->num_pkts_128_to_256_bytes++;
    else if(pkt_len <= 512)  eth->num_pkts_256_to_512_bytes++;
    else if(pkt_len <= 1024) eth->num_pkts_512_to_1024_bytes++;
    else if(pkt_len <= 1514) eth->num_pkts_1024_to_1514_bytes++;
    else eth->num_pkts_over_1514_bytes++;

    if(direction == src2dst_direction) {
      if(bkt->core.tuple.flowTimers.lastSeenSent.tv_sec == 0)
	diff = 0;
      else {
	timeval_diff(&bkt->core.tuple.flowTimers.lastSeenSent, when, &delta, 0);
	diff = toMs(&delta);
      }
    } else {
      if(bkt->core.tuple.flowTimers.lastSeenRcvd.tv_sec == 0)
	diff = 0;
      else {
	timeval_diff(&bkt->core.tuple.flowTimers.lastSeenRcvd, when, &delta, 0);
	diff = toMs(&delta);
      }
    }

    /* PUT YOUR FORMULA HERE */
    value = (pkt_len * pkt_len) / diff;
    // value = diff * diff;

    eth->bytes_time_variance += value;

    if(unlikely(readOnlyGlobals.enable_debug)) {
      u_int32_t pkts = (direction == src2dst_direction) ? bkt->core.tuple.flowCounters.pktSent : bkt->core.tuple.flowCounters.pktRcvd;

      traceEvent(TRACE_ERROR,
		 "[direction=%u][pkt len=%u][value=%u][tot pkts=%u][delta=%.2f][%.2f ms]",
		 (unsigned int)direction, pkt_len, value, pkts, diff,
		 (float)eth->bytes_time_variance/(float)pkts);
    }
  }
}

/* ****************************************************** */

inline void updateTTL(FlowHashBucket *bkt, FlowDirection direction, u_int8_t ttl) {
  if(direction == src2dst_direction) {
    if(ttl > 0) {
      if(bkt->ext->src2dstMinTTL == 0)
	bkt->ext->src2dstMinTTL = ttl;
      else
	bkt->ext->src2dstMinTTL = min(bkt->ext->src2dstMinTTL, ttl);
    }

    bkt->ext->src2dstMaxTTL = max(bkt->ext->src2dstMaxTTL, ttl);
  } else {
    if(ttl > 0) {
      if(bkt->ext->dst2srcMinTTL == 0)
	bkt->ext->dst2srcMinTTL = ttl;
      else
	bkt->ext->dst2srcMinTTL = min(bkt->ext->dst2srcMinTTL, ttl);
    }

    bkt->ext->dst2srcMaxTTL = max(bkt->ext->dst2srcMaxTTL, ttl);
  }
}

/* ****************************************************** */

inline void updateTos(FlowHashBucket *bkt, FlowDirection direction, u_int8_t tos) {
  if(direction == src2dst_direction)
    bkt->ext->src2dstTos |= tos;
  else
    bkt->ext->dst2srcTos |= tos;
}

/* ****************************************************** */

void timeval_diff(struct timeval *begin, struct timeval *end,
		  struct timeval *result, u_short divide_by_two) {
  if(end->tv_sec >= begin->tv_sec) {
    result->tv_sec = end->tv_sec-begin->tv_sec;

    if((end->tv_usec - begin->tv_usec) < 0) {
      result->tv_usec = 1000000 + end->tv_usec - begin->tv_usec;
      if(result->tv_usec > 1000000) begin->tv_usec = 1000000;
      result->tv_sec--;
    } else
      result->tv_usec = end->tv_usec-begin->tv_usec;

    if(divide_by_two)
      result->tv_sec /= 2, result->tv_usec /= 2;
  } else
    result->tv_sec = 0, result->tv_usec = 0;
}

/* ****************************************************** */

static char* print_flags(u_int8_t flags, char *buf, u_int buf_len) {
  snprintf(buf, buf_len, "%s%s%s%s%s",
	   (flags & TH_SYN) ? " SYN" : "",
	   (flags & TH_ACK) ? " ACK" : "",
	   (flags & TH_FIN) ? " FIN" : "",
	   (flags & TH_RST) ? " RST" : "",
	   (flags & TH_PUSH) ? " PUSH" : "");
  if(buf[0] == ' ')
    return(&buf[1]);
  else
    return(buf);
}

/* ****************************************************** */

inline u_int32_t getNextTcpSeq(u_int8_t tcpFlags,
			       u_int32_t tcpSeqNum,
			       u_int32_t payloadLen) {

  return(tcpSeqNum + ((tcpFlags & TH_SYN) ? 1 : 0) + payloadLen);
}

/* ****************************************************** */

void updateTcpSeq(struct timeval *when,
		  FlowHashBucket *bkt, FlowDirection direction,
		  u_int8_t tcpFlags, u_int32_t tcpSeqNum,
		  u_int32_t tcpAckNum, u_int32_t payloadLen) {
  u_int32_t nextSeqNum;
  double msLatency = 0, lastLatency;
  char buf[32];
  u_int8_t debug = 0;

  if(!readOnlyGlobals.enableTcpSeqStats) return;
  if(bkt->ext->extensions == NULL) return;

  // if(debug) traceEvent(TRACE_ERROR, "updateTcpSeq(seqNum=%u, ackNum=%u)", tcpSeqNum, tcpAckNum);

  /* Not always nProbe gets the TCP sequence number */
  if(tcpSeqNum == 0) return;

  nextSeqNum = getNextTcpSeq(tcpFlags, tcpSeqNum, payloadLen);

  if(bkt->ext->lastPktDirection != direction) {
    /*
      In case we're in the middle of a connection, the network delay
      is the miminum (yet > 0) that we have observed so far. This is
      because some communications might be triggered based on some events
      and thus we need to take as latency the minimum of observed event
      latency
     */
    if(direction == src2dst_direction) {
      if((bkt->ext->extensions->src2dstNextSeqNum == tcpSeqNum)
	 && (bkt->ext->extensions->dst2srcNextSeqNum == tcpAckNum)) {
	/* This is what we waited for */
	msLatency = toMs(when) - toMs(&bkt->core.tuple.flowTimers.lastSeenRcvd);
	lastLatency = toMs(&bkt->ext->extensions->clientNwDelay);

	if((msLatency < lastLatency) || (lastLatency == 0))
	  timeval_diff(&bkt->core.tuple.flowTimers.lastSeenRcvd, when, &bkt->ext->extensions->clientNwDelay, 1);
      }
    } else {
      if((bkt->ext->extensions->dst2srcNextSeqNum == tcpSeqNum)
	 && (bkt->ext->extensions->src2dstNextSeqNum == tcpAckNum)) {
	/* This is what we waited for */
	msLatency = toMs(when) - toMs(&bkt->core.tuple.flowTimers.lastSeenSent);
	lastLatency = toMs(&bkt->ext->extensions->serverNwDelay);

	if((msLatency < lastLatency) || (lastLatency == 0))
	  timeval_diff(&bkt->core.tuple.flowTimers.lastSeenSent, when, &bkt->ext->extensions->serverNwDelay, 1);
      }
    }
  }

  if(debug)
    traceEvent(TRACE_ERROR, "[%s] [payload_len=%u][%s][received=%u][expected=%u][next=%u][ack=%u][ooo=%u][retransmitted=%u][latency=%.2f ms]",
	       (direction == src2dst_direction) ? "src->dst" : "dst->src",
	       payloadLen, print_flags(tcpFlags, buf, sizeof(buf)), tcpSeqNum,
	       (direction == src2dst_direction) ? bkt->ext->extensions->src2dstNextSeqNum : bkt->ext->extensions->dst2srcNextSeqNum,
	       nextSeqNum, tcpAckNum,
	       (direction == src2dst_direction) ? bkt->ext->protoCounters.tcp.sentOOOrder :
	       bkt->ext->protoCounters.tcp.rcvdOOOrder,
	       (direction == src2dst_direction) ? bkt->ext->protoCounters.tcp.sentRetransmitted :
	       bkt->ext->protoCounters.tcp.rcvdRetransmitted,
	       (direction == src2dst_direction) ? toMs(&bkt->ext->extensions->clientNwDelay) : toMs(&bkt->ext->extensions->serverNwDelay));


  if(direction == src2dst_direction) {
    /* src -> dst */

    if(bkt->ext->extensions->src2dstNextSeqNum > 0) {
      if(bkt->ext->extensions->src2dstNextSeqNum != tcpSeqNum) {
	if(bkt->ext->extensions->src2dstNextSeqNum < tcpSeqNum)
	  bkt->ext->protoCounters.tcp.sentRetransmitted++;
	else {
	  bkt->ext->protoCounters.tcp.sentOOOrder++;
	  bkt->ext->extensions->src2dstNextSeqNum = nextSeqNum;
	}
      }
    }

    bkt->ext->extensions->src2dstNextSeqNum = nextSeqNum;
  } else {
    /* dst -> src */

    if(bkt->ext->extensions->dst2srcNextSeqNum > 0) {
      if(bkt->ext->extensions->dst2srcNextSeqNum != tcpSeqNum) {
	if(bkt->ext->extensions->dst2srcNextSeqNum < tcpSeqNum)
	  bkt->ext->protoCounters.tcp.sentRetransmitted++;
	else {
	  bkt->ext->protoCounters.tcp.sentOOOrder++;
	  bkt->ext->extensions->dst2srcNextSeqNum = nextSeqNum;
	}
      }
    }

    bkt->ext->extensions->dst2srcNextSeqNum = nextSeqNum;
  }
}

/* ****************************************************** */

/*
  Client           nProbe            Server
  ->    SYN                       synTime
  <-    SYN|ACK                   synAckTime
  ->    ACK                       ackTime

  serverNwDelay = (synAckTime - synTime) / 2
  clientNwDelay = (ackTime - synAckTime) / 2
*/

void updateTcpFlags(FlowHashBucket *bkt, FlowDirection direction,
		    struct timeval *stamp, u_int8_t flags) {
#if 0
  char buf[32];

  traceEvent(TRACE_NORMAL, "updateTcpFlags() [%s][direction: %s]",
	     print_flags(flags, buf, sizeof(buf)),
	     direction == src2dst_direction ? "src->dst" : "dst->src");
#endif

  if(bkt->ext->extensions == NULL) return;

  /* This is a termination */
  if(((flags & TH_FIN) == TH_FIN) || ((flags & TH_RST) == TH_RST)) {
    /* Check if this is the first FIN/RST */
    if(((bkt->ext->protoCounters.tcp.src2dstTcpFlags & (TH_FIN|TH_RST)) == 0)
       && ((bkt->ext->protoCounters.tcp.dst2srcTcpFlags & (TH_FIN|TH_RST)) == 0))
      bkt->ext->terminationInitiator = direction;
  }

  if(!nwLatencyComputed(bkt->ext)) {
    if(flags == TH_SYN) {
      bkt->ext->extensions->synTime.tv_sec = stamp->tv_sec;
      bkt->ext->extensions->synTime.tv_usec = stamp->tv_usec;
    } else if(flags == (TH_SYN | TH_ACK)) {
      if((bkt->ext->extensions->synTime.tv_sec != 0) && (bkt->ext->extensions->synAckTime.tv_sec == 0)) {
	bkt->ext->extensions->synAckTime.tv_sec  = stamp->tv_sec;
	bkt->ext->extensions->synAckTime.tv_usec = stamp->tv_usec;
	timeval_diff(&bkt->ext->extensions->synTime, stamp, &bkt->ext->extensions->serverNwDelay, 1);
      }
    } else if(flags == TH_ACK) {
      if(bkt->ext->extensions->synTime.tv_sec == 0) {
	/* We missed the SYN flag */
	NPROBE_FD_SET(FLAG_NW_LATENCY_COMPUTED,   &(bkt->ext->flags));
	NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->ext->flags)); /* We cannot calculate it as we have
								     missed the 3-way handshake */
	return;
      }

      if(((direction == src2dst_direction)    && (bkt->ext->protoCounters.tcp.src2dstTcpFlags != TH_SYN))
	 || ((direction == dst2src_direction) && (bkt->ext->protoCounters.tcp.dst2srcTcpFlags != TH_SYN)))
	return; /* Wrong flags */

      if(bkt->ext->extensions->synAckTime.tv_sec > 0) {
	timeval_diff(&bkt->ext->extensions->synAckTime, stamp, &bkt->ext->extensions->clientNwDelay, 1);

#if 0
	printf("[Client: %.1f ms][Server: %.1f ms]\n",
	       (float)(bkt->ext->extensions->clientNwDelay.tv_sec*1000+(float)bkt->ext->extensions->clientNwDelay.tv_usec/1000),
	       (float)(bkt->ext->extensions->serverNwDelay.tv_sec*1000+(float)bkt->ext->extensions->serverNwDelay.tv_usec/1000));
#endif

	NPROBE_FD_SET(FLAG_NW_LATENCY_COMPUTED, &(bkt->ext->flags));
	updateApplLatency(IPPROTO_TCP, bkt, direction, stamp);
      }
    }
  } else {
    /* Nw latency computed */
    if(!applLatencyComputed(bkt->ext)) {
      /*
	src ---------> dst -+
	| Application
	| Latency
	<--------      -+

	NOTE:
	1. Application latency is calculated as the time passed since the first
	packet sent after the 3-way handshake until the first packet on
	the opposite direction is received.
	2. Application latency is calculated only on the first packet
      */

      updateApplLatency(IPPROTO_TCP, bkt, direction, stamp);
    }
  }
}

/* ****************************************************** */

/*
  1 - equal
  0 - different
*/
inline int cmpIpAddress(IpAddress *src, IpAddress *dst) {
  if(src->ipVersion != dst->ipVersion) return(0);

  if(src->ipVersion == 4) {
    return(src->ipType.ipv4 == dst->ipType.ipv4 ? 1 : 0);
  } else {
    return(!memcmp(&src->ipType.ipv6, &dst->ipType.ipv6, sizeof(struct in6_addr)));
  }
}

/* ****************************************************** */

static FlowHashBucket* allocFlowBucket(u_int8_t proto, u_short thread_id,
				       u_short hash_idx, u_short mutex_idx,
				       u_short idx) {
  FlowHashBucket *bkt;
  ticks when;
  static u_int8_t once = 0;

  if(unlikely(readOnlyGlobals.tracePerformance)) when = getticks();

  bkt = (FlowHashBucket*)calloc(1, sizeof(FlowHashBucket));

  if(bkt == NULL)
    goto bkt_failure;

  if(unlikely(readOnlyGlobals.tracePerformance)) {
    ticks diff = getticks() - when;

    if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
    readOnlyGlobals.bucketMallocTicks += diff, readOnlyGlobals.num_malloced_buckets++;
    if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
  }

  if(readOnlyGlobals.enable_l7_protocol_discovery) {
    if((bkt->core.l7.flow = calloc(1, readOnlyGlobals.l7.flow_struct_size)) == NULL)
      goto bkt_failure;

    bkt->core.l7.src = malloc(readOnlyGlobals.l7.proto_size);
    bkt->core.l7.dst = malloc(readOnlyGlobals.l7.proto_size);

    if((bkt->core.l7.src == NULL) || (bkt->core.l7.dst == NULL))
      goto bkt_failure;
  }

  if(readOnlyGlobals.quick_mode) {
    bkt->ext = NULL;
  } else {
    bkt->ext = (FlowHashExtendedBucket*)calloc(1, sizeof(FlowHashExtendedBucket));

    if(bkt->ext == NULL)
      goto bkt_failure;

    if(readOnlyGlobals.enableExtBucket) {
      bkt->ext->extensions = (FlowHashBucketExtensions*)calloc(1, sizeof(FlowHashBucketExtensions));

      if(bkt->ext->extensions == NULL)
	goto bkt_failure;
    }

    if(unlikely(readOnlyGlobals.numProcessThreads > 1)) {
      pthread_rwlock_init(&bkt->ext->src2dstLock, NULL);
      pthread_rwlock_init(&bkt->ext->dst2srcLock, NULL);
    }
  }

  if(bkt->ext)
    bkt->ext->thread_id = thread_id;

#if 0
  if(readWriteGlobals->exportBucketsLen < 16)
    traceEvent(TRACE_NORMAL, "[+] bucketsAllocated=%u",
	       readWriteGlobals->bucketsAllocated[thread_id]);
#endif

  if(proto == 1)       readWriteGlobals->accumulateStats[thread_id].icmpFlows++;
  else if(proto == 6)  readWriteGlobals->accumulateStats[thread_id].tcpFlows++;
  else if(proto == 17) readWriteGlobals->accumulateStats[thread_id].udpFlows++;

  if(readWriteGlobals->expireFlowListHead[hash_idx] == NULL) {
    /* The only entry of the list */
    readWriteGlobals->expireFlowListHead[hash_idx] = readWriteGlobals->expireFlowListTail[hash_idx] = bkt;
  } else {
    /* The list is already populated: append at the end */
    readWriteGlobals->expireFlowListTail[hash_idx]->core.max_duration.next = bkt;
    bkt->core.max_duration.prev = readWriteGlobals->expireFlowListTail[hash_idx];
    readWriteGlobals->expireFlowListTail[hash_idx] = bkt;
  }

  /* Append it to the idle flow list */
  if(readWriteGlobals->idleFlowListHead[hash_idx] == NULL) {
    /* The only entry of the list */
    readWriteGlobals->idleFlowListHead[hash_idx] = readWriteGlobals->idleFlowListTail[hash_idx] = bkt;
  } else {
    /* The list is already populated: append */
    readWriteGlobals->idleFlowListTail[hash_idx]->core.no_traffic.next = bkt;
    bkt->core.no_traffic.prev = readWriteGlobals->idleFlowListTail[hash_idx];
    readWriteGlobals->idleFlowListTail[hash_idx] = bkt;
  }

  if(unlikely(readOnlyGlobals.tracePerformance)) {
    ticks diff = getticks() - when;

    if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
    readOnlyGlobals.bucketAllocationTicks += diff, readOnlyGlobals.num_allocated_buckets++;
    if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
  }

  readWriteGlobals->bucketsAllocated[thread_id]++;

  /* This is the return point in case of succefull allocation */
  return(bkt);

 bkt_failure:
  if(!once) {
    traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)");
    once = 1;
  }

  purgeBucket(bkt);
  return(NULL);
}

/* ****************************************************** */

inline void updateHost(HostInfo *host, IpAddress *addr, u_int32_t ifHost, u_int16_t ifIdx) {
  host->ifHost = ifHost, host->ifIdx = ifIdx;
}

/* ****************************************************** */

static inline u_int32_t hostHash(IpAddress *host) {
  if(host->ipVersion == 4)
    return(host->ipType.ipv4);
  else
    return(host->ipType.ipv6.s6_addr32[0]
	   + host->ipType.ipv6.s6_addr32[1]
	   + host->ipType.ipv6.s6_addr32[2]
	   + host->ipType.ipv6.s6_addr32[3]);
}

/* ****************************************************** */

#ifdef ACCURATE_HASH

inline void sortFlowIndex(struct flow_index *to_index) {
  u_int32_t u32;
  u_int32_t u16;

  if(to_index->sport == to_index->dport) {
    /* Sort on host */

    if(to_index->srcHost <= to_index->dstHost)
      return; /* Nothing to do */
    else {
      /* Just swap hosts */
      u32 = to_index->srcHost;
      to_index->srcHost = to_index->dstHost;
      to_index->dstHost = u32;
    }
  } else if(to_index->sport < to_index->dport) {
    return; /* Nothing to do */
  } else /* to_index->sport > to_index->dport */ {
    u32 = to_index->srcHost, u16 = to_index->sport;
    to_index->srcHost = to_index->dstHost, to_index->sport = to_index->dport;
    to_index->dstHost = u32, to_index->dport= u16;
  }
}

/* ****************************************************** */

#if 1

/* http://burtleburtle.net/bob/hash/evahash.html */

/* The mixing step */
#define mix(a,b,c) \
  { \
    a=a-b;  a=a-c;  a=a^(c>>13); \
    b=b-c;  b=b-a;  b=b^(a<<8);  \
    c=c-a;  c=c-b;  c=c^(b>>13); \
    a=a-b;  a=a-c;  a=a^(c>>12); \
    b=b-c;  b=b-a;  b=b^(a<<16); \
    c=c-a;  c=c-b;  c=c^(b>>5);  \
    a=a-b;  a=a-c;  a=a^(c>>3);  \
    b=b-c;  b=b-a;  b=b^(a<<10); \
    c=c-a;  c=c-b;  c=c^(b>>15); \
  }

#define mix64(a,b,c) \
  { \
    a=a-b;  a=a-c;  a=a^(c>>43); \
    b=b-c;  b=b-a;  b=b^(a<<9); \
    c=c-a;  c=c-b;  c=c^(b>>8); \
    a=a-b;  a=a-c;  a=a^(c>>38); \
    b=b-c;  b=b-a;  b=b^(a<<23); \
    c=c-a;  c=c-b;  c=c^(b>>5); \
    a=a-b;  a=a-c;  a=a^(c>>35); \
    b=b-c;  b=b-a;  b=b^(a<<49); \
    c=c-a;  c=c-b;  c=c^(b>>11); \
    a=a-b;  a=a-c;  a=a^(c>>12); \
    b=b-c;  b=b-a;  b=b^(a<<18); \
    c=c-a;  c=c-b;  c=c^(b>>22); \
  }

/* The whole new hash function */
u_int32_t hashVal(const u_int8_t *k,  /* the key */
		  u_int32_t length,   /* the length of the key in bytes */
		  u_int32_t initval)  /* the previous hash, or an arbitrary value */
{
  u_int32_t a,b,c;  /* the internal state */
  u_int32_t          len;    /* how many key bytes still need mixing */

  /* Set up the internal state */
  len = length;
  a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
  c = initval;         /* variable initialization of internal state */

  /*---------------------------------------- handle most of the key */
  while (len >= 12)
    {
      a=a+(k[0]+((u_int32_t)k[1]<<8)+((u_int32_t)k[2]<<16) +((u_int32_t)k[3]<<24));
      b=b+(k[4]+((u_int32_t)k[5]<<8)+((u_int32_t)k[6]<<16) +((u_int32_t)k[7]<<24));
      c=c+(k[8]+((u_int32_t)k[9]<<8)+((u_int32_t)k[10]<<16)+((u_int32_t)k[11]<<24));
      mix(a,b,c);
      k = k+12; len = len-12;
    }

  /*------------------------------------- handle the last 11 bytes */
  c = c+length;
  switch(len)              /* all the case statements fall through */
    {
    case 11: c=c+((u_int32_t)k[10]<<24);
    case 10: c=c+((u_int32_t)k[9]<<16);
    case 9 : c=c+((u_int32_t)k[8]<<8);
      /* the first byte of c is reserved for the length */
   case 8 : b=b+((u_int32_t)k[7]<<24);
    case 7 : b=b+((u_int32_t)k[6]<<16);
    case 6 : b=b+((u_int32_t)k[5]<<8);
    case 5 : b=b+k[4];
    case 4 : a=a+((u_int32_t)k[3]<<24);
    case 3 : a=a+((u_int32_t)k[2]<<16);
    case 2 : a=a+((u_int32_t)k[1]<<8);
    case 1 : a=a+k[0];
      /* case 0: nothing left to add */
    }
  mix(a,b,c);

  /*-------------------------------------------- report the result */
  return c;
}

#else
/*
  http://sites.google.com/site/murmurhash/

  The code below is MurmurHash2()
*/

unsigned int hashVal(const u_int8_t * key, int len, unsigned int seed)
{
  // 'm' and 'r' are mixing constants generated offline.
  // They're not really 'magic', they just happen to work well.

  const unsigned int m = 0x5bd1e995;
  const int r = 24;

  // Initialize the hash to a 'random' value

  unsigned int h = seed ^ len;

  // Mix 4 bytes at a time into the hash

  const unsigned char * data = (const unsigned char *)key;

  while(len >= 4)
    {
      unsigned int k = *(unsigned int *)data;

      k *= m;
      k ^= k >> r;
      k *= m;

      h *= m;
      h ^= k;

      data += 4;
      len -= 4;
    }

  // Handle the last few bytes of the input array

  switch(len)
    {
    case 3: h ^= data[2] << 16;
    case 2: h ^= data[1] << 8;
    case 1: h ^= data[0];
      h *= m;
    };

  // Do a few final mixes of the hash to ensure the last few
  // bytes are well-incorporated.

  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;

  return h;
}
#endif

#endif

/* ******************************************************** */

static void walkHashList(u_int32_t thread_id, int flushHash, time_t now) {
  FlowHashBucket *myBucket, *myNextBucket;
  u_int num_exported, num_runs;

  num_exported = 0, num_runs = 0;

  for(num_runs = 0; num_runs < 2; num_runs++) {
    if(num_runs == 0)
      myBucket = readWriteGlobals->expireFlowListHead[thread_id];
    else {
      if(flushHash) break;
      myBucket = readWriteGlobals->idleFlowListHead[thread_id];
    }

    while(myBucket != NULL) {
      myNextBucket = (num_runs == 0) ? myBucket->core.max_duration.next : myBucket->core.no_traffic.next;

      if(flushHash || isFlowExpired(myBucket, now)) {
	/* Remove it from bucket list */
	myBucket->core.bucket_expired = 1;

	/*
	  We've updated the pointers, hence removed this bucket from the active bucket list,
	  therefore we now invalidate the next pointer
	*/
	/* 1 - Remove from hash */
	if(readWriteGlobals->theFlowHash[thread_id][myBucket->core.tuple.flow_idx] == myBucket) {
	  /* 1st Element of the list */
	  readWriteGlobals->theFlowHash[thread_id][myBucket->core.tuple.flow_idx] = myBucket->core.hash.next;
	  if(readWriteGlobals->theFlowHash[thread_id][myBucket->core.tuple.flow_idx] != NULL)
	    readWriteGlobals->theFlowHash[thread_id][myBucket->core.tuple.flow_idx]->core.hash.prev = NULL;
	} else {
	  /* Middle or last */
	  (myBucket->core.hash.prev)->core.hash.next = myBucket->core.hash.next;
	  if(myBucket->core.hash.next != NULL) /* We are not the last element */
	    (myBucket->core.hash.next)->core.hash.prev = myBucket->core.hash.prev;
	}

	/* 2 - Max Duration */
	if(readWriteGlobals->expireFlowListHead[thread_id] == readWriteGlobals->expireFlowListTail[thread_id]) {
	  /* The list has only one element: me */
	  if(readWriteGlobals->expireFlowListHead[thread_id] != myBucket) {
	    traceEvent(TRACE_WARNING, "Internal error: [Head: %p][Tail: %p][myBucket: %p]",
		       readWriteGlobals->expireFlowListHead[thread_id],
		       readWriteGlobals->expireFlowListTail[thread_id],
		       myBucket);
	  }
	  readWriteGlobals->expireFlowListHead[thread_id] = readWriteGlobals->expireFlowListTail[thread_id] = NULL;
	} else if(readWriteGlobals->expireFlowListHead[thread_id] == myBucket) {
	  /* 1st Element of the list and more than one element on the list */
	  readWriteGlobals->expireFlowListHead[thread_id] = myBucket->core.max_duration.next;
	  readWriteGlobals->expireFlowListHead[thread_id]->core.max_duration.prev = NULL;
	} else if(readWriteGlobals->expireFlowListTail[thread_id] == myBucket) {
	  /* Last element of the list */
	  readWriteGlobals->expireFlowListTail[thread_id] = myBucket->core.max_duration.prev;
	  readWriteGlobals->expireFlowListTail[thread_id]->core.max_duration.next = NULL;
	} else {
	  /* Middle */
	  (myBucket->core.max_duration.prev)->core.max_duration.next = myBucket->core.max_duration.next;
	  (myBucket->core.max_duration.next)->core.max_duration.prev = myBucket->core.max_duration.prev;
	}

	/* 3 - No Traffic */
	if(readWriteGlobals->idleFlowListHead[thread_id] == readWriteGlobals->idleFlowListTail[thread_id]) {
	  /* The list has only one element: me */
	  if(readWriteGlobals->idleFlowListHead[thread_id] != myBucket) {
	    traceEvent(TRACE_WARNING, "Internal error: [Head: %p][Tail: %p][myBucket: %p]",
		       readWriteGlobals->idleFlowListHead[thread_id],
		       readWriteGlobals->idleFlowListTail[thread_id],
		       myBucket);
	  }
	  readWriteGlobals->idleFlowListHead[thread_id] = readWriteGlobals->idleFlowListTail[thread_id] = NULL;
	} else if(readWriteGlobals->idleFlowListHead[thread_id] == myBucket) {
	  /* 1st Element of the list */
	  readWriteGlobals->idleFlowListHead[thread_id] = myBucket->core.no_traffic.next;
	  readWriteGlobals->idleFlowListHead[thread_id]->core.no_traffic.prev = NULL;
	} else if(readWriteGlobals->idleFlowListTail[thread_id] == myBucket) {
	  /* Last element of the list */
	  readWriteGlobals->idleFlowListTail[thread_id] = myBucket->core.no_traffic.prev;
	  readWriteGlobals->idleFlowListTail[thread_id]->core.no_traffic.next = NULL;
	} else {
	  /* Middle */
	  (myBucket->core.no_traffic.prev)->core.no_traffic.next = myBucket->core.no_traffic.next;
	  (myBucket->core.no_traffic.next)->core.no_traffic.prev = myBucket->core.no_traffic.prev;
	}

	if(!(myBucket->ext && myBucket->ext->sampled_flow)) {
	  if(readWriteGlobals->exportBucketsLen < readOnlyGlobals.maxExportQueueLen) {
	    /*
	      The flow is both expired and we have room in the export
	      queue to send it out, hence we can export it
	    */
	    queueBucketToExport(myBucket);
	  } else {
	    /* The export queue is full:

	       The flow is expired and in queue since too long. As there's
	       no room left in queue, the only thing we can do is to
	       drop it
	    */
	    discardBucket(myBucket);
	    readWriteGlobals->probeStats.totFlowDropped++;

	    /*
	      Too much work to be done: let's decrease the export delay
	      if this has been set!
	    */
	    if(readOnlyGlobals.flowExportDelay > 0)
	      readOnlyGlobals.flowExportDelay--;
	  }
	} else {
	  /* Free bucket */
	  discardBucket(myBucket);
	}

	num_exported++;

	myBucket = myNextBucket;
      } else {
	/* Max duration */

	if(flushHash) {
	  myBucket = myNextBucket;
	  continue;
	} else
	  break;
      }
    }
  }

  /* Check idle flows */

  if(num_exported > 0)
    signalCondvar(&readWriteGlobals->exportQueueCondvar, 0);
}

/* ****************************** */

inline void hash_lock(const char *filename, const int line, u_int32_t hash_idx, u_int32_t mutex_idx) {
  if(unlikely(readOnlyGlobals.numProcessThreads > 1)) {
    pthread_rwlock_t *rwlock = &readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx];
    int rc = pthread_rwlock_wrlock(rwlock);

    if(rc != 0) traceEvent(TRACE_WARNING, "hash_lock failed [rc=%d][hash_idx=%u][mutex_idx=%u] @ %s:%d",
                           rc, hash_idx, mutex_idx, filename, line);
  }
}

/* ****************************************************** */

inline void hash_unlock(const char *filename, const int line, u_int32_t hash_idx, u_int32_t mutex_idx) {
  if(unlikely(readOnlyGlobals.numProcessThreads > 1)) {
    pthread_rwlock_t *rwlock = &readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx];
    int rc = pthread_rwlock_unlock(rwlock);

    if(rc != 0) traceEvent(TRACE_WARNING, "hash_unlock failed [rc=%d][hash_idx=%u][mutex_idx=%u] @ %s:%d",
                           rc, hash_idx, mutex_idx, filename, line);
  }
}

/* ****************************************************** */

FlowHashBucket* getHashBucket(u_int32_t packet_hash, u_short thread_id) {
  u_int32_t hash_idx = thread_id, idx;
  FlowHashBucket *bkt;

  idx = packet_hash % readOnlyGlobals.flowHashSize;

  bkt = readWriteGlobals->theFlowHash[hash_idx][idx];

  while(bkt != NULL) {
    if((!bkt->core.bucket_expired) && (bkt->core.tuple.flow_hash == packet_hash)) {
      return(bkt);
    } else
      bkt = bkt->core.hash.next;
  }

  return(NULL);
}

/* ****************************************************** */

void quickProcessFlowPacket(u_short thread_id,
			    int packet_if_idx /* -1 = unknown */,
			    u_int8_t proto,
			    u_int16_t ip_offset, u_short numPkts,
			    u_short vlanId,
			    IpAddress *src, u_short sport,
			    IpAddress *dst, u_short dport,
			    u_int16_t if_input, u_int16_t if_output,
			    struct pcap_pkthdr *h, u_char *p,
			    u_int16_t payload_shift, u_int payloadLen,
			    u_int originalPayloadLen,
			    u_int32_t packet_hash) {
  u_char *payload = NULL;
  u_int32_t n = 0, mutex_idx, subflow_id = 0;
  FlowHashBucket *bkt;
  struct timeval firstSeen;
  u_int32_t hash_idx, idx;
  FlowDirection direction;
  ticks when;
  u_int32_t srcHost, dstHost;

  h->caplen = min(h->caplen, readOnlyGlobals.snaplen);

  if(src->ipVersion == 4) {
    srcHost = src->ipType.ipv4, dstHost = dst->ipType.ipv4;
  } else {
    srcHost = src->ipType.ipv6.s6_addr32[0]+src->ipType.ipv6.s6_addr32[1]
      +src->ipType.ipv6.s6_addr32[2]+src->ipType.ipv6.s6_addr32[3];
    dstHost = dst->ipType.ipv6.s6_addr32[0]+dst->ipType.ipv6.s6_addr32[1]
      +dst->ipType.ipv6.s6_addr32[2]+dst->ipType.ipv6.s6_addr32[3];
  }

  packet_hash = vlanId+proto+srcHost+dstHost+sport+dport;
  hash_idx = thread_id;
  idx = packet_hash % readOnlyGlobals.flowHashSize;

  firstSeen.tv_sec = h->ts.tv_sec, firstSeen.tv_usec = h->ts.tv_usec;

  if(likely(readOnlyGlobals.pcapFile == NULL)) /* Live capture */
    readWriteGlobals->actTime.tv_sec = h->ts.tv_sec, readWriteGlobals->actTime.tv_usec = h->ts.tv_usec;

  if(payload_shift > 0) payload = &p[payload_shift];
  mutex_idx = idx % MAX_HASH_MUTEXES;

  /* The statement below guarantees that packets are serialized */
  hash_lock(__FILE__, __LINE__, hash_idx, mutex_idx);

  bkt = readWriteGlobals->theFlowHash[hash_idx][idx];

  while(bkt != NULL) {
#ifdef ENABLE_MAGIC
    if(bkt->magic != 67) {
      traceEvent(TRACE_ERROR, "Magic error detected (magic=%d)", bkt->magic);
    }
#endif

    if((!bkt->core.bucket_expired)) {
      if(((bkt->core.tuple.proto == proto)
	  && (bkt->core.tuple.vlanId == vlanId)
	  && (((bkt->core.tuple.sport == sport)
	       && (bkt->core.tuple.dport == dport)
	       && cmpIpAddress(&bkt->core.tuple.src, src)
	       && cmpIpAddress(&bkt->core.tuple.dst, dst)
	       )
	      ||
	      ((bkt->core.tuple.sport == dport)
	       && (bkt->core.tuple.dport == sport)
	       && cmpIpAddress(&bkt->core.tuple.src, dst)
	       && cmpIpAddress(&bkt->core.tuple.dst, src)
	       )))) {
	if((bkt->core.tuple.sport == sport)
	   && cmpIpAddress(&bkt->core.tuple.src, src)) {
	  direction = src2dst_direction;
	} else {
	  direction = dst2src_direction;
	}

	if(direction == src2dst_direction) {
	  /* src -> dst */
	  bkt->core.tuple.flowCounters.bytesSent += h->len, bkt->core.tuple.flowCounters.pktSent += numPkts;

	  if(bkt->core.tuple.flowTimers.firstSeenSent.tv_sec == 0)
	    bkt->core.tuple.flowTimers.firstSeenSent.tv_sec = h->ts.tv_sec, bkt->core.tuple.flowTimers.firstSeenSent.tv_usec = h->ts.tv_usec;

	  bkt->core.tuple.flowTimers.lastSeenSent.tv_sec = h->ts.tv_sec, bkt->core.tuple.flowTimers.lastSeenSent.tv_usec = h->ts.tv_usec;

	  if(readOnlyGlobals.enable_l7_protocol_discovery)
	    setPayload(bkt, h, p, ip_offset, payload, payloadLen, 0);
	} else {
	  /* dst -> src */

	  bkt->core.tuple.flowCounters.bytesRcvd += h->len, bkt->core.tuple.flowCounters.pktRcvd += numPkts;

	  if(((bkt->core.tuple.flowTimers.firstSeenRcvd.tv_sec == 0) && (bkt->core.tuple.flowTimers.firstSeenRcvd.tv_usec == 0))
	     || (to_msec(&firstSeen) < to_msec(&bkt->core.tuple.flowTimers.firstSeenRcvd)))
	    bkt->core.tuple.flowTimers.firstSeenRcvd.tv_sec = firstSeen.tv_sec, bkt->core.tuple.flowTimers.firstSeenRcvd.tv_usec = firstSeen.tv_usec;

	  bkt->core.tuple.flowTimers.lastSeenRcvd.tv_sec = h->ts.tv_sec, bkt->core.tuple.flowTimers.lastSeenRcvd.tv_usec = h->ts.tv_usec;

	  if(readOnlyGlobals.enable_l7_protocol_discovery)
	    setPayload(bkt, h, p, ip_offset, payload, payloadLen, 1);
	}

	/* Sanity check */
	if(payload == NULL) payloadLen = 0;

	if(((direction == src2dst_direction) && (bkt->core.tuple.flowCounters.bytesSent > BYTES_WRAP_THRESHOLD))
	   || ((direction == dst2src_direction) && (bkt->core.tuple.flowCounters.bytesRcvd > BYTES_WRAP_THRESHOLD))) {
	  /*
	    The counter has a pretty high value: we better mark this flow as expired
	    in order to avoid wrapping the counter.
	  */
	  bkt->core.bucket_expired = 1;
	}

        /* Let's move this flow at the end of the idle flow list */
        if((readWriteGlobals->idleFlowListTail[hash_idx] != bkt)
           /* The list has only one element */
           && (readWriteGlobals->idleFlowListHead[hash_idx] != readWriteGlobals->idleFlowListTail[hash_idx])
           ) {
          /* We're not the last/first one of the list */

          /* 1 - Remove bkt from the list */
	  if(readWriteGlobals->idleFlowListHead[hash_idx] == readWriteGlobals->idleFlowListTail[hash_idx]) {
	    /* The list has only one element: me */
	    readWriteGlobals->idleFlowListHead[hash_idx] = readWriteGlobals->idleFlowListTail[hash_idx] = NULL;
	  } else if(readWriteGlobals->idleFlowListHead[hash_idx] == bkt) {
	    /* 1st Element of the list */
	    readWriteGlobals->idleFlowListHead[hash_idx] = bkt->core.no_traffic.next;
	    readWriteGlobals->idleFlowListHead[hash_idx]->core.no_traffic.prev = NULL;
	  } else if(readWriteGlobals->idleFlowListTail[hash_idx] == bkt) {
	    /* Last element of the list */
	    readWriteGlobals->idleFlowListTail[hash_idx] = bkt->core.no_traffic.prev;
	    readWriteGlobals->idleFlowListTail[hash_idx]->core.no_traffic.next = NULL;
	  } else {
	    /* Middle */
	    (bkt->core.no_traffic.prev)->core.no_traffic.next = bkt->core.no_traffic.next;
	    (bkt->core.no_traffic.next)->core.no_traffic.prev = bkt->core.no_traffic.prev;
	  }

          /* 2 - Append it at the end */
          readWriteGlobals->idleFlowListTail[hash_idx]->core.no_traffic.next = bkt;
          bkt->core.no_traffic.prev = readWriteGlobals->idleFlowListTail[hash_idx];
          bkt->core.no_traffic.next = NULL;
          readWriteGlobals->idleFlowListTail[hash_idx] = bkt;
        }

	if(unlikely(readOnlyGlobals.tracePerformance)) {
	  ticks diff = getticks() - when;
	  if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
	  readOnlyGlobals.processingWoFlowCreationTicks += diff, readOnlyGlobals.num_pkts_without_flow_creation++;
	  if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
	}
	idleThreadTask(thread_id);
	hash_unlock(__FILE__, __LINE__, hash_idx, mutex_idx);
	return;
      }
    }

    /* Bucket not found yet */
    n++, bkt = bkt->core.hash.next;
  } /* while */

  if(n > readWriteGlobals->maxBucketSearch) {
    readWriteGlobals->maxBucketSearch = n;
    // traceEvent(TRACE_NORMAL, "[maxBucketSearch=%d][hash_idx=%u][idx=%u]", readWriteGlobals->maxBucketSearch, hash_idx, idx);
  }

#ifdef DEBUG_EXPORT
  printf("Adding new bucket");
#endif

  if(bkt == NULL) {
    if(readWriteGlobals->bucketsAllocated[thread_id] >= readOnlyGlobals.maxNumActiveFlows) {
      static u_char msgSent = 0;

      if(!msgSent) {
	traceEvent(TRACE_WARNING, "WARNING: too many (%u) active flows [threadId=%u][limit=%u] (see -M)",
		   readWriteGlobals->bucketsAllocated[thread_id],
		   thread_id, readOnlyGlobals.maxNumActiveFlows);
	msgSent = 1;
      }
      readWriteGlobals->probeStats.droppedPktsTooManyFlows++;

      hash_unlock(__FILE__, __LINE__, hash_idx, mutex_idx);
      return;
    }

    bkt = allocFlowBucket(proto, thread_id, hash_idx, mutex_idx, idx);

    if(bkt == NULL) {
      static u_int8_t once = 0;

      if(!once) {
	traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)");
	once = 1;
      }

      hash_unlock(__FILE__, __LINE__, hash_idx, mutex_idx);
      return;
    }
  }

#ifdef ENABLE_MAGIC
  bkt->magic = 67;
#endif

  if(readOnlyGlobals.disableFlowCache) bkt->core.bucket_expired = 1;
  bkt->core.tuple.flow_idx = idx, bkt->core.tuple.flow_hash = packet_hash;
  memcpy(&bkt->core.tuple.src, src, sizeof(HostInfo)), memcpy(&bkt->core.tuple.dst, dst, sizeof(HostInfo));

  bkt->core.tuple.proto = proto, bkt->core.tuple.vlanId = vlanId,
    bkt->core.tuple.sport = sport, bkt->core.tuple.dport = dport;

  bkt->core.tuple.flowTimers.firstSeenSent.tv_sec = firstSeen.tv_sec, bkt->core.tuple.flowTimers.lastSeenSent.tv_sec = h->ts.tv_sec,
    bkt->core.tuple.flowTimers.firstSeenSent.tv_usec = firstSeen.tv_usec, bkt->core.tuple.flowTimers.lastSeenSent.tv_usec = h->ts.tv_usec;
  bkt->core.tuple.flowTimers.firstSeenRcvd.tv_sec = bkt->core.tuple.flowTimers.lastSeenRcvd.tv_sec = 0,
    bkt->core.tuple.flowTimers.firstSeenRcvd.tv_usec = bkt->core.tuple.flowTimers.lastSeenRcvd.tv_usec = 0;
  bkt->core.tuple.flowCounters.bytesSent += h->len, bkt->core.tuple.flowCounters.pktSent += numPkts;

  if(readOnlyGlobals.enable_l7_protocol_discovery)
    setPayload(bkt, h, p, ip_offset, payload, payloadLen, 0);

  addToList(bkt, &readWriteGlobals->theFlowHash[hash_idx][idx]);

#ifdef DEBUG_EXPORT
  traceEvent(TRACE_INFO, "Bucket added");
#endif

  idleThreadTask(thread_id);

  if(readOnlyGlobals.traceMode == 2) {
    char buf[256], buf1[256], src_buf[32], dst_buf[32];

    traceEvent(TRACE_INFO, "New Flow: [%s] %s:%d -> %s:%d",
	       proto2name(proto),
	       _intoa(*src, buf, sizeof(buf)), sport,
	       _intoa(*dst, buf1, sizeof(buf1)), dport);
  }

  if(readOnlyGlobals.disableFlowCache)
    bkt->core.bucket_expired = 1;

  hash_unlock(__FILE__, __LINE__, hash_idx, mutex_idx);

  if(unlikely(readOnlyGlobals.tracePerformance)) {
    ticks diff = getticks() - when;
    if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
    readOnlyGlobals.processingWithFlowCreationTicks += diff, readOnlyGlobals.num_pkts_with_flow_creation++;
    if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
  }
}

/* ****************************************************** */

void processFlowPacket(u_short thread_id,
		       int packet_if_idx /* -1 = unknown */,
		       u_int8_t proto, u_short numFragments,
		       u_int16_t ip_offset, u_int8_t sampledPacket,
		       u_short numPkts, u_int8_t tos, u_int8_t ttl,
		       u_short vlanId, u_int32_t tunnel_id, u_int16_t gtp_offset,
		       struct eth_header *ehdr,
		       IpAddress *src, u_short sport,
		       IpAddress *dst, u_short dport,
		       u_int8_t untunneled_proto,
		       IpAddress *untunneled_src, u_short untunneled_sport,
		       IpAddress *untunneled_dst, u_short untunneled_dport,
		       u_int len, u_int8_t tcpFlags,
		       u_int32_t tcpSeqNum, u_int32_t tcpAckNum,
		       u_int8_t icmpType, u_int8_t icmpCode,
		       u_short numMplsLabels,
		       u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
		       u_int16_t if_input, u_int16_t if_output,
		       struct pcap_pkthdr *h, u_char *p,
		       u_int16_t payload_shift, u_int payloadLen,
		       u_int originalPayloadLen,
		       time_t _firstSeen, /* Always set to 0 unless numPkts > 0 */
		       u_int32_t src_as, u_int32_t dst_as,
		       u_int16_t src_mask, u_int16_t dst_mask,
		       u_int32_t flow_sender_ip,
		       u_int32_t packet_hash) {
  u_char *payload = NULL;
  u_int32_t n = 0, mutex_idx, subflow_id = 0, realLen = sampledPacket ? (numPkts*len) : len;
  FlowHashBucket *bkt;
  struct timeval firstSeen;
  u_int32_t hash_idx, idx;
  FlowDirection direction;
  ticks when;
  u_int8_t is_request;
#ifdef ACCURATE_HASH
  struct flow_index to_index;
#endif

  if(unlikely(readOnlyGlobals.tracePerformance)) when = getticks();
  if(unlikely(readOnlyGlobals.ignoreVlan))       vlanId = 0;
  if(unlikely(readOnlyGlobals.ignoreProtocol))   proto = 0;
  if(unlikely(readOnlyGlobals.ignoreIP))         src->ipVersion = 4, src->ipType.ipv4 = 0, dst->ipVersion = 4, dst->ipType.ipv4 = 0;
  if(unlikely(readOnlyGlobals.ignorePorts))      sport = 0, dport = 0;
  if(unlikely(readOnlyGlobals.ignoreTos
	      || readOnlyGlobals.enableMySQLPlugin
	      || readOnlyGlobals.enableHttpPlugin
	      || readOnlyGlobals.enableOraclePlugin))
    tos = 0;

#ifdef ACCURATE_HASH
  if(src->ipVersion == 4) {
    to_index.srcHost = src->ipType.ipv4, to_index.dstHost = dst->ipType.ipv4;
  } else {
    to_index.srcHost = src->ipType.ipv6.s6_addr32[0] + src->ipType.ipv6.s6_addr32[1]
      + src->ipType.ipv6.s6_addr32[2] + src->ipType.ipv6.s6_addr32[3];
    to_index.dstHost = dst->ipType.ipv6.s6_addr32[0] + dst->ipType.ipv6.s6_addr32[1]
      + dst->ipType.ipv6.s6_addr32[2] + dst->ipType.ipv6.s6_addr32[3];
  }
  to_index.vlanId = vlanId, to_index.sport = sport, to_index.dport = dport, to_index.tos = tos,
    to_index.proto = proto, to_index.subflow_id = subflow_id;
#endif

  if(unlikely(readOnlyGlobals.enableDnsPlugin)) {
    if((proto == IPPROTO_UDP)
       && ((sport == 53) || (dport == 53))
       && (payloadLen > 2)) {
      u_int16_t transaction_id;

      memcpy(&transaction_id, &p[payload_shift], 2);
      transaction_id = ntohs(transaction_id);
      subflow_id = transaction_id;
    }
  }

  if(unlikely(readOnlyGlobals.enableRadiusPlugin)) {
    if((proto == IPPROTO_UDP)
       && ((sport == 1812) || (dport == 1812)    /* Start/Stop */
	   || (sport == 1813) || (dport == 1813) /* Accounting */
	   || (sport == 1645) || (dport == 1645) /* Start/Stop */
	   || (sport == 1646) || (dport == 1646) /* Accounting */
	   )
       && (payloadLen > 20)) {
      subflow_id = p[payload_shift+1] /* Packet Identifier */;
    }
  }

  if(unlikely(readOnlyGlobals.enableSipPlugin)) {
    if((proto == IPPROTO_UDP) && ((sport == 5060) || (dport == 5060)) && (payloadLen > 9)) {
      char *my_payload, *strtokState, *row;

      my_payload = malloc(payloadLen+1);
      if(my_payload != NULL) {

        memcpy(my_payload, &p[payload_shift], payloadLen);
        my_payload[payloadLen] = '\0';
        row = strtok_r((char*)my_payload, "\r\n", &strtokState);

        while (row != NULL) {
          if(!strncmp(row, "Call-ID: ", 8)) {
            u_int32_t hash = 0, c;
            char *call_id;

            call_id = &row[9];
            while (c = *call_id++)
              hash = c + (hash << 6) + (hash << 16) - hash;

            //traceEvent(TRACE_INFO, "Computing SIP HASH Call-ID=%s Hash=%u ", &row[9], hash);

            subflow_id = hash;
            break;
          }
          row = strtok_r(NULL, "\r\n", &strtokState);
        }

        free(my_payload);
      } else
        traceEvent(TRACE_ERROR, "Not enough memory?");
    }
  }

  h->caplen = min(h->caplen, readOnlyGlobals.snaplen);

  if(gtp_offset > 0) {
    struct gtp_header *gtp = (struct gtp_header*)&p[gtp_offset];

    subflow_id = ntohs(gtp->sequence_number);

    if((gtp->message_type == 0x10 /* Create Request  */)
       || (gtp->message_type == 0x12 /* Update Request  */)
       || (gtp->message_type == 0x14 /* Delete Request  */)) {
      /* We support IPv4 only  [TODO add IPv6 support] */
      packet_hash = gtp->sequence_number + src->ipType.ipv4, is_request = 1;
    } else if((gtp->message_type == 0x11 /* Create Response */)
	      || (gtp->message_type == 0x13 /* Update Response */)
	      || (gtp->message_type == 0x15 /* Delete Response */)) {
      /* We support IPv4 only [TODO add IPv6 support] */
      packet_hash = gtp->sequence_number + dst->ipType.ipv4, is_request = 0;
    } else
      gtp_offset = 0 /* unknown msg, we ignore GTP */, packet_hash = 0;
  }

  if(unlikely(packet_hash == 0)) {
#ifdef ACCURATE_HASH
    sortFlowIndex(&to_index); /* We need a symmetric hash value */
    packet_hash = hashVal((const u_int8_t*)&to_index, sizeof(to_index), readOnlyGlobals.numProcessThreads /* seed */);
#else
    {
      u_int32_t srcHost, dstHost;

      if(src->ipVersion == 4) {
	srcHost = src->ipType.ipv4, dstHost = dst->ipType.ipv4;
      } else {
	srcHost = src->ipType.ipv6.s6_addr32[0]+src->ipType.ipv6.s6_addr32[1]
	  +src->ipType.ipv6.s6_addr32[2]+src->ipType.ipv6.s6_addr32[3];
	dstHost = dst->ipType.ipv6.s6_addr32[0]+dst->ipType.ipv6.s6_addr32[1]
	  +dst->ipType.ipv6.s6_addr32[2]+dst->ipType.ipv6.s6_addr32[3];
      }

      packet_hash = vlanId+proto+srcHost+dstHost+sport+dport+tos;
    }
#endif
  }

  hash_idx = thread_id;

  idx = packet_hash % readOnlyGlobals.flowHashSize;

  if(_firstSeen == 0)
    firstSeen.tv_sec = h->ts.tv_sec, firstSeen.tv_usec = h->ts.tv_usec;
  else
    firstSeen.tv_sec = _firstSeen, firstSeen.tv_usec = 0;

  if(likely(readOnlyGlobals.pcapFile == NULL)) /* Live capture */
    readWriteGlobals->actTime.tv_sec = h->ts.tv_sec, readWriteGlobals->actTime.tv_usec = h->ts.tv_usec;

  if(payload_shift > 0) payload = &p[payload_shift];
  mutex_idx = idx % MAX_HASH_MUTEXES;

  // traceEvent(TRACE_INFO, "mutex_idx=%d", mutex_idx);
  // traceEvent(TRACE_NORMAL, "packet_hash=%u/hash_idx=%d/idx=%d", packet_hash, hash_idx, idx);

  /* The statement below guarantees that packets are serialized */
  hash_lock(__FILE__, __LINE__, hash_idx, mutex_idx);

  bkt = readWriteGlobals->theFlowHash[hash_idx][idx];

  while(bkt != NULL) {
#ifdef ENABLE_MAGIC
    if(bkt->magic != 67) {
      traceEvent(TRACE_ERROR, "Magic error detected (magic=%d)", bkt->magic);
    }
#endif

    if((!bkt->core.bucket_expired) && (bkt->core.tuple.flow_hash == packet_hash)) {
      if(((bkt->core.tuple.proto == proto)
	  && (bkt->core.tuple.vlanId == vlanId)
	  && (bkt->ext->subflow_id == subflow_id)
	  && (((bkt->core.tuple.sport == sport)
	       && (bkt->core.tuple.dport == dport)
	       /* Don't check TOS if we've not sent any packet (it can happen with resetBucketStats()) */
	       && ((bkt->core.tuple.flowCounters.pktSent == 0) || (bkt->ext->src2dstTos == tos))
	       && cmpIpAddress(&bkt->core.tuple.src, src)
	       && cmpIpAddress(&bkt->core.tuple.dst, dst)
	       )
	      ||
	      ((bkt->core.tuple.sport == dport)
	       && (bkt->core.tuple.dport == sport)
	       /* Don't check TOS if we've not seen any backward packet */
	       && ((bkt->core.tuple.flowCounters.pktRcvd == 0) || (bkt->ext->dst2srcTos == tos))
	       && cmpIpAddress(&bkt->core.tuple.src, dst)
	       && cmpIpAddress(&bkt->core.tuple.dst, src)
	       )))
	 || ((gtp_offset > 0)
	     && (bkt->ext->subflow_id == subflow_id)
	     && ((is_request && (src->ipType.ipv4 == bkt->core.tuple.src.ipType.ipv4))
		 || ((!is_request) && (dst->ipType.ipv4 == bkt->core.tuple.dst.ipType.ipv4))))
	 ) {
	if((bkt->core.tuple.sport == sport)
	   && cmpIpAddress(&bkt->core.tuple.src, src)) {
	  direction = src2dst_direction;
	} else {
	  direction = dst2src_direction;
	}

	if(bkt->ext->extensions && (gtp_offset > 0) && (!is_request)) {
	  memcpy(&bkt->ext->extensions->gtp.server_ip, src, sizeof(IpAddress));
	}

	if(unlikely(readOnlyGlobals.numProcessThreads > 1)) {
	  if(direction == src2dst_direction)
	    pthread_rwlock_wrlock(&bkt->ext->src2dstLock);
	  else
	    pthread_rwlock_wrlock(&bkt->ext->dst2srcLock);
	}

	if(likely(!bkt->ext->sampled_flow)) {
	  /* This flow has not been sampled */

	  if(proto == IPPROTO_TCP) {
	    /* We must do this here before we update the flow timers */
	    updateTcpSeq(&h->ts, bkt, direction, tcpFlags, tcpSeqNum, tcpAckNum, originalPayloadLen);
	  }

	  if(direction == src2dst_direction) {
	    /* src -> dst */
	    bkt->core.tuple.flowCounters.bytesSent += realLen, bkt->core.tuple.flowCounters.pktSent += numPkts;

	    /* NOTE: do not move the statement below after the time update below */
	    updatePktLenStats(bkt, direction, &h->ts, h->len);

	    if(bkt->core.tuple.flowTimers.firstSeenSent.tv_sec == 0)
	      bkt->core.tuple.flowTimers.firstSeenSent.tv_sec = h->ts.tv_sec, bkt->core.tuple.flowTimers.firstSeenSent.tv_usec = h->ts.tv_usec;

	    bkt->core.tuple.flowTimers.lastSeenSent.tv_sec = h->ts.tv_sec, bkt->core.tuple.flowTimers.lastSeenSent.tv_usec = h->ts.tv_usec;
	    if(numFragments > 0) bkt->ext->flowCounters.sentFragPkts += numFragments;

	    if(tos != 0) updateTos(bkt, 0, tos);
	    updateTTL(bkt, 0, ttl);
	    if(readOnlyGlobals.enable_l7_protocol_discovery)
	      setPayload(bkt, h, p, ip_offset, payload, payloadLen, 0);
	  } else {
	    /* dst -> src */

	    bkt->core.tuple.flowCounters.bytesRcvd += realLen, bkt->core.tuple.flowCounters.pktRcvd += numPkts;

	    /* NOTE: do not move the statement below after the time update below */
	    updatePktLenStats(bkt, direction, &h->ts, h->len);

	    if(((bkt->core.tuple.flowTimers.firstSeenRcvd.tv_sec == 0) && (bkt->core.tuple.flowTimers.firstSeenRcvd.tv_usec == 0))
	       || (to_msec(&firstSeen) < to_msec(&bkt->core.tuple.flowTimers.firstSeenRcvd)))
	      bkt->core.tuple.flowTimers.firstSeenRcvd.tv_sec = firstSeen.tv_sec, bkt->core.tuple.flowTimers.firstSeenRcvd.tv_usec = firstSeen.tv_usec;

	    bkt->core.tuple.flowTimers.lastSeenRcvd.tv_sec = h->ts.tv_sec, bkt->core.tuple.flowTimers.lastSeenRcvd.tv_usec = h->ts.tv_usec;
	    if(numFragments > 0) bkt->ext->flowCounters.rcvdFragPkts += numFragments;

	    if(tos != 0) updateTos(bkt, 1, tos);
	    updateTTL(bkt, 1, ttl);
	    if(readOnlyGlobals.enable_l7_protocol_discovery)
	      setPayload(bkt, h, p, ip_offset, payload, payloadLen, 1);
	  }

	  /* Sanity check */
	  if(payload == NULL) payloadLen = 0;

	  if(unlikely(readOnlyGlobals.num_active_plugins > 0))
	    pluginCallback(PACKET_CALLBACK, packet_if_idx,
			   bkt, direction,
			   ip_offset, proto, (numFragments > 0) ? 1 : 0,
			   numPkts, tos,
			   vlanId, ehdr, src, sport,
			   dst, dport, len,
			   tcpFlags, tcpSeqNum, icmpType, numMplsLabels,
			   mplsLabels, h, p, payload, payloadLen);
	}

	switch(proto) {
	case IPPROTO_TCP:
	  if(bkt->ext->extensions) {
	    updateTcpFlags(bkt, direction, &h->ts, tcpFlags);
	    /* NOTE: updateTcpSeq() has been already called above */

	    /* Do not move this line before updateTcpFlags(...) */
	    if(direction == src2dst_direction)
	      bkt->ext->protoCounters.tcp.src2dstTcpFlags |= tcpFlags;
	    else
	      bkt->ext->protoCounters.tcp.dst2srcTcpFlags |= tcpFlags;
	  }
	  break;

	case IPPROTO_UDP:
	  updateApplLatency(proto, bkt, direction, &h->ts);
	  break;
	}

	if(((direction == src2dst_direction) && (bkt->core.tuple.flowCounters.bytesSent > BYTES_WRAP_THRESHOLD))
	   || ((direction == dst2src_direction) && (bkt->core.tuple.flowCounters.bytesRcvd > BYTES_WRAP_THRESHOLD))) {
	  /*
	    The counter has a pretty high value: we better mark this flow as expired
	    in order to avoid wrapping the counter.
	  */
	  bkt->core.bucket_expired = 1;
	}

        /* Let's move this flow at the end of the idle flow list */
        if((readWriteGlobals->idleFlowListTail[hash_idx] != bkt)
           /* The list has only one element */
           && (readWriteGlobals->idleFlowListHead[hash_idx] != readWriteGlobals->idleFlowListTail[hash_idx])
           ) {
          /* We're not the last/first one of the list */

          /* 1 - Remove bkt from the list */
	  if(readWriteGlobals->idleFlowListHead[hash_idx] == readWriteGlobals->idleFlowListTail[hash_idx]) {
	    /* The list has only one element: me */
	    readWriteGlobals->idleFlowListHead[hash_idx] = readWriteGlobals->idleFlowListTail[hash_idx] = NULL;
	  } else if(readWriteGlobals->idleFlowListHead[hash_idx] == bkt) {
	    /* 1st Element of the list */
	    readWriteGlobals->idleFlowListHead[hash_idx] = bkt->core.no_traffic.next;
	    readWriteGlobals->idleFlowListHead[hash_idx]->core.no_traffic.prev = NULL;
	  } else if(readWriteGlobals->idleFlowListTail[hash_idx] == bkt) {
	    /* Last element of the list */
	    readWriteGlobals->idleFlowListTail[hash_idx] = bkt->core.no_traffic.prev;
	    readWriteGlobals->idleFlowListTail[hash_idx]->core.no_traffic.next = NULL;
	  } else {
	  /* Middle */
	    (bkt->core.no_traffic.prev)->core.no_traffic.next = bkt->core.no_traffic.next;
	    (bkt->core.no_traffic.next)->core.no_traffic.prev = bkt->core.no_traffic.prev;
	  }

          /* 2 - Append it at the end */
          readWriteGlobals->idleFlowListTail[hash_idx]->core.no_traffic.next = bkt;
          bkt->core.no_traffic.prev = readWriteGlobals->idleFlowListTail[hash_idx];
          bkt->core.no_traffic.next = NULL;
          readWriteGlobals->idleFlowListTail[hash_idx] = bkt;
        }

	if(unlikely(readOnlyGlobals.numProcessThreads > 1)) {
	  if(direction == src2dst_direction)
	    pthread_rwlock_unlock(&bkt->ext->src2dstLock);
	  else
	    pthread_rwlock_unlock(&bkt->ext->dst2srcLock);
	}

	bkt->ext->lastPktDirection = direction;

	if(unlikely(readOnlyGlobals.tracePerformance)) {
	  ticks diff = getticks() - when;
	  if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
	  readOnlyGlobals.processingWoFlowCreationTicks += diff, readOnlyGlobals.num_pkts_without_flow_creation++;
	  if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
	}
	idleThreadTask(thread_id);
	hash_unlock(__FILE__, __LINE__, hash_idx, mutex_idx);
	return;
      }
    }

    /* Bucket not found yet */
    n++, bkt = bkt->core.hash.next;
  } /* while */

  if(n > readWriteGlobals->maxBucketSearch) {
    readWriteGlobals->maxBucketSearch = n;
    // traceEvent(TRACE_NORMAL, "[maxBucketSearch=%d][hash_idx=%u][idx=%u]", readWriteGlobals->maxBucketSearch, hash_idx, idx);
  }

#ifdef DEBUG_EXPORT
  printf("Adding new bucket");
#endif

  if(bkt == NULL) {
    if(readWriteGlobals->bucketsAllocated[thread_id] >= readOnlyGlobals.maxNumActiveFlows) {
      static u_char msgSent = 0;

      if(!msgSent) {
	traceEvent(TRACE_WARNING, "WARNING: too many (%u) active flows [threadId=%u][limit=%u] (see -M)",
		   readWriteGlobals->bucketsAllocated[thread_id],
		   thread_id, readOnlyGlobals.maxNumActiveFlows);
	msgSent = 1;
      }
      readWriteGlobals->probeStats.droppedPktsTooManyFlows++;

      hash_unlock(__FILE__, __LINE__, hash_idx, mutex_idx);
      return;
    }

    bkt = allocFlowBucket(proto, thread_id, hash_idx, mutex_idx, idx);

    if(bkt == NULL) {
      static u_int8_t once = 0;

      if(!once) {
	traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)");
	once = 1;
      }

      hash_unlock(__FILE__, __LINE__, hash_idx, mutex_idx);
      return;
    }
  }

#ifdef ENABLE_MAGIC
  bkt->magic = 67;
#endif

  if(readOnlyGlobals.disableFlowCache) bkt->core.bucket_expired = 1;

  direction = src2dst_direction, bkt->core.tuple.flow_idx = idx, bkt->core.tuple.flow_hash = packet_hash;
  bkt->ext->lastPktDirection = direction;

  memcpy(&bkt->core.tuple.src, src, sizeof(HostInfo)), memcpy(&bkt->core.tuple.dst, dst, sizeof(HostInfo));
  updateHost(&bkt->ext->srcInfo, src, flow_sender_ip, if_input);
  updateHost(&bkt->ext->dstInfo, dst, 0 /* unknown */, NO_INTERFACE_INDEX);

  if(readOnlyGlobals.flowSampleRate > 1) {
    pthread_rwlock_wrlock(&readWriteGlobals->rwGlobalsRwLock);

    if(readWriteGlobals->flowsToGo <= 1) {
      readWriteGlobals->flowsToGo = readOnlyGlobals.flowSampleRate;
    } else {
      readWriteGlobals->flowsToGo--;
      bkt->ext->sampled_flow = 1;
    }

    pthread_rwlock_unlock(&readWriteGlobals->rwGlobalsRwLock);
  }

  bkt->ext->subflow_id = subflow_id,
    bkt->core.tuple.proto = proto, bkt->core.tuple.vlanId = vlanId, bkt->ext->tunnel_id = tunnel_id,
    bkt->core.tuple.sport = sport, bkt->core.tuple.dport = dport,
    bkt->ext->srcInfo.asn = src_as, bkt->ext->dstInfo.asn = dst_as,
    bkt->ext->srcInfo.mask = src_mask, bkt->ext->dstInfo.mask = dst_mask;

  /* Tunnels */
  if(unlikely(readOnlyGlobals.tunnel_mode)) {
    if(bkt->ext->extensions && untunneled_src && untunneled_dst) {
      memcpy(&bkt->ext->extensions->untunneled.src, untunneled_src, sizeof(IpAddress));
      memcpy(&bkt->ext->extensions->untunneled.dst, untunneled_dst, sizeof(IpAddress));
      bkt->ext->extensions->untunneled.proto = untunneled_proto;
      bkt->ext->extensions->untunneled.sport = untunneled_sport, bkt->ext->extensions->untunneled.dport = untunneled_dport;
    }
  }

  if(ehdr) {
    memcpy(bkt->ext->srcInfo.macAddress, (char *)ESRC(ehdr), 6);
    memcpy(bkt->ext->dstInfo.macAddress, (char *)EDST(ehdr), 6);
  }

  bkt->ext->if_input = if_input, bkt->ext->if_output = if_output,
  bkt->core.tuple.flowTimers.firstSeenSent.tv_sec = firstSeen.tv_sec, bkt->core.tuple.flowTimers.lastSeenSent.tv_sec = h->ts.tv_sec,
    bkt->core.tuple.flowTimers.firstSeenSent.tv_usec = firstSeen.tv_usec, bkt->core.tuple.flowTimers.lastSeenSent.tv_usec = h->ts.tv_usec;
  bkt->core.tuple.flowTimers.firstSeenRcvd.tv_sec = bkt->core.tuple.flowTimers.lastSeenRcvd.tv_sec = 0,
    bkt->core.tuple.flowTimers.firstSeenRcvd.tv_usec = bkt->core.tuple.flowTimers.lastSeenRcvd.tv_usec = 0;
  bkt->core.tuple.flowCounters.bytesSent += realLen, bkt->core.tuple.flowCounters.pktSent += numPkts;
  if(numFragments > 0) bkt->ext->flowCounters.sentFragPkts += numFragments;

  updatePktLenStats(bkt, direction, &h->ts, h->len);
  updateTTL(bkt, 0, ttl);
  if(tos != 0) updateTos(bkt, 0, tos);
  if(proto == IPPROTO_TCP) {
    updateTcpFlags(bkt, 0, &h->ts, tcpFlags);
    updateTcpSeq(&h->ts, bkt, 0, tcpFlags, tcpSeqNum, tcpAckNum, originalPayloadLen);
  } else if(proto == IPPROTO_UDP)
    updateApplLatency(proto, bkt, 0, &h->ts);
  else if((proto == IPPROTO_ICMP) || (proto == IPPROTO_ICMPV6)) {
    u_int16_t val = (256 * icmpType) + icmpCode;

    /* We "& 0x7F" as with IPv6 the codes will exceed the bitmask */
    if(direction == src2dst_direction) {
      bkt->ext->protoCounters.icmp.src2dstIcmpType = val;
      NPROBE_FD_SET(icmpType & 0x7F, &bkt->ext->protoCounters.icmp.src2dstIcmpFlags);
    } else {
      bkt->ext->protoCounters.icmp.dst2srcIcmpType = val;
      NPROBE_FD_SET(icmpType & 0x7F, &bkt->ext->protoCounters.icmp.dst2srcIcmpFlags);
    }
  }

  if(readOnlyGlobals.enable_l7_protocol_discovery)
    setPayload(bkt, h, p, ip_offset, payload, payloadLen, 0);

  bkt->ext->protoCounters.tcp.src2dstTcpFlags |= tcpFlags;

  if(bkt->ext->extensions && (numMplsLabels > 0)) {
    bkt->ext->extensions->mplsInfo = malloc(sizeof(struct mpls_labels));

    if(bkt->ext->extensions->mplsInfo) {
      bkt->ext->extensions->mplsInfo->numMplsLabels = numMplsLabels;
      memcpy(bkt->ext->extensions->mplsInfo->mplsLabels, mplsLabels,
	     MAX_NUM_MPLS_LABELS*MPLS_LABEL_LEN);
    } else
      traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)");
  }

  if(unlikely(readOnlyGlobals.num_active_plugins > 0))
    pluginCallback(CREATE_FLOW_CALLBACK, packet_if_idx,
		   bkt, src2dst_direction /* direction */,
		   ip_offset, proto, (numFragments > 0) ? 1 : 0,
		   numPkts,  tos,
		   vlanId, ehdr,
		   src,  sport,
		   dst,  dport, len,
		   tcpFlags, tcpSeqNum,
		   icmpType, numMplsLabels,
		   mplsLabels, h, p, payload, payloadLen);

  addToList(bkt, &readWriteGlobals->theFlowHash[hash_idx][idx]);

#ifdef DEBUG_EXPORT
  traceEvent(TRACE_INFO, "Bucket added");
#endif

  idleThreadTask(thread_id);

  if(readOnlyGlobals.traceMode == 2) {
    char buf[256], buf1[256], src_buf[32], dst_buf[32];

    traceEvent(TRACE_INFO, "New Flow: [%s] %s:%d -> %s:%d [%s -> %s][vlan %d][tos %d][ifIdx: %u -> %u][subflowId: %u/0x%04x]"
	       // "[idx=%u][packet_hash=%u]"
	       ,
	       proto2name(proto),
	       _intoa(*src, buf, sizeof(buf)), sport,
	       _intoa(*dst, buf1, sizeof(buf1)), dport,
	       etheraddr_string(bkt->ext->srcInfo.macAddress, src_buf),
	       etheraddr_string(bkt->ext->dstInfo.macAddress, dst_buf),
	       vlanId, tos, bkt->ext->if_input, bkt->ext->if_output,
	       bkt->ext->subflow_id, bkt->ext->subflow_id
	       //, idx, packet_hash
	       );
  }

  if(readOnlyGlobals.disableFlowCache)
    bkt->core.bucket_expired = 1;

  hash_unlock(__FILE__, __LINE__, hash_idx, mutex_idx);

  if(unlikely(readOnlyGlobals.tracePerformance)) {
    ticks diff = getticks() - when;
    if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
    readOnlyGlobals.processingWithFlowCreationTicks += diff, readOnlyGlobals.num_pkts_with_flow_creation++;
    if(unlikely(readOnlyGlobals.numProcessThreads > 1)) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
  }
}

/* ****************************************************** */

#define	NPROBE_ICMP_V6_ECHO_REQUEST   128		/* V6 echo request */
#define	NPROBE_ICMP_V6_ECHO_REPLY     129		/* V6 echo reply */
#define	NPROBE_ICMP_V6_ROUTER_SOL     133		/* V6 router solicitation */
#define	NPROBE_ICMP_V6_ROUTER_ADV     134		/* V6 router advertisement */
#define	NPROBE_ICMP_V6_NEIGHBOR_SOL   135		/* V6 neighbor solicitation */
#define	NPROBE_ICMP_V6_NEIGHBOR_ADV   136		/* V6 neighbor advertisement */
#define	NPROBE_ICMP_V6_MDPV2          143		/* V6 Multicast Listener Report Message v2 */


void printICMPflags(u_int8_t proto, u_int32_t flags, char *icmpBuf, int icmpBufLen) {

  if(proto == IPPROTO_ICMPV6) {
    snprintf(icmpBuf, icmpBufLen, "%s%s%s%s%s%s%s",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_ECHO_REQUEST & 0x7F, &flags)     ? "[ECHO REQUEST]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_ECHO_REPLY & 0x7F, &flags)     ? "[ECHO REPLY]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_ROUTER_SOL & 0x7F, &flags)     ? "[ROUTER SOLIC]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_ROUTER_ADV & 0x7F, &flags)     ? "[ROUTER ADV]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_NEIGHBOR_SOL & 0x7F, &flags)     ? "[NEIGHBOR SOLIC]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_NEIGHBOR_ADV & 0x7F, &flags)     ? "[NEIGHBOR ADV]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_MDPV2 & 0x7F, &flags)     ? "[MDP V2]" : ""
	     );
  } else {
    snprintf(icmpBuf, icmpBufLen, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	     NPROBE_FD_ISSET(NPROBE_ICMP_ECHOREPLY, &flags)     ? "[ECHO REPLY]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_UNREACH, &flags)       ? "[UNREACH]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_SOURCEQUENCH, &flags)  ? "[SOURCE_QUENCH]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_REDIRECT, &flags)      ? "[REDIRECT]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_ECHO, &flags)          ? "[ECHO]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_ROUTERADVERT, &flags)  ? "[ROUTERADVERT]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_ROUTERSOLICIT, &flags) ? "[ROUTERSOLICIT]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_TIMXCEED, &flags)      ? "[TIMXCEED]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_PARAMPROB, &flags)     ? "[PARAMPROB]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_TSTAMP, &flags)        ? "[TIMESTAMP]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_TSTAMPREPLY, &flags)   ? "[TIMESTAMP REPLY]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_IREQ, &flags)          ? "[INFO REQ]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_IREQREPLY, &flags)     ? "[INFO REPLY]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_MASKREQ , &flags)      ? "[MASK REQ]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_MASKREPLY, &flags)     ? "[MASK REPLY]": "");
  }
}

/* ****************************************************** */

void printFlow(FlowHashBucket *theFlow, FlowDirection direction) {
  char buf[256] = { 0 }, buf1[256] = { 0 }, latBuf[48] = { 0 };
  char vlanStr[16] = { 0 }, tunnelStr[32] = { 0 }, fragmented[32] =  { 0 };
  char icmpBuf[128] = { 0 }, applLatBuf[48] = { 0 }, jitterStr[64] = { 0 };
  char subflowStr[32] = { 0 }, l7proto[32] = { 0 };
  float time_diff;

  if(theFlow->ext) {
    if(((direction == src2dst_direction) && (theFlow->ext->flowCounters.sentFragPkts > 0))
       || ((direction == dst2src_direction) && (theFlow->ext->flowCounters.rcvdFragPkts > 0))) {
      snprintf(fragmented, sizeof(fragmented), "[%u FRAGMENT(S)]",
	       (direction == src2dst_direction) ? theFlow->ext->flowCounters.sentFragPkts
	       : theFlow->ext->flowCounters.rcvdFragPkts);
  }

    if(nwLatencyComputed(theFlow->ext)
       && theFlow->ext
       && ((theFlow->ext->extensions->clientNwDelay.tv_sec > 0) || (theFlow->ext->extensions->clientNwDelay.tv_usec > 0))) {
      snprintf(latBuf, sizeof(latBuf), "[CND: %.2f ms]",
	       (float)(theFlow->ext->extensions->clientNwDelay.tv_sec*1000+(float)theFlow->ext->extensions->clientNwDelay.tv_usec/1000));
    }

    if(nwLatencyComputed(theFlow->ext)
     && theFlow->ext
     && ((theFlow->ext->extensions->serverNwDelay.tv_sec > 0) || (theFlow->ext->extensions->serverNwDelay.tv_usec > 0))) {
    int len = strlen(latBuf);

    snprintf(&latBuf[len], sizeof(latBuf)-len, "[SND: %.2f ms]",
	     (float)(theFlow->ext->extensions->serverNwDelay.tv_sec*1000+(float)theFlow->ext->extensions->serverNwDelay.tv_usec/1000));
  }

  if(applLatencyComputed(theFlow->ext)
     && theFlow->ext) {
    if((direction == src2dst_direction)
       && (theFlow->ext->extensions->src2dstApplLatency.tv_sec || theFlow->ext->extensions->src2dstApplLatency.tv_usec))
      snprintf(applLatBuf, sizeof(applLatBuf), "[A: %.2f ms]",
	       timeval2ms(&theFlow->ext->extensions->src2dstApplLatency));
    else if((direction == dst2src_direction)
	    && (theFlow->ext->extensions->dst2srcApplLatency.tv_sec || theFlow->ext->extensions->dst2srcApplLatency.tv_usec))
      snprintf(applLatBuf, sizeof(applLatBuf), "[A: %.2f ms]",
	       timeval2ms(&theFlow->ext->extensions->dst2srcApplLatency));
  }


  if((theFlow->core.tuple.proto == IPPROTO_ICMP) || (theFlow->core.tuple.proto == IPPROTO_ICMPV6)) {
    if(direction == src2dst_direction)
      printICMPflags(theFlow->core.tuple.proto, theFlow->ext->protoCounters.icmp.src2dstIcmpFlags, icmpBuf, sizeof(icmpBuf));
    else
      printICMPflags(theFlow->core.tuple.proto, theFlow->ext->protoCounters.icmp.dst2srcIcmpFlags, icmpBuf, sizeof(icmpBuf));
  }

  if(theFlow->ext->tunnel_id == 0)
    tunnelStr[0] = '\0';
  else
    snprintf(tunnelStr, sizeof(tunnelStr), "[TunnelId 0x%08X]", theFlow->ext->tunnel_id);

  if(theFlow->ext->subflow_id == 0)
    subflowStr[0] = '\0';
  else
    snprintf(subflowStr, sizeof(subflowStr), "[SubflowId %u/0x%04x]",
	     theFlow->ext->subflow_id, theFlow->ext->subflow_id);
}

  if((theFlow->core.tuple.vlanId == 0) || (theFlow->core.tuple.vlanId == NO_VLAN))
    vlanStr[0] = '\0';
  else
    snprintf(vlanStr, sizeof(vlanStr), "[VLAN %u]", theFlow->core.tuple.vlanId);

  if(readOnlyGlobals.enable_l7_protocol_discovery) {
    /* if(theFlow->l7.proto != IPOQUE_PROTOCOL_UNKNOWN)  */
    {
      char *prot_long_str[] = { IPOQUE_PROTOCOL_LONG_STRING };

      snprintf(l7proto, sizeof(l7proto), "[%s]", prot_long_str[theFlow->core.l7.proto]);
    }
  }

  if(direction == src2dst_direction) {
    time_diff = (readOnlyGlobals.collectorInPort > 0) ? 0 :
      (float)msTimeDiff(&theFlow->core.tuple.flowTimers.lastSeenSent,
			&theFlow->core.tuple.flowTimers.firstSeenSent)/1000;

    if(!readOnlyGlobals.bidirectionalFlows)
      traceEvent(TRACE_INFO, "Emitting Flow: [->][%s] %s:%d -> %s:%d %s[%u pkt/%u bytes][ifIdx %d->%d][duration %.1f sec]%s%s%s%s%s%s%s%s",
		 proto2name(theFlow->core.tuple.proto),
		 _intoa(theFlow->core.tuple.src, buf, sizeof(buf)), theFlow->core.tuple.sport,
		 _intoa(theFlow->core.tuple.dst, buf1, sizeof(buf1)), theFlow->core.tuple.dport,
		 subflowStr,
		 (int)theFlow->core.tuple.flowCounters.pktSent, (int)theFlow->core.tuple.flowCounters.bytesSent,
		 theFlow->ext ? theFlow->ext->if_input : 0,
		 theFlow->ext ? theFlow->ext->if_output : 0, time_diff,
		 latBuf, applLatBuf, jitterStr, icmpBuf, fragmented, vlanStr, tunnelStr, l7proto);
    else
      traceEvent(TRACE_INFO, "Emitting Flow: [<->][%s] %s:%d -> %s:%d %s[%u/%u pkt][%u/%u bytes][ifIdx %d<->%d][%.1f sec]%s%s%s%s%s%s%s%s",
		 proto2name(theFlow->core.tuple.proto),
		 _intoa(theFlow->core.tuple.src, buf, sizeof(buf)), theFlow->core.tuple.sport,
		 _intoa(theFlow->core.tuple.dst, buf1, sizeof(buf1)), theFlow->core.tuple.dport,
		 subflowStr,
	 	 (int)theFlow->core.tuple.flowCounters.pktSent, (int)theFlow->core.tuple.flowCounters.pktRcvd,
		 (int)theFlow->core.tuple.flowCounters.bytesSent, (int)theFlow->core.tuple.flowCounters.bytesRcvd,
		 theFlow->ext ? theFlow->ext->if_input : 0,
		 theFlow->ext ? theFlow->ext->if_output : 0, time_diff,
		 latBuf, applLatBuf, jitterStr, icmpBuf, fragmented, vlanStr, tunnelStr, l7proto);
  } else {
    time_diff = (readOnlyGlobals.collectorInPort > 0) ? 0 : (float)msTimeDiff(&theFlow->core.tuple.flowTimers.lastSeenRcvd,
									      &theFlow->core.tuple.flowTimers.firstSeenRcvd)/1000;

    traceEvent(TRACE_INFO, "Emitting Flow: [<-][%s] %s:%d -> %s:%d %s[%u pkt/%u bytes][ifIdx %d->%d][%.1f sec]%s%s%s%s%s%s%s%s",
	       proto2name(theFlow->core.tuple.proto),
	       _intoa(theFlow->core.tuple.dst, buf, sizeof(buf)), theFlow->core.tuple.dport,
	       _intoa(theFlow->core.tuple.src, buf1, sizeof(buf1)), theFlow->core.tuple.sport, subflowStr,
	       (int)theFlow->core.tuple.flowCounters.pktRcvd, (int)theFlow->core.tuple.flowCounters.bytesRcvd,
	       theFlow->ext ? theFlow->ext->if_output : 0,
	       theFlow->ext ? theFlow->ext->if_input : 0, time_diff,
	       latBuf, applLatBuf, jitterStr, icmpBuf, fragmented, vlanStr, tunnelStr, l7proto);
  }
}

/* ****************************************************** */

u_int8_t endTcpFlow(unsigned short flags) {
  if(((flags & (TH_FIN | TH_ACK)) == (TH_FIN | TH_ACK))
     || ((flags & TH_RST) == TH_RST))
    return(1);
  else
    return(0);
}

/* ****************************************************** */

int isFlowExpired(FlowHashBucket *myBucket, time_t theTime) {
  if(myBucket->core.bucket_expired /* Forced expire */
     || ((theTime-myBucket->core.tuple.flowTimers.lastSeenSent.tv_sec)  >= readOnlyGlobals.idleTimeout)      /* flow expired: data not sent for a while */
     || ((theTime-myBucket->core.tuple.flowTimers.firstSeenSent.tv_sec) >= readOnlyGlobals.lifetimeTimeout)  /* flow expired: flow active but too old   */
     || ((myBucket->core.tuple.flowCounters.pktRcvd > 0)
	 && (((theTime-myBucket->core.tuple.flowTimers.lastSeenRcvd.tv_sec) >= readOnlyGlobals.idleTimeout)  /* flow expired: data not sent for a while */
	     || ((theTime-myBucket->core.tuple.flowTimers.firstSeenRcvd.tv_sec) >= readOnlyGlobals.lifetimeTimeout)))  /* flow expired: flow active but too old   */
     || ((myBucket->core.tuple.proto == IPPROTO_TCP) && (theTime-myBucket->core.tuple.flowTimers.lastSeenSent.tv_sec > 10 /* sec */)
	 && (myBucket->ext && endTcpFlow(myBucket->ext->protoCounters.tcp.src2dstTcpFlags))
	     && (myBucket->ext && endTcpFlow(myBucket->ext->protoCounters.tcp.dst2srcTcpFlags)))
     /* Checks for avoiding that bad time on received flows
	(e.g. via logs) can create problems with export */
     || (theTime < myBucket->core.tuple.flowTimers.lastSeenSent.tv_sec)
     || ((myBucket->core.tuple.flowCounters.pktRcvd > 0)
	 && (theTime < myBucket->core.tuple.flowTimers.lastSeenRcvd.tv_sec))
     /* This should not happen but let's take into account */
     || (theTime < myBucket->core.tuple.flowTimers.firstSeenSent.tv_sec)
     || (theTime < myBucket->core.tuple.flowTimers.firstSeenRcvd.tv_sec)
     ) {
    return(1);
  } else {
    /* if(hashDebug) printBucket(myBucket); */
    return(0);
  }
}

/* ****************************************************** */

int isFlowExpiredSinceTooLong(FlowHashBucket *myBucket, time_t theTime) {
  if(myBucket->core.bucket_expired /* Forced expire */
     || ((theTime-myBucket->core.tuple.flowTimers.lastSeenSent.tv_sec)  >= 2*readOnlyGlobals.idleTimeout)      /* flow expired: data not sent for a while */
     || ((theTime-myBucket->core.tuple.flowTimers.firstSeenSent.tv_sec) >= 2*readOnlyGlobals.lifetimeTimeout)  /* flow expired: flow active but too old   */
     || ((myBucket->core.tuple.flowCounters.pktRcvd > 0)
	 && (((theTime-myBucket->core.tuple.flowTimers.lastSeenRcvd.tv_sec) >= 2*readOnlyGlobals.idleTimeout)  /* flow expired: data not sent for a while */
	     || ((theTime-myBucket->core.tuple.flowTimers.firstSeenRcvd.tv_sec) >= 2*readOnlyGlobals.lifetimeTimeout)))  /* flow expired: flow active but too old   */
     ) {
    return(1);
  } else {
    /* if(hashDebug) printBucket(myBucket); */
    return(0);
  }
}

/* ****************************************************** */

void printBucket(FlowHashBucket *myBucket) {
  char str[128], str1[128];
  int a = time(NULL)-myBucket->core.tuple.flowTimers.firstSeenSent.tv_sec;
  int b = time(NULL)-myBucket->core.tuple.flowTimers.lastSeenSent.tv_sec;
  int c = myBucket->core.tuple.flowCounters.bytesRcvd ? time(NULL)-myBucket->core.tuple.flowTimers.firstSeenRcvd.tv_sec : 0;
  int d = myBucket->core.tuple.flowCounters.bytesRcvd ? time(NULL)-myBucket->core.tuple.flowTimers.lastSeenRcvd.tv_sec : 0;

#ifdef DEBUG
  if((a > 30) || (b>30) || (c>30) || (d>30))
#endif
    {
      printf("[%4s] %s:%d [%u pkts] <-> %s:%d [%u pkts] [FsSent=%d][LsSent=%d][FsRcvd=%d][LsRcvd=%d]\n",
	     proto2name(myBucket->core.tuple.proto),
	     _intoa(myBucket->core.tuple.src, str, sizeof(str)),
	     myBucket->core.tuple.sport, myBucket->core.tuple.flowCounters.pktSent,
	     _intoa(myBucket->core.tuple.dst, str1, sizeof(str1)),
	     myBucket->core.tuple.dport, myBucket->core.tuple.flowCounters.pktRcvd,
	     a, b, c, d);
    }
}

/* ******************************************************** */

/* NOTE: this function should not be called by a separate thread */
void walkHash(u_int32_t hash_idx, int flushHash) {
  if(readWriteGlobals->expireFlowListHead[hash_idx] != NULL) {
    if(flushHash) traceEvent(TRACE_NORMAL, "About to flush hash (threadId %d)", hash_idx);
    walkHashList(hash_idx, flushHash, readWriteGlobals->now);
    if(flushHash) traceEvent(TRACE_NORMAL, "Completed hash walk (thread %d)", hash_idx);
  }
}

/* ****************************************************** */

#ifdef HAVE_SQLITE
void sqlite_exec_sql(char* sql) {
  int rc;
  char *zErrMsg = 0;

  if(readWriteGlobals->sqlite3Handler == NULL) {
    traceEvent(TRACE_ERROR, "NULL sqlite3 handler [%s]", sql);
    return;
  }

  rc = sqlite3_exec(readWriteGlobals->sqlite3Handler, sql, NULL, 0, &zErrMsg);
  if(rc != SQLITE_OK) {
    traceEvent(TRACE_ERROR, "SQL error: %s [%s]", sql, zErrMsg);
    sqlite3_free(zErrMsg);
  }
}
#endif

/* ****************************************************** */

void close_dump_file() {
  char newPath[512]; /* same size as dumpFilePath */
  int len = strlen(readWriteGlobals->dumpFilePath)-strlen(TEMP_PREFIX);

  switch(readOnlyGlobals.dumpFormat) {
#ifdef HAVE_SQLITE
  case sqlite_format:
    if(readWriteGlobals->sqlite3Handler != NULL) {
      sqlite_exec_sql("commit;");
      sqlite3_close(readWriteGlobals->sqlite3Handler);
      readWriteGlobals->sqlite3Handler = NULL;
      traceEvent(TRACE_NORMAL, "Insert %u rows into the saved database",
		 readWriteGlobals->sql_row_idx);
    }
    break;
#endif

  case binary_format:
  case text_format:
  case binary_core_flow_format:
    if(readWriteGlobals->flowFd != NULL)
      fclose(readWriteGlobals->flowFd);
    break;
  }

  if(readWriteGlobals->dumpFilePath[0] != '\0') {
    strncpy(newPath, readWriteGlobals->dumpFilePath, len); newPath[len] = '\0';
    rename(readWriteGlobals->dumpFilePath, newPath);
    traceEvent(TRACE_NORMAL, "Flow file '%s' is now available", newPath);
    readWriteGlobals->flowFd = NULL;
  }
}

/* ****************************************************** */

#ifdef HAVE_GEOIP
void geoLocate(IpAddress *addr, HostInfo *bkt) {

  if((readOnlyGlobals.geo_ip_city_db == NULL)
     || (bkt->geo != NULL))
    return;

  pthread_rwlock_wrlock(&readWriteGlobals->geoipRwLock);
  if(addr->ipVersion == 4)
    bkt->geo = GeoIP_record_by_ipnum(readOnlyGlobals.geo_ip_city_db, addr->ipType.ipv4);
#ifdef HAVE_GEOIP_IPv6
  else if((addr->ipVersion == 6) && readOnlyGlobals.geo_ip_city_db_v6)
    bkt->geo = GeoIP_record_by_ipnum_v6(readOnlyGlobals.geo_ip_city_db_v6, addr->ipType.ipv6);
#endif

  pthread_rwlock_unlock(&readWriteGlobals->geoipRwLock);
}
#endif

/* ****************************************************** */

/*
  NOTE

  A flow might call exportBucket() several times for instance if it
  expires before the expected time.

  So before allocating memory into exportBucket() make sure that
  you're not allocating it several times
*/
void exportBucket(FlowHashBucket *myBucket, u_char free_memory) {
  int rc = 0;

  if(unlikely(readOnlyGlobals.demo_mode && readOnlyGlobals.demo_expired))
    return;

  if(unlikely(readOnlyGlobals.l7.discard_unknown_flows > 0)) {
    if(readOnlyGlobals.enable_l7_protocol_discovery
       && (myBucket->core.l7.proto == IPOQUE_PROTOCOL_UNKNOWN)
       && myBucket->core.l7.flow)
      myBucket->core.l7.proto = ntop_guess_undetected_protocol(myBucket->core.tuple.proto,
							       myBucket->core.tuple.src.ipType.ipv4,
							       myBucket->core.tuple.sport,
							       myBucket->core.tuple.dst.ipType.ipv4,
							       myBucket->core.tuple.dport);

    switch(readOnlyGlobals.l7.discard_unknown_flows) {
    case 1: /* Export only known flows */
      if(myBucket->core.l7.proto == IPOQUE_PROTOCOL_UNKNOWN)
	return;
      break;
    case 2: /* Export only unknown flows */
      if(myBucket->core.l7.proto != IPOQUE_PROTOCOL_UNKNOWN)
	return;
      break;
    }
  }

  /* Pre-export activities */
  if(myBucket->ext) {
    if(myBucket->ext->if_input == NO_INTERFACE_INDEX)  myBucket->ext->if_input = ifIdx(myBucket, 1);
    if(myBucket->ext->if_output == NO_INTERFACE_INDEX) myBucket->ext->if_output = ifIdx(myBucket, 0);
  }

  pthread_rwlock_wrlock(&readWriteGlobals->exportRwLock);

#ifdef HAVE_GEOIP
  if(readOnlyGlobals.geo_ip_city_db != NULL) {
    /* We need to geo-locate this flow */
    geoLocate(&myBucket->core.tuple.src, &myBucket->ext->srcInfo);
    geoLocate(&myBucket->core.tuple.dst, &myBucket->ext->dstInfo);
  }
#endif

  /* traceEvent(TRACE_NORMAL, "exportBucket(fd=%p)", readWriteGlobals->flowFd); */

  if(unlikely(readOnlyGlobals.dirPath != NULL)) {
    time_t theTime = time(NULL);
    static time_t lastTheTime = 0;
    struct tm *tm;
    char creation_time[256], dir_path[256];

    theTime -= (theTime % readOnlyGlobals.file_dump_timeout);

    if(lastTheTime != theTime) {
      close_dump_file();
      lastTheTime = theTime;
    }

    if((readWriteGlobals->flowFd == NULL)
#ifdef HAVE_SQLITE
       && (readWriteGlobals->sqlite3Handler == NULL)
#endif
       ) {
      tm = localtime(&theTime);

      strftime(creation_time, sizeof(creation_time), "%Y/%m/%d/%H", tm);
      snprintf(dir_path, sizeof(dir_path), "%s%c%s",
	       readOnlyGlobals.dirPath, CONST_DIR_SEP, creation_time);

      mkdir_p(dir_path);

      snprintf(readWriteGlobals->dumpFilePath,
	       sizeof(readWriteGlobals->dumpFilePath),
	       "%s%c%s%c%02d.%s%s",
	       readOnlyGlobals.dirPath, '/', creation_time, '/',
	       tm->tm_min - (tm->tm_min % ((readOnlyGlobals.file_dump_timeout+59)/60)),
#ifdef HAVE_SQLITE
	       (readOnlyGlobals.dumpFormat == sqlite_format) ? "sqlite" : "flows",
#else
	       "flows",
#endif
	       TEMP_PREFIX);

#ifdef WIN32
      revertSlash(readWriteGlobals->dumpFilePath, 0);
#endif

#ifdef HAVE_SQLITE
      if(readOnlyGlobals.dumpFormat == sqlite_format) {
	traceEvent(TRACE_NORMAL, "About to open database %s", readWriteGlobals->dumpFilePath);

	if(sqlite3_open(readWriteGlobals->dumpFilePath, &readWriteGlobals->sqlite3Handler) != 0) {
	  traceEvent(TRACE_WARNING, "WARNING: Unable to create database %s' [%s]",
		     readWriteGlobals->dumpFilePath, sqlite3_errmsg(readWriteGlobals->sqlite3Handler));
	  sqlite3_close(readWriteGlobals->sqlite3Handler);
	  readWriteGlobals->sqlite3Handler = NULL;
	} else {
	  int i;
	  char sql_buffer[2048] = { '\0' };

	  traceEvent(TRACE_NORMAL, "Saving flows into temporary database '%s'",
		     readWriteGlobals->dumpFilePath);
	  snprintf(sql_buffer, sizeof(sql_buffer), "begin; create table flows (");

	  /* Dump header */
	  for(i=0; i<TEMPLATE_LIST_LEN; i++) {
	    if(readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[i] != NULL) {
	      if(i > 0) snprintf(&sql_buffer[strlen(sql_buffer)], sizeof(sql_buffer)-strlen(sql_buffer), ", ");
	      snprintf(&sql_buffer[strlen(sql_buffer)], sizeof(sql_buffer)-strlen(sql_buffer),
		       "%s %s",
		       readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[i]->netflowElementName,
		       (readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[i]->templateElementLen <= 4) ? "number" : "string");
	    } else
	      break;
	  }

	  snprintf(&sql_buffer[strlen(sql_buffer)], sizeof(sql_buffer)-strlen(sql_buffer), ")");
	  sqlite_exec_sql(sql_buffer);
	}
      }
#endif

      if((readOnlyGlobals.dumpFormat == text_format)
	 || (readOnlyGlobals.dumpFormat == binary_format)
	 || (readOnlyGlobals.dumpFormat == binary_core_flow_format)
	 ) {
	if((readWriteGlobals->flowFd = fopen(readWriteGlobals->dumpFilePath, "w+b")) == NULL) {
	  traceEvent(TRACE_WARNING, "WARNING: Unable to create file '%s' [errno=%d]",
		     readWriteGlobals->dumpFilePath, errno);
	} else {
	  int i;

	  traceEvent(TRACE_NORMAL, "Saving flows into temporary file '%s'",
		     readWriteGlobals->dumpFilePath);

	  /* Dump header */
	  if(readOnlyGlobals.dumpFormat == text_format) {
	    for(i=0; i<TEMPLATE_LIST_LEN; i++) {
	      if(readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[i] != NULL) {
		if(i > 0)
		  fprintf(readWriteGlobals->flowFd, "%s", readOnlyGlobals.csv_separator);
		fprintf(readWriteGlobals->flowFd, "%s",
			readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[i]->netflowElementName);
	      } else
		break;
	    }

	    fprintf(readWriteGlobals->flowFd, "\n");
	  }
	}
      }

      readWriteGlobals->sql_row_idx = 0;
    }
  }

  if((myBucket->core.tuple.proto != TCP_PROTOCOL)
     || (myBucket->core.tuple.flowCounters.bytesSent >= readOnlyGlobals.minFlowSize)) {
    exportBucketToNetflow(myBucket, 0 /* src -> dst */);
  }

  /* *********************** */

  if((readOnlyGlobals.netFlowVersion == 5)
     || ((readOnlyGlobals.netFlowVersion != 5) && (!readOnlyGlobals.bidirectionalFlows))) {
    if(myBucket->core.tuple.flowCounters.bytesRcvd > 0) {
      /*
	v9 flows do not need to be exported twice, once per direction
	as they are bi-directional. However if the flow format does not
	contain bi-directional info (e.g. IN_BYTES, OUT_BYTES) the two
	flow directions need to be sent anyway. Hence we decide to send
	both flow directions
      */

      if((myBucket->core.tuple.proto != TCP_PROTOCOL)
	 || (myBucket->core.tuple.flowCounters.bytesRcvd >= readOnlyGlobals.minFlowSize)) {
	exportBucketToNetflow(myBucket, 1 /* dst -> src */);
      }
    }
  }

  if(free_memory) {
    if(unlikely(readOnlyGlobals.num_active_plugins > 0))
      pluginCallback(DELETE_FLOW_CALLBACK,
		     -1 /* packet_if_idx, -1 = unknown */,
		     myBucket, 0,
		     0, 0, 0,
		     0, 0,
		     0, NULL,
		     NULL, 0,
		     NULL, 0,
		     0,
		     0, 0, 0, 0, NULL,
		     NULL, NULL, NULL, 0);
  }

  pthread_rwlock_unlock(&readWriteGlobals->exportRwLock);
}

/* ****************************************************** */

void discardBucket(FlowHashBucket *myBucket) {
  readWriteGlobals->probeStats.totFlowBytesDropped +=
    myBucket->core.tuple.flowCounters.bytesSent + myBucket->core.tuple.flowCounters.bytesRcvd;
  readWriteGlobals->probeStats.totFlowPktsDropped +=
    myBucket->core.tuple.flowCounters.pktSent + myBucket->core.tuple.flowCounters.pktRcvd;

  if(unlikely(readOnlyGlobals.num_active_plugins > 0))
    pluginCallback(DELETE_FLOW_CALLBACK,
		   -1 /* packet_if_idx, -1 = unknown */,
		   myBucket, 0,
		   0, 0, 0,
		   0, 0,
		   0, NULL,
		   NULL, 0,
		   NULL, 0,
		   0,
		   0, 0, 0, 0, NULL,
		   NULL, NULL, NULL, 0);

  purgeBucket(myBucket);
}

/* ****************************************************** */

void queueBucketToExport(FlowHashBucket *myBucket) {
  if(readWriteGlobals->exportBucketsLen > MAX_EXPORT_QUEUE_LEN) {
    static char show_message = 0;

    if(!show_message) {
      if(readOnlyGlobals.flowExportDelay > 0) {
	traceEvent(TRACE_WARNING,
		   "Too many (%u) queued buckets for export: bucket discarded.",
		   readWriteGlobals->exportBucketsLen);
	traceEvent(TRACE_WARNING, "Please check -e value and decrease it.");
	show_message = 1;
      }
    }

    discardBucket(myBucket);
  } else {
    pthread_rwlock_wrlock(&readWriteGlobals->exportMutex);
    addToList(myBucket, &readWriteGlobals->exportQueue);
    readWriteGlobals->exportBucketsLen++;
#ifdef DEBUG
    traceEvent(TRACE_NORMAL, "[+] [exportBucketsLen=%d][myBucket=%p]",
	       readWriteGlobals->exportBucketsLen, myBucket);
#endif
    pthread_rwlock_unlock(&readWriteGlobals->exportMutex);
  }
}

/* ****************************************************** */

void* dequeueBucketToExport(void* notUsed) {
  u_int num_exported = 0;

  traceEvent(TRACE_INFO, "Starting bucket dequeue thread");

  readOnlyGlobals.dequeueBucketToExport_up = 1;

  while(1 /* !readWriteGlobals->shutdownInProgress */) {
#if 0
    if(unlikely(readOnlyGlobals.enable_debug))
      traceEvent(TRACE_NORMAL, "dequeueBucketToExport()");
#endif

    if(readWriteGlobals->exportQueue == NULL) {
      if(!readWriteGlobals->shutdownInProgress) {
	/* traceEvent(TRACE_INFO, "About to call waitCondvar()"); */
	waitCondvar(&readWriteGlobals->exportQueueCondvar);
	/* traceEvent(TRACE_INFO, "waitCondvar() called"); */
	num_exported = 0;
      } else
	break;
    }

    if(readWriteGlobals->exportQueue != NULL) {
      FlowHashBucket *myBucket;

      if(num_exported >= 100) {
	usleep(2000);
	num_exported = 0;
      }

      /* Remove bucket from list */
      pthread_rwlock_wrlock(&readWriteGlobals->exportMutex);
      if(readWriteGlobals->exportQueue != NULL) {
	myBucket = getListHead(&readWriteGlobals->exportQueue);
	if(myBucket != NULL) {
	  if(readWriteGlobals->exportBucketsLen == 0)
	    traceEvent(TRACE_WARNING, "Internal error (exportBucketsLen == 0)");
	  else
	    readWriteGlobals->exportBucketsLen--;
	}

#if 0
	if(readWriteGlobals->exportBucketsLen < 16)
	  traceEvent(TRACE_NORMAL, "[-] [exportBucketsLen=%d][myBucket=%p]",
		     readWriteGlobals->exportBucketsLen, myBucket);
#endif
      } else
	myBucket = NULL;

      pthread_rwlock_unlock(&readWriteGlobals->exportMutex);

      if(myBucket != NULL) {
	/* Export bucket */
	ticks when, when1, diff;

	if(unlikely(readOnlyGlobals.tracePerformance)) when = getticks();
	exportBucket(myBucket, 1);

	if(unlikely(readOnlyGlobals.tracePerformance)) {
	  when1 = getticks();
	  diff = when1 - when;
	  pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
	  readOnlyGlobals.bucketExportTicks += diff, readOnlyGlobals.num_exported_buckets++;
	  pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
	}

	purgeBucket(myBucket);

	if(unlikely(readOnlyGlobals.tracePerformance)) {
	  diff = getticks() - when1;
	  pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
	  readOnlyGlobals.bucketPurgeTicks += diff,  readOnlyGlobals.num_purged_buckets++;
	  pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
	}
      }
    }
  }

 readOnlyGlobals.dequeueBucketToExport_up = 0;

  traceEvent(TRACE_INFO, "Export thread terminated [exportQueue=%x]",
	     readWriteGlobals->exportQueue);
  signalCondvar(&readWriteGlobals->termCondvar, 0);
  return(NULL);
}

/* ****************************************************** */

void purgeBucket(FlowHashBucket *myBucket) {
  PluginInformation *next_info, *info;

  info = myBucket->ext ? myBucket->ext->plugin : NULL;

#ifdef ENABLE_MAGIC
  myBucket->magic = 0;
#endif

  /* These pointers should have been already freed by plugins */
  while(info != NULL) {
    if(info->pluginData) free(info->pluginData);
    next_info = info->next;
    free(info);
    info = next_info;
  }

  if(myBucket->core.l7.flow) {
    free(myBucket->core.l7.flow);
    myBucket->core.l7.flow = NULL;
  }

  if(myBucket->core.l7.src) {
    free(myBucket->core.l7.src);
    myBucket->core.l7.src = NULL;
  }

  if(myBucket->core.l7.dst) {
    free(myBucket->core.l7.dst);
    myBucket->core.l7.dst = NULL;
  }

  /*
    Do not move this statement below as we will free
    myBucket->ext invalidating its value
  */
  readWriteGlobals->bucketsAllocated[myBucket->ext ? myBucket->ext->thread_id : 0]--;

  if(myBucket->ext) {
    /*
      On Windows all mutexes that have been created must be destroyed otherwise
      they leak handles and thus the system runs out of memory/handles
    */
    if(unlikely(readOnlyGlobals.numProcessThreads > 1)) {
      pthread_rwlock_destroy(&myBucket->ext->src2dstLock);
      pthread_rwlock_destroy(&myBucket->ext->dst2srcLock);
    }

#ifdef HAVE_GEOIP
    if(myBucket->ext->srcInfo.geo) GeoIPRecord_delete(myBucket->ext->srcInfo.geo);
    if(myBucket->ext->dstInfo.geo) GeoIPRecord_delete(myBucket->ext->dstInfo.geo);
#endif

    if(myBucket->ext->srcInfo.aspath != NULL) {
      free(myBucket->ext->srcInfo.aspath);
      myBucket->ext->srcInfo.aspath = NULL;
    }

    if(myBucket->ext->dstInfo.aspath != NULL) {
      free(myBucket->ext->dstInfo.aspath);
      myBucket->ext->dstInfo.aspath = NULL;
    }

    if(myBucket->ext->extensions) {
      if(myBucket->ext->extensions->mplsInfo) free(myBucket->ext->extensions->mplsInfo);
      free(myBucket->ext->extensions);
    }

    free(myBucket->ext);
  }

#if 0
  traceEvent(TRACE_NORMAL, "[-] bucketsAllocated=%u",
	     readWriteGlobals->bucketsAllocated[myBucket->ext ? myBucket->ext->thread_id : 0]);
#endif

  free(myBucket);
}

/* ****************************************************** */

void idleThreadTask(u_int8_t thread_id) {
  if(unlikely(!readOnlyGlobals.disableFlowCache)) {
    if(likely(readWriteGlobals->shutdownInProgress || (readWriteGlobals->now < readWriteGlobals->idleTaskNextUpdate[thread_id])))
      return;
  }

  /* traceEvent(TRACE_INFO, "idleThreadTask(%d)", thread_id); */

  pthread_rwlock_wrlock(&readWriteGlobals->idleCheckLock[thread_id]); // REMOVE WHEN POSSIBLE

  /* We're not reading from a pcap file dump */
  if(readOnlyGlobals.pcapFile == NULL)
    readWriteGlobals->now = time(NULL);

  walkHashList(thread_id, 0, readWriteGlobals->now);
  readWriteGlobals->idleTaskNextUpdate[thread_id] = readWriteGlobals->now + IDLE_TASK_UPDATE_FREQUENCY;

  /* We call the idle task only for the first thread */
  if(thread_id == 0)
    pluginIdleThreadTask();

  pthread_rwlock_unlock(&readWriteGlobals->idleCheckLock[thread_id]); // REMOVE WHEN POSSIBLE
}
