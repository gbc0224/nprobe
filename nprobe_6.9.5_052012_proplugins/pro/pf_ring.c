/*
 *  Copyright (C) 2007-11 Luca Deri <deri@ntop.org>
 *
 *  		       http://www.ntop.org/
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_PF_RING

/* ****************************************************** */

inline void processPfringPktHdr(struct pfring_pkthdr *hdr,
				char *packet, long thread_id, 
				u_int32_t packet_hash) {
  if(likely((!readWriteGlobals->shutdownInProgress) 
	    && (!readWriteGlobals->stopPacketCapture)))
    decodePacket(thread_id, 
		 hdr->extended_hdr.if_index,
		 (struct pcap_pkthdr*)hdr, packet,
		 0 /* sampledPacket */,
		 1, NO_INTERFACE_INDEX, NO_INTERFACE_INDEX,
		 0 /* flow_sender_ip */,
		 packet_hash);
}

/* ****************************************************** */

struct n2disk_metadata_header {
  u_int16_t version;
  u_int16_t metadata_len;
};

struct n2disk_metadata {
  u_int32_t pkt_offset;
  struct pfring_pkthdr metadata;
};

static void* readMetadataPkts(void) {
  struct n2disk_metadata_header metadata_hdr;
  struct n2disk_metadata entry;
  int n;

  n = fread((void*)&metadata_hdr, 1, sizeof(metadata_hdr), readOnlyGlobals.metadata_fd);
  if(n != sizeof(metadata_hdr)) {
    traceEvent(TRACE_WARNING, "Metadatda file is too short");
    return(NULL);
  }

  while(fread((void*)&entry, 1, sizeof(entry), readOnlyGlobals.metadata_fd) == sizeof(entry)) {
    processPfringPktHdr(&entry.metadata, NULL, 0 /* fake thread_id */, 0);
  }

  return(NULL);
}

/* ****************************************************** */

void printPfRingStats(void) {
  pfring_stat stats;

  if(pfring_stats(readWriteGlobals->ring, &stats) >= 0)
    traceEvent(TRACE_NORMAL, "Packet stats (PF_RING): %u/%u pkts rcvd/dropped",
	       stats.recv, stats.drop);
}

/* ****************************************************** */

static time_t my_time;

void timealarm(int sig) {
  my_time = time(NULL);

  if((!readWriteGlobals->shutdownInProgress) 
     && (!readWriteGlobals->stopPacketCapture)) {
    alarm(1);
    signal(SIGALRM, timealarm);
  }
}


/* ****************************************************** */

void* fetchPfRingPackets(void* notUsed) {
  unsigned long thread_id = (unsigned long)notUsed;
  struct pfring_pkthdr hdr;
  u_char *packet;
  int rc, use_full_packet = 0;
  struct pcap_pkthdr h;
  u_short numPkts;
  int input_index, output_index;

  if(readOnlyGlobals.metadata_fd) return(readMetadataPkts());

  readWriteGlobals->ring_enabled = 1;

#if 0
  setThreadAffinity(thread_id % readOnlyGlobals.numProcessThreads);
#endif

  if(readOnlyGlobals.numProcessThreads > 1) {
    packet = (u_char*)malloc(readOnlyGlobals.snaplen+1);

    if(packet == NULL) {
      traceEvent(TRACE_WARNING, "Not enough memory!");
      return(NULL);
    }
  }

  if(readOnlyGlobals.pktSampleRate > 1)
    rc = pfring_set_sampling_rate(readWriteGlobals->ring,
				  readOnlyGlobals.pktSampleRate);

  memset(&hdr, 0, sizeof(hdr));

  if(readOnlyGlobals.quick_mode)
    timealarm(SIGALRM);

  while((!readWriteGlobals->shutdownInProgress) 
	&& (!readWriteGlobals->stopPacketCapture)) {
    if(likely(readOnlyGlobals.numProcessThreads == 1)) {
      while(pfring_poll(readWriteGlobals->ring, 0) == 0) {
	readWriteGlobals->now = time(NULL);
	idleThreadTask(thread_id);
	usleep(1);
	if(readWriteGlobals->shutdownInProgress 
	   || readWriteGlobals->stopPacketCapture)
	  break;
      }
    }

    if(readWriteGlobals->shutdownInProgress
       || readWriteGlobals->stopPacketCapture)
      break;

    rc = pfring_recv(readWriteGlobals->ring,
		     &packet,
		     (readOnlyGlobals.numProcessThreads > 1) ? readOnlyGlobals.snaplen : 0,
		     &hdr, 1 /* wait_for_incoming_packet */);

    if(rc > 0) {
      ticks when, diff;

      if(unlikely(readOnlyGlobals.tracePerformance)) when = getticks();
      if(hdr.ts.tv_sec == 0) {
	if(readOnlyGlobals.quick_mode)
	  hdr.ts.tv_sec = my_time;
	else
	  gettimeofday((struct timeval*)&hdr.ts, NULL);
      }

      processPfringPktHdr(&hdr, packet, thread_id, hdr.extended_hdr.pkt_hash);

      if(unlikely(readOnlyGlobals.tracePerformance)) {
	diff = getticks() - when;
	if(readOnlyGlobals.numProcessThreads > 1) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
	readOnlyGlobals.allInclusiveTicks += diff;
	if(readOnlyGlobals.numProcessThreads > 1) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
      }
    }

    idleThreadTask(thread_id);
  }

  if(readOnlyGlobals.numProcessThreads > 1)
    free(packet);

  readWriteGlobals->ring_enabled = 0;

  traceEvent(TRACE_NORMAL, "Terminated PF_RING packet processing");

  return(NULL);
}

/* ********************************************* */

pfring* open_ring(char *dev, u_char *open_device, u_short thread_id) {
  pfring* the_ring = NULL;
  u_int flags = 0;

  /*
    We disable promiscuous mode when using NFlite as we will capture
    just packets sent to use and not those that belong to other
    host (thus that are not interesting for us)
  */
  if(readOnlyGlobals.nfLitePluginEnabled)
    readOnlyGlobals.promisc_mode = 0, readOnlyGlobals.snaplen = 256;

  if(readOnlyGlobals.numProcessThreads > 1) flags |= PF_RING_REENTRANT;
  if(readOnlyGlobals.promisc_mode)          flags |= PF_RING_PROMISC;
  flags |= PF_RING_LONG_HEADER;
  
  if((the_ring = pfring_open(dev, readOnlyGlobals.snaplen, flags)) != NULL) {
    u_int32_t version;
    int rc;

    rc = pfring_version(the_ring, &version);

    if((rc == -1) || (version < 0x030502)) {
      traceEvent(TRACE_WARNING,
		 "nProbe requires PF_RING v.3.9.3 or above (you have v.%d.%d.%d)",
		 (version & 0xFFFF0000) >> 16,
		 (version & 0x0000FF00) >> 8,
		 version & 0x000000FF);
      pfring_close(the_ring);
      the_ring = NULL;
    } else {
      if(thread_id == 0)
	traceEvent(TRACE_INFO, "Successfully open PF_RING v.%d.%d.%d on device %s [snaplen=%u]\n",
		   (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8,
		   (version & 0x000000FF),
		   readOnlyGlobals.captureDev, readOnlyGlobals.snaplen);
      *open_device = 0;
      readOnlyGlobals.datalink = DLT_EN10MB;
      pfring_set_application_name(the_ring, "nProbe");

      if(thread_id == 0) {
	traceEvent(TRACE_NORMAL, "Using PF_RING in-kernel accelerated packet parsing");
      }

      if(readOnlyGlobals.nfLitePluginEnabled) {
	filtering_rule rule;

	pfring_toggle_filtering_policy(the_ring, 0); /* Default to drop */

	memset(&rule, 0, sizeof(rule));

	rule.rule_id = 1;
	rule.rule_action = execute_action_and_stop_rule_evaluation;
	rule.plugin_action.plugin_id = 13 /* NFLITE_PLUGIN_ID */;
	rule.core_fields.proto       = 17; /* UDP */
	rule.core_fields.dport_low    = readOnlyGlobals.nfLitePluginLowPort;
	rule.core_fields.dport_high   = readOnlyGlobals.nfLitePluginLowPort + readOnlyGlobals.nfLitePluginNumPorts;

	if(pfring_add_filtering_rule(the_ring, &rule) < 0) {
	  traceEvent(TRACE_WARNING, "[NFLite] Unable to add PF_RING NFLite rule: quitting");
	  traceEvent(TRACE_WARNING, "[NFLite] Did you 'modprobe nflite_plugin' ?");
	  exit(-1);
	} else
	  traceEvent(TRACE_INFO, "[NFLite] PF_RING NFLite rule added successfully [UDP ports %d:%d]",
		     readOnlyGlobals.nfLitePluginLowPort,
		     readOnlyGlobals.nfLitePluginLowPort + readOnlyGlobals.nfLitePluginNumPorts);

	pfring_set_direction(the_ring, rx_only_direction);
      }

      if(readOnlyGlobals.netFilter != NULL) {
	errno = 0;
	if((rc = pfring_set_bpf_filter(the_ring, readOnlyGlobals.netFilter)) != 0)
	  traceEvent(TRACE_WARNING, "[PF_RING] Unable to set PF_RING filter '%s' [rc=%d/%s]",
		     readOnlyGlobals.netFilter, rc, strerror(errno));
	else
	  traceEvent(TRACE_INFO, "Successfully set PF_RING filter '%s'",
                     readOnlyGlobals.netFilter);
      }

      if(readOnlyGlobals.cluster_id != -1) {
	/*
	  We need to use cluster_per_flow_2_tuple as otherwise we have no idea
	  how to handle fragments
	*/
	rc = pfring_set_cluster(the_ring, readOnlyGlobals.cluster_id, cluster_per_flow_2_tuple);
	if(rc < 0)
	  traceEvent(TRACE_WARNING, "[PF_RING] Unable to set PF_RING cluster %d [rc=%d]", 
		     readOnlyGlobals.cluster_id, rc);
	else
	  traceEvent(TRACE_INFO, "Successfully bound to PF_RING cluster %d");
      }

      if(readOnlyGlobals.enableL7BridgePlugin) {
	pfring_set_poll_watermark(the_ring, 1);
	pfring_set_direction(the_ring, rx_only_direction);
      } else {
	pfring_set_poll_watermark(the_ring, 64);
      }

      pfring_enable_ring(the_ring);
    }
  }

  return(the_ring);
}

#endif /* HAVE_PF_RING */
