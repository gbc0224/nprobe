/*
 *  Copyright (C) 2005-12 Luca Deri <deri@ntop.org>
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

#define SIP_INVITE        "INVITE" /* User Info */
#define SIP_OK            "SIP/2.0 200 Ok" /* Stream Info */

#include "nprobe.h"

#define BASE_ID             NTOP_BASE_ID+130
#define MAX_SIP_STR_LEN      64
#define SIP_CODECS_STR_LEN   32
#define DEFAULT_SIP_PORT   5060

static V9V10TemplateElementId sipPlugin_template[] = {
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID,    VARIABLE_FIELD_LEN, MAX_SIP_STR_LEN,    ascii_format,   dump_as_ascii,        "SIP_CALL_ID",             "", "SIP call-id" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+1,  VARIABLE_FIELD_LEN, MAX_SIP_STR_LEN,    ascii_format,   dump_as_ascii,        "SIP_CALLING_PARTY",       "", "SIP Call initiator" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+2,  VARIABLE_FIELD_LEN, MAX_SIP_STR_LEN,    ascii_format,   dump_as_ascii,        "SIP_CALLED_PARTY",        "", "SIP Called party" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+3,  STATIC_FIELD_LEN,   SIP_CODECS_STR_LEN, ascii_format,   dump_as_ascii,        "SIP_RTP_CODECS",          "", "SIP RTP codecs" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+4,  STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_uint,         "SIP_INVITE_TIME",         "", "SIP SysUptime (msec) of INVITE" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+5,  STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_uint,         "SIP_TRYING_TIME",         "", "SIP SysUptime (msec) of Trying" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+6,  STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_uint,         "SIP_RINGING_TIME",        "", "SIP SysUptime (msec) of RINGING" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+7,  STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_uint,         "SIP_INVITE_OK_TIME",      "", "SIP SysUptime (msec) of INVITE OK" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+8,  STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_uint,         "SIP_INVITE_FAILURE_TIME", "", "SIP SysUptime (msec) of INVITE FAILURE" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+9,  STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_uint,         "SIP_BYE_TIME",            "", "SIP SysUptime (msec) of BYE" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+10, STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_uint,         "SIP_BYE_OK_TIME",         "", "SIP SysUptime (msec) of BYE OK" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+11, STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_uint,         "SIP_CANCEL_TIME",         "", "SIP SysUptime (msec) of CANCEL" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+12, STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_uint,         "SIP_CANCEL_OK_TIME",      "", "SIP SysUptime (msec) of CANCEL OK" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+13, STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_ipv4_address, "SIP_RTP_IPV4_SRC_ADDR",   "", "SIP RTP stream source IP" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+14, STATIC_FIELD_LEN,   2,                  numeric_format, dump_as_ip_port,      "SIP_RTP_L4_SRC_PORT",     "", "SIP RTP stream source port" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+15, STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_ipv4_address, "SIP_RTP_IPV4_DST_ADDR",   "", "SIP RTP stream dest IP" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+16, STATIC_FIELD_LEN,   2,                  numeric_format, dump_as_ip_port,      "SIP_RTP_L4_DST_PORT",     "", "SIP RTP stream dest port" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+17, STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_uint,         "SIP_FAILURE_CODE",        "", "SIP failure response code" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+18, STATIC_FIELD_LEN,   4,                  numeric_format, dump_as_uint,         "SIP_REASON_CAUSE",        "", "SIP Cancel/Bye/Failure reason cause" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, 0, STATIC_FIELD_LEN, 0, 0, 0, NULL, NULL, NULL }
};

/* *********************************************** */

struct sip_plugin_dir_info {
  struct timeval sip_invite_time, sip_trying_time,
    sip_ringing_time, sip_invite_ok_time, sip_invite_failure_time,
    sip_bye_time, sip_bye_ok_time, sip_cancel_time, sip_cancel_ok_time;
  char rtp_codecs[SIP_CODECS_STR_LEN];
};

struct sip_plugin_info {
  char sip_call_id[MAX_SIP_STR_LEN];
  char sip_calling_party[MAX_SIP_STR_LEN];
  char sip_called_party[MAX_SIP_STR_LEN];
  struct sip_plugin_dir_info dir_info[2];
  u_int16_t rtp_src_port, rtp_dst_port;
  u_int32_t rtp_src_ip, rtp_dst_ip;
  u_int32_t sip_failure_code;
  u_int32_t reason_cause;
};

/* *********************************************** */

static PluginEntryPoint sipPlugin; /* Forward */

/* *********************************************** */

typedef enum {
  method_unknown     = 0,
  method_invite      = 1 <<  0,
  method_cancel      = 1 <<  1,
  method_bye         = 1 <<  2,
  method_sip_ok      = 1 <<  3,
  method_sip_trying  = 1 <<  4,
  method_sip_ringing = 1 <<  5,
  method_sip_failure = 1 <<  6
} sip_method;

/* ******************************************* */

void sipPlugin_init() {
  traceEvent(TRACE_INFO, "Initialized SIP plugin\n");
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void sipPlugin_packet(u_char new_bucket,
			     int packet_if_idx /* -1 = unknown */,
			     void *pluginData,
			     FlowHashBucket* bkt,
			     FlowDirection flow_direction,
			     u_int16_t ip_offset, u_short proto, u_char isFragment,
			     u_short numPkts, u_char tos,
			     u_short vlanId, struct eth_header *ehdr,
			     IpAddress *src, u_short sport,
			     IpAddress *dst, u_short dport,
			     u_int len, u_int8_t flags,
			     u_int32_t tcpSeqNum, u_int8_t icmpType,
			     u_short numMplsLabels,
			     u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
			     const struct pcap_pkthdr *h, const u_char *p,
			     u_char *payload, int payloadLen) {

  if(new_bucket /* This bucket has been created recently */) {
    /* Check whether this is an RTP or SIP flow */
    if((bkt->core.tuple.proto == 17 /* UDP */)
       && ((bkt->core.tuple.sport == DEFAULT_SIP_PORT)
	   || (bkt->core.tuple.dport == DEFAULT_SIP_PORT)) /* SIP */
       ) {
      PluginInformation *info;

      info = (PluginInformation*)malloc(sizeof(PluginInformation));
      if(info == NULL) {
	traceEvent(TRACE_ERROR, "Not enough memory?");
	return; /* Not enough memory */
      }

      info->pluginPtr  = (void*)&sipPlugin;
      pluginData = info->pluginData = (struct sip_plugin_info*)malloc(sizeof(struct sip_plugin_info));

      if(info->pluginData == NULL) {
	traceEvent(TRACE_ERROR, "Not enough memory?");
	free(info);
	return; /* Not enough memory */
      } else {
	/* Set defaults */
	struct sip_plugin_info *infos = (struct sip_plugin_info*)pluginData;

	info->next = bkt->ext->plugin;
	bkt->ext->plugin = info;
	info->plugin_used = 0;  
	memset(infos, 0, sizeof(struct sip_plugin_info));
      }
    }
  }

  /*
    Do not put the checks below at the beginning of the function as otherwise
    the flow will not be able to export info about the template specified
   */
  if(proto != IPPROTO_UDP) return;  
  if((payload == NULL) || (payloadLen == 0)) return;

  if(bkt->ext->plugin) bkt->ext->plugin->plugin_used = 1; /* This flow is dissected by this plugin */

  if((pluginData != NULL) && (payloadLen > 0)) {
    char *my_payload, *strtokState, *row;
    char *from = NULL, *to = NULL, *audio = NULL, *video = NULL, *c_ip = NULL, *cseq = NULL, *reason = NULL;
    sip_method message_type = method_unknown;
    struct sip_plugin_info *info = (struct sip_plugin_info*)pluginData;

    /* Handle your Sip packet here */
    my_payload = malloc(payloadLen+1);

    if(my_payload != NULL) {
      char *rtpmap;

      memcpy(my_payload, payload, payloadLen);
      my_payload[payloadLen] = '\0';

      row = strtok_r((char*)my_payload, "\r\n", &strtokState);

      if(row != NULL) {
	if(!strncmp(row, "INVITE", 6)) {
	  message_type = method_invite;
	  info->dir_info[flow_direction].sip_invite_time.tv_sec = h->ts.tv_sec, info->dir_info[flow_direction].sip_invite_time.tv_usec = h->ts.tv_usec;
	} else if(!strncmp(row, "CANCEL", 6)) {
	  message_type = method_cancel;
	  info->dir_info[flow_direction].sip_cancel_time.tv_sec = h->ts.tv_sec, info->dir_info[flow_direction].sip_cancel_time.tv_usec = h->ts.tv_usec;
	} else if(!strncmp(row, "BYE", 3)) {
	  message_type = method_bye;
	  info->dir_info[flow_direction].sip_bye_time.tv_sec = h->ts.tv_sec, info->dir_info[flow_direction].sip_bye_time.tv_usec = h->ts.tv_usec;
	} else if(!strncmp(row, "SIP/2.0", 7)) {
	  int status_code = atoi(&row[8]);
	  switch(status_code) {
	    case 200: /* OK */
	      message_type = method_sip_ok;
	      break;
	    case 100: /* Trying */
	      message_type = method_sip_trying;
	      info->dir_info[flow_direction].sip_trying_time.tv_sec = h->ts.tv_sec, info->dir_info[flow_direction].sip_trying_time.tv_usec = h->ts.tv_usec;
	      break;
	    case 180: /* Ringing */
	      message_type = method_sip_ringing;
	      info->dir_info[flow_direction].sip_ringing_time.tv_sec = h->ts.tv_sec, info->dir_info[flow_direction].sip_ringing_time.tv_usec = h->ts.tv_usec;
	      break;
	    default:
	      if(status_code > 399) { /* Failure */
	        message_type = method_sip_failure;
	        info->sip_failure_code = status_code;
	      }
	  }
	}


	row = strtok_r(NULL, "\r\n", &strtokState);

	while(row != NULL) {
	  if((from == NULL) && ((!strncmp(row, "From: ", 6))  || (!strncmp(row, "f: ", 3)))) {
	    from = row;
	  } else if((to == NULL) && ((!strncmp(row, "To: ", 4)) || (!strncmp(row, "t: ", 3)))) {
	    to = row;
	  } else if(!strncmp(row, "Call-ID: ", 9)) {
	    strncpy(info->sip_call_id, &row[9], MAX_SIP_STR_LEN);
	  } else if(!strncmp(row, "CSeq: ", 6)) {
            cseq = row;
          } else if((reason == NULL) && (!strncmp(row, "Reason: ", 8))) {
	    reason = row;
	  } else if((audio == NULL) && (!strncmp(row, "m=audio ", 8))) {
	    audio = row;
	  } else if((video == NULL) && (!strncmp(row, "m=video ", 8))) {
	    video = row;
	  } else if((c_ip == NULL) && (!strncmp(row, "c=IN IP4 ", 9))) {
	    c_ip = &row[9];
	  } else if((rtpmap = strstr(row, "=rtpmap:")) != NULL) {
	    char *codec;
	    int i;

	    if(rtpmap[10] == ' ')
	      codec = &rtpmap[11];
	    else
	      codec = &rtpmap[10];

	    for(i=0; codec[i] != '\0'; i++)
	      if(codec[i] == '/') {
		codec[i] = '\0';
		break;
	      }

	    if(strstr(codec, "telephone-event") == NULL) {
	      if(info->dir_info[flow_direction].rtp_codecs[0] == '\0') {
		snprintf(info->dir_info[flow_direction].rtp_codecs, sizeof(info->dir_info[flow_direction].rtp_codecs)-1, "%s", codec);
	      } else {
		if(strstr(info->dir_info[flow_direction].rtp_codecs, codec) == NULL) {
		  char tmpStr[SIP_CODECS_STR_LEN];
		  
		  snprintf(tmpStr, sizeof(tmpStr)-1, "%s;%s", info->dir_info[flow_direction].rtp_codecs, codec);
		  strcpy(info->dir_info[flow_direction].rtp_codecs, tmpStr);
		}
	      }
	    }
	  }

	  row = strtok_r(NULL, "\r\n", &strtokState);
	}
      }

      if ((message_type & (method_sip_ok|method_sip_failure)) && cseq) {
        cseq = &cseq[6];
	strtok_r(cseq, " ", &strtokState);
	cseq = strtok_r(NULL, " ", &strtokState);

        if(message_type & method_sip_ok) {
          if(!strncmp(cseq, "INVITE", 6))
	    info->dir_info[flow_direction].sip_invite_ok_time.tv_sec = h->ts.tv_sec, info->dir_info[flow_direction].sip_invite_ok_time.tv_usec = h->ts.tv_usec;
	  else if(!strncmp(cseq, "BYE", 3))
	    info->dir_info[flow_direction].sip_bye_ok_time.tv_sec = h->ts.tv_sec, info->dir_info[flow_direction].sip_bye_ok_time.tv_usec = h->ts.tv_usec;
	  else if(!strncmp(cseq, "CANCEL", 6))
	    info->dir_info[flow_direction].sip_cancel_ok_time.tv_sec = h->ts.tv_sec, info->dir_info[flow_direction].sip_cancel_ok_time.tv_usec = h->ts.tv_usec;
        } else if(message_type & method_sip_failure) {
          if(!strncmp(cseq, "INVITE", 6))
	    info->dir_info[flow_direction].sip_invite_failure_time.tv_sec = h->ts.tv_sec, info->dir_info[flow_direction].sip_invite_failure_time.tv_usec = h->ts.tv_usec;
	}
      }

      if ((message_type & (method_cancel|method_bye|method_sip_failure)) && reason) {
        reason = &reason[8];
	reason = strtok_r(reason, " ;", &strtokState);

	if(!strncmp(reason, "Q.850", 5)) {
	  /* Q.850: The cause parameter contains an ITU-T Q.850 cause value in decimal representation. */
	  reason = strtok_r(NULL, " ;", &strtokState);
	  if(!strncmp(reason, "cause=", 6)) {
	    info->reason_cause = atoi(&reason[6]);
	  }
	}
      }

      if(from && to /* && (!strncasecmp((char*)my_payload, SIP_INVITE, strlen(SIP_INVITE))) */ 
         && !info->sip_calling_party[0] 
	 && !info->sip_called_party[0]) {
	strtok_r(from, ":", &strtokState);
	strtok_r(NULL, ":\"", &strtokState);
	from = strtok_r(NULL, "\"@>", &strtokState);

	strtok_r(to, ":", &strtokState);
	strtok_r(NULL, "\":", &strtokState);
	to = strtok_r(NULL, "\"@>", &strtokState);

	if(unlikely(readOnlyGlobals.enable_debug))
	  traceEvent(TRACE_INFO, "'%s'->'%s'", from, to);

	strncpy(info->sip_calling_party, from, MAX_SIP_STR_LEN);
	strncpy(info->sip_called_party, to, MAX_SIP_STR_LEN);
      }

      if(audio) {
	strtok_r(audio, " ", &strtokState);
	audio = strtok_r(NULL, " ", &strtokState);

	if(unlikely(readOnlyGlobals.enable_debug))
	  traceEvent(TRACE_INFO, "RTP '%s:%s'", c_ip /* _intoa(*src, buf, sizeof(buf))*/, audio);

	if(cmpIpAddress(&bkt->core.tuple.src, src)) {
	  /* Direction: src -> dst */

	  info->rtp_src_ip = c_ip ? ntohl(inet_addr(c_ip)) : 0;

	  if(audio)
	    info->rtp_src_port = atoi(audio);
	} else {
	  /* Direction: dst -> src */

	  info->rtp_dst_ip = c_ip ? ntohl(inet_addr(c_ip)) : 0;
	  if(audio) info->rtp_dst_port = atoi(audio);
	}
      }

      if(video) {
	strtok_r(video, " ", &strtokState);
	video = strtok_r(NULL, " ", &strtokState);

	if(unlikely(readOnlyGlobals.enable_debug))
	  traceEvent(TRACE_INFO, "RTP '%s:%s'", c_ip /* _intoa(*src, buf, sizeof(buf)) */, video);
      }

      free(my_payload);
    } else
      traceEvent(TRACE_ERROR, "Not enough memory?");
  }
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void sipPlugin_delete(FlowHashBucket* bkt, void *pluginData) {

  if(pluginData != NULL) {
    struct sip_plugin_info *info = (struct sip_plugin_info*)pluginData;

    if(unlikely(readOnlyGlobals.enable_debug)) {
      char buf[256], buf1[256];
      
      traceEvent(TRACE_INFO, "SIP: '%s'->'%s'", info->sip_calling_party, info->sip_called_party);
      traceEvent(TRACE_INFO, "RTP  '%s:%d'->'%s:%d'",
		 _intoaV4(info->rtp_src_ip, buf, sizeof(buf)), info->rtp_src_port,
		 _intoaV4(info->rtp_dst_ip, buf1, sizeof(buf1)), info->rtp_dst_port);
    }

    free(info);
  }
}

/* *********************************************** */

/* Handler called at startup when the template is read */

static V9V10TemplateElementId* sipPlugin_get_template(char* template_name) {
  int i;

  for(i=0; sipPlugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, sipPlugin_template[i].netflowElementName)) {
      return(&sipPlugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenver a flow attribute needs to be exported */

static int sipPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplateElement,
			    FlowDirection direction /* 0 = src->dst, 1 = dst->src */,
			    FlowHashBucket *bkt, char *outBuffer,
			    uint* outBufferBegin, uint* outBufferMax) {
  int i;
  char buf[32];
  
  if(theTemplateElement == NULL) return(-1);

  for(i=0; sipPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplateElement->templateElementId == sipPlugin_template[i].templateElementId) {
      if((*outBufferBegin)+sipPlugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      if(pluginData) {
	struct sip_plugin_info *info = (struct sip_plugin_info *)pluginData;
	int len;

	switch(sipPlugin_template[i].templateElementId) {
	case BASE_ID:
	  if((readOnlyGlobals.netFlowVersion == 10)
	     && (sipPlugin_template[i].variableFieldLength == VARIABLE_FIELD_LEN)) {
	    len = min(strlen(info->sip_call_id), sipPlugin_template[i].templateElementLen);
	    
	    /* Len won't be > 255 */
	    copyInt8(len, outBuffer, outBufferBegin, outBufferMax);
	  } else
	    len = sipPlugin_template[i].templateElementLen;

	  copyLen((u_char*)info->sip_call_id, len, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_call_id: %s", info->sip_call_id);
	  }
	  break;
	case BASE_ID+1:
	  if((readOnlyGlobals.netFlowVersion == 10)
	     && (sipPlugin_template[i].variableFieldLength == VARIABLE_FIELD_LEN)) {
	    len = min(strlen(info->sip_calling_party), sipPlugin_template[i].templateElementLen);
	    
	    /* Len won't be > 255 */
	    copyInt8(len, outBuffer, outBufferBegin, outBufferMax);
	  } else
	    len = sipPlugin_template[i].templateElementLen;

	  copyLen((u_char*)info->sip_calling_party, len, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_calling_party: %s", info->sip_calling_party);
	  }
	  break;
	case BASE_ID+2:
	  if((readOnlyGlobals.netFlowVersion == 10)
	     && (sipPlugin_template[i].variableFieldLength == VARIABLE_FIELD_LEN)) {
	    len = min(strlen(info->sip_called_party), sipPlugin_template[i].templateElementLen);
	    
	    /* Len won't be > 255 */
	    copyInt8(len, outBuffer, outBufferBegin, outBufferMax);
	  } else
	    len = sipPlugin_template[i].templateElementLen;

	  copyLen((u_char*)info->sip_called_party, len, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_called_party: %s", info->sip_called_party);
	  }
	  break;
	case BASE_ID+3:
	  copyLen((u_char*)info->dir_info[direction].rtp_codecs, sipPlugin_template[i].templateElementLen,
		  outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "rtp_codecs: %s", info->dir_info[direction].rtp_codecs);
	  }
	  break;
	case BASE_ID+4:
	  copyInt32(info->dir_info[direction].sip_invite_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_invite_time: %u", info->dir_info[direction].sip_invite_time.tv_sec);
	  }
	  break;
	case BASE_ID+5:
	  copyInt32(info->dir_info[direction].sip_trying_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_trying_time: %u",
						     info->dir_info[direction].sip_trying_time.tv_sec);
	  }
	  break;
	case BASE_ID+6:
	  copyInt32(info->dir_info[direction].sip_ringing_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_ringing_time: %u",
						     info->dir_info[direction].sip_ringing_time.tv_sec);
	  }
	  break;
	case BASE_ID+7:
	  copyInt32(info->dir_info[direction].sip_invite_ok_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_invite_ok_time: %u",
						     info->dir_info[direction].sip_invite_ok_time.tv_sec);
	  }
	  break;
	case BASE_ID+8:
	  copyInt32(info->dir_info[direction].sip_invite_failure_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_invite_failure_time: %u",
						     info->dir_info[direction].sip_invite_failure_time.tv_sec);
	  }
	  break;
	case BASE_ID+9:
	  copyInt32(info->dir_info[direction].sip_bye_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_bye_time: %u",
						     info->dir_info[direction].sip_bye_time.tv_sec);
	  }
	  break;
	case BASE_ID+10:
	  copyInt32(info->dir_info[direction].sip_bye_ok_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_bye_ok_time: %u",
						     info->dir_info[direction].sip_bye_ok_time.tv_sec);
	  }
	  break;
	case BASE_ID+11:
	  copyInt32(info->dir_info[direction].sip_cancel_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_cancel_time: %u",
						     info->dir_info[direction].sip_cancel_time.tv_sec);
	  }
	  break;
	case BASE_ID+12:
	  copyInt32(info->dir_info[direction].sip_cancel_ok_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_cancel_ok_time: %u",
						     info->dir_info[direction].sip_cancel_ok_time.tv_sec);
	  }
	  break;
	case BASE_ID+13:
	  copyInt32(direction == src2dst_direction ? info->rtp_src_ip :
		    info->rtp_dst_ip, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) 
	      traceEvent(TRACE_INFO, "rtp_src_ip: %s",
		       _intoaV4(info->rtp_src_ip, buf, sizeof(buf)));
	  }
	  break;
	case BASE_ID+14:
	  copyInt16(direction == src2dst_direction ? info->rtp_src_port :
		    info->rtp_dst_port, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "rtp_src_port: %d",
						     info->rtp_src_port);
	  }
	  break;
	case BASE_ID+15:
	  copyInt32(direction != src2dst_direction ? info->rtp_src_ip :
		    info->rtp_dst_ip, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "rtp_dst_ip: %s",
						     _intoaV4(info->rtp_dst_ip, buf, sizeof(buf)));
	  }
	  break;
	case BASE_ID+16:
	  copyInt16(direction != src2dst_direction ? info->rtp_src_port :
		    info->rtp_dst_port, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "rtp_dst_port: %d",
						     info->rtp_dst_port);
	  }
	  break;
	case BASE_ID+17:
	  copyInt32(info->sip_failure_code, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_failure_code: %d",
						     info->sip_failure_code);
	  }
	  break;
	case BASE_ID+18:
	  copyInt32(info->reason_cause, outBuffer, outBufferBegin, outBufferMax);

	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "reason_cause: %d",
						     info->reason_cause);
	  }
	  break;

	default:
	  return(-1); /* Not handled */
	}

	return(0);
      }
    }
  }

  return(-1); /* Not handled */
}

/* *********************************************** */

static int sipPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplateElement,
			   FlowDirection direction /* 0 = src->dst, 1 = dst->src */,
			   FlowHashBucket *bkt, char *line_buffer, uint line_buffer_len) {
  int i;
  char buf[32];

  for(i=0; sipPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplateElement->templateElementId == sipPlugin_template[i].templateElementId) {
      if(pluginData) {
	struct sip_plugin_info *info = (struct sip_plugin_info *)pluginData;

	switch(sipPlugin_template[i].templateElementId) {
	case BASE_ID:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   info->sip_call_id);
	  break;
	case BASE_ID+1:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   info->sip_calling_party);
	  break;
	case BASE_ID+2:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   info->sip_called_party);
	  break;
	case BASE_ID+3:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   info->dir_info[direction].rtp_codecs);
	  break;
	case BASE_ID+4:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->dir_info[direction].sip_invite_time.tv_sec);
	  break;
	case BASE_ID+5:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->dir_info[direction].sip_trying_time.tv_sec);
	  break;
	case BASE_ID+6:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->dir_info[direction].sip_ringing_time.tv_sec);
	  break;
	case BASE_ID+7:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->dir_info[direction].sip_invite_ok_time.tv_sec);
	  break;
	case BASE_ID+8:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->dir_info[direction].sip_invite_failure_time.tv_sec);
	  break;
	case BASE_ID+9:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->dir_info[direction].sip_bye_time.tv_sec);
	  break;
	case BASE_ID+10:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->dir_info[direction].sip_bye_ok_time.tv_sec);
	  break;
	case BASE_ID+11:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->dir_info[direction].sip_cancel_time.tv_sec);
	  break;
	case BASE_ID+12:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->dir_info[direction].sip_cancel_ok_time.tv_sec);
	  break;
	case BASE_ID+13:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   _intoaV4(direction == src2dst_direction ? info->rtp_src_ip : info->rtp_dst_ip, buf, sizeof(buf)));
	  break;
	case BASE_ID+14:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d",
		   direction == src2dst_direction ? info->rtp_src_port : info->rtp_dst_port);
	  break;
	case BASE_ID+15:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   _intoaV4(direction != src2dst_direction ? info->rtp_src_ip : info->rtp_dst_ip, buf, sizeof(buf)));
	  break;
	case BASE_ID+16:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d",
		   direction != src2dst_direction ? info->rtp_src_port : info->rtp_dst_port);
	  break;
	case BASE_ID+17:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->sip_failure_code);
	  break;
	case BASE_ID+18:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->reason_cause);
	  break;
	default:
	  return(-1); /* Not handled */
	}

	return(0);
      }
    }
  }

  return(-1); /* Not handled */
}

/* *********************************************** */

static V9V10TemplateElementId* sipPlugin_conf(void) {
  return(sipPlugin_template);
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginEntryPoint sipPlugin = {
  NPROBE_REVISION,
  "SIP",
  "0.2",
  "Handle SIP protocol",
  "L.Deri <deri@ntop.org>",
  0 /* not always enabled */, 1, /* enabled */
  PLUGIN_DONT_NEED_LICENSE,
  sipPlugin_init,
  NULL, /* Term */
  sipPlugin_conf,
  sipPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  sipPlugin_packet,
  sipPlugin_get_template,
  sipPlugin_export,
  sipPlugin_print,
  NULL,
  NULL,
  NULL,
  NULL, 0, 0
};


/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginEntryPoint* sipPluginEntryFctn(void)
#else
PluginEntryPoint* PluginEntryFctn(void)
#endif
{
  return(&sipPlugin);
}

