/*
 *  Copyright (C) 2006-12 Luca Deri <deri@ntop.org>
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

#include "nprobe.h"

#define BASE_ID           NTOP_BASE_ID+188
#define ADDRESS_MAX_LEN    32

#define MAIL_FROM         "MAIL From:"
#define RCPT_TO           "RCPT To:"
#define RESET             "RESET"

static V9V10TemplateElementId smtpPlugin_template[] = {
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID,   VARIABLE_FIELD_LEN, ADDRESS_MAX_LEN, ascii_format, dump_as_ascii, "SMTP_MAIL_FROM", "", "Mail sender" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+1, VARIABLE_FIELD_LEN, ADDRESS_MAX_LEN, ascii_format, dump_as_ascii, "SMTP_RCPT_TO", "", "Mail recipient" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, 0, STATIC_FIELD_LEN, 0, 0, 0, NULL, NULL, NULL }
};

struct smtp_plugin_info {
  char mail_from[ADDRESS_MAX_LEN+1];
  char rcpt_to[ADDRESS_MAX_LEN+1];
};

/* *********************************************** */

static PluginEntryPoint smtpPlugin; /* Forward */

/* ******************************************* */

void smtpPlugin_init() {
  traceEvent(TRACE_INFO, "Initialized SMTP plugin");
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void smtpPlugin_packet(u_char new_bucket,
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
  PluginInformation *info;
  struct smtp_plugin_info *pinfo;

  // traceEvent(TRACE_INFO, "smtpPlugin_packet(%d)", payloadLen);

  if(new_bucket) {
    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return; /* Not enough memory */
    }

    info->pluginPtr  = (void*)&smtpPlugin;
    pluginData = info->pluginData = malloc(sizeof(struct smtp_plugin_info));

    if(info->pluginData == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      free(info);
      return; /* Not enough memory */
    } else
      memset(info->pluginData, 0, sizeof(struct smtp_plugin_info));

    info->next = bkt->ext->plugin;
    info->plugin_used = 0;  
    bkt->ext->plugin = info;
  }

  /*
    Do not put the checks below at the beginning of the function as otherwise
    the flow will not be able to export info about the template specified
   */
  if(proto != IPPROTO_TCP) return;
  if((sport != 25) && (dport != 25)) return;
  
  pinfo = (struct smtp_plugin_info*)pluginData;
  if(bkt->ext->plugin) bkt->ext->plugin->plugin_used = 1; /* This flow is dissected by this plugin */

  if(payloadLen > 0) {
    char *method;

    //traceEvent(TRACE_INFO, "==> [%d][%d]'%s'", bkt->bytesSent, bkt->bytesRcvd, payload);

    if((!strncasecmp((char*)payload, MAIL_FROM, strlen(MAIL_FROM)))) method = MAIL_FROM;
    else if((!strncasecmp((char*)payload, RCPT_TO, strlen(RCPT_TO)))) method = RCPT_TO;
    else if((!strncasecmp((char*)payload, RESET, strlen(RESET)))) method = RESET;
    else method = NULL;

    if(method) {
      char address[ADDRESS_MAX_LEN+1];
      int i, method_len, begin;
      
      if(!strncmp(method, RESET, strlen(RESET))) {
	/* We need to export this flow now */
	exportBucket(bkt, 0);
	resetBucketStats(bkt, h, (u_char*)p, len, ip_offset, flow_direction, payload, payloadLen);
	memset(pinfo, 0, sizeof(struct smtp_plugin_info));	  
	return;
      }
      
      method_len = strlen(method);
      strncpy(address, (char*)&payload[method_len], min(ADDRESS_MAX_LEN, (payloadLen-method_len)));

      //traceEvent(TRACE_INFO, "==> ADDRESS[%d]='%s'", 1, address);

      address[ADDRESS_MAX_LEN] = '\0';
      for(i=0; i<ADDRESS_MAX_LEN; i++) 
	if((address[i] == '\r')
	   || (address[i] == '\n')) {
	  address[i] = '\0';
	  break;
	} else if(address[i] == '>') {
	  address[i+1] = '\0';
	  break;
	}

      //traceEvent(TRACE_INFO, "==> ADDRESS[%d]='%s'", 2, address);

      for(begin=0; (address[begin] != '\0') && (address[begin] == ' '); begin++) ;
      
      len = strlen(address);
      while(len > 0) {
	if(address[len] == ' ') {
	  len--;
	} else
	  break;
      }
      if((address[begin] == '<') && (address[len-1] == '>'))
	begin++, len--;

      address[len] = '\0';

      if(!strncmp(method, MAIL_FROM, strlen(MAIL_FROM)))
	memcpy(pinfo->mail_from, &address[begin], strlen(address)-begin);
      else if(!strncmp(method, RCPT_TO, strlen(RCPT_TO)))
	memcpy(pinfo->rcpt_to, &address[begin], strlen(address)-begin);
    }
  }
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void smtpPlugin_delete(FlowHashBucket* bkt, void *pluginData) {
  if(pluginData != NULL)
    free(pluginData);
}

/* *********************************************** */
   
/* Handler called at startup when the template is read */

static V9V10TemplateElementId* smtpPlugin_get_template(char* template_name) {
  int i;

  for(i=0; smtpPlugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, smtpPlugin_template[i].netflowElementName)) {
      return(&smtpPlugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int smtpPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
			     FlowDirection direction /* 0 = src->dst, 1 = dst->src */,
			     FlowHashBucket *bkt, char *outBuffer,
			     uint* outBufferBegin, uint* outBufferMax) {
  int i;

  if(theTemplate == NULL) return(-1);

  for(i=0; smtpPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == smtpPlugin_template[i].templateElementId) {
      if((*outBufferBegin)+smtpPlugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      if(pluginData) {
	struct smtp_plugin_info *info = (struct smtp_plugin_info *)pluginData;
	u_int len;

	switch(smtpPlugin_template[i].templateElementId) {
	case BASE_ID:
	  if((readOnlyGlobals.netFlowVersion == 10)
	     && (smtpPlugin_template[i].variableFieldLength == VARIABLE_FIELD_LEN)) {
	    len = min(strlen(info->mail_from), smtpPlugin_template[i].templateElementLen);
	    
	    if(len < 255)
	      copyInt8(len, outBuffer, outBufferBegin, outBufferMax);
	    else {
	      copyInt8(255, outBuffer, outBufferBegin, outBufferMax);
	      copyInt16(len, outBuffer, outBufferBegin, outBufferMax);
	    }    
	  } else
	    len = smtpPlugin_template[i].templateElementLen;

	  memcpy(&outBuffer[*outBufferBegin], info->mail_from, len);
#ifdef DEBUG
	  traceEvent(TRACE_INFO, "==> MAIL_FROM='%s'", info->mail_from);
#endif
	  (*outBufferBegin) += len;
	  break;

	case BASE_ID+1:
	  if((readOnlyGlobals.netFlowVersion == 10)
	     && (smtpPlugin_template[i].variableFieldLength == VARIABLE_FIELD_LEN)) {
	    len = min(strlen(info->rcpt_to), smtpPlugin_template[i].templateElementLen);
	    
	    if(len < 255)
	      copyInt8(len, outBuffer, outBufferBegin, outBufferMax);
	    else {
	      copyInt8(255, outBuffer, outBufferBegin, outBufferMax);
	      copyInt16(len, outBuffer, outBufferBegin, outBufferMax);
	    }    
	  } else
	    len = smtpPlugin_template[i].templateElementLen;

	  memcpy(&outBuffer[*outBufferBegin], info->rcpt_to, len);
#ifdef DEBUG
	  traceEvent(TRACE_INFO, "==> RCPT_TO='%s'", info->rcpt_to);
#endif
	  (*outBufferBegin) += len;
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

static int smtpPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
			    FlowDirection direction /* 0 = src->dst, 1 = dst->src */,
			    FlowHashBucket *bkt, char *line_buffer, uint line_buffer_len) {
  int i;

  for(i=0; smtpPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == smtpPlugin_template[i].templateElementId) {
      if(pluginData) {
	struct smtp_plugin_info *info = (struct smtp_plugin_info *)pluginData;

	switch(smtpPlugin_template[i].templateElementId) {
	case BASE_ID:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->mail_from);
	  break;
	case BASE_ID+1:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->rcpt_to);
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

static V9V10TemplateElementId* smtpPlugin_conf(void) {
  return(smtpPlugin_template);
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginEntryPoint smtpPlugin = {
  NPROBE_REVISION,
  "SMTP Protocol Dissector",
  "0.1",
  "Handle SMTP protocol",
  "L.Deri <deri@ntop.org>",
  0 /* not always enabled */, 1, /* enabled */
  PLUGIN_DONT_NEED_LICENSE,
  smtpPlugin_init,
  NULL, /* Term */
  smtpPlugin_conf,
  smtpPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  smtpPlugin_packet,
  smtpPlugin_get_template,
  smtpPlugin_export,
  smtpPlugin_print,
  NULL,
  NULL,
  NULL,
  NULL, 0, 0
};

/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginEntryPoint* smtpPluginEntryFctn(void)
#else
  PluginEntryPoint* PluginEntryFctn(void)
#endif
{
  return(&smtpPlugin);
}
 
