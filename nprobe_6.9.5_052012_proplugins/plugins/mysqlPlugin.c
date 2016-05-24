/*
 *  Copyright (C)  2010-12 Luca Deri <deri@ntop.org>
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

static int packet_id = 0;

#define BASE_ID                 NTOP_BASE_ID+195

//#define DEBUG
//#define PACKET_SPLIT_DEBUG

#define MYSQL_MIN_LEN           16     /* Min lenght for string */
#define MYSQL_MAX_LEN           32     /* Max lenght for string */
#define MYSQL_SERVER_PORT     3306
#define MAX_QUERY_LEN          128
#define MAX_PREV_PKT_BUF_LEN   512
#define PAYLOAD_BUF_LEN       (2*PCAP_LONG_SNAPLEN)
#define MAX_NUM_LINES        10000
#define TMP_FILE_POSTFIX    ".tmp"

static V9V10TemplateElementId mysqlPlugin_template[] = {
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID,   STATIC_FIELD_LEN, MYSQL_MIN_LEN, ascii_format, dump_as_ascii, "MYSQL_SERVER_VERSION", "", "MySQL server version" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+1, STATIC_FIELD_LEN, MYSQL_MIN_LEN, ascii_format, dump_as_ascii, "MYSQL_USERNAME", "", "MySQL username" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+2, STATIC_FIELD_LEN, MYSQL_MAX_LEN, ascii_format, dump_as_ascii, "MYSQL_DB", "", "MySQL database in use" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+3, VARIABLE_FIELD_LEN, MYSQL_MAX_LEN, ascii_format, dump_as_ascii, "MYSQL_QUERY", "", "MySQL Query" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+4, STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint, "MYSQL_RESPONSE", "", "MySQL server response" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, 0, STATIC_FIELD_LEN, 0, 0, 0, NULL, NULL, NULL }
};

struct packet_header {
  u_int32_t packet_length; /* only 24 bit */
  u_int8_t packet_number, is_request;
};

struct mysql_plugin_info {
  char mysql_server_version[MYSQL_MIN_LEN];
  char mysql_username[MYSQL_MIN_LEN];
  char mysql_db[MYSQL_MAX_LEN], last_mysql_db[MYSQL_MAX_LEN];
  char *mysql_query;
  u_int8_t mysql_command;
  u_int16_t mysql_response_code;

  /* Used to merge MySQL packets across TCP packets */
  char previous_pkt[MAX_PREV_PKT_BUF_LEN];
  u_short previous_pkt_len, last_pkt_number;

  u_int32_t last_client2server_seqId, last_server2client_seqId;
};

/* *********************************************** */

static char last_mysql_dump_dir[256] = { 0 }, last_mysql_dump_file[256] = { 0 };
static char mysql_exec_command[256] = { 0 };
static u_int mysql_file_dump_timeout  = 300;  /* 5 min */
static u_int mysql_directory_duration = 3600; /* 1 hour */
static u_int max_num_lines = MAX_NUM_LINES;
static u_int8_t nest_dirs = 1;
static FILE *fd = NULL;
static time_t fd_close_timeout = 0;
static u_int num_file = 0, num_log_lines = 0;
static char mysql_dump_dir[256] = { 0 };

/* *********************************************** */

static PluginEntryPoint mysqlPlugin; /* Forward */

/* ******************************************* */

void mysqlPlugin_init() {
  int i;

  for(i=0; i<readOnlyGlobals.argc; i++)
    if(!strcmp(readOnlyGlobals.argv[i], "--mysql-dump-dir")) {
      if((i+1) < readOnlyGlobals.argc) {
	int len;

	snprintf(mysql_dump_dir, sizeof(mysql_dump_dir), "%s", readOnlyGlobals.argv[i+1]);
	len = strlen(mysql_dump_dir);
	if(len > 0) len--;

	if(mysql_dump_dir[len] == '/')
	  mysql_dump_dir[len] = '\0';

	traceEvent(TRACE_NORMAL, "MYSQL log files will be saved in %s", mysql_dump_dir);
      }

      readOnlyGlobals.enableMySQLPlugin = 1;
    } else if(!strcmp(readOnlyGlobals.argv[i], "--mysql-exec-cmd")) {
      if((i+1) < readOnlyGlobals.argc) {
	snprintf(mysql_exec_command, sizeof(mysql_exec_command), "%s", readOnlyGlobals.argv[i+1]);
	traceEvent(TRACE_NORMAL, "MYSQL directories will be processed by '%s'",
		   mysql_exec_command);
      }
    } else if(!strcmp(readOnlyGlobals.argv[i], "--max-mysql-log-lines")) {
      if((i+1) < readOnlyGlobals.argc) {
	max_num_lines = atol(readOnlyGlobals.argv[i+1]);
      }
    }

  traceEvent(TRACE_INFO, "Initialized MySQL plugin");
}

/* *********************************************** */

void exec_mysql_cmd(void) {
  if((last_mysql_dump_dir[0] != 0) && (mysql_exec_command[0] != 0)) {
    char command_buf[1024];
    int rc;

    snprintf(command_buf, sizeof(command_buf), "%s %s &", mysql_exec_command, last_mysql_dump_dir);
    traceEvent(TRACE_INFO, "Executing '%s'", command_buf);
    rc = system(command_buf);

    if(rc == -1)
      traceEvent(TRACE_WARNING, "Unable to execute '%s'", command_buf);
  }
}

/* *********************************************** */

static void close_mysql_dump(void) {
  if(fd != NULL) {
    fclose(fd);
    fd = NULL;
  }

  if(last_mysql_dump_file[0] != '\0') {
    char new_file[256];

    snprintf(new_file, sizeof(new_file), "%s", last_mysql_dump_file);
    new_file[strlen(new_file)-strlen(TMP_FILE_POSTFIX)] = '\0';

    rename(last_mysql_dump_file, new_file);
    traceEvent(TRACE_INFO, "Renamed %s to %s", last_mysql_dump_file, new_file);
    last_mysql_dump_file[0] = '\0';
  }
}

/* *********************************************** */

static void dumpMySQLlog(FlowHashBucket *bkt, struct mysql_plugin_info *pinfo) {
#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "[username: %s][db: %s][query: %s][response: %d][pinfo: %p]",
	     pinfo->mysql_username, pinfo->mysql_db,
	     pinfo->mysql_query, pinfo->mysql_response_code, pinfo);
#endif

  if(mysql_dump_dir[0] != '\0') {
    char buf[64], buf1[64];
    char *client = _intoa((bkt->core.tuple.dport == MYSQL_SERVER_PORT) ? bkt->core.tuple.src : bkt->core.tuple.dst, buf, sizeof(buf));
    char *server = _intoa((bkt->core.tuple.sport == MYSQL_SERVER_PORT) ? bkt->core.tuple.src : bkt->core.tuple.dst, buf1, sizeof(buf1));
    u_int begin_time = min(bkt->core.tuple.flowTimers.firstSeenSent.tv_sec, bkt->core.tuple.flowTimers.firstSeenRcvd.tv_sec);
    u_int end_time = max(bkt->core.tuple.flowTimers.lastSeenSent.tv_sec, bkt->core.tuple.flowTimers.lastSeenRcvd.tv_sec);
    time_t now = time(NULL);

    if(fd && (fd_close_timeout < now)) {
      close_mysql_dump();
    }

    if(fd == NULL) {
      char current_dump_dir[256];
      int rc = 0;

      if(nest_dirs) {
	char creation_time[256];
	time_t theTime = time(NULL);
	struct tm *tm;

	if(readOnlyGlobals.pcapFile != NULL)
	  theTime = readOnlyGlobals.initialSniffTime.tv_sec;

	theTime -= (theTime % mysql_directory_duration);
	tm = localtime(&theTime);

	strftime(creation_time, sizeof(creation_time), "%Y/%m/%d/%H", tm);
	snprintf(current_dump_dir, sizeof(current_dump_dir), "%s%c%s",
		 mysql_dump_dir, CONST_DIR_SEP, creation_time);

	if(strcmp(last_mysql_dump_dir, current_dump_dir)) {
	  exec_mysql_cmd();
	  rc = mkdir_p(current_dump_dir);
	  num_file = 0;
	  snprintf(last_mysql_dump_dir, sizeof(last_mysql_dump_dir), "%s", current_dump_dir);
	}
      } else
	snprintf(current_dump_dir, sizeof(current_dump_dir), "%s", mysql_dump_dir);
      snprintf(last_mysql_dump_file, sizeof(buf), "%s%cmysql_%u.txt%s",
	       current_dump_dir, CONST_DIR_SEP,
	       (unsigned int)time(NULL),
	       TMP_FILE_POSTFIX);
      num_log_lines = 0;
      fd = fopen(last_mysql_dump_file, "w");
      
      if(fd) {
	traceEvent(TRACE_INFO, "Created %s", last_mysql_dump_file);
	fprintf(fd, "#\n# %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n#\n",
		"Client", "Server", "User", "Database", "Query",
		"ResponseCode", "Bytes", "BeginTime", "EndTime");
	fd_close_timeout = now + mysql_file_dump_timeout;
      } else
	traceEvent(TRACE_WARNING, "Unable to create file %s [%s]",
		   last_mysql_dump_file, strerror(errno));     
    }

    if(fd) {
      fprintf(fd, "%s\t%s\t%s\t%s\t%s\t%u\t%u\t%u\t%u\n",
	      client, server,
	      pinfo->mysql_username ? pinfo->mysql_username : "",
	      pinfo->mysql_db ? pinfo->mysql_db : "",
	      pinfo->mysql_query ? pinfo->mysql_query : "",
	      pinfo->mysql_response_code,
	      (bkt->core.tuple.flowCounters.bytesSent + bkt->core.tuple.flowCounters.bytesRcvd),
	      begin_time, end_time);

      num_log_lines++;

      if(num_log_lines == max_num_lines) {
	close_mysql_dump();
      }
    }
  }
}

/* *********************************************** */

static void mysql_dissect(FlowHashBucket *bkt,
			  const struct pcap_pkthdr *h,
			  u_char *p, 
			  u_int plen, FlowDirection flow_direction,
			  u_char *payload, int payloadLen,
			  u_int ip_offset,
			  struct packet_header *pkt_header,
			  struct mysql_plugin_info *pinfo,
			  u_char *packet) {
  int len;
  u_char *version, *username;

#ifdef DEBUG
  if(0) {
    traceEvent(TRACE_NORMAL, "BEGIN mysql_dissect() [packet_number: %d][packet_len: %d][%02X %02X][pinfo: %p]",
	       pkt_header->packet_number, pkt_header->packet_length,
	       packet[0] & 0xFF, packet[1] & 0xFF, pinfo);
  }
#endif

  if(pkt_header->is_request) {
    /* Request */

    switch(pkt_header->packet_number) {
    case 0: /* Command */
      pinfo->mysql_command = packet[0];

      switch(pinfo->mysql_command) {
      case 2: /* Use Database */
	{
	  char buf[64];

	  strcpy(pinfo->last_mysql_db, pinfo->mysql_db);
	  snprintf(pinfo->mysql_db, sizeof(pinfo->mysql_db), "%s", (char*)&packet[1]);

	  snprintf(buf, sizeof(buf), "use database %s", pinfo->mysql_db);
	  if(pinfo->mysql_query) free(pinfo->mysql_query);
	  pinfo->mysql_query = strdup(buf);
#ifdef DEBUG
	  traceEvent(TRACE_NORMAL, "%s=%s", "mysql_query", pinfo->mysql_query);
#endif
	}
	break;

      case 3: /* Query */
	if(pinfo->mysql_query) free(pinfo->mysql_query);
	len = min(pkt_header->packet_length-1, MAX_QUERY_LEN);
	pinfo->mysql_query = (char*)malloc(len+1);
	if(pinfo->mysql_query) {
	  int i = 1;

	  while(i<len) {
	    u_int8_t stop = 0;

            switch(packet[i]) {
            case '\t':
            case '\r':
            case '\n':
            case ' ':
	      break;
	    default:
	      stop = 1;
	      break;
	    }

	    if(!stop)
	      i++;
	    else
	      break;
	  }

	  len = len-i+1;
	  strncpy(pinfo->mysql_query, (char*)&packet[i], len);
	  pinfo->mysql_query[len] = '\0';

	  for(i=0; i<len; i++) {
	    switch(pinfo->mysql_query[i]) {
	    case '\t':
	    case '\r':
	    case '\n':
	      pinfo->mysql_query[i] = ' ';
	      break;
	    }
	  }

#ifdef DEBUG
	  traceEvent(TRACE_NORMAL, "%s=%s", "mysql_query", pinfo->mysql_query);
#endif
	}
	break;
      }
      break;

    case 1: /* Login Request */
      username = &packet[32];
      snprintf(pinfo->mysql_username, sizeof(pinfo->mysql_username), "%s", username);
#ifdef DEBUG
      traceEvent(TRACE_NORMAL, "==>>> %s=%s", "mysql_username", pinfo->mysql_username);
#endif
      break;

    default: /* Request */
      break;
    }
  } else {
    /* Response */

    switch(pkt_header->packet_number) {
    case 0: /* Server Greeting */
      version = &packet[1];
      snprintf(pinfo->mysql_server_version, sizeof(pinfo->mysql_server_version), "%s", (char*)version);
#ifdef DEBUG
      traceEvent(TRACE_NORMAL, "%s=%s", "mysql_server_version", pinfo->mysql_server_version);
#endif
      break;

    case 1: /* Server Response */
      if((pkt_header->packet_length == 1) || (packet[0] != 0xFF)) {
	pinfo->mysql_response_code = 0; /* OK */
      } else {
	pinfo->mysql_response_code = (packet[1] & 0xFF) + (packet[2] & 0xFF) * 256;

	if(pinfo->mysql_command == 2 /* Use Database */) {
	  strcpy(pinfo->mysql_db, pinfo->last_mysql_db);
	}
      }

#ifdef DEBUG
      {
	char msg[256];

	if(pinfo->mysql_response_code != 0) {
	  int len = min(pkt_header->packet_length-9, sizeof(msg)-1);

	  strncpy(msg, (char*)&packet[9], len);
	  msg[len] = '\0';
	} else
	  msg[0] = '\0';

	traceEvent(TRACE_NORMAL, "%s=%d [%s]", "mysql_response_code", pinfo->mysql_response_code, msg);
      }
#endif

      if(pinfo->mysql_query != NULL) {
	dumpMySQLlog(bkt, pinfo);

	exportBucket(bkt, 0);
	resetBucketStats(bkt, h, (u_char*)p, plen, ip_offset, flow_direction, payload, payloadLen);

	free(pinfo->mysql_query); pinfo->mysql_query = NULL;
      }
      break;

    default: /* Response */
      break;
    }
  }
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void mysqlPlugin_packet(u_char new_bucket,
			       int packet_if_idx /* -1 = unknown */,
			       void *pluginData,
			       FlowHashBucket *bkt,
			       FlowDirection flow_direction,
			       u_int16_t ip_offset, u_short proto, u_char isFragment,
			       u_short numPkts, u_char tos,
			       u_short vlanId, struct eth_header *ehdr,
			       IpAddress *src, u_short sport,
			       IpAddress *dst, u_short dport,
			       u_int plen, u_int8_t flags,
			       u_int32_t tcpSeqNum, u_int8_t icmpType,
			       u_short numMplsLabels,
			       u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
			       const struct pcap_pkthdr *h, const u_char *p,
			       u_char *payload, int payloadLen) {
  PluginInformation *info;
  struct mysql_plugin_info *pinfo;

#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "mysqlPlugin_packet(len=%d, new_bucket=%d, tos=%d)", h->len, new_bucket, tos);
#endif

  if(new_bucket) {
    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return; /* Not enough memory */
    }

    info->pluginPtr  = (void*)&mysqlPlugin;
    pluginData = info->pluginData = malloc(sizeof(struct mysql_plugin_info));

    if(info->pluginData == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      free(info);
      return; /* Not enough memory */
    } else
      memset(info->pluginData, 0, sizeof(struct mysql_plugin_info));

    info->next = bkt->ext->plugin;
    info->plugin_used = 0;  
    bkt->ext->plugin = info;
  }

  /*
    Do not put the checks below at the beginning of the function as otherwise
    the flow will not be able to export info about the template specified
  */
  if((sport != MYSQL_SERVER_PORT) && (dport != MYSQL_SERVER_PORT))
    return;

  pinfo = (struct mysql_plugin_info*)pluginData;
  if(!pinfo) return;

  if(bkt->ext->plugin) bkt->ext->plugin->plugin_used = 1; /* This flow is dissected by this plugin */
  packet_id++;

  if(payloadLen > 0) {
#ifdef PACKET_SPLIT_DEBUG
    traceEvent(TRACE_NORMAL, "*** Payload %d [packetId %d]", payloadLen, packet_id);
#endif

    char payloadBuf[PAYLOAD_BUF_LEN], *mysqlbuf;
    u_int mysqlbuf_len;
    struct packet_header pkt_header;

    if(pinfo->previous_pkt_len > 0) {
#ifdef PACKET_SPLIT_DEBUG
      traceEvent(TRACE_NORMAL, "Merging packet with previous stored buffer [%d bytes]", pinfo->previous_pkt_len);
#endif
      memcpy(payloadBuf, pinfo->previous_pkt, pinfo->previous_pkt_len);
      memcpy(&payloadBuf[pinfo->previous_pkt_len], payload, payloadLen);
      mysqlbuf = payloadBuf, mysqlbuf_len = payloadLen + pinfo->previous_pkt_len;
    } else {
      mysqlbuf_len = payloadLen, mysqlbuf = (char*)payload;
    }

#ifdef PACKET_SPLIT_DEBUG
    traceEvent(TRACE_NORMAL, "Dissecting %d bytes packet [payloadLen %d][prevPkt %d]",
	       mysqlbuf_len, payloadLen, pinfo->previous_pkt_len);
#endif

    if(dport == MYSQL_SERVER_PORT) {
      /* Client -> Server */

      if(tcpSeqNum <= pinfo->last_client2server_seqId) {
	/* Ignoring retransmissions */
#ifdef PACKET_SPLIT_DEBUG
        traceEvent(TRACE_NORMAL, "Skipping client->server retransmission [last seq num: %u][received seq num: %u]",
		   pinfo->last_client2server_seqId, tcpSeqNum);
#endif
	return;
      } else
	pinfo->last_client2server_seqId = tcpSeqNum;

      pkt_header.is_request = 1;
    } else {
      /* Server -> Client */

      if(tcpSeqNum <= pinfo->last_server2client_seqId) {
	/* Ignoring retransmissions */
#ifdef PACKET_SPLIT_DEBUG
        traceEvent(TRACE_NORMAL, "Skipping server->client retransmission [last seq num: %u][received seq num: %u]",
		   pinfo->last_server2client_seqId, tcpSeqNum);
#endif
	return;
      } else
	pinfo->last_server2client_seqId = tcpSeqNum;

      pkt_header.is_request = 0;
    }

    while(mysqlbuf_len > 0) {
      if(mysqlbuf_len <= 4) {
	/* The header does not fit into this packet: let's buffer it */
	memcpy(pinfo->previous_pkt, mysqlbuf, mysqlbuf_len);
	pinfo->previous_pkt_len = mysqlbuf_len;
	return;
      } else {
#ifdef PACKET_SPLIT_DEBUG
	traceEvent(TRACE_NORMAL, "%02X %02X %02X", mysqlbuf[0], mysqlbuf[1], mysqlbuf[2]);
#endif

	pkt_header.packet_length = (mysqlbuf[0] & 0xFF) + (mysqlbuf[1] & 0xFF) * 256 + (mysqlbuf[2] & 0xFF) * 256;
	pinfo->last_pkt_number = pkt_header.packet_number = (mysqlbuf[3] & 0xFF);

	if(pkt_header.packet_length > PCAP_LONG_SNAPLEN) {
#ifdef PACKET_SPLIT_DEBUG
	  /* TODO We need to implement packet reordering: this could be the cause of the problem */
	  traceEvent(TRACE_WARNING, "[MYSQL] Our dissector is in nuts: the lenght %u is not acceptable ", pkt_header.packet_length);
#endif
	  pinfo->previous_pkt_len = 0;
	  return;
	}

	if(mysqlbuf_len >= (pkt_header.packet_length+4)) {
#ifdef PACKET_SPLIT_DEBUG
	  traceEvent(TRACE_NORMAL,
		     "Dissecting %d bytes MySQL packet [packet number %d] [mysqlbufLeft: %d bytes]",
		     pkt_header.packet_length, pkt_header.packet_number, mysqlbuf_len);
#endif

	  mysql_dissect(bkt, h, (u_char*)p, plen, flow_direction,
			payload, payloadLen, ip_offset,
			&pkt_header, pinfo, (u_char*)&mysqlbuf[4]);
	  pkt_header.packet_length += 4; /* Include header too */

#ifdef PACKET_SPLIT_DEBUG
	  traceEvent(TRACE_NORMAL, "Moving %d bytes forward", pkt_header.packet_length);
#endif
	  mysqlbuf_len -= pkt_header.packet_length, mysqlbuf = &mysqlbuf[pkt_header.packet_length];
	} else {
#ifdef PACKET_SPLIT_DEBUG
	  traceEvent(TRACE_NORMAL,
		     "Skipping short MySQL packet [expected %d, got %d]: will be merged with the next packet",
		     pkt_header.packet_length, mysqlbuf_len);
#endif

	  if(mysqlbuf_len < MAX_PREV_PKT_BUF_LEN) {
	    /* Buffer this packet as it's a partial packet that will be processed
	       as oon as we will process the next one
	    */
	    memcpy(pinfo->previous_pkt, mysqlbuf, mysqlbuf_len);
	    pinfo->previous_pkt_len = mysqlbuf_len;
	    return;
	  }

	  break;
	}
      }
    }
  }

  pinfo->previous_pkt_len = 0; /* Just to be safe */
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void mysqlPlugin_delete(FlowHashBucket* bkt, void *pluginData) {
  struct mysql_plugin_info *pinfo = (struct mysql_plugin_info*)pluginData;

  if(pinfo != NULL) {
    if(pinfo->mysql_query) free(pinfo->mysql_query);
    free(pinfo);
  }
}

/* *********************************************** */

/* Handler called at startup when the template is read */

static V9V10TemplateElementId* mysqlPlugin_get_template(char* template_name) {
  int i;

  for(i=0; mysqlPlugin_template[i].templateElementId != 0; i++)
    if(!strcmp(template_name, mysqlPlugin_template[i].netflowElementName))
      return(&mysqlPlugin_template[i]);

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int mysqlPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
			      FlowDirection direction /* 0 = src->dst, 1 = dst->src */,
			      FlowHashBucket *bkt, char *outBuffer,
			      uint* outBufferBegin, uint* outBufferMax) {
  int i;

  if(theTemplate == NULL) return(-1);

  for(i=0; mysqlPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == mysqlPlugin_template[i].templateElementId) {
      struct mysql_plugin_info *pinfo = (struct mysql_plugin_info *)pluginData;

      if((*outBufferBegin)+mysqlPlugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      if(pinfo) {
	char sql_buf[512] = { 0 };
	uint len;

	switch(mysqlPlugin_template[i].templateElementId) {
	case BASE_ID:
	  copyLen((u_char*)pinfo->mysql_server_version, mysqlPlugin_template[i].templateElementLen,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case BASE_ID+1:
	  copyLen((u_char*)pinfo->mysql_username, mysqlPlugin_template[i].templateElementLen,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case BASE_ID+2:
	  copyLen((u_char*)pinfo->mysql_db, mysqlPlugin_template[i].templateElementLen,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case BASE_ID+3:
	  snprintf(sql_buf, sizeof(sql_buf), "%s", pinfo->mysql_query ? pinfo->mysql_query : "");

	  if((readOnlyGlobals.netFlowVersion == 10)
	     && (mysqlPlugin_template[i].variableFieldLength == VARIABLE_FIELD_LEN)) {
	    len = min(strlen(sql_buf), mysqlPlugin_template[i].templateElementLen);

	    if(len < 255)
	      copyInt8(len, outBuffer, outBufferBegin, outBufferMax);
	    else {
	      copyInt8(255, outBuffer, outBufferBegin, outBufferMax);
	      copyInt16(len, outBuffer, outBufferBegin, outBufferMax);
	    }
	  }
	  else
	    len = mysqlPlugin_template[i].templateElementLen;

	  memcpy(&outBuffer[*outBufferBegin], sql_buf, len);
#ifdef DEBUG
	  traceEvent(TRACE_INFO, "==> Query='%s'", sql_buf);
#endif
	  (*outBufferBegin) += len;
	  break;

	case BASE_ID+4:
	  copyInt16(pinfo->mysql_response_code, outBuffer, outBufferBegin, outBufferMax);
#ifdef DEBUG
	  traceEvent(TRACE_INFO, "==> Response='%d'", pinfo->mysql_response_code);
#endif
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

/* Handler called whenever a flow attribute needs to be printed on file */

static int mysqlPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
			     FlowDirection direction /* 0 = src->dst, 1 = dst->src */,
			     FlowHashBucket *bkt, char *line_buffer, uint line_buffer_len) {
  int i;

  for(i=0; mysqlPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == mysqlPlugin_template[i].templateElementId) {
      struct mysql_plugin_info *pinfo = (struct mysql_plugin_info *)pluginData;

      if(pinfo) {
	switch(mysqlPlugin_template[i].templateElementId) {
	case BASE_ID:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   pinfo->mysql_server_version ? pinfo->mysql_server_version : "");
	  break;
	case BASE_ID+1:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   pinfo->mysql_username ? pinfo->mysql_username : "");
	  break;
	case BASE_ID+2:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   pinfo->mysql_db ? pinfo->mysql_db : "");
	  break;
	case BASE_ID+3:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   pinfo->mysql_query ? pinfo->mysql_query : "");
	  break;
	case BASE_ID+4:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d",
		   pinfo->mysql_response_code);
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

static V9V10TemplateElementId* mysqlPlugin_conf(void) {
  return(mysqlPlugin_template);
}

/* *********************************************** */

static void mysqlPlugin_term(void) {
  traceEvent(TRACE_INFO, "Terminating mysql plugin...");

  close_mysql_dump();
  exec_mysql_cmd();
}

/* *********************************************** */

static void mysqlPlugin_help(void) {
  printf("  --mysql-dump-dir <dump dir>                        | Directory where MySQL logs will be dumped\n");
  printf("  --mysql-exec-cmd <cmd>                             | Command executed whenever a directory has been dumped\n");
  printf("  --max-mysql-log-lines                              | Max number of lines per log file (default %u)\n", max_num_lines);
}
/* *********************************************** */

/* Plugin entrypoint */
static PluginEntryPoint mysqlPlugin = {
  NPROBE_REVISION,
  "MySQL Plugin",
  "1.0",
  "Handle MySQL protocol",
  "L. Deri <deri@ntop.org>",
  0 /* not always enabled */, 1, /* enabled */
  PLUGIN_DONT_NEED_LICENSE,
  mysqlPlugin_init,
  mysqlPlugin_term,
  mysqlPlugin_conf,
  mysqlPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  mysqlPlugin_packet,
  mysqlPlugin_get_template,
  mysqlPlugin_export,
  mysqlPlugin_print,
  NULL,
  NULL,
  mysqlPlugin_help,
  NULL, 0, 0
};

/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginEntryPoint* mysqlPluginEntryFctn(void)
#else
PluginEntryPoint* PluginEntryFctn(void)
#endif
{
  return(&mysqlPlugin);
}

