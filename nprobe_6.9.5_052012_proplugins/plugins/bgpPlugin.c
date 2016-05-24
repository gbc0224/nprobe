/*
 *  Copyright (C) 2010-12 Luca Deri <deri@ntop.org>
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

#include "patricia.h"
#include "patricia.c"


#define BASE_ID           NTOP_BASE_ID+290

static V9V10TemplateElementId bgpPlugin_template[] = {
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID,    STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "SRC_AS_PATH_1", "", "Src AS path position 1" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+1,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "SRC_AS_PATH_2", "", "Src AS path position 2" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+2,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "SRC_AS_PATH_3", "", "Src AS path position 3" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+3,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "SRC_AS_PATH_4", "", "Src AS path position 4" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+4,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "SRC_AS_PATH_5", "", "Src AS path position 5" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+5,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "SRC_AS_PATH_6", "", "Src AS path position 6" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+6,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "SRC_AS_PATH_7", "", "Src AS path position 7" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+7,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "SRC_AS_PATH_8", "", "Src AS path position 8" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+8,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "SRC_AS_PATH_9", "", "Src AS path position 9" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+9,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "SRC_AS_PATH_10", "", "Src AS path position 10" },
  /* IMPORTANT - If you extend the fields please also update "#define MAX_AS_PATH_LEN 10" */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+10,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DST_AS_PATH_1", "", "Dest AS path position 1" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+11,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DST_AS_PATH_2", "", "Dest AS path position 2" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+12,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DST_AS_PATH_3", "", "Dest AS path position 3" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+13,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DST_AS_PATH_4", "", "Dest AS path position 4" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+14,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DST_AS_PATH_5", "", "Dest AS path position 5" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+15,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DST_AS_PATH_6", "", "Dest AS path position 6" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+16,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DST_AS_PATH_7", "", "Dest AS path position 7" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+17,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DST_AS_PATH_8", "", "Dest AS path position 8" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+18,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DST_AS_PATH_9", "", "Dest AS path position 9" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+19,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DST_AS_PATH_10", "", "Dest AS path position 10" },
  /* IMPORTANT - If you extend the fields please also update "#define MAX_AS_PATH_LEN 10" */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, 0, STATIC_FIELD_LEN, 0, 0, 0, NULL, NULL, NULL }
};

/* *********************************************** */

typedef struct {
  u_int8_t path_len;
  u_int32_t *path;
} as_path;

/* *********************************************** */

static PluginEntryPoint bgpPlugin; /* Forward */
static patricia_tree_t *ptree = NULL;
static int bgp_sock = -1;
static int incoming_bgp_port = 0;
static u_int32_t numNodes = 0;
static pthread_t bgpListenThread;
static pthread_rwlock_t ptree_lock;

/* ******************************************* */

void fill_prefix(prefix_t *p, int f, struct in_addr *a, int b, int mb) {
  do {
    if(b < 0 || b > mb) {
      traceEvent(TRACE_WARNING, "Invalid key [bits=%d][maxbits=%d]", b, mb);
      break;
    }

    memcpy(&p->add.sin, a, (mb+7)/8);
    p->family = f;
    p->bitlen = b;
    p->ref_count = 0;
  } while (0);
}

/* *********************************************** */

void dump_as_path(as_path *path) {
  int i;

  for(i=0; i<path->path_len; i++)
    traceEvent(TRACE_NORMAL, "\t%u@%d", path->path[i], i);
}

/* *********************************************** */

void free_ptree_data(void *data) {
  as_path *path = (as_path*)data;

  /*
    traceEvent(TRACE_WARNING, "free_ptree_data(%p) [len=%d]", path, path->path_len);
    dump_as_path(path);
  */

  free(path->path);
  free(path);
}

/* ******************************************* */

patricia_node_t* add_to_ptree(patricia_tree_t *tree, int family, struct in_addr *addr, int bits, void *data) {
  prefix_t prefix;
  patricia_node_t *node;

  fill_prefix(&prefix, family, addr, bits, tree->maxbits);
  pthread_rwlock_wrlock(&ptree_lock);
  node = patricia_lookup(tree, &prefix);

  if((patricia_node_t *)0 != node) {
    /*
      We have added a new node that was under a previous node
      for this reason we overwrite node->data but NOT
      free it as it's still used by its father
    */
    node->data = data;
  } else
    numNodes++;

  pthread_rwlock_unlock(&ptree_lock);
 return(node);
}

/* ******************************************* */

int remove_from_ptree(patricia_tree_t *tree, int family, struct in_addr *addr, int bits) {
  prefix_t prefix;
  patricia_node_t *node;
  int rc;

  fill_prefix(&prefix, family, addr, bits, tree->maxbits);

  pthread_rwlock_wrlock(&ptree_lock);
  node = patricia_lookup(tree, &prefix);

  if((patricia_node_t *)0 != node) {
    if(node->data) {
      free_ptree_data(node->data);
      node->data = NULL;
    }

    patricia_remove(tree, node);
    numNodes--;
    rc = 0;
  } else {
    rc = -1;
  }

  pthread_rwlock_unlock(&ptree_lock);
  return(rc);
}

/* ******************************************* */

void* ptree_match(patricia_tree_t *tree, int family, struct in_addr* addr, int bits) {
  prefix_t prefix;
  patricia_node_t *node;

  fill_prefix(&prefix, family, addr, bits, tree->maxbits);

  node = patricia_search_best(tree, &prefix);

  if((patricia_node_t *)0 != node) {
    return(node->data);
  } else {
    return(NULL);
  }
}

/* ******************************************* */

char* readTcpLine(int sock, char *buf, u_int buflen) {
  u_int i;

  for(i=0; i<buflen-1; i++) {
    if(recv(sock, &buf[i], 1, 0) <= 0) {
      return(NULL);
    }

    if(buf[i] == '\n') {
      break;
    }
  }

  buf[i] = '\0';

  if(i == 0)
    return(NULL);
  else
    return(buf);
}


/* ******************************************* */

static void* bgpListener(void *not_used) {
  int clientSock;
  socklen_t clntLen;
  struct sockaddr_in bgpClntAddr; /* Client address */

  /* Run forever */
  while(!readWriteGlobals->shutdownInProgress) {
    /* Set the size of the in-out parameter */
    clntLen = sizeof(bgpClntAddr);

    /* Wait for a client to connect */
    if((clientSock = accept(bgp_sock, (struct sockaddr *) &bgpClntAddr, &clntLen)) < 0) {
      traceEvent(TRACE_WARNING, "BGP accept() failed");
    } else {
      char bgpBuffer[512], *line;

      traceEvent(TRACE_INFO, "Handling BGP client %s", inet_ntoa(bgpClntAddr.sin_addr));

      while((line = readTcpLine(clientSock, bgpBuffer, sizeof(bgpBuffer))) != NULL) {
	char *addr, *equal, *bits, *aspath, *slash, *as_entry, *as_ptr= NULL;
	struct in_addr pin;

	//traceEvent(TRACE_INFO, "=> %s", line);

	addr = &line[1];
	slash = strchr(addr, '/');

	if(slash) {
	  slash[0] = '\0';
	  bits = &slash[1];
	  equal = strchr(bits, '=');

	  if(equal) {
	    equal[0] = '\0';
	    aspath = &equal[1];

	    if(line[0] == '+') {
	      as_path *path;
	      char *at = strchr(aspath, '@');
	      int num, id;

	      if(at == NULL) continue;
	      at[0]= '\0';
	      num = atoi(aspath);

	      if(num > 0) {
		path = (as_path*)malloc(sizeof(as_path));

		if(path == NULL) {
		  traceEvent(TRACE_INFO, "Not enough memory (1)");
		  continue;
		}

		if(num > MAX_AS_PATH_LEN) num = MAX_AS_PATH_LEN;
		path->path_len = num;
		path->path = (u_int32_t*)calloc(num, sizeof(u_int32_t));

		if(path->path == NULL) {
		  traceEvent(TRACE_INFO, "Not enough memory (2)");
		  free(path);
		  continue;
		}

		/* Format: (number of elements)@(elem 1),(elem 2).... */
		for(id = 0, as_entry = strtok_r(&at[1], ",", &as_ptr);
		    as_entry && (id < num);
		    as_entry = strtok_r(NULL, ",", &as_ptr)) {
		  path->path[id] = atoi(as_entry);
		  //traceEvent(TRACE_NORMAL, "\t%d@%u [%s]", id, path->path[id], bits);
		  id++;
		}

		inet_aton(addr, &pin);
		add_to_ptree(ptree, AF_INET, &pin, atoi(bits), path);
	      }
	    } else if(line[0] == '-') {
	      remove_from_ptree(ptree, AF_INET, &pin, atoi(bits));
	    }
	  }
	}

      }
    }

    close(clientSock);
  }

  return(NULL);
}

/* ******************************************* */

void bgpFillASInfo(FlowHashBucket *bkt) {
  struct in_addr pin;
  as_path *path;

  if(bkt->core.tuple.src.ipVersion == 6) {
    /* We don't support IPv6 yet */
    return;
  }

  pthread_rwlock_wrlock(&ptree_lock);

  pin.s_addr = htonl(bkt->core.tuple.src.ipType.ipv4);
  path = ptree_match(ptree, AF_INET, &pin, 32);

  if(bkt->ext->srcInfo.aspath == NULL) bkt->ext->srcInfo.aspath = (u_int32_t*)calloc(MAX_AS_PATH_LEN, sizeof(u_int32_t));
  if(path && bkt->ext->srcInfo.aspath) {
    memcpy(bkt->ext->srcInfo.aspath, path->path, path->path_len*sizeof(u_int32_t));
    bkt->ext->srcInfo.aspath_len = path->path_len;
  } else
    bkt->ext->srcInfo.aspath_len = 0;

  /* ********************************* */

  pin.s_addr = htonl(bkt->core.tuple.dst.ipType.ipv4);
  path = ptree_match(ptree, AF_INET, &pin, 32);

  if(bkt->ext->dstInfo.aspath == NULL) bkt->ext->dstInfo.aspath = (u_int32_t*)calloc(MAX_AS_PATH_LEN, sizeof(u_int32_t));
  if(path && bkt->ext->dstInfo.aspath) {
    memcpy(bkt->ext->dstInfo.aspath, path->path, path->path_len*sizeof(u_int32_t));
    bkt->ext->dstInfo.aspath_len = path->path_len;
  } else
    bkt->ext->dstInfo.aspath_len = 0;

  pthread_rwlock_unlock(&ptree_lock);

  /* traceEvent(TRACE_NORMAL, "AS Path [%d/%d]", bkt->ext->srcInfo.aspath_len, bkt->ext->dstInfo.aspath_len); */
}

/* ******************************************* */

u_int32_t bgpIp2AS(IpAddress ip) {
  as_path *path;
  u_int32_t as = 0;

  pthread_rwlock_wrlock(&ptree_lock);

  if(ip.ipVersion == 4) {
    struct in_addr pin;

    pin.s_addr = htonl(ip.ipType.ipv4);
    path = ptree_match(ptree, AF_INET, &pin, 32);
  } else {
    path = NULL; /* FIX - Not yet supported */
  }

  if(path)
    as = path->path[path->path_len-1];

  pthread_rwlock_unlock(&ptree_lock);

  return(as);
}

/* ******************************************* */

void bgpPlugin_init() {
  int size = 32 /* IPv4 */; /* Use 128 for AF_INET6 */
  struct sockaddr_in bgpServAddr; /* Local address */
  int sockopt = 1, i;

  for(i=0; i<readOnlyGlobals.argc; i++) {
    if((!strcmp(readOnlyGlobals.argv[i], "--bgp-port")) && ((i+1) < readOnlyGlobals.argc)) {
      incoming_bgp_port = atoi(readOnlyGlobals.argv[i+1]);
      break;
    }
  }

  if(incoming_bgp_port == 0) {
    traceEvent(TRACE_INFO, "BGP plugin is disabled (--bgp-port has not been specified)");
    return;
  }

  traceEvent(TRACE_NORMAL, "Initializing BGP plugin");

  if((bgp_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    traceEvent(TRACE_ERROR, "Unable to create BGP socket");
    exit(-1);
  }

  /* Construct local address structure */
  memset(&bgpServAddr, 0, sizeof(bgpServAddr));    /* Zero out structure */
  bgpServAddr.sin_family = AF_INET;                /* Internet address family */
  bgpServAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
  bgpServAddr.sin_port = htons(incoming_bgp_port); /* Local port */

  /* Bind to the local address */
  if(bind(bgp_sock, (struct sockaddr *) &bgpServAddr, sizeof(bgpServAddr)) < 0) {
    traceEvent(TRACE_ERROR, "Unable to bind BGP socket at port %d", incoming_bgp_port);
    exit(-1);
  }

  setsockopt(bgp_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

  /* Mark the socket so it will listen for incoming connections */
  if(listen(bgp_sock, 1) < 0) {
    traceEvent(TRACE_ERROR, "Unable to listen() on BGP socket");
    exit(-1);
  }

  ptree = New_Patricia(size);

  pthread_rwlock_init(&ptree_lock, NULL);
  pthread_create(&bgpListenThread, NULL, bgpListener, NULL);
  setIp2AS(bgpIp2AS);
  setFillASInfo(bgpFillASInfo);

  traceEvent(TRACE_NORMAL, "BGP plugin is ready...  (listening port %d)", incoming_bgp_port);
}

/* *********************************************** */

void bgpPlugin_term(void) {
  if(incoming_bgp_port > 0) {
    close(bgp_sock);
    setIp2AS(NULL);
    setFillASInfo(NULL);
    if(ptree) Destroy_Patricia(ptree, free_ptree_data);
  }

  traceEvent(TRACE_INFO, "BGP plugin is shutdown");
}

/* *********************************************** */

/* Handler called at startup when the template is read */

static V9V10TemplateElementId* bgpPlugin_get_template(char* template_name) {
  int i;

  for(i=0; bgpPlugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, bgpPlugin_template[i].netflowElementName)) {
      return(&bgpPlugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

static u_int32_t getAsPathElement(FlowHashBucket *bkt,
				 FlowDirection direction /* 0 = src->core.tuple.dst, 1 = dst->core.tuple.src */,
				 u_int8_t as_path_element_id /* 0...MAX_AS_PATH_LEN */) {
  HostInfo *host = (direction == src2dst_direction) ? &bkt->ext->srcInfo : &bkt->ext->dstInfo;
  u_int32_t ret;

  if(host->aspath) {
    /* The last element is the host AS, the first one is our AS */
    ret = host->aspath[as_path_element_id];
  } else
    ret = 0;

  /* traceEvent(TRACE_NORMAL, "getAsPathElement(%d) = %d", as_path_element_id, ret); */

  return(ret);
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int bgpPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
			    FlowDirection direction /* 0 = src->core.tuple.dst, 1 = dst->core.tuple.src */,
			    FlowHashBucket *bkt, char *outBuffer,
			    uint* outBufferBegin, uint* outBufferMax) {
  int i;

  if(theTemplate == NULL) return(-1);

  for(i=0; bgpPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == bgpPlugin_template[i].templateElementId) {
      if((*outBufferBegin)+bgpPlugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      switch(bgpPlugin_template[i].templateElementId) {
      case BASE_ID:   copyInt32(getAsPathElement(bkt, direction, 0), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+1: copyInt32(getAsPathElement(bkt, direction, 1), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+2: copyInt32(getAsPathElement(bkt, direction, 2), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+3: copyInt32(getAsPathElement(bkt, direction, 3), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+4: copyInt32(getAsPathElement(bkt, direction, 4), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+5: copyInt32(getAsPathElement(bkt, direction, 5), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+6: copyInt32(getAsPathElement(bkt, direction, 6), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+7: copyInt32(getAsPathElement(bkt, direction, 7), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+8: copyInt32(getAsPathElement(bkt, direction, 8), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+9: copyInt32(getAsPathElement(bkt, direction, 9), outBuffer, outBufferBegin, outBufferMax); break;

      case BASE_ID+10: copyInt32(getAsPathElement(bkt, direction, 0), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+11: copyInt32(getAsPathElement(bkt, direction, 1), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+12: copyInt32(getAsPathElement(bkt, direction, 2), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+13: copyInt32(getAsPathElement(bkt, direction, 3), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+14: copyInt32(getAsPathElement(bkt, direction, 4), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+15: copyInt32(getAsPathElement(bkt, direction, 5), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+16: copyInt32(getAsPathElement(bkt, direction, 6), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+17: copyInt32(getAsPathElement(bkt, direction, 7), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+18: copyInt32(getAsPathElement(bkt, direction, 8), outBuffer, outBufferBegin, outBufferMax); break;
      case BASE_ID+19: copyInt32(getAsPathElement(bkt, direction, 9), outBuffer, outBufferBegin, outBufferMax); break;

      default:
	return(-1); /* Not handled */
      }

      return(0);
    }
  }

  return(-1); /* Not handled */
}

/* *********************************************** */

static int bgpPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
			   FlowDirection direction /* 0 = src->core.tuple.dst, 1 = dst->core.tuple.src */,
			   FlowHashBucket *bkt, char *line_buffer, uint line_buffer_len) {
  int i;

  for(i=0; bgpPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == bgpPlugin_template[i].templateElementId) {

      switch(bgpPlugin_template[i].templateElementId) {
      case BASE_ID:   snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 0)); break;
      case BASE_ID+1: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 1)); break;
      case BASE_ID+2: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 2)); break;
      case BASE_ID+3: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 3)); break;
      case BASE_ID+4: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 4)); break;
      case BASE_ID+5: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 5)); break;
      case BASE_ID+6: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 6)); break;
      case BASE_ID+7: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 7)); break;
      case BASE_ID+8: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 8)); break;
      case BASE_ID+9: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 9)); break;

      case BASE_ID+10: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 0)); break;
      case BASE_ID+11: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 1)); break;
      case BASE_ID+12: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 2)); break;
      case BASE_ID+13: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 3)); break;
      case BASE_ID+14: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 4)); break;
      case BASE_ID+15: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 5)); break;
      case BASE_ID+16: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 6)); break;
      case BASE_ID+17: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 7)); break;
      case BASE_ID+18: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 8)); break;
      case BASE_ID+19: snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", getAsPathElement(bkt, direction, 9)); break;

      default:
	return(-1); /* Not handled */
      }

      return(0);
    }
  }

  return(-1); /* Not handled */
}

/* *********************************************** */

static V9V10TemplateElementId* bgpPlugin_conf(void) {
  return(bgpPlugin_template);
}

/* *********************************************** */

static void bgpPlugin_packet(u_char new_bucket, 
			     int packet_if_idx /* -1 = unknown */,
			     void *pluginData,
			     FlowHashBucket* bkt,
			     FlowDirection flow_direction,
			     u_int16_t ip_offset, u_short proto, u_char isFragment,
			     u_short numPkts, u_char tos,
			     u_short vlanId, struct eth_header *ehdr,
			     IpAddress *src, u_short sport,
			     IpAddress *dst, u_short dport,
			     u_int len, u_int8_t flags, u_int32_t tcpSeqNum,
			     u_int8_t icmpType,
			     u_short numMplsLabels,
			     u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
			     const struct pcap_pkthdr *h, const u_char *p,
			     u_char *payload, int payloadLen) {
  /* traceEvent(TRACE_INFO, "bgpPlugin_packet(%d)", payloadLen); */

  if(new_bucket) {
    PluginInformation *info;

    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return; /* Not enough memory */
    }

    pluginData = info->pluginData = NULL;
    info->pluginPtr  = (void*)&bgpPlugin;

    info->next = bkt->ext->plugin;
    bkt->ext->plugin = info;
  }
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void bgpPlugin_delete(FlowHashBucket* bkt, void *pluginData) {
  if(pluginData != NULL)
    free(pluginData);
}

/* *********************************************** */

static void bgpPlugin_help(void) {
  printf("  --bgp-port <port>                                  | TCP port on which BGP updates will be sent\n");
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginEntryPoint bgpPlugin = {
  NPROBE_REVISION,
  "BGP Update Listener",
  "0.2",
  "Implement BGP communications",
  "L.Deri <deri@ntop.org>",
  0 /* not always enabled */, 1, /* enabled */
  PLUGIN_DONT_NEED_LICENSE,
  bgpPlugin_init,
  bgpPlugin_term,
  bgpPlugin_conf,
  bgpPlugin_delete,
  0, /* Don't call packetFlowFctn for each packet */
  bgpPlugin_packet,
  bgpPlugin_get_template,
  bgpPlugin_export,
  bgpPlugin_print,
  NULL,
  NULL,
  bgpPlugin_help,
  NULL, 0, 0
};

/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginEntryPoint* bgpPluginEntryFctn(void)
#else
PluginEntryPoint* PluginEntryFctn(void)
#endif
{
  return(&bgpPlugin);
}

