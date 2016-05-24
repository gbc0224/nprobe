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

#ifdef FREEBSD
#include <pthread_np.h>

typedef cpuset_t cpu_set_t;
#endif

#ifdef sun
extern char *strtok_r(char *, const char *, char **);
#endif

#ifdef WIN32
//#define strtok_r(a, b, c) strtok(a, b)
#endif

#ifdef HAVE_SQLITE
extern void sqlite_exec_sql(char* sql);
#endif

static u_int8_t getIfIdx(struct in_addr *addr, u_int16_t *interface_id);

/* ********************** */

static char *port_mapping[0xFFFF] = { NULL };
static char *proto_mapping[0xFF] = { NULL };

/* ************************************ */

void traceEvent(const int eventTraceLevel, const char* file,
		const int line, const char * format, ...) {
  va_list va_ap;

  if(eventTraceLevel <= readOnlyGlobals.traceLevel) {
    char buf[2048], out_buf[640];
    char theDate[32], *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    /* We have two paths - one if we're logging, one if we aren't
     *   Note that the no-log case is those systems which don't support it (WIN32),
     *                                those without the headers !defined(USE_SYSLOG)
     *                                those where it's parametrically off...
     */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    if(eventTraceLevel == 0 /* TRACE_ERROR */)
      extra_msg = "ERROR: ";
    else if(eventTraceLevel == 1 /* TRACE_WARNING */)
      extra_msg = "WARNING: ";

    while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

    snprintf(out_buf, sizeof(out_buf)-1, "%s [%s:%d] %s%s", theDate,
#ifdef WIN32
	     strrchr(file, '\\')+1,
#else
	     file,
#endif
	     line, extra_msg, buf);

#ifndef WIN32
    if(readOnlyGlobals.useSyslog) {
      if(!readWriteGlobals->syslog_opened) {
	openlog(readOnlyGlobals.nprobeId, LOG_PID, LOG_DAEMON);
	readWriteGlobals->syslog_opened = 1;
      }

      syslog(LOG_INFO, "%s", out_buf);
    } else
      printf("%s\n", out_buf);
#else
    printf("%s\n", out_buf);
#endif
  }

  fflush(stdout);
  va_end(va_ap);
}


/* ************************************ */

#ifdef WIN32
unsigned long waitForNextEvent(unsigned long ulDelay /* ms */) {
  unsigned long ulSlice = 1000L; /* 1 Second */

  while(ulDelay > 0L) {
    if(ulDelay < ulSlice)
      ulSlice = ulDelay;
    Sleep(ulSlice);
    ulDelay -= ulSlice;
  }

  return ulDelay;
}

/* ******************************* */

void initWinsock32() {
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  wVersionRequested = MAKEWORD(2, 0);
  err = WSAStartup( wVersionRequested, &wsaData );
  if( err != 0 ) {
    /* Tell the user that we could not find a usable */
    /* WinSock DLL.                                  */
    traceEvent(TRACE_ERROR, "FATAL ERROR: unable to initialise Winsock 2.x.");
    exit(-1);
  }
}

/* ******************************** */

short isWinNT() {
  DWORD dwVersion;
  DWORD dwWindowsMajorVersion;

  dwVersion=GetVersion();
  dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
  if(!(dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4))
    return 1;
  else
    return 0;
}

/* ****************************************************** */
/*
  int snprintf(char *string, size_t maxlen, const char *format, ...) {
  int ret=0;
  va_list args;

  va_start(args, format);
  vsprintf(string,format,args);
  va_end(args);
  return ret;
  }
*/
#endif /* Win32 */

/* ******************************************************************* */

u_int8_t ip2mask(IpAddress *addr, HostInfo *ip) {
  if(ip->mask != 0) return(ip->mask);
  else if((readOnlyGlobals.numInterfaceNetworks == 0) || (addr->ipVersion != 4))
    return(0);
  else {
    int i;
    u_int32_t address = htonl(addr->ipType.ipv4);

    for(i=0; i<readOnlyGlobals.numInterfaceNetworks; i++) {
      if((address & readOnlyGlobals.interfaceNetworks[i].netmask) == readOnlyGlobals.interfaceNetworks[i].network) {
	// traceEvent(TRACE_INFO, "--> %d", readOnlyGlobals.interfaceNetworks[i].netmask_v6);
	ip->mask = readOnlyGlobals.interfaceNetworks[i].netmask_v6;
	return(ip->mask);
      }
    }
  }

  return(0); /* Unknown */
}

/* ******************************************************************* */

static ip_to_AS _ip_to_AS;
static fillASinfo _fillASinfo;

void initAS() {
  _ip_to_AS = NULL;
  _fillASinfo = NULL;
}

void setIp2AS(ip_to_AS ptr) {
  _ip_to_AS = ptr;
}

void setFillASInfo(fillASinfo ptr) {
  _fillASinfo = ptr;
}

void fillASInfo(FlowHashBucket *bkt) {
  if(/* (!readWriteGlobals->shutdownInProgress) && */ _fillASinfo)
    _fillASinfo(bkt);
}

/* ******************************************************************* */

static u_int32_t _ip2AS(IpAddress *ip) {
  if((!readWriteGlobals->shutdownInProgress) && (_ip_to_AS != NULL)) {
    return(_ip_to_AS(*ip));
  }

#ifdef HAVE_GEOIP
  if((readOnlyGlobals.geo_ip_asn_db == NULL)
#ifdef WIN32
     || (ip.ipVersion == 6)
#endif
     )
    return(0);
  else {
    char *rsp = NULL;
    u_int32_t as;

    pthread_rwlock_wrlock(&readWriteGlobals->geoipRwLock);
    if(ip->ipVersion == 4)
      rsp = GeoIP_name_by_ipnum(readOnlyGlobals.geo_ip_asn_db, ip->ipType.ipv4);
    else {
#ifdef HAVE_GEOIP_IPv6
#ifndef WIN32
      /* Invalid database type GeoIP ASNum Edition, expected GeoIP Organization Edition */
      if(readOnlyGlobals.geo_ip_asn_db_v6)
	rsp = GeoIP_name_by_ipnum_v6(readOnlyGlobals.geo_ip_asn_db_v6, ip->ipType.ipv6);
#endif
#endif
    }
    pthread_rwlock_unlock(&readWriteGlobals->geoipRwLock);

    as = rsp ? atoi(&rsp[2]) : 0;
    free(rsp);
    /* traceEvent(TRACE_WARNING, "--> %s (%d)", rsp, as); */
    return(as);
  }
#else
  return(0);
#endif
}

/* ************************************* */

u_int32_t _getAS(IpAddress *addr, HostInfo *bkt) {
  if(bkt->aspath && (bkt->aspath_len > 0)) {
    /* The last element is the host AS, the first one is our AS */
    bkt->asn = bkt->aspath[bkt->aspath_len-1];
  } else
    bkt->asn = _ip2AS(addr);

  /* traceEvent(TRACE_WARNING, "--> %u", ret);  */

  return(bkt->asn);
}

/* ************************************ */

u_int32_t getAS(IpAddress *addr, HostInfo *bkt) {
  return((bkt->asn != 0) ? bkt->asn : _getAS(addr, bkt));
}

/* ************************************ */

void readASs(char *path) {
#ifdef HAVE_GEOIP
  if(path == NULL)
    return;
  else {
    struct stat stats;
    char the_path[256];

    if(stat(path, &stats) == 0)
      snprintf(the_path, sizeof(the_path), "%s", path);
    else
      snprintf(the_path, sizeof(the_path), "/usr/local/nprobe/%s", path);

    if((readOnlyGlobals.geo_ip_asn_db = GeoIP_open(the_path, GEOIP_CHECK_CACHE)) != NULL) {
      traceEvent(TRACE_NORMAL, "GeoIP: loaded AS config file %s", the_path);
    } else
      traceEvent(TRACE_WARNING, "Unable to load AS file %s. AS support disabled", the_path);

    /* ********************************************* */

    strcpy(&the_path[strlen(the_path)-4], "v6.dat");

    if((readOnlyGlobals.geo_ip_asn_db_v6 = GeoIP_open(the_path, GEOIP_CHECK_CACHE)) != NULL) {
      traceEvent(TRACE_NORMAL, "GeoIP: loaded AS IPv6 config file %s", the_path);
    } else
      traceEvent(TRACE_WARNING, "Unable to load AS IPv6 file %s. AS IPv6 support disabled", the_path);
  }
#endif
}

/* ************************************ */

void readCities(char *path) {
#ifdef HAVE_GEOIP
  if(path == NULL)
    return;
  else {
    struct stat stats;
    char the_path[256];

    if(stat(path, &stats) == 0)
      snprintf(the_path, sizeof(the_path), "%s", path);
    else
      snprintf(the_path, sizeof(the_path), "/usr/local/nprobe/%s", path);

    if((readOnlyGlobals.geo_ip_city_db = GeoIP_open(the_path, GEOIP_CHECK_CACHE)) != NULL) {
      traceEvent(TRACE_NORMAL, "GeoIP: loaded cities config file %s", the_path);
    } else
      traceEvent(TRACE_WARNING, "Unable to load cities file %s. IP geolocation disabled", the_path);

    /* ********************************************* */

    strcpy(&the_path[strlen(the_path)-4], "v6.dat");

    if((readOnlyGlobals.geo_ip_city_db_v6 = GeoIP_open(the_path, GEOIP_CHECK_CACHE)) != NULL) {
      traceEvent(TRACE_NORMAL, "GeoIP: loaded IPv6 cities config file %s", the_path);
    } else
      traceEvent(TRACE_WARNING, "Unable to load IPv6 cities file %s. IPv6 cities geolocation disabled", the_path);

  }
#endif
}

/* ******************************************** */

void copyInt8(u_int8_t t8, char *outBuffer,
	      uint *outBufferBegin, uint *outBufferMax) {
  if((*outBufferBegin)+sizeof(t8) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t8, sizeof(t8));
    (*outBufferBegin) += sizeof(t8);
  }
}

/* ******************************************** */

void copyInt16(u_int16_t _t16, char *outBuffer,
	       uint *outBufferBegin, uint *outBufferMax) {
  u_int16_t t16 = htons(_t16);

  if((*outBufferBegin)+sizeof(t16) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t16, sizeof(t16));
    (*outBufferBegin) += sizeof(t16);
  }
}

/* ******************************************** */

void copyInt32(u_int32_t _t32, char *outBuffer,
	       uint *outBufferBegin, uint *outBufferMax) {
  u_int32_t t32 = htonl(_t32);

  if((*outBufferBegin)+sizeof(t32) < (*outBufferMax)) {
#ifdef DEBUG
    char buf1[32];

    printf("(8) %s\n", _intoaV4(_t32, buf1, sizeof(buf1)));
#endif

    memcpy(&outBuffer[(*outBufferBegin)], &t32, sizeof(t32));
    (*outBufferBegin) += sizeof(t32);
  }
}

/* ******************************************** */

/* 64-bit version of ntohl and htonl */
u_int64_t htonll(u_int64_t v) {
  union { u_int32_t lv[2]; u_int64_t llv; } u;
  u.lv[0] = htonl(v >> 32);
  u.lv[1] = htonl(v & 0xFFFFFFFFULL);
  return u.llv;
}

u_int64_t ntohll(u_int64_t v) {
  union { u_int32_t lv[2]; u_int64_t llv; } u;
  u.llv = v;
  return ((u_int64_t)ntohl(u.lv[0]) << 32) | (u_int64_t)ntohl(u.lv[1]);
}

/* ******************************************** */

void copyInt64(u_int64_t _t64, char *outBuffer,
	       uint *outBufferBegin, uint *outBufferMax) {
  u_int64_t t64 = htonll(_t64);

  if((*outBufferBegin)+sizeof(t64) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t64, sizeof(t64));
    (*outBufferBegin) += sizeof(t64);
  }
}

/* ******************************************** */

void copyLen(u_char *str, int strLen, char *outBuffer,
	     uint *outBufferBegin, uint *outBufferMax) {
  if((*outBufferBegin)+strLen < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], str, strLen);
    (*outBufferBegin) += strLen;
  }
}

/* ******************************************** */

u_int16_t ifIdx(FlowHashBucket *myBucket, int computeInputIfIdx) {
  u_char *mac;
  u_int16_t idx;
  struct in_addr addr;

  if(readOnlyGlobals.use_vlanId_as_ifId != vlan_disabled)
    return(myBucket->core.tuple.vlanId);

  addr.s_addr = computeInputIfIdx ? htonl(myBucket->core.tuple.src.ipType.ipv4) : htonl(myBucket->core.tuple.dst.ipType.ipv4);

  if(getIfIdx(&addr, &idx))
    return(idx);

  if(readWriteGlobals->num_src_mac_export > 0) {
    int i;

    for(i = 0; i<readWriteGlobals->num_src_mac_export; i++)
      if(computeInputIfIdx && (memcmp(myBucket->ext->srcInfo.macAddress, readOnlyGlobals.mac_if_match[i].mac_address, 6) == 0))
        return(readOnlyGlobals.mac_if_match[i].interface_id);
      else if((!computeInputIfIdx) && (memcmp(myBucket->ext->dstInfo.macAddress,readOnlyGlobals.mac_if_match[i].mac_address, 6) == 0))
        return(readOnlyGlobals.mac_if_match[i].interface_id);
  }

  if(computeInputIfIdx) {
    if(readOnlyGlobals.inputInterfaceIndex != NO_INTERFACE_INDEX)
      return(readOnlyGlobals.inputInterfaceIndex);
  } else {
    if(readOnlyGlobals.outputInterfaceIndex != NO_INTERFACE_INDEX)
      return(readOnlyGlobals.outputInterfaceIndex);
  }

  /* ...else dynamic */

  /* Calculate the input/output interface using
     the last two MAC address bytes */
  if(computeInputIfIdx)
    mac = &(myBucket->ext->srcInfo.macAddress[4]);
  else
    mac = &(myBucket->ext->dstInfo.macAddress[4]);

  idx = (mac[0] * 256) + mac[1];

  return(idx);
}

/* ******************************************** */

char* port2name(u_int16_t port, u_int8_t proto) {
#if 0
  struct servent *svt;

  if((svt = getservbyport(htons(port), proto2name(proto))) != NULL)
    return(svt->s_name);
  else {
    static char the_port[8];

    snprintf(the_port, sizeof(the_port), "%d", port);
    return(the_port);
  }
#else
  if(port_mapping[port] != NULL)
    return(port_mapping[port]);
  else if(proto == 6)  return("tcp_other");
  else if(proto == 17) return("udp_other");
  else return("<unknown>"); /* Not reached */
#endif
}

/* **************************************************************** */

void reset_bitmask(bitmask_selector *selector) {
  memset((char*)selector->bits_memory, 0, selector->num_bits/8);
}

/* **************************************************************** */

int alloc_bitmask(u_int32_t tot_bits, bitmask_selector *selector) {
  uint tot_mem = 1 + (tot_bits >> 3); /* /= 8 */

  if((selector->bits_memory = malloc(tot_mem)) != NULL) {
  } else {
    selector->num_bits = 0;
    return(-1);
  }

  selector->num_bits = tot_bits;
  reset_bitmask(selector);
  return(0);
}

/* ********************************** */

void free_bitmask(bitmask_selector *selector) {
  if(selector->bits_memory > 0) {
    free(selector->bits_memory);
    selector->bits_memory = 0;
  }
}

/* ******************************************** */

void bitmask_set(u_int32_t n, bitmask_selector* p)       { (((char*)p->bits_memory)[n >> 3] |=  (1 << (n & 7))); }
void bitmask_clr(u_int32_t n, bitmask_selector* p)       { (((char*)p->bits_memory)[n >> 3] &= ~(1 << (n & 7))); }
u_int8_t bitmask_isset(u_int32_t n, bitmask_selector* p) { return(((char*)p->bits_memory)[n >> 3] &   (1 << (n & 7))); }

/* ******************************************** */

void loadApplProtocols(void) {
  struct servent *s;

  alloc_bitmask(65536, &readOnlyGlobals.udpProto);
  alloc_bitmask(65536, &readOnlyGlobals.tcpProto);

#ifndef WIN32
  setservent(1);
#endif

  while((s = getservent()) != NULL) {
    s->s_port = ntohs(s->s_port);

    if(s->s_proto[0] == 'u')
      bitmask_set(s->s_port, &readOnlyGlobals.udpProto);
    else
      bitmask_set(s->s_port, &readOnlyGlobals.tcpProto);
  }

  endservent();

  /* Add extra protocols (if missing) */
  bitmask_set(4343 /* das   */, &readOnlyGlobals.tcpProto);
  bitmask_set(80   /* http  */, &readOnlyGlobals.tcpProto);
  bitmask_set(43   /* whois */, &readOnlyGlobals.tcpProto);
  bitmask_set(443  /* https */, &readOnlyGlobals.tcpProto);
  bitmask_set(25   /* smtp  */, &readOnlyGlobals.tcpProto);
  bitmask_set(53   /* dns   */, &readOnlyGlobals.udpProto);
}

/* ******************************************** */

u_int16_t port2ApplProtocol(u_int8_t proto, u_int16_t port) {
  u_int16_t value;

  if(proto == IPPROTO_TCP)
    value = bitmask_isset(port, &readOnlyGlobals.tcpProto);
  else if(proto == IPPROTO_UDP)
    value = bitmask_isset(port, &readOnlyGlobals.udpProto);
  else
    value = 0;

  return(value ? port : 0);
}

/* ******************************************** */

u_int16_t getFlowApplProtocol(FlowHashBucket *theFlow) {
  u_int16_t value;
  u_int16_t proto_sport = port2ApplProtocol(theFlow->core.tuple.proto, theFlow->core.tuple.sport);
  u_int16_t proto_dport = port2ApplProtocol(theFlow->core.tuple.proto, theFlow->core.tuple.dport);

  if((theFlow->core.tuple.proto == IPPROTO_TCP) || (theFlow->core.tuple.proto == IPPROTO_UDP)) {
    if(proto_sport == 0) value = proto_dport;
    else if(proto_dport == 0) value = proto_sport;
    else {
      if(theFlow->core.tuple.sport < theFlow->core.tuple.dport) value = proto_sport;
      else value = proto_dport;
    }
  } else
    value = 0;

  // traceEvent(TRACE_ERROR, "[%u/%u] -> %u", theFlow->core.tuple.sport, theFlow->core.tuple.dport, value);

  return(value);
}

/* ******************************************** */

void load_mappings() {
  struct servent *sv;
#if !defined(WIN32)
  struct protoent *pe;
#endif

  while((sv = getservent()) != NULL) {
    u_short port = ntohs(sv->s_port);
    if(port_mapping[port] == NULL)
      port_mapping[port] = strdup(sv->s_name);
  }

#if !defined(WIN32)
  endservent();
#endif

  /* ******************** */

#if !defined(WIN32)
  while((pe = getprotoent()) != NULL) {
    if(proto_mapping[pe->p_proto] == NULL) {
      proto_mapping[pe->p_proto] = strdup(pe->p_name);
      // traceEvent(TRACE_INFO, "[%d][%s]", pe->p_proto, pe->p_name);
    }
  }

  endprotoent();
#else
  proto_mapping[0] = strdup("ip");
  proto_mapping[1] = strdup("icmp");
  proto_mapping[2] = strdup("igmp");
  proto_mapping[6] = strdup("tcp");
  proto_mapping[17] = strdup("udp");
#endif
}

/* ******************************************** */

void unload_mappings() {
  int i;

  for(i=0; i<0xFFFF; i++) if(port_mapping[i])  free(port_mapping[i]);
  for(i=0; i<0xFF; i++)   if(proto_mapping[i]) free(proto_mapping[i]);
}

/* ******************************************** */

/* FIX: improve performance */
char* proto2name(u_int8_t proto) {
#if 0
  struct protoent *svt;

  if(proto == 6)       return("tcp");
  else if(proto == 17) return("udp");
  else if(proto == 1)  return("icmp");
  else if(proto == 2)  return("igmp");
  else if((svt = getprotobynumber(proto)) != NULL)
    return(svt->p_name);
  else {
    static char the_proto[8];

    snprintf(the_proto, sizeof(the_proto), "%d", proto);
    return(the_proto);
  }
#else
  if(proto_mapping[proto] != NULL) {
    // traceEvent(TRACE_INFO, "[%d][%s]", proto, proto_mapping[proto]);
    return(proto_mapping[proto]);
  } else
    return("unknown");
#endif
}

/* ******************************************** */

/*
 0                         1                   2
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                Label                  | Exp |S|
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 Label:  Label Value, 20 bits
  Exp:    Experimental Use, 3 bits
  S:      Bottom of Stack, 1 bit
*/

static int mplsLabel2int(struct mpls_labels *mplsInfo, int labelId) {
  int32_t val;

  if(mplsInfo == NULL)
    return(0);

  val = (mplsInfo->mplsLabels[labelId][0] << 12)
    + (mplsInfo->mplsLabels[labelId][1] << 4)
    + ((mplsInfo->mplsLabels[labelId][2] >> 4) & 0xff);

  return(val);
}

/* ******************************************** */

static void printRecordWithTemplate(V9V10TemplateElementId *theTemplateElement,
				    char *line_buffer, uint line_buffer_len,
				    FlowHashBucket *theFlow, FlowDirection direction) {
  char buf[128], *dst;
#ifdef HAVE_GEOIP
  GeoIPRecord *geo;
#endif
  uint len;

  /* traceEvent(TRACE_INFO, "[%s][%d]",
     theTemplate->netflowElementName, theTemplate->templateElementLen);
  */

  len = strlen(line_buffer);
  dst = &line_buffer[len];

  switch(theTemplateElement->templateElementId) {
  case 1:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == dst2src_direction ? theFlow->core.tuple.flowCounters.bytesRcvd : theFlow->core.tuple.flowCounters.bytesSent);
    break;
  case 2:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == dst2src_direction ? theFlow->core.tuple.flowCounters.pktRcvd : theFlow->core.tuple.flowCounters.pktSent);
    break;
  case 4:
    snprintf(dst, (line_buffer_len-len), "%d", theFlow->core.tuple.proto);
    break;
  case 0xFF+4:
    snprintf(dst, (line_buffer_len-len), "%s", proto2name(theFlow->core.tuple.proto));
    break;
  case 5:
    snprintf(dst, (line_buffer_len-len), "%d",
	     (theFlow->ext == NULL) ? 0 : ((direction == src2dst_direction) ? theFlow->ext->src2dstTos : theFlow->ext->dst2srcTos));
    break;
  case 6:
    snprintf(dst, (line_buffer_len-len), "%d",
	     (theFlow->ext == NULL) ? 0 : ((direction == src2dst_direction) ? theFlow->ext->protoCounters.tcp.src2dstTcpFlags : theFlow->ext->protoCounters.tcp.dst2srcTcpFlags));
    break;
  case 7:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? theFlow->core.tuple.sport : theFlow->core.tuple.dport);
    break;
  case 0xFF+7:
    snprintf(dst, (line_buffer_len-len), "%s",
	     port2name(direction == src2dst_direction ? theFlow->core.tuple.sport : theFlow->core.tuple.dport, theFlow->core.tuple.proto));
    break;
  case 8:
  case 27:
    snprintf(dst, (line_buffer_len-len), "%s",
	     _intoa(direction == src2dst_direction ? theFlow->core.tuple.src : theFlow->core.tuple.dst, buf, sizeof(buf)));
    break;
  case 9: /* IPV4_SRC_MASK */
    snprintf(dst, (line_buffer_len-len), "%d",
	     (theFlow->ext == NULL) ? 0 : 
	     ((direction == src2dst_direction) ? ip2mask(&theFlow->core.tuple.src, &theFlow->ext->srcInfo)
	      : ip2mask(&theFlow->core.tuple.dst, &theFlow->ext->dstInfo)));
    break;
  case 10: /* INPUT_SNMP */
    snprintf(dst, (line_buffer_len-len), "%d", (theFlow->ext == NULL) ? 0 : 
	     ((direction == src2dst_direction) ? theFlow->ext->if_input : theFlow->ext->if_output));
    break;
  case 11:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? theFlow->core.tuple.dport : theFlow->core.tuple.sport);
    break;
  case 0xFF+11:
    snprintf(dst, (line_buffer_len-len), "%s",
	     port2name(direction == src2dst_direction ? theFlow->core.tuple.dport : theFlow->core.tuple.sport, theFlow->core.tuple.proto));
    break;
  case 12:
  case 28:
    snprintf(dst, (line_buffer_len-len), "%s",
	     _intoa(direction == src2dst_direction ? theFlow->core.tuple.dst : theFlow->core.tuple.src, buf, sizeof(buf)));
    break;
  case 13: /* IPV4_DST_MASK */
    snprintf(dst, (line_buffer_len-len), "%d",
	     (theFlow->ext == NULL) ? 0 : 
	     ((direction == dst2src_direction) ? ip2mask(&theFlow->core.tuple.src, &theFlow->ext->srcInfo) :
	      ip2mask(&theFlow->core.tuple.dst, &theFlow->ext->dstInfo)));
    break;
  case 14: /* OUTPUT_SNMP */
    snprintf(dst, (line_buffer_len-len), "%d", 
	     (theFlow->ext == NULL) ? 0 : ((direction != src2dst_direction) ? theFlow->ext->if_input : theFlow->ext->if_output));
    break;
  case 15: /* IPV4_NEXT_HOP */
    snprintf(dst, (line_buffer_len-len), "%s", "0.0.0.0");
    break;
  case 16: /* SRC_AS */
    snprintf(dst, (line_buffer_len-len), "%d", (theFlow->ext == NULL) ? 0 : 
	     ((direction == src2dst_direction) ? getAS(&theFlow->core.tuple.src, &theFlow->ext->srcInfo) : getAS(&theFlow->core.tuple.dst, &theFlow->ext->dstInfo)));
    break;
  case 17: /* DST_AS */
    snprintf(dst, (line_buffer_len-len), "%d", (theFlow->ext == NULL) ? 0 : 
	     ((direction == src2dst_direction) ? getAS(&theFlow->core.tuple.dst, &theFlow->ext->dstInfo) : getAS(&theFlow->core.tuple.src, &theFlow->ext->srcInfo)));
    break;
  case 21:
  case 151: /* flowEndSeconds */
      snprintf(dst, (line_buffer_len-len), "%u",
	       (unsigned int)(direction == src2dst_direction ? theFlow->core.tuple.flowTimers.lastSeenSent.tv_sec :
			      theFlow->core.tuple.flowTimers.lastSeenRcvd.tv_sec));
    break;
  case 22:
  case 150: /* flowStartSeconds */
    snprintf(dst, (line_buffer_len-len), "%u",
	     (unsigned int)(direction == src2dst_direction ? theFlow->core.tuple.flowTimers.firstSeenSent.tv_sec :
			    theFlow->core.tuple.flowTimers.firstSeenRcvd.tv_sec));
    break;
  case 23:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == dst2src_direction ? theFlow->core.tuple.flowCounters.bytesSent : theFlow->core.tuple.flowCounters.bytesRcvd);
    break;
  case 24:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == src2dst_direction ? theFlow->core.tuple.flowCounters.pktRcvd : theFlow->core.tuple.flowCounters.pktSent);
    break;
  case 29:
  case 30:
    snprintf(dst, (line_buffer_len-len), "%d", 0);
    break;
  case 32:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? theFlow->ext->protoCounters.icmp.src2dstIcmpType : theFlow->ext->protoCounters.icmp.dst2srcIcmpType);
    break;
  case 34: /* SAMPLING INTERVAL */
    snprintf(dst, (line_buffer_len-len), "%d", 1 /* 1:1 = no sampling */);
    break;
  case 35: /* SAMPLING ALGORITHM */
    snprintf(dst, (line_buffer_len-len), "%d",
	     0x01 /* 1=Deterministic Sampling, 0x02=Random Sampling */);
    break;
  case 36: /* FLOW ACTIVE TIMEOUT */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.lifetimeTimeout);
    break;
  case 37: /* FLOW INACTIVE TIMEOUT */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.idleTimeout);
    break;
  case 38:
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.engineType);
    break;
  case 39:
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.engineId);
    break;
  case 40: /* TOTAL_BYTES_EXP */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readWriteGlobals->flowExportStats.totExportedBytes);
    break;
  case 41: /* TOTAL_PKTS_EXP */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readWriteGlobals->flowExportStats.totExportedPkts);
    break;
  case 42: /* TOTAL_FLOWS_EXP */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readWriteGlobals->flowExportStats.totExportedFlows);
    break;

  case 52: /* MIN_TTL */
    snprintf(dst, (line_buffer_len-len), "%d", direction == src2dst_direction ? theFlow->ext->src2dstMinTTL : theFlow->ext->dst2srcMinTTL);
    break;

  case 53: /* MAX_TTL */
    snprintf(dst, (line_buffer_len-len), "%d", direction == src2dst_direction ? theFlow->ext->src2dstMaxTTL : theFlow->ext->dst2srcMaxTTL);
    break;

  case 56: /* IN_SRC_MAC */
    snprintf(dst, (line_buffer_len-len), "%s",
	     direction == src2dst_direction ? etheraddr_string(theFlow->ext->srcInfo.macAddress, buf)
	     : etheraddr_string(theFlow->ext->dstInfo.macAddress, buf));
    break;
  case 58: /* SRC_VLAN */
  case 59: /* DST_VLAN */
    snprintf(dst, (line_buffer_len-len), "%d", theFlow->core.tuple.vlanId);
    break;
  case 60: /* IP_PROTOCOL_VERSION */
    snprintf(dst, (line_buffer_len-len), "%d",
	     (theFlow->core.tuple.src.ipVersion == 4) && (theFlow->core.tuple.dst.ipVersion == 4) ? 4 : 6);
    break;
  case 61: /* Direction */
    snprintf(dst, (line_buffer_len-len), "%d", 0);
    break;
  case 62: /* IPV6_NEXT_HOP */
    snprintf(dst, (line_buffer_len-len), "[::]" /* Same as 0.0.0.0 in IPv4 */);
    break;
  case 70: /* MPLS: label 1 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int((theFlow->ext->extensions == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 0));
    break;
  case 71: /* MPLS: label 2 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int((theFlow->ext->extensions == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 1));
    break;
  case 72: /* MPLS: label 3 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int((theFlow->ext->extensions == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 2));
    break;
  case 73: /* MPLS: label 4 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int((theFlow->ext->extensions == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 3));
    break;
  case 74: /* MPLS: label 5 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int((theFlow->ext->extensions == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 4));
    break;
  case 75: /* MPLS: label 6 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int((theFlow->ext->extensions == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 5));
    break;
  case 76: /* MPLS: label 7 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int((theFlow->ext->extensions == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 6));
    break;
  case 77: /* MPLS: label 8 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int((theFlow->ext->extensions == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 7));
    break;
  case 78: /* MPLS: label 9 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int((theFlow->ext->extensions == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 8));
    break;
  case 79: /* MPLS: label 10 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int((theFlow->ext->extensions == NULL) ? 0 : theFlow->ext->extensions->mplsInfo, 9));
    break;
  case 80: /* OUT_DST_MAC */
    snprintf(dst, (line_buffer_len-len), "%s",
	     direction == src2dst_direction ? etheraddr_string(theFlow->ext->dstInfo.macAddress, buf)
	     : etheraddr_string(theFlow->ext->srcInfo.macAddress, buf));
    break;

  case 148: /* FLOW_ID */
    snprintf(dst, (line_buffer_len-len), "%u", theFlow->core.tuple.flow_idx);
    break;

    /* ************************************ */

    /* nProbe Extensions */
  case NTOP_BASE_ID+80:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == src2dst_direction ? theFlow->ext->flowCounters.sentFragPkts : theFlow->ext->flowCounters.rcvdFragPkts);
    break;
#if 0
  case NTOP_BASE_ID+81:
    break;
#endif
  case NTOP_BASE_ID+82:
    snprintf(dst, (line_buffer_len-len), "%d",
	     (int)(nwLatencyComputed(theFlow->ext) ? theFlow->ext->extensions->clientNwDelay.tv_sec : 0));
    break;
  case NTOP_BASE_ID+83:
    snprintf(dst, (line_buffer_len-len), "%u",
	     nwLatencyComputed(theFlow->ext) ? (u_int32_t)theFlow->ext->extensions->clientNwDelay.tv_usec : 0);
    break;
  case NTOP_BASE_ID+84:
    snprintf(dst, (line_buffer_len-len), "%u",
	     (int)(nwLatencyComputed(theFlow->ext) ? (u_int32_t)theFlow->ext->extensions->serverNwDelay.tv_sec : 0));
    break;
  case NTOP_BASE_ID+85:
    snprintf(dst, (line_buffer_len-len), "%u",
	     nwLatencyComputed(theFlow->ext) ? (u_int32_t)theFlow->ext->extensions->serverNwDelay.tv_usec : 0);
    break;

  case NTOP_BASE_ID+86:
    snprintf(dst, (line_buffer_len-len), "%u",
	     (u_int32_t)(applLatencyComputed(theFlow->ext) ?
			 (direction == src2dst_direction ? theFlow->ext->extensions->src2dstApplLatency.tv_sec
			  : theFlow->ext->extensions->dst2srcApplLatency.tv_sec) : 0));
    break;
  case NTOP_BASE_ID+87:
    snprintf(dst, (line_buffer_len-len), "%d",
	     (u_int32_t)(applLatencyComputed(theFlow->ext) ?
			 (direction == src2dst_direction ? theFlow->ext->extensions->src2dstApplLatency.tv_usec
			  : theFlow->ext->extensions->dst2srcApplLatency.tv_usec) : 0));
    break;

  case NTOP_BASE_ID+88:
    snprintf(dst, (line_buffer_len-len), "%d",
	     theFlow->ext ?
	     (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_up_to_128_bytes
	      : theFlow->ext->extensions->etherstats.dst2src.num_pkts_up_to_128_bytes) : 0);
    break;

  case NTOP_BASE_ID+89:
    snprintf(dst, (line_buffer_len-len), "%d",
	     theFlow->ext ?
	     (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_128_to_256_bytes
	      : theFlow->ext->extensions->etherstats.dst2src.num_pkts_128_to_256_bytes) : 0);
    break;

  case NTOP_BASE_ID+90:
    snprintf(dst, (line_buffer_len-len), "%d",
	     theFlow->ext ?
	     (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_256_to_512_bytes
	      : theFlow->ext->extensions->etherstats.dst2src.num_pkts_256_to_512_bytes) : 0);
    break;

  case NTOP_BASE_ID+91:
    snprintf(dst, (line_buffer_len-len), "%d",
	     theFlow->ext ?
	     (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_512_to_1024_bytes
	      : theFlow->ext->extensions->etherstats.dst2src.num_pkts_512_to_1024_bytes) : 0);
    break;

  case NTOP_BASE_ID+92:
    snprintf(dst, (line_buffer_len-len), "%d",
	     theFlow->ext ?
	     (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_1024_to_1514_bytes
	      : theFlow->ext->extensions->etherstats.dst2src.num_pkts_1024_to_1514_bytes) : 0);
    break;

  case NTOP_BASE_ID+93:
    snprintf(dst, (line_buffer_len-len), "%d",
	     theFlow->ext ?
	     (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_over_1514_bytes
	      : theFlow->ext->extensions->etherstats.dst2src.num_pkts_over_1514_bytes) : 0);
    break;

  case NTOP_BASE_ID+94:
    if(((direction == src2dst_direction) ? theFlow->core.tuple.flowCounters.pktSent : theFlow->core.tuple.flowCounters.pktRcvd) == 0)
      snprintf(dst, (line_buffer_len-len), "%d", 0);
    else
      snprintf(dst, (line_buffer_len-len), "%u",
	       (u_int32_t)(theFlow->ext ?
			   (direction == src2dst_direction ? theFlow->ext->extensions->etherstats.src2dst.bytes_time_variance/theFlow->core.tuple.flowCounters.pktSent
			    : theFlow->ext->extensions->etherstats.dst2src.bytes_time_variance/theFlow->core.tuple.flowCounters.pktRcvd) : 0));
    break;

  case NTOP_BASE_ID+98:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? theFlow->ext->protoCounters.icmp.src2dstIcmpFlags : theFlow->ext->protoCounters.icmp.dst2srcIcmpFlags);
    break;

  case NTOP_BASE_ID+101: /* SRC_IP_COUNTRY */
#ifdef HAVE_GEOIP
    geo = (direction == src2dst_direction) ? theFlow->ext->srcInfo.geo : theFlow->ext->dstInfo.geo;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->country_code) ? geo->country_code :
#endif
	     "");
    break;

  case NTOP_BASE_ID+102: /* SRC_IP_CITY */
#ifdef HAVE_GEOIP
    geo = (direction == src2dst_direction) ? theFlow->ext->srcInfo.geo : theFlow->ext->dstInfo.geo;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->city) ? geo->city :
#endif
	     "");
    break;

  case NTOP_BASE_ID+103: /* DST_IP_COUNTRY */
#ifdef HAVE_GEOIP
    geo = (direction == src2dst_direction) ? theFlow->ext->dstInfo.geo : theFlow->ext->srcInfo.geo;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->country_code) ? geo->country_code :
#endif
	     "");
    break;

  case NTOP_BASE_ID+104: /* DST_IP_CITY */
#ifdef HAVE_GEOIP
    geo = (direction == src2dst_direction) ? theFlow->ext->dstInfo.geo : theFlow->ext->srcInfo.geo;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->city) ? geo->city :
#endif
	     "");
    break;

  case NTOP_BASE_ID+105: /* FLOW_PROTO_PORT */
    snprintf(dst, (line_buffer_len-len), "%u", getFlowApplProtocol(theFlow));
    break;

  case NTOP_BASE_ID+106: /* TUNNEL_ID */
    snprintf(dst, (line_buffer_len-len), "%u", theFlow->ext->tunnel_id);
    break;

  case NTOP_BASE_ID+107: /* LONGEST_FLOW_PKT */
    snprintf(dst, (line_buffer_len-len), "%u",
	     theFlow->ext->flowCounters.pktSize.longest);
    break;

  case NTOP_BASE_ID+108: /* SHORTEST_FLOW_PKT */
    snprintf(dst, (line_buffer_len-len), "%u",
	     theFlow->ext->flowCounters.pktSize.shortest);
    break;

  case NTOP_BASE_ID+109: /* RETRANSMITTED_IN_PKTS */
    snprintf(dst, (line_buffer_len-len), "%u",
	     (direction == dst2src_direction) ? theFlow->ext->protoCounters.tcp.rcvdRetransmitted :
	     theFlow->ext->protoCounters.tcp.sentRetransmitted);
    break;

  case NTOP_BASE_ID+110: /* RETRANSMITTED_OUT_PKTS */
    snprintf(dst, (line_buffer_len-len), "%u",
	     (direction == src2dst_direction) ? theFlow->ext->protoCounters.tcp.rcvdRetransmitted :
	     theFlow->ext->protoCounters.tcp.sentRetransmitted);
    break;

  case NTOP_BASE_ID+111: /* OOORDER_IN_PKTS */
    snprintf(dst, (line_buffer_len-len), "%u",
	     (direction == dst2src_direction) ? theFlow->ext->protoCounters.tcp.rcvdOOOrder :
	     theFlow->ext->protoCounters.tcp.sentOOOrder);
    break;

  case NTOP_BASE_ID+112: /* OOORDER_OUT_PKTS */
    snprintf(dst, (line_buffer_len-len), "%u",
	     (direction == src2dst_direction) ? theFlow->ext->protoCounters.tcp.rcvdOOOrder :
	     theFlow->ext->protoCounters.tcp.sentOOOrder);
    break;

  case NTOP_BASE_ID+113: /* UNTUNNELED_PROTOCOL */
    snprintf(dst, (line_buffer_len-len), "%d",
	     ((readOnlyGlobals.tunnel_mode == 0) || (theFlow->ext == NULL))? 0 : theFlow->ext->extensions->untunneled.proto);
    break;

  case NTOP_BASE_ID+114: /* UNTUNNELED_IPV4_SRC_ADDR */
    snprintf(dst, (line_buffer_len-len), "%s",
	     ((readOnlyGlobals.tunnel_mode == 0) || (theFlow->ext == NULL)
	      || (theFlow->ext->extensions->untunneled.proto == 0)) ? "" :
	     (_intoa(direction == src2dst_direction ? theFlow->ext->extensions->untunneled.src :
		     theFlow->ext->extensions->untunneled.dst, buf, sizeof(buf))));
    break;

  case NTOP_BASE_ID+115: /* UNTUNNELED_L4_SRC_PORT */
    snprintf(dst, (line_buffer_len-len), "%d",
	     ((theFlow->ext == NULL) || (readOnlyGlobals.tunnel_mode == 0)) ? 0 :
	     ((direction == src2dst_direction) ? theFlow->ext->extensions->untunneled.sport : theFlow->ext->extensions->untunneled.dport));
    break;

  case NTOP_BASE_ID+116: /* UNTUNNELED_IPV4_DST_ADDR */
    snprintf(dst, (line_buffer_len-len), "%s",
	     ((readOnlyGlobals.tunnel_mode == 0) || (theFlow->ext == NULL)
	      || (theFlow->ext->extensions->untunneled.proto == 0)) ? "" :
	     (_intoa(direction == src2dst_direction ? theFlow->ext->extensions->untunneled.dst :
		     theFlow->ext->extensions->untunneled.src, buf, sizeof(buf))));
    break;

  case NTOP_BASE_ID+117: /* UNTUNNELED_L4_DST_PORT */
    snprintf(dst, (line_buffer_len-len), "%d",
	     ((readOnlyGlobals.tunnel_mode == 0) || (theFlow->ext == NULL)) ? 0 :
	     (direction == src2dst_direction ? theFlow->ext->extensions->untunneled.dport : theFlow->ext->extensions->untunneled.sport));
    break;

  case NTOP_BASE_ID+118: /* L7_PROTO */
    snprintf(dst, (line_buffer_len-len), "%d", theFlow->core.l7.proto);
    break;

  case NTOP_BASE_ID+119: /* L7_PROTO_NAME */
    snprintf(dst, (line_buffer_len-len), "%s", getProtoName(theFlow->core.l7.proto));
    break;

  default:
    if(checkPluginPrint(theTemplateElement, direction, theFlow,
			line_buffer, line_buffer_len) == -1) {
      char *val = "";

      if(strcmp(theTemplateElement->netflowElementName, "RTP_OUT_PAYLOAD_TYPE") == 0)
	val = "-1";
      else {
	switch(theTemplateElement->fileDumpFormat) {
	case dump_as_uint:
	case dump_as_formatted_uint:
	case dump_as_ip_proto:
	case dump_as_ip_port:
	case dump_as_epoch:
	case dump_as_tcp_flags:
	case dump_as_hex:
	  val = NPROBE_UNKNOWN_VALUE_STR;
	  break;
	case dump_as_ipv4_address:
	  val = "0.0.0.0";
	  break;
	case dump_as_ipv6_address:
	  val = "::";
	  break;
	case dump_as_mac_address:
	  val = "00:00:00:00:00:00";
	  break;
	case dump_as_bool:
	  val = "false";
	  break;
	case dump_as_ascii:
	  val = "";
	  break;
	}
      }

      snprintf(dst, (line_buffer_len-len), "%s", val);
    }
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "name=%s/Id=%d\n",
	     theTemplateElement->netflowElementName,
	     theTemplateElement->templateElementId);
#endif
}

/* ******************************************** */

void flowFilePrintf(V9V10TemplateElementId **templateList,
		    FILE *stream, FlowHashBucket *theFlow, FlowDirection direction) {
  int idx = 0;
  char line_buffer[2048] = { '\0' };

  readWriteGlobals->sql_row_idx++;
  if(readOnlyGlobals.dumpFormat == sqlite_format)
    snprintf(&line_buffer[strlen(line_buffer)],
	     sizeof(line_buffer), "insert into flows values ('");

  while(templateList[idx] != NULL) {
    if(idx > 0) {
      if(readOnlyGlobals.dumpFormat == sqlite_format)
	snprintf(&line_buffer[strlen(line_buffer)], sizeof(line_buffer), "','");
      else
	snprintf(&line_buffer[strlen(line_buffer)], sizeof(line_buffer), "%s",
		 readOnlyGlobals.csv_separator);
    }

    printRecordWithTemplate(templateList[idx], line_buffer,
			    sizeof(line_buffer), theFlow, direction);
    idx++;
  }

  if(readOnlyGlobals.dumpFormat == sqlite_format) {
    snprintf(&line_buffer[strlen(line_buffer)], sizeof(line_buffer), "');");
#ifdef HAVE_SQLITE
    sqlite_exec_sql(line_buffer);
#endif
  } else
    fprintf(stream, "%s\n", line_buffer);
}

/* ****************************************************** */

double toMs(struct timeval *t) {
  return(((double)t->tv_sec)*1000+((double)t->tv_usec)/1000);
}

/* ****************************************************** */

u_int32_t msTimeDiff(struct timeval *end, struct timeval *begin) {
  if((end->tv_sec == 0) && (end->tv_usec == 0))
    return(0);
  else
    return((end->tv_sec-begin->tv_sec)*1000+(end->tv_usec-begin->tv_usec)/1000);
}


/* ****************************************************** */

#ifndef WIN32
int createCondvar(ConditionalVariable *condvarId) {
  int rc;

  pthread_mutex_init(&condvarId->mutex, NULL);
  rc = pthread_cond_init(&condvarId->condvar, NULL);
  condvarId->predicate = 0;

  return(rc);
}

/* ************************************ */

void deleteCondvar(ConditionalVariable *condvarId) {
  pthread_mutex_destroy(&condvarId->mutex);
  pthread_cond_destroy(&condvarId->condvar);
}

/* ************************************ */

int waitCondvar(ConditionalVariable *condvarId) {
  int rc;

  if((rc = pthread_mutex_lock(&condvarId->mutex)) != 0)
    return rc;

  while(condvarId->predicate <= 0)
    pthread_cond_wait(&condvarId->condvar, &condvarId->mutex);

  condvarId->predicate--;

  rc = pthread_mutex_unlock(&condvarId->mutex);

  return rc;
}
/* ************************************ */

int signalCondvar(ConditionalVariable *condvarId, int broadcast) {
  int rc;

  pthread_mutex_lock(&condvarId->mutex);
  condvarId->predicate++;
  pthread_mutex_unlock(&condvarId->mutex);

  if(broadcast)
    rc = pthread_cond_broadcast(&condvarId->condvar);
  else
    rc = pthread_cond_signal(&condvarId->condvar);

  return rc;
}

#undef sleep /* Used by ntop_sleep */

#else /* WIN32 */

/* ************************************ */

int createCondvar(ConditionalVariable *condvarId) {
  condvarId->condVar = CreateEvent(NULL,  /* no security */
				   TRUE , /* auto-reset event (FALSE = single event, TRUE = broadcast) */
				   FALSE, /* non-signaled initially */
				   NULL); /* unnamed */
  InitializeCriticalSection(&condvarId->criticalSection);
  return(1);
}

/* ************************************ */

void deleteCondvar(ConditionalVariable *condvarId) {
  CloseHandle(condvarId->condVar);
  DeleteCriticalSection(&condvarId->criticalSection);
}

/* ************************************ */

int waitCondvar(ConditionalVariable *condvarId) {
  int rc;
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Wait (%x)...", condvarId->condVar);
#endif
  EnterCriticalSection(&condvarId->criticalSection);
  rc = WaitForSingleObject(condvarId->condVar, INFINITE);
  LeaveCriticalSection(&condvarId->criticalSection);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Got signal (%d)...", rc);
#endif

  return(rc);
}

/* ************************************ */

/* NOTE: broadcast is currently ignored */
int signalCondvar(ConditionalVariable *condvarId, int broadcast) {
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Signaling (%x)...", condvarId->condVar);
#endif
  return((int)PulseEvent(condvarId->condVar));
}

#define sleep(a /* sec */) waitForNextEvent(1000*a /* ms */)

#endif /* WIN32 */

/* ******************************************* */

unsigned int ntop_sleep(unsigned int secs) {
  unsigned int unsleptTime = secs, rest;

  while((rest = sleep(unsleptTime)) > 0)
    unsleptTime = rest;

  return(secs);
}

/* ******************************************* */

FlowHashBucket* getListHead(FlowHashBucket **list) {
  FlowHashBucket *bkt = *list;

  if(bkt == NULL)
    traceEvent(TRACE_ERROR, "INTERNAL ERROR: getListHead is empty");
  else
    (*list) = bkt->core.hash.next;

  return(bkt);
}

/* ******************************************* */

void addToList(FlowHashBucket *bkt, FlowHashBucket **list) {
  if(*list)
    (*list)->core.hash.prev = bkt;

  bkt->core.hash.next = *list, bkt->core.hash.prev = NULL;
  (*list) = bkt;
}

/* **************************************** */

#ifndef WIN32

void detachFromTerminal(int doChdir) {
  if(doChdir) {
    int rc = chdir("/");
    if(rc != 0) traceEvent(TRACE_ERROR, "Error while moving to / directory");
  }

  setsid();  /* detach from the terminal */

  fclose(stdin);
  fclose(stdout);
  /* fclose(stderr); */

  /*
   * clear any inherited file mode creation mask
   */
  umask (0);

  /*
   * Use line buffered stdout
   */
  /* setlinebuf (stdout); */
  setvbuf(stdout, (char *)NULL, _IOLBF, 0);
}

/* **************************************** */

void daemonize(void) {
  int childpid;

  signal(SIGHUP, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);

  if((childpid = fork()) < 0)
    traceEvent(TRACE_ERROR, "INIT: Occurred while daemonizing (errno=%d)", errno);
  else {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "DEBUG: after fork() in %s (%d)",
	       childpid ? "parent" : "child", childpid);
#endif
    if(!childpid) { /* child */
      traceEvent(TRACE_INFO, "INIT: Bye bye: I'm becoming a daemon...");
      detachFromTerminal(1);
    } else { /* father */
      traceEvent(TRACE_INFO, "INIT: Parent process is exiting (this is normal)");
      exit(0);
    }
  }
}

#endif /* WIN32 */

/* ****************************************

   Address management

   **************************************** */

static int int2bits(int number) {
  int bits = 8;
  int test;

  if((number > 255) || (number < 0))
    return(CONST_INVALIDNETMASK);
  else {
    test = ~number & 0xff;
    while (test & 0x1)
      {
	bits --;
	test = test >> 1;
      }
    if(number != ((~(0xff >> bits)) & 0xff))
      return(CONST_INVALIDNETMASK);
    else
      return(bits);
  }
}

/* ********************** */

static int dotted2bits(char *mask) {
  int		fields[4];
  int		fields_num, field_bits;
  int		bits = 0;
  int		i;

  fields_num = sscanf(mask, "%d.%d.%d.%d",
		      &fields[0], &fields[1], &fields[2], &fields[3]);
  if((fields_num == 1) && (fields[0] <= 32) && (fields[0] >= 0))
    {
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: dotted2bits (%s) = %d", mask, fields[0]);
#endif
      return(fields[0]);
    }
  for (i=0; i < fields_num; i++)
    {
      /* We are in a dotted quad notation. */
      field_bits = int2bits (fields[i]);
      switch (field_bits)
	{
	case CONST_INVALIDNETMASK:
	  return(CONST_INVALIDNETMASK);

	case 0:
	  /* whenever a 0 bits field is reached there are no more */
	  /* fields to scan                                       */
	  /* In this case we are in a bits (not dotted quad) notation */
	  return(bits /* fields[0] - L.Deri 08/2001 */);

	default:
	  bits += field_bits;
	}
    }
  return(bits);
}

/* ********************************* */

static char* read_file(char* path, char* buf, uint buf_len) {
  FILE *fd = fopen(&path[1], "r");

  if(fd == NULL) {
    traceEvent(TRACE_WARNING, "Unable to read file %s", path);
    return(NULL);
  } else {
    char line[256];
    int idx = 0;

    while(!feof(fd) && (fgets(line, sizeof(line), fd) != NULL)) {
      if((line[0] == '#') || (line[0] == '\n')) continue;
      while(strlen(line) && (line[strlen(line)-1] == '\n')) {
	line[strlen(line)-1] = '\0';
      }

      snprintf(&buf[idx], buf_len-idx-2, "%s%s", (idx > 0) ? "," : "", line);
      idx = strlen(buf);
    }

    fclose(fd);
    return(buf);
  }
}

/* ********************************* */

static u_int8_t num_network_bits(u_int32_t addr) {
  u_int8_t i, j, bits = 0, fields[4];

  memcpy(fields, &addr, 4);

  for(i = 8; i <= 8; i--)
    for(j=0; j<4; j++)
      if ((fields[j] & (1 << i)) != 0) bits++;

  return(bits);
}

/* ********************** */

typedef struct {
  u_int32_t network;
  u_int32_t networkMask;
  u_int32_t broadcast;
} netAddress_t;

int parseAddress(char * address, netAddress_t * netaddress) {
  u_int32_t network, networkMask, broadcast;
  int bits, a, b, c, d;
  char *mask = strchr(address, '/');

  if(mask == NULL)
    bits= 32;
  else {
    mask[0] = '\0';
    mask++;
    bits = dotted2bits (mask);
  }

  if(sscanf(address, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
    return -1;

  if(bits == CONST_INVALIDNETMASK) {
    traceEvent(TRACE_WARNING, "netmask '%s' not valid - ignoring entry", mask);
    /* malformed netmask specification */
    return -1;
  }

  network = ((a & 0xff) << 24) + ((b & 0xff) << 16) + ((c & 0xff) << 8) + (d & 0xff);
  /* Special case the /32 mask - yeah, we could probably do it with some fancy
     u long long stuff, but this is simpler...
     Burton Strauss <Burton@ntopsupport.com> Jun2002
  */
  if(bits == 32) {
    networkMask = 0xffffffff;
  } else {
    networkMask = 0xffffffff >> bits;
    networkMask = ~networkMask;
  }

  if((network & networkMask) != network)  {
    /* malformed network specification */

    traceEvent(TRACE_WARNING, "%d.%d.%d.%d/%d is not a valid network - correcting mask",
	       a, b, c, d, bits);
    /* correcting network numbers as specified in the netmask */
    network &= networkMask;

    /*
      a = (int) ((network >> 24) & 0xff);
      b = (int) ((network >> 16) & 0xff);
      c = (int) ((network >>  8) & 0xff);
      d = (int) ((network >>  0) & 0xff);

      traceEvent(CONST_TRACE_NOISY, "Assuming %d.%d.%d.%d/%d [0x%08x/0x%08x]",
      a, b, c, d, bits, network, networkMask);
    */
  }

  broadcast = network | (~networkMask);

  a = (int) ((network >> 24) & 0xff);
  b = (int) ((network >> 16) & 0xff);
  c = (int) ((network >>  8) & 0xff);
  d = (int) ((network >>  0) & 0xff);

  traceEvent(TRACE_INFO, "Adding %d.%d.%d.%d/%d to the local network list",
	     a, b, c, d, bits);

  netaddress->network     = network;
  netaddress->networkMask = networkMask;
  netaddress->broadcast   = broadcast;

  return 0;
}

/* ********************** */

void parseLocalAddressLists(char* _addresses) {
  char *address, *addresses, *strTokState = NULL, buf[2048];

  readOnlyGlobals.numLocalNetworks = 0;

  if((_addresses == NULL) || (_addresses[0] == '\0'))
    return;
  else if(_addresses[0] == '@') {
    addresses = strdup(read_file(_addresses, buf, sizeof(buf)));
  } else
    addresses = strdup(_addresses);

  address = strtok_r(addresses, ",", &strTokState);

  while(address != NULL) {
    char *mask = strchr(address, '/');

    if(mask == NULL) {
      traceEvent(TRACE_WARNING, "Empty mask '%s' - ignoring entry", address);
    } else {
      netAddress_t netaddress;

      if(readOnlyGlobals.numLocalNetworks >= MAX_NUM_NETWORKS) {
	traceEvent(TRACE_WARNING, "Too many networks defined (-L): skipping further networks");
	break;
      }

      if(parseAddress(address, &netaddress)==-1) {
	address = strtok_r(NULL, ",", &strTokState);
	continue;
      }

      /* NOTE: entries are saved in network byte order for performance reasons */
      readOnlyGlobals.localNetworks[readOnlyGlobals.numLocalNetworks].network    = htonl(netaddress.network);
      readOnlyGlobals.localNetworks[readOnlyGlobals.numLocalNetworks].netmask    = htonl(netaddress.networkMask);
      readOnlyGlobals.localNetworks[readOnlyGlobals.numLocalNetworks].broadcast  = htonl(netaddress.broadcast);
      readOnlyGlobals.localNetworks[readOnlyGlobals.numLocalNetworks].netmask_v6 = num_network_bits(netaddress.networkMask); /* Host byte-order */
      readOnlyGlobals.numLocalNetworks++;
    }

    address = strtok_r(NULL, ",", &strTokState);
  }

  free(addresses);
}

/* ********************** */

#define MAX_NUM_ENTRIES 256

struct net_sort {
  u_int mask;
  char *network;
};

int cmpNet(const void *_a, const void *_b) {
  struct net_sort *a = (struct net_sort*)_a;
  struct net_sort *b = (struct net_sort*)_b;

  if(a->mask == b->mask) return(0);
  else if(a->mask > b->mask) return(-1);
  else return(1);
}

/* ********************** */

char *sortNetworks(char *_addresses) {
  int num = 0, i, len = strlen(_addresses)+1;
  char  *strTokState = NULL, *address;
  struct net_sort nwsort[MAX_NUM_ENTRIES];

  address = strtok_r(_addresses, ",", &strTokState);

  while(address != NULL) {
    if(num < MAX_NUM_ENTRIES) {
      char *mask = strchr(address, '/');

      if(mask != NULL) {
	nwsort[num].mask = atoi(&mask[1]);
	nwsort[num++].network = address;
      } else {
	/*
	   This looks like a mac address or an IP
	   address without a /mask
	*/
	nwsort[num].mask = 32; /* / 32 */
	nwsort[num++].network = address;
      }
    }

    address = strtok_r(NULL, ",", &strTokState);
  }

  qsort(nwsort, num, sizeof(struct net_sort), cmpNet);

  address = (char*)malloc(len);
  if(address == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory");
    return(_addresses);
  } else
    address[0] = '\0';

  for(i=0; i<num; i++) {
    // traceEvent(TRACE_WARNING, "%s => %d", nwsort[i].network, nwsort[i].mask);
    sprintf(&address[strlen(address)], "%s%s", (i == 0) ? "" : ",", nwsort[i].network);
  }

  /* traceEvent(TRACE_WARNING, "<=> '%s'", address); */

  return(address);
}

/* ********************** */

void parseInterfaceAddressLists(char* _addresses) {
  char *address, *addresses, *strTokState = NULL, buf[2048];

  readOnlyGlobals.numInterfaceNetworks = 0;

  if((_addresses == NULL) || (_addresses[0] == '\0'))
    return;
  else if(_addresses[0] == '@') {
    addresses = strdup(read_file(_addresses, buf, sizeof(buf)));
  } else
    addresses = strdup(_addresses);

  addresses = sortNetworks(addresses);

  address = strtok_r(addresses, ",", &strTokState);

  while(address != NULL) {
    char *mask;
    char *at = strchr(address, '@');
    u_int a, b, c, d, e, f, ifIdx;

    /* traceEvent(TRACE_WARNING, "Parsing %s", address); */

    mask = strchr(address, '/');

    if((mask == NULL)
       && (sscanf(address, "%d.%d.%d.%d@%d", &a, &b, &c, &d, &e) != 5) /* IP without /mask */) {
      /* Maybe this is a MAC address */

      if(sscanf(address, "%2X:%2X:%2X:%2X:%2X:%2X@%d", &a, &b, &c, &d, &e, &f, &ifIdx) != 7) {
	traceEvent(TRACE_WARNING,
		   "WARNING: Wrong MAC address/Interface specified (format AA:BB:CC:DD:EE:FF@4) "
		   "with '-L': ignored");
      } else {
	if(readWriteGlobals->num_src_mac_export >= NUM_MAC_INTERFACES) {
	  traceEvent(TRACE_ERROR, "Too many '-L' specified. Ignored.");
	  break;
	} else {
	  readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[0] = a,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[1] = b,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[2] = c,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[3] = d,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[4] = e,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[5] = f,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].interface_id = ifIdx;
	  readWriteGlobals->num_src_mac_export++;
	}
      }
    } else {
      netAddress_t netaddress;

      if(readOnlyGlobals.numInterfaceNetworks >= MAX_NUM_NETWORKS) {
	traceEvent(TRACE_WARNING, "Too many networks defined (-L): skipping further networks");
	break;
      }

      if(at == NULL) {
	traceEvent(TRACE_WARNING, "Invalid format for network %s: ignored", address);
      } else {
	at[0] = '\0';
	if(parseAddress(address, &netaddress) == -1) {
	  address = strtok_r(NULL, ",", &strTokState);
	  continue;
	}

	/* NOTE: entries are saved in network byte order for performance reasons */
	readOnlyGlobals.interfaceNetworks[readOnlyGlobals.numInterfaceNetworks].network    = htonl(netaddress.network);
	readOnlyGlobals.interfaceNetworks[readOnlyGlobals.numInterfaceNetworks].netmask    = htonl(netaddress.networkMask);
	readOnlyGlobals.interfaceNetworks[readOnlyGlobals.numInterfaceNetworks].broadcast  = htonl(netaddress.broadcast);
	readOnlyGlobals.interfaceNetworks[readOnlyGlobals.numInterfaceNetworks].netmask_v6 = num_network_bits(netaddress.networkMask); /* Host byte-order */
	readOnlyGlobals.interfaceNetworks[readOnlyGlobals.numInterfaceNetworks].interface_id = atoi(&at[1]);
	readOnlyGlobals.numInterfaceNetworks++;
      }
    }

    address = strtok_r(NULL, ",", &strTokState);
  }

  free(addresses);
}

/* ************************************************ */

void parseBlacklistNetworks(char* _addresses) {
  char *address, *addresses, buf[2048], *strTokState = NULL;

  readOnlyGlobals.numBlacklistNetworks = 0;

  if((_addresses == NULL) || (_addresses[0] == '\0'))
    return;
  else if(_addresses[0] == '@') {
    addresses = strdup(read_file(_addresses, buf, sizeof(buf)));
  } else
    addresses = strdup(_addresses);

  address = strtok_r(addresses, ",", &strTokState);

  while(address != NULL) {
    char *mask = strchr(address, '/');

    if(mask == NULL) {
      traceEvent(TRACE_WARNING, "Empty mask '%s' - ignoring entry", address);
    } else {
      netAddress_t netaddress;

      if(readOnlyGlobals.numBlacklistNetworks >= MAX_NUM_NETWORKS) {
	traceEvent(TRACE_WARNING, "Too many networks defined (--black-list): skipping further networks");
	break;
      }

      if (parseAddress(address,&netaddress)==-1) {
	address = strtok_r(NULL, ",", &strTokState);
	continue;
      }

      /* NOTE: entries are saved in network byte order for performance reasons */
      readOnlyGlobals.blacklistNetworks[readOnlyGlobals.numBlacklistNetworks].network    = htonl(netaddress.network);
      readOnlyGlobals.blacklistNetworks[readOnlyGlobals.numBlacklistNetworks].netmask    = htonl(netaddress.networkMask);
      readOnlyGlobals.blacklistNetworks[readOnlyGlobals.numBlacklistNetworks].broadcast  = htonl(netaddress.broadcast);
      readOnlyGlobals.blacklistNetworks[readOnlyGlobals.numBlacklistNetworks].netmask_v6 = num_network_bits(netaddress.networkMask); /* Host byte-order */
      readOnlyGlobals.numBlacklistNetworks++;
    }

    address = strtok_r(NULL, ",", &strTokState);
  }

  free(addresses);
}

/* ************************************************ */

//#define DEBUG
#undef DEBUG

static u_int8_t getIfIdx(struct in_addr *addr, u_int16_t *interface_id) {
  int i;

  if(readOnlyGlobals.numInterfaceNetworks == 0) return(0);

  for(i=0; i<readOnlyGlobals.numInterfaceNetworks; i++)
    if((addr->s_addr & readOnlyGlobals.interfaceNetworks[i].netmask) == readOnlyGlobals.interfaceNetworks[i].network) {
      *interface_id = readOnlyGlobals.interfaceNetworks[i].interface_id;
      return(1);
    }

  return(0);
}

/* ************************************************ */

unsigned short isLocalAddress(struct in_addr *addr) {
  int i;

  /* If unset all the addresses are local */
  if(readOnlyGlobals.numLocalNetworks == 0) return(1);

  for(i=0; i<readOnlyGlobals.numLocalNetworks; i++)
    if((addr->s_addr & readOnlyGlobals.localNetworks[i].netmask) == readOnlyGlobals.localNetworks[i].network) {
      return 1;
    }

  return(0);
}

/* ************************************************ */

u_short isBlacklistedAddress(struct in_addr *addr) {
  int i;
#ifdef DEBUG
  char buf[64];
#endif

  /* If unset is not blacklisted */
  if(readOnlyGlobals.numBlacklistNetworks == 0) return(0);

  for(i=0; i<readOnlyGlobals.numBlacklistNetworks; i++)
    if((addr->s_addr & readOnlyGlobals.blacklistNetworks[i].netmask) == readOnlyGlobals.blacklistNetworks[i].network) {

#ifdef DEBUG
      traceEvent(TRACE_INFO, "%s is blacklisted",
		 _intoaV4(ntohl(addr->s_addr), buf, sizeof(buf)));
#endif
      return 1;
    }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "%s is NOT blacklisted",
	     _intoaV4(ntohl(addr->s_addr), buf, sizeof(buf)));
#endif
  return(0);
}

/* ************************************************ */

/* Utility function */
u_int32_t str2addr(char *address) {
  int a, b, c, d;

  if(sscanf(address, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
    return(0);
  } else
    return(((a & 0xff) << 24) + ((b & 0xff) << 16) + ((c & 0xff) << 8) + (d & 0xff));
}

/* ************************************************ */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  uint i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ************************************ */

void resetBucketStats(FlowHashBucket* bkt,
		      const struct pcap_pkthdr *h,
		      u_char *p,
		      u_int len,  u_int ip_offset,
		      FlowDirection direction,
		      u_char *payload, int payloadLen) {
  bkt->core.bucket_expired = 0; /* Not really necessary */

  memset(&bkt->core.tuple.flowCounters, 0, sizeof(bkt->core.tuple.flowCounters));

  if(bkt->ext != NULL) {
    //memset(&bkt->core.tuple.flowTimers, 0, sizeof(bkt->core.tuple.flowTimers));
    //memset(&bkt->ext->extensions->clientNwDelay, 0, sizeof(bkt->ext->extensions->clientNwDelay));
    //memset(&bkt->ext->extensions->serverNwDelay, 0, sizeof(bkt->ext->extensions->serverNwDelay));
    memset(&bkt->ext->extensions->synTime, 0, sizeof(bkt->ext->extensions->synTime));
    memset(&bkt->ext->extensions->synAckTime, 0, sizeof(bkt->ext->extensions->synAckTime));
    memset(&bkt->ext->extensions->src2dstApplLatency, 0, sizeof(bkt->ext->extensions->src2dstApplLatency));
    memset(&bkt->ext->extensions->dst2srcApplLatency, 0, sizeof(bkt->ext->extensions->dst2srcApplLatency));
  }

  if(direction == src2dst_direction /* src -> dst */) {
    bkt->core.tuple.flowCounters.bytesSent = len, bkt->core.tuple.flowCounters.pktSent = 1, bkt->core.tuple.flowCounters.bytesRcvd = bkt->core.tuple.flowCounters.pktRcvd = 0;
    memcpy(&bkt->core.tuple.flowTimers.firstSeenSent, &h->ts, sizeof(struct timeval));
    memcpy(&bkt->core.tuple.flowTimers.lastSeenSent, &h->ts, sizeof(struct timeval));
    /* Reset the opposite direction */
    memset(&bkt->core.tuple.flowTimers.firstSeenRcvd, 0, sizeof(struct timeval));
    memset(&bkt->core.tuple.flowTimers.lastSeenRcvd, 0, sizeof(struct timeval));
  } else {
    bkt->core.tuple.flowCounters.bytesSent = bkt->core.tuple.flowCounters.pktSent = 0, bkt->core.tuple.flowCounters.bytesRcvd = len, bkt->core.tuple.flowCounters.pktRcvd = 1;
    memcpy(&bkt->core.tuple.flowTimers.firstSeenRcvd, &h->ts, sizeof(struct timeval));
    memcpy(&bkt->core.tuple.flowTimers.lastSeenRcvd, &h->ts, sizeof(struct timeval));
    /* Reset the opposite direction */
    memset(&bkt->core.tuple.flowTimers.firstSeenSent, 0, sizeof(struct timeval));
    memset(&bkt->core.tuple.flowTimers.lastSeenSent, 0, sizeof(struct timeval));
  }

  /* NOTE: don't reset TOS as this is part of the flow key */
  bkt->ext->flags = 0, bkt->core.l7.proto = IPOQUE_PROTOCOL_UNKNOWN;

  if(payloadLen > 0)
    setPayload(bkt, h, p, ip_offset, payload, payloadLen, direction);
}

/* ****************************************** */

/*
  UNIX was not designed to stop you from doing stupid things, because that
  would also stop you from doing clever things.
  -- Doug Gwyn
*/
void maximize_socket_buffer(int sock_fd, int buf_type) {
  int i, rcv_buffsize_base, rcv_buffsize, max_buf_size = 1024 * 2 * 1024 /* 2 MB */, debug = 0;
  socklen_t len = sizeof(rcv_buffsize_base);

  if(getsockopt(sock_fd, SOL_SOCKET, buf_type, &rcv_buffsize_base, &len) < 0) {
    traceEvent(TRACE_ERROR, "Unable to read socket receiver buffer size [%s]",
	       strerror(errno));
    return;
  } else {
    if(debug) traceEvent(TRACE_INFO, "Default socket %s buffer size is %d",
			 buf_type == SO_RCVBUF ? "receive" : "send",
			 rcv_buffsize_base);
  }

  for(i=2;; i++) {
    rcv_buffsize = i * rcv_buffsize_base;
    if(rcv_buffsize > max_buf_size) break;

    if(setsockopt(sock_fd, SOL_SOCKET, buf_type, &rcv_buffsize, sizeof(rcv_buffsize)) < 0) {
      if(debug) traceEvent(TRACE_ERROR, "Unable to set socket %s buffer size [%s]",
			   buf_type == SO_RCVBUF ? "receive" : "send",
			   strerror(errno));
      break;
    } else
      if(debug) traceEvent(TRACE_INFO, "%s socket buffer size set %d",
			   buf_type == SO_RCVBUF ? "Receive" : "Send",
			   rcv_buffsize);
  }
}

/* ****************************************** */

#ifdef linux

/* /usr/local/bin/setethcore <eth2> <core Id> */
#define SET_NETWORK_CARD_AFFINITY   "/usr/local/bin/setethcore"

void setCpuAffinity(char *dev_name, char *cpuId) {
  pid_t p = 0; /* current process */
  int ret, num = 0;
  cpu_set_t cpu_set;
  int numCpus = sysconf(_SC_NPROCESSORS_CONF);
  char *strtokState, *cpu, _cpuId[256] = { 0 };

  if(cpuId == NULL)
    return; /* No affinity */

  traceEvent(TRACE_INFO, "This computer has %d processor(s)\n", numCpus);

  CPU_ZERO(&cpu_set);

  cpu = strtok_r(cpuId, ",", &strtokState);
  while(cpu != NULL) {
    int id = atoi(cpu);

    if((id >= numCpus) || (id < 0)) {
      traceEvent(TRACE_ERROR, "Skept CPU id %d as you have %d available CPU(s) [0..%d]", id, numCpus, numCpus-1);
    } else {
      CPU_SET(id, &cpu_set), num++;
      traceEvent(TRACE_INFO, "Adding CPU %d to the CPU affinity set", id);
      snprintf(&_cpuId[strlen(_cpuId)], sizeof(_cpuId)-strlen(_cpuId)-1, "%s%d", (_cpuId[0] != '\0') ? "," : "", id);
    }

    cpu = strtok_r(NULL, ",", &strtokState);
  }

  if(num == 0) {
    traceEvent(TRACE_WARNING, "No valid CPU id has been selected: skipping CPU affinity set");
    return;
  }

  ret = sched_setaffinity(p, sizeof(cpu_set_t), &cpu_set);

  if(ret == 0) {
    traceEvent(TRACE_NORMAL, "CPU affinity successfully set to %s", _cpuId);

    /*
      Call instead on your system
      ~/PF_RING/drivers/intel/ixgbe/ixgbe-3.1.15-FlowDirector-NoTNAPI/scripts/set_irq_affinity.sh ethX
    */
#if 0
    if((dev_name != NULL) && strcmp(dev_name, "none")) {
      struct stat stats;

      if(stat(SET_NETWORK_CARD_AFFINITY, &stats) == 0) {
	char affinity_buf[256];
	int ret;

	snprintf(affinity_buf, sizeof(affinity_buf), "%s %s %s",
		 SET_NETWORK_CARD_AFFINITY, dev_name, _cpuId);

	ret = system(affinity_buf);
	traceEvent(TRACE_NORMAL, "Executed '%s' (ret: %d)", affinity_buf, ret);
      } else {
	traceEvent(TRACE_WARNING, "Missing %s: unable to set %s affinity",
		   SET_NETWORK_CARD_AFFINITY, dev_name);
      }
    } else {
      traceEvent(TRACE_NORMAL, "Unspecified card (-i missing): not setting card affinity");
    }
#endif
  } else
    traceEvent(TRACE_ERROR, "Unable to set CPU affinity to %08lx [ret: %d]",
	       cpu_set, ret);
}
#endif

/* ******************************************* */

int mkdir_p(char *path) {
  int i, rc = 0;
  int permission = 0777;

  if(path == NULL) return(-1);

#ifdef WIN32
  revertSlash(path, 0);
#endif

  /* Start at 1 to skip the root */
  for(i=1; path[i] != '\0'; i++)
    if(path[i] == CONST_DIR_SEP) {
#ifdef WIN32
      /* Do not create devices directory */
      if((i > 1) && (path[i-1] == ':')) continue;
#endif

      path[i] = '\0';
      rc = mkdir(path, permission);

      if((rc != 0) && (errno != EEXIST) )
	traceEvent(TRACE_WARNING, "mkdir_p(%s): [error=%d/%s]",
		   path, errno, strerror(errno));
      path[i] = CONST_DIR_SEP;
    }

  mkdir(path, permission);

  if((rc != 0) && (errno != EEXIST))
    traceEvent(TRACE_WARNING, "mkdir_p(%s), error %d %s",
	       path, errno, strerror(errno));

  return(rc);
}

/* ******************************************* */

void dropPrivileges(void) {
#ifndef WIN32
  struct passwd *pw = NULL;
  char *username;

  if(readOnlyGlobals.do_not_drop_privileges) return;

  pw = getpwnam(readOnlyGlobals.unprivilegedUser);
  /* if(pw == NULL) pw = getpwnam(username = "anonymous"); */

  if(pw != NULL) {
    /* Drop privileges */
    if((setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0)) {
      traceEvent(TRACE_WARNING, "Unable to drop privileges [%s]", strerror(errno));
    } else
      traceEvent(TRACE_NORMAL, "nProbe changed user to '%s'",
		 readOnlyGlobals.unprivilegedUser);
  } else {
    traceEvent(TRACE_WARNING, "Unable to locate user %s",
	       readOnlyGlobals.unprivilegedUser);
  }

  umask(0);
#endif
}

/* ******************************************* */

char* CollectorAddress2Str(CollectorAddress *collector, char *buf, u_int buf_len) {
  char *transport, addr[64];
  u_int port;

  switch(collector->transport) {
  case TRANSPORT_UDP:     transport = "udp";     break;
  case TRANSPORT_TCP:     transport = "tcp";     break;
  case TRANSPORT_SCTP:    transport = "sctp";    break;
#ifdef IP_HDRINCL
  case TRANSPORT_UDP_RAW: transport = "udp-raw"; break;
#endif
  default:                transport = "???";
  }

  if(collector->isIPv6 == 0)
    inet_ntop(AF_INET, &collector->u.v4Address.sin_addr, addr, sizeof(addr)), port = collector->u.v4Address.sin_port;
  else
    inet_ntop(AF_INET6, &collector->u.v6Address.sin6_addr, addr, sizeof(addr)), port = collector->u.v6Address.sin6_port;

  snprintf(buf, buf_len, "%s://%s:%d", transport, addr, ntohs(port));
  return(buf);
}

/* ******************************************* */

static char* LogEventSeverity2Str(LogEventSeverity event_severity) {
 switch(event_severity) {
 case severity_error:   return("ERROR");
 case severity_warning: return("WARN");
 case severity_info:    return("INFO");
 default:               return("???");
 }
}

/* ******************************************* */

static char* LogEventType2Str(LogEventType event_type) {
  switch(event_type) {
  case probe_started:              return("NPROBE_START");
  case probe_stopped:              return("NPROBE_STOP");
  case packet_drop:                return("CAPTURE_PACKET_DROP");
  case flow_export_error:          return("FLOW_EXPORT_ERROR");
  case collector_connection_error: return("COLLECTOR_CONNECTION_ERROR");
  case collector_connected:        return("CONNECTED_TO_COLLECTOR");
  case collector_disconnected:     return("DISCONNECTED_FROM_COLLECTOR");
  case collector_too_slow:         return("COLLECTOR_TOO_SLOW");
  default:                         return("???");
  }
}

/* ******************************************* */

void dumpLogEvent(LogEventType event_type, LogEventSeverity severity, char *message) {
  FILE *fd;
  time_t theTime;
  char theDate[32];
  static int skipDump = 0;

  if(readOnlyGlobals.eventLogPath == NULL) return;

  fd = fopen(readOnlyGlobals.eventLogPath, "a");
  if(fd == NULL) {
    if(!skipDump) {
      traceEvent(TRACE_WARNING, "Unable to append event on file %s",
		 readOnlyGlobals.eventLogPath);
      skipDump = 1;
    }

    return;
  } else
    skipDump = 0;

  theTime = time(NULL);
  strftime(theDate, sizeof(theDate), "%d/%b/%Y %H:%M:%S", localtime(&theTime));

  fprintf(fd, "%s\t%s\t%s\t%s\n", theDate,
	  LogEventSeverity2Str(severity),
	  LogEventType2Str(event_type), message ? message : "");
  fclose(fd);
}

/* ****************************************************** */

u_int64_t to_msec(struct timeval *tv) {
  u_int64_t val = (u_int64_t)tv->tv_sec * 1000;

  val += (u_int64_t)tv->tv_usec/1000;

  return(val);
}

/* ****************************************************** */

struct timeval* min_timeval(struct timeval *a, struct timeval *b) {
  if((a->tv_sec == 0) && (a->tv_usec == 0))
    return(b);
  else if(a->tv_sec < b->tv_sec)
    return(a);
  else if(a->tv_sec > b->tv_sec)
    return(b);
  else {
    if(a->tv_usec < b->tv_usec)
      return(a);
    else
      return(b);
  }
}

/* ****************************************************** */

struct timeval* max_timeval(struct timeval *a, struct timeval *b) {
  if(min_timeval(a, b) == a)
    return(b);
  else
    return(a);
}

/* ****************************************************** */

char* format_tv(struct timeval *a, char *buf, u_int buf_len) {
  snprintf(buf, buf_len-1, "%u.%03u",
	   (unsigned int)a->tv_sec, (unsigned int)a->tv_usec/1000);
  return(buf);
}

/* ****************************************************** */

/* Remove tabs */
char* detab(char *str) {
  int i;

  for(i=0; str[i] != '\0'; i++) {
    switch(str[i]) {
    case '\t':
    case '\r':
      str[i] = ' ';
      break;
    }
  }

  return(str);
}

/* ****************************************************** */

void setThreadAffinity(u_int core_id) {
#ifdef HAVE_PTHREAD_SET_AFFINITY
  if((getNumCores() > 1) && (readOnlyGlobals.numProcessThreads > 1)) {
    /* Bind this thread to a specific core */
    cpu_set_t cpuset;
    int rc;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    if((rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0)
      traceEvent(TRACE_ERROR, "Error while binding to core %ld: errno=%i\n",
		 core_id, rc);
    else {
      traceEvent(TRACE_INFO, "Bound thread to core %lu/%u\n", core_id, getNumCores());
    }
  }
#endif
}

/* ****************************************************** */

float timeval2ms(struct timeval *tv) {
  return((float)tv->tv_sec*1000+(float)tv->tv_usec/1000);
}

/* ****************************************************** */

u_short getNumCores(void) {
#ifdef linux
  return(sysconf(_SC_NPROCESSORS_CONF));
#else
  return(ACT_NUM_PCAP_THREADS);
#endif
}

/* ************************************ */

char *getProtoName(u_short protoId) {
  char *prot_long_str[] = { IPOQUE_PROTOCOL_LONG_STRING };

  return(prot_long_str[protoId]);
}

/* ************************************ */

#ifdef HAVE_PF_RING
int forwardPacket(int rx_device_id, char *p, int p_len) {
  pfring *out_dev;
  int rc;

  if(readWriteGlobals->out_devices[0].deviceId == rx_device_id)
    out_dev = readWriteGlobals->out_devices[1].ring;
  else
    out_dev = readWriteGlobals->out_devices[0].ring;

  if(out_dev != NULL)
    rc = pfring_send(out_dev, (char*)p, p_len, 1 /* flush_packet */);
 else
   rc = 0;

  if(rc < 0)
    traceEvent(TRACE_NORMAL, "[PF_RING] pfring_send(%s,len=%d) returned %d",
	       out_dev->device_name, p_len, rc);

  return(rc);
}
#endif
