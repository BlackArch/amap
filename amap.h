#ifndef _AMAP_H

/* AMAP - Application MAPper Copyright (c) 2003-2005 van Hauser and DJ RevMoon
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.    
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *    
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define AMAP_PROGRAM   "amap"
#define AMAP_VERSION   "5.4"
#define AMAP_YEAR      "2011"
#define AMAP_AUTHOR    "van Hauser"
#define AMAP_EMAIL     "vh@thc.org"
#define AMAP_RESOURCE  "www.thc.org/thc-amap"

#ifndef AMAP_PREFIX
 #ifdef PREFIX
  #warning "PREFIX definition found, installing to this prefix directory location"
  #define AMAP_PREFIX         PREFIX
 #else
  #define AMAP_PREFIX         "/usr/local"
 #endif
#endif

#define AMAP_BUFSIZE		1024	// standard buffer size
#define AMAP_BUFSIZE_BIG	65536   // big standard buffer size
#define AMAP_REGEX_OPTIONS	( PCRE_MULTILINE | PCRE_CASELESS | PCRE_DOTALL )

/* web update feature */
#define AMAP_WEBBUFLEN 1024
#define AMAP_MAXTOKENLEN 64

/* connection and task definitions */
#define AMAP_MAX_CONNECT_RETRIES	3	// connect() retries
#define AMAP_CONNECT_TIME	5	// seconds to wait for connect
#define AMAP_RESPONSE_TIME      5	// seconds to wait for response
#define AMAP_MAX_TASKS		256	// maximum parallel tasks
#define AMAP_DEFAULT_TASKS	32	// default parallel tasks
#define AMAP_MAX_ID_LENGTH	32
#define AMAP_UFO		"unidentified"

/* file definitions */
#define AMAP_DEFAULT_FILENAME	"appdefs"	// default filename
#define AMAP_FILETYPE_RESPONSES	".resp"	// default extension
#define AMAP_FILETYPE_TRIGGERS	".trig"	// default extension
#define AMAP_FILETYPE_RPC	".rpc"	// default extension

/* scan modes */
#define AMAP_SCANMODE_DEFAULT	1
#define AMAP_SCANMODE_SSL	2
#define AMAP_SCANMODE_RPC	3

/* ip protocols */
#define AMAP_PROTO_TCP	1
#define AMAP_PROTO_UDP  2
#define AMAP_PROTO_BOTH 3

/* connect states */
#define AMAP_CONNECT_NULL        0
#define AMAP_CONNECT_INPROGRESS  1
#define AMAP_CONNECT_READY       2
#define AMAP_CONNECT_ACTIVE      3
#define AMAP_CONNECT_REUSABLE    4
#define AMAP_CONNECT_RETRY       5

/* all the important structures */
typedef struct {
  char  *only_send_trigger;
  FILE  *logfile;
  int   tasks;
  unsigned char  timeout_connect;
  unsigned char  timeout_response;
  char  max_connect_retries;
  char  do_scan_ssl;
  char  do_scan_rpc;
  char  verbose;
  char  quiet;
  char  banner;
  char  banner_only;
  char  portscanner;
  char  update;
  char  machine_readable;
  char  harmful;
  char  one_is_enough;
  char  dump_unidentified;
  char  dump_all;
  char  ipv6;
  /* for lib package moved here */
  char  *file_nmap;
  char  *file_log;
  char  *filename;
  int   cmd_proto;
} amap_struct_options;

typedef struct {
  unsigned short int port;
  struct amap_struct_portlist *next;
} amap_struct_portlist;

typedef struct {
  char *id;
  amap_struct_portlist *ports;
  char ip_prot;
  char harmful;
  char *trigger;
  int  trigger_length;
  struct amap_struct_triggers *next;
} amap_struct_triggers;

typedef struct {
  char *trigger;
  struct amap_struct_triggerptr *next;
} amap_struct_triggerptr;

typedef struct {
  char *id;
  amap_struct_triggerptr *triggerptr;
  char ip_prot;
  int min_length;
  int max_length;
  pcre *pattern;
  pcre_extra *hints;
  struct amap_struct_responses *next;
} amap_struct_responses;

typedef struct {
  char *id;
  struct amap_struct_identifications *next;
} amap_struct_identifications;

typedef struct {
  unsigned short int port;
  char ip_prot;
  char ssl;
  char rpc;
  char skip;
  int unknown_response_length;
  char *unknown_response;
  amap_struct_identifications *ids;
  struct amap_struct_ports *next;
} amap_struct_ports;

typedef struct {
  char *target;
  amap_struct_ports *ports;
  struct amap_struct_targets *next;
} amap_struct_targets;

typedef struct {
  int running;
  int tasks;
  char scanmode;
} amap_struct_scaninfo;

typedef struct {
  char active;
  char ssl_enabled;
  char retry;
  unsigned char response[AMAP_BUFSIZE + 1];
  int socket;
  int response_length;
  int sockaddr_len;
  time_t timer;
  struct sockaddr *sockaddr;
#ifdef OPENSSL
  SSL *ssl_socket;
#endif
  amap_struct_targets *target;
  amap_struct_ports *port;
  amap_struct_triggers *trigger;
} amap_struct_coms;

#define _AMAP_H
#endif
