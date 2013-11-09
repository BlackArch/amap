/* AMAP - application mapper Copyright (c) 2003 van Hauser and DJ.RevMoon
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

// INCLUDES //
#include "amap-inc.h"
#include "amap.h"
#include "amap-lib.h"

int amap6 = 0;

// HELP //
void help(char *prg) {
  printf("%s v%s (c) %s by %s <%s> %s\n", AMAP_PROGRAM, AMAP_VERSION, AMAP_YEAR, AMAP_AUTHOR, AMAP_EMAIL, AMAP_RESOURCE);
  printf("Syntax: %s [-A|-B|-P|-W] [-1buSRHUdqv] [[-m] -o <file>] [-D <file>] [-t/-T sec] [-c cons] [-C retries] [-p proto] [-i <file>] [target port [port] ...]\n", prg);
  printf("Modes:\n");
  printf("  -A         Map applications: send triggers and analyse responses (default)\n");
  printf("  -B         Just grab banners, do not send triggers\n");
  printf("  -P         No banner or application stuff - be a (full connect) port scanner\n");
//  printf("  -W         Web Update - online update the application fingerprint database!\n");
  printf("Options:\n");
  printf("  -1         Only send triggers to a port until 1st identification. Speeeeed!\n");
#ifdef AF_INET6
  if (amap6)
    printf("  -4         Use IPv4 instead of IPv6\n");
  else
    printf("  -6         Use IPv6 instead of IPv4\n");
#endif
  printf("  -b         Print ascii banner of responses\n");
  printf("  -i FILE    Nmap machine readable outputfile to read ports from\n");
  printf("  -u         Ports specified on commandline are UDP (default is TCP)\n");
#ifdef OPENSSL
  printf("  -R / -S    Do NOT identify RPC / SSL services\n");
#else
  printf("  -R         Do NOT identify RPC service\n");
#endif
  printf("  -H         Do NOT send application triggers marked as potentially harmful\n");
  printf("  -U         Do NOT dump unrecognised responses (better for scripting)\n");
  printf("  -d         Dump all responses\n");
  printf("  -v         Verbose mode, use twice (or more!) for debug (not recommended :-)\n");
  printf("  -q         Do not report closed ports, and do not print them as unidentified\n");
  printf("  -o FILE [-m] Write output to file FILE, -m creates machine readable output\n");
  printf("  -c CONS    Amount of parallel connections to make (default %d, max %d)\n", AMAP_DEFAULT_TASKS, AMAP_MAX_TASKS);
  printf("  -C RETRIES Number of reconnects on connect timeouts (see -T) (default %d)\n", AMAP_MAX_CONNECT_RETRIES);
  printf("  -T SEC     Connect timeout on connection attempts in seconds (default %d)\n", AMAP_CONNECT_TIME);
  printf("  -t SEC     Response wait timeout in seconds (default %d)\n", AMAP_RESPONSE_TIME);
  printf("  -p PROTO   Only send triggers for this protocol (e.g. ftp)\n");
//  printf("  -D FILE    Read from Definitions FILE[.trig|.resp|.rpc] instead of default\n");
//  printf("  -h         Print this shit\n");
  printf("  TARGET PORT   The target address and port(s) to scan (additional to -i)\n");
  printf("%s is a tool to identify application protocols on target ports.\n", AMAP_PROGRAM);
#ifndef OPENSSL
  printf("Note: this version was NOT compiled with SSL support!\n");
#endif
  printf("Usage hint: Options \"-bqv\" are recommended, add \"-1\" for fast/rush checks.\n");
  exit(-1);
}


// MAIN //
int main(int argc, char *argv[]) {
  // VARIABLES //
  amap_struct_options   *opt;
  int newargc;
  char *newargv[argc];
  int  i = 0;

  // INITIALISATION //
  opt = amap_main_init();

  if (strstr(argv[0], "amap6") != NULL) {
    amap6 = 1;
    opt->ipv6 = 1;
  }

  // GETOPT //
  if (argc < 2 || strncmp(argv[1], "-?", 2) == 0 || strncmp(argv[1], "--h", 3) == 0)
    help(argv[0]);
  while ((i = getopt(argc, argv, "146SRHUbuvdhmi:T:c:C:p:o:D:t:qABPW")) >= 0) {
    switch (i) {
    case 'A': // defines in the future that we want default AMAP mode
      break;
    case '1':
      opt->one_is_enough = 1;
      break;
    case '4':
      opt->ipv6 = 0;
      break;
    case '6':
      opt->ipv6 = 1;
#ifndef AF_INET6
      amap_error("No IPv6 support found on your system");
#endif
      break;
    case 'd':
      opt->dump_all = 1;
      break;
    case 'v':
      opt->verbose++;
      break;
    case 'S':
      opt->do_scan_ssl = 0;
      break;
    case 'R':
      opt->do_scan_rpc = 0;
      break;
    case 'b':
      opt->banner = 1;
      break;
    case 'm':
      opt->machine_readable = 1;
      break;
    case 'H':
      opt->harmful = 0;
      break;
    case 'U':
      opt->dump_unidentified = 0;
      break;
    case 'c':
      opt->tasks = atoi(optarg);
      break;
    case 'C':
      opt->max_connect_retries = atoi(optarg);
      break;
    case 'i':
      opt->file_nmap = optarg;
      break;
    case 'u':
      opt->cmd_proto = AMAP_PROTO_UDP;
      break;
    case 'p':
      opt->only_send_trigger = optarg;
      break;
    case 'o':
      opt->file_log = optarg;
      break;
    case 'q':
      opt->quiet = 1;
      break;
    case 'D':
      opt->filename = optarg;
      break;
    case 't':
      opt->timeout_response = atoi(optarg);
      break;
    case 'T':
      opt->timeout_connect = atoi(optarg);
      break;
    case 'B':
      opt->banner_only = 1;
      opt->do_scan_ssl = 0;
      opt->do_scan_rpc = 0;
      opt->one_is_enough = 1;
      break;
    case 'P':
      opt->portscanner = 1;
      opt->do_scan_ssl = 0;
      opt->do_scan_rpc = 0;
      opt->one_is_enough = 1;
      opt->timeout_response--;
      break;
    case 'W':
      fprintf(stderr, "Error: web update is not available anymore\n");
      exit(-1);
      opt->update = 1;
      break;
    case 'h':
      help(argv[0]);
      break;
    default:
      fprintf(stderr, "Error: unknown option -%c\n", i);
      help(argv[0]);
    }
  }

  // VARIABLES VERIFICATION //
  if (opt->update && argc != 2 && opt->filename == NULL)
    amap_warn("amap takes no other commandline options when in -W online update mode except -D");
  if ((optind + 2 > argc) && (opt->file_nmap == NULL) && (opt->update == 0))
    help(argv[0]);
  if (opt->file_log == NULL && opt->machine_readable)
    amap_error("option -m set, but no logfile defined (-o)");
  if (opt->tasks < 1 || opt->tasks > AMAP_MAX_TASKS)
    amap_error("the connect task option (-c) must be between 1 and %d", AMAP_MAX_TASKS);
  if (opt->timeout_connect < 1 || opt->timeout_connect > 240)
    amap_error("the connect timeout option (-T) must be between 1 and 240, its counted in seconds!");
  if (opt->timeout_response < 1 || opt->timeout_response > 240)
    amap_error("the response timeout option (-t) must be between 1 and 240, its counted in seconds!");

  newargc = argc - optind;
  for (i = optind; i < argc; i++)
    newargv[i - optind] = argv[i];
  newargv[newargc] = NULL;

  return amap_main(opt, newargc, newargv);
}
