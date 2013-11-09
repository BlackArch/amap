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

#ifdef OPENSSL
RSA *amap_rsa = NULL;
#endif

int glob;
int glob_af_inet = AF_INET;
struct sockaddr_in glob_sin;
struct in_addr glob_in;
struct sockaddr *glob_sockaddr = (struct sockaddr *) &glob_sin;
char *glob_addr = (char *) &glob_in;
int glob_sockaddr_len = sizeof(glob_sin);
int glob_addr_len = sizeof(glob_in);
#ifdef AF_INET6
struct sockaddr_in6 glob_sin6;
struct in6_addr glob_in6;
struct addrinfo glob_hints, *glob_result;
#endif

// AMAP_ERROR - partial rip from vh-lib //
void amap_error(char *string, ...) {
  va_list ap;
  char *ptr;

  fprintf(stderr, "Error: ");
  va_start(ap, string);
  for (ptr = string; *ptr != '\0'; ptr++) {
    if (*ptr == '%') {
      ptr++;
      switch(*ptr) {
        case 's': fprintf(stderr, "%s", va_arg(ap, char *));
          break;
        case 'd': fprintf(stderr, "%d", va_arg(ap, int));
          break;
        case 'c': fprintf(stderr, "%c", va_arg(ap, int));
          break;
        default:  fprintf(stderr, "%c", *ptr);
      }
    } else
      fprintf(stderr, "%c", *ptr);
  }
  fprintf(stderr, "\n");
  va_end(ap);
  exit(-1);
}


// AMAP_WARN - partial rip from vh-lib //
void amap_warn(char *string, ...) {
  va_list ap;
  char *ptr;

  printf("Warning: ");
  va_start(ap, string);
  for (ptr = string; *ptr != '\0'; ptr++) {
    if (*ptr == '%') {
      ptr++;
      switch(*ptr) {
        case 's': printf("%s", va_arg(ap, char *));
          break;
        case 'd': printf("%d", va_arg(ap, int));
          break;
        case 'c': printf("%c", va_arg(ap, int));
          break;
        default:  printf("%c", *ptr);
      }
    } else
      printf("%c", *ptr);
  }
  printf("\n");
  va_end(ap);
}


// AMAP_GET_DATA_TOKEN - partial rip from vh-lib //
char *amap_get_data_token(char *data, char token) {
  static char vdata[AMAP_MAXTOKENLEN] = "";
  char search[4] = "#X:";
  char *ptr;

  search[1] = token;
  if (strncmp(data, "###", 3) != 0) {
//    amap_warn("invalid or missing version data: %s", data);
    return(vdata);
  }
  if ((ptr = strstr(data, search)) == NULL) {
//    amap_warn("missing token in data: %s", data);
    return(vdata);
  }
  
  memcpy(vdata, ptr + 3, sizeof(vdata)-1);
  vdata[sizeof(vdata) - 1] = 0;
  if ((ptr = index(vdata, '#')) == NULL) {
//    amap_error("invalid or missing version string in webfile: %s", data);
    strcpy(vdata, "");
    return(vdata);
  }
  *ptr = 0;
  return(vdata);
}


// AMAP_WEBUPDATE_FILE - partial rip from vh-lib //
int amap_webupdate_file(char *webfile, char *localfile, int checkversion, int ask) {
  int len = strlen("http://");
  int wlen = strlen(webfile);
  int port = 80, s, result = 1, datalen = 0, version = -1, fck;
int xx = 0;
  unsigned long int ip;
  time_t epoch;
  struct in_addr in;
  struct hostent *target;
  struct sockaddr_in addr;
  struct tm *the_time;
  char *url, *ptr, *data = NULL, *filedata;
  char *host = malloc(strlen(webfile));
  char *request = malloc(AMAP_WEBBUFLEN + wlen);
  char datetime[64] = "";
  FILE *f;

  if (strncmp(webfile, "http://", len) != 0)
    amap_error("webfile location is missing http://: %s", webfile);
  if ((url = index(webfile + len, '/')) == NULL)
    amap_error("webfile definition is missing a web file location: %s", webfile);
  memset(host, 0, wlen);
  memset(request, 0, AMAP_WEBBUFLEN + wlen);
  memcpy(host, webfile + len, url - (webfile + len));
  if (index(host, '@') != NULL)
    amap_error("authentication not supported: %s", host);
  if ((ptr = index(host, ':')) != NULL) {
    *ptr++ = 0;
    port = atoi(ptr);
    if (port < 0 || port > 65535)
      amap_error("invalid port: %s", ptr);
  }
  snprintf(request, AMAP_WEBBUFLEN + wlen, "GET %s HTTP/1.0\r\nHost: %s:%d\r\nUser-Agent: %s %s\r\n\r\n", url, host, port, AMAP_PROGRAM, AMAP_VERSION);

//#ifdef AF_INET6
//printf("uses pton\n");
//  if ((xx = inet_pton(AF_INET, host, &in)) < 0) {
//printf("failed %d: %d %s\n",xx,AF_INET,host);
//#else
//printf("uses aton\n");
//  if ((xx=inet_aton(host, &in)) <= 0) {
//printf("failed %d: %d %s\n",xx,AF_INET,host);
//#endif
    if ((target = gethostbyname(host)) != NULL) {
      memcpy((char*)&ip, (char*)target->h_addr, 4);
    } else
      amap_error("could not resolve host: %s", host);
//  } else
//{
//    memcpy((char*)&ip, (char*)&in.s_addr, 4);
//printf("success: %d: %d %s\n", xx, AF_INET, host);
//}
//
//  printf("!!! SPECIAL DEBUG OUTPUT !!!\nPlease send the following information in if the web update fails:\n");
//  printf("Host: %s\n", host);
//  printf("IP (int): %d\n", ip);
//  printf("Dump of (in):\n");
//  amap_dump_string(stdout, (unsigned char*)&in, sizeof(in), 16);
//  printf("\n");

  if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    amap_error("could not get a socket");
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &result, sizeof(result));
  addr.sin_port = htons(port);
  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr.s_addr, &ip, 4);
  if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    amap_error("could not connect to host: %s (%lu)", host, ip);

  if (send(s, request, strlen(request), 0) < 0)
    amap_error("web site closed connection");
  memset(request, 0, AMAP_WEBBUFLEN + wlen);
  
  while ((len = recv(s, request, AMAP_WEBBUFLEN, 0)) > 0) {
    if (data == NULL)
      data = malloc(len);
    else
      data = realloc(data, datalen + len);
    memcpy(data + datalen, request, len);
    datalen += len;
    memset(request, 0, AMAP_WEBBUFLEN);
  }
  close(s);

  // prevent memory access voilation if no version data is present
  data = realloc(data, datalen + AMAP_MAXTOKENLEN);
  memset(data + datalen, 0, AMAP_MAXTOKENLEN);

  if (strncmp(data, "HTTP/", strlen("HTTP/")) != 0)
    amap_error("invalid http response: %s", data);
  if (strncmp(data + strlen("HTTP/1.0 "), "200", 3) != 0)
    amap_error("file could not be found by web server: %s", data);
  if ((filedata = strstr(data, "\r\n\r\n")) == NULL)
    amap_error("no data found in response: %s", data);
  filedata += 4;
  datalen = datalen - (filedata - data);

  // versioncheck > 0 - check version information on file
  // format: "###V:104#P:1.0#D:1231231231#M:Have fun!###DO NOT EDIT THIS LINE!"
  if (checkversion) {
    if ((f = fopen(localfile, "r")) != NULL) {
      memset(request, 0, AMAP_WEBBUFLEN);
      fck=fread(request, AMAP_WEBBUFLEN - AMAP_MAXTOKENLEN, 1, f);
      version = atoi(amap_get_data_token(request, 'V'));
      fclose(f);
    }
    
    if (version >= atoi(amap_get_data_token(filedata, 'V'))) {
      printf("No new updates for file %s available\n", localfile);
      free(request);
      free(host);
      free(data);
      return -1;
    }
  }

  // if ask > 0 - ask if overwrite file
  if (ask) {
    printf("Please confirm updating of file %s [YES(default)/no]: ", localfile);
    result = fgetc(stdin);
    if (result == 'N' || result == 'n')
      return -1;
  }
  
  // get other data
  if ((epoch = strtoul(amap_get_data_token(filedata, 'D'), NULL, 10)) > 1000000000) {
    the_time = localtime(&epoch);
    strftime(datetime, sizeof(datetime), " (data from %Y-%m-%d %H:%M:%S)", the_time);
  }
  
  // write file
  if ((f = fopen(localfile, "w")) == NULL)
    amap_error("can not write file %s", localfile);
  fwrite(filedata, datalen, 1, f);
  fclose(f);
  printf("File %s successfully updated%s\n", localfile, datetime);

  // msg check
  ptr = amap_get_data_token(filedata, 'M');
  if (strlen(ptr) > 0) {
    printf("This update comes with the following message:\n\"%s\"\n", ptr);
  }

  // main program version check
  ptr = amap_get_data_token(filedata, 'P');
  if (strlen(ptr) > 2) {
    if (strcmp(ptr, AMAP_VERSION) != 0)
      printf("A new version of %s is available! You are using v%s, current is v%s.\nGo and download from %s !\n", AMAP_PROGRAM, AMAP_VERSION, ptr, AMAP_RESOURCE);
  }

  free(request);
  free(host);
  free(data);
  return 0;
}


#ifdef OPENSSL
// AMAP_SSL_TEMP_RSA_CB //
RSA *amap_ssl_temp_rsa_cb(SSL *ssl, int export, int keylength) {
  if (amap_rsa == NULL)
    amap_rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
  return amap_rsa;
}
#endif


// AMAP_OPEN_FILE //
FILE *amap_open_file(char *fnam, char *type, char *extension, int verbose) {
  char file_name[256];
  FILE *f = NULL;

  if (fnam != NULL) {
    strncpy(file_name, fnam, sizeof(file_name) - strlen(extension) - 1);
    file_name[sizeof(file_name) - strlen(extension) - 1] = 0;
    strcat(file_name, extension);
    f = fopen(file_name, "r");
  } else {
    strcpy(file_name, "./");
    strcat(file_name, AMAP_DEFAULT_FILENAME);
    strcat(file_name, extension);
    if ((f = fopen(file_name, "r")) == NULL) {
      strcpy(file_name, AMAP_PREFIX);
      if (file_name[strlen(file_name) - 1] != '/')
        strcat(file_name, "/");
      strcat(file_name, "etc/");
      strcat(file_name, AMAP_DEFAULT_FILENAME);
      strcat(file_name, extension);
      f = fopen(file_name, "r");
    }
  }
  if (f == NULL)
    amap_error("can not open %s file: %s", type, file_name);
  else 
    if (verbose)
      printf("Using %s file %s ... ", type, file_name);
  return f;
}


// AMAP_STRDUP //
char *amap_strdup(char *string) {
  char *ptr;
  int count;

  if (string == NULL)
    return NULL;
  count = strlen(string) + 1;
  if ((ptr = malloc(count)) == NULL)
    amap_error("malloc failed");
  if (count == 1)
    *ptr = 0;
  else
    strcpy(ptr, string);
  return ptr;
}


// AMAP_MEMDUP //
char *amap_memdup(unsigned char *string, int len) {
  char *ptr;

  if (string == NULL)
    return NULL;
  if ((ptr = malloc(len)) == NULL)
    amap_error("malloc failed");
  memcpy(ptr, string, len);
  return ptr;
}


// AMAP_INDEX //
char *amap_index(char *string, char c) {
  if (string == NULL)
    return NULL;
  return(index(string + 1, c));
}


// AMAP_DELETE_WHITESPACE //
void amap_delete_whitespace(char *target) {
  register int l = 0;
  register int k = 0;

  if (target == NULL)
    return;

  while ((target[l] != '\0')) {
    if ((target[l] == ' ') || (target[l] == '\t')) {
      k = l--;
      while (target[k++] != '\0')
	target[k - 1] = target[k];
    }
    l++;
  }
}


// AMAP_MAKE_LOWERCASE //
void amap_make_lowercase(char *target, int len) {
  register int l = 0;

  for (l = 0; l < len; l++)
    if (target[l] != 0)
      target[l] = (char) tolower(target[l]);
}


// READ_FILE_TRIGGERS //
amap_struct_triggers *read_file_triggers(char *extension, char *filename, amap_struct_options *opt) {
  amap_struct_triggers *triggers;
  amap_struct_triggers *trigger;
  FILE *f;
  char line[AMAP_BUFSIZE];
  char orig_line[AMAP_BUFSIZE];
  char *t_uid;
  char *ports;
  char *proto;
  char *harmful;
  char *string;
  char *ptr;
  char *only_trigger = NULL;
  int i;
  int a;
  int b;
  int count;
  int count_triggers = 0;

  f = amap_open_file(filename, "trigger", extension, opt->verbose);
  if (opt->verbose > 1)
    printf("\n");
  if ((triggers = trigger = (amap_struct_triggers*) malloc(sizeof(amap_struct_triggers))) == NULL)
    amap_error("malloc failed");
  memset(trigger, 0, sizeof(amap_struct_triggers));

  if (strcmp(extension, AMAP_FILETYPE_TRIGGERS) == 0 && opt->only_send_trigger != NULL) {
    if ((only_trigger = malloc(strlen(opt->only_send_trigger) + 2)) == NULL)
      amap_error("malloc failed");
    strcpy(only_trigger, opt->only_send_trigger);
    strcat(only_trigger, ":");
  }

  while (fgets(line, AMAP_BUFSIZE, f) != NULL) {
    if (line[strlen(line) - 1] != '\n')
      amap_error("line in trigger file is too long or not terminating with \\n: %s", line);
    if ((line[0] != '#') && (index(line, ':') != NULL) && (only_trigger == NULL || strncmp(only_trigger, line, strlen(only_trigger)) == 0)) { // weed out comment lines
      count_triggers++;
      if (count_triggers > 1) {
        if ((/*(amap_struct_triggers*)*/ trigger->next = /*(amap_struct_triggers*)*/ malloc(sizeof(amap_struct_triggers))) == NULL)
          amap_error("malloc failed");
        trigger = (amap_struct_triggers*) trigger->next;
        memset(trigger, 0, sizeof(amap_struct_triggers));
      }
      line[strlen(line) - 1] = 0;
      if (line[strlen(line) - 1] == '\r')
        line[strlen(line) - 1] = 0;
      strcpy(orig_line, line);
      t_uid = line;
      ports = amap_index(t_uid, ':');
      proto = amap_index(ports, ':');
      harmful = amap_index(proto, ':');
      string = amap_index(harmful, ':');
      if (string == NULL)
        amap_error("too few fields in the following line of the trigger file: %s", orig_line);
      *string++ = 0; // we cut before the trigger string first
      amap_make_lowercase(line, strlen(line)); // then make everything before the string lowercase
      amap_delete_whitespace(line); // and remove whitespace
      ports = amap_index(t_uid, ':');
      proto = amap_index(ports, ':');
      harmful = amap_index(proto, ':');
      *ports++ = 0; // and now cut the fields
      *proto++ = 0;
      *harmful++ = 0;
      trigger->id = amap_strdup(t_uid);
      if (strlen(t_uid) > AMAP_MAX_ID_LENGTH)
        amap_error("id of trigger is too long: %s", orig_line);
      if (strlen(t_uid) == 0)
        amap_error("id of trigger is not set: %s", orig_line);
      if (opt->one_is_enough && strlen(ports) > 0) { // without one_is_enough activated, this is senseless
        count = 0;
        for (i = 0; i < strlen(ports); i++)
          if (ports[i] == ',')
            count++;
#ifdef AMAP_DEBUG
#warning "implement common port usage"
#endif
        for (i = 0; i < count; i++) {
/*
   It is unsure yet what to do here ...
   lets think about it carefully.
   present is: amap_struct_portlist *ports;
   which is defined as: unsigned short int port; struct amap_struct_portlist *next;
*/
        }
        if (opt->verbose > 1)
          amap_warn("common ports definition in trigger file are currently ignored");
      }
      switch (*proto) {
        case 0:
        case 'b': trigger->ip_prot = AMAP_PROTO_BOTH; break;
        case 't': trigger->ip_prot = AMAP_PROTO_TCP; break;
        case 'u': trigger->ip_prot = AMAP_PROTO_UDP; break;
        default:  amap_error("protocol field in trigger file must be tcp, udp or empty: %s", orig_line);
      }
      if ((*harmful != '1' && *harmful != '0') || strlen(harmful) != 1)
        amap_error("harmful field in trigger file must be 0 or 1: %s", orig_line);
      trigger->harmful = atoi(harmful);
      if (strcmp(extension, AMAP_FILETYPE_RPC) == 0) {
        trigger->trigger = amap_strdup(string);
        trigger->trigger_length = 0;
      } else {
        while (*string != '"' && *string != 0 && *string != '0')
          string++;
        if (*string == 0 || strlen(string) < 3)
          amap_error("invalid trigger data in trigger file: %s", orig_line);
        if (*string == '"') {
          string++;
          if ((ptr = rindex(string, '"')) == NULL)
            amap_error("missing \" in trigger data: %s", orig_line);
          *ptr = 0;
          if ((ptr = malloc(strlen(string))) == NULL)
            amap_error("malloc failed");
          a = 0;
          b = 0;
          for (a = 0; a < strlen(string); a++) {
            if (string[a] != '\\')
              ptr[b] = string[a];
            else {
              a++;
              switch(string[a]) {
                case '\\': ptr[b] = '\\'; break;
                case 'n': ptr[b] = '\n'; break;
                case 'r': ptr[b] = '\r'; break;
                case 't': ptr[b] = '\t'; break;
                default: amap_error("wrong escape in trigger data : \"\\%c\" : %s", string[a], orig_line);
              }
            }
            b++;
          }
          ptr[b] = 0;
          trigger->trigger = amap_strdup(ptr);
          trigger->trigger_length = strlen(trigger->trigger);
          free(ptr);
        } else {
          if (strncmp(string, "0x", 2) != 0)
            amap_error("invalid trigger data in trigger file: %s", orig_line);
          string = string + 2;
          amap_delete_whitespace(string);
          if (strlen(string) < 2 || strlen(string) % 2 > 0)
            amap_error("invalid trigger data in trigger file, incomplete pair: %s", orig_line);
          amap_make_lowercase(string, strlen(string));
          trigger->trigger_length = strlen(string) / 2;
          if ((trigger->trigger = malloc(trigger->trigger_length)) == NULL)
            amap_error("malloc failed");
          for (i = 0; i < strlen(string) / 2; i++) {
            if (isxdigit(string[i*2]))
              a = string[i*2];
            else
              amap_error("non-hex digit in hex-type trigger data: %c : %s", string[i*2], orig_line);
            if (isxdigit(string[(i*2) + 1]))
              b = string[(i*2) + 1];
            else
              amap_error("non-hex digit in hex-type trigger data: %c : %s", string[(i*2) + 1], orig_line);
            isalpha(a) ? (a -= 87) : (a -= 48);
            isalpha(b) ? (b -= 87) : (b -= 48);
            trigger->trigger[i] = (a * 16) + b;
          }
        }
      }
      if (opt->verbose > 1)
        printf("DEBUG: Loaded trigger %s ...\n", trigger->id);
    }
  }
  if (count_triggers == 0)
    amap_error("no triggers loaded - either trigger file is empty, or -p proto nonexisting");
  if (opt->verbose)
    printf("loaded %d triggers\n", count_triggers);
  if (only_trigger != NULL)
    free(only_trigger);
  return triggers;
}


// READ_FILE_RESPONSES //
amap_struct_responses *read_file_responses(char *extension, char *filename, amap_struct_options *opt) {
  amap_struct_responses *responses;
  amap_struct_responses *response;
  amap_struct_triggerptr *triggerptr_tmp;
  FILE *f;
  char line[AMAP_BUFSIZE];
  char orig_line[AMAP_BUFSIZE];
  char *t_uid;
  char *triggerptr;
  char *proto;
  char *length;
  char *string;
  char *ptr;
  int errptr;
  int i;
  int count;
  const char *error;
  int count_responses = 0;

  f = amap_open_file(filename, "response", extension, opt->verbose);
  if (opt->verbose > 1)
    printf("\n");
  if ((responses = response = (amap_struct_responses*) malloc(sizeof(amap_struct_responses))) == NULL)
    amap_error("malloc failed");
  memset(response, 0, sizeof(amap_struct_responses));

  while (fgets(line, AMAP_BUFSIZE, f) != NULL) {
    if (line[strlen(line) - 1] != '\n')
      amap_error("line in response file is too long or not terminating with \\n: %s", line);
    if ((line[0] != '#') && (index(line, ':') != NULL)) { // weed out comment lines
      count_responses++;
      if (count_responses > 1) {
        if ((/*(amap_struct_responses*)*/ response->next = /*(amap_struct_responses*)*/ malloc(sizeof(amap_struct_responses))) == NULL)
          amap_error("malloc failed");
        response = (amap_struct_responses*) response->next;
        memset(response, 0, sizeof(amap_struct_responses));
      }
      line[strlen(line) - 1] = 0;
      if (line[strlen(line) - 1] == '\r')
        line[strlen(line) - 1] = 0;
      strcpy(orig_line, line);
      t_uid = line;
      triggerptr = amap_index(t_uid, ':');
      proto = amap_index(triggerptr, ':');
      length = amap_index(proto, ':');
      string = amap_index(length, ':');
      if (string == NULL)
        amap_error("too few fields in the following line of the response file: %s", orig_line);
      *string++ = 0; // first cut the string at the regex string, then make everything before lowercase
      amap_make_lowercase(line, strlen(line));
      amap_delete_whitespace(line); // and remove whitespace
      triggerptr = amap_index(t_uid, ':');
      proto = amap_index(triggerptr, ':');
      length = amap_index(proto, ':');
      *triggerptr++ = 0; // and now cut the fields
      *proto++ = 0;
      *length++ = 0;
      response->id = amap_strdup(t_uid);
      if (strlen(response->id) > AMAP_MAX_ID_LENGTH)
        amap_error("id of response is too long: %s", orig_line);
      if (strlen(response->id) == 0)
        amap_error("id of response is not set: %s", orig_line);
      if (*triggerptr != 0) {
        count = 1;
        for (i = 0; i < strlen(triggerptr); i++)
          if (triggerptr[i] == ',')
            count++;
        if ((triggerptr_tmp = response->triggerptr = malloc(sizeof(amap_struct_triggerptr))) == NULL)
          amap_error("malloc failed");
        triggerptr_tmp->next = NULL;
        
        for (i = 0; i < count; i++) {
          if (i + 1 < count) {
            ptr = index(triggerptr, ',');
            *ptr++ = 0;
          }
          triggerptr_tmp->trigger = strdup(triggerptr);
          if (i + 1 < count) {
            triggerptr = ptr;
            if ((/*(amap_struct_triggerptr*)*/ triggerptr_tmp->next = malloc(sizeof(amap_struct_triggerptr))) == NULL)
              amap_error("malloc failed");
            triggerptr_tmp = (amap_struct_triggerptr*) triggerptr_tmp->next;
            triggerptr_tmp->next = NULL;
          }
        }
      }
      switch (*proto) {
        case 0:
        case 'b': response->ip_prot = AMAP_PROTO_BOTH; break;
        case 't': response->ip_prot = AMAP_PROTO_TCP; break;
        case 'u': response->ip_prot = AMAP_PROTO_UDP; break;
        default:  amap_error("protocol field in response file must be tcp, udp or empty: %s", orig_line);
      }
      amap_delete_whitespace(length);
      if (*length == 0) {
        response->min_length = 0;
        response->max_length = AMAP_BUFSIZE + 1;
      } else {
        if ((ptr = index(length, ',')) == NULL) {
          response->min_length = atoi(length);
          response->max_length = response->min_length;
        } else {
          *ptr++ = 0;
          response->min_length = atoi(length);
          response->max_length = atoi(ptr);
        }
        if (response->min_length > response->max_length)
          amap_error("minimum length is greater than maximum length of response: %s", orig_line);
      }
      response->pattern = pcre_compile(string, AMAP_REGEX_OPTIONS, &error, &errptr, NULL);
      if (! response->pattern)
        amap_error("response regex string compilation failed with the error: %s -> %s", error, orig_line);
      response->hints = pcre_study(response->pattern, 0, &error);
      if (error != NULL)
        amap_error("response regex string compilation failed with the error: %s -> %s", error, orig_line);
      if (opt->verbose > 1)
        printf("DEBUG: Loaded response %s ...\n", response->id);
    }
  }

  if (count_responses == 0)
    amap_error("no responses loaded - responses file is empty");
  if (opt->verbose)
    printf("loaded %d responses\n", count_responses);
  return responses;
}


// AMAP_ADD_PORT_STRING //
amap_struct_ports *amap_add_port_string(amap_struct_ports *port_tmp, char *port, int cmd_proto, amap_struct_options *opt) {
  char *ptr;
  int pfrom, pto;

  if ((ptr = index(port, '-')) == NULL) {
    if (atoi(port) < 0 || atoi(port) > 65535)
      amap_error("ports to be scanned must be between 0 and 65535 inclusive: %s", port);
    port_tmp->port = atoi(port);
    port_tmp->ip_prot = cmd_proto;
  } else {
    *ptr = 0;
    ptr++;
    pfrom = atoi(port);
    pto = atoi(ptr);
    if (pto < 1 || pfrom < 1 || pto < pfrom || pto > 65535 || pfrom > 65535)
      amap_error("range definition is invalid: %s-%s",port, ptr);
    for ( ;  pfrom <= pto; pfrom++) {
      port_tmp->port = (unsigned short int) pfrom;
      port_tmp->ip_prot = cmd_proto;
      if (opt->verbose > 1)
        printf("%d/%s ", port_tmp->port, port_tmp->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
      if (pto != pfrom) {
        if ((/*(amap_struct_ports *)*/ port_tmp->next = /*(amap_struct_ports *)*/ malloc(sizeof(amap_struct_ports))) == NULL)
          amap_error("malloc failed");
        port_tmp = (amap_struct_ports *) port_tmp->next;
        memset(port_tmp, 0, sizeof(amap_struct_ports));
      }
    }
  }

  return port_tmp;
}


// READ_FILE_NMAP //
amap_struct_targets *read_file_nmap(char *filename, amap_struct_options *opt) {
  amap_struct_targets *targets;
  amap_struct_targets *target;
  amap_struct_ports   *port_tmp;
  FILE *f;
  char line[AMAP_BUFSIZE_BIG];
  char orig_line[AMAP_BUFSIZE_BIG];
  char *ip;
  char *portinfo;
  char *proto;
  char *ptr;
  int ip_prot;
  int count = 0;

  f = amap_open_file(filename, "nmap", "", opt->verbose);
  if ((targets = target = (amap_struct_targets*) malloc(sizeof(amap_struct_targets))) == NULL)
    amap_error("malloc failed");
  memset(target, 0, sizeof(amap_struct_targets));
  if ((port_tmp = target->ports = (amap_struct_ports *) malloc(sizeof(amap_struct_ports))) == NULL)
    amap_error("malloc failed");
  memset(port_tmp, 0, sizeof(amap_struct_ports));

  while (fgets(line, AMAP_BUFSIZE_BIG, f) != NULL) {
    if (line[strlen(line) - 1] != '\n')
      amap_error("line in nmap file is too long or not terminating with \\n: %s", line);
    if ((line[0] == 'H') && (index(line, ' ') != NULL) && ((portinfo = strstr(line, "/open/")) != NULL)) { // just care for data lines
      if (count != 0) {
        if ((/*(amap_struct_targets*)*/ target->next = /*(amap_struct_targets*)*/ malloc(sizeof(amap_struct_targets))) == NULL)
          amap_error("malloc failed");
        target = (amap_struct_targets*) target->next;
        memset(target, 0, sizeof(amap_struct_targets));
        if ((port_tmp = target->ports = (amap_struct_ports *) malloc(sizeof(amap_struct_ports))) == NULL)
          amap_error("malloc failed");
        memset(port_tmp, 0, sizeof(amap_struct_ports));
      }
      line[strlen(line) - 1] = 0;
      if (line[strlen(line) - 1] == '\r')
        line[strlen(line) - 1] = 0;
      strcpy(orig_line, line);
      ip = index(line, ' ');
      ip++;
      if (opt->ipv6)
        ptr = amap_index(ip, ':');
      else
        ptr = amap_index(ip, '.');
      if ((ptr = amap_index(ptr, ' ')) == NULL)
        amap_error("nmap data line fucked up (is it ipv6 but you did not use the -6 option?) : %s", orig_line);
      *ptr = 0;
      if (index(ip, ':') == NULL)
        target->target = strdup(ip);
      else {
        target->target = malloc(strlen(ip) + 3);
        strcpy(target->target, "[");
        strcat(target->target, ip);
        strcat(target->target, "]");
      }
      if (opt->ipv6 == 0)
        if (inet_addr(target->target) == -1)
          amap_error("invalid IP address in nmap line: %s : %s", target->target, orig_line);
      if (opt->verbose > 1)
        printf("DEBUG: Loading ports for %s ... ", target->target);
      while (*(portinfo - 1) != ' ')
        portinfo--;
      ptr = amap_index(portinfo, '/');
      proto = amap_index(ptr, '/');
      if (proto == NULL)
        amap_error("too few number of fields in the following port data in the nmap file: %s", portinfo);
      *ptr++ = 0;
      *proto++ = 0;
      switch (*proto) {
        case 't': ip_prot = AMAP_PROTO_TCP; break;
        case 'u': ip_prot = AMAP_PROTO_UDP; break;
        default:  amap_error("protocol field in nmap file is not tcp or udp : %s : %s", proto, orig_line);
      }
      port_tmp->port = atoi(portinfo);
      port_tmp->ip_prot = ip_prot;
      if (opt->verbose > 1)
        printf("%d/%s ", port_tmp->port, port_tmp->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
      while ((portinfo = strstr(proto + 1, "/open/")) != NULL) {
        if ((/*(amap_struct_ports *)*/ port_tmp->next = /*(amap_struct_ports *)*/ malloc(sizeof(amap_struct_ports))) == NULL)
          amap_error("malloc failed");
        port_tmp = (amap_struct_ports *) port_tmp->next;
        memset(port_tmp, 0, sizeof(amap_struct_ports));
        while (*(portinfo - 1) != ' ')
          portinfo--;
        ptr = amap_index(portinfo, '/');
        proto = amap_index(ptr, '/');
        if (proto == NULL)
          amap_error("too few number of fields in the following port data in the nmap file: %s", portinfo);
        *ptr++ = 0;
        *proto++ = 0;
        switch (*proto) {
          case 't': ip_prot = AMAP_PROTO_TCP; break;
          case 'u': ip_prot = AMAP_PROTO_UDP; break;
          default:  amap_error("protocol field in nmap file is not tcp or udp : %s : %s", proto, orig_line);
        }
        port_tmp->port = atoi(portinfo);
        port_tmp->ip_prot = ip_prot;
        if (opt->verbose > 1)
          printf("%d/%s ", port_tmp->port, port_tmp->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
      }
      count++;
      if (opt->verbose > 1)
        printf("\n");
    }
  }
  if (targets->target == NULL) {
    printf("\n");
    amap_warn("No readable information in file %s found - was it really generated with nmap's -oM option?\n", filename);
    free(targets);
    targets = NULL;
  }
  if (opt->verbose)
    printf("done\n");
  return targets;
}


// AMAP_SKIP_TRANSLATE //
char *amap_skip_translate(int i) {
  switch(i) {
    case 0:
    case 1:
      return "open";
    case 2:
      return "closed";
    case 3:
      return "timeout";
    case 4:
      return "timeout";
    default:
      amap_error("unknown skip value, programmer's error or memory corruption");
  }
  return "";
}


// AMAP_BUILD_TIME //
char *amap_build_time(char *today, int len) {
  time_t t = time(NULL);
  struct tm *time = localtime(&t);
  
  snprintf(today, len, "%d-%02d-%02d %02d:%02d:%02d", time->tm_year + 1900, time->tm_mon + 1, time->tm_mday, time->tm_hour, time->tm_min, time->tm_sec);
  return today;
}


// AMAP_PRINTABLE_BANNER_STRING //
char *amap_printable_banner_string(unsigned char *string, int slen, char *banner, int blen) {
  int i = 0;
  int j = 0;

  if (slen < 1 || string == NULL || banner == NULL || blen < 1)
    return "";
  
  while (i < blen - 2 && j < slen) {
    if (string[j] != ':' && (isprint(string[j]) || isspace(string[j]))) {
      if ((isspace(string[j]) && string[j] != ' ') || string[j] == '\\') {
        banner[i] = '\\';
        i++;
        switch (string[j]) {
          case '\n': banner[i] = 'n'; break;
          case '\r': banner[i] = 'r'; break;
          case '\t': banner[i] = 't'; break;
          case '\v': banner[i] = 'v'; break;
          case '\f': banner[i] = 'f'; break;
          case '\\': banner[i] = '\\'; break;
          default: banner[i] = '?';
        }
        i++;
      } else {
        banner[i] = string[j];
        i++;
      }
    }
    j++;
  }
  banner[i] = 0;
  return banner;
}


// AMAP_BANNER_STRING //
void amap_banner_string(FILE *f, unsigned char *string, int len) {
  int i = 0;
  int j = 0;
  
  if (f == NULL || string == NULL || len < 1)
    return;
  
  while (j == 0 && i < len) {
    if (!isprint(string[i]) && !isspace(string[i]) && string[i] != ':' && string[i] != '"')
      j = 1;
    i++;
  }
  
  if (j) {
    fprintf(f, "0x");
    for (i = 0; i < len; i++) {
      fprintf(f, "%c", string[i] / 16 > 9 ? string[i] / 16 + 87 : string[i] / 16 + 48);
      fprintf(f, "%c", string[i] % 16 > 9 ? string[i] % 16 + 87 : string[i] % 16 + 48);
    }
  } else {
    fprintf(f, "\"");
    for (i = 0; i < len; i++)
      switch(string[i]) {
        case '\n': fprintf(f, "\\n"); break;
        case '\r': fprintf(f, "\\r"); break;
        case '\t': fprintf(f, "\\t"); break;
        case '\v': fprintf(f, "\\v"); break;
        case '\f': fprintf(f, "\\f"); break;
        case '\\': fprintf(f, "\\\\"); break;
        default:   fprintf(f, "%c", string[i]);
      }
    fprintf(f, "\"");
  }
}


// AMAP_DUMP_STRING - partial rip from vh-lib //
void amap_dump_string(FILE *f, unsigned char *string, int length, int width) {
    unsigned char *p = (unsigned char *) string;
    unsigned char lastrow_data[16];
    int rows = length / width;
    int lastrow = length % width;
    int i, j;

    for (i = 0; i < rows; i++) {
        fprintf(f, "%04hx:  ", i * 16);
        for (j = 0; j < width; j++) {
            fprintf(f, "%02x", p[(i * 16) + j]);
            if (j % 2 == 1)
                fprintf(f, " ");
        }
        fprintf(f, "   [ ");
        for (j = 0; j < width; j++) {
            if (isprint(p[(i * 16) + j]))
                fprintf(f, "%c", p[(i * 16) + j]);
            else
                fprintf(f, ".");
        }
        fprintf(f, " ]\n");
    }
    if (lastrow > 0) {
        memset(lastrow_data, 0, sizeof(lastrow_data));
        memcpy(lastrow_data, p + length - lastrow, lastrow);
        fprintf(f, "%04hx:  ", i * 16);
        for (j = 0; j < lastrow; j++) {
            fprintf(f, "%02x", p[(i * 16) + j]);
            if (j % 2 == 1)
                fprintf(f, " ");
        }
        while(j < width) {
            fprintf(f, "  ");
            if (j % 2 == 1)
                fprintf(f, " ");
            j++;
        }
        fprintf(f, "   [ ");
        for (j = 0; j < lastrow; j++) {
            if (isprint(p[(i * 16) + j]))
                fprintf(f, "%c", p[(i * 16) + j]);
            else
                fprintf(f, ".");
        }
        while(j < width) {
            fprintf(f, " ");
            j++;
        }
        fprintf(f, " ]\n");
    }
}


// AMAP_LOOKUP_ID //
int amap_lookup_id(amap_struct_identifications *ids, char *id) {
  while (ids != NULL) {
    if (strcmp(ids->id, id) == 0)
      return 1;
    ids = (amap_struct_identifications*) ids->next;
  }
  return 0;
}


// AMAP_ADD_ID //
void amap_add_id(amap_struct_ports *port, char *id) {
  amap_struct_identifications *ids = port->ids;
  if (port->ids == NULL) {
    if ((ids = port->ids = malloc(sizeof(amap_struct_identifications))) == NULL)
      amap_error("malloc failed");
  } else {
    while (ids->next != NULL)
      ids = (amap_struct_identifications*) ids->next;
    if ((/*(char *)*/ ids->next = malloc(sizeof(amap_struct_identifications))) == NULL)
      amap_error("malloc failed");
    ids = (amap_struct_identifications*) ids->next;
  }
  ids->next = NULL;
  ids->id = amap_strdup(id);
}


// AMAP_LOOKUP_TRIGGERPTR //
int amap_lookup_triggerptr(amap_struct_triggerptr *triggerptr, char *id) {
  while (triggerptr != NULL) {
    if (strcmp(triggerptr->trigger, id) == 0)
      return 1;
    triggerptr = (amap_struct_triggerptr*) triggerptr->next;
  }
  return 0;
}


// AMAP_READ_RESPONSES //
void amap_read_responses(amap_struct_coms *coms, amap_struct_responses *responses, amap_struct_scaninfo *scaninfo, amap_struct_options *opt) {
  amap_struct_responses *response;
  unsigned char buf[AMAP_BUFSIZE];
  time_t t;
  int len = 1;
  int i;
  int ii;
  int found;
  int offsets[16];
  char banner[256];
  char info[AMAP_MAX_ID_LENGTH + 16];

  // for every active connection we check for responses
  if (opt->verbose > 3)
    printf("DEBUG: entering amap_read_responses\n");
  for (i = 0; i < scaninfo->tasks; i++) {
    if (len > 0)
      memset(buf, 0, sizeof(buf));
    errno = 0;
    found = 0;
    if (coms[i].active == AMAP_CONNECT_ACTIVE && coms[i].socket != -1) {
      if (coms[i].ssl_enabled) {
#ifdef OPENSSL
        if (SSL_pending(coms[i].ssl_socket) > 0)
          len = SSL_read(coms[i].ssl_socket, buf, sizeof(buf));
        else
          len = 0;
#endif
      } else {
        len = recv(coms[i].socket, buf, sizeof(buf), 0);
      }
      if (len < 0 && opt->portscanner && errno != 0) {
        if (errno == ECONNREFUSED) {
          if (coms[i].port->skip < 1 && opt->verbose && opt->quiet == 0)
            if (coms[i].target != NULL)
              amap_warn("Could not connect to %s%s%s:%d/%s, disabling port",opt->ipv6 ? "[" : "", coms[i].target->target,opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          coms[i].port->skip = 2;
          shutdown(coms[i].socket, SHUT_RDWR);
          close(coms[i].socket);
          memset(&coms[i], 0, sizeof(amap_struct_coms));
          scaninfo->running--;
        } else 
          if (errno != EAGAIN) { // EAGAIN
            if (coms[i].port->skip < 1 && opt->verbose && opt->quiet == 0)
              if (coms[i].target != NULL)
                amap_warn("Could not connect to %s:%d/%s, disabling port, unknown error: %d", coms[i].target->target, coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", errno);
          } else {
            if (coms[i].port->ip_prot == AMAP_PROTO_TCP) {
              printf("Port on %s%s%s:%d/%s is OPEN\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
              if (opt->logfile != NULL) {
                if (opt->machine_readable)
                  fprintf(opt->logfile, "%s%s%s:%d:%s:open::%s::\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", AMAP_UFO);
                else
                  fprintf(opt->logfile, "Port on %s%s%s:%d/%s is OPEN\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
              }
              coms[i].port->skip = 1;
              memset(&coms[i], 0, sizeof(amap_struct_coms));
              scaninfo->running--;
            }
          }
      }
      // oh yeah, we received data!
      if (len > 0 && opt->banner_only) {
        printf("Banner on %s%s%s:%d/%s : %s\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", amap_printable_banner_string((char *)buf, len, banner, sizeof(banner)));
        if (opt->logfile != NULL) {
          if (opt->machine_readable) {
            fprintf(opt->logfile, "%s%s%s:%d:%s:%s::%s:%s:", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", amap_skip_translate(coms[i].port->skip), AMAP_UFO, amap_printable_banner_string((char *)buf, len, banner, sizeof(banner)));
            amap_banner_string(opt->logfile, buf, len);
            fprintf(opt->logfile, "\n");
          } else
            fprintf(opt->logfile, "Banner on %s%s%s:%d/%s : %s\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", amap_printable_banner_string((char *)buf, len, banner, sizeof(banner)));
        }
        coms[i].port->skip = 1;
#ifdef OPENSSL
        if (coms[i].ssl_enabled)
          SSL_shutdown(coms[i].ssl_socket);
#endif
        shutdown(coms[i].socket, SHUT_RDWR);
        close(coms[i].socket);
        memset(&coms[i], 0, sizeof(amap_struct_coms));
        scaninfo->running--;
      }
      if (len > 0 && opt->banner_only == 0 && opt->portscanner == 0) {
        coms[i].response_length = len;
        memcpy(coms[i].response, buf, len);
        if (scaninfo->scanmode != AMAP_SCANMODE_RPC) {
          found = 0;
          response = (amap_struct_responses*) responses;
          // match the received data to our response database
/* when is a response matched?
 - when option one_is_enough (-1) is enabled and no other response matched so far
 - if the min/max values of the response length are in range that of the response id
 - if the ip protocol is matching that of the response id
 - if the id is not already identified (no doubles)
 - if the trigger is matching the trigger definition in the response id
 - if the regex matches the response
 */
          while (response != NULL) {
            if ((opt->one_is_enough == 0 || found == 0) && amap_lookup_id(coms[i].port->ids, "echo") == 0) {
              if (len >= response->min_length && len <= response->max_length && (response->ip_prot == AMAP_PROTO_BOTH || response->ip_prot == coms[i].port->ip_prot)
                  && amap_lookup_id(coms[i].port->ids, response->id) == 0 && (response->triggerptr == NULL || amap_lookup_triggerptr(response->triggerptr, coms[i].trigger->id) == 1)) {
                if (pcre_exec(response->pattern, response->hints, (char *)buf, len, 0, 0, offsets, sizeof(offsets)) >= 0) {
                  found++;
                  amap_add_id(coms[i].port, response->id);
                  if (strcmp(response->id, "ssl") == 0 || strncmp(response->id, "ssl-", 4) == 0)
                    coms[i].port->ssl = 1;
                  if (strcmp(response->id, "rpc") == 0 || strncmp(response->id, "rpc-", 4) == 0)
                    coms[i].port->rpc = 1;
                  if (opt->verbose)
                    snprintf(info, sizeof(info), "(by trigger %s) ", coms[i].trigger->id);
                  else
                    info[0] = 0;
                  if (opt->logfile != NULL) {
                    if (opt->machine_readable) {
                      fprintf(opt->logfile, "%s%s%s:%d:%s:%s:%s:%s:%s:", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", amap_skip_translate(coms[i].port->skip), coms[i].ssl_enabled ? "SSL" : "", response->id, amap_printable_banner_string((char *)coms[i].response, coms[i].response_length, banner, sizeof(banner)));
                      amap_banner_string(opt->logfile, coms[i].response, coms[i].response_length);
                      fprintf(opt->logfile, "\n");
                    } else {
                      fprintf(opt->logfile, "Protocol on %s%s%s:%d/%s%s%smatches %s", opt->ipv6 ? "]" : "", coms[i].target->target, opt->ipv6 ? "[" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", coms[i].ssl_enabled ? " over SSL " : " ", info, response->id);
                      if (opt->banner) 
                        fprintf(opt->logfile, " - banner: %s\n", amap_printable_banner_string((char *)coms[i].response, coms[i].response_length, banner, sizeof(banner)));
                      else
                        fprintf(opt->logfile, "\n");
                      if (opt->dump_all) {
                        snprintf(info, sizeof(info), "(by trigger %s)", coms[i].trigger->id);
                        fprintf(opt->logfile, "Identified response from %s%s%s:%d/%s%s%s:\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", coms[i].ssl_enabled ? " over SSL " : " ", info);
                        amap_dump_string(opt->logfile, coms[i].response, coms[i].response_length, 16);
                      }
                    }
                  }
                  printf("Protocol on %s%s%s:%d/%s%s%smatches %s", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", coms[i].ssl_enabled ? " over SSL " : " ", info, response->id);
                  if (opt->banner) 
                    printf(" - banner: %s\n", amap_printable_banner_string((char *)coms[i].response, coms[i].response_length, banner, sizeof(banner)));
                  else
                    printf("\n");
                  if (opt->dump_all) {
                    snprintf(info, sizeof(info), "(by trigger %s)", coms[i].trigger->id);
                    printf("Dump of identified response from %s%s%s:%d/%s%s%s:\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", coms[i].ssl_enabled ? " over SSL " : " ", info);
                    amap_dump_string(stdout, coms[i].response, coms[i].response_length, 16);
                  }
                }
              }
            }
            response = (amap_struct_responses*) response->next;
          }
          // if !found then now response matched the received data, report this
          //                opt->dump_all ||
          if (found < 1 && ( (coms[i].port->unknown_response == NULL && coms[i].port->ids == NULL))) {
            //if (opt->verbose)
              snprintf(info, sizeof(info), "(by trigger %s) ", coms[i].trigger->id);
            //else
            //  info[0] = 0;
            if (opt->logfile != NULL && !opt->machine_readable) {
              fprintf(opt->logfile, "Unrecognized response from %s%s%s:%d/%s%s%sreceived.\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", coms[i].ssl_enabled ? " over SSL " : " ", info);
              if (opt->dump_unidentified) {
                fprintf(opt->logfile, "Please send output + name of the application to %s:\n", AMAP_EMAIL);
                amap_dump_string(opt->logfile, coms[i].response, coms[i].response_length, 16);
              }
            }
            printf("Unrecognized response from %s%s%s:%d/%s%s%sreceived.\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", coms[i].ssl_enabled ? " over SSL " : " ", info);
            if (opt->dump_unidentified) {
              printf("Please send this output and the name of the application to %s:\n", AMAP_EMAIL);
              amap_dump_string(stdout, coms[i].response, coms[i].response_length, 16);
            }
            coms[i].port->unknown_response = (unsigned char *)amap_memdup((char *)coms[i].response, coms[i].response_length);
            coms[i].port->unknown_response_length = coms[i].response_length;
          }
          // now shutdown the connection
#ifdef OPENSSL
          if (coms[i].ssl_enabled)
            SSL_shutdown(coms[i].ssl_socket);
#endif
          shutdown(coms[i].socket, SHUT_RDWR);
          close(coms[i].socket);
          memset(&coms[i], 0, sizeof(amap_struct_coms));
          scaninfo->running--;
        } else { // RPC response handling - dont tear it down, we will reuse it
          if (coms[i].response_length == 32 || coms[i].response_length == 36) {
            strcpy(banner, "rpc-");
            strcat(banner, coms[i].trigger->id);
            strcat(banner, "-v");
            ii = strlen(banner);
            banner[ii] = (char) coms[i].response[coms[i].response_length - 1] + 48;
            banner[ii+1] = 0;
            amap_add_id(coms[i].port, banner);
            if (opt->logfile != NULL) {
              if (opt->machine_readable) {
                fprintf(opt->logfile, "%s%s%s:%d:%s:%s:%s:%s:%s:", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", amap_skip_translate(coms[i].port->skip), coms[i].ssl_enabled ? "SSL" : "", coms[i].port->ids->id, amap_printable_banner_string((char *)coms[i].response, coms[i].response_length, banner, sizeof(banner)));
                amap_banner_string(opt->logfile, coms[i].response, coms[i].response_length);
                fprintf(opt->logfile, "\n");
              } else
                fprintf(opt->logfile, "Protocol on %s%s%s:%d/%s%smatches %s\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", coms[i].ssl_enabled ? " over SSL " : " ", coms[i].port->ids->id);
            }
            printf("Protocol on %s%s%s:%d/%s%smatches %s\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", coms[i].ssl_enabled ? " over SSL " : " ", coms[i].port->ids->id);
            coms[i].port->skip = 1;
#ifdef OPENSSL
            if (coms[i].ssl_enabled)
              SSL_shutdown(coms[i].ssl_socket);
#endif
            shutdown(coms[i].socket, SHUT_RDWR);
            close(coms[i].socket);
            memset(&coms[i], 0, sizeof(amap_struct_coms));
            scaninfo->running--;
          } else {
            coms[i].active = AMAP_CONNECT_REUSABLE;
            if (opt->verbose > 2)
              printf("DEBUG: response from socket %d, length %d\n", coms[i].socket, coms[i].response_length);
          }
        }
      } else {
        if (opt->portscanner == 0) {
          // hmm no response yet - but maybe its udp and it reported "port closed" via ICMP?
          if (errno == ECONNREFUSED) {
            if (coms[i].port->skip < 1 && (opt->portscanner == 0 || opt->verbose) && opt->quiet == 0)
              amap_warn("Could not connect to %s:%d/%s, disabling port", coms[i].target->target, coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
            coms[i].port->skip = 2;
            shutdown(coms[i].socket, SHUT_RDWR);
            close(coms[i].socket);
            memset(&coms[i], 0, sizeof(amap_struct_coms));
            scaninfo->running--;
          } else {
            // and finally: shutdown the port after connection lifetime reaches the defined timeout
            t = time(NULL);
            if ((t - coms[i].timer) > opt->timeout_response) {
#ifdef OPENSSL
              if (coms[i].ssl_enabled)
                SSL_shutdown(coms[i].ssl_socket);
#endif
              shutdown(coms[i].socket, SHUT_RDWR);
              close(coms[i].socket);
              memset(&coms[i], 0, sizeof(amap_struct_coms));
              scaninfo->running--;
            }
          }
        } else { // portscan mode, and port is still active (no ICMP unreachable or RST received)
          if (coms[i].active == AMAP_CONNECT_ACTIVE) { // has the timer become old?
            t = time(NULL);
            if ((t - coms[i].timer) > opt->timeout_response) {
              shutdown(coms[i].socket, SHUT_RDWR);
              close(coms[i].socket);
              coms[i].active = AMAP_CONNECT_RETRY; // retry connection until -C value. this prevents false positives
              coms[i].ssl_enabled = 0;
              scaninfo->running--;
            }
          }
        }
      }
    }
  }
  if (opt->verbose > 3)
    printf("DEBUG: leaving amap_read_responses\n");
}


// AMAP_CHECK_CONNECTS //
void amap_check_connects(amap_struct_coms *coms, amap_struct_scaninfo *scaninfo, amap_struct_options *opt, char *rpc_ptr) {
  struct timeval tv;
  fd_set rfd, wfd;
  int i, ii, fck, res, error;
  socklen_t error_len = sizeof(error);
  socklen_t sock_len = sizeof(struct sockaddr);
  int maxfd = -1;
  char *ptr;
  long int *j;
  time_t t;
#ifdef OPENSSL
  int err;
  SSL *ssl;
  SSL_CTX *sslContext;
#endif

  tv.tv_sec = 0;
  tv.tv_usec = 0;

  if (opt->verbose > 3)
    printf("DEBUG: entering amap_check_connects\n");
  
  // #1 : check for finished connects
/**/
// variant 1
  FD_ZERO(&rfd);
  for (i = 0; i < scaninfo->tasks; i++)
    if (coms[i].active == AMAP_CONNECT_INPROGRESS) {
      FD_SET(coms[i].socket, &rfd);
      if (coms[i].socket > maxfd)
        maxfd = coms[i].socket;
    }
  wfd = rfd;
  if ((res = select(maxfd + 1, &rfd, &wfd, NULL, &tv)) > 0) { // something happened with the socket
    for (i = 0; i < scaninfo->tasks; i++)
      if (FD_ISSET(coms[i].socket, &rfd) || FD_ISSET(coms[i].socket, &wfd)) {
      // somethings here ...
        error = 0;
        if (getsockopt(coms[i].socket, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&error_len) < 0 || error != 0) {
          if (coms[i].port->skip < 1 && opt->portscanner != 1 && opt->verbose && opt->quiet == 0)
            amap_warn("Could not connect (unreachable) to %s%s%s:%d/%s, disabling port (EUNKN)", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          coms[i].port->skip = 2;
          close(coms[i].socket);
          memset(&coms[i], 0, sizeof(amap_struct_coms));
          scaninfo->running--;
        } else {
          if (opt->verbose > 2)
            printf("DEBUG: socket %d to %s%s%s:%d/%s became READY\n", coms[i].socket, opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          coms[i].active = AMAP_CONNECT_READY;
        }
      // until here
      }
   }
/**/
// variant 2
/*
  for (i = 0; i < scaninfo->tasks; i++) {
    if (coms[i].active == AMAP_CONNECT_INPROGRESS) {
      FD_ZERO(&rfd);
      FD_SET(coms[i].socket, &rfd);
      wfd = rfd;
      if ((res = select(coms[i].socket + 1, &rfd, &wfd, NULL, &tv)) > 0) { // something happened with the socket
        // somethings here ...
//... copy from above ...
        error = 0;
        if (getsockopt(coms[i].socket, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0 || error != 0) {
          if (coms[i].port->skip < 1 && (opt->portscanner == 0 || opt->verbose) && opt->quiet == 0)
            amap_warn("Could not connect (unreachable) to %s:%d/%s, disabling port", coms[i].target->target, coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          coms[i].port->skip = 2;
          close(coms[i].socket);
          memset(&coms[i], 0, sizeof(amap_struct_coms));
          scaninfo->running--;
        } else {
          if (opt->verbose > 2)
            printf("DEBUG: socket %d to %s:%d/%s became READY\n", coms[i].socket, coms[i].target->target, coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          coms[i].active = AMAP_CONNECT_READY;
        }
//... delete until here
      }
    }
  }
*/

  // #2 : check timeouts on inprogress connects
  
  t = time(NULL);
  for (i = 0; i < scaninfo->tasks; i++) {
    if (coms[i].active == AMAP_CONNECT_INPROGRESS) {
      if ((t - coms[i].timer) > opt->timeout_connect + 1) {
        if (opt->verbose > 2) {
#ifdef AF_INET6
          if (opt->ipv6) {
            struct sockaddr_in6 sa;
            int t = sizeof(sa);
            getsockname(coms[i].socket, (struct sockaddr*)&sa, (socklen_t *)&t);
            printf("DEBUG: socket %d/%d to %s%s%s:%d/%s is now RETRY CONNECT\n", coms[i].socket, htons(sa.sin6_port), opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          } else
#endif
          {
            struct sockaddr_in sa;
            int t = sizeof(sa);
            getsockname(coms[i].socket, (struct sockaddr*)&sa, (socklen_t *)&t);
            printf("DEBUG: socket %d/%d to %s%s%s:%d/%s is now RETRY CONNECT\n", coms[i].socket, htons(sa.sin_port), opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          }
        }
        shutdown(coms[i].socket, SHUT_RDWR);
        close(coms[i].socket);
        coms[i].active = AMAP_CONNECT_RETRY;
        coms[i].ssl_enabled = 0;
      }
    }
  }
  
  // #3 : retry connections we have to

  for (i = 0; i < scaninfo->tasks; i++)
    if (coms[i].active == AMAP_CONNECT_RETRY) {
      coms[i].retry++;
      coms[i].timer = time(NULL);
      if (coms[i].retry >= opt->max_connect_retries) {
        if (coms[i].port->skip < 1 && (opt->portscanner == 0 || opt->verbose))
          amap_warn("Could not connect (timeout %d, retries %d) to %s:%d/%s, disabling port", opt->timeout_connect, opt->max_connect_retries, coms[i].target->target, coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
        coms[i].port->skip = 3;
        memset(&coms[i], 0, sizeof(amap_struct_coms));
        scaninfo->running--;
      } else {
        errno = 0;
        if (coms[i].port->ip_prot == AMAP_PROTO_TCP)
          while ((coms[i].socket = socket(glob_af_inet, SOCK_STREAM, IPPROTO_TCP)) == 0);
        else
          while ((coms[i].socket = socket(glob_af_inet, SOCK_DGRAM, IPPROTO_UDP)) == 0);
        if (coms[i].socket < 0)
          amap_error("socket creation failed");
        res = 1;
        setsockopt(coms[i].socket, SOL_SOCKET, SO_REUSEADDR, &res, sizeof(res));
        fcntl(coms[i].socket, F_SETFL, O_NONBLOCK);
printf("this connect\n");
        if ((res = connect(coms[i].socket, (struct sockaddr *) coms[i].sockaddr, coms[i].sockaddr_len)) >= 0)
          coms[i].active = AMAP_CONNECT_READY;
        else {
          if (errno == EINPROGRESS)
            coms[i].active = AMAP_CONNECT_INPROGRESS;
          else {
            if (coms[i].port->skip < 1 && (opt->portscanner == 0 || opt->verbose) && opt->quiet == 0)
              amap_warn("Could not connect (unreachable) to %s:%d/%s, disabling port", coms[i].target->target, coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
            coms[i].port->skip = 2;
            close(coms[i].socket);
            memset(&coms[i], 0, sizeof(amap_struct_coms));
            scaninfo->running--;
          }
        }
        if (opt->verbose > 2) {
          int dport;
#ifdef AF_INET6
          if (opt->ipv6) {
            struct sockaddr_in6 sa;
            int t = sizeof(sa);
            getpeername(coms[i].socket, (struct sockaddr*)&sa, (socklen_t *)&t);
            dport = htons(sa.sin6_port);
            getsockname(coms[i].socket, (struct sockaddr*)&sa, (socklen_t *)&t);
            printf("DEBUG: socket %d/%d->%d to %s%s%s:%d/%s became RETRY CONNECT\n", coms[i].socket, htons(sa.sin6_port), dport, opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          } else
#endif
          {
            struct sockaddr_in sa;
            int t = sizeof(sa);
            getpeername(coms[i].socket, (struct sockaddr*)&sa, (socklen_t *)&t);
            dport = htons(sa.sin_port);
            getsockname(coms[i].socket, (struct sockaddr*)&sa, (socklen_t *)&t);
            printf("DEBUG: socket %d/%d->%d to %s%s%s:%d/%s became RETRY CONNECT\n", coms[i].socket, htons(sa.sin_port), dport, opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          }
        }
      }
    }

  // #4 : if we run in portscan mode, just report READY sockets and terminate connections

  for (i = 0; i < scaninfo->tasks; i++)
    if (coms[i].active == AMAP_CONNECT_READY && opt->portscanner == 1) {
      if (coms[i].port->ip_prot == AMAP_PROTO_TCP) {
        shutdown(coms[i].socket, SHUT_RDWR);
        close(coms[i].socket);
        printf("Port on %s%s%s:%d/%s is OPEN\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
        if (opt->logfile != NULL) {
          if (opt->machine_readable)
            fprintf(opt->logfile, "%s%s%s:%d:%s:open::%s::\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", AMAP_UFO);
          else
            fprintf(opt->logfile, "Port on %s%s%s:%d/%s is OPEN\n", opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
        }
        coms[i].port->skip = 1;
        memset(&coms[i], 0, sizeof(amap_struct_coms));
        scaninfo->running--;
      } else {
        fck=write(coms[i].socket, coms[i].trigger->trigger, coms[i].trigger->trigger_length);
        coms[i].active = AMAP_CONNECT_ACTIVE;
        coms[i].timer = time(NULL);
      }
    }


  // #5 : check for connections which are active and send the triggers
  
  for (i = 0; i < scaninfo->tasks; i++)
    if (coms[i].active == AMAP_CONNECT_READY) {
      if (opt->banner_only == 0) {
#ifdef OPENSSL
        if (coms[i].port->ssl && scaninfo->scanmode != AMAP_SCANMODE_DEFAULT) {
          if ((sslContext = SSL_CTX_new(SSLv23_method())) == NULL) {
            err = ERR_get_error();
            amap_error("ssl connection preparation failed: ", ERR_error_string(err, NULL));
          }
          SSL_CTX_set_options(sslContext, SSL_OP_ALL);
          (void) SSL_CTX_set_default_verify_paths(sslContext);
          SSL_CTX_set_tmp_rsa_callback(sslContext, amap_ssl_temp_rsa_cb);
          SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
          if ((ssl = SSL_new(sslContext)) == NULL)
            amap_error("could not prepare SSL context, you've got severe memory problems here");
          SSL_set_fd(ssl, coms[i].socket);
          fcntl(coms[i].socket, F_SETFL, fcntl(coms[i].socket, F_GETFL) &~ O_NONBLOCK);
          if ((error = SSL_connect(ssl)) < 0) {
            if (opt->verbose > 2)
              printf("SSL connection failed\n");
            shutdown(coms[i].socket, SHUT_RDWR);
            close(coms[i].socket);
            coms[i].active = AMAP_CONNECT_RETRY;
          } else {
            if (opt->verbose > 2)
              printf("SSL connection succeeded\n");
            coms[i].ssl_socket = ssl;
            coms[i].active = AMAP_CONNECT_READY;
            coms[i].ssl_enabled = 1;
          }
        }
#endif
        if (coms[i].active == AMAP_CONNECT_READY) {
          if (scaninfo->scanmode != AMAP_SCANMODE_RPC) {
            if (coms[i].ssl_enabled) {
#ifdef OPENSSL
              SSL_write(coms[i].ssl_socket, coms[i].trigger->trigger, coms[i].trigger->trigger_length);
#endif
            } else {
              fck = write(coms[i].socket, coms[i].trigger->trigger, coms[i].trigger->trigger_length);
            }
          } else {
            // here we build the RPC packet and send it off
            memset(rpc_ptr, 0, AMAP_BUFSIZE);
            if (coms[i].port->ip_prot == AMAP_PROTO_TCP) {
              rpc_ptr[0] = 128;
              rpc_ptr[3] = 40;
              ptr = rpc_ptr + 4;
              ii = 44;
            } else {
              ptr = rpc_ptr;
              ii = 40;
            }
            j = (long int*) ptr;
            *j = htonl(strtol(coms[i].trigger->trigger, (char **) NULL, 10));
            j = (long int *) (ptr + 12);
            ptr[11] = 2;
            *j = htonl(strtol(coms[i].trigger->trigger, (char **) NULL, 10));
            ptr[17] = 7;
            ptr[18] = 120;
            ptr[19] = 74;
            if (coms[i].ssl_enabled) {
#ifdef OPENSSL
              SSL_write(coms[i].ssl_socket, rpc_ptr, ii);
#endif
            } else {
              fck = write(coms[i].socket, rpc_ptr, ii);
            }
          }
          if (opt->verbose > 2) {
            int dport;
#ifdef AF_INET6
            if (opt->ipv6) {
              struct sockaddr_in6 sa;
              int t = sizeof(sa);
              getpeername(coms[i].socket, (struct sockaddr*)&sa, (socklen_t *)&t);
              dport = htons(sa.sin6_port);
              getsockname(coms[i].socket, (struct sockaddr*)&sa, (socklen_t *)&t);
              printf("DEBUG: socket %d/%d->%d to %s%s%s:%d/%s became ACTIVE (trigger %s send)\n", coms[i].socket, ntohs(sa.sin6_port), dport, opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", coms[i].trigger->id);
            } else
#endif
            {
              struct sockaddr_in sa;
              int t = sizeof(sa);
              getpeername(coms[i].socket, (struct sockaddr*)&sa, (socklen_t *)&t);
              dport = htons(sa.sin_port);
              getsockname(coms[i].socket, (struct sockaddr*)&sa, (socklen_t *)&t);
              printf("DEBUG: socket %d/%d->%d to %s%s%s:%d/%s became ACTIVE (trigger %s send)\n", coms[i].socket, ntohs(sa.sin_port), dport, opt->ipv6 ? "[" : "", coms[i].target->target, opt->ipv6 ? "]" : "", coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", coms[i].trigger->id);
            }
          }
          coms[i].active = AMAP_CONNECT_ACTIVE;
          coms[i].timer = time(NULL);
        }
      } else {
        if (coms[i].port->ip_prot == AMAP_PROTO_UDP)
          fck = write(coms[i].socket, coms[i].trigger->trigger, coms[i].trigger->trigger_length);
        coms[i].active = AMAP_CONNECT_ACTIVE;
        coms[i].timer = time(NULL);
      }
    }      

  if (opt->verbose > 3)
    printf("DEBUG: leaving amap_check_connects\n");
}


// AMAP_SCAN //
int amap_scan(int scanmode, amap_struct_targets *targets, amap_struct_triggers *triggers, amap_struct_responses *responses, amap_struct_options *opt) {
  amap_struct_triggers *trigger;
  amap_struct_targets *target = (amap_struct_targets*) targets;
  amap_struct_ports *port;
  amap_struct_identifications *ids;
  amap_struct_identifications *ids_save;
  amap_struct_coms coms[AMAP_MAX_TASKS];
  amap_struct_scaninfo scaninfo;
//  struct sockaddr_in target_in;
//  struct in_addr target_addr;
  char *rpc_ptr = NULL;
  int todo = 0;
  int ready_for_next;
  int i;
  int ii;
  int s;
  int ret;

  memset(coms, 0, sizeof(coms));
  scaninfo.scanmode = scanmode;
  scaninfo.tasks = opt->tasks;
  scaninfo.running = 0;

  // count ports to identify
  while (target != NULL) {
    port = (amap_struct_ports*) target->ports;
    while (port != NULL) {
      if (port->skip == 4)
        port->skip = 0;
      if (port->skip == 0
#ifndef OPENSSL
          && (port->ssl == 0 || scanmode == AMAP_SCANMODE_DEFAULT)
#endif
          && (scanmode == AMAP_SCANMODE_DEFAULT || (scanmode == AMAP_SCANMODE_SSL && port->ssl) || (scanmode == AMAP_SCANMODE_RPC && port->rpc))) {
        if (opt->portscanner || opt->banner_only)
          todo++;
        else {
          trigger = (amap_struct_triggers*) triggers;
          while (trigger != NULL) {
            if ((trigger->ip_prot == AMAP_PROTO_BOTH || trigger->ip_prot == port->ip_prot)
                && (trigger->harmful == 0 || opt->harmful == 1))
              todo++;
            trigger = (amap_struct_triggers*) trigger->next;
          }
        }
        if (scanmode != AMAP_SCANMODE_DEFAULT) {
          if (port->ids != NULL) {
            while (port->ids->next != NULL) {
              ids = port->ids;
              while (ids->next != NULL) {
                ids_save = ids;
                ids = (amap_struct_identifications*) ids->next;
              }
              free(ids);
              ids_save->next = NULL;
            }
            free(port->ids);
            port->ids = NULL;
          }
        }
      }
      port = (amap_struct_ports*) port->next;
    }
    target = (amap_struct_targets*) target->next;
  }
  if (todo == 0)
    return todo;
  if (todo < scaninfo.tasks)
    scaninfo.tasks = todo;

  if (opt->verbose) {
    printf("Total amount of tasks to perform in ");
    switch(scanmode) {
      case AMAP_SCANMODE_DEFAULT: printf("plain"); break;
      case AMAP_SCANMODE_SSL: printf("SSL"); break;
      case AMAP_SCANMODE_RPC: printf("RPC"); break;
      default: amap_error("unknown scanmode - memory must be corrupted");
    }
    printf(" connect mode: %d\n", todo);
  }

  // prepare RPC mode stuff
  if (scanmode == AMAP_SCANMODE_RPC) {
    opt->one_is_enough = 1;
    if ((rpc_ptr = malloc(AMAP_BUFSIZE)) == NULL)
      amap_error("malloc failed");
  }

  // prepare SSL mode stuff
  if (scanmode == AMAP_SCANMODE_SSL) {
#ifndef OPENSSL
    amap_warn("amap is not compiled with SSL support, probing SSL ports not possible");
    return 0;
#else
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
#endif
  }

  // resetting main value and then lets go!
  trigger = (amap_struct_triggers*) triggers;

  // here the scanning really starts
  while (trigger != NULL || opt->portscanner == 1) {
    target = (amap_struct_targets*) targets;
    if (strcmp(target->target, "0.0.0.0") != 0 && (opt->harmful == 1 || trigger->harmful == 0))
      while (target != NULL) {
        port = (amap_struct_ports*) target->ports;
        while (port != NULL) {
//printf("probing port: %d/%d skip:%d id:%s    trigger: %s/%d\n",port->port,port->ip_prot,port->skip,port->ids == NULL ? "(null)" : port->ids,trigger->id == NULL ? "(null)" : port->ids->id,trigger->id,trigger->ip_prot);
          if (port->skip == 0 && (opt->one_is_enough == 0 || port->ids == NULL)
#ifndef OPENSSL
              && (port->ssl == 0 || scanmode != AMAP_SCANMODE_RPC)
#endif
              && (
                  (opt->portscanner || opt->banner_only) ||
                  ( (trigger->ip_prot == AMAP_PROTO_BOTH || trigger->ip_prot == port->ip_prot)
                    && (scaninfo.scanmode == AMAP_SCANMODE_DEFAULT || (scaninfo.scanmode == AMAP_SCANMODE_SSL && port->ssl) || (scaninfo.scanmode == AMAP_SCANMODE_RPC && port->rpc))))
          ) {
            if (opt->verbose > 1)
              printf("DEBUG: probing now trigger %s (%d) on %s%s%s:%d/%s\n", trigger->id, trigger->ip_prot, opt->ipv6 ? "[" : "", target->target, opt->ipv6 ? "]" : "", port->port, port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
            ready_for_next = 0;

            // if we do RPC scanning, check if there is a reusable connection to the target port
            if (scaninfo.scanmode == AMAP_SCANMODE_RPC)
              for (i = 0; i < scaninfo.tasks; i++)
                if (coms[i].active == AMAP_CONNECT_REUSABLE && port == coms[i].port) {
                  ready_for_next = 1;
                  break;
                }
            // try to find a free socket (within our max active connections)
            if (ready_for_next == 0)
              for (i = 0; i < scaninfo.tasks; i++)
                if (coms[i].active == AMAP_CONNECT_NULL) {
                  ready_for_next = 1;
                  break;
                }

            // still none found?
            if (ready_for_next == 0) {
              // if we do rpc scanning, shutdown the next reusable one, otherwise we might block unfinite ...
              if (scaninfo.scanmode == AMAP_SCANMODE_RPC)
                for (i = 0; i < scaninfo.tasks; i++)
                  if (coms[i].active == AMAP_CONNECT_REUSABLE) {
#ifdef OPENSSL
                    if (coms[i].ssl_enabled)
                      SSL_shutdown(coms[i].ssl_socket);
#endif
                    shutdown(coms[i].socket, SHUT_RDWR);
                    close(coms[i].socket);
                    memset(&coms[i], 0, sizeof(amap_struct_coms));
                    ready_for_next = 1;
                    break;
                  }
              // loop until something is free
              while (ready_for_next == 0) {
                amap_check_connects(coms, &scaninfo, opt, rpc_ptr);
                amap_read_responses(coms, responses, &scaninfo, opt);
                for (i = 0; i < scaninfo.tasks; i++)
                  if (coms[i].active == AMAP_CONNECT_NULL || coms[i].active == AMAP_CONNECT_REUSABLE) {
                    if (coms[i].active == AMAP_CONNECT_REUSABLE && port != coms[i].port) {
#ifdef OPENSSL
                      if (coms[i].ssl_enabled)
                        SSL_shutdown(coms[i].ssl_socket);
#endif
                      shutdown(coms[i].socket, SHUT_RDWR);
                      close(coms[i].socket);
                      memset(&coms[i], 0, sizeof(amap_struct_coms));
                    }
                    ready_for_next = 1;
                    break;
                  }
              }
            }
            
            // amap_conn() (part 1)
            if (coms[i].active == AMAP_CONNECT_REUSABLE && port != coms[i].port)
              amap_warn("programming error, lost one socket");
            // if we try an RPC trigger on an already active connection, we reuse it!
            if (coms[i].active == AMAP_CONNECT_REUSABLE && port == coms[i].port) {
              coms[i].active = AMAP_CONNECT_READY;
              coms[i].timer = time(NULL);
              coms[i].trigger = trigger;
              if (opt->verbose > 1)
                printf("DEBUG: Connection reuse on socket %d\n", coms[i].socket);
            } else {
              memset(&coms[i], 0, sizeof(amap_struct_coms));
              coms[i].target = target;
              coms[i].trigger = trigger;
              coms[i].port = port;

              if (coms[i].port->ip_prot == AMAP_PROTO_TCP)
                while ((s = socket(glob_af_inet, SOCK_STREAM, IPPROTO_TCP)) == 0);
              else
                while ((s = socket(glob_af_inet, SOCK_DGRAM, IPPROTO_UDP)) == 0);

              if (s < 0)
                amap_error("socket creation failed");
              else {
#ifdef AF_INET6
                if (opt->ipv6) {
                  glob_sin6.sin6_port = htons((unsigned short int) coms[i].port->port);
                  glob_sin6.sin6_family = glob_af_inet;
                } else
#endif
                {
                  glob_sin.sin_port = htons((unsigned short int) coms[i].port->port);
                  glob_sin.sin_family = glob_af_inet;
                }
#ifndef AF_INET6
                if (inet_aton(coms[i].target->target, (struct in_addr *) glob_addr) <= 0) {
                  amap_warn("inet_aton failed for %s, removing this target from my list completely", coms[i].target->target);
#else
                if (inet_pton(glob_af_inet, coms[i].target->target, glob_addr) < 0) {
                  amap_warn("inet_pton failed for %s, removing this target from my list completely", coms[i].target->target);
#endif
                  strcpy(coms[i].target->target, "0.0.0.0");
                  coms[i].target->ports = NULL;
                  port->next = NULL;
                } else {
#ifdef AF_INET6
                  if (opt->ipv6)
                    memcpy(glob_sin6.sin6_addr.s6_addr, glob_in6.s6_addr, 16);
                  else
#endif
                  glob_sin.sin_addr.s_addr = glob_in.s_addr;
                  ii = 1;
                  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &ii, sizeof(ii));
                  fcntl(s, F_SETFL, O_NONBLOCK);
                  coms[i].timer = time(NULL);
                  coms[i].socket = s;
                  /*(char*)*/ coms[i].sockaddr = (struct sockaddr*) amap_memdup((unsigned char *) glob_sockaddr, glob_sockaddr_len);
                  coms[i].sockaddr_len = glob_sockaddr_len;
                  scaninfo.running++;
                  errno = 0;
                  if ((ret = connect(coms[i].socket, (struct sockaddr *) coms[i].sockaddr, coms[i].sockaddr_len)) >= 0)
                    coms[i].active = AMAP_CONNECT_READY;
                  else {
                    if (errno == EINPROGRESS)
                      coms[i].active = AMAP_CONNECT_INPROGRESS;
                    else {
                      if (coms[i].port->skip < 1 && (opt->portscanner == 0 || opt->verbose) && opt->quiet == 0)
                        amap_warn("Could not connect (unreachable) to %s:%d/%s, disabling port", coms[i].target->target, coms[i].port->port, coms[i].port->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
                      coms[i].port->skip = 2;
                      close(coms[i].socket);
                      memset(&coms[i], 0, sizeof(amap_struct_coms));
                      scaninfo.running--;
                    }
                  }
                }
              }
            }
            amap_check_connects(coms, &scaninfo, opt, rpc_ptr);
            amap_read_responses(coms, responses, &scaninfo, opt);
          }
          port = (amap_struct_ports*) port->next;
        }
        target = (amap_struct_targets*) target->next;
      }
      trigger = (amap_struct_triggers*) trigger->next;
      if (opt->portscanner == 1)
        opt->portscanner = 2;
  }

  if (scaninfo.running > 0) {
    i = 0;
    ii = 1;
    if (opt->one_is_enough) {
      ii = 0;
      target = targets;
      while (target != NULL) {
        port = (amap_struct_ports*) target->ports;
        while (port != NULL) {
          if (port->ids == NULL && port->skip == 0 && (scaninfo.scanmode == AMAP_SCANMODE_DEFAULT || (scaninfo.scanmode == AMAP_SCANMODE_SSL && port->ssl) || (scaninfo.scanmode == AMAP_SCANMODE_RPC && port->rpc)))
            ii++;
          port = (amap_struct_ports*) port->next;
        }
        target = (amap_struct_targets*) target->next;
      }
    }
    if (opt->verbose && ii > 0)
      printf("Waiting for timeout on %d connections ...\n", scaninfo.running);
    if (opt->verbose)
      opt->verbose--;
    while(scaninfo.running != 0 && i < (opt->timeout_connect + opt->timeout_response + 1) * 10 && ii > 0) {
      if (opt->verbose > 3)
        printf("DEBUG: still running: %d\n", scaninfo.running);
      usleep(100000);
      i++;
      amap_check_connects(coms, &scaninfo, opt, rpc_ptr);
      amap_read_responses(coms, responses, &scaninfo, opt);
      if (opt->one_is_enough) {
        ii = 0;
        target = targets;
        while (target != NULL) {
          port = (amap_struct_ports*) target->ports;
          while (port != NULL) {
            if (port->ids == NULL && port->skip == 0 && (scaninfo.scanmode == AMAP_SCANMODE_DEFAULT || (scaninfo.scanmode == AMAP_SCANMODE_SSL && port->ssl) || (scaninfo.scanmode == AMAP_SCANMODE_RPC && port->rpc)))
              ii++;
            port = (amap_struct_ports*) port->next;
          }
          target = (amap_struct_targets*) target->next;
        }
      }
    }
  }

  // shutdown all sockets
  for (i = 0; i < AMAP_MAX_TASKS; i++)
    if (coms[i].active != AMAP_CONNECT_NULL) {
      if (coms[i].port->skip == 0)
        coms[i].port->skip = 4;
#ifdef OPENSSL
      if (coms[i].ssl_enabled)
        SSL_shutdown(coms[i].ssl_socket);
#endif
      shutdown(coms[i].socket, SHUT_RDWR);
      close(coms[i].socket);
    }

  return todo;
}


// AMAP_LIB_LOOKUP_ID //
int amap_lib_lookup_id(char *r[], char *str) {
  int i = 0;

  while (r[i] != NULL) {
    if (strcmp(r[i], str) == 0)
      return 1;
    i++;
  }

  return 0;
}


// AMAP_LIB_IDENTIFY //
char **amap_lib_identify(char *data, int datalen, int proto, amap_struct_responses *responses) {
  static char *result[32] = { "", NULL } ;
  amap_struct_responses *response = responses;
  int offsets[16];
  int found = 0;
  int prot;
  
  if (data == NULL || datalen < 1 || response == NULL)
    return NULL;

  switch(proto) {
    case 0:
        prot = AMAP_PROTO_BOTH;
        break;
    case AMAP_PROTO_TCP:
    case 't':
    case 'T':
        prot = AMAP_PROTO_TCP;
        break;
    case AMAP_PROTO_UDP:
    case 'u':
    case 'U':
        prot = AMAP_PROTO_UDP;
        break;
    default: prot = AMAP_PROTO_BOTH;
  }
  
  while (response != NULL && found < 31) {
    if (datalen >= response->min_length && datalen <= response->max_length
        && (response->ip_prot == AMAP_PROTO_BOTH || prot == AMAP_PROTO_BOTH || prot == response->ip_prot)
        && amap_lib_lookup_id(result, response->id) == 0)
      if (pcre_exec(response->pattern, response->hints, data, datalen, 0, 0, offsets, sizeof(offsets)) >= 0) {
        result[found++] = amap_strdup(response->id);
        result[found] = NULL;
      }
    response = (amap_struct_responses*) response->next;
  }
  
  return result;
}


// AMAP_MAIN_INIT //
amap_struct_options *amap_main_init() {
  static amap_struct_options lopt;
  
  // INITIALISATION //
  memset(&lopt, 0, sizeof(lopt));
  lopt.max_connect_retries = AMAP_MAX_CONNECT_RETRIES;
  lopt.do_scan_ssl = 1;
  lopt.do_scan_rpc = 1;
  lopt.tasks = AMAP_DEFAULT_TASKS;
  lopt.timeout_connect = AMAP_CONNECT_TIME;
  lopt.timeout_response = AMAP_RESPONSE_TIME;
  lopt.harmful = 1;
  lopt.dump_unidentified = 1;
  lopt.cmd_proto = AMAP_PROTO_TCP;
  
  return &lopt;
}


// AMAP_LIB_INIT //
amap_struct_responses *amap_lib_init(char *fn) {
  static amap_struct_responses *response;
  amap_struct_options *opt;
  
  opt = amap_main_init();
// opt->verbose = 1;
  response = read_file_responses(AMAP_FILETYPE_RESPONSES, fn, opt);

  return response;
}


// AMAP_MAIN //
int amap_main(amap_struct_options *opt, int argc, char *argv[]) {
  // VARIABLES //
  amap_struct_responses *responses = NULL;
  amap_struct_triggers  *triggers = NULL;
  amap_struct_triggers  *triggers_rpc = NULL;
  amap_struct_responses *responses_tmp;
  amap_struct_triggers  *trigger_tmp;
  amap_struct_targets   *target_tmp;
  amap_struct_triggerptr *triggerptr_tmp;
  amap_struct_targets   *targets = NULL;
  amap_struct_ports     *port_tmp;
  char today[24];
  char banner[256];
  int  i = 0;
  int  pfrom, pto;
  char *ptr;
  
  (void) setvbuf(stdout, NULL, _IONBF, 0);
  
  // VARIABLES VERIFICATION //
  if ((argc < 2) && (opt->file_nmap == NULL) && (opt->update == 0))
    amap_error("no targets to scan defined");
  if (opt->file_log == NULL && opt->machine_readable)
    amap_error("option -m set, but no logfile defined (-o)");
  if (opt->tasks < 1 || opt->tasks > AMAP_MAX_TASKS)
    amap_error("the connect task option (-c) must be between 1 and %d", AMAP_MAX_TASKS);
  if (opt->timeout_connect < 1 || opt->timeout_connect > 240)
    amap_error("the connect timeout option (-T) must be between 1 and 240, its counted in seconds!");
  if (opt->timeout_response < 1 || opt->timeout_response > 240)
    amap_error("the response timeout option (-t) must be between 1 and 240, its counted in seconds!");

  // ONLINE UPDATE //
  if (opt->update) {
    printf("Running Online Update for fingerprints, connecting to %s\n", AMAP_RESOURCE);
    if (opt->filename == NULL) {
      opt->filename = malloc(strlen(AMAP_PREFIX) + 5 + strlen(AMAP_DEFAULT_FILENAME) + 2);
      strcpy(opt->filename, AMAP_PREFIX);
      strcat(opt->filename, "/etc/");
      strcat(opt->filename, AMAP_DEFAULT_FILENAME);
    }
    opt->file_log = malloc(strlen(opt->filename) + 6);
    strcpy(opt->file_log, opt->filename);
    opt->file_nmap = malloc(strlen(AMAP_RESOURCE) + strlen(opt->file_log) + 16);
    strcpy(opt->file_nmap, "http://");
    strcat(opt->file_nmap, AMAP_RESOURCE);
    strcat(opt->file_nmap, "/");
    strcat(opt->file_nmap, AMAP_DEFAULT_FILENAME);
    strcat(opt->file_log, AMAP_FILETYPE_RESPONSES);
    ptr = malloc(strlen(opt->file_nmap) + 8);
    strcpy(ptr, opt->file_nmap);
    strcat(ptr, AMAP_FILETYPE_RESPONSES);
    amap_webupdate_file(ptr, opt->file_log, 1, 0);
    strcpy(opt->file_log, opt->filename);
    strcat(opt->file_log, AMAP_FILETYPE_TRIGGERS);
    strcpy(ptr, opt->file_nmap);
    strcat(ptr, AMAP_FILETYPE_TRIGGERS);
    amap_webupdate_file(ptr, opt->file_log, 1, 0);
    strcpy(opt->file_log, opt->filename);
    strcat(opt->file_log, AMAP_FILETYPE_RPC);
    strcpy(ptr, opt->file_nmap);
    strcat(ptr, AMAP_FILETYPE_RPC);
    amap_webupdate_file(ptr, opt->file_log, 1, 0);
    printf("Done with Online Update.\n");
    exit(0);
  }
  
  // READING FILES //
  if (opt->file_nmap != NULL)
    targets = read_file_nmap(opt->file_nmap, opt);
  if (opt->portscanner == 0 && opt->banner_only == 0) {
    triggers = read_file_triggers(AMAP_FILETYPE_TRIGGERS, opt->filename, opt);
    responses = read_file_responses(AMAP_FILETYPE_RESPONSES, opt->filename, opt);
    if (opt->do_scan_rpc)
      triggers_rpc = read_file_triggers(AMAP_FILETYPE_RPC, opt->filename, opt);

  // SANITY CHECKS ON FILE DATA //
    responses_tmp = responses;
    while (opt->only_send_trigger == NULL && responses_tmp != NULL) {
      triggerptr_tmp = (amap_struct_triggerptr*) responses_tmp->triggerptr;
      while (triggerptr_tmp != NULL) {
        trigger_tmp = triggers;
        i = 0;
        while (trigger_tmp != NULL && i == 0) {
          if (strcmp(trigger_tmp->id, triggerptr_tmp->trigger) == 0)
            i = 1;
          trigger_tmp = (amap_struct_triggers*) trigger_tmp->next;
        }
        if (i == 0)
          amap_warn("the trigger \"%s\" required in the response id \"%s\" was not found and will therefore never match", triggerptr_tmp->trigger, responses_tmp->id);
        triggerptr_tmp = (amap_struct_triggerptr*) triggerptr_tmp->next;
      }
      responses_tmp = (amap_struct_responses*) responses_tmp->next;
    }
  } else {
    if (( triggers = (amap_struct_triggers*) malloc(sizeof(amap_struct_triggers))) == NULL)
      amap_error("malloc failed");
    triggers->next = NULL;
    triggers->id = strdup("NULL");
    triggers->ports = NULL;
    triggers->harmful = 0;
    triggers->trigger = strdup("");
    triggers->trigger_length = 1;
    triggers->ip_prot = AMAP_PROTO_BOTH;
  }

#ifdef AF_INET6
  if (opt->ipv6) {
    glob_af_inet = AF_INET6;
    glob_sockaddr = (struct sockaddr *) &glob_sin6;
    glob_sockaddr_len = sizeof(glob_sin6);
    glob_addr = (char *) &glob_in6;
    glob_addr_len = sizeof(glob_in6);
  }
  memset(&glob_hints, 0, sizeof(glob_hints));
  glob_hints.ai_family = glob_af_inet;
#endif

  // PROCESSING CMDLINE TARGET OPTIONS //
  if (argc >= 2) {
    struct hostent *ip;
#ifdef AF_INET6
    char out[64];
#endif
    if (inet_addr(argv[0]) == -1) {
#ifndef AF_INET6
      if ((ip = gethostbyname(argv[0])) == NULL)
        amap_error("can not resolve target: %s", argv[0]);
      memcpy(&glob_in, ip->h_addr, ip->h_length);
      argv[0] = inet_ntoa(glob_in);
#else
      if ((glob = getaddrinfo(argv[0], NULL, &glob_hints, &glob_result)) != 0)
        amap_error("can not resolve target (getaddrinfo): %s (%d/%d)", argv[0], glob, errno);
      if ((glob = getnameinfo(glob_result->ai_addr, glob_result->ai_addrlen,
          out, sizeof(out), NULL, 0, NI_NUMERICHOST)) != 0)
        amap_error("can not resolve address (getnameinfo): %s (%d/%d)", argv[0], glob, errno);
      argv[0] = (char *) &out;
#endif
    } 
    if (targets == NULL) { // no nmap input file was loaded
      if ((target_tmp = targets = (amap_struct_targets *) malloc(sizeof(amap_struct_targets))) == NULL)
        amap_error("malloc failed");
      memset(target_tmp, 0, sizeof(amap_struct_targets));
      if (index(argv[0], ':') == NULL)
        target_tmp->target = argv[0];
      else {
        target_tmp->target = malloc(strlen(argv[0]) + 3);
        strcpy(target_tmp->target, argv[0]);
      }
      if (opt->verbose > 1)
        printf("DEBUG: Loading ports for %s ... ", target_tmp->target);
      if ((port_tmp = target_tmp->ports = (amap_struct_ports *) malloc(sizeof(amap_struct_ports))) == NULL)
        amap_error("malloc failed");
      memset(port_tmp, 0, sizeof(amap_struct_ports));
      port_tmp = amap_add_port_string(port_tmp, argv[1], opt->cmd_proto, opt);
      i = 2;
      while (i < argc) {
        if ((/*(amap_struct_ports *)*/ port_tmp->next = /*(amap_struct_ports *)*/ malloc(sizeof(amap_struct_ports))) == NULL)
          amap_error("malloc failed");
        port_tmp = (amap_struct_ports *) port_tmp->next;
        memset(port_tmp, 0, sizeof(amap_struct_ports));
        port_tmp = amap_add_port_string(port_tmp, argv[i], opt->cmd_proto, opt);
        i++;
      }
    } else { // check if cmdline target + ports is already in from nmap inputfile to prevent doubles
      target_tmp = targets;
      while (strcmp(target_tmp->target, argv[0]) != 0 && target_tmp->next != NULL)
        target_tmp = (amap_struct_targets *) target_tmp->next;
      if (strcmp(target_tmp->target, argv[0]) != 0) { // it is not
        if ((/*(amap_struct_targets *)*/ target_tmp->next = /*(amap_struct_targets *)*/ malloc(sizeof(amap_struct_targets))) == NULL)
          amap_error("malloc failed");
        target_tmp = (amap_struct_targets *) target_tmp->next;
        memset(target_tmp, 0, sizeof(amap_struct_targets));
        if (index(argv[0], ':') == NULL)
          target_tmp->target = argv[0];
        else {
          target_tmp->target = malloc(strlen(argv[0]) + 3);
          strcpy(target_tmp->target, "[");
          strcat(target_tmp->target, argv[0]);
          strcat(target_tmp->target, "]");
        }
        if (opt->verbose > 1)
          printf("DEBUG: Loading ports for %s ... ", target_tmp->target);
        if ((port_tmp = target_tmp->ports = (amap_struct_ports *) malloc(sizeof(amap_struct_ports))) == NULL)
          amap_error("malloc failed");
        memset(port_tmp, 0, sizeof(amap_struct_ports));
        port_tmp = amap_add_port_string(port_tmp, argv[1], opt->cmd_proto, opt);
        if (opt->verbose > 1)
          printf("%d/%s ", port_tmp->port, port_tmp->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
        i = 2;
        while (i < argc) {
          if ((/*(amap_struct_ports *)*/ port_tmp->next = /*(amap_struct_ports *)*/ malloc(sizeof(amap_struct_ports))) == NULL)
            amap_error("malloc failed");
          port_tmp = (amap_struct_ports *) port_tmp->next;
          memset(port_tmp, 0, sizeof(amap_struct_ports));
          port_tmp = amap_add_port_string(port_tmp, argv[i], opt->cmd_proto, opt);
          if (opt->verbose > 1)
            printf("%d/%s ", port_tmp->port, port_tmp->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          i++;
        }
      } else { // it is
        if (opt->verbose > 1)
          printf("DEBUG: Loading ports for existing %s ... ", target_tmp->target);
        i = 1;
        while (i < argc) {
          if ((ptr = index(argv[i], '-')) != NULL) {
            *ptr = 0;
            ptr++;
            pfrom = atoi(argv[i]);
            pto = atoi(ptr);
          } else {
            pto = atoi(argv[i]);
            pfrom = pto;
          }
          if (pto < 1 || pfrom < 1 || pto < pfrom)
            amap_error("range definition is invalid: %s-%s",argv[i], ptr);
          for ( ; pfrom <= pto; pfrom++) {
            port_tmp = target_tmp->ports;
            while (((port_tmp->ip_prot != opt->cmd_proto) || (port_tmp->port != (unsigned short int) pfrom)) && port_tmp->next != NULL)
              port_tmp = (amap_struct_ports *) port_tmp->next;
            if (port_tmp->port != (unsigned short int) pfrom) { // we have to add the port
              if ((/*(amap_struct_ports *)*/ port_tmp->next = /*(amap_struct_ports *)*/ malloc(sizeof(amap_struct_ports))) == NULL)
//              if ((port_tmp->next = (amap_struct_ports *) malloc(sizeof(amap_struct_ports))) == NULL)
                amap_error("malloc failed");
              port_tmp = (amap_struct_ports *) port_tmp->next;
              memset(port_tmp, 0, sizeof(amap_struct_ports));
              port_tmp->port = pfrom;
              port_tmp->ip_prot = opt->cmd_proto;
              if (opt->verbose > 1)
                printf("%d/%s ", port_tmp->port, port_tmp->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
            } else
              if (opt->verbose > 3)
                printf("(port %d exists) ", pfrom);
          }
          i++;
        }
      }
    }
    if (opt->verbose > 1)
      printf("\n");
  }

  amap_build_time(today, sizeof(today));

  // PREPARING LOGFILE //
  if (opt->file_log != NULL) {
    struct stat tmpstat;
    if (stat(opt->file_log, &tmpstat) == 0) {
      char fn[1024];
      strncpy(fn, opt->file_log, sizeof(fn) - 5);
      fn[sizeof(fn) - 5] = 0;
      strcat(fn, ".old");
      amap_warn("output file already exists. Moving to %s", fn);
      rename(opt->file_log, fn);
    }
    if ((opt->logfile = fopen(opt->file_log, "w")) == NULL) {
      perror("Error: can not create logfile");
      exit(-1);
    }
    (void) setvbuf(opt->logfile, NULL, _IONBF, 0);
    if (opt->machine_readable)
      fprintf(opt->logfile, "# ");
    fprintf(opt->logfile, "%s v%s (%s) started at %s - ", AMAP_PROGRAM, AMAP_VERSION, AMAP_RESOURCE, today);
    if (opt->portscanner)
      fprintf(opt->logfile, "PORTSCAN mode\n");
    else if (opt->banner_only)
      fprintf(opt->logfile, "BANNER mode\n");
    else
      fprintf(opt->logfile, "MAPPING mode\n");
    if (opt->machine_readable)
      fprintf(opt->logfile, "# IP_ADDRESS:PORT:PROTOCOL:PORT_STATUS:SSL:IDENTIFICATION:PRINTABLE_BANNER:FULL_BANNER\n");
  }
  
  // STARTING SCAN //
  if (opt->verbose)
    printf("\n");
  printf("%s v%s (%s) started at %s - ", AMAP_PROGRAM, AMAP_VERSION, AMAP_RESOURCE, today);
  if (opt->portscanner)
    printf("PORTSCAN mode\n\n");
  else if (opt->banner_only)
    printf("BANNER mode\n\n");
  else
    printf("APPLICATION MAPPING mode\n\n");
  
  if (opt->portscanner && opt->cmd_proto == AMAP_PROTO_UDP)
    printf("Warning: UDP port scanning is highly unreliable against Linux, Cisco and other systems that throttle ICMP error messages\n\n");

  if (amap_scan(AMAP_SCANMODE_DEFAULT, targets, triggers, responses, opt) == 0)
    amap_error("nothing to scan - no open ports in nmap output file");

  if (opt->do_scan_ssl)
    (void) amap_scan(AMAP_SCANMODE_SSL, targets, triggers, responses, opt);

  if (opt->do_scan_rpc)
    (void) amap_scan(AMAP_SCANMODE_RPC, targets, triggers_rpc, NULL, opt);

  // PRINTING UNIDENTIFIED PORTS //
  if (opt->portscanner == 0 && opt->banner_only == 0 && opt->quiet == 0) {
    i = 0;
    target_tmp = targets;
    printf("\nUnidentified ports:");
    if (opt->logfile != NULL && !opt->machine_readable)
      fprintf(opt->logfile, "Unidentified ports:");
    while(target_tmp != NULL) {
      port_tmp = target_tmp->ports;
      while(port_tmp != NULL) {
        if (port_tmp->ids == NULL && (opt->quiet == 0 || port_tmp->skip < 2)) {
          i++;
          printf(" %s%s%s:%d/%s", opt->ipv6 ? "[" : "", target_tmp->target, opt->ipv6 ? "]" : "", port_tmp->port, port_tmp->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          if (opt->logfile != NULL) {
            if (opt->machine_readable) {
              fprintf(opt->logfile, "%s%s%s:%d:%s:%s:%s:%s:%s:", opt->ipv6 ? "[" : "", target_tmp->target, opt->ipv6 ? "]" : "", port_tmp->port, port_tmp->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", amap_skip_translate(port_tmp->skip), port_tmp->ssl ? "SSL" : "", AMAP_UFO, amap_printable_banner_string((char *)port_tmp->unknown_response, port_tmp->unknown_response_length, banner, sizeof(banner)));
              amap_banner_string(opt->logfile, port_tmp->unknown_response, port_tmp->unknown_response_length);
              fprintf(opt->logfile, "\n");
            } else
              fprintf(opt->logfile, " %s%s%s:%d/%s", opt->ipv6 ? "[" : "", target_tmp->target, opt->ipv6 ? "]" : "", port_tmp->port, port_tmp->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp");
          }
        }
        port_tmp = (amap_struct_ports*) port_tmp->next;
      }
      target_tmp = (amap_struct_targets*) target_tmp->next;
    }
    if (i == 0) {
      printf(" none.\n");
      if (opt->logfile != NULL) {
        if (opt->machine_readable)
          fprintf(opt->logfile, "# Unidentified ports: none.\n");
        else
          fprintf(opt->logfile, " none.\n");
      }
    } else {
      printf(" (total %d).", i);
      if (i > 10)
        printf(" \t[Note: the -q option suppresses this listing]\n");
      else
        printf("\n");
      if (opt->logfile != NULL) {
        if (opt->machine_readable)
          fprintf(opt->logfile, "# Unidentified ports: %d.\n", i);
        else
          fprintf(opt->logfile, " (total %d).\n", i);
      }
    }
  } else {
    if (opt->portscanner) {
      target_tmp = targets;
      while(target_tmp != NULL) {
        port_tmp = target_tmp->ports;
        while(port_tmp != NULL) {
          if ((port_tmp->skip == 0 || port_tmp->skip == 3) && port_tmp->ip_prot == AMAP_PROTO_UDP) {
            printf("Port on %s%s%s:%d/udp is OPEN\n", opt->ipv6 ? "[" : "", target_tmp->target, opt->ipv6 ? "]" : "", port_tmp->port);
            if (opt->logfile != NULL) {
              if (opt->machine_readable)
                fprintf(opt->logfile, "%s%s%s:%d:%s:open::%s::\n", opt->ipv6 ? "[" : "", target_tmp->target, opt->ipv6 ? "]" : "", port_tmp->port, port_tmp->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", AMAP_UFO);
              else
                fprintf(opt->logfile, "Port on %s%s%s:%d/udp is OPEN\n", opt->ipv6 ? "[" : "", target_tmp->target, opt->ipv6 ? "]" : "", port_tmp->port);
            }
          } else if ((port_tmp->skip == 4) && port_tmp->ip_prot == AMAP_PROTO_UDP) {
            printf("Port on %s%s%s:%d/udp is OPEN or FILTERED\n", opt->ipv6 ? "[" : "", target_tmp->target, opt->ipv6 ? "]" : "", port_tmp->port);
            if (opt->logfile != NULL) {
              if (opt->machine_readable)
                fprintf(opt->logfile, "%s%s%s:%d:%s:open or filtered::%s::\n", opt->ipv6 ? "[" : "", target_tmp->target, opt->ipv6 ? "]" : "", port_tmp->port, port_tmp->ip_prot == AMAP_PROTO_TCP ? "tcp" : "udp", AMAP_UFO);
              else
                fprintf(opt->logfile, "Port on %s%s%s:%d/udp is OPEN or FILTERED\n", opt->ipv6 ? "[" : "", target_tmp->target, opt->ipv6 ? "]" : "", port_tmp->port);
            }
          }
          port_tmp = (amap_struct_ports*) port_tmp->next;
        }
        target_tmp = (amap_struct_targets*) target_tmp->next;
      }
    }
  }

  amap_build_time(today, sizeof(today));
  if (opt->logfile != NULL) {
    if (opt->machine_readable)
      fprintf(opt->logfile, "# ");
    fprintf(opt->logfile, "%s v%s finished at %s\n", AMAP_PROGRAM, AMAP_VERSION, today);
  }
  printf("\n%s v%s finished at %s\n", AMAP_PROGRAM, AMAP_VERSION, today);

  return 0;
}
