/*
 * AmapCrap (c) 2003 by van Hauser / THC <vh@thc.org>
 * http://www.thc.org
 *
 * Sends random data to silent ports to illicit a reponse. For use with amap
 * for protocol identification.
 *
 * Use allowed only for legal purposes.
 *
 * To compile:   cc -o amapcrap -O2 amapcrap.c
 * with openssl: cc -o amapcrap -O2 amapcrap.c -DOPENSSL -lssl
 *
 */

#include "amap-inc.h"
#include "amap.h"

#define UNLIMITED   0		// dont change this
#define ASCII "abcdefghijklmnopqrstuvwxyz "

#ifdef OPENSSL
SSL *ssl = NULL;
SSL_CTX *sslContext = NULL;
RSA *rsa = NULL;

RSA *ssl_temp_rsa_cb(SSL * ssl, int export, int keylength)
{
  if (rsa == NULL)
    rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
  return rsa;
}
#endif

char *prg;
int warn = 0;

void help()
{
  printf("amapcrap v%s (c) %s by van Hauser/THC <vh@thc.org>\n\n", AMAP_VERSION, AMAP_YEAR);
  printf("Syntax: %s [-S] [-u] [-m 0ab] [-M min,max] [-n connects] [-N delay] [-w delay] [-e] [-v] TARGET PORT\n\n", prg);
  printf("Options:\n");
  printf("    -S           use SSL after TCP connect (not usuable with -u)\n");
  printf("    -u           use UDP protocol (default: TCP) (not usable with -c)\n");
  printf("    -n connects  maximum number of connects (default: unlimited)\n");
  printf("    -N delay     delay between connects in ms (default: 0)\n");
  printf("    -w delay     delay before closing the port (default: 250)\n");
  printf("    -e           do NOT stop when a response was made by the server\n");
  printf("    -v           verbose mode\n");
  printf("    -m 0ab       send as random crap:0-nullbytes, a-letters+spaces, b-binary\n");
  printf("    -M min,max   minimum and maximum length of random crap\n");
  printf("    TARGET PORT  target (ip or dns) and port to send random crap\n\n");
  printf("This tool sends random data to a silent port to illicit a response, which can\n");
  printf("then be used within amap for future detection. It outputs proper amap\n");
  printf("appdefs definitions. Note: by default all modes are activated (0:10%%, a:40%%,\n");
  printf("b:50%%). Mode 'a' always sends one line with letters and spaces which end with\n");
  printf("\\r\\n. Visit our homepage at http://www.thc.org\n");
  exit(-1);
}

int main(int argc, char *argv[])
{
  unsigned short int port = 0;
  long int max_connects = UNLIMITED;
  int sent_mode = 0, sent_mode_old = 0;
  int send_nullbytes = 1;
  int send_ascii = 1;
  int send_binary = 1;
  int send_min = 3;
  int send_max = 256;
  int verbose = 0;
  int use_ssl = 0;
  int debug = 0;
  int dont_exit_when_response = 0;
  long int connect_delay = 1;
  long int close_delay = 250;
  unsigned char *str = NULL, *str_old;
  int str_len = 0, str_len_old = 0;
  int i, j;
  int s;
  int ret;
  int reads = 0;
  int sock_type = SOCK_STREAM;
  int sock_protocol = IPPROTO_TCP;
  unsigned char buf[8196];
  long int count, successful;
  struct sockaddr_in target;
  struct hostent *resolv;
  int res = 0;
#ifdef OPENSSL
  int err;
#endif
#ifdef AF_INET6
  char out[16];
#endif

  srand((getpid() + getuid() + getgid()) ^ time(0));

  prg = argv[0];

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0)
    help();

  while ((i = getopt(argc, argv, "M:N:SVem:n:p:uvw:")) >= 0) {
    switch (i) {
    case 'M':
      if ((str = (unsigned char *)index(optarg, ',')) == NULL) {
	fprintf(stderr,
		"Error: Syntax is \"-M min,max\", e.g. \"-M 1,256\".\n");
	exit(-1);
      }
      *str++ = 0;
      send_min = atoi(optarg);
      send_max = atoi((char *)str);
      if (send_min < 3 || send_max < 3 || send_min > 1024 || send_max > 1024
	  || send_min > send_max) {
	fprintf(stderr,
		"Error: min and max values must be between 3 and 1024.\n");
	exit(-1);
      }
      break;
    case 'm':
      send_nullbytes = 0;
      send_ascii = 0;
      send_binary = 0;
      for (i = 0; i < strlen(optarg); i++)
	switch (optarg[i]) {
	case '0':
	  send_nullbytes = 1;
	  break;
	case 'a':
	case 'A':
	  send_ascii = 1;
	  break;
	case 'b':
	case 'B':
	  send_binary = 1;
	  break;
	case 0:
	  break;
	default:
	  fprintf(stderr, "Error: character for -m option unknown: %c\n",
		  optarg[i]);
	  exit(-1);
	}
      break;
    case 'N':
      connect_delay = atol(optarg);
      break;
    case 'w':
      close_delay = atol(optarg);
      break;
    case 'e':
      dont_exit_when_response = 1;
      break;
    case 'u':
      sock_type = SOCK_DGRAM;
      sock_protocol = IPPROTO_UDP;
      break;
    case 'v':
      verbose++;
      break;
    case 'V':
      debug = 1;
      break;
    case 'n':
      max_connects = atol(optarg);
      break;
    case 'S':
      use_ssl = 1;
#ifndef OPENSSL
      fprintf(stderr,
	      "Error: Not compiled with openssl support, use -DOPENSSL -lssl\n");
      exit(-1);
#endif
      break;
    case 'p':
      if (atoi(optarg) < 0 || atoi(optarg) > 65535) {
	fprintf(stderr, "Error: port must be between 0 and 65535\n");
	exit(-1);
      }
      port = atoi(optarg) % 65536;
      break;
    default:
      fprintf(stderr, "Error: unknown option -%c\n", i);
      help();
    }
  }

  if ((optind + 1 != argc && port > 0) && (optind + 2 != argc && port == 0)) {
    fprintf(stderr,
	    "Error: target missing or too many commandline options!\n");
    exit(-1);
  }

  if (atoi(argv[argc - 1]) < 0 || atoi(argv[argc - 1]) > 65535) {
    fprintf(stderr, "Error: port must be between 0 and 65535\n");
    exit(-1);
  }
  port = atoi(argv[argc - 1]) % 65536;

  if ((resolv = gethostbyname(argv[argc - 2])) == NULL) {
    fprintf(stderr, "Error: can not resolve target\n");
    exit(-1);
  }
  memset(&target, 0, sizeof(target));
  memcpy(&target.sin_addr.s_addr, resolv->h_addr, 4);
  target.sin_port = htons(port);
  target.sin_family = AF_INET;

  if (connect_delay > 0)
    connect_delay = connect_delay * 1000;	/* ms to microseconds */
  else
    connect_delay = 1;
  if (close_delay > 0)
    close_delay = close_delay * 1000;	/* ms to microseconds */
  else
    close_delay = 1;

  for (i = 3; i < 4096; i++)
    close(i);

  printf("# Starting AmapCrap on %s port %d\n",
#ifndef AF_INET6
	 inet_ntoa((struct in_addr) target.sin_addr), port);
#else
         inet_ntop(AF_INET, &target.sin_addr, (char *) &out, sizeof(out)), port);
#endif
  (void) setvbuf(stdout, NULL, _IONBF, 0);
  printf("# Writing a \"+\" for every 10 connect attempts\n# ");

  ret = 0;
  count = 0;
  successful = 0;
  i = 1;
  s = -1;
  res = 1;

  if (use_ssl) {
#ifdef OPENSSL
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    // context: ssl2 + ssl3 is allowed, whatever the server demands
    if ((sslContext = SSL_CTX_new(SSLv23_method())) == NULL) {
      if (verbose) {
	err = ERR_get_error();
	fprintf(stderr, "SSL: Error allocating context: %s\n",
		ERR_error_string(err, NULL));
      }
      res = -1;
    }
    // set the compatbility mode
    SSL_CTX_set_options(sslContext, SSL_OP_ALL);

    // we set the default verifiers and dont care for the results
    (void) SSL_CTX_set_default_verify_paths(sslContext);
    SSL_CTX_set_tmp_rsa_callback(sslContext, ssl_temp_rsa_cb);
    SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
#endif
  }

  str = malloc(send_max);
  str_old = malloc(send_max);

  while (count < max_connects || max_connects == UNLIMITED) {
    if (ret >= 0) {
      if ((s = socket(AF_INET, sock_type, sock_protocol)) < 0) {
	perror("Error");
	exit(-1);
      } else {
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
      }
    }
    if (s >= 0) {
      ret = connect(s, (struct sockaddr *) &target, sizeof(target));
      if (use_ssl && ret >= 0) {
#ifdef OPENSSL
	if ((ssl = SSL_new(sslContext)) == NULL) {
	  if (verbose) {
	    err = ERR_get_error();
	    fprintf(stderr, "Error preparing an SSL context: %s\n",
		    ERR_error_string(err, NULL));
	  }
	  ret = -1;
	} else
	  SSL_set_fd(ssl, s);
	if (ret >= 0 && SSL_connect(ssl) <= 0) {
	  printf("ERROR %d\n", SSL_connect(ssl));
	  if (verbose) {
	    err = ERR_get_error();
	    fprintf(stderr, "Could not create an SSL session: %s\n",
		    ERR_error_string(err, NULL));
	  }
	  ret = -1;
	}

	if (debug)
	  fprintf(stderr, "SSL negotiated cipher: %s\n", SSL_get_cipher(ssl));
#endif
      }
      count++;
      if (ret >= 0) {
	successful++;
	warn = 0;
// begin string generation
	if (str_len > 0) {
	  str_len_old = str_len;
	  memcpy(str_old, str, str_len_old);
	  sent_mode_old = sent_mode;
	}
	j = 0;
	while (j == 0) {
	  i = (int) (100.0 * rand() / (RAND_MAX + 1.0));
	  if (i < 11 && send_nullbytes) {
	    sent_mode = 0;
	    j = 1;
	  }
	  if (i >= 11 && i < 50 && send_ascii) {
	    sent_mode = 1;
	    j = 1;
	  }
	  if (i >= 50 && send_binary) {
	    sent_mode = 2;
	    j = 1;
	  }
	}
	str_len =
	  send_min +
	  (int) ((1.0 * (send_max + 1 - send_min)) * rand() /
		 (RAND_MAX + 1.0));
	switch (sent_mode) {
	case 0:
	  memset(str, 0, str_len);
	  break;
	case 1:
	  for (i = 0; i < str_len - 2; i++)
	    str[i] =
	      ASCII[(unsigned char) (1.0 * (1 + strlen(ASCII)) * rand() /
				     (RAND_MAX + 1.0)) % strlen(ASCII)];
	  str[str_len - 2] = '\r';
	  str[str_len - 1] = '\n';
	  break;
	case 2:
	  for (i = 0; i < str_len; i++)
	    str[i] =
	      (unsigned char) (256.0 * rand() / (RAND_MAX + 1.0)) % 256;
	  break;
	default:
	  fprintf(stderr, "Error: memory corrupted (1)\n");
	  exit(-1);
	}
	if (verbose > 1 || debug)
	  printf(" %d:%d ", sent_mode, str_len);
// end string generation
	if (use_ssl) {
#ifdef OPENSSL
	  SSL_write(ssl, str, str_len);
#endif
	} else {
	  if (write(s, str, str_len) < 0) {
	    perror("\n\nError");
	    if (ret == -1 && str_len > 0) {
	      printf
		("\n# Service seems to have crashed from the following trigger:\n");
	      if (sent_mode == 1) {
		printf("PROTOCOL_CRASH::%s:1:\"",
		       sock_type == SOCK_DGRAM ? "udp" : "tcp");
		for (i = 0; i < str_len; i++)
		  switch (str[i]) {
		  case '\t':
		    printf("\\t");
		    break;
		  case '\n':
		    printf("\\n");
		    break;
		  case '\r':
		    printf("\\r");
		    break;
		  default:
		    printf("%c", str[i]);
		  }
		printf("\"");
	      } else {
		printf("PROTOCOL_CRASH::%s:1:0x",
		       sock_type == SOCK_DGRAM ? "udp" : "tcp");
		for (i = 0; i < str_len; i++) {
		  printf("%c",
			 str[i] / 16 >
			 9 ? str[i] / 16 + 87 : str[i] / 16 + 48);
		  printf("%c",
			 str[i] % 16 >
			 9 ? str[i] % 16 + 87 : str[i] % 16 + 48);
		}
	      }
	      printf("\n\n");
	    }
	    exit(-1);
	  }
	}

	if (close_delay > 0)
	  usleep(close_delay);

	fcntl(s, F_SETFL, O_NONBLOCK);
	errno = 0;
	if (use_ssl) {
#ifdef OPENSSL
	  reads = SSL_read(ssl, buf, sizeof(buf));
#endif
	} else {
	  reads = read(s, buf, sizeof(buf));
	}
	if (reads < 0 && errno == ECONNREFUSED && sock_type == SOCK_DGRAM) {
	  perror("\n\nError");
	  if (str_len_old > 0) {
	    printf
	      ("\n# Service seems to have crashed from the following trigger:\n");
	    if (sent_mode_old == 1) {
	      printf("PROTOCOL_CRASH::%s:1:\"",
		     sock_type == SOCK_DGRAM ? "udp" : "tcp");
	      for (i = 0; i < str_len_old; i++)
		switch (str_old[i]) {
		case '\t':
		  printf("\\t");
		  break;
		case '\n':
		  printf("\\n");
		  break;
		case '\r':
		  printf("\\r");
		  break;
		default:
		  printf("%c", str_old[i]);
		}
	      printf("\"");
	    } else {
	      printf("PROTOCOL_CRASH::%s:1:0x",
		     sock_type == SOCK_DGRAM ? "udp" : "tcp");
	      for (i = 0; i < str_len_old; i++) {
		printf("%c",
		       str_old[i] / 16 >
		       9 ? str_old[i] / 16 + 87 : str_old[i] / 16 + 48);
		printf("%c",
		       str_old[i] % 16 >
		       9 ? str_old[i] % 16 + 87 : str_old[i] % 16 + 48);
	      }
	    }
	    printf("\n\n");
	  }
	  exit(-1);
	}
	if (reads > 0) {
// output function
	  printf("\n\n# Put this line into appdefs.trig:\n");
	  if (sent_mode == 1) {
	    printf("PROTOCOL_NAME::%s:0:\"",
		   sock_type == SOCK_DGRAM ? "udp" : "tcp");
	    for (i = 0; i < str_len; i++)
	      switch (str[i]) {
	      case '\t':
		printf("\\t");
		break;
	      case '\n':
		printf("\\n");
		break;
	      case '\r':
		printf("\\r");
		break;
	      default:
		printf("%c", str[i]);
	      }
	    printf("\"");
	  } else {
	    printf("PROTOCOL_NAME::%s:0:0x",
		   sock_type == SOCK_DGRAM ? "udp" : "tcp");
	    for (i = 0; i < str_len; i++) {
	      printf("%c",
		     str[i] / 16 > 9 ? str[i] / 16 + 87 : str[i] / 16 + 48);
	      printf("%c",
		     str[i] % 16 > 9 ? str[i] % 16 + 87 : str[i] % 16 + 48);
	    }
	  }
	  printf("\n\n# Put this line into appdefs.resp:\n");
	  j = 0;
	  i = 0;
	  while (j == 0 && i < reads) {
	    if (!isprint(buf[i]) && !isspace(buf[i]))
	      j = 1;
	    i++;
	  }
	  if (j) {
	    printf("PROTOCOL_NAME::%s::0x",
		   sock_type == SOCK_DGRAM ? "udp" : "tcp");
	    for (i = 0; i < reads; i++) {
	      printf("%c",
		     buf[i] / 16 > 9 ? buf[i] / 16 + 87 : buf[i] / 16 + 48);
	      printf("%c",
		     buf[i] % 16 > 9 ? buf[i] % 16 + 87 : buf[i] % 16 + 48);
	    }
	    printf("\n\n");
	  } else {
	    printf("PROTOCOL_NAME::%s::\"",
		   sock_type == SOCK_DGRAM ? "udp" : "tcp");
	    for (i = 0; i < reads; i++)
	      switch (buf[i]) {
	      case '\t':
		printf("\\t");
		break;
	      case '\n':
		printf("\\n");
		break;
	      case '\r':
		printf("\\r");
		break;
	      default:
		printf("%c", buf[i]);
	      }
	    printf("\"\n\n");
	  }
// output function end
	  if (!dont_exit_when_response)
	    exit(0);
	}
#ifdef OPENSSL
	if (use_ssl)
	  SSL_shutdown(ssl);
#endif
	close(s);
	if (connect_delay > 0)
	  usleep(connect_delay);
      } else {
	perror("\n\nError");
	if (ret == -1 && str_len > 0) {
	  printf
	    ("\n# Service seems to have crashed from the following trigger:\n");
	  if (sent_mode == 1) {
	    printf("PROTOCOL_CRASH::%s:1:\"",
		   sock_type == SOCK_DGRAM ? "udp" : "tcp");
	    for (i = 0; i < str_len; i++)
	      switch (str[i]) {
	      case '\t':
		printf("\\t");
		break;
	      case '\n':
		printf("\\n");
		break;
	      case '\r':
		printf("\\r");
		break;
	      default:
		printf("%c", str[i]);
	      }
	    printf("\"");
	  } else {
	    printf("PROTOCOL_CRASH::%s:1:0x",
		   sock_type == SOCK_DGRAM ? "udp" : "tcp");
	    for (i = 0; i < str_len; i++) {
	      printf("%c",
		     str[i] / 16 > 9 ? str[i] / 16 + 87 : str[i] / 16 + 48);
	      printf("%c",
		     str[i] % 16 > 9 ? str[i] % 16 + 87 : str[i] % 16 + 48);
	    }
	  }
	  printf("\n\n");
	}
	exit(-1);
      }
      if (count % 10 == 0)
	printf("+");
    } else
      close(s);
  }

  printf("\ndone\n");
  return 0;			// not reached
}
