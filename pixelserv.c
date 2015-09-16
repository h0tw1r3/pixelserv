/*
* pixelserv.c a small mod to public domain server.c -- a stream socket server demo
* from http://beej.us/guide/bgnet/
* single pixel http string from http://proxytunnel.sourceforge.net/pixelserv.php
*/

#ifndef VERSION
#define VERSION "????"
#endif
#ifndef BUILD_USER
#define BUILD_USER "unknown"
#endif

#define BACKLOG 30              // how many pending connections queue will hold
#define CHAR_BUF_SIZE 2048      // surprising how big requests can be with cookies etc

#define DEFAULT_IP "*"          // default IP address = all
#define DEFAULT_PORT "80"         // the default port users will be connecting to
#define SECOND_PORT  "443"

#define DEFAULT_TIMEOUT 10      // default timeout for select() calls, in seconds

#define DEFAULT_USER "nobody"   // nobody used by dnsmasq

#define MAX_PORTS 10

#define DEFAULT_STATS_PATH "/servstats"

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>        // for TCP_NODELAY
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <pwd.h>                // for getpwnam
#include <ctype.h>              // isdigit() & tolower()

#define xstr(a) str(a)
#define str(a) #a

#ifdef HEX_DUMP
/* from http://sws.dett.de/mini/hexdump-c/ */
static void hex_dump(void *data, int size)
{
	/* dumps size bytes of *data to stdout. Looks like:
	 * [0000] 75 6E 6B 6E 6F 77 6E 20   30 FF 00 00 00 00 39 00 unknown 0.....9.
	 * (in a single line of course)
	 */

	unsigned char *p = data;
	unsigned char c;
	int n;
	char bytestr[4] = { 0 };
	char addrstr[10] = { 0 };
	char hexstr[16 * 3 + 5] = { 0 };
	char charstr[16 * 1 + 5] = { 0 };
	for (n = 1; n <= size; n++) {
		if (n % 16 == 1) {
			/* store address for this line */
			snprintf(addrstr, sizeof addrstr, "%.4x",
						((unsigned int)p - (unsigned int)data));
		}

		c = *p;
		if (isprint(c) == 0) {
			c = '.';
		}

		/* store hex str (for left side) */
		snprintf(bytestr, sizeof bytestr, "%02X ", *p);
		strncat(hexstr, bytestr, sizeof hexstr - strlen(hexstr) - 1);

		/* store char str (for right side) */
		snprintf(bytestr, sizeof bytestr, "%c", c);
		strncat(charstr, bytestr, sizeof charstr - strlen(charstr) - 1);

		if (n % 16 == 0) {
			/* line completed */
			printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
			hexstr[0] = 0;
			charstr[0] = 0;
		} else if (n % 8 == 0) {
			/* half line: add whitespaces */
			strncat(hexstr, "  ", sizeof hexstr - strlen(hexstr) - 1);
			strncat(charstr, " ", sizeof charstr - strlen(charstr) - 1);
		}

		p++; /* next byte */
	}

	if (strlen(hexstr) > 0) {
		/* print rest of buffer if not empty */
		printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
	}
}
#endif

char * strstr_last(const char *str1, const char *str2) {
	char *strp;
	int len1, len2;
	len2 = strlen(str2);
	if (len2==0) {
		return (char *) str1;
	}
	len1 = strlen(str1);
	if (len1 - len2 <= 0) {
		return 0;
	}
	strp = (char *)(str1 + len1 - len2);
	while (strp != str1) {
		if (*strp == *str2 && strncmp(strp, str2, len2) == 0) {
			return strp;
		}
		strp--;
	}
	return 0;
}

char from_hex(char ch) {
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

void urldecode(char *decoded, char *encoded) {
	char *pstr = encoded, *pbuf = decoded;

	while (*pstr) {
		if (*pstr == '%') {
			if (pstr[1] && pstr[2]) {
				*pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
				pstr += 2;
			}
		} else {
			*pbuf++ = *pstr;
		}
		pstr++;
	}
	*pbuf = '\0';
}

#ifdef READ_FILE
#include <sys/stat.h>
#endif

#ifdef TEST
#define TEXT_REPLY 1
#define VERBOSE 1
#define TESTPRINT printf
#else
#define TESTPRINT(x,y...)
#endif

#ifdef VERBOSE
#define MYLOG syslog
#else                           // rely on optimiser to remove redundant code
#define MYLOG(x,y...)
#endif

#ifdef TINY
/* redefine log functions to NULL */
#define openlog(x,y...)
#define syslog(x,y...)
#endif

#define OK (0)
#define ERROR (-1)

enum responsetypes {
	SEND_GIF = 10,
	SEND_TXT,
	SEND_JPG,
	SEND_PNG,
	SEND_SWF,
	SEND_ICO,
	SEND_BAD,
	SEND_SSL,
	SEND_REDIRECT,
	SEND_STATS
};

#ifdef DO_COUNT
volatile sig_atomic_t count = 0;
volatile sig_atomic_t gif = 0;
volatile sig_atomic_t err = 0;
#ifdef TEXT_REPLY
volatile sig_atomic_t txt = 0;
volatile sig_atomic_t bad = 0;
#ifdef NULLSERV_REPLIES
volatile sig_atomic_t jpg = 0;
volatile sig_atomic_t png = 0;
volatile sig_atomic_t swf = 0;
volatile sig_atomic_t ico = 0;
#endif
#ifdef SSL_RESP
volatile sig_atomic_t ssl = 0;
#endif
#endif                          // TEXT_REPLY
volatile sig_atomic_t rdr = 0;
volatile sig_atomic_t sta = 0;

/* stats string generator
 * note that caller is expected to call free()
 * on the return value when done using it
 * also, the purpose of sta_offset is to allow
 * accounting for an in-progress status response
 */
inline char* get_stats(int sta_offset) {
	char *retbuf = NULL;
	asprintf(&retbuf, "%d reg, %d err, %d gif,"
#ifdef TEXT_REPLY
				" %d bad, %d txt"
#ifdef NULLSERV_REPLIES
				", %d jpg, %d png, %d swf %d ico"
#endif
#ifdef SSL_RESP
				", %d ssl"
#endif
#endif // TEXT_REPLY
				", %d rdr, %d sta"
				, count, err, gif
#ifdef TEXT_REPLY
				, bad, txt
#ifdef NULLSERV_REPLIES
				, jpg, png, swf, ico
#endif
#ifdef SSL_RESP
				, ssl
#endif
#endif // TEXT_REPLY
				, rdr, sta
			);
	return retbuf;
}
#endif // DO_COUNT

inline char *get_version(char *program_name)
{
	char *retbuf = NULL;
	asprintf(&retbuf, "%s version %s (built %s %s by %s)", program_name, xstr(VERSION), __DATE__, __TIME__, xstr(BUILD_USER));
	return retbuf;
}

void signal_handler(int sig)    // common signal handler
{
	int status;
	switch (sig) {
	case SIGCHLD:                // ensure no zombie sub processes left */
		while (waitpid(-1, &status, WNOHANG) > 0) {
#ifdef DO_COUNT
			if (WIFEXITED(status)) {
				switch (WEXITSTATUS(status)) {
				case EXIT_FAILURE:
					err++;
					break;

				case SEND_GIF:
					gif++;
					break;
				case SEND_REDIRECT:
					rdr++;
					break;
				case SEND_STATS:
					sta++;
					break;
#ifdef TEXT_REPLY
				case SEND_BAD:
					bad++;
					break;

				case SEND_TXT:
					txt++;
					break;
#ifdef NULLSERV_REPLIES
				case SEND_JPG:
					jpg++;
					break;

				case SEND_PNG:
					png++;
					break;

				case SEND_SWF:
					swf++;
					break;

				case SEND_ICO:
					ico++;
					break;
#endif // NULLSERV_REPLIES
#ifdef SSL_RESP
				case SEND_SSL:
					ssl++;
					break;
#endif
#endif // TEXT_REPLY
				}
			}
#endif // DO_COUNT
		};
		return;

#ifndef TINY
	case SIGTERM: // Handler for the SIGTERM signal (kill)
		signal(sig, SIG_IGN); // Ignore this signal while we are quiting
#ifdef DO_COUNT
	case SIGUSR1:
		{
			char *stats_string = get_stats(0);
			syslog(LOG_INFO, "%s", stats_string);
			free(stats_string);
		}

		if (sig == SIGUSR1) {
			return;
		}
#endif // DO_COUNT
		syslog(LOG_NOTICE, "exit on SIGTERM");
		exit(EXIT_SUCCESS);
#endif // TINY
	}
}


#ifdef TEST
void *get_in_addr(struct sockaddr *sa) // get sockaddr, IPv4 or IPv6
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in *)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}
#endif

int main(int argc, char *argv[]) // program start
{
	int sockfd; // listen on sock_fd
	int new_fd; // new connection on new_fd
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	int yes = 1;
	int n = -1; // to turn off linger2
#ifdef TEST
	char s[INET6_ADDRSTRLEN];
#endif
	time_t select_timeout = DEFAULT_TIMEOUT;
	int rv;
	char *ip_addr = DEFAULT_IP;
	int use_ip = 0;
	char buf[CHAR_BUF_SIZE + 1];

	char *ports[MAX_PORTS];
	int sockets[MAX_PORTS];
	int num_ports = 0;
	fd_set readfds;

	int i;

	char *ifname = "";
	int use_if = 0;

	char *user = DEFAULT_USER; // used to be long enough
	struct passwd *pw;

	int do_redirect = 0;
#ifdef TEXT_REPLY
	char *location = NULL;
	char *url = NULL;
	char *bufptr = NULL;
#endif

#ifdef READ_FILE
	char *fname = NULL;
	int fsize;
#ifdef READ_GIF
	int do_gif = 0;
#endif
	int hsize = 0;
	struct stat file_stat;
	FILE *fp;
#endif // READ_FILE

#ifdef DO_COUNT
	char *stats_path = DEFAULT_STATS_PATH;

	static const char *httpstats =
				"HTTP/1.1 200 OK\r\n"
				"Content-type: text/plain\r\n"
				"Content-length: %d\r\n"
				"Connection: close\r\n\r\n%s";
#endif

#ifdef TEXT_REPLY
	static const char *httpredirect = 
				"HTTP/1.1 307 Temporary Redirect\r\n"
				"Location: %s\r\n"
				"Content-type: text/plain\r\n"
				"Content-length: 0\r\n"
				"Connection: close\r\n\r\n";
#endif

	static unsigned char httpnullpixel[] =
				"HTTP/1.1 200 OK\r\n"
				"Content-type: image/gif\r\n"
				"Content-length: 42\r\n"
				"Connection: close\r\n"
				"\r\n"
				"GIF89a"   //header
				"\1\0\1\0" // little endian width, height
				"\x80"     // Global Colour Table flag
				"\0"       // background colour
				"\0"       // default pixel aspect ratio
				"\1\1\1"   // RGB
				"\0\0\0"   // RBG black
				"!\xf9"    // Graphical Control Extension
				"\4"       // 4 byte GCD data follow
				"\1"       // there is transparent background color
				"\0\0"     // delay for animation
				"\0"       // transparent colour
				"\0"       // end of GCE block
				","        // image descriptor
				"\0\0\0\0" // NW corner
				"\1\0\1\0" // height * width
				"\0"       // no local color table
				"\2"       // start of image LZW size
				"\1"       // 1 byte of LZW encoded image data
				"D"        // image data
				"\0"       // end of image data
				";";       // GIF file terminator

#ifdef TEXT_REPLY
	static unsigned char httpnulltext[] =
				"HTTP/1.1 200 OK\r\n"
				"Content-type: text/html\r\n"
				"Content-length: 0\r\n"
				"Connection: close\r\n"
				"\r\n";

	static unsigned char http501[] =
				"HTTP/1.1 501 Method Not Implemented\r\n"
				"Connection: close\r\n"
				"\r\n";

#ifdef NULLSERV_REPLIES
	static unsigned char httpnull_png[] =
				"HTTP/1.1 200 OK\r\n"
				"Content-type: image/png\r\n"
				"Content-length: 67\r\n"
				"Connection: close\r\n"
				"\r\n"
				"\x89"
				"PNG"
				"\r\n"
				"\x1a\n"            // EOF
				"\0\0\0\x0d"        // 13 bytes length
				"IHDR"
				"\0\0\0\1\0\0\0\1"  // width x height
				"\x08"              // bit depth
				"\x06"              // Truecolour with alpha
				"\0\0\0"            // compression, filter, interlace
				"\x1f\x15\xc4\x89"  // CRC
				"\0\0\0\x0a"        // 10 bytes length
				"IDAT"
				"\x78\x9c\x63\0\1\0\0\5\0\1"
				"\x0d\x0a\x2d\xb4"  // CRC
				"\0\0\0\0"          // 0 length
				"IEND"
				"\xae\x42\x60\x82"; // CRC

	static unsigned char httpnull_jpg[] =
				"HTTP/1.1 200 OK\r\n"
				"Content-type: image/jpeg\r\n"
				"Content-length: 159\r\n"
				"Connection: close\r\n"
				"\r\n"
				"\xff\xd8" // SOI, Start Of Image
				"\xff\xe0" // APP0
				"\x00\x10" // length of section 16
				"JFIF\0"
				"\x01\x01" // version 1.1
				"\x01"     // pixel per inch
				"\x00\x48" // horizontal density 72
				"\x00\x48" // vertical density 72
				"\x00\x00" // size of thumbnail 0 x 0
				"\xff\xdb" // DQT
				"\x00\x43" // length of section 3+64
				"\x00"     // 0 QT 8 bit
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xc0" // SOF
				"\x00\x0b" // length 11
				"\x08\x00\x01\x00\x01\x01\x01\x11\x00"
				"\xff\xc4" // DHT Define Huffman Table
				"\x00\x14" // length 20
				"\x00\x01" // DC table 1
				"\x00\x00\x00\x00\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x00\x00\x00\x03"
				"\xff\xc4" // DHT
				"\x00\x14" // length 20
				"\x10\x01" // AC table 1
				"\x00\x00\x00\x00\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x00\x00\x00\x00"
				"\xff\xda"  // SOS, Start of Scan
				"\x00\x08"  // length 8
				"\x01"      // 1 component
				"\x01\x00"
				"\x00\x3f\x00"  // Ss 0, Se 63, AhAl 0
				"\x37"      // image
				"\xff\xd9"; // EOI, End Of image

	static unsigned char httpnull_swf[] =
				"HTTP/1.1 200 OK\r\n"
				"Content-type: application/x-shockwave-flash\r\n"
				"Content-length: 25\r\n"
				"Connection: close\r\n"
				"\r\n"
				"FWS"
				"\x05"              // File version
				"\x19\x00\x00\x00"  // litle endian size 16+9=25
				"\x30\x0A\x00\xA0"  // Frame size 1 x 1
				"\x00\x01"          // frame rate 1 fps
				"\x01\x00"          // 1 frame
				"\x43\x02"          // tag type is 9 = SetBackgroundColor block 3 bytes long
				"\x00\x00\x00"      // black
				"\x40\x00"          // tag type 1 = show frame
				"\x00\x00";         // tag type 0 - end file

static unsigned char httpnull_ico[] =
				"HTTP/1.1 200 OK\r\n"
				"Content-type: image/x-icon\r\n"
				"Cache-Control: max-age=2592000\r\n"
				"Content-length: 70\r\n"
				"Connection: close\r\n"
				"\r\n"
				"\x00\x00" // reserved 0
				"\x01\x00" // ico
				"\x01\x00" // 1 image
				"\x01\x01\x00" // 1 x 1 x >8bpp colour
				"\x00" // reserved 0
				"\x01\x00" // 1 colour plane
				"\x20\x00" // 32 bits per pixel
				"\x30\x00\x00\x00" // size 48 bytes
				"\x16\x00\x00\x00" // start of image 22 bytes in
				"\x28\x00\x00\x00" // size of DIB header 40 bytes
				"\x01\x00\x00\x00" // width
				"\x02\x00\x00\x00" // height
				"\x01\x00" // colour planes
				"\x20\x00" // bits per pixel
				"\x00\x00\x00\x00" // no compression
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
				"\x00\x00\x00\x00" // end of header
				"\x00\x00\x00\x00" // Colour table
				"\x00\x00\x00\x00" // XOR B G R
				"\x80\xF8\x9C\x41"; // AND ?
#endif

#ifdef SSL_RESP
	static unsigned char SSL_no[] =
				"\x15"  // Alert 21
				"\3\0"  // Version 3.0
				"\0\2"  // length 2
				"\2"    // fatal
				"\x31"; // 0 close notify, 0x28 Handshake failure 40, 0x31 TLS access denied 49
#endif
#endif // TEXT_REPLY

#ifdef NULLSERV_REPLIES
#define DEFAULT_REPLY SEND_TXT
	unsigned char *response = httpnulltext;
	int rsize = sizeof httpnulltext - 1;
#else
#define DEFAULT_REPLY SEND_GIF
	unsigned char *response = httpnullpixel;
	int rsize = sizeof httpnullpixel - 1;
#endif

	struct addrinfo hints, *servinfo;
	int error = 0;

	fd_set set;
	struct timeval timeout;
	int select_rv;
	int status = EXIT_FAILURE; // default return from child

	/* command line arguments processing */
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if ((i + 1) < argc) {
				switch (argv[i][1]) {
				case 'n':
					ifname = argv[++i];
					use_if = 1;
					break;
				case 'o':
					select_timeout = strtol(argv[++i], NULL, 10);
					if (errno) {
						error = 1;
					}
					break;
				case 'p':
					if (num_ports < MAX_PORTS) {
						ports[num_ports++] = argv[++i];
					} else {
						i++;
						error = 1;
					}
					break;
				case 'u':
					user = argv[++i];
					break;
#ifdef READ_FILE
#ifdef READ_GIF
				case 'g':
					do_gif = 1;
#endif
				case 'f':
					fname = argv[++i];
					break;
#endif // READ_FILE
#ifdef DO_COUNT
				case 's':
					stats_path = argv[++i];
					break;
#endif
				default:
					error = 1;
				}
			} else if (argv[i][1] == 'r') {
				do_redirect = 1;
				break;
			} else {
				error = 1;
			}
		} else if (use_ip == 0) { // assume its a listening IP address
			ip_addr = argv[i];
			use_ip = 1;
		} else {
			error = 1; // fix bug with 2 IP like args
		}
	}

	if (error) {
#ifndef TINY
		printf("Usage: %s [OPTIONS...] [IP (default all)]\n"
					"\t-p\tlisten on port\n\t\t** "DEFAULT_PORT" "SECOND_PORT"\n"
					"\t-n\tbind to interface\n"
					"\t-o\tselect timeout\n\t\t** "xstr(DEFAULT_TIMEOUT)" seconds\n"
					"\t-u\trun as user\n\t\t** "DEFAULT_USER"\n"
					"\t-r\tredirect encoded tracking links"
#ifdef DO_COUNT
					"\n\t-s\tcounter statistics report url path\n\t\t** "DEFAULT_STATS_PATH
#endif
#ifdef READ_FILE
					"\n\t-f\tcustom file response"
#ifdef READ_GIF
					"\n\t-g\tcustom gif response"
#endif
#endif // READ_FILE
					"\n", argv[0]);
#endif // TINY
		char *version_string = get_version(argv[0]);
		printf("%s\n", version_string);
		free(version_string);
		exit(EXIT_FAILURE);
	}

	if (num_ports == 0) {
		ports[num_ports++] = DEFAULT_PORT;
		ports[num_ports++] = SECOND_PORT;
	}

	openlog("pixelserv", LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
	char* version_string = get_version(argv[0]);
	syslog(LOG_INFO, "%s", version_string);
	free(version_string);

#ifdef READ_FILE
	if (fname) {
		if (stat(fname, &file_stat) < 0) {
			syslog(LOG_ERR, "stat: '%s': %m", fname);
			exit(EXIT_FAILURE);
		}

		fsize = (int)file_stat.st_size;
		TESTPRINT("fsize:%d\n", fsize);

		if (fsize < 43) {
			syslog(LOG_ERR, "%s: size only %d", fname, fsize);
			exit(EXIT_FAILURE);
		}

		if ((fp = fopen(fname, "rb")) == NULL) {
			syslog(LOG_ERR, "fopen: '%s': %m", fname);
			exit(EXIT_FAILURE);
		}
#ifdef READ_GIF
		if (do_gif) {
			snprintf(buf, CHAR_BUF_SIZE,
						"HTTP/1.1 200 OK\r\n"
						"Content-type: image/gif\r\n"
						"Content-length: %d\r\n" "Connection: close\r\n" "\r\n", fsize);

			hsize = strlen(buf);
			TESTPRINT("hsize:%d\n", hsize);
		}
#endif

		rsize = hsize + fsize;
		TESTPRINT("rsize:%d\n", rsize);
		if ((response = malloc(rsize)) == NULL) {
			syslog(LOG_ERR, "malloc: %m");
			exit(EXIT_FAILURE);
		}
#ifdef READ_GIF
		if (do_gif) {
			strcpy((char *)response, buf);
		}
#endif

		if (fread(&response[hsize], sizeof(char), fsize, fp) < fsize) {
			syslog(LOG_ERR, "fread: '%s': %m", fname);
			exit(EXIT_FAILURE);
		}

		fclose(fp);
	}
#ifdef SAVE_RESP
	fp = fopen("test.tmp", "wb");
	fwrite(response, sizeof(char), rsize, fp);
	fclose(fp);
#endif
#endif // READ_FILE

#ifndef TEST
	if (daemon(0, 0) != OK) {
		syslog(LOG_ERR, "failed to daemonize, exit: %m");
		exit(EXIT_FAILURE);
	}
#endif

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // AF_UNSPEC - AF_INET restricts to IPV4
	hints.ai_socktype = SOCK_STREAM;
	if (!use_ip) {
		hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG; // use my IP
	}

	for (i = 0; i < num_ports; i++) {
		rv = getaddrinfo(use_ip ? ip_addr : NULL, ports[i], &hints, &servinfo);
		if (rv != OK) {
			syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(rv));
			exit(EXIT_FAILURE);
		}

		if ((sockets[i] = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) < 1) {
			syslog(LOG_ERR, "Failed to create socket: %m");
			exit(EXIT_FAILURE);
		}
		if ((setsockopt(sockets[i], SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) != OK)
				/* only use selected i/f */
				|| (use_if && (setsockopt(sockets[i], SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) != OK))
				/* send short packets straight away */
				|| (setsockopt(sockets[i], SOL_TCP, TCP_NODELAY, &yes, sizeof(int)) != OK)
				/* try to prevent hanging processes in FIN_WAIT2 */
				|| (setsockopt(sockets[i], SOL_TCP, TCP_LINGER2, (void *)&n, sizeof n) != OK))
		{
			syslog(LOG_ERR, "Failed to setsockopt: %m");
			exit(EXIT_FAILURE);
		}

		if ((bind(sockets[i], servinfo->ai_addr, servinfo->ai_addrlen) != OK)
				|| (listen(sockets[i], BACKLOG) != OK)) {
			syslog(LOG_ERR, "Socket bind failure: %m");
			exit(EXIT_FAILURE);
		}
	}

	freeaddrinfo(servinfo);       /* all done with this structure */

	{
		struct sigaction sa;
		sa.sa_handler = signal_handler;
		sigemptyset(&sa.sa_mask);

#ifndef TINY
		/* set signal handler for termination */
		if (sigaction(SIGTERM, &sa, NULL) != OK) {
			syslog(LOG_ERR, "SIGTERM %m");
			exit(EXIT_FAILURE);
		}
#endif
		/* reap all dead processes */
		sa.sa_flags = SA_RESTART;
		if (sigaction(SIGCHLD, &sa, NULL) != OK) {
			syslog(LOG_ERR, "SIGCHLD %m");
			exit(EXIT_FAILURE);
		}
#ifdef DO_COUNT
		/* set signal handler for info */
		if (sigaction(SIGUSR1, &sa, NULL) != OK) {
			syslog(LOG_ERR, "SIGUSR1 %m");
			exit(EXIT_FAILURE);
		}
#endif
	}

	if ((pw = getpwnam(user)) == NULL) {
		syslog(LOG_ERR, "Unknown user \"%s\"", user);
		exit(EXIT_FAILURE);
	}
	
	if (getuid() == 0) {
		if (setuid(pw->pw_uid)) {
			syslog(LOG_ERR, "setuid %d: %s\n", pw->pw_uid, strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		syslog(LOG_NOTICE, "Not running as root, ignoring setuid(%d)\n", pw->pw_uid);
	}

	for (i = 1; i < num_ports; i++) {
		syslog(LOG_NOTICE, "Listening on %s %s:%s", use_if ? ifname : "", use_ip ? ip_addr : "*", ports[i]);
	}

	sin_size = sizeof their_addr;
	while (1) { // main accept() loop
		sockfd = 0;
		// clear the set
		FD_ZERO(&readfds);
		// add our descriptors to the set
		for (i = 0; i < num_ports; i++) {
			FD_SET(sockets[i], &readfds);
		}
		/* NOTE: MACRO needs "_GNU_SOURCE", without this the select gets interrupte with errno EINTR */
		select_rv = TEMP_FAILURE_RETRY(select(FD_SETSIZE, &readfds, NULL, NULL, NULL));
		if (select_rv < 0) {
			syslog(LOG_ERR, "select(fd) error: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < num_ports; i++) {
			if (FD_ISSET(sockets[i], &readfds)) {
				sockfd = sockets[i];
				break;
			}
		}

		if (!sockfd) continue;

		new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &sin_size);
		if (new_fd < 1) {
			MYLOG(LOG_WARNING, "accept: %m");
			continue;
		}
#ifdef DO_COUNT
		count++;
#endif

		if (fork() == 0) {
			/* this is the child process */
			close(sockfd); // child doesn't need the listener
#ifndef TINY
			signal(SIGTERM, SIG_DFL);
#endif
			signal(SIGCHLD, SIG_DFL);
#ifdef DO_COUNT
			signal(SIGUSR1, SIG_IGN);
#endif

#ifdef TEST
			inet_ntop(their_addr.ss_family,
					get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
			printf("server: got connection from %s\n", s);
#endif

#ifdef TEXT_REPLY
			/* read a line from the request */
			FD_ZERO(&set);
			FD_SET(new_fd, &set);
			/* Initialize the timeout data structure */
			timeout.tv_sec = select_timeout;
			timeout.tv_usec = 0;

			/* select returns 0 if timeout, 1 if input available, -1 if error */
			select_rv = select(new_fd + 1, &set, NULL, NULL, &timeout);
			if (select_rv < 0) {
				MYLOG(LOG_ERR, "select: %m");
			} else if (select_rv == 0) {
				MYLOG(LOG_ERR, "timeout on select");
			} else {
				rv = recv(new_fd, buf, CHAR_BUF_SIZE, 0);
				if (rv < 0) {
					MYLOG(LOG_ERR, "recv: %m");
				} else if (rv == 0) {
					MYLOG(LOG_ERR, "recv: No data");
				} else {
					buf[rv] = '\0';
					TESTPRINT("\nreceived %d bytes\n'%s'\n", rv, buf);
#ifdef HEX_DUMP
					hex_dump(buf, rv);
#endif
#ifdef SSL_RESP
					if (buf[0] == '\x16') {
						TESTPRINT("SSL handshake request received\n");
						status = SEND_SSL;
						response = SSL_no;
						rsize = sizeof SSL_no - 1;
					} else {
#endif
						char *req = strtok_r(buf, "\r\n", &bufptr);
						char *method = strtok(req, " ");

						if (method == NULL) {
							MYLOG(LOG_ERR, "null method");
						} else {
							TESTPRINT("method: '%s'\n", method);
							if (strcmp(method, "GET")) {
								MYLOG(LOG_ERR, "unknown method: %s", method);
								status = SEND_BAD;
								TESTPRINT("Sending 501 response\n");
								response = http501;
								rsize = sizeof http501 - 1;
							} else {
								status = DEFAULT_REPLY; // send default from here
								/* trim up to non path chars */
								char *path = strtok(NULL, " "); //, " ?#;=");     // "?;#:*<>[]='\"\\,|!~()"
								if (path == NULL) {
									MYLOG(LOG_ERR, "null path");
#ifdef DO_COUNT
								} else if (!strcmp(path, stats_path)) {
									status = SEND_STATS;
									char *stat_string = get_stats(1);
									asprintf((char**)(&response), httpstats, strlen(stat_string), stat_string);
									free(stat_string);
									rsize = strlen((char*)response);
#endif
								} else {
									/* pick out encoded urls (usually advert redirects) */
									if (do_redirect && strstr(path, "=http") && strchr(path, '%')) {
										char *decoded = malloc(strlen(path)+1);
										urldecode(decoded, path);
										/* double decode */
										urldecode(path, decoded);
										free(decoded);
										url = strstr_last(path, "http://");
										if (url == NULL) {
											url = strstr_last(path, "https://");
										}
										/* WORKAROUND: google analytics block - request bomb on pages with conversion callbacks (see in chrome) */
										if (url) {
											char *tok = NULL;
											for (tok = strtok_r(NULL, "\r\n", &bufptr); tok; tok = strtok_r(NULL, "\r\n", &bufptr)) {
												char *hkey = strtok(tok, ":");
												char *hvalue = strtok(NULL, "\r\n");
												if (strstr(hkey, "Referer") && strstr(hvalue, url)) {
													url = NULL;
													TESTPRINT("%s:%s\n", hkey, hvalue);
													break;
												}
											}
										}
									}
									if (do_redirect && url) {
										location = NULL;
										status = SEND_REDIRECT;
										rsize = asprintf(&location, httpredirect, url);
										response = (unsigned char *)(location);
										TESTPRINT("Sending redirect: %s\n", url);
										url = NULL;
									} else {
										char *file = strrchr(strtok(path, "?#;="), '/');
										if (file == NULL) {
											MYLOG(LOG_ERR, "invalid file path %s", path);
										} else {
											TESTPRINT("file: '%s'\n", file);
											char *ext = strrchr(file, '.');
											if (ext == NULL) {
												MYLOG(LOG_ERR, "No file extension %s", file);
											} else {
												TESTPRINT("ext: '%s'\n", ext);
#ifdef NULLSERV_REPLIES
												if (!strcasecmp(ext, ".gif")) {
													TESTPRINT("Sending gif response\n");
													status = SEND_GIF;
													response = httpnullpixel;
													rsize = sizeof httpnullpixel - 1;
												} else if (!strcasecmp(ext, ".png")) {
													TESTPRINT("Sending png response\n");
													status = SEND_PNG;
													response = httpnull_png;
													rsize = sizeof httpnull_png - 1;
												} else if (!strncasecmp(ext, ".jp", 3)) {
													TESTPRINT("Sending jpg response\n");
													status = SEND_JPG;
													response = httpnull_jpg;
													rsize = sizeof httpnull_jpg - 1;
												} else if (!strcasecmp(ext, ".swf")) {
													TESTPRINT("Sending swf response\n");
													status = SEND_SWF;
													response = httpnull_swf;
													rsize = sizeof httpnull_swf - 1;
												} else if (!strcasecmp(ext, ".ico")) {
													TESTPRINT("Sending ico response\n");
													status = SEND_ICO;
													response = httpnull_ico;
													rsize = sizeof httpnull_ico - 1;
												}
#else
												if (!strncasecmp(ext, ".js", 3)) { // .jsx ?
													status = SEND_TXT;
													TESTPRINT("Sending Txt response\n");
													response = httpnulltext;
													rsize = sizeof httpnulltext - 1;
												}
#endif
												/* add other response types here */
											}
										}
									}
								}
							}
#ifdef SSL_RESP
						}
#endif
					}
				}
			}

			if (status != EXIT_FAILURE) {
#else // TEXT_REPLY
			{
				status = SEND_GIF;
				TESTPRINT("Sending a gif response\n");
#endif
				rv = send(new_fd, response, rsize, 0);

#ifdef DO_COUNT
				if (status == SEND_STATS) {
					free(response);
				}
#endif
#ifdef TExT_REPLY
				if (status == SEND_REDIRECT) {
					// free memory allocated by asprintf()
					free(location);
					location = NULL;
				}
#endif
				response = NULL;

				/* check for error message, but don't bother checking that all bytes sent */
				if (rv < 0) {
					MYLOG(LOG_WARNING, "send: %m");
					status = EXIT_FAILURE;
				}
			}

			/* clean way to flush read buffers and close connection */
			if (shutdown(new_fd, SHUT_WR) == OK) {
				do {
					/* Initialize the file descriptor set */
					FD_ZERO(&set);
					FD_SET(new_fd, &set);
					/* Initialize the timeout data structure */
					timeout.tv_sec = select_timeout;
					timeout.tv_usec = 0;
					/* select returns 0 if timeout, 1 if input available, -1 if error */
					select_rv = select(new_fd + 1, &set, NULL, NULL, &timeout);
				} while ((select_rv > 0) && (recv(new_fd, buf, CHAR_BUF_SIZE, 0) > 0));
			}

			shutdown(new_fd, SHUT_RD);
			close(new_fd);
			exit(status);
		}

		close(new_fd); // parent doesn't need this
	}

	return (EXIT_SUCCESS);
}

/* vim: set ts=4 sw=4 tw=0 noet : */
