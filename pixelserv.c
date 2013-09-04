/*
* pixelserv.c a small mod to public domain server.c -- a stream socket server demo
* from http://beej.us/guide/bgnet/
* single pixel http string from http://proxytunnel.sourceforge.net/pixelserv.php
*/

#define VERSION "0.33"

#define BACKLOG 30              // how many pending connections queue will hold
#define CHAR_BUF_SIZE 1023      //surprising how big requests can be with cookies etc

#define DEFAULT_IP "0.0.0.0"    // default IP address = all
#define DEFAULT_PORT "80"       // the default port users will be connecting to

#define DEFAULT_USER "nobody"   // nobody used by dnsmasq

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
#include <net/if.h>             // for IFNAMSIZ
#include <pwd.h>                // for getpwnam
#include <ctype.h>

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

    p++;                        /* next byte */
  }

  if (strlen(hexstr) > 0) {
    /* print rest of buffer if not empty */
    printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
  }
}
#endif

/* http://stackoverflow.com/questions/2673207/c-c-url-decode-library */
void urldecode(char *decoded, const char *encoded)
{
    char d1;
    char d2;
    while (*encoded) {
        if ((*encoded == '%') &&
                ((d1 = encoded[1]) && (d2 = encoded[2])) &&
                (isxdigit(d1) && isxdigit(d2))) {
            if (d1 >= 'a')
                d1 -= 'A'-'a';
            if (d1 >= 'A')
                d1 -= ('A' - 10);
            else
                d1 -= '0';

            if (d2 >= 'a')
                d2 -= 'A'-'a';
            if (d2 >= 'A')
                d2 -= ('A' - 10);
            else
                d2 -= '0';

            *decoded++ = 16*d1+d2;
            encoded+=3;
        } else {
            *decoded++ = *encoded++;
        }
    }
    *decoded++ = '\0';
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
  SEND_BAD,
  SEND_SSL,
  SEND_REDIRECT
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
#endif
#ifdef SSL_RESP
volatile sig_atomic_t ssl = 0;
#endif
#endif                          // TEXT_REPLY
#ifdef DECODE_URL
volatile sig_atomic_t rdr = 0;
#endif
#endif                          // DO_COUNT

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
#ifdef DECODE_URL
        case SEND_REDIRECT:
          rdr++;
          break;
#endif
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
#endif                          // NULLSERV_REPLIES
#ifdef SSL_RESP
        case SEND_SSL:
          ssl++;
          break;
#endif
#endif                          // TEXT_REPLY
        }
      }
#endif                          // DO_COUNT
    };
    return;

#ifndef TINY
  case SIGTERM:                // Handler for the SIGTERM signal (kill)
    signal(sig, SIG_IGN);       // Ignore this signal while we are quiting
#ifdef DO_COUNT
  case SIGUSR1:
    syslog(LOG_INFO, "%d req, %d err, %d gif,"
#ifdef TEXT_REPLY
           " %d bad, %d txt"
#ifdef NULLSERV_REPLIES
           ", %d jpg, %d png, %d swf"
#endif
#ifdef SSL_RESP
           ", %d ssl"
#endif
#endif                          // TEXT_REPLY
#ifdef DECODE_URL
           ", %d rdr"
#endif
           , count, err, gif
#ifdef TEXT_REPLY
           , bad, txt
#ifdef NULLSERV_REPLIES
           , jpg, png, swf
#endif
#ifdef SSL_RESP
           , ssl
#endif
#endif                          // TEXT_REPLY
#ifdef DECODE_URL
           , rdr
#endif
        );

    if (sig == SIGUSR1) {
      return;
    }
#endif                          // DO_COUNT
    syslog(LOG_NOTICE, "exit on SIGTERM");
    exit(EXIT_SUCCESS);
#endif                          // TINY
  }
}


#ifdef TEST
void *get_in_addr(struct sockaddr *sa)  // get sockaddr, IPv4 or IPv6
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}
#endif

int main(int argc, char *argv[])        // program start
{
  int sockfd;                   // listen on sock_fd
  int new_fd;                   // new connection on new_fd
  struct sockaddr_storage their_addr;   // connector's address information
  socklen_t sin_size;
  int yes = 1;
  int n = -1;                   // to turn off linger2
#ifdef TEST
  char s[INET6_ADDRSTRLEN];
#endif
  int rv;
  char ip_addr[INET_ADDRSTRLEN] = DEFAULT_IP;
  int use_ip = 0;
  char buf[CHAR_BUF_SIZE + 1];

  char port[6] = DEFAULT_PORT;  // not sure how long this can be, use number if name too long
  int i;

  char ifname[IFNAMSIZ];

  char user[8] = DEFAULT_USER;  // used to be long enough
  struct passwd *pw;

#ifdef READ_FILE
  char *fname = NULL;
  int fsize;
#ifdef READ_GIF
  int do_gif = 0;
#endif
  int hsize = 0;
#ifdef DECODE_URL
  char *location;
#endif
  struct stat file_stat;
  FILE *fp;
#endif                          // READ_FILE

#ifdef DECODE_URL
  const char *httpredirect = 
      "HTTP/1.1 302 Found\r\n"
      "Location: %sn\r\n"
      "Content-type: text/plain\r\n"
      "Content-length: 0\r\n"
      "Connection: close\r\n\r\n";
#endif

  static unsigned char httpnullpixel[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-type: image/gif\r\n"
      "Content-length: 43\r\n"
      "Connection: close\r\n"
      "\r\n"
      "GIF89a\1\0\1\0\x80\0\0\xff\xff\xff\0\0\0\x21\xf9\4\1\0\0\0\0,\0\0\0\0\1\0\1\0\0\2\2\x44\1\0;";

#ifdef TEXT_REPLY
  static unsigned char httpnulltext[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-type: text/html\r\n"
      "Content-length: 0\r\n" "Connection: close\r\n" "\r\n";

  static unsigned char http501[] =
      "HTTP/1.1 501 Method Not Implemented\r\n" "Connection: close\r\n" "\r\n";

#ifdef NULLSERV_REPLIES
  static unsigned char httpnull_png[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-type: image/png\r\n"
      "Content-length: 114\r\n"
      "Connection: close\r\n"
      "\r\n"
      "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52"
      "\x00\x00\x00\x01\x00\x00\x00\x01\x01\x03\x00\x00\x00\x25\xdb\x56"
      "\xca\x00\x00\x00\x03\x73\x42\x49\x54\x08\x08\x08\xdb\xe1\x4f\xe0"
      "\x00\x00\x00\x06\x50\x4c\x54\x45\xff\xff\xff\x00\x00\x00\x55\xc2"
      "\xd3\x7e\x00\x00\x00\x02\x74\x52\x4e\x53\x00\xff\x5b\x91\x22\xb5"
      "\x00\x00\x00\x0a\x49\x44\x41\x54\x08\x99\x63\x60\x00\x00\x00\x02"
      "\x00\x01\xf4\x71\x64\xa6\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42"
      "\x60\x82";

  static unsigned char httpnull_jpg[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-type: image/jpeg\r\n"
      "Content-length: 142\r\n"
      "Connection: close\r\n"
      "\r\n"
      "\xff\xd8\xff\xdb\x00\x43\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01"
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
      "\x01\x01\x01\x01\x01\x01\x01\xff\xc0\x00\x0b\x08\x00\x01\x00\x01"
      "\x01\x01\x11\x00\xff\xc4\x00\x14\x00\x01\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\xff\xc4\x00\x14\x10\x01"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x7f\x0f\xff\xd9";

  static unsigned char httpnull_swf[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-type: application/x-shockwave-flash\r\n"
      "Content-length: 1386\r\n"
      "Connection: close\r\n"
      "\r\n"
      "\x88\x08\x02\x35\x00\x42\x75\x66\x66\x65\x72\x00\x4E\x61\x74\x69"
      "\x76\x65\x00\x6C\x6F\x61\x64\x00\x42\x75\x66\x66\x65\x72\x5F\x6C"
      "\x6F\x61\x64\x00\x70\x72\x6F\x74\x6F\x74\x79\x70\x65\x00\x64\x69"
      "\x66\x66\x00\x42\x75\x66\x66\x65\x72\x5F\x64\x69\x66\x66\x00\x66"
      "\x69\x6E\x64\x00\x42\x75\x66\x66\x65\x72\x5F\x66\x69\x6E\x64\x00"
      "\x73\x75\x62\x00\x42\x75\x66\x66\x65\x72\x5F\x73\x75\x62\x00\x74"
      "\x6F\x53\x74\x72\x69\x6E\x67\x00\x42\x75\x66\x66\x65\x72\x5F\x74"
      "\x6F\x53\x74\x72\x69\x6E\x67\x00\x49\x6D\x61\x67\x65\x00\x63\x6F"
      "\x6D\x70\x61\x72\x65\x00\x49\x6D\x61\x67\x65\x5F\x63\x6F\x6D\x70"
      "\x61\x72\x65\x00\x73\x61\x76\x65\x00\x49\x6D\x61\x67\x65\x5F\x73"
      "\x61\x76\x65\x00\x53\x6F\x63\x6B\x65\x74\x00\x63\x6C\x6F\x73\x65"
      "\x00\x53\x6F\x63\x6B\x65\x74\x5F\x63\x6C\x6F\x73\x65\x00\x65\x72"
      "\x72\x6F\x72\x00\x53\x6F\x63\x6B\x65\x74\x5F\x65\x72\x72\x6F\x72"
      "\x00\x73\x65\x6E\x64\x00\x53\x6F\x63\x6B\x65\x74\x5F\x73\x65\x6E"
      "\x64\x00\x63\x6C\x6F\x73\x65\x64\x00\x53\x6F\x63\x6B\x65\x74\x5F"
      "\x67\x65\x74\x5F\x63\x6C\x6F\x73\x65\x64\x00\x61\x64\x64\x50\x72"
      "\x6F\x70\x65\x72\x74\x79\x00\x54\x65\x73\x74\x00\x61\x64\x76\x61"
      "\x6E\x63\x65\x00\x54\x65\x73\x74\x5F\x61\x64\x76\x61\x6E\x63\x65"
      "\x00\x6D\x6F\x75\x73\x65\x5F\x6D\x6F\x76\x65\x00\x54\x65\x73\x74"
      "\x5F\x6D\x6F\x75\x73\x65\x5F\x6D\x6F\x76\x65\x00\x6D\x6F\x75\x73"
      "\x65\x5F\x70\x72\x65\x73\x73\x00\x54\x65\x73\x74\x5F\x6D\x6F\x75"
      "\x73\x65\x5F\x70\x72\x65\x73\x73\x00\x6D\x6F\x75\x73\x65\x5F\x72"
      "\x65\x6C\x65\x61\x73\x65\x00\x54\x65\x73\x74\x5F\x6D\x6F\x75\x73"
      "\x65\x5F\x72\x65\x6C\x65\x61\x73\x65\x00\x72\x65\x6E\x64\x65\x72"
      "\x00\x54\x65\x73\x74\x5F\x72\x65\x6E\x64\x65\x72\x00\x72\x65\x73"
      "\x65\x74\x00\x54\x65\x73\x74\x5F\x72\x65\x73\x65\x74\x00\x72\x61"
      "\x74\x65\x00\x54\x65\x73\x74\x5F\x67\x65\x74\x5F\x72\x61\x74\x65"
      "\x00\x71\x75\x69\x74\x00\x54\x65\x73\x74\x5F\x67\x65\x74\x5F\x71"
      "\x75\x69\x74\x00\x74\x72\x61\x63\x65\x00\x54\x65\x73\x74\x5F\x67"
      "\x65\x74\x5F\x74\x72\x61\x63\x65\x00\x6C\x61\x75\x6E\x63\x68\x65"
      "\x64\x00\x54\x65\x73\x74\x5F\x67\x65\x74\x5F\x6C\x61\x75\x6E\x63"
      "\x68\x65\x64\x00\x70\x72\x69\x6E\x74\x00\x73\x00\x49\x4E\x46\x4F"
      "\x3A\x20\x00\x45\x52\x52\x4F\x52\x3A\x20\x00\x96\x04\x00\x08\x00"
      "\x08\x01\x1C\x96\x02\x00\x08\x00\x4E\x1D\x96\x02\x00\x08\x00\x1C"
      "\x96\x04\x00\x08\x02\x08\x01\x1C\x96\x02\x00\x08\x03\x4E\x4F\x96"
      "\x02\x00\x08\x00\x1C\x96\x07\x00\x08\x04\x07\x00\x00\x00\x00\x43"
      "\x4F\x96\x02\x00\x08\x00\x1C\x96\x02\x00\x08\x04\x4E\x96\x04\x00"
      "\x08\x05\x08\x01\x1C\x96\x02\x00\x08\x06\x4E\x4F\x96\x02\x00\x08"
      "\x00\x1C\x96\x02\x00\x08\x04\x4E\x96\x04\x00\x08\x07\x08\x01\x1C"
      "\x96\x02\x00\x08\x08\x4E\x4F\x96\x02\x00\x08\x00\x1C\x96\x02\x00"
      "\x08\x04\x4E\x96\x04\x00\x08\x09\x08\x01\x1C\x96\x02\x00\x08\x0A"
      "\x4E\x4F\x96\x02\x00\x08\x00\x1C\x96\x02\x00\x08\x04\x4E\x96\x04"
      "\x00\x08\x0B\x08\x01\x1C\x96\x02\x00\x08\x0C\x4E\x4F\x96\x04\x00"
      "\x08\x0D\x08\x01\x1C\x96\x02\x00\x08\x0D\x4E\x1D\x96\x02\x00\x08"
      "\x0D\x1C\x96\x07\x00\x08\x04\x07\x00\x00\x00\x00\x43\x4F\x96\x02"
      "\x00\x08\x0D\x1C\x96\x02\x00\x08\x04\x4E\x96\x04\x00\x08\x0E\x08"
      "\x01\x1C\x96\x02\x00\x08\x0F\x4E\x4F\x96\x02\x00\x08\x0D\x1C\x96"
      "\x02\x00\x08\x04\x4E\x96\x04\x00\x08\x10\x08\x01\x1C\x96\x02\x00"
      "\x08\x11\x4E\x4F\x96\x02\x00\x08\x12\x9B\x05\x00\x00\x00\x00\x00"
      "\x00\x1D\x96\x02\x00\x08\x12\x1C\x96\x07\x00\x08\x04\x07\x00\x00"
      "\x00\x00\x43\x4F\x96\x02\x00\x08\x12\x1C\x96\x02\x00\x08\x04\x4E"
      "\x96\x04\x00\x08\x13\x08\x01\x1C\x96\x02\x00\x08\x14\x4E\x4F\x96"
      "\x02\x00\x08\x12\x1C\x96\x02\x00\x08\x04\x4E\x96\x04\x00\x08\x15"
      "\x08\x01\x1C\x96\x02\x00\x08\x16\x4E\x4F\x96\x02\x00\x08\x12\x1C"
      "\x96\x02\x00\x08\x04\x4E\x96\x04\x00\x08\x17\x08\x01\x1C\x96\x02"
      "\x00\x08\x18\x4E\x4F\x96\x03\x00\x02\x08\x01\x1C\x96\x02\x00\x08"
      "\x1A\x4E\x96\x09\x00\x08\x19\x07\x03\x00\x00\x00\x08\x12\x1C\x96"
      "\x02\x00\x08\x04\x4E\x96\x02\x00\x08\x1B\x52\x17\x96\x04\x00\x08"
      "\x1C\x08\x01\x1C\x96\x02\x00\x08\x1C\x4E\x1D\x96\x02\x00\x08\x1C"
      "\x1C\x96\x07\x00\x08\x04\x07\x00\x00\x00\x00\x43\x4F\x96\x02\x00"
      "\x08\x1C\x1C\x96\x02\x00\x08\x04\x4E\x96\x04\x00\x08\x1D\x08\x01"
      "\x1C\x96\x02\x00\x08\x1E\x4E\x4F\x96\x02\x00\x08\x1C\x1C\x96\x02"
      "\x00\x08\x04\x4E\x96\x04\x00\x08\x1F\x08\x01\x1C\x96\x02\x00\x08"
      "\x20\x4E\x4F\x96\x02\x00\x08\x1C\x1C\x96\x02\x00\x08\x04\x4E\x96"
      "\x04\x00\x08\x21\x08\x01\x1C\x96\x02\x00\x08\x22\x4E\x4F\x96\x02"
      "\x00\x08\x1C\x1C\x96\x02\x00\x08\x04\x4E\x96\x04\x00\x08\x23\x08"
      "\x01\x1C\x96\x02\x00\x08\x24\x4E\x4F\x96\x02\x00\x08\x1C\x1C\x96"
      "\x02\x00\x08\x04\x4E\x96\x04\x00\x08\x25\x08\x01\x1C\x96\x02\x00"
      "\x08\x26\x4E\x4F\x96\x02\x00\x08\x1C\x1C\x96\x02\x00\x08\x04\x4E"
      "\x96\x04\x00\x08\x27\x08\x01\x1C\x96\x02\x00\x08\x28\x4E\x4F\x96"
      "\x03\x00\x02\x08\x01\x1C\x96\x02\x00\x08\x2A\x4E\x96\x09\x00\x08"
      "\x29\x07\x03\x00\x00\x00\x08\x1C\x1C\x96\x02\x00\x08\x04\x4E\x96"
      "\x02\x00\x08\x1B\x52\x17\x96\x03\x00\x02\x08\x01\x1C\x96\x02\x00"
      "\x08\x2C\x4E\x96\x09\x00\x08\x2B\x07\x03\x00\x00\x00\x08\x1C\x1C"
      "\x96\x02\x00\x08\x04\x4E\x96\x02\x00\x08\x1B\x52\x17\x96\x03\x00"
      "\x02\x08\x01\x1C\x96\x02\x00\x08\x2E\x4E\x96\x09\x00\x08\x2D\x07"
      "\x03\x00\x00\x00\x08\x1C\x1C\x96\x02\x00\x08\x04\x4E\x96\x02\x00"
      "\x08\x1B\x52\x17\x96\x03\x00\x02\x08\x01\x1C\x96\x02\x00\x08\x30"
      "\x4E\x96\x09\x00\x08\x2F\x07\x03\x00\x00\x00\x08\x1C\x1C\x96\x02"
      "\x00\x08\x04\x4E\x96\x02\x00\x08\x1B\x52\x17\x96\x02\x00\x08\x31"
      "\x9B\x07\x00\x00\x01\x00\x73\x00\x27\x00\x96\x02\x00\x08\x32\x1C"
      "\x12\x9D\x02\x00\x1B\x00\x96\x04\x00\x08\x33\x08\x32\x1C\x47\x96"
      "\x07\x00\x07\x01\x00\x00\x00\x08\x01\x1C\x96\x02\x00\x08\x31\x52"
      "\x17\x1D\x96\x02\x00\x08\x15\x9B\x07\x00\x00\x01\x00\x73\x00\x27"
      "\x00\x96\x02\x00\x08\x32\x1C\x12\x9D\x02\x00\x1B\x00\x96\x04\x00"
      "\x08\x34\x08\x32\x1C\x47\x96\x07\x00\x07\x01\x00\x00\x00\x08\x01"
      "\x1C\x96\x02\x00\x08\x31\x52\x17\x1D\x00";
#endif

#ifdef SSL_RESP
  static unsigned char SSL_no[] = "\x15"        // Alert 21
      "\3\0"                    // Version 3.0
      "\0\2"                    // length 2
      "\2"                      // fatal
      "\x31";                   // 0 close notify, 0x28 Handshake failure 40, 0x31 TLS access denied 49
#endif
#endif                          // TEXT_REPLY

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
  int status = EXIT_FAILURE;    /* default return from child */

  /* command line arguments processing */
  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '-') {
      if ((i + 1) < argc) {
        switch (argv[i][1]) {
        case 'n':
          strncpy(ifname, argv[++i], IFNAMSIZ);
          ifname[IFNAMSIZ - 1] = '\0';
          break;
        case 'p':
          strncpy(port, argv[++i], sizeof port);
          port[sizeof port - 1] = '\0';
          break;
        case 'u':
          strncpy(user, argv[++i], sizeof user);
          user[sizeof user - 1] = '\0';
          break;
#ifdef READ_FILE
#ifdef READ_GIF
        case 'g':
          do_gif = 1;           // and fall through
#endif
        case 'f':
          fname = argv[++i];
          break;
#endif                          // READ_FILE
        default:
          error = 1;
        }
      } else {
        error = 1;
      }
    } else if (use_ip == 0) {   // assume its a listening IP address
      strncpy(ip_addr, argv[i], INET_ADDRSTRLEN);
      ip_addr[INET_ADDRSTRLEN - 1] = '\0';
      use_ip = 1;
    } else {
      error = 1;                // fix bug with 2 IP like args
    }
  }

  if (error) {
#ifndef TINY
    printf("Usage:%s" " [IP No/hostname (all)]"
           " [-p port (80)]"
           " [-n i/f (all)]"
           " [-u user (\"nobody\")]"
#ifdef READ_FILE
           " [-f response.bin]"
#ifdef READ_GIF
           " [-g name.gif]"
#endif
#endif                          // READ_FILE
           "\n", argv[0]);
#endif                          // TINY
    exit(EXIT_FAILURE);
  }

  openlog("pixelserv", LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
  syslog(LOG_INFO, "%s version: %s compiled: %s from %s", argv[0], VERSION,
         __DATE__ " " __TIME__, __FILE__);

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
#endif                          // READ_FILE

#ifndef TEST
  if (daemon(0, 0) != OK) {
    syslog(LOG_ERR, "failed to daemonize, exit: %m");
    exit(EXIT_FAILURE);
  }
#endif

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;    // AF_UNSPEC - AF_INET restricts to IPV4
  hints.ai_socktype = SOCK_STREAM;
  if (use_ip == 0) {
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;        // use my IP
  }

  rv = getaddrinfo(use_ip ? ip_addr : NULL, port, &hints, &servinfo);
  if (rv != OK) {
    syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(rv));
    exit(EXIT_FAILURE);
  }

  if ((sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) < 1) {
      syslog(LOG_ERR, "Failed to create socket: %m");
      exit(EXIT_FAILURE);
  }
  if ((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) != OK)
      /* only use selected i/f */
      || (strlen(ifname) > 1 && (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, IFNAMSIZ) != OK))
      /* send short packets straight away */
      || (setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &yes, sizeof(int)) != OK)
      /* try to prevent hanging processes in FIN_WAIT2 */
      || (setsockopt(sockfd, SOL_TCP, TCP_LINGER2, (void *)&n, sizeof n) != OK))
  {
    syslog(LOG_ERR, "Failed to setsockopt: %m");
    exit(EXIT_FAILURE);
  }

  if ((bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) != OK)
      || (listen(sockfd, BACKLOG) != OK)) {
    syslog(LOG_ERR, "Socket bind failure: %m");
    exit(EXIT_FAILURE);
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

  syslog(LOG_NOTICE, "Listening on %s %s:%s", ifname, use_ip ? ip_addr : "*", port);

  while (1) {                   /* main accept() loop */
    sin_size = sizeof their_addr;
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd < 1) {
      MYLOG(LOG_WARNING, "accept: %m");
      continue;
    }
#ifdef DO_COUNT
    count++;
#endif

    if (fork() == 0) {
      /* this is the child process */
      close(sockfd);            /* child doesn't need the listener */
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
      timeout.tv_sec = 2;
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
            char *method = strtok(buf, " ");
            if (method == NULL) {
              MYLOG(LOG_ERR, "null method");
            } else {
              TESTPRINT("method: '%s'\n", method);
              if (strcasecmp(method, "GET")) {
                MYLOG(LOG_ERR, "unknown method: %s", method);
                status = SEND_BAD;
                TESTPRINT("Sending 501 response\n");
                response = http501;
                rsize = sizeof http501 - 1;
              } else {
                status = DEFAULT_REPLY; // send default from here
                /* trim up to non path chars */
                char *path = strtok(NULL, " ");//, " ?#;=");     // "?;#:*<>[]='\"\\,|!~()"
                if (path == NULL) {
                  MYLOG(LOG_ERR, "null path");
                } else {
#ifdef DECODE_URL
                  /* pick out encoded urls (usually advert redirects) */
                  if (strstr(path, "=http") && strchr(path, '%')) {
                    TESTPRINT("decoding url\n");
                    char *decoded = malloc(strlen(path)+1);
                    urldecode(decoded, path);
                    /* double decode */
                    urldecode(path, decoded);
                    free(decoded);
                  }
                  TESTPRINT("path: '%s'\n", path);
                  if (strstr(path, "http://")) {
                    status = SEND_REDIRECT;
                    location = (char *) malloc(strlen(path));
                    strcpy(location, path);
                  } else
#endif
                  {
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
                        }
#else
                        if (!strncasecmp(ext, ".js", 3)) {        /* .jsx ? */
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
#else                           // TEXT_REPLY
      {
        status = SEND_GIF;
        TESTPRINT("Sending a gif response\n");
#endif

#ifdef DECODE_URL
        if (status == SEND_REDIRECT) {
            TESTPRINT("Sending a redirect: %s\n", location);
            char *url = strstr(location, "http://");
            char *boof = malloc(strlen(httpredirect) + strlen(location));
            sprintf(boof, httpredirect, url);
            rv = send(new_fd, boof, strlen(boof), 0);
            free(boof);
            free(location);
        } else
#endif
        {
            rv = send(new_fd, response, rsize, 0);
        }

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
          timeout.tv_sec = 2;
          timeout.tv_usec = 0;
          /* select returns 0 if timeout, 1 if input available, -1 if error */
          select_rv = select(new_fd + 1, &set, NULL, NULL, &timeout);
        } while ((select_rv > 0) && (recv(new_fd, buf, CHAR_BUF_SIZE, 0) > 0));
      }

      shutdown(new_fd, SHUT_RD);
      close(new_fd);
      exit(status);
    }

    close(new_fd);              // parent doesn't need this
  }

  return (EXIT_SUCCESS);
}

/*
V1	Proof of concept mstombs www.linkysinfo.org 06/09/09
V2	usleep after send to delay socket close 08/09/09
V3	TCP_NODELAY not usleep 09/09/09
V4	daemonize with syslog 10/09/09
V5	usleep back in 10/09/09
V6	only use IPV4, add linger and shutdown to avoid need for sleep 11/09/09
	Consistent exit codes and version stamp
V7	use shutdown/read/shutdown to cleanly flush and close connection
V8	add inetd and listening IP option
V9	minimalize
V10	make inetd mode compiler option -DINETD_MODE
V11	debug TCP_NODELAY back and MSG_DONTWAIT flag on send
V12	Change read to recv with MSG_DONTWAIT and add MSG_NOSIGNAL on send
V13	DONTWAIT's just trigger RST connection closing so remove
V14	Back to V8 fork(), add header "connection: close"" and reformat pixel def
V15	add command line options for variable port 2nd March 2010
V16	add command line option for ifname, add SO_LINGER2 to not hang in FIN_WAIT2
V17	only send null pixel if image requested, make most options compiler options to make small version
V18	move image file test back into TEST
V19	add TINY build which has no output.
V20	Remove default interface "br0" assignment"
	amend http header to not encourage server like byte requests"
	use CHAR_BUF_SIZE rather than sizeof
	try again to turn off FIN_WAIT2
V21	run as user nobody by default
V22	Use apache style close using select to timeout connection
	and not leave dormant processes lying around if browser doeesn't close connection cleanly
	use SIGURS1 for report count, not system signal SIGHUP - thanks Rodney
V23	be more selective about replies
V24	common signal_handler and minor mods to minimize size
	Fix V23 bugs and use null string and javascript detection by ~nephelim~
V25	test version for robust parsing of path
V26	timeout on recv, block signals in child, enhance stats collection, fix bug in "-u user"
V27	add error reply messages
V28	move log, add option to read nullpixel from file.
V29	add option to read gif from file
V30	tidy up
V31 development - add nullserv responses from https://github.com/flexiondotorg/nullserv 30/05/13
V32 Add candidate SSL response
*/
