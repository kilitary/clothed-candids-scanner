#pragma pack(1)

#include <ncurses.h>
#ifndef __USE_BSD
#define __USE_BSD         /* Using BSD IP header           */
#endif
#include <stdlib.h>
#define __FAVOR_BSD     /* Using BSD TCP header     */  
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>   /* Internet Protocol             */
     
#include <netinet/tcp.h>  /* Transmission Control Protocol */
#include <pcap.h>         /* Libpcap                       */
#include <string.h>       /* String operations             */       /* Standard library definitions  */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <vector>
#include <algorithm>
#include <pthread.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <mysql/mysql.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <sys/resource.h>
#include <ifaddrs.h>
#include <time.h>
#include <string>
#include <iostream>
#include <utility>
using namespace std;

//int sendsyn(u_int32 seq, u_int32 src_ip, u_int32 dst_ip, u_int16 src_prt,
//u_int16 dst_prt);
unsigned short in_cksum(unsigned short *addr, int len);

#define SLL_HDR_LEN	16		/* total header length */
#define SLL_ADDRLEN	8		/* length of address field */
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
struct sll_header {
	u_int16_t	sll_pkttype;	/* packet type */
	u_int16_t	sll_hatype;	/* link-layer address type */
	u_int16_t	sll_halen;	/* link-layer address length */
	u_int8_t	sll_addr[SLL_ADDRLEN];	/* link-layer address */
	u_int16_t	sll_protocol;	/* protocol */
};

/*
* The LINUX_SLL_ values for "sll_pkttype"; these correspond to the
* PACKET_ values on Linux, but are defined here so that they're
* available even on systems other than Linux, and so that they
* don't change even if the PACKET_ values change.
*/
#define LINUX_SLL_HOST		0
#define LINUX_SLL_BROADCAST	1
#define LINUX_SLL_MULTICAST	2
#define LINUX_SLL_OTHERHOST	3
#define LINUX_SLL_OUTGOING	4

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */

	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	//#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

#define TCPSYN_LEN 20
#define MAXBYTES2CAPTURE 2048

/* Pseudoheader (Used to compute TCP checksum. Check RFC 793) */
typedef struct pseudoheader
{
	u_int32_t src;
	u_int32_t dst;
	u_char zero;
	u_char protocol;
	u_int16_t tcplen;
} tcp_phdr_t;

typedef unsigned short u_int16;
typedef unsigned long u_int32;
