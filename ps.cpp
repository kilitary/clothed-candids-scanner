/* ni0s priv8 */
#pragma pack(1)
#include "pkt.h"

#define MYSQLHOST "avalos.armed.us"
#define MYSQLUSER "pwned"
#define MYSQLPWD "pwned"
#define MYSQLDB "proxy"
#define MYSQLPORT 3307
using namespace std;
MYSQL *mysql=0;
MYSQL_RES *mysql_res=0;
bool verbose=true;
pthread_t t1, t2, t3, toffone;
pthread_mutex_t mysql_mutex = PTHREAD_MUTEX_INITIALIZER,
nc_mutex = PTHREAD_MUTEX_INITIALIZER,ncclr_mutex=PTHREAD_MUTEX_INITIALIZER,scanned_mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutexattr_t mysql_mutex_attr,nc_mutex_attr;
unsigned long scanned_ips = 0;
struct sockaddr_in msin;
vector<struct sockaddr_in> scanned;
vector<unsigned long> fake;
bool fast=true;
unsigned long scans_per_second=0;
time_t scanchecktime=0;
unsigned long drops=0;
bool continue_scan=true;
unsigned long ack_packets=0,other_packets=0,own_packets=0,sockscheck_packets=0,invalid_packets=0;
time_t mysql_optimize_time = 0;
unsigned long new_proxys=0;
unsigned long db_querys=0;
unsigned long db_querys_second=0;
unsigned long old_db_querys=0;
bool offone=false;
bool checkonly=true;
char target[128];
int scan_port=1080;
unsigned long checked_hosts=0;
unsigned long invalid_tcp=0;
unsigned long last_scans = 0;
bool demon=false;
bool networktest=false;
unsigned long dup_rnd=0;
unsigned long rst_packets=0;
unsigned long total_packets=0;
int speed_test_time=3;
int chkd_proxys=0;
int delay=1;
char opt;
int type=0;
pthread_attr_t tattr;
size_t stacksize;
bool show_scan_speed = false;
time_t st_time = time(NULL);
char q[1024];
struct sockaddr_in ip;
char addrs[255][16];
static unsigned long sc=0;
int nthreads=20;
int humandelay=0;
double bw_net=0;
int addrfound=0;
int auth_timeout=2;
int connect_timeout=1;
int request_timeout=4;
unsigned long network_ndelay = 35;
unsigned long sec_packets=0;
//typedef pair<long, string> dnsrec;
//vector<dnsrec> dns_requests;
pthread_mutex_t dns_requestsDataLock=PTHREAD_MUTEX_INITIALIZER;
#define PHI 0x9e3779b9
static uint32_t Q[4096], c = 362436;


void
deb(char *msg,...)
{
	//	return;
	//static bool busy=false;
	
//	while(busy) {
	//	usleep(200);
//	}
	//busy=true;
  va_list ap;

   FILE *logfile = fopen("log.txt","a");
   if(!logfile)
   		return;

   va_start(ap,msg);

//   if(demon) {
//   fprintf(logfile,"",);
      vfprintf(logfile,msg,ap);
//   } else {
//      fprintf(stderr,"[%2d %2d] ",total_mail_sent,id);
//      vfprintf(stderr,msg,ap);
//   }

   va_end(ap);
   fclose(logfile);
  // busy=false;
}

//
//char *ip2host(char *ip, bool cached=false)
//{
//	 struct hostent *hp;
//   long    addr;
//   
//   addr = inet_addr(ip);
//   
//   if(cached) {
//   		
//   		pthread_mutex_lock( &dns_requestsDataLock );
//      string out;  
//   		for(vector<dnsrec>::iterator it=dns_requests.begin();it!=dns_requests.end();it++)
//			{
//				dnsrec p;
//				
//				p = (*it);
//				if(p.first == addr) {
//					
//						out= p.second;
//						break;
//				}
//			}
//			pthread_mutex_unlock( &dns_requestsDataLock ); 
//			if(out.length())
//					return (char*)out.c_str();
//			
//			string s = "";
//			pthread_mutex_lock( &dns_requestsDataLock );
//   		dns_requests.push_back(make_pair(addr,s));
//   		pthread_mutex_unlock( &dns_requestsDataLock ); 
//   		return "";
//   	}
//
//   if (hp = gethostbyaddr((char *) &addr, sizeof(addr), AF_INET))
//				return hp->h_name;
//	return "";
//}
//
//void *async_resolver(void *arg)
//{
//	return NULL;
//	deb("async resolver started");
//	
//		if(mysql_thread_init())
//	{
//		perror("mysqlthread_init");
//		pthread_exit(0);
//	}
//	in_addr ia;
//	
//	while(continue_scan)
//	{
//		ia.s_addr = 0;
//		if(!dns_requests.size())
//		{
//			sleep(1);
//			continue;
//		}
//		
//		//vector<long>::iterator last;
//		pthread_mutex_lock( &dns_requestsDataLock );
//		for(vector<dnsrec>::iterator it=dns_requests.begin();it!=dns_requests.end();it++)
//		{
//			dnsrec p;
//			
//			p=(*it);
//			if(p.second.length())
//					continue;
//					
//			memcpy(&ia, &p.first, sizeof(ia));
//			deb("resolving (%d) %s ... ", dns_requests.size(), inet_ntoa(ia));
//			break;
//		}
//		
//		pthread_mutex_unlock( &dns_requestsDataLock );
//		if(!ia.s_addr)
//				continue;
//					
//			deb("%s\r\n", ip2host(inet_ntoa(ia)));
//			
//			if(strlen(ip2host(inet_ntoa(ia))))
//			{
//				pthread_mutex_lock( &dns_requestsDataLock );
//				for(vector<dnsrec>::iterator it=dns_requests.begin();it!=dns_requests.end();it++)
//				{
//					if((*it).first==  ia.s_addr)
//						(*it).second.assign(ip2host(inet_ntoa(ia)));
//				}
//				pthread_mutex_unlock( &dns_requestsDataLock ); 
//			}
//			else {
//				pthread_mutex_lock( &dns_requestsDataLock );
//				for(vector<dnsrec>::iterator it=dns_requests.begin();it!=dns_requests.end();it++)
//				{
//					if((*it).first == ia.s_addr)
//						dns_requests.erase(it);
//				}
//				pthread_mutex_unlock( &dns_requestsDataLock ); 
//				break;
//			}
//		ia.s_addr=0;
//	}
//}

struct in_addr  resolve(char *ip)
{
	struct hostent *he;
	struct in_addr a;
	
	a.s_addr=inet_addr(ip);
	if((a.s_addr)!=INADDR_NONE)
			return a;
	 he = gethostbyname (ip);
    if (he)
    {
       // printf("name: %s\n", he->h_name);
       // while (*he->h_aliases)
          //  printf("alias: %s\n", *he->h_aliases++);
        //while (*he->h_addr_list)
        //{
            bcopy(*he->h_addr_list, (char *) &a, sizeof(a));
           // printf("address: %s\n", inet_ntoa(a));
        //}
        return a;
    } else {
    	return a;
    }
}
void init_rand(uint32_t x)
{
	int i;

	Q[0] = x;
	Q[1] = x + PHI;
	Q[2] = x + PHI + PHI;

	for (i = 3; i < 4096; i++)
	Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}



uint32_t rand_cmwc(void)
{
	uint64_t t, a = 18782LL;
	static uint32_t i = 4095;
	uint32_t x, r = 0xfffffffe;
	i = (i + 1) & 4095;
	t = a * Q[i] + c;
	c = (t >> 32);
	x = t + c;
	if (x < c) {
		x++;
		c++;
	}
	return (Q[i] = r - x);
}

uint32_t mrand(unsigned long max=0)
{
	return (max ? rand_cmwc()%max : rand_cmwc());
}

void mysql_lock(MYSQL *m=0)
{
	pthread_mutex_lock(&mysql_mutex);
}
void mysql_unlock(MYSQL *m=0)
{
	pthread_mutex_unlock(&mysql_mutex);
}
bool mfree(void)
{
	bool ret;
	
	if(!pthread_mutex_trylock(&nc_mutex)){
			pthread_mutex_unlock(&nc_mutex);
			return true;
	}
	return false;
}
void mclreol(int x=0, int y=0)
{
	if(demon)
		return;
	
	pthread_mutex_lock(&nc_mutex);

	move(x,y);
	clrtoeol();
	pthread_mutex_unlock(&nc_mutex);
}
void
mprint(int x, int y, char *msg,...)
{
	if(demon)
		return;
		
		pthread_mutex_lock(&nc_mutex);
   va_list ap;

   va_start(ap,msg);
   
  

 	 char str[4096];
 	 vsprintf(str, msg, ap);
  	mvprintw(x,y,str);
	
   va_end(ap);
	//	refresh();
    pthread_mutex_unlock(&nc_mutex);
}


int mmysql_query(MYSQL *m, char *q)
{
	//fprintf(stderr,"\r\nmysql: %s",q);
	db_querys++;
	return mysql_real_query(m, q, strlen(q));
}
void loadscanned(void)
{
		printf("loading scanned ...");
		MYSQL_ROW row;
		MYSQL_RES *res;
		mmysql_query(mysql, "select ip from ip");
		res = mysql_store_result(mysql);
		while(row = mysql_fetch_row(res))
		{
			char ip[128];
			strcpy(ip,row[0]);
			struct sockaddr_in a;
			a.sin_addr.s_addr = inet_addr(ip);
			scanned.push_back(a);
		}
		mysql_free_result(res);
	
}

bool isscanned(struct sockaddr_in addr)
{
	
	pthread_mutex_lock(&scanned_mutex);
	bool a=false;
	for(vector<struct sockaddr_in>::iterator it=scanned.begin();it!=scanned.end();it++)
	{
		if((*it).sin_addr.s_addr == addr.sin_addr.s_addr)
			a= true;
	}
	pthread_mutex_unlock(&scanned_mutex);
	return a;
}

int sendsyn(u_int32 seq, u_int32 src_ip, u_int32 dst_ip, u_int16 src_prt,
u_int16 dst_prt)
{
	static int i = 0;
	int one = 1; /* R.Stevens says we need this variable for the setsockopt call*/
	

	//fprintf(stderr, "%u %u \r\n",src_ip,dst_ip);
	/* Raw socket file descriptor */
	int rawsocket = 0;

	/* Buffer for the TCP/IP SYN Packets */
	char packet[sizeof(struct tcphdr) + sizeof(struct ip) + 1];

	/* It will point to start of the packet buffer */
	struct ip *ipheader = (struct ip*)packet;

	/* It will point to the end of the IP header in packet buffer */
	struct tcphdr *tcpheader = (struct tcphdr*)(packet + sizeof(struct ip));

	/* TPC Pseudoheader (used in checksum)    */
	tcp_phdr_t pseudohdr;

	/* TCP Pseudoheader + TCP actual header used for computing the checksum */
	char tcpcsumblock[sizeof(tcp_phdr_t) + TCPSYN_LEN];

	/* Although we are creating our own IP packet with the destination address */
	/* on it, the sendto() system call requires the sockaddr_in structure */
	struct sockaddr_in dstaddr, srcaddr;

	memset(&pseudohdr, 0, sizeof(tcp_phdr_t));
	memset(&packet, 0, sizeof(packet));
	memset(&dstaddr, 0, sizeof(dstaddr));

	dstaddr.sin_family = AF_INET; /* Address family: Internet protocols */
	dstaddr.sin_port = dst_prt; /* Leave it empty */
	dstaddr.sin_addr.s_addr = dst_ip; /* Destination IP */
	
	srcaddr.sin_addr.s_addr = src_ip;
	
	//fprintf(stderr, "%s => %s %u %u", src, inet_ntoa(dstaddr.sin_addr),
	//	srcaddr.sin_addr.s_addr, dstaddr.sin_addr.s_addr);

	/* Get a raw socket to send TCP packets */
	if ((rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
	{
		perror("synsend():socket()");
		return -1;
	}

	/* We need to tell the kernel that we'll be adding our own IP header */
	/* Otherwise the kernel will create its own. The ugly "one" variable */
	/* is a bit obscure but R.Stevens says we have to do it this way ;-) */
	if (setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
	{
		perror("synsend():setsockopt()");
		return -1;
	}


	/* IP Header */
	ipheader->ip_hl = 5; /* Header lenght in octects                       */
	ipheader->ip_v = 4; /* Ip protocol version (IPv4)                     */
	ipheader->ip_tos = 0; /* Type of Service (Usually zero)                 */
	ipheader->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
	ipheader->ip_off = 0; /* Fragment offset. We'll not use this            */
	ipheader->ip_ttl = (rand()%2) ? 128 : 64; /* Time to live: 64 in Linux, 128 in Windows...   */
	ipheader->ip_p = 6; /* Transport layer prot. TCP=6, UDP=17, ICMP=1... */
	ipheader->ip_sum = 0; /* Checksum. It has to be zero for the moment     */
	ipheader->ip_id = htons(rand());
	ipheader->ip_src.s_addr = src_ip; /* Source IP address                    */
	ipheader->ip_dst.s_addr = dst_ip; /* Destination IP address               */
	if(!fast && memcmp(inet_ntoa(ipheader->ip_dst), "127.", 4) == 0) 
	{
	//	dup_packets++;
		close(rawsocket);
		return -1;
	}
	/* TCP Header */
	tcpheader->th_seq = htonl(rand()); /* Sequence Number                         */
	tcpheader->th_ack = htonl(0) ; /* Acknowledgement Number                  */
	tcpheader->th_x2 = 0; /* Variable in 4 byte blocks. (Deprecated) */
	tcpheader->th_off = 5; /* Segment offset (Lenght of the header)   */
	tcpheader->th_flags = TH_SYN; /* TCP Flags. We set the Reset Flag        */
	tcpheader->th_win = htons(4000+(rand()%5000)); /* Window size
	*/
	tcpheader->th_urp = 0; /* Urgent pointer.                         */
	tcpheader->th_sport = src_prt; /* Source Port                             */
	tcpheader->th_dport = dst_prt; /* Destination Port                        */
	tcpheader->th_sum = 0; /* Checksum. (Zero until computed)         */

	/* Fill the pseudoheader so we can compute the TCP checksum*/
	pseudohdr.src = ipheader->ip_src.s_addr;
	pseudohdr.dst = ipheader->ip_dst.s_addr;
	pseudohdr.zero = 0;
	pseudohdr.protocol = ipheader->ip_p;
	pseudohdr.tcplen = htons(sizeof(struct tcphdr));

	/* Copy header and pseudoheader to a buffer to compute the checksum */
	memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));
	memcpy(tcpcsumblock + sizeof(tcp_phdr_t), tcpheader, sizeof(struct tcphdr));

	/* Compute the TCP checksum as the standard says (RFC 793) */
	tcpheader->th_sum = in_cksum((unsigned short*)(tcpcsumblock), sizeof
	(tcpcsumblock));

	/* Compute the IP checksum as the standard says (RFC 791) */
	ipheader->ip_sum = in_cksum((unsigned short*)ipheader, sizeof(struct ip));
	int r;
	/* Send it through the raw socket */
	if ((r=sendto(rawsocket, packet, ipheader->ip_len, 0, (struct sockaddr*)
				&dstaddr, sizeof(dstaddr))) <= 0)
	{
		if(networktest) 
		{
			char asrc[128],adst[128];
			strcpy(asrc,inet_ntoa(ipheader->ip_src));
			strcpy(adst,inet_ntoa(ipheader->ip_dst));
			perror("sendsyn():sendto");
			fprintf(stderr,"%s => %s\r\n", asrc, adst);
			usleep(network_ndelay*3000);
		}
		if(errno!=22 && errno!=49)
			{
				mclreol(1,0);
			mprint(1,0,"%s: %s (%d)", inet_ntoa(dstaddr.sin_addr), strerror(errno),errno);
		}
		if(errno==1) {
				//fprintf(stderr,"sleep ");
			//	sleep(1);
			}
		drops++;
		close(rawsocket);
		return  -1;
	}

	// fprintf(stderr,"Sent SYN Packet (len %d): %s:%d\n",r,inet_ntoa(ipheader->ip_dst),ntohs(tcpheader->th_dport));
	//  printf("   SRC: %s:%d\n", inet_ntoa(ipheader->ip_src), ntohs(tcpheader
	//    ->th_sport));

	// printf("   Seq=%u\n", ntohl(tcpheader->th_seq));
	// // printf("   Ack=%d\n", ntohl(tcpheader->th_ack));
	//  printf("   TCPsum: %02x\n", tcpheader->th_sum);
	//  printf("   IPsum: %02x\n", ipheader->ip_sum);

	close(rawsocket);

	return 0;


} /* End of IP_Id_send() */

unsigned short in_cksum(unsigned short *addr, int len)
{

	register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;

	/*
	* Our algorithm is simple, using a 32-bit accumulator (sum),
	* we add sequential 16-bit words to it, and at the end, fold back
	* all the carry bits from the top 16 bits into the lower 16 bits.
	*/

	while (nleft > 1)
	{
		sum +=  *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
	{
		*(u_char*)(&answer) = *(u_char*)w;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum &0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */
	answer = ~sum; /* truncate to 16 bits */
	return (answer);

} /* End of in_cksum() */

/* check_host */

 long countquery(char *q)
{
	time_t sttime;
	sttime=time(NULL);
	long count;
	mysql_lock();
	
	if(mmysql_query(mysql, q))
	{
		//mprint(1,0, "mysql: %s", mysql_error(mysql));
		deb("\r\n\r\nmysql(%s): %s\r\n", q, mysql_error(mysql));
	}
	
		MYSQL_ROW row;
		MYSQL_RES *res;
		res = mysql_store_result(mysql);

		
		if(res)
		{
			row = mysql_fetch_row(res);
			
			if(row!=NULL && row[0])
			{
				
				
					count=atol(row[0]);
				
			}
			mysql_free_result(res);
		}

	mysql_unlock();

	if(time(NULL)-sttime >= 50)
			deb("countquery: %d %s\r\n",time(NULL)-sttime , q);

	return count;
}


int query(char *q, bool ret=false)
{
	time_t sttime;
	sttime=time(NULL);
	
	mysql_lock();
	
	//		mclreol(3,0);
//	mprint(3,0, "%s", q);
	//printf("q %s\r\n",q);
	if(mmysql_query(mysql, q)) 
	{
		//mprint(1,0, "mysql: %s", mysql_error(mysql));
		deb("\r\n\r\nmysql(%s): %s\r\n", q, mysql_error(mysql));
		
	//	exit(0);
		//refresh();
	}
	int num=0;
	if(ret)
	{
		mysql_res = mysql_store_result(mysql);

		//	printf("%s: %d\r\n",query,num);
		if(mysql_res) {
			num=mysql_num_rows(mysql_res);
			mysql_free_result(mysql_res);
		}
	}
	mysql_unlock();
//	if(time(NULL) - sttime >= 4)
//		{
//		//move(0,40);
//		mclreol(69,40);
//		mprint(69,40,"WARNING - '%s' take %d seconds", q, time(NULL)-sttime);
//		//refresh();
//	}
	//move(4,0);

	//refresh();
	//fprintf(stderr,"\r\nsql: %s in %d secs",query,time(NULL)-sttime);
	if(time(NULL)-sttime >= 50)
			deb("%d %s\r\n",time(NULL)-sttime , q);
	
//	if(time(NULL)-sttime>=2) {
//			connect_timeout+=3;
//			request_timeout+=3;
//		}
//	else {
//			if(request_timeout>=4)
//					request_timeout-=1;
//			if(connect_timeout>=4)
//					connect_timeout-=1;
//		}
	
	
	
//	struct sched_param param;
//	memset(&param, 0, sizeof(param));
//	param.sched_priority = 2;
//	pthread_setschedparam(pthread_self(), SCHED_RR, &param);

	return num;
}

int ipindb(in_addr saddr)
{
	//return isscanned
	struct sockaddr_in s;
	s.sin_addr=saddr;
//	if(fast)
//			return isscanned(s);
	char q[1024];
	sprintf(q, "select ip from ip where ip = '%s'", inet_ntoa(saddr));
	int ret;
	ret=query(q,true);
//	fprintf(stderr,"check %s:%d\r\n",q,ret);
	return ret;
}

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	if(demon)
		return;
	
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{
	struct sniff_ip *ip;
	struct sniff_ip *ip2;
	struct sniff_tcp *tcp;
	struct sniff_tcp *tcp2;
	struct sniff_ethernet *eth;
	struct sll_header *sllhdr;
	struct sockaddr_in sip;
	static unsigned long honeyrepeats=0;
	int offset;
	//if(h->len==60)
	//	return;

	if(networktest)
		fprintf(stderr,"process_packet(%x, %x, %x)\r\n", user,h,packet);
	
	sec_packets++;
	total_packets++;
	
	eth=(struct sniff_ethernet*) packet;
	sllhdr = (struct sll_header*) packet;
	offset= (type==113 ? 16 : SIZE_ETHERNET);
	ip = (struct sniff_ip*) &packet[offset];
	
	sip.sin_addr.s_addr = ip->ip_src.s_addr;
		
	if(isscanned(sip))
	{
		if(networktest)
			fprintf(stderr,"isscanned=true(%s)\r\n", inet_ntoa(ip->ip_src));
			return;
	}
	
	vector<unsigned long>::iterator  fff;
		
	//find(fake.begin(),fake.end(), (unsigned long)ip->ip_src.s_addr);
	if( (fff = find(fake.begin(),fake.end(), (unsigned long)ip->ip_src.s_addr)) != fake.end()) 
	{
		mclreol(4,0);
		mprint(4,0,"honey #%4d %s (known: %d)", honeyrepeats++, inet_ntoa(ip->ip_src), fake.size());
		return;
	}

	int size_ip;
	size_ip = (IP_HL(ip)*4);
	
	if (size_ip < 20)
	{
		invalid_packets++;
		fprintf(stderr,"Invalid IP header length: %u bytes, type %x", size_ip, *packet);
		mprint(1,0,"Invalid IP header length: %u bytes, type %x #%4d ", size_ip, *packet, invalid_packets);
		//refresh();
		return;
	} 
	
	for(int i=0;i<addrfound;i++)
	{
		if(inet_addr(addrs[addrfound]) == ip->ip_src.s_addr)
		{
			own_packets++;
			mprint(4,0,"own packet %s", inet_ntoa(ip->ip_src));
			return;
		} 
	}
//	if(msin.sin_addr.s_addr == ip->ip_src.s_addr || msin.sin_addr.s_addr == ip->ip_dst.s_addr)
//	{
//		sockscheck_packets++;
//		mprint(4,0,"sockscheck packet %s", inet_ntoa(ip->ip_src));
//		return;
//	}
//	
	tcp = (struct sniff_tcp*) &packet[offset+size_ip];
	
	int size_tcp=0;
	size_tcp = TH_OFF(tcp)*4;
	
	if (size_tcp < 20) 
	{
		mprint(1,0,"Invalid TCP header length: %u bytes #%4d ",size_tcp, invalid_tcp);

		invalid_tcp++;
		return;
	}
	char sflags[128];
	
	memset(sflags,0,sizeof(sflags));
	
	
		
	if(tcp->th_flags & TH_RST)
	{
		strcat(sflags, "RST ");
		rst_packets++;
	}
	if(tcp->th_flags & TH_FIN)
		strcat(sflags, "FIN ");
	if(tcp->th_flags & TH_SYN)
		strcat(sflags, "SYN ");
	if(tcp->th_flags & TH_URG)
		strcat(sflags, "URG ");
	if(tcp->th_flags & TH_PUSH)
		strcat(sflags, "PUSH ");
	if(tcp->th_flags & TH_ACK) {
		ack_packets++;
		strcat(sflags, "ACK ");
	}

//		mclreol(1,0);
//		mprint(1,0, "pkt %2d capt %d (ip %2d,tcp %2d) from %15s:%d %s", h->len,  h->caplen,size_ip, size_tcp,
	//		inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), sflags);
	if(tcp->th_flags & TH_ACK && tcp->th_flags & TH_SYN)
	{
		if(verbose && networktest)
			fprintf(stderr,"ACK & SYN set %s\r\n", inet_ntoa(ip->ip_src));
			
		//print_payload(packet, h->caplen);
		
		char q[1024];
		//if(isscanned(sip))
		//{
//				if(verbose && networktest)
//						fprintf(stderr,"%s skipped, already scanned\r\n", inet_ntoa(ip->ip_src));
//			sprintf(q, "update ip set status = 0 where ip = '%s'", inet_ntoa(ip->ip_src));
//			query(q);
		//} else {
			if(!ipindb(sip.sin_addr))
			{
				sprintf(q, "insert into ip set status = 0, ip = '%s'", inet_ntoa(ip->ip_src));
				query(q);
			} else {
				if(verbose && networktest)
						fprintf(stderr,"%s skipped, in db\r\n", inet_ntoa(ip->ip_src));
			}
			
			pthread_mutex_lock(&scanned_mutex);
			
			scanned.push_back(sip);
			pthread_mutex_unlock(&scanned_mutex);
		//}
		//fprintf(stderr,"\r\n");
	} else {
		other_packets++;
	}
		if(verbose) {
			mclreol(3,0);
			mprint(3,0,"packet #%-8lu %-16s %-10s",total_packets, inet_ntoa(ip->ip_src), sflags);
			
		}
		if(verbose&&networktest) {
			deb("packet #%-8lu %-16s %-10s\r\n",total_packets, inet_ntoa(ip->ip_src), sflags);
			
				fprintf(stderr,"packet #%-8lu %-16s %-10s",total_packets, inet_ntoa(ip->ip_src), sflags);
		}
	
}

void
segv(int)
{
	deb("\r\n\r\n!!! sigsegv!");
	fprintf(stderr,"\r\n\r\n       sigsegv! sigsegv!sigsegv! sigsegv!sigsegv! sigsegv!\r\n\r\n      \r\n");
	exit(-1);
}

void
sig_timeout(int)
{
	signal(SIGALRM, SIG_IGN);
	//printf("signal");
	alarm(0);
}

void
set_timeout(int t)
{
	if (t) {
		signal(SIGALRM, sig_timeout);
		alarm(t);
	} else {
		alarm(0);
	}
}

int check_proxy(char *ip, int port, int nc_line, int how=0)
{
	int             s, r;
	
	char            req[1024];
	char            rep[1024];
	//static char    *buf = NULL;
	char buf[56000];

	struct sockaddr_in msin;

//	if (!buf) {
//		buf = (char *)malloc(1024);
//		if (!buf) {
//			fprintf(stderr, "malloc error: %s",strerror(errno));
//			exit(1);
//		}
//	}
	checked_hosts++;
	bzero(&msin, sizeof(msin));
	msin.sin_family = AF_INET;
	msin.sin_port = htons(port);
	msin.sin_addr = resolve(ip);
	

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) == NULL) {
		perror("socket");
		_exit(1);
	}
		int on=1;
	ioctl(s, FIONBIO, (int *)&on);
	//set_timeout(delay);
	//move(3,0);
	mclreol(nc_line,0);
	//refresh();
	char *what;
	switch(how)
	{
		case 0:
			what="proxchk";
		break;
		case 2:
			what="fastchk";
		break;
		default:
			what="unk";
		break;
	}
		mprint(nc_line,0,"%s %15s:%-4d",what, inet_ntoa(msin.sin_addr),port);
		//refresh();
	//set_timeout(3);
	//errno = 0;
	
	
	time_t sttime=time(NULL);
	//move(nc_line,30);
	mclreol(nc_line,30);
	mprint(nc_line,30,"connecting  ... ");
	
	struct timespec nsttime,ncurtime;
	clock_gettime(CLOCK_REALTIME, &nsttime);
	unsigned long connect_ntime;
	connect_ntime = connect_timeout * 1000 ;
	
	if(verbose&&networktest)
		fprintf(stderr,"\r\nproxychk connecting %s:%-d\r\n", ip,port);
//	mprint(nc_line, 30, "connect timeout: %lu",connect_ntime);
//	sleep(1);
	while (true)
	{
	//	mprint(nc_line, 30, "connect timeout: %lu",connect_ntime);
	//sleep(1);
		clock_gettime(CLOCK_REALTIME, &ncurtime);
		r = connect(s, (struct sockaddr *) & msin, sizeof(msin));
		//printf("r %d ",r);
		if(!r || errno==56)
			break;
		
		if(connect_ntime <= 0 )
		{
				close(s);
				mprint(nc_line, 30, "connect timeout: %s",strerror(errno));
				if(verbose&&networktest)
					fprintf(stderr,"connect timeout: %s-%d (left %lu)",strerror(errno),errno,connect_ntime);
				//refresh();
				return 33;
		} else {
			//move(nc_line,0);
			mclreol(nc_line,30);
			
			if(connect_ntime >= network_ndelay)
				connect_ntime -= network_ndelay;
			else
				connect_ntime = 0;
			mclreol(nc_line, 30);
			mprint(nc_line,30,"connecting %.2f ... ",
				(float)connect_ntime/1000.0);
			//refresh();
		}
				
	
		usleep(network_ndelay*1000);
	}
	//ip2host(ip,true);
	if(verbose&&networktest)
		fprintf(stderr,"\r\nconnected <=> %s:%d requesting data ...\r\n", ip,port);

	if(verbose&&networktest)
		fprintf(stderr,"requesting signature data ...\r\n");

	char q[1024];
	on=0;
	ioctl(s, FIONBIO, (int *)&on);
	sprintf(q,"GET http://www.showip.com/ HTTP/1.0\r\nHost: www.showip.com\r\nUser-Agent: GBot 2.1\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n");
	send(s, q, strlen(q), 0);
	on=1;
	ioctl(s, FIONBIO, (int *)&on);
	
	bzero(buf, sizeof(buf));
	sttime=time(NULL);
	int totr=0;

	clock_gettime(CLOCK_REALTIME, &nsttime);

	connect_ntime = request_timeout * 1000 ;
	char reply[128]="";
	reply[0]=0;
	int httpcode=0;
	memset(buf,0,sizeof(buf));
	while((r = recv(s, &buf[totr], 1500, 0)))
	{
		if(r>0)
		{
			connect_ntime=request_timeout * 1000 ;
			totr+=r;
			if(totr>=(sizeof(buf)-1600)) {
				deb("\r\ntoo much buf daata");
				break;
			}
		}
		clock_gettime(CLOCK_REALTIME, &ncurtime);
		if(connect_ntime <= 0 )
		{
				//move(nc_line,30);
			mclreol(nc_line, 30);
			mprint(nc_line,30, "timeout reading");
			//refresh();
			close(s);
			return 7;
		}
		char sver[128]="<unscanned>";
		char readstr[1024]="";
		unsigned servsum=0;
		if(totr)
		{
			memcpy(reply, buf,13);
			for(int i=0;i<13;i++)
				if(reply[i]==0x0a ||reply[i]==0x0d||!isalnum((int)reply[i]))
						reply[i]=0x20;
			buf[14]=0x0;
			char *serv;
			serv = strstr(buf, "HTTP/1.");
			if(serv) 
			{
					httpcode=atoi(&serv[9]);
					if(httpcode==404||httpcode==403||httpcode==401)
					{
						mclreol(nc_line, 30);
						mprint(nc_line, 30, "%d: ACCESS DENIED",httpcode);
					//	deb("%s aces denied %d %s\r\n",ip, httpcode,buf);
						close(s);
						return 13;
					}

				
				strcpy(sver,"<defunct>");
				if(serv=strstr(buf,"Server:"))
					{
				sscanf(serv,"Server: %s\r\n", sver);
				strcat(reply, " # ");
				strcat(reply,sver);
			}
				char spow[128];
				strcpy(spow,"<defunct>");
				serv=strstr(buf,"X-Powered-By: ");
				if(serv)
					{
						sscanf(serv,"X-Powered-By: %s\r\n", spow);
						strcat(reply, " Powered: ");
						strcat(reply,spow);
					}
				if(totr>256)
					servsum=in_cksum((unsigned short*)spow,strlen(spow)) +in_cksum((unsigned short*)sver,strlen(sver));
				else if(totr<128)
					servsum=in_cksum((unsigned short*)buf,totr);
			} 
						
			sprintf(readstr, "%-6d CRC: %5d [%4d %s]",totr,servsum,httpcode, reply);
			if(	strstr(buf, "Your IP address is <b><big><big>"))
			{
					
					char zip[128]="";
					char *sip;
					sip=strstr(buf,"<b><big><big>");
					if(sip)
						{
							sscanf(sip,"<b><big><big>%[^<]</big>",zip);
							if(strlen(zip))
							{
								strcat(readstr," ext: ");
								strcat(readstr,zip);
								deb("%s:%d - %s external ip %s ccrc %x\r\n", ip,port,sver,zip,servsum);
							}
						}
			}
			
			
		}
		
		
			if(connect_ntime >= network_ndelay)
				connect_ntime -= network_ndelay;
			else
				connect_ntime = 0;
		mclreol(nc_line, 30);
		mprint(nc_line, 30, "%s %-3.2f    ... %s",totr?"reading":"waiting", (float)connect_ntime/1000.0, readstr
				);
		usleep(network_ndelay*1000);
	}
//	printf("recv %d %s",re,buf);
	char *checkaddr=NULL;
	if(totr)
			checkaddr = &buf[totr>=90?90:0];
	
	if (checkaddr && strstr(checkaddr, "Your IP address is <b><big><big>"))
	{
		shutdown(s,SHUT_RDWR);
		close(s);
		//move(nc_line,0);
		mclreol(nc_line, 30);
		mprint(nc_line,30, "signature found");
			//refresh();
		if(verbose&&networktest)
			fprintf(stderr,"working proxy - %s:%d\r\n", ip,port);
		
		char q[34095];
		char str[14097];
		memset(str,0x0,sizeof(str));
		memset(q,0x0,sizeof(q));
		//snprintf(str, 4096, "%s", buf);
	//	mysql_lock();
	//	buf[14096]=0;
	//	mysql_real_escape_string(mysql,  str, buf, totr);
		//str[4097]=0;
	//	mysql_unlock();
		//snprintf(q,sizeof(q)-1, "update ip set status = 1,rep = '%s' where ip = '%s' and port = %d",str, ip,scan_port);
	//	snprintf(q,sizeof(q)-1, "update ip set status = 1 where ip = '%s' and port = %d", ip,scan_port);
		//deb("log \"%s\"",q);
		//query(q);
		
		if(how!=2)
			{
		clock_gettime(CLOCK_REALTIME, &nsttime);
	mclreol(nc_line, 30);		
		mprint(nc_line, 30, "reconnecting ... ");
	connect_ntime = connect_timeout*2 * 1000 ;
		bzero(&msin, sizeof(msin));
	msin.sin_family = AF_INET;
	msin.sin_port = htons(port);
	msin.sin_addr = resolve(ip);
	if ((s = socket(PF_INET, SOCK_STREAM, 0)) == NULL) {
		perror("socket");
		_exit(1);
	}
	on=1;
	ioctl(s, FIONBIO, (int *)&on);
	while (true)
	{
	//	mprint(nc_line, 30, "connect timeout: %lu",connect_ntime);
	//sleep(1);
		clock_gettime(CLOCK_REALTIME, &ncurtime);
		r = connect(s, (struct sockaddr *) & msin, sizeof(msin));
		//printf("r %d ",r);
		if(!r || errno==56)
			break;
		
		if(connect_ntime <= 0 )
		{
				close(s);
				mprint(nc_line, 30, "connect timeout: %s",strerror(errno));
				if(verbose&&networktest)
					fprintf(stderr,"connect timeout: %s-%d (left %lu)",strerror(errno),errno,connect_ntime);
				//refresh();
				return 33;
		} else {
			//move(nc_line,0);
			mclreol(nc_line,30);
			
			if(connect_ntime >= network_ndelay)
				connect_ntime -= network_ndelay;
			else
				connect_ntime = 0;
			
			mprint(nc_line,30,"reconnecting %.2f ... ",
				(float)connect_ntime/1000.0);
			//refresh();
		}
				
	
		usleep(network_ndelay*1000);
	}
	char sspeed[128]="-";
	sprintf(sspeed,"%.2f sec", float(((connect_timeout*2 * 1000)  - connect_ntime))/1000);	
	on=0;
	ioctl(s, FIONBIO, (int *)&on);
	sprintf(q,"GET http://www.kernel.org/pub/linux/kernel/v3.0/linux-3.0.8.tar.bz2?force=%lu HTTP/1.0\r\n"
		"Host: www.kernel.org\r\n"
		"User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.106 Safari/535.2\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		"Accept-encoding: \r\nAccept-Language: en\r\n"
		"Accept-Charset: windows-1251,utf-8\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n",connect_ntime+rand());
	send(s, q, strlen(q), 0);
	on=1;
	ioctl(s, FIONBIO, (int *)&on);
	
	bzero(buf, sizeof(buf));
	sttime=time(NULL);
	

	clock_gettime(CLOCK_REALTIME, &nsttime);
	mclreol(nc_line, 30);		
		mprint(nc_line, 30, "estimating speed ... ");
		long init_speed;
		init_speed=speed_test_time+(connect_timeout/1000);
	connect_ntime = (init_speed) * 1000 ;
	totr=0;
	char *spbuf;
	int speed_buf_size=131072;
	spbuf=(char*)malloc(speed_buf_size);
	char reply[128]="\0";
	reply[0]=0;
	double speed=0.0;
	while((r = recv(s, spbuf, speed_buf_size, 0)))
	{
		if(r>0)
		{
			//if(!totr)
				//deb("calc speed: %s", spbuf);
				
		//	connect_ntime=speed_test_time * 1000 ;
			totr+=r;
//			if(totr>=speed_buf_size-1501)
//				break;
		}
		clock_gettime(CLOCK_REALTIME, &ncurtime);
		if(connect_ntime <= 0 )
		{
				//move(nc_line,30);
			mclreol(nc_line, 30);
			mprint(nc_line, 30, "throughput: %.2f KB/s",speed);
			deb("%s:%d - %.2f KB/s\r\n", ip,port,speed);
			//refresh();
			
			break;
		}
		
		if(connect_ntime >= network_ndelay)
				connect_ntime -= network_ndelay;
			else
				connect_ntime = 0;
				
			if(totr && strstr(spbuf,"Server:") && !reply[0])
			{
				memset(reply,0,sizeof(reply));
				snprintf(reply,8,"%s ", spbuf);
				//strcat(reply," ");
				strncat(reply, strstr(spbuf,"Server:")+7,20);
				for(int i=0;i<23;i++)
				if(reply[i]==0x0a ||reply[i]==0x0d)
						reply[i]=0x20;
			}
		mclreol(nc_line, 30);		
		
		
		speed=(float)totr/1024.0/ ((float)((float)init_speed-((float)connect_ntime/1000.0)));
		if(speed) {
			sprintf(sspeed,"%.2f KB/s",speed);
		}
		mprint(nc_line, 30, "examining speed %.2f ... %-9d %s",(float)connect_ntime/1000.0,totr, 
			sspeed);
		usleep(network_ndelay*1000);
	}
		close(s);
		free(spbuf);
		snprintf(q,sizeof(q)-1, "update ip set kbps= '%.2f' where ip = '%s' and port = %d",
			speed, ip,scan_port);
		query(q);
	}
		
		return 1;
		
	} else {
		close(s);
	//	deb("%d %d: %s",httpcode, totr, buf);
		mclreol(nc_line, 30);
		char rrep[128]="";
		if(strlen(buf)&&totr)
		{
			snprintf(rrep, 32, ": %s", buf);
			for(int i=0;rrep[i];i++)
				if(rrep[i]==0x0d||rrep[i]==0x0a||!isalnum((int)rrep[i]))
					rrep[i]='.';
		}
		mprint(nc_line,30, "signature not found %d ",totr);
		char q[14095];
		char str[32768];
		memset(str,0x0,5000);
		//snprintf(str, 4096, "%s", buf);
		mysql_lock();
		buf[4097]=0;
		mysql_real_escape_string(mysql,  str, buf, totr > 16384 ? 16384 : totr);
		//str[4097]=0;
		
		snprintf(q,sizeof(q)-1, "update ip set status = -3,rep = '%s' where ip = '%s' and port = %d",str, ip,scan_port);
		//deb("log \"%s\"",q);
		query(q);
		mysql_unlock();
	//	deb("honeypot %s:%d\r\n", ip,port);
		if(verbose&&networktest)
			fprintf(stderr,"maybe honeynets proxy - %s:%d [filtered content]\r\n", ip,port);
		//refresh();
		
		return 9;
	}
	
	
	
	return 99;
}

void mysqloptimize(void)
{
	//if(demon)
	//	return;
		
	while(!mysql)
		sleep(1);
		
	if(!demon)
		deb( "%x optimizing ip ... ",mysql);

//	query("use socks");
	query("optimize table ip");
	if(!demon)
		deb( "%x analyzing tables ... ",mysql);
	query("analyze table ip");

	if(!demon)
		deb("done\r\n");
		
	mysql_optimize_time = time(NULL);
}

void *send_packets(void *arg)
{
	unsigned char *p_ip;
	unsigned long ul_dst;
	unsigned long cursent=0;
	
	while(continue_scan)
	{
		
		if(time(NULL)-scanchecktime >= 1)
		{
			scans_per_second = scanned_ips - sc;
			scanchecktime = time(NULL);
			sc = scanned_ips;
			db_querys_second=db_querys-old_db_querys;
			old_db_querys=db_querys;
			
			if(networktest) {
				fprintf(stderr,"scanned %lu ips, drops %lu \r\n",scanned_ips, drops);
				scanned_ips=0;
				drops=0;
			}
		}
	
		for(unsigned i=rand_cmwc()%4;i>1;i--)
			rand_cmwc();
			
		p_ip = (unsigned char*) &ul_dst;
		for(int i=0;i<sizeof(unsigned long);i++)
			*p_ip++ = rand_cmwc()%255;
	//	ul_dst=inet_addr("204.12.227.184");
		//ul_dst=rand_cmwc();
	//	ul_dst = rand();
		if(networktest) {
			ul_dst = inet_addr("46.254.18.161");
			scan_port = 444;
		}
		ip.sin_addr.s_addr = ul_dst;//
	//	memcpy(&ul_dst, &ip.sin_addr.s_addr, sizeof(ul_dst));
		
		// check for already tested
		if(!fast && isscanned(ip))
		{
//		//sprintf(q, "select ip from ip where ip='%s'",inet_ntoa(ip));
//		//int num=query(q,true);
//		//if(num) {
//		//	printf("already %s\r\n", inet_ntoa(ip.sin_addr));
			dup_rnd++;
			continue;
		}

		// insert checkd ip

	//	sprintf(q, "insert into ip set ip = '%s', status = -1", inet_ntoa(ip.sin_addr));
	//	query(q);
		
//		if(!fast)
//		{
//			pthread_mutex_lock(&scanned_mutex);
//			scanned.push_back(ip);
//			pthread_mutex_unlock(&scanned_mutex);
//		}
		if(networktest&&verbose)
				fprintf(stderr,"target: %s ", inet_ntoa(ip.sin_addr));
		
		unsigned long srcaddr;
		
		if(humandelay)
				delay=humandelay;
				
		srcaddr = inet_addr(addrs[rand()%addrfound]);
		if(sendsyn(rand(), srcaddr, ul_dst, htons(rand()%65535), htons(scan_port)) != -1)
		{
			scanned_ips++;
			if(networktest&&verbose)
				fprintf(stderr," OK\r\n");
		//	if(delay)
		//		usleep(delay*1000);
		} else {
			if(networktest&&verbose)
			fprintf(stderr,"! %s:%s\r\n", strerror(errno),inet_ntoa(ip.sin_addr));
		
		
//			if(errno!=22&&errno!=49) 
//				{
//					delay=drops;
//					mclreol(1,0);
//					mprint(1,0,"delay set to %d (error %d: %s)", delay, errno, strerror(errno));
//				}
//				else if(fast) {
//					
//					if(delay){
//						mclreol(1,0);
//						mprint(1,0,"delay set to 0");
//					}
//					delay=0;
//				}
					
			
		}
		if(networktest)
			sleep(1);
			
		if(cursent++ >= humandelay)
		{
				usleep(1);
				cursent=0;
		}
	//	pthread_exit(0);
	}
}

void *check_new_proxys(void *arg)
{
	intptr_t thread_id;
	
	thread_id = (intptr_t) arg;

	if(mysql_thread_init())
		{
		perror("mysqlthread_init");
		exit(0);
	}
	
	//sleep(thread_id*1);

	mclreol(thread_id+6,0);
	mprint(thread_id+6,0,"%4x ready",thread_id);
	int num=0;
	time_t sleepsecs=time(NULL);
	if(verbose&&networktest)
		fprintf(stderr,"check_proxys running\r\n");

	while(continue_scan)
	{
		char q[1024];
		
			struct sched_param param;
			int pol;
		
		//move(3,0);
		attron(COLOR_PAIR(3));
		mclreol(thread_id+6,0);
		mprint(thread_id+6,0,"querying db ...", num);
		//refresh();
		attroff(COLOR_PAIR(3));
		sprintf(q, "select count(ip) from ip where status = 0  limit 1");

//			memset(&param, 0, sizeof(param));
//			param.sched_priority = 1;
//			pthread_setschedparam(pthread_self(), SCHED_BATCH, &param);
	
		mysql_lock();
		num=countquery(q);

		if(!num)
		{
			mysql_unlock();
			//move(3,0);
			//attron(COLOR_PAIR(2));
			
			int sl;
			sl=1+(rand()%8);
			
			//refresh();
			//attroff(COLOR_PAIR(2));
			for(int i=0;i<sl;i++)
			{
				mclreol(thread_id+6,0);
				mprint(thread_id+6,0,"sleep %4d sec ...",sl, time(NULL)-sleepsecs);
				sleep(1);
			}
			if(sl==2)
			{
				mysql_lock();
				mclreol(thread_id+6,0);
				mprint(thread_id+6,0,"deleting old proxy's ...");
				sprintf(q,"delete from ip where lastworktime!=0 and lastworktime <= %lu", time(NULL)-(60*60*24*2));
				query(q);
				
				mclreol(thread_id+6,0);
				mprint(thread_id+6,0,"restoring zero status of bad proxy's ...");
				sprintf(q,"update ip set status=0 where status not in(1,-2) and updated <= %lu", time(NULL)-(60*30));
				query(q);
				mysql_unlock();
			}
					
			if(verbose && networktest)
				fprintf(stderr,"check_new_proxys no new sockes, sleeping...\r\n");
			continue;
		}
		sleepsecs=time(NULL);
//ysql_mutex=PTHREAD_MUTEX_RECURSIVE;

		
		MYSQL_ROW row;
		MYSQL_RES *res;
		query("select ip,port,id from ip where status = 0 or status IS NULL order by rand() limit 1");
		res = mysql_store_result(mysql);
		char ip[128];
		unsigned id;
		if(res)
		{
			row = mysql_fetch_row(res);
			if(row!=NULL)
			{
				strcpy(ip,row[0]);
				if(row[1])
					scan_port = atoi(row[1]);
				if(row[2])
						id=atol(row[2]);
				
			} else {
				mclreol(69,0);
				mprint(69,0,"mysql: %s",mysql_error(mysql));
			}
			mysql_free_result(res);
		} else {
			strcpy(ip,"unknown");
		}
		
		sprintf(q,"update ip set status = -1 where id = %u", id);
		query(q);
		
		mysql_unlock();

		if(verbose && networktest)
				fprintf(stderr,"checking proxy %s:%d ", ip,scan_port);
			
//				
//
	
			int ret=check_proxy(ip, scan_port, thread_id+6);
			
//			memset(&param, 0, sizeof(param));
//
//			param.sched_priority = 0;
//			int rr=pthread_setschedparam(pthread_self(), SCHED_RR, &param);
//			if(rr) {
//				perror("pthread_setschedparam");
//				exit(0);
//			}

		

		scans_per_second++;
		if(ret==1)
				deb("#%09d %16s:%-5d status %3d\r\n", checked_hosts, ip, scan_port, ret);
		//if(ret==33) {
			//struct in_addr sin;
			//sin.s_addr = inet_addr(ip);
			//fake.push_back((unsigned long) sin.s_addr);
			//mprint(4,0,"new fake %15s:%4d status %2d ...",ip,scan_port, ret);
		//}
		//move(3,0);
		if(ret==1)
		{
			attron(COLOR_PAIR(1));
			mclreol(thread_id+6,0);
			mprint(thread_id+6,0,"update  %15s:%-4d  status: %2d ",ip,scan_port, ret);
		//refresh();
			attroff(COLOR_PAIR(1));

			sprintf(q,"update ip set status = %d,lastworktime=%lu,updated=%lu where id = %u",ret, 
				(unsigned long)time(NULL), (unsigned long)time(NULL), id);
		//printf(" %s\r\n",q);
			query(q);
		} else {
			mclreol(thread_id+6,0);
			mprint(thread_id+6,0,"update  %15s:%-4d  status: %2d ",ip,scan_port, ret);
		//refresh();

			//sprintf(q,"delete from ip where ip = '%s' and port = %d",ip,scan_port);
			sprintf(q,"update ip set status = %d,updated=%lu where id = %u",ret, (unsigned long)time(NULL),id);
		//printf(" %s\r\n",q);
			//query(q);
		}
	}
	fprintf(stderr,"check_proxy %d exited\r\n",thread_id);
}


void *check_exist_socks(void *arg)
{
	intptr_t thread_id;
	
	thread_id = (intptr_t) arg;

	if(mysql_thread_init())
		{
		perror("mysqlthread_init");
		exit(0);
	}
	
	
	
	//sleep(thread_id*1);

	mclreol(thread_id+6,0);
	mprint(thread_id+6,0,"%4x ready",thread_id);
	int num=0;
	time_t sleepsecs=time(NULL);
	if(verbose&&networktest)
		fprintf(stderr,"check_exist_proxys running\r\n");
	while(continue_scan)
	{
		char q[1024];
		
	
		//move(3,0);
		attron(COLOR_PAIR(3));
		mclreol(thread_id+6,0);
		mprint(thread_id+6,0,"querying db ...");
		//refresh();
		attroff(COLOR_PAIR(3));
		unsigned long tyt;
		tyt=time(NULL)-60*10;
		sprintf(q, "select ip from ip where status = 1 and (updated <= %lu or updated IS NULL) order by updated asc limit 1", tyt);
		num=query(q, true);
		if(!num)
		{
			new_proxys = countquery("select 0+count(id) as cnt from proxy.ip where status=0");
			chkd_proxys = countquery("select 0+count(id) as cnt from proxy.ip where status=1");
			bw_net = (double) countquery("select (0 + SUM(kbps)) as sssu from proxy.ip where status=1");
			bw_net /= 1024.0;
			int sl;
			sl=4+(rand()%16);
			//move(3,0);
			//attron(COLOR_PAIR(2));
			for(int i=0;i<sl;i++)
			{
				db_querys_second=0;
				mclreol(thread_id+6,0);
				mprint(thread_id+6,0,"rechecker sleep %4d sec ...", time(NULL)-sleepsecs);
				sleep(1);
				
			}
			
//			if(( time(NULL) - mysql_optimize_time) >= 10*60) 
//			{
//				mclreol(thread_id+6,0);
//				mprint(thread_id+6,0,"rechecker OPTIMIZING DB ...");
//				
//				mysqloptimize();
//			}
			
			if(sl==5) 
			{
					sprintf(q,"update ip set status=0 where status not in(1,-2,-1) and updated <= %lu", time(NULL)-(60*30));
					query(q);
			} 
			//refresh();
			//attroff(COLOR_PAIR(2));
			
			
			if(verbose && networktest)
				fprintf(stderr,"check_new_proxys no exist sockes, sleeping...\r\n");
			continue;
		}
		sleepsecs=time(NULL);
//ysql_mutex=PTHREAD_MUTEX_RECURSIVE;

		mysql_lock();
		MYSQL_ROW row;
		MYSQL_RES *res;
		tyt=time(NULL)-60*10;
		sprintf(q, "select ip,port,id from ip where status = 1 and (updated <= %lu or updated IS NULL)  order by updated asc limit 1",tyt);
		query(q);
		unsigned id;
		res = mysql_store_result(mysql);
		char ip[128];
		if(res)
		{
			row = mysql_fetch_row(res);
			if(row!=NULL)
			{
				strcpy(ip,row[0]);
				if(row[1])
					scan_port = atoi(row[1]);
				if(row[2])
						id=atol(row[2]);
				
			} else {
				mclreol(69,0);
				mprint(69,0,"mysql: %s",mysql_error(mysql));
			}
			mysql_free_result(res);
		} else {
			strcpy(ip,"unknown");
		}
		
		//sprintf(q,"update ip set status = -2 where id= %u", id);
		//query(q);
		
		mysql_unlock();

		if(verbose && networktest)
				fprintf(stderr,"pinging proxy %s:%d ", ip,scan_port);
				
		int ret=check_proxy(ip, scan_port, thread_id+6, 2);

		if(ret!=33 )
				deb("#%09d %16s:%-5d status %3d\r\n", checked_hosts, ip, scan_port, ret);
		//if(ret==33) {
	
		//}
		//move(3,0);
		if(ret==1)
		{
			attron(COLOR_PAIR(1));
			mclreol(thread_id+6,0);
			mprint(thread_id+6,0,"updating %15s:%4d status %2d ...",ip,scan_port, ret);
		//refresh();
			attroff(COLOR_PAIR(1));

			sprintf(q,"update ip set status = %d,lastworktime=%lu, updated= %lu where id = %u",ret,  (unsigned long)time(NULL),
				 (unsigned long)time(NULL), id);
		//printf(" %s\r\n",q);
			query(q);
		} else {
			mclreol(thread_id+6,0);
			mprint(thread_id+6,0,"deleting %15s:%4d [status %2d] ...",ip,scan_port, ret);
		//refresh();

			//sprintf(q,"delete from ip where ip = '%s' and port = %d",ip,scan_port);
			sprintf(q,"update ip set status = -1, updated=%lu where id= %u",time(NULL), id);
		//printf(" %s\r\n",q);
			query(q);
		}
	}
	fprintf(stderr,"check_exist_proxy exited\r\n");
}

void *capture_thread(void *arg)
{
	pcap_t *descr;
	char error[PCAP_ERRBUF_SIZE];
	int i;
	char *dev;
	bpf_u_int32 netaddr=0, mask=0;
	int data_size = 20;
	int packet_size;
	int tcp_opt_size = 0;
	
	if(mysql_thread_init())
	{
		perror("mysqlthread_init");
		pthread_exit(0);
	}
	
	

	dev=pcap_lookupdev(error);
	
//	dev="venet0:0";

	if((descr = pcap_open_live(dev, 4096, 1, 1000, error) ) == NULL)
	{
		fprintf(stderr,"\nError opening device: %s\n", error);
		return 0;
	}
	
	//mprint(6,0, "pcap using capturing device %s", dev);
	if(verbose&&networktest)
		fprintf(stderr,"pcap using capturing device %s type = %d (need %d)\r\n", dev, pcap_datalink(descr),
		DLT_LINUX_SLL);
	deb("pcap using capturing device %s type = %d (need %d)\r\n", dev, pcap_datalink(descr),
		DLT_LINUX_SLL);
	//fprintf(stderr,"xyubla");


	if(pcap_datalink(descr) != DLT_LINUX_SLL) 
	{
			if(verbose&&networktest)
		fprintf(stderr, "%s type not LINUX_SSL %d, using native code\n\r", dev, pcap_datalink(descr));
		//delay=1000;
		//exit(0);
		type = pcap_datalink(descr);
	} else {
			if(verbose&&networktest)
				fprintf(stderr, "linux cooked sockets DLT_LINUX_SLL\r\n");
	}

	pcap_lookupnet(dev, &netaddr, &mask, error);

	struct bpf_program filter;
	
	char capstr[1024];
	sprintf(capstr, "src port %d ",scan_port);
	for(int i=0;i<addrfound;i++) 
	{
		char ss[128];
		sprintf(ss, "and src host not %s ", addrs[i]);
		strcat(capstr, ss);
	}
	if(verbose)
	{	
		mprint(1,0,capstr);
		deb("pcap: %s\r\n",capstr);
	}
	if(networktest) 
	{
			fprintf(stderr,"pcap: %s\r\n",capstr);
			sleep(1);
	}
	//mprint(0,0,capstr);
	//strcpy(capstr,"src port 22 and host not 127.0.0.1");
	if(pcap_compile(descr, &filter, capstr
		//	"and tcp[tcpflags] & (tcp-ack) != 0"
			, 1, mask)==-1)
	{
		pcap_perror(descr, "pcap_compile");
		exit(0);
	}
	if(pcap_setfilter(descr, &filter)==-1)
	{
		pcap_perror(descr, "pcap_setfilter");
		exit(0);
	}
	if(pcap_loop(descr, -1, process_packet, NULL)==-1)
	{
		pcap_perror(descr, "pcap_loop");
		exit(0);
	}
}
void terminate(int)
{
	fprintf(stderr,"\r\nterminating ...\r\nscanned: %lu at %lu ips/second\r\n",scanned_ips,scans_per_second);
	continue_scan=false;
}
void *dooffone(void *arg)
{
	mprint(0,0,"offone %s", target);
	sleep(3);
}

void getips(void)
{
	struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;
    
		if(networktest)
			fprintf(stderr,"getting ips ...\r\n");
    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) 
    {
    	if(!ifa->ifa_addr) {
    		if(networktest)
    			fprintf(stderr,"skip %s\r\n",ifa->ifa_name);
    		continue;
    	}
    		
        if (ifa ->ifa_addr->sa_family==AF_INET) 
        { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            if(strcmp(addressBuffer, "127.0.0.1")==0 || strstr(addressBuffer,"192.168")) {
            	if(networktest)
            		fprintf(stderr,"skip %s\r\n", addressBuffer);
            	continue;
            }
           if(networktest)
           		printf("%s:%s\n", ifa->ifa_name, addressBuffer);
            strncpy(addrs[addrfound], addressBuffer, 16);
          //  ip2host(addrs[addrfound], true);
            addrfound++; 
        } else if (ifa->ifa_addr->sa_family==AF_INET6) { // check it is IP6
            // is a valid IP6 Address
            tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
           if(networktest)printf("%s:%s\n", ifa->ifa_name, addressBuffer); 
        } 
    }
  if (ifAddrStruct!=NULL) 
  	freeifaddrs(ifAddrStruct);

}

int main(int argc, char *argv[])
{
//	signal(SIGSEGV, segv);
		srand(time(NULL));
	init_rand(rand());


	bool cleardb=false;
	
	while ((opt = getopt(argc, argv, "d:vcfhq:w:e:p:t:so:mu")) != -1)
	{
		switch (opt)
		{
			case 'u':
				checkonly=true;
				break;
			case 'm':
				demon=true;
				break;
			case 'o':
				strcpy(target, optarg);
				offone=true;
				break;
			case 't':
				nthreads=atoi(optarg);
				break;
			case 'p':
				scan_port=atoi(optarg);
				break;
			case 'h':
				printf("%s [-v -f -d -c] [(c) 2022, ni0s. us3 %s f0r fun]\r\n\r\n-v verbose+speed shown"
				"\r\n-f fast mode (no db interaction)\r\n"
				"-d delay in msecs (default 0)\r\n"
				"-c clear ip db\r\n"
				"-m demon\r\n"
				"-q connect timeout in secs, default 2\r\n"
				"-w auth request timeout, default 2\r\n"
				"-s network subsystem speed test\r\n"
				"-u only check proxies, update in db\r\n"
				"-e request timeout, default 4\r\n\r\n",argv[0],argv[0]);
				
				exit(0);
				break;
			case 'f':
			fast=true;
			printf("fast mode\r\n");
			break;
			case 's':
				delay=0;
			
			networktest=true;
			break;
			case 'c':
				cleardb=true;
			break;
			
			break;
			case 'q':
				connect_timeout=atoi(optarg);
				break;
			case 'w':
				auth_timeout=atoi(optarg);
				break;
			case 'e':
			request_timeout=atoi(optarg);
			break;
			case 'd':
				humandelay=atoi(optarg);
			delay = atoi(optarg);
			printf("using delay of %d millisecs\r\n", delay);
			break;
			case 'v':
			verbose=true;
			printf("verbose mode\r\n");
			break;
		}
	}
	
	deb("maxprio: %d", sched_get_priority_max(SCHED_RR));
		
	deb("minprio: %d", sched_get_priority_min(SCHED_RR));
	
	
	getips();

	if(!addrfound)
	{
		fprintf(stderr, "no ips!\r\n");
		exit(1);
	}
	
	if(networktest)
		fprintf(stderr, "%d ips ok\r\n",addrfound);
		
	
	mysql = mysql_init(NULL);
	if(!mysql)
		{
		perror("mysql_init");
		exit(0);
	}
	
	if(networktest)
		fprintf(stderr,"connecting mysql %s:%d ... ", MYSQLHOST, MYSQLPORT);
		
	if(!mysql_real_connect(mysql, MYSQLHOST, MYSQLUSER, MYSQLPWD, MYSQLDB, MYSQLPORT, NULL, 0))
	{
		fprintf(stderr,"mysql_real_connect: %s",mysql_error(mysql));
		exit(0);
	}
	if(networktest)
			fprintf(stderr,"OK\r\n");
	
	if(mysql_thread_init())
	{
		perror("mysqlthread_init");
		exit(0);
	}
	 
	if(cleardb) 
		{
			//query("delete from ip ");
			query("update ip set rep='',status=0");
			printf("db cleared\r\n");
			//exit(0);
		}
	pthread_mutex_init(&dns_requestsDataLock, NULL);
	
	pthread_mutexattr_init(&mysql_mutex_attr);
	pthread_mutexattr_settype(&mysql_mutex_attr, PTHREAD_MUTEX_RECURSIVE  );
	pthread_mutex_init(&mysql_mutex,&mysql_mutex_attr);// &mysql_mutex_attr);
	
	pthread_mutex_init(&scanned_mutex, NULL);//&mysql_mutex_attr);
	
	pthread_mutexattr_init(&nc_mutex_attr);
	pthread_mutexattr_settype(&nc_mutex_attr, PTHREAD_MUTEX_RECURSIVE  );
	pthread_mutex_init(&nc_mutex, &nc_mutex_attr);
	
	signal(SIGINT, terminate);
	
	stacksize = 1024*1024;
	
//	for(int a=0;a<5;a++)
//	{
//		pthread_attr_init(&tattr);
//		pthread_attr_setstacksize (&tattr, stacksize);
//		pthread_create(&t1, &tattr, async_resolver, NULL);
//	}
	
	if(!checkonly)
		{pthread_attr_init(&tattr);
	pthread_attr_setstacksize (&tattr, stacksize);
	pthread_create(&t1, &tattr, capture_thread, NULL);
}
	pthread_attr_init(&tattr);
	pthread_attr_setstacksize (&tattr, stacksize);
	
	if(verbose)
		fprintf(stderr,"check_new_proxys=%x\r\n",t3);
	if(networktest)
	{
		pthread_create(&t3, &tattr, check_new_proxys, (void*)0);
		fprintf(stderr,"performing network test ...\r\n");
		send_packets(0);
		exit(0);
	}
	
	int unchecked=query("select * from ip where status=0",true);
	fprintf(stderr,"%d ips unchecked\r\n",unchecked);
	
	//mysqloptimize();
	
	query("update ip set status = 0 where status = -2");
	
	loadscanned();
	
	if(scanned.size())
			printf(" %d ips\r\n",scanned.size());

	
	if(!demon)
	{
		initscr();
		clear();
		refresh();
	}
	if(demon&&fork())
		exit(0);
	
	pthread_attr_init(&tattr);
	pthread_attr_setstacksize (&tattr, stacksize);
	
	if(offone)
		{
			pthread_create(&toffone, &tattr, dooffone, NULL);
		//	exit(0);
		} else {
		//pthread_setconcurrency(10);
		int i=0;
		for( i=0;i<nthreads/7;i++)
		{
			pthread_attr_init(&tattr);
	
			pthread_attr_setstacksize (&tattr, stacksize);
		
			
//			struct sched_param param;
//			memset(&param, 0, sizeof(param));
//			pthread_attr_getschedparam(&tattr, &param);
//			param.sched_priority = 1;
//			pthread_attr_setschedparam(&tattr, &param);

			usleep(1*1000);
			refresh();
			pthread_create(&t2, &tattr, check_exist_socks, (void*)i);
		//	pthread_setschedparam(t2, SCHED_RR, &param);
		}
		for( ;i<nthreads;i++)
		{
			pthread_attr_init(&tattr);
	
			pthread_attr_setstacksize (&tattr, stacksize);
			
			
//			struct sched_param param;
//			memset(&param, 0, sizeof(param));
//			pthread_attr_getschedparam(&tattr, &param);
//			param.sched_priority = 7;
//			pthread_attr_setschedparam(&tattr, &param);


//			pthread_setschedparam(pthread_self(), SCHED_RR, &param);
			
			pthread_create(&t3, &tattr, check_new_proxys, (void*)i);
			usleep(1*1000);
			refresh();
		//	pthread_setschedparam(t3, SCHED_RR, &param);
		
		}
		
//		i++;
//		pthread_attr_init(&tattr);
//			pthread_attr_setstacksize (&tattr, stacksize);
//			pthread_create(&t3, &tattr, check_exist_socks, (void*)i);
	

	
	//for(int i=0;i<4;i++)
		if(!checkonly)
		{
			pthread_attr_init(&tattr);
			pthread_attr_setstacksize (&tattr, stacksize);
	//for(int i=0;i<3;i++)
			pthread_create(&t1, &tattr, send_packets, NULL);
			
		}	

	
	//start_color();			/* Start color 			*/
//	init_pair(1, COLOR_RED, COLOR_BLACK);
//	init_pair(2, COLOR_CYAN, COLOR_BLACK);
//	init_pair(3, COLOR_YELLOW, COLOR_BLACK);

		mprint(0, 0, "proxy scanner - active [ni0s pri8 soft.war.e]");
	}
	
	new_proxys=countquery("select count(id) from proxy.ip where status=0");
	chkd_proxys=countquery("select count(id) from proxy.ip where status=1");
	bw_net = (double) countquery("select (0 + SUM(kbps)) as sssu from proxy.ip where status=1");
	bw_net /= 1024.0;
		
	while(continue_scan)
	{
		if(!demon)
			refresh();

				mclreol(2, 0);
				
				static float eff=0.9;

					eff = (float(total_packets) / float(scanned_ips)) * 100.0;
				mprint(2, 0, "speed:%-3lu db:%-3d  unchkd:%-6d chkd:%-6d bw:%.2f MB/s "
					"fake:%-5d", scans_per_second,db_querys_second,new_proxys,
						chkd_proxys,bw_net,  fake.size());

	 			if(!checkonly)
	 			{
	 				mclreol(0, 50);
					mprint(0,50,"%s:%d",inet_ntoa((struct in_addr) ip.sin_addr), scan_port);
					last_scans = scans_per_second;
				}
		drops=0;
		scans_per_second=0;
		other_packets=0;

			rst_packets=0;
		//ack_packets=0;
		sec_packets=0;
		usleep(1*100);
	}

	if(!demon)
		endwin();
	mysql_close(mysql);
}