/* ni0s priv8 */
#pragma pack(3)
#include "pkt.h"

#define MYSQLHOST "avalos.armed.us"
#define MYSQLUSER "pwned"
#define MYSQLPWD "pwned"
#define MYSQLDB "socks"
#define MYSQLPORT 3307

#define SOCKS_CHECK_MIN 3

MYSQL* mysql = 0;
MYSQL_RES* mysql_res = 0;
bool verbose = true;
pthread_t t1, t2, t3, toffone;
pthread_mutex_t mysql_mutex = PTHREAD_MUTEX_INITIALIZER,
nc_mutex = PTHREAD_MUTEX_INITIALIZER, ncclr_mutex = PTHREAD_MUTEX_INITIALIZER, scanned_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutexattr_t mysql_mutex_attr, nc_mutex_attr;
unsigned long scanned_ips = 0;
struct sockaddr_in msin;
vector<struct sockaddr_in> scanned;
vector<unsigned long> fake;
bool fast = false;
unsigned long scans_per_second = 0;
time_t scanchecktime = 0;
unsigned long drops = 0;
bool continue_scan = true;
unsigned long ack_packets = 0, other_packets = 0, own_packets = 0, sockscheck_packets = 0, invalid_packets = 0;
time_t mysql_optimize_time = 0;
unsigned long new_socks = 0;
unsigned long db_querys = 0;
unsigned long db_querys_second = 0;
unsigned long old_db_querys = 0;
bool offone = false;
char target[128];
int scan_port = 1080;
unsigned long checked_hosts = 0;
unsigned long invalid_tcp = 0;
unsigned long last_scans = 0;
bool demon = false;
bool networktest = false;
unsigned long dup_rnd = 0;
unsigned long rst_packets = 0;
unsigned long total_packets = 0;
int chkd_socks = 0;
int delay = 1;
char opt;
int type = 0;
pthread_attr_t tattr;
size_t stacksize;
bool show_scan_speed = false;
time_t st_time = time(NULL);
char q[1024];
struct sockaddr_in ip;
char addrs[255][16];
static unsigned long sc = 0;
int nthreads = 10;
int humandelay = 0;
int addrfound = 0;
int auth_timeout = 4;
int connect_timeout = 3;
int request_timeout = 14;
unsigned long network_ndelay = 15;
unsigned long sec_packets = 0;
bool checkonly = false;

#define PHI 0x9e3779b9
static uint32_t Q[4096], c = 362436;

void init_rand(uint32_t x)
{
	int i;

	Q[0] = x;
	Q[1] = x + PHI;
	Q[2] = x + PHI + PHI;

	for(i = 3; i < 4096; i++)
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
	if(x < c) {
		x++;
		c++;
	}
	return (Q[i] = r - x);
}

uint32_t mrand(unsigned long max = 0)
{
	return (max ? rand_cmwc() % max : rand_cmwc());
}

void mysql_lock(MYSQL* m = 0)
{
	pthread_mutex_lock(&mysql_mutex);
}
void mysql_unlock(MYSQL* m = 0)
{
	pthread_mutex_unlock(&mysql_mutex);
}
bool mfree(void)
{
	bool ret;

	if(!pthread_mutex_trylock(&nc_mutex)) {
		pthread_mutex_unlock(&nc_mutex);
		return true;
	}
	return false;
}
void mclreol(int x = 0, int y = 0)
{
	if(demon)
		return;

	pthread_mutex_lock(&nc_mutex);

	move(x, y);
	clrtoeol();
	pthread_mutex_unlock(&nc_mutex);
}
void
mprint(int x, int y, char* msg, ...)
{
	if(demon)
		return;

	pthread_mutex_lock(&nc_mutex);
	va_list ap;

	va_start(ap, msg);



	char str[4096];
	vsprintf(str, msg, ap);
	mvprintw(x, y, str);

	va_end(ap);
	//	refresh();
	pthread_mutex_unlock(&nc_mutex);
}

void
deb(char* msg, ...)
{
	//	return;
	static bool busy = false;

	//	while(busy) {
	//		usleep(200);
	//	}
	//	busy=true;
	va_list ap;

	FILE* logfile = fopen("log.txt", "a");

	va_start(ap, msg);

	//   if(demon) {
	//   fprintf(logfile,"",);
	vfprintf(logfile, msg, ap);
	//   } else {
	//      fprintf(stderr,"[%2d %2d] ",total_mail_sent,id);
	//      vfprintf(stderr,msg,ap);
	//   }

	va_end(ap);
	fclose(logfile);
	busy = false;
}

int mmysql_query(MYSQL* m, char* q)
{
	//fprintf(stderr,"\r\nmysql: %s",q);
	db_querys++;
	return mysql_real_query(m, q, strlen(q));
}
void loadscanned(void)
{
	printf("loading scanned ...");
	MYSQL_ROW row;
	MYSQL_RES* res;
	mmysql_query(mysql, "select ip from ip");
	res = mysql_store_result(mysql);
	while(row = mysql_fetch_row(res))
	{
		char ip[128];
		strcpy(ip, row[0]);
		struct sockaddr_in a;
		a.sin_addr.s_addr = inet_addr(ip);
		scanned.push_back(a);
	}
	mysql_free_result(res);

}

bool isscanned(struct sockaddr_in addr)
{

	pthread_mutex_lock(&scanned_mutex);
	bool a = false;
	for(vector<struct sockaddr_in>::iterator it = scanned.begin();it != scanned.end();it++)
	{
		if((*it).sin_addr.s_addr == addr.sin_addr.s_addr)
			a = true;
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
	struct ip* ipheader = (struct ip*) packet;

	/* It will point to the end of the IP header in packet buffer */
	struct tcphdr* tcpheader = (struct tcphdr*) (packet + sizeof(struct ip));

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
	if((rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
	{
		perror("synsend():socket()");
		return -1;
	}

	/* We need to tell the kernel that we'll be adding our own IP header */
	/* Otherwise the kernel will create its own. The ugly "one" variable */
	/* is a bit obscure but R.Stevens says we have to do it this way ;-) */
	if(setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
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
	ipheader->ip_ttl = (rand() % 2) ? 128 : 64; /* Time to live: 64 in Linux, 128 in Windows...   */
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
	tcpheader->th_ack = htonl(0); /* Acknowledgement Number                  */
	tcpheader->th_x2 = 0; /* Variable in 4 byte blocks. (Deprecated) */
	tcpheader->th_off = 5; /* Segment offset (Lenght of the header)   */
	tcpheader->th_flags = TH_SYN; /* TCP Flags. We set the Reset Flag        */
	tcpheader->th_win = htons(4000 + (rand() % 5000)); /* Window size
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
	tcpheader->th_sum = in_cksum((unsigned short*) (tcpcsumblock), sizeof
	(tcpcsumblock));

	/* Compute the IP checksum as the standard says (RFC 791) */
	ipheader->ip_sum = in_cksum((unsigned short*) ipheader, sizeof(struct ip));
	int r;
	/* Send it through the raw socket */
	if((r = sendto(rawsocket, packet, ipheader->ip_len, 0, (struct sockaddr*)
		&dstaddr, sizeof(dstaddr))) <= 0)
	{
		if(networktest)
		{
			char asrc[128], adst[128];
			strcpy(asrc, inet_ntoa(ipheader->ip_src));
			strcpy(adst, inet_ntoa(ipheader->ip_dst));
			perror("sendsyn():sendto");
			fprintf(stderr, "%s => %s\r\n", asrc, adst);
			usleep(network_ndelay * 3000);
		}
		if(errno != 22 && errno != 49)
		{
			mclreol(1, 0);
			mprint(1, 0, "%s: %s (%d)", inet_ntoa(dstaddr.sin_addr), strerror(errno), errno);
		}
		if(errno == 1) {
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

unsigned short in_cksum(unsigned short* addr, int len)
{

	register int sum = 0;
	u_short answer = 0;
	register u_short* w = addr;
	register int nleft = len;

	/*
	* Our algorithm is simple, using a 32-bit accumulator (sum),
	* we add sequential 16-bit words to it, and at the end, fold back
	* all the carry bits from the top 16 bits into the lower 16 bits.
	*/

	while(nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if(nleft == 1)
	{
		*(u_char*) (&answer) = *(u_char*) w;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */
	answer = ~sum; /* truncate to 16 bits */
	return (answer);

} /* End of in_cksum() */

/* check_host */



int query(char* q, bool ret = false)
{
	time_t sttime;
	sttime = time(NULL);

	mysql_lock();
	//		mclreol(3,0);
//	mprint(3,0, "%s", q);
	//printf("q %s\r\n",q);
	if(mmysql_query(mysql, q)) {
		//mprint(70,0, "mysql(%s): %s\r\n", q, mysql_error(mysql));
		deb("mysql(%s): %s\r\n", q, mysql_error(mysql));
		refresh();
		//exit(0);
		//refresh();
	}
	int num = 0;
	if(ret)
	{
		mysql_res = mysql_store_result(mysql);

		//	printf("%s: %d\r\n",query,num);
		if(mysql_res) {
			num = mysql_num_rows(mysql_res);
			mysql_free_result(mysql_res);
		}
	}



	if(time(NULL) - sttime >= 4)
	{
		//move(0,40);
		mclreol(69, 40);
		mprint(69, 40, "WARNING - '%s' take %d seconds", q, time(NULL) - sttime);
		//refresh();
	}
	//move(4,0);

	//refresh();
	//fprintf(stderr,"\r\nsql: %s in %d secs",query,time(NULL)-sttime);
	if(time(NULL) - sttime >= 20)
		deb("%d %s\r\n", time(NULL) - sttime, q);

	mysql_unlock();

	return num;
}

int ipindb(in_addr saddr)
{
	//return isscanned
	struct sockaddr_in s;
	s.sin_addr = saddr;
	//	if(fast)
	//			return isscanned(s);
	char q[1024];
	sprintf(q, "select ip from ip where ip = '%s'", inet_ntoa(saddr));
	int ret;
	ret = query(q, true);
	//	fprintf(stderr,"check %s:%d\r\n",q,ret);
	return ret;
}

void
print_hex_ascii_line(const u_char* payload, int len, int offset)
{
	if(demon)
		return;

	int i;
	int gap;
	const u_char* ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if(i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if(len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if(len < 16) {
		gap = 16 - len;
		for(i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if(isprint(*ch))
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
print_payload(const u_char* payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char* ch = payload;

	if(len <= 0)
		return;

	/* data fits on one line */
	if(len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for(;; ) {
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
		if(len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void process_packet(u_char* user, const struct pcap_pkthdr* h, const u_char* packet)
{
	struct sniff_ip* ip;
	struct sniff_ip* ip2;
	struct sniff_tcp* tcp;
	struct sniff_tcp* tcp2;
	struct sniff_ethernet* eth;
	struct sll_header* sllhdr;
	struct sockaddr_in sip;
	static unsigned long honeyrepeats = 0;
	int offset;
	//if(h->len==60)
	//	return;

	if(networktest)
		fprintf(stderr, "process_packet(%x, %x, %x)\r\n", user, h, packet);

	sec_packets++;
	total_packets++;

	eth = (struct sniff_ethernet*) packet;
	sllhdr = (struct sll_header*) packet;
	offset = (type == 113 ? 16 : SIZE_ETHERNET);
	ip = (struct sniff_ip*) &packet[offset];

	sip.sin_addr.s_addr = ip->ip_src.s_addr;

	if(isscanned(sip))
	{
		if(networktest)
			fprintf(stderr, "isscanned=true(%s)\r\n", inet_ntoa(ip->ip_src));
		return;
	}

	vector<unsigned long>::iterator  fff;

	//find(fake.begin(),fake.end(), (unsigned long)ip->ip_src.s_addr);
	if((fff = find(fake.begin(), fake.end(), (unsigned long) ip->ip_src.s_addr)) != fake.end())
	{
		mclreol(4, 0);
		mprint(4, 0, "honey #%4d %s (known: %d)", honeyrepeats++, inet_ntoa(ip->ip_src), fake.size());
		return;
	}

	int size_ip;
	size_ip = (IP_HL(ip) * 4);

	if(size_ip < 20)
	{
		invalid_packets++;
		fprintf(stderr, "Invalid IP header length: %u bytes, type %x", size_ip, *packet);
		mprint(3, 0, "#%4d Invalid IP header length: %u bytes, type %x", invalid_packets, size_ip, *packet);
		//refresh();
		return;
	}

	for(int i = 0;i < addrfound;i++)
	{
		if(inet_addr(addrs[addrfound]) == ip->ip_src.s_addr)
		{
			own_packets++;
			mprint(4, 0, "own packet %s", inet_ntoa(ip->ip_src));
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
	tcp = (struct sniff_tcp*) &packet[offset + size_ip];

	int size_tcp = 0;
	size_tcp = TH_OFF(tcp) * 4;

	if(size_tcp < 20)
	{
		mprint(4, 0, "#%4d Invalid TCP header length: %u bytes", invalid_tcp, size_tcp);

		invalid_tcp++;
		return;
	}
	char sflags[128];

	memset(sflags, 0, sizeof(sflags));



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
			fprintf(stderr, "ACK & SYN set %s\r\n", inet_ntoa(ip->ip_src));

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
		}
		else {
			if(verbose && networktest)
				fprintf(stderr, "%s skipped, in db\r\n", inet_ntoa(ip->ip_src));
		}

		pthread_mutex_lock(&scanned_mutex);

		scanned.push_back(sip);
		pthread_mutex_unlock(&scanned_mutex);
		//}
		//fprintf(stderr,"\r\n");
	}
	else {
		other_packets++;
	}
	if(verbose) {
		mclreol(3, 0);
		mprint(3, 0, "packet #%-8lu %-16s %-10s", total_packets, inet_ntoa(ip->ip_src), sflags);

	}
	if(verbose && networktest) {
		deb("packet #%-8lu %-16s %-10s\r\n", total_packets, inet_ntoa(ip->ip_src), sflags);

		fprintf(stderr, "packet #%-8lu %-16s %-10s", total_packets, inet_ntoa(ip->ip_src), sflags);
	}

}

void
segv(int)
{
	deb("\r\n\r\n!!! sigsegv!");
	fprintf(stderr, "\r\n\r\n       sigsegv! sigsegv!sigsegv! sigsegv!sigsegv! sigsegv!\r\n\r\n      \r\n");
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
	if(t) {
		signal(SIGALRM, sig_timeout);
		alarm(t);
	}
	else {
		alarm(0);
	}
}

int check_socks(char* ip, int port, int nc_line = 0)
{
	int             s, r;

	char            req[128];
	char            rep[128];
	//static char    *buf = NULL;
	char buf[1024];
	struct socks_desc {
		char            ver;
		char            cmd;
		char            rsv;
		char            atype;
		struct in_addr  sin_addr;
		u_short         s_port;
	}               sq;
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
	msin.sin_addr.s_addr = inet_addr(ip);


	if((s = socket(PF_INET, SOCK_STREAM, 0)) == NULL) {
		perror("socket");
		_exit(1);
	}
	int on = 1;
	ioctl(s, FIONBIO, (int*) &on);
	//set_timeout(delay);
	//move(3,0);
	mclreol(nc_line, 0);
	//refresh();
	mprint(nc_line, 0, "sckschk %15s:%4d", ip, port);
	//refresh();
//set_timeout(3);
//errno = 0;
	time_t sttime = time(NULL);
	//move(nc_line,30);
	mclreol(nc_line, 30);
	mprint(nc_line, 30, "connecting ... ");
	struct timespec nsttime, ncurtime;
	clock_gettime(CLOCK_REALTIME, &nsttime);
	long connect_ntime = connect_timeout * 1000;
	if(!nc_line)
		deb("\r\nsockscheck connecting %s:%d\r\n", ip, port);
	while(true)
	{
		clock_gettime(CLOCK_REALTIME, &ncurtime);
		r = connect(s, (struct sockaddr*) &msin, sizeof(msin));
		//printf("r %d ",r);
		if(!r || errno == 56)
			break;

		if(connect_ntime <= 0)
		{
			close(s);
			mprint(nc_line, 30, "connect timeout: %s", strerror(errno));
			if(!nc_line)
				deb("connect timeout: %s-%d (left %lu)", strerror(errno), errno, connect_ntime);
			//refresh();
			return 10;
		}
		else {
			//move(nc_line,0);
			mclreol(nc_line, 30);

			if(connect_ntime >= network_ndelay)
				connect_ntime -= network_ndelay;
			else
				connect_ntime = 0;

			mprint(nc_line, 30, "connecting ... %.2f",
				(float) connect_ntime / 1000.0);
			//refresh();
		}



		usleep(network_ndelay * 1000);
	}
	//fprintf(stderr, "%d: %s\n", errno, strerror(errno));
//	alarm(0);
	//if (debug)
	//move(nc_line,30);
	if(!nc_line)
		deb("\r\nconnected <=> %s:%d request auth \r\n", ip, port);
	mclreol(nc_line, 30);
	mprint(nc_line, 30, "requesting auth %d ...");
	//refresh();
	on = 0;
	ioctl(s, FIONBIO, (int*) &on);
	//alarm(0);

	req[0] = 0x05;
	req[1] = 0x03;
	req[2] = 0x00;
	req[3] = 0x01;
	req[4] = 0x02;

	send(s, req, 5, 0);
	if(!nc_line)
		deb("auth req sent, ");
	////refresh();

	on = 1;
	ioctl(s, FIONBIO, (int*) &on);

	sttime = time(NULL);
	memset(rep, 0, sizeof(rep));
	while(r = recv(s, rep, 55, 0) == -1)
	{
		if(time(NULL) - sttime >= auth_timeout)
		{
			//move(nc_line,30);
			if(!nc_line)
				deb("timeout reading auth");
			mclreol(nc_line, 30);
			mprint(nc_line, 30, "timeout reading auth");
			//refresh();
			close(s);
			return 4;
		}
		mclreol(nc_line, 30);
		mprint(nc_line, 30, "requesting auth %d ...", time(NULL) - sttime);
		usleep(network_ndelay * 1000);
	}

	//	if(!r) {
	//		fprintf(stderr, "zero reply");
	//		close(s);
	//		return 2;
	//	}
	if(rep[0] != 4 && rep[0] != 5)
	{
		//move(nc_line,30);
		if(!nc_line)
			deb("not socks ");
		mclreol(nc_line, 30);
		mprint(nc_line, 30, "not socks protocol (%x)", rep[0]);
		//refresh();
		close(s);
		return 5;
	}
	//move(nc_line,0);
	mclreol(nc_line, 30);
	mprint(nc_line, 30, "[ver %x] auth %s ", rep[0], rep[1] ? "required " : "not required, ");
	deb("%s:%d [ver %x] auth %s ", inet_ntoa(msin.sin_addr), scan_port, rep[0], rep[1] ? "required \r\n" : "not required, \r\n");

	if(!nc_line)
		deb("requesting signature data ...\r\n");

	on = 0;
	ioctl(s, FIONBIO, (int*) &on);

	sq.ver = 0x05;
	sq.cmd = 0x01;
	sq.rsv = 0x00;
	sq.atype = 0x01;
	sq.sin_addr.s_addr = inet_addr("69.36.12.216");
	sq.s_port = htons(80);

	send(s, &sq, sizeof(sq), 0);
	//move(nc_line,30);
	if(!nc_line)
		deb("twaiting reply ...");
	mclreol(nc_line, 30);
	mprint(nc_line, 30, "waiting reply ...", time(NULL) - sttime);
	//refresh();
	on = 1;
	ioctl(s, FIONBIO, (int*) &on);

	bzero(buf, 1024);
	sttime = time(NULL);
	while((r = recv(s, buf, 1024, 0)) == -1)
	{
		if(time(NULL) - sttime >= request_timeout)
		{
			//move(nc_line,30);
			mclreol(nc_line, 30);
			mprint(nc_line, 60, "timeout reading");
			//refresh();
			close(s);
			return 7;
		}
		mclreol(nc_line, 30);
		mprint(nc_line, 30, "waiting reply %d ...", time(NULL) - sttime);
		usleep(network_ndelay * 1000);
	}
	if(!nc_line)
		deb("got asked data \r\n");
	/*
	* if(debug) { fprintf(stderr," got %d bytes ",r);
	* for(i=0;i<4;i++) { fprintf(stderr,"
	* 0x%02x",buf[i]); }		fprintf(stderr,"\n");
	* }
	*/

	if(buf[1])
	{
		//				switch (buf[1])
		//				{
		//					case 0x01:
		//					fprintf(stderr, "general socks failure\n");
		//					close(s);
		//					return 8;
		//					break;
		//				}
		//move(nc_line,0);
		mclreol(nc_line, 30);
		mprint(nc_line, 30, "unsuccessfull 0x%x 0x%x 0x%x", buf[0], buf[1], buf[2]);
		if(verbose && networktest)
			fprintf(stderr, "unsuccessfull - not socks/hz\r\n");
		//refresh();
	}
	//close(s);
	//return 2;
	char q[1024];
	on = 0;
	ioctl(s, FIONBIO, (int*) &on);
	sprintf(q, "HEAD / HTTP/1.0\r\n\r\n");
	send(s, q, strlen(q), 0);
	on = 1;
	ioctl(s, FIONBIO, (int*) &on);

	bzero(buf, 1024);
	sttime = time(NULL);
	while((r = recv(s, buf, 1024, 0)) == -1)
	{
		if(time(NULL) - sttime >= request_timeout)
		{
			//move(nc_line,30);
			mclreol(nc_line, 30);
			mprint(nc_line, 60, "timeout reading");
			//refresh();
			close(s);
			return 7;
		}
		mclreol(nc_line, 30);
		mprint(nc_line, 30, "waiting data %d ...", time(NULL) - sttime);
		usleep(network_ndelay * 1000);
	}
	if(!nc_line)	deb("recv %d %s", r, buf);
	if(strstr(buf, "Apache/1.3.31 (Unix) PHP/4.3.6"))
	{
		close(s);
		//move(nc_line,0);
		mclreol(nc_line, 30);
		mprint(nc_line, 30, "signature found");
		//refresh();
		if(!nc_line)
			deb("working socks - %s:%d\r\n", ip, port);
		return 1;

	}
	else {
		//move(nc_line,0);
		mclreol(nc_line, 30);
		mprint(nc_line, 30, "signature not found");
		deb("honeypot %s:%d\r\n%s", ip, port, buf);
		if(!nc_line)
			deb("maybe honeynets socks - %s:%d [filtered content]\r\n", ip, port);
		//refresh();
		close(s);
		return 9;
	}

	return 99;
}

void mysqloptimize(void)
{
	if(demon)
		return;

	while(!mysql)
		sleep(1);

	if(!demon)
		fprintf(stderr, "%x optimizing tables ... ", mysql);

	//	query("use socks");
	query("optimize table ip");
	//query("analyze table ip");

	if(!demon)
		fprintf(stderr, "done\r\n");
	mysql_optimize_time = time(NULL);
}

void* send_packets(void* arg)
{
	unsigned char* p_ip;
	unsigned long ul_dst;
	unsigned long cursent = 0;

	while(continue_scan)
	{

		if(time(NULL) - scanchecktime >= 1)
		{
			scans_per_second = scanned_ips - sc;
			scanchecktime = time(NULL);
			sc = scanned_ips;
			db_querys_second = db_querys - old_db_querys;
			old_db_querys = db_querys;

			if(networktest) {
				fprintf(stderr, "scanned %lu ips, drops %lu \r\n", scanned_ips, drops);
				scanned_ips = 0;
				drops = 0;
			}
		}

		for(unsigned i = rand_cmwc() % 4;i > 1;i--)
			rand_cmwc();

		p_ip = (unsigned char*) &ul_dst;
		for(int i = 0;i < sizeof(unsigned long);i++)
			*p_ip++ = rand_cmwc() % 255;
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
		if(networktest && verbose)
			fprintf(stderr, "target: %s ", inet_ntoa(ip.sin_addr));

		unsigned long srcaddr;

		if(humandelay)
			delay = humandelay;

		srcaddr = inet_addr(addrs[rand() % addrfound]);
		if(sendsyn(rand(), srcaddr, ul_dst, htons(rand() % 65535), htons(scan_port)) != -1)
		{
			scanned_ips++;
			if(networktest && verbose)
				fprintf(stderr, " OK\r\n");
			//	if(delay)
			//		usleep(delay*1000);
		}
		else {
			if(networktest && verbose)
				fprintf(stderr, "! %s:%s\r\n", strerror(errno), inet_ntoa(ip.sin_addr));


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
			cursent = 0;
		}
		//	pthread_exit(0);
	}
}

void* check_new_socks(void* arg)
{
	intptr_t thread_id;
	int scan_port;

	thread_id = (intptr_t) arg;

	if(mysql_thread_init())
	{
		perror("mysqlthread_init");
		pthread_exit(0);
	}

	//sleep(thread_id*1);

	mclreol(thread_id + 6, 0);
	mprint(thread_id + 6, 0, "%4x ready", thread_id);
	int num = 0;
	time_t sleepsecs = time(NULL);
	if(verbose && networktest)
		fprintf(stderr, "check_socks running\r\n");
	while(continue_scan)
	{
		char q[1024];


		//move(3,0);
		attron(COLOR_PAIR(3));
		mclreol(thread_id + 6, 0);
		mprint(thread_id + 6, 0, "querying db %d ...", num);
		//refresh();
		attroff(COLOR_PAIR(3));
		sprintf(q, "select ip from ip where status not in(1,-2) and updated <= %lu  limit 1", time(NULL) - (60 * SOCKS_CHECK_MIN));
		num = query(q, true);
		if(!num)
		{
			//move(3,0);
			//attron(COLOR_PAIR(2));
			mclreol(thread_id + 6, 0);
			int sl;
			sl = 1 + (rand() % 8);
			while(sl)
			{
				mprint(thread_id + 6, 0, "sleep %-2d sec ...", time(NULL) - sleepsecs);
				//refresh();
				//attroff(COLOR_PAIR(2));
				sleep(sl);
				sl--;
			}
			if(verbose && networktest)
				fprintf(stderr, "check_new_socks no new sockes, sleeping...\r\n");
			continue;
		}
		sleepsecs = time(NULL);
		//ysql_mutex=PTHREAD_MUTEX_RECURSIVE;

		mysql_lock();
		MYSQL_ROW row;
		MYSQL_RES* res;
		sprintf(q, "select ip,port from ip where status not in(1,-2) and updated <= %lu limit 1", time(NULL) - (60 * SOCKS_CHECK_MIN));
		query(q);
		res = mysql_store_result(mysql);
		char ip[128];
		if(res)
		{
			row = mysql_fetch_row(res);
			if(row != NULL)
			{
				strcpy(ip, row[0]);
				if(row[1]) {
					scan_port = atoi(row[1]);
				}
			}
			else {
				mclreol(69, 0);
				mprint(69, 0, "mysql: %s", mysql_error(mysql));
			}
			mysql_free_result(res);
		}
		else {
			strcpy(ip, "unknown");
			continue;
		}

		sprintf(q, "update ip set status = -2 where ip = '%s' and port=%d", ip, scan_port);
		query(q);

		mysql_unlock();

		if(verbose && networktest)
			fprintf(stderr, "checking socks %s:%d ", ip, scan_port);
		int ret = check_socks(ip, scan_port, thread_id + 6);
		if(ret != 10)
			deb("#%09d %-16s status %3d\r\n", checked_hosts, ip, ret);
		//if(ret==33) {
		//	struct in_addr sin;
		//	sin.s_addr = inet_addr(ip);
			//fake.push_back((unsigned long) sin.s_addr);
			//mprint(4,0,"new fake %15s:%4d status %2d ...",ip,scan_port, ret);
		//}
		//move(3,0);
		if(ret == 1)
		{
			attron(COLOR_PAIR(1));
			mclreol(thread_id + 6, 0);
			mprint(thread_id + 6, 0, "updating %15s:%4d status %2d ...", ip, scan_port, ret);
			//refresh();
			attroff(COLOR_PAIR(1));

			sprintf(q, "update ip set status = %d,updated=%lu,lastworktime=%lu where ip = '%s' and port=%d",
				ret, time(NULL), time(NULL), ip, scan_port);
			//printf(" %s\r\n",q);
			query(q);
		}
		else {
			mclreol(thread_id + 6, 0);
			mprint(thread_id + 6, 0, "updating %15s:%4d [status %2d] ...", ip, scan_port, ret);
			//refresh();

			sprintf(q, "update ip set updated=%lu,status=%d where ip = '%s' and port=%d", time(NULL), ret, ip, scan_port);
			//printf(" %s\r\n",q);
			query(q);
		}
	}
	fprintf(stderr, "check_socks exited\r\n");
}

void* check_exist_socks(void* arg)
{
	intptr_t thread_id;
	int scan_port;

	thread_id = (intptr_t) arg;
	deb("checkexist %x started\r\n", thread_id);
	if(mysql_thread_init())
	{
		perror("mysqlthread_init");
		pthread_exit(0);
	}

	//sleep(thread_id*1);

	mclreol(thread_id + 6, 0);
	mprint(thread_id + 6, 0, "%4x ready", thread_id);
	int num = 0;
	time_t sleepsecs = time(NULL);
	if(verbose && networktest)
		fprintf(stderr, "check_socks running\r\n");
	while(continue_scan)
	{
		char q[1024];


		//move(3,0);
		attron(COLOR_PAIR(3));
		mclreol(thread_id + 6, 0);
		mprint(thread_id + 6, 0, "querying db %d ...", num);
		//refresh();
		attroff(COLOR_PAIR(3));
		sprintf(q, "select ip from ip where updated <= %lu and status not in(-2) limit 1",
			time(NULL) - (60 * SOCKS_CHECK_MIN));
		num = query(q, true);
		if(!num)
		{
			//move(3,0);
			//attron(COLOR_PAIR(2));
			mclreol(thread_id + 6, 0);
			int sl;
			sl = 1 + (rand() % 8);
			while(sl)
			{
				mprint(thread_id + 6, 0, "recheck sleep %-2d sec ...", time(NULL) - sleepsecs);
				//refresh();
				//attroff(COLOR_PAIR(2));
				sleep(1);
				sl--;
			}
			if(verbose && networktest)
				fprintf(stderr, "check_exist_socks no new sockes, sleeping...\r\n");
			continue;
		}
		sleepsecs = time(NULL);
		//ysql_mutex=PTHREAD_MUTEX_RECURSIVE;

		mysql_lock();
		MYSQL_ROW row;
		MYSQL_RES* res;
		sprintf(q, "select ip,port from ip where updated <= %lu and status not in (-2) order by rand() limit 1",
			time(NULL) - (60 * SOCKS_CHECK_MIN));
		query(q);
		res = mysql_store_result(mysql);
		char ip[128];
		if(res)
		{
			row = mysql_fetch_row(res);
			if(row != NULL)
			{
				strcpy(ip, row[0]);
				if(row[1])
					scan_port = atoi(row[1]);

			}
			else {
				mclreol(69, 0);
				mprint(69, 0, "mysql: %s", mysql_error(mysql));
			}
			mysql_free_result(res);
		}
		else {
			strcpy(ip, "unknown");
			continue;
		}

		sprintf(q, "update ip set status = -2 where ip = '%s' and port = %d", ip, scan_port);
		query(q);

		mysql_unlock();

		if(verbose && networktest)
			fprintf(stderr, "checking socks %s:%d ", ip, scan_port);
		int ret = check_socks(ip, scan_port, thread_id + 6);
		if(ret != 10)
			deb("#%09d %-16s status %3d\r\n", checked_hosts, ip, ret);
		//if(ret==33) {
		//	struct in_addr sin;
		//	sin.s_addr = inet_addr(ip);
		//	fake.push_back((unsigned long) sin.s_addr);
			//mprint(4,0,"new fake %15s:%4d status %2d ...",ip,scan_port, ret);
		//}
		//move(3,0);
		if(ret == 1)
		{
			attron(COLOR_PAIR(1));
			mclreol(thread_id + 6, 0);
			mprint(thread_id + 6, 0, "updating %15s:%4d status %2d ...", ip, scan_port, ret);
			//refresh();
			attroff(COLOR_PAIR(1));

			sprintf(q, "update ip set status = %d,updated=%lu,lastworktime=%lu where ip = '%s' and port = %d",
				ret, time(NULL), time(NULL), ip, scan_port);
			//printf(" %s\r\n",q);
			query(q);
		}
		else {
			mclreol(thread_id + 6, 0);
			mprint(thread_id + 6, 0, "deleting %15s:%4d [status %2d] ...", ip, scan_port, ret);
			//refresh();

			sprintf(q, "update  ip set status=%d,updated=%lu where ip = '%s' and port =%d", ret, time(NULL), ip, scan_port);
			//printf(" %s\r\n",q);
			query(q);
		}
	}
	fprintf(stderr, "check_exist_socks exited\r\n");
}

void* capture_thread(void* arg)
{
	pcap_t* descr;
	char error[PCAP_ERRBUF_SIZE];
	int i;
	char* dev;
	bpf_u_int32 netaddr = 0, mask = 0;
	int data_size = 20;
	int packet_size;
	int tcp_opt_size = 0;

	if(mysql_thread_init())
	{
		perror("mysqlthread_init");
		pthread_exit(0);
	}

	dev = pcap_lookupdev(error);

	//	dev="venet0:0";

	if((descr = pcap_open_live(dev, 4096, 1, 1000, error)) == NULL)
	{
		fprintf(stderr, "\nError opening device: %s\n", error);
		return 0;
	}

	//mprint(6,0, "pcap using capturing device %s", dev);
	//fprintf(stderr,"pcap using capturing device %s type = %d (need %d)\r\n", dev, pcap_datalink(descr),
		//DLT_LINUX_SLL);
	deb("pcap using capturing device %s type = %d (need %d)\r\n", dev, pcap_datalink(descr),
		DLT_LINUX_SLL);
	//fprintf(stderr,"xyubla");


	if(pcap_datalink(descr) != DLT_LINUX_SLL)
	{
		fprintf(stderr, "%s type not LINUX_SSL %d, using native code\n\r", dev, pcap_datalink(descr));
		//delay=1000;
		//exit(0);
		type = pcap_datalink(descr);
	}
	else {
		fprintf(stderr, "linux cooked sockets DLT_LINUX_SLL\r\n");
	}

	pcap_lookupnet(dev, &netaddr, &mask, error);

	struct bpf_program filter;

	char capstr[1024];
	sprintf(capstr, "src port %d ", scan_port);
	for(int i = 0;i < addrfound;i++)
	{
		char ss[128];
		sprintf(ss, "and src host not %s ", addrs[i]);
		strcat(capstr, ss);
	}
	//mprint(3,0,capstr);
	deb("pcap: %s\r\n", capstr);
	if(networktest)
	{
		fprintf(stderr, "pcap: %s\r\n", capstr);
		sleep(1);
	}
	//mprint(0,0,capstr);
	//strcpy(capstr,"src port 22 and host not 127.0.0.1");
	if(pcap_compile(descr, &filter, capstr
		//	"and tcp[tcpflags] & (tcp-ack) != 0"
		, 1, mask) == -1)
	{
		pcap_perror(descr, "pcap_compile");
		exit(0);
	}
	if(pcap_setfilter(descr, &filter) == -1)
	{
		pcap_perror(descr, "pcap_setfilter");
		exit(0);
	}
	if(pcap_loop(descr, -1, process_packet, NULL) == -1)
	{
		pcap_perror(descr, "pcap_loop");
		exit(0);
	}
}
void terminate(int)
{
	fprintf(stderr, "\r\nterminating ...\r\nscanned: %lu at %lu ips/second\r\n", scanned_ips, scans_per_second);
	continue_scan = false;
}
void* dooffone(void* arg)
{
	mprint(0, 0, "offone %s", target);
	sleep(3);
}

void getips(void)
{
	struct ifaddrs* ifAddrStruct = NULL;
	struct ifaddrs* ifa = NULL;
	void* tmpAddrPtr = NULL;

	if(networktest)
		fprintf(stderr, "getting ips ...\r\n");
	getifaddrs(&ifAddrStruct);

	for(ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
	{
		if(!ifa->ifa_addr) {
			if(networktest)
				fprintf(stderr, "skip %s\r\n", ifa->ifa_name);
			continue;
		}

		if(ifa->ifa_addr->sa_family == AF_INET)
		{ // check it is IP4
			// is a valid IP4 Address
			tmpAddrPtr = &((struct sockaddr_in*) ifa->ifa_addr)->sin_addr;
			char addressBuffer[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
			if(strcmp(addressBuffer, "127.0.0.1") == 0 || strstr(addressBuffer, "192.168")) {
				if(networktest)
					fprintf(stderr, "skip %s\r\n", addressBuffer);
				continue;
			}
			if(networktest)
				printf("%s:%s\n", ifa->ifa_name, addressBuffer);
			strncpy(addrs[addrfound], addressBuffer, 16);
			addrfound++;
		}
		else if(ifa->ifa_addr->sa_family == AF_INET6) { // check it is IP6
		 // is a valid IP6 Address
			tmpAddrPtr = &((struct sockaddr_in6*) ifa->ifa_addr)->sin6_addr;
			char addressBuffer[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
			if(networktest)printf("%s:%s\n", ifa->ifa_name, addressBuffer);
		}
	}
	if(ifAddrStruct != NULL)
		freeifaddrs(ifAddrStruct);

}

int main(int argc, char* argv [])
{
	//signal(SIGSEGV, segv);
	srand(time(NULL));
	init_rand(rand());
	//	check_socks("46.254.18.161",444, 0);
	//	exit(0);
		//fprintf(stderr, "start");

	//	for(int i=0;i<addrfound;i++)
	//		printf("%s\r\n",addrs[i]);
	//		exit(0);

	//	struct rlimit lim = {1*1024*1024, 1*1024*1024};
	//  if (setrlimit(RLIMIT_STACK, &lim) == -1)
	//  {
	//  	perror("setrlimit");
	//  	return 1;
	//  }

	bool cleardb = false;


	while((opt = getopt(argc, argv, "d:vcfhq:w:e:p:t:so:mu")) != -1)
	{
		switch(opt)
		{
		case 'u':
			checkonly = true;
			break;
		case 'm':
			demon = true;
			break;
		case 'o':
			strcpy(target, optarg);
			offone = true;
			break;
		case 't':
			nthreads = atoi(optarg);
			break;
		case 'p':
			scan_port = atoi(optarg);
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
				"-e request timeout, default 4\r\n\r\n", argv[0], argv[0]);

			exit(0);
			break;
		case 'f':
			fast = true;
			printf("fast mode\r\n");
			break;
		case 's':
			delay = 0;

			networktest = true;
			break;
		case 'c':
			cleardb = true;
			break;

			break;
		case 'q':
			connect_timeout = atoi(optarg);
			break;
		case 'w':
			auth_timeout = atoi(optarg);
			break;
		case 'e':
			request_timeout = atoi(optarg);
			break;
		case 'd':
			humandelay = atoi(optarg);
			delay = atoi(optarg);
			printf("using delay of %d millisecs\r\n", delay);
			break;
		case 'v':
			verbose = true;
			printf("verbose mode\r\n");
			break;
		}
	}



	getips();

	if(!addrfound)
	{
		fprintf(stderr, "no ips!\r\n");
		exit(1);
	}

	if(networktest)
		fprintf(stderr, "%d ips ok\r\n", addrfound);


	mysql = mysql_init(NULL);
	if(!mysql)
	{
		perror("mysql_init");
		exit(0);
	}

	if(networktest)
		fprintf(stderr, "connecting mysql %s:%d ... ", MYSQLHOST, MYSQLPORT);

	if(!mysql_real_connect(mysql, MYSQLHOST, MYSQLUSER, MYSQLPWD, MYSQLDB, MYSQLPORT, NULL, 0))
	{
		fprintf(stderr, "mysql_real_connect: %s", mysql_error(mysql));
		exit(0);
	}
	fprintf(stderr, "OK\r\n");

	if(mysql_thread_init())
	{
		perror("mysqlthread_init");
		exit(0);
	}

	if(cleardb) {
		query("delete from ip ");
		printf("db cleared\r\n");
		exit(0);
	}

	pthread_mutexattr_init(&mysql_mutex_attr);
	pthread_mutexattr_settype(&mysql_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mysql_mutex, &mysql_mutex_attr);// &mysql_mutex_attr);

	pthread_mutex_init(&scanned_mutex, NULL);//&mysql_mutex_attr);

	pthread_mutexattr_init(&nc_mutex_attr);
	pthread_mutexattr_settype(&nc_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&nc_mutex, &nc_mutex_attr);

	signal(SIGINT, terminate);

	stacksize = 512 * 1024;

	//	struct sched_param param;
//	param.sched_priority = 99;
//	pthread_setschedparam(t1, SCHED_OTHER, &param);



	if(!checkonly)
	{
		pthread_attr_init(&tattr);
		pthread_attr_setstacksize(&tattr, stacksize);
		pthread_create(&t1, &tattr, capture_thread, NULL);

		pthread_attr_init(&tattr);
		pthread_attr_setstacksize(&tattr, stacksize);
		pthread_create(&t3, &tattr, check_new_socks, (void*) 0);
	}
	if(verbose)
		fprintf(stderr, "check_new_socks=%x\r\n", t3);
	if(networktest)
	{
		fprintf(stderr, "performing network test ...\r\n");
		send_packets(0);
		exit(0);
	}

	int unchecked = query("select * from ip where status=0", true);
	fprintf(stderr, "%d ips unchecked\r\n", unchecked);

	//mysqloptimize();

	query("update ip set status = 0 where status = -2");

	loadscanned();

	if(scanned.size())
		printf(" %d ips\r\n", scanned.size());


	if(!demon)
	{
		initscr();
		clear();
		refresh();
	}

	pthread_attr_init(&tattr);
	pthread_attr_setstacksize(&tattr, stacksize);

	if(offone)
	{
		pthread_create(&toffone, &tattr, dooffone, NULL);
		//	exit(0);
	}
	else {



		int i = 1;


		for(;i < nthreads / 3;i++)
		{
			pthread_attr_init(&tattr);

			pthread_attr_setstacksize(&tattr, stacksize);
			pthread_create(&t2, &tattr, check_exist_socks, (void*) i);

		}

		for(;i < (nthreads);i++)
		{
			pthread_attr_init(&tattr);

			pthread_attr_setstacksize(&tattr, stacksize);
			pthread_create(&t3, &tattr, check_new_socks, (void*) i);

		}

		if(!checkonly)
		{
			//for(int i=0;i<4;i++)
			pthread_attr_init(&tattr);
			pthread_attr_setstacksize(&tattr, stacksize);
			//for(int i=0;i<3;i++)
			pthread_create(&t1, &tattr, send_packets, NULL);
		}


		//start_color();			/* Start color 			*/
	//	init_pair(1, COLOR_RED, COLOR_BLACK);
	//	init_pair(2, COLOR_CYAN, COLOR_BLACK);
	//	init_pair(3, COLOR_YELLOW, COLOR_BLACK);

		mprint(0, 0, "socks scanner - active [ni0s pri8 soft.war.e]");
	}
	if(demon && !fork())
		exit(0);

	while(continue_scan)
	{
		if(!demon)
			refresh();
		//if(last_scans != scans_per_second && mfree())
		//{

				//if(verbose)
				//move(2,0);
		mclreol(2, 0);
		static float eff = 0.9;
		//if(rst_packets > ack_packets)
		eff = (float(total_packets) / float(scanned_ips)) * 100.0;
		mprint(2, 0, "speed:%8lu drp:%3lu oth:%-5d ack:%-5d sks:%-5d rst:%-4d | dup:%3lu db:%3d  unchkd:%3d chkd:%3d "
			"ndelay:%3d delay:%3d eff:%.2f fake:%3d", scans_per_second, drops,
			other_packets, ack_packets, sockscheck_packets, rst_packets,
			dup_rnd, db_querys_second, new_socks, chkd_socks, network_ndelay, delay, eff, fake.size());
		//refresh();
		mclreol(0, 50);
		mprint(0, 50, "%s:%d", inet_ntoa((struct in_addr) ip.sin_addr), scan_port);
		last_scans = scans_per_second;
		//}
		drops = 0;

		other_packets = 0;
		//		if(eff <= 25.0) 
		//		{
		//			mprint(5,0,"%lu <= %lu",ack_packets,rst_packets+other_packets);
		//			if(network_ndelay<=150)
		//				network_ndelay+=rand()%3;
		//			
		//			delay += rand()%1;
		//		} else {
		//			//if(sec_packets )
		//					delay=0;
		//			//if(network_ndelay>10)
		//				if(network_ndelay>=99)
		//						network_ndelay-=rand()%13;
		//		}
		rst_packets = 0;
		//ack_packets=0;
		sec_packets = 0;
		usleep(network_ndelay * 1000);
	}

	if(!demon)
		endwin();
	mysql_close(mysql);
}
