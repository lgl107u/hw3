#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */

        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* MAC Adress */
struct sniff_ether{
   const struct ether_addr dAddr;
   const struct ether_addr sAddr;
   uint8_t protocol; 
};

typedef struct accm{
    char src[30];
    char dst[30];
    int cnt;
}accm;

#define idxofmem 100

int int_cmp(const void *a, const void *b) 
{ 
    struct accm *ia = (struct accm *)a; // casting pointer types 
    struct accm *ib = (struct accm *)b;
    return ib->cnt-ia->cnt; 
} 

int main(int argc, char **argv)
{
    char *filename= argv[1];
    char frmt[] = "%Y-%m-%d %H:%M:%0S ";
    char errbuf[PCAP_ERRBUF_SIZE];
    int idxme=0;
    pcap_t *handle = pcap_open_offline(filename,errbuf);
    
    FILE *fp = fopen("captured.txt","w");
    FILE *amt = fopen("result.txt","w");
    struct pcap_pkthdr *header;

    static int count = 0;
	const char *payload;
    const u_char *packet;

    accm counterfile[100000] ;
    int run=0;

    /* header of output file */
    fprintf(amt,"No\tSource address\t\tDest address\t\tCount\n");
    fprintf(fp,"No\tSrc add\t\tDest add\tPrtcl\tS.port\tD.port\tS.mac\t\t\tD.mac\t\t\tTime\n");

    while ( pcap_next_ex(handle,&header,&packet) >=0)
    {
        /* declare pointers to packet headers */
        const struct sniff_ether *eth;
        const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
        const struct sniff_ip *ip;              /* The IP header */
        const struct sniff_tcp *tcp;            /* The TCP header */
        const char *payload;                    /* Packet payload */

        int size_ip;
        int size_tcp;
        int size_payload;

        /* define mac header*/
        eth = (struct sniff_ether*)(packet);
        
        /* define ethernet header */
        ethernet = (struct sniff_ethernet*)(packet);
        
        /* define/compute ip header offset */
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;

        size_ip = IP_HL(ip)*4;
        // if (size_ip < 20) {
        //     printf("   * Invalid IP header length: %u bytes\n", size_ip);
        //     break;
        // }
        fprintf(fp,"%d\t",++count);
        
        /* source and destination ip */
        if(run>0)
        {
            int i;
            int flag=0;

            for(i=0;i<run;i++)
            {
                if(strcmp(counterfile[i].src,inet_ntoa(ip->ip_src) )==0 )
                {
                    if(strcmp(counterfile[i].dst,inet_ntoa(ip->ip_dst) )==0)
                    {
                        counterfile[i].cnt++;
                        flag=1;
                        break;
                    }
                }
            }
            // printf("|i=%d flag=%d run=%d|\n",i,flag,run);

            if(flag==0)
            {
                strcpy ( counterfile[i].src , inet_ntoa(ip->ip_src) );
                strcpy ( counterfile[i].dst , inet_ntoa(ip->ip_dst) );
                counterfile[i].cnt = 1;
                run++;
            }
            // printf("%d|%s|\t\t|%s|\n",count,counterfile[i].src,counterfile[i].dst);
        }

        else if (run == 0 )
        {
            strcpy ( counterfile[0].src , inet_ntoa(ip->ip_src) );
            strcpy ( counterfile[0].dst , inet_ntoa(ip->ip_dst) );
            counterfile[0].cnt = 1;
            // printf("|%s|\t\t|%s|\n",counterfile[0].src,counterfile[0].dst);
            run++;
        }

        if( strcmp(inet_ntoa(ip->ip_src),"0.0.0.0")==0 || strlen(inet_ntoa(ip->ip_src)) <8) fprintf(fp,"%s\t\t",inet_ntoa(ip->ip_src)); 
        else fprintf(fp,"%s\t",inet_ntoa(ip->ip_src));
        
        if( strcmp(inet_ntoa(ip->ip_dst),"0.0.0.0")==0 || strlen(inet_ntoa(ip->ip_dst)) <8) fprintf(fp,"%s\t\t",inet_ntoa(ip->ip_dst)); 
        else fprintf(fp,"%s\t",inet_ntoa(ip->ip_dst));

        // fprintf(fp,"|%d|\t",ip->ip_p);
        switch(ip->ip_p) {
            case 7:
                fprintf(fp," ARP\t");
                break;
            // case 17:
            case IPPROTO_UDP:
                fprintf(fp," UDP\t");
                break;
            case IPPROTO_TCP:
                fprintf(fp," TCP\t");
                break;
            case IPPROTO_ICMP:
                fprintf(fp," ICMP\t");
                break;
            case IPPROTO_IP:
                fprintf(fp," IP\t");
                break;
            default:
                fprintf(fp,"unknw\t");
                break;
	    }

        //ports 
        fprintf(fp,"%d\t%d\t", ntohs(tcp->th_sport), ntohs(tcp->th_dport));

        /*mac adrress*/
        if(strlen(ether_ntoa(&eth->sAddr))<=15) fprintf(fp,"%s\t\t", ether_ntoa(&eth->sAddr));
        else fprintf(fp,"%s\t", ether_ntoa(&eth->sAddr),strlen(ether_ntoa(&eth->sAddr)));

        if(strlen(ether_ntoa(&eth->dAddr))<=15) fprintf(fp,"%s\t\t", ether_ntoa(&eth->dAddr));
        else fprintf(fp,"%s\t", ether_ntoa(&eth->dAddr));

        //time 
        struct tm *lt = localtime(&header->ts.tv_sec);
        char st[100];
        strftime(st, 100, frmt, lt);
        fprintf(fp,"%s",st);

        /* file new line */
        fprintf(fp,"\n");
    }
    int i;
    qsort(counterfile, run, sizeof(accm), int_cmp);
    for(i=0;i<run;i++)
    {
        fprintf(amt,"%d\t%s\t\t%s\t\t%d\n",i+1,counterfile[i].src,counterfile[i].dst,counterfile[i].cnt);
    }

    fclose(fp);
    return 0;
}
