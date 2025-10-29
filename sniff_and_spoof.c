// minimal sniff_and_spoof.c
// build: gcc -O2 -Wall -o sniff_and_spoof sniff_and_spoof.c -lpcap
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned short csum(void *b,int len){
    unsigned short *buf=b; unsigned int sum=0;
    while(len>1){ sum+=*buf++; len-=2; }
    if(len==1) sum+=*(unsigned char*)buf;
    sum=(sum>>16)+(sum&0xffff); sum+=sum>>16;
    return ~sum;
}

int rawfd;
void send_reply(const u_char *ip_pkt,int plen){
    struct iphdr *rip=(struct iphdr*)ip_pkt;
    int ihl=rip->ihl*4;
    if(plen<ihl+sizeof(struct icmphdr)) return;
    struct icmphdr *req=(struct icmphdr*)(ip_pkt+ihl);
    if(req->type!=ICMP_ECHO) return;
    int dlen=plen-ihl-sizeof(struct icmphdr);
    int pktlen=sizeof(struct iphdr)+sizeof(struct icmphdr)+dlen;
    char *pkt=malloc(pktlen); if(!pkt) return;
    memset(pkt,0,pktlen);
    struct iphdr *iph=(struct iphdr*)pkt;
    struct icmphdr *ic=(struct icmphdr*)(pkt+sizeof(struct iphdr));
    if(dlen>0) memcpy(pkt+sizeof(struct iphdr)+sizeof(struct icmphdr), ip_pkt+ihl+sizeof(struct icmphdr), dlen);
    ic->type=ICMP_ECHOREPLY; ic->code=0; ic->un.echo.id=req->un.echo.id; ic->un.echo.sequence=req->un.echo.sequence;
    ic->checksum=0; ic->checksum=csum(ic,sizeof(struct icmphdr)+dlen);
    iph->ihl=5; iph->version=4; iph->tot_len=htons(pktlen); iph->ttl=64; iph->protocol=IPPROTO_ICMP;
    iph->saddr=rip->daddr; iph->daddr=rip->saddr; iph->check=0; iph->check=csum(iph,iph->ihl*4);
    struct sockaddr_in sin; sin.sin_family=AF_INET; sin.sin_addr.s_addr=iph->daddr;
    sendto(rawfd,pkt,pktlen,0,(struct sockaddr*)&sin,sizeof(sin));
    free(pkt);
}

void cb(u_char *usr,const struct pcap_pkthdr *h,const u_char *bytes){
    if(h->caplen<14) return;
    const u_char *ip_pkt=bytes+14;
    struct iphdr *iph=(struct iphdr*)ip_pkt;
    if(iph->protocol!=IPPROTO_ICMP) return;
    send_reply(ip_pkt,h->caplen-14);
}

int main(int argc,char **argv){
    if(argc!=2) return printf("usage: %s <iface>\n",argv[0]),1;
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *p=pcap_open_live(argv[1],65535,1,1000,err);
    if(!p) return fprintf(stderr,"pcap_open_live fail: %s\n",err),1;
    rawfd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    if(rawfd<0) return perror("socket"),1;
    int one=1; setsockopt(rawfd,IPPROTO_IP,IP_HDRINCL,&one,sizeof(one));
    pcap_loop(p,-1,cb,NULL);
    close(rawfd); pcap_close(p);
    return 0;
}
