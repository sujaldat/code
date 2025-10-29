// sniff_and_spoof.c
// Build: gcc -O2 -Wall -o sniff_and_spoof sniff_and_spoof.c -lpcap
// Run: sudo ./sniff_and_spoof <interface>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#define SNAPLEN 65535

// checksum helper
unsigned short checksum(void *b, int len){
    unsigned short *buf = b;
    unsigned int sum=0;
    while(len>1){
        sum += *buf++;
        len -= 2;
    }
    if(len==1) sum += *(unsigned char*)buf;
    sum = (sum>>16) + (sum & 0xffff);
    sum += (sum>>16);
    return (unsigned short)(~sum);
}

int raw_socket = -1;

void send_icmp_reply(const u_char *ip_pkt, int plen){
    struct iphdr *rip = (struct iphdr*)ip_pkt;
    int ihl = rip->ihl*4;
    if(plen < ihl + sizeof(struct icmphdr)) return;

    struct icmphdr *icmp_req = (struct icmphdr*)(ip_pkt + ihl);
    if(icmp_req->type != ICMP_ECHO) return;

    // build reply packet buffer: IP + ICMP + payload
    int data_len = plen - ihl - sizeof(struct icmphdr);
    int packet_len = ihl + sizeof(struct icmphdr) + data_len;
    char *packet = malloc(packet_len);
    if(!packet) return;
    memset(packet,0,packet_len);

    struct iphdr *iph = (struct iphdr*)packet;
    struct icmphdr *icmph = (struct icmphdr*)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct icmphdr);

    // copy payload (if any)
    if(data_len > 0) memcpy(data, ip_pkt + ihl + sizeof(struct icmphdr), data_len);

    // fill ICMP reply
    icmph->type = ICMP_ECHOREPLY;
    icmph->code = 0;
    icmph->un.echo.id = icmp_req->un.echo.id;
    icmph->un.echo.sequence = icmp_req->un.echo.sequence;
    icmph->checksum = 0;
    icmph->checksum = checksum((unsigned short*)icmph, sizeof(struct icmphdr) + data_len);

    // fill IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(packet_len);
    iph->id = htons(0);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0;
    iph->saddr = rip->daddr; // swap: reply source = original dst
    iph->daddr = rip->saddr; // reply dest = original src
    iph->check = checksum((unsigned short*)iph, iph->ihl*4);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iph->daddr;

    // send packet (RAW socket with IP_HDRINCL)
    ssize_t sent = sendto(raw_socket, packet, packet_len, 0, (struct sockaddr*)&sin, sizeof(sin));
    free(packet);
    (void)sent;
}

void pkt_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
    // bytes points to L2 (Ethernet) frame. Skip Ethernet header (assume 14 bytes)
    if(h->caplen < 14 + 20 + 8) return;
    const u_char *ip_pkt = bytes + 14;
    struct iphdr *iph = (struct iphdr*)ip_pkt;
    if(iph->protocol != IPPROTO_ICMP) return;
    // check icmp type
    unsigned int ihl = iph->ihl*4;
    if(h->caplen < 14 + ihl + sizeof(struct icmphdr)) return;
    struct icmphdr *icmph = (struct icmphdr*)(ip_pkt + ihl);
    if(icmph->type == ICMP_ECHO){
        send_icmp_reply(ip_pkt, h->caplen - 14);
    }
}

int main(int argc, char **argv){
    if(argc != 2){
        fprintf(stderr,"Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(dev, SNAPLEN, 1, 1000, errbuf);
    if(!pcap){ fprintf(stderr,"pcap_open_live failed: %s\n", errbuf); return 1; }

    // open raw socket
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(raw_socket < 0){ perror("socket"); return 1; }
    int one = 1;
    if(setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){ perror("setsockopt"); close(raw_socket); return 1; }

    // filter for icmp only (link-layer header type = Ethernet -> offset 14)
    struct bpf_program fp;
    char filter_exp[128];
    snprintf(filter_exp, sizeof(filter_exp), "icmp and not src host 127.0.0.1");
    if(pcap_compile(pcap, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1){
        fprintf(stderr,"pcap_compile failed\n"); return 1;
    }
    if(pcap_setfilter(pcap, &fp) == -1){ fprintf(stderr,"pcap_setfilter failed\n"); return 1; }

    // loop, call pkt_handler when packet arrives
    pcap_loop(pcap, -1, pkt_handler, NULL);

    pcap_close(pcap);
    close(raw_socket);
    return 0;
}
