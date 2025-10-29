#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

/* -- checksum helper: standard 16-bit ones-complement checksum -- */
static unsigned short csum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/* raw socket descriptor used to inject crafted IP packets with IP_HDRINCL */
static int rawfd = -1;

/*
 send_reply:
  - ip_pkt: pointer to the start of an IPv4 packet (network byte order)
  - plen: length of IPv4 packet in bytes
  - constructs an IPv4 + ICMP echo-reply packet with:
      src = original dst, dst = original src
      ICMP id/seq copied from request
      payload copied unchanged
  - sends packet via raw socket (IP_HDRINCL must be enabled)
*/
void send_reply(const u_char *ip_pkt, int plen) {
    struct iphdr *rip = (struct iphdr*)ip_pkt;
    int ihl = rip->ihl * 4;
    /* require minimum IP + ICMP header length */
    if (plen < ihl + (int)sizeof(struct icmphdr)) return;

    struct icmphdr *req = (struct icmphdr*)(ip_pkt + ihl);
    /* only respond to echo requests (type 8) */
    if (req->type != ICMP_ECHO) return;

    int data_len = plen - ihl - sizeof(struct icmphdr);
    int pktlen = sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len;

    /* allocate packet buffer for reply (IP + ICMP + payload) */
    char *pkt = malloc(pktlen);
    if (!pkt) return;
    memset(pkt, 0, pktlen);

    struct iphdr *iph = (struct iphdr*)pkt;
    struct icmphdr *ic = (struct icmphdr*)(pkt + sizeof(struct iphdr));
    char *payload_dst = pkt + sizeof(struct iphdr) + sizeof(struct icmphdr);

    /* copy payload (if present) from request to reply */
    if (data_len > 0) {
        memcpy(payload_dst, ip_pkt + ihl + sizeof(struct icmphdr), data_len);
    }

    /* populate ICMP reply header */
    ic->type = ICMP_ECHOREPLY;                 /* 0 */
    ic->code = 0;
    ic->un.echo.id = req->un.echo.id;          /* copy id */
    ic->un.echo.sequence = req->un.echo.sequence; /* copy seq */
    ic->checksum = 0;
    ic->checksum = csum(ic, sizeof(struct icmphdr) + data_len);

    /* populate IP header (simple, minimal fields) */
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(pktlen);
    iph->id = htons(0);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = rip->daddr; /* reply source = original dst */
    iph->daddr = rip->saddr; /* reply dest   = original src */
    iph->check = 0;
    iph->check = csum(iph, iph->ihl * 4);

    /* destination sockaddr for sendto */
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iph->daddr;

    /* inject packet */
    sendto(rawfd, pkt, pktlen, 0, (struct sockaddr*)&sin, sizeof(sin));

    free(pkt);
}

/*
 pcap callback:
  - receives full link-layer frame; this code assumes Ethernet and strips 14-octet header.
  - checks IPv4 & ICMP; if an ICMP echo-request is found, calls send_reply.
*/
void pkt_cb(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    if (h->caplen < 14) return;                 /* not an Ethernet frame */
    const u_char *ip_pkt = bytes + 14;          /* skip Ethernet header */
    struct iphdr *iph = (struct iphdr*)ip_pkt;
    if (iph->version != 4) return;
    if (iph->protocol != IPPROTO_ICMP) return;
    int ip_plen = h->caplen - 14;               /* IPv4 packet length captured */
    send_reply(ip_pkt, ip_plen);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <interface>\n", argv[0]);
        return 1;
    }
    char *iface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    /* open pcap in promiscuous mode to capture ICMP frames at link layer */
    pcap_t *pcap = pcap_open_live(iface, 65535, 1, 1000, errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    /* open raw socket for injection and enable IP_HDRINCL */
    rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rawfd < 0) { perror("socket"); pcap_close(pcap); return 1; }
    int one = 1;
    if (setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(rawfd); pcap_close(pcap); return 1;
    }

    /* optional BPF filter can be set here (omitted to keep minimal) */
    pcap_loop(pcap, -1, pkt_cb, NULL);

    close(rawfd);
    pcap_close(pcap);
    return 0;
}
