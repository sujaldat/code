/* icmpspoof.c
   Build: gcc -O2 -Wall -o icmpspoof icmpspoof.c
   Usage:
     sudo ./icmpspoof <spoof-src-ip> <dst-ip> [--totlen N]
   Notes:
     - MUST run as root (raw sockets require CAP_NET_RAW).
     - Only test against machines you control (lab VMs/containers). Do NOT target random Internet hosts.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

/* simple ones-complement checksum */
static unsigned short chksum(void *b, int len){
    unsigned short *p = b;
    unsigned int sum = 0;
    while(len > 1){ sum += *p++; len -= 2; }
    if(len == 1) sum += *(unsigned char*)p;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char **argv){
    if(argc < 3){
        fprintf(stderr,"usage: %s <spoof-src-ip> <dst-ip> [--totlen N]\n", argv[0]);
        return 1;
    }
    const char *src = argv[1];
    const char *dst = argv[2];
    int custom_totlen = 0;
    int totlen_val = 0;
    if(argc == 5 && strcmp(argv[3],"--totlen")==0){
        custom_totlen = 1;
        totlen_val = atoi(argv[4]);
        if(totlen_val <= 0 || totlen_val > 65535){ fprintf(stderr,"bad totlen\n"); return 1; }
    }

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0){ perror("socket"); return 1; }

    int on = 1;
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
        perror("setsockopt(IP_HDRINCL)");
        close(sd);
        return 1;
    }

    /* prepare payload */
    const char *payload = "ICMP-SPOOF";
    int plen = strlen(payload);

    /* build IP+ICMP in buffer */
    unsigned char buf[4096];
    memset(buf,0,sizeof(buf));
    struct iphdr *iph = (struct iphdr*)buf;
    struct icmphdr *icm = (struct icmphdr*)(buf + sizeof(struct iphdr));
    char *data = (char*)(buf + sizeof(struct iphdr) + sizeof(struct icmphdr));
    memcpy(data, payload, plen);

    /* ICMP echo request (we spoof a request leaving src=spoof-src -> dst) */
    icm->type = ICMP_ECHO;
    icm->code = 0;
    icm->un.echo.id = htons(0x1234);
    icm->un.echo.sequence = htons(1);
    icm->checksum = 0;
    icm->checksum = chksum(icm, sizeof(struct icmphdr) + plen);

    int ip_hdr_len = sizeof(struct iphdr);
    int ip_total = ip_hdr_len + sizeof(struct icmphdr) + plen;

    if(custom_totlen){
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(totlen_val); /* intentionally set to chosen value */
    } else {
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(ip_total);
    }

    iph->id = htons(0x5555);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0;
    iph->saddr = inet_addr(src);
    iph->daddr = inet_addr(dst);
    iph->check = chksum(iph, iph->ihl*4);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iph->daddr;

    ssize_t sent = sendto(sd, buf, ip_total, 0, (struct sockaddr*)&sin, sizeof(sin));
    if(sent < 0){
        perror("sendto");
        close(sd);
        return 1;
    }
    printf("sent %zd bytes IP(src=%s -> dst=%s) tot_len_field=%d actual_len=%d\n",
           sent, src, dst, custom_totlen ? totlen_val : ip_total, ip_total);
    close(sd);
    return 0;
}
