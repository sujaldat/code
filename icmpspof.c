/* icmpspoof.c
   Minimal ICMP spoof (raw socket). Compile with: gcc -O2 -o icmpspoof icmpspoof.c
   Usage: sudo ./icmpspoof <src-ip> <dst-ip> [payload-text] [ip_len_override]
   Example: sudo ./icmpspoof 10.9.0.5 10.9.0.6 "hello"    # default correct lengths
            sudo ./icmpspoof 10.9.0.5 10.9.0.6 "x" 60    # override ip total-length to 60 bytes
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "seedheaders.h"   /* provides struct icmpheader and struct ipheader */

unsigned short in_cksum (unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(u_char *) (&temp) = *(u_char *)w;
        sum += temp;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}

/* Send the raw IP packet buffer of total length 'len' (host order). */
void send_raw_ip_packet(void *packet, int len) {
    struct sockaddr_in dest_info;
    int enable = 1;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket(AF_INET,SOCK_RAW)");
        return;
    }
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sock);
        return;
    }
    struct ipheader *ip = (struct ipheader *)packet;
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;
    if (sendto(sock, packet, len, 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
        perror("sendto");
    } else {
        printf("[+] sent %d bytes: %s -> %s\n", len,
               inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
    }
    close(sock);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <src-ip> <dst-ip> [payload-text] [ip_len_override]\n", argv[0]);
        return 1;
    }

    const char *src_ip_s = argv[1];
    const char *dst_ip_s = argv[2];
    const char *payload_txt = (argc >= 4) ? argv[3] : "ICMP-TEST";
    int ip_len_override = (argc >= 5) ? atoi(argv[4]) : 0; /* 0 => no override */

    /* Build packet buffer: IP header + ICMP header + payload */
    int payload_len = strlen(payload_txt);
    int ip_hdr_len = sizeof(struct ipheader);
    int icmp_hdr_len = sizeof(struct icmpheader);
    int total_true_len = ip_hdr_len + icmp_hdr_len + payload_len;

    /* allocate buffer slightly larger than needed */
    int buf_size = 4096;
    unsigned char *packet = calloc(1, buf_size);
    if (!packet) { perror("calloc"); return 1; }

    struct ipheader *ip = (struct ipheader *) packet;
    struct icmpheader *icmp = (struct icmpheader *) (packet + ip_hdr_len);
    unsigned char *data = packet + ip_hdr_len + icmp_hdr_len;

    /* Fill ICMP header */
    icmp->icmp_type = 8;       /* echo request */
    icmp->icmp_code = 0;
    icmp->icmp_id = htons(0x1234);  /* arbitrary id */
    icmp->icmp_seq = htons(1);
    icmp->icmp_chksum = 0;
    /* copy payload */
    memcpy(data, payload_txt, payload_len);
    /* compute ICMP checksum over header+payload */
    int icmp_total_len = icmp_hdr_len + payload_len;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp, icmp_total_len);

    /* Fill IP header */
    ip->iph_ver = 4;
    ip->iph_ihl = 5; /* 5*4 = 20 bytes */
    ip->iph_tos = 0;
    /* total length: header + icmp+payload (network byte order) */
    int ip_total_len = total_true_len;
    if (ip_len_override > 0) {
        /* if user provided override, use it (but still must store in network order) */
        ip_total_len = ip_len_override;
        printf("[!] NOTE: IP total-length overridden to %d (may not match actual payload).\n", ip_len_override);
    }
    ip->iph_len = htons(ip_total_len);
    ip->iph_ident = htons(0xABCD);
    ip->iph_flag = 2; /* Don't Fragment (DF) bit: 2 indicates DF in this bitfield layout */
    ip->iph_offset = 0;
    ip->iph_ttl = 64;
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_chksum = 0;
    inet_aton(src_ip_s, &ip->iph_sourceip);
    inet_aton(dst_ip_s, &ip->iph_destip);
    /* compute IP header checksum (over the header only) */
    ip->iph_chksum = in_cksum((unsigned short *)ip, ip_hdr_len);

    /* Determine send length for sendto: use ip_total_len (host order) */
    int send_len = ntohs(ip->iph_len);
    if (send_len <= 0 || send_len > buf_size) {
        fprintf(stderr, "invalid send length %d\n", send_len);
        free(packet);
        return 1;
    }

    /* Send */
    send_raw_ip_packet(packet, send_len);

    free(packet);
    return 0;
}
