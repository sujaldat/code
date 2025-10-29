#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

// Basic checksum routine for IP/ICMP 
static unsigned short calc_checksum(void *data, int len) {
    unsigned short *ptr = data;
    unsigned int sum= 0;
    while (len >1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1)sum +=*(unsigned char *)ptr;
    // fold 32-bit to 16-bit and return one's complement
    sum = (sum >> 16)+(sum & 0xffff);
    sum += (sum >>16);
    return ~sum;
}
// Socket for sending forged replies
int raw_socket =-1;
// Build and send a fake ICMP Echo Reply based on the captured request
void send_icmp_reply(const u_char *packet, int pkt_len) {
    struct iphdr *incoming_ip = (struct iphdr *)packet;
    int ip_header_len = incoming_ip->ihl *4;
    // sanity: make sure there's room for an ICMP header
    if (pkt_len < ip_header_len+(int)sizeof(struct icmphdr)) return;
    struct icmphdr *icmp_req =(struct icmphdr *)(packet + ip_header_len);
    if (icmp_req->type != ICMP_ECHO)
        return; // not a ping? so skiping it
    int data_len = pkt_len -ip_header_len- sizeof(struct icmphdr);
    int full_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len;
    char *reply_buf = malloc(full_len);
    if (!reply_buf) return;
    memset(reply_buf,0,full_len);
    struct iphdr *ip_out =(struct iphdr *)reply_buf;
    struct icmphdr *icmp_out =(struct icmphdr *)(reply_buf +sizeof(struct iphdr));
    char *payload = reply_buf+ sizeof(struct iphdr) + sizeof(struct icmphdr);
    // copy over the original data/payload if there's any
    if (data_len >0)
        memcpy(payload, packet + ip_header_len + sizeof(struct icmphdr), data_len);
    // build the ICMP header
    icmp_out->type =ICMP_ECHOREPLY;
    icmp_out->code =0;
    icmp_out->un.echo.id= icmp_req->un.echo.id;
    icmp_out->un.echo.sequence= icmp_req->un.echo.sequence;
    icmp_out->checksum= 0;
    icmp_out->checksum= calc_checksum(icmp_out, sizeof(struct icmphdr) + data_len);
    // now building the IP header
    ip_out->ihl=5;
    ip_out->version=4;
    ip_out->tos =0;
    ip_out->tot_len= htons(full_len);
    ip_out->id = 0;  // could randomize this if needed ()
    ip_out->frag_off=0;
    ip_out->ttl=64;
    ip_out->protocol = IPPROTO_ICMP;
    ip_out->saddr= incoming_ip->daddr;  // swap src / dst
    ip_out->daddr= incoming_ip->saddr;
    ip_out->check= 0;
    ip_out->check= calc_checksum(ip_out, ip_out->ihl *4);
    // send it out
    struct sockaddr_in target_addr ={0};
    target_addr.sin_family =AF_INET;
    target_addr.sin_addr.s_addr= ip_out->daddr;

    sendto(raw_socket, reply_buf,full_len, 0,
           (struct sockaddr *)&target_addr,sizeof(target_addr));

    free(reply_buf);
}

// pcap callback: strip off Ethernet header, check protocol, maybe spoof
void sniff_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *frame) {
    if (hdr->caplen < 14) return;  // false
    const u_char *ip_packet = frame + 14;
    struct iphdr *ip = (struct iphdr *)ip_packet;
    if (ip->version != 4) return;
    if (ip->protocol != IPPROTO_ICMP) return;
    send_icmp_reply(ip_packet, hdr->caplen -14);
}

// main: open capture and injection sockets, loop forever
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    char *iface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *pcap = pcap_open_live(iface, 65535, 1, 1000, errbuf);
    if(!pcap) {
        fprintf(stderr,"pcap_open_live failed: -- %s\n", errbuf);
        return 1;
    }
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_socket <0) {
        perror("socket");
        pcap_close(pcap);
        return 1;
    }
    int enable =1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("setsockopt(IP_HDRINCL) :");
        close(raw_socket);
        pcap_close(pcap);
        return 1;
    }
    // sniff packets forever
    pcap_loop(pcap, -1, sniff_cb, NULL);
    // should never get here, but just in case
    close(raw_socket);
    pcap_close(pcap);
    return 0;
}



