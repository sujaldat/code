/* pcap_sniffer.c
   usage: sudo ./pcap_sniffer <iface> "<bpf-filter>" <count> <out.pcap>
*/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

static pcap_dumper_t *dumper = NULL;

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    /* print short summary: timestamp len and first 6 bytes of IP header if present */
    printf("pkt: len=%u\n", h->len);
    if (dumper) pcap_dump((u_char*)dumper, h, bytes);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <iface> \"<bpf-filter>\" <count> <out.pcap>\n", argv[0]);
        return 1;
    }
    char *dev = argv[1];
    char *filter_exp = argv[2];
    int count = atoi(argv[3]);
    char *outname = argv[4];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (!handle) { fprintf(stderr, "pcap_open_live(%s): %s\n", dev, errbuf); return 1; }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile failed for filter '%s'\n", filter_exp);
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed\n");
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&fp);

    dumper = pcap_dump_open(handle, outname);
    if (!dumper) { fprintf(stderr, "pcap_dump_open failed for %s\n", outname); pcap_close(handle); return 1; }

    printf("Listening on %s  filter=\"%s\"  count=%d  writing=%s\n", dev, filter_exp, count, outname);
    pcap_loop(handle, count, packet_handler, NULL);

    pcap_dump_close(dumper);
    pcap_close(handle);
    return 0;
}
