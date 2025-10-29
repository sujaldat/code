/* sniffex.c - minimal libpcap example for the lab */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static volatile int keep_running = 1;
void intHandler(int dummy) { keep_running = 0; }

void pkt_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    printf("Captured packet: len=%u\n", h->len);
    /* print first 64 bytes hex */
    unsigned int i, n = h->len < 64 ? h->len : 64;
    for (i = 0; i < n; ++i) {
        printf("%02x ", bytes[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");
    keep_running = 0; /* stop after first packet */
}

int main(int argc, char **argv) {
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int promisc = 1; /* default: promiscuous ON */
    int snaplen = 65535;
    int to_ms = 1000; /* read timeout */

    if (argc > 1) dev = argv[1];
    if (argc > 2) promisc = atoi(argv[2]); /* 1 or 0 */

    if (!dev) {
        dev = pcap_lookupdev(errbuf);
        if (!dev) { fprintf(stderr, "pcap_lookupdev: %s\n", errbuf); return 1; }
    }

    /* open */
    handle = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);
    if (!handle) { fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf); return 1; }

    /* optional: compile & set a filter (none here) */
    /* run capture loop -- will call pkt_handler for each packet */
    signal(SIGINT, intHandler);
    while (keep_running) {
        pcap_dispatch(handle, 1, pkt_handler, NULL); /* read 1 packet at a time */
    }

    pcap_close(handle);
    return 0;
}
