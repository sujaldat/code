/* ICMP  Header */
struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; // Checksum for ICMP header and data
    unsigned short int icmp_id; // used for identifying request
    unsigned short int icmp_seq; // sequence number
};

/* ip header */
struct ipheader {
    unsigned char iph_ihl:4,
    iph_ver:4;
    unsigned char iph_tos; //type of service
    unsigned short int iph_len; //header length
    unsigned short int iph_ident; //identifier
    unsigned short int iph_flag:3,iph_offset:13; //flags, fragment offset
    unsigned char iph_ttl; //time to live
    unsigned char iph_protocol; //protocol type
    unsigned short int iph_chksum; //checksum
    struct in_addr iph_sourceip; //source ip
    struct in_addr iph_destip; //dest ip
};
