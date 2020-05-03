/**
 * @file   sniffer.cpp
 * @author Simon Sedlacek, xsedla1h
 * @brief  This module implements the core sniffer functions.
 */ 

#include "sniffer.hpp"

/* This is a hostname cache which allows us to resolve hostnames without endlessly
 * resolving the queries... */
std::map<uint32_t, std::string> ipv4_cache;

int sniff_init(char *interface, unsigned *port, unsigned *n_packets, bool tcp, bool udp) {

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;


    /* First, open the target device */
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error: cannot open device - " << errbuf << std::endl;
        return ERROR_OPEN_DEVICE;
    }

    /* Check the link-layer type for the device - ETHERNET 802.3 and linux cooked
     * only... */
    if (pcap_datalink(handle) != DLT_EN10MB && pcap_datalink(handle) != DLT_LINUX_SLL) {
        std::cerr << "Error: only ethernet is supported\n";
        return(ERROR_SNIFFER);
    }

    /* Get the netmask for the device */
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        std::cerr << "Error: could not load the device's netmask - "
            << errbuf << std::endl;
        net = 0;
        mask = 0;
    }

    /* Filter the packets for ipv4/v6 and tcp/ucp only.. */
    struct bpf_program fp;
    std::string filter;
    std::string tcp_filter = "proto \\tcp";
    std::string udp_filter = "proto \\udp";
    if (tcp != udp) {
        filter = (tcp ? tcp_filter : udp_filter);
    } else {
        filter = "(" + tcp_filter + ") or (" + udp_filter + ")";
    }

    /* Filter the traffic by port if specified... */
    if (port != nullptr) {
        filter = "(" + filter + ") and (port " + std::to_string(*port) + ")";
    }

    /* Compile and set the final filter */
    if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1) {
        std::cerr << "Error: Invalid filter" << filter << ": "
            << pcap_geterr(handle) << std::endl;
        return(ERROR_SNIFFER);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
       std::cerr << "Error: Couldn't set filter " << filter << ": "
           << pcap_geterr(handle) << std::endl;
        return(ERROR_SNIFFER);
    }

    /* Start the actual sniffing process */
    if (sniff(handle, n_packets) != SUCCESS) {
        return ERROR_SNIFFER;
    }

    pcap_freecode(&fp);
    pcap_close(handle);
    return SUCCESS;
}

int sniff(pcap_t *handle, unsigned *n_packets) {
    int retval;
    u_char *user = NULL;
    unsigned packet_count = 1;

    /* Set the number of packets we want to sniff. The implicit value is 1, 0 means
     * sniffing until a user interrupt. */
    if (n_packets != nullptr) packet_count = *n_packets;

    /* Enter the sniffing loop.. */
    while ((retval = pcap_loop(handle, packet_count,
                    (pcap_handler)&process_packet, user)) != 0) {

        /* Handle potential errors.. */
        if (retval == PCAP_ERROR) {
            std::cerr << "Error: An error occured during packet sniffing.\n";
            pcap_perror(handle, "Error: ");

        } else if (retval == PCAP_ERROR_BREAK) {
            std::cerr << "PCAP_ERROR_BREAK\n";
            break;
        }
    }

    return SUCCESS;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (args) {} /* eliminate the unused parameter warning... */
    int retval;
    const struct ether_header *eth_header;
    pckt_data packet_data;

    /* Store the pcap packet header and the packet itself to our structure */
    packet_data.header = header;
    packet_data.packet = packet;
    packet_data.eth_len = ETH_HDR_SIZE;

    eth_header = (struct ether_header *)(packet); /* get the ethernet header */
    u_short type = ntohs(eth_header->ether_type); /* get the ethernet type */

    /* Determine the type of the IP packet and process it */
    if (type == ETHERTYPE_IP) {
        retval = process_ipv4(packet + ETH_HDR_SIZE, &packet_data);

    } else if (type == ETHERTYPE_IPV6) {
        retval = process_ipv6(packet + ETH_HDR_SIZE, &packet_data);

    } else {
        return;
    }

    if (retval != 0)
        return;

    print_current_packet_data(packet_data);
}

int process_ipv4(const u_char *packet, pckt_data *packet_data) {
    int retval;
    const struct ip *ip_hdr;
    packet_data->ipv = IP_VER4;

    /* Extract the ip packet */
    ip_hdr = (struct ip *)(packet);

    /* Store the source and destination ip_address */
    packet_data->ip_src.ipv4_src = ip_hdr->ip_src;
    packet_data->ip_dst.ipv4_dst = ip_hdr->ip_dst;

    /* Determine whether the underlying packet is tcp or udp and trim off the ip
     * header and options.. */

    int offset = ip_hdr->ip_hl * 4; /* We need to skip the whole header */
    packet_data->ip_len = offset;
    if (ip_hdr->ip_p == PRTCL_TCP) {
        retval = process_tcp(packet + offset, packet_data);

    } else if (ip_hdr->ip_p == PRTCL_UDP){
        retval = process_udp(packet + offset, packet_data);
        
    } else {
        retval = -1; /* Unsupported protocol */
    }

    return retval;
}

int process_ipv6(const u_char *packet, pckt_data *packet_data) {
    int retval;
    const struct ip6_hdr *ip_hdr;
    packet_data->ipv = IP_VER6;

    ip_hdr = (struct ip6_hdr *)(packet);

    /* Store the source and destination ip_address */
    packet_data->ip_src.ipv6_src = ip_hdr->ip6_src;
    packet_data->ip_dst.ipv6_dst = ip_hdr->ip6_dst;
    packet_data->ip_len = sizeof(struct ip6_hdr);

    /* Determine the type of the underlying packet */
    if (ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == PRTCL_TCP) {
        retval = process_tcp((const u_char *)ip_hdr + sizeof(struct ip6_hdr),
                packet_data);

    } else if (ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == PRTCL_UDP){
        retval = process_udp((const u_char *)ip_hdr + sizeof(struct ip6_hdr),
                packet_data);
        
    } else {
        retval = -1; /* Unsupported protocol */
    }

    return retval;
}

int process_udp(const u_char *packet, pckt_data *packet_data) {
    int retval = SUCCESS;

    /* Get the udp header */
    const struct udphdr *udp_hdr;
    udp_hdr = (struct udphdr *)(packet);

    /* Get packet info */
    packet_data->tcp_udp = PRTCL_UDP;
    packet_data->tcp_udp_len = sizeof(struct udphdr);
    packet_data->src_port = ntohs(udp_hdr->source);
    packet_data->dst_port = ntohs(udp_hdr->dest);

    return retval;
}

int process_tcp(const u_char *packet, pckt_data *packet_data) {
    int retval = SUCCESS;

    /* Get the tcp header */
    const struct tcphdr *tcp_hdr;
    tcp_hdr = (struct tcphdr *)(packet);

    /* Get packet info */
    packet_data->tcp_udp = PRTCL_TCP;
    packet_data->tcp_udp_len = tcp_hdr->th_off * 4;
    packet_data->src_port = ntohs(tcp_hdr->source);
    packet_data->dst_port = ntohs(tcp_hdr->dest);

    return retval;
}

void print_current_packet_data(const pckt_data packet_data) {
    /* Prepare and print the timestamp */
    struct tm *t =  localtime(&packet_data.header->ts.tv_sec);
    printf("%02d:%02d:%02d.%06ld ", t->tm_hour, t->tm_min, t->tm_sec,
            packet_data.header->ts.tv_usec);

    /* Print the adresses and port numbers */
    if (packet_data.ipv == IP_VER4) {
        std::string name_src = get_hostname_ipv4(packet_data.ip_src.ipv4_src);
        std::string name_dst = get_hostname_ipv4(packet_data.ip_dst.ipv4_dst);
        printf("%s : %u > ",
                name_src == "" ? inet_ntoa(packet_data.ip_src.ipv4_src) : name_src.c_str(),
                packet_data.src_port);
        printf("%s : %u\n",
                name_dst == "" ? inet_ntoa(packet_data.ip_dst.ipv4_dst) : name_dst.c_str(),
                packet_data.dst_port);

    } else if (packet_data.ipv == IP_VER6) {
        std::string name_src = get_hostname_ipv6(packet_data.ip_src.ipv6_src);
        std::string name_dst = get_hostname_ipv6(packet_data.ip_dst.ipv6_dst);

        /* Source address and port - care for endians*/
        if (name_src != "") {
            printf("%s : %u > ", name_src.c_str(), packet_data.src_port);

        } else {
            /* Print the bare ip address */
            for (int i = 0; i < 7; i++)
                printf("%x:", ntohs(packet_data.ip_src.ipv6_src.s6_addr16[i]));
            printf("%x : %u > ", ntohs(packet_data.ip_src.ipv6_src.s6_addr16[7])
                    , packet_data.src_port);
        }

        /* Destination address and port */
        if (name_dst != "") {
            printf("%s : %u\n", name_dst.c_str(), packet_data.dst_port);
        } else {
            for (int i = 0; i < 7; i++)
                printf("%x:", ntohs(packet_data.ip_dst.ipv6_dst.s6_addr16[i]));
            printf("%x : %u\n", ntohs(packet_data.ip_dst.ipv6_dst.s6_addr16[7])
                    , packet_data.dst_port);
        }
    }

    /* Now print the actual packet data... */
    std::string output; /* Stores the ascii representation of the bytes... */
    output.clear();

    /* This loop is just a mesh of modulo rules to format the output elegantly.. */
    for (uint16_t i = 0; i < packet_data.header->caplen; i++) {
        if (i % 8 == 0 && i % 16 != 0) {
            /* Separate the output by 8 octets */
            printf(" ");
            output += ' ';
        }

        /* Finish the current line and start a new one */
        if (i % 16 == 0) {
            if (i != 0) {
                printf(" %s\n", output.c_str());
                output.clear();
            }
            printf("0x%04x:  ", i);
        }

        /* Get the next octet */
        int c = packet_data.packet[i];
        /* Append it to the output string */
        if (isgraph(c) || c == ' ')
            output += c;
        else
            output += '.';
        
        printf("%02x ", c); /* Print the hexa value of the octet */
    }

    /* Print the last row */
    int len = output.length();
    if (len != 0) {
        if (len > 8 && len != 17) printf("   ");
        for (int i = len; i < 16; i++) {
            if (i == 8) printf(" ");
            printf("   ");
        }
        printf(" %s\n", output.c_str());
    }
    printf("\n");
}

std::string get_hostname_ipv4(struct in_addr address) {
    std::string name;
    name.clear();
#ifdef DO_NOT_TRANSLATE_IP
    if(address.s_addr) {} /* Eliminate wunused warning... */
    return name;
#else
    std::map<uint32_t, std::string>::iterator it = ipv4_cache.find(address.s_addr);
    if (it != ipv4_cache.end()) {
        return it->second;
    } else {
        /* Get the hostname */
        struct hostent *host = gethostbyaddr((void *)&address, sizeof(address), AF_INET);
        if (host == nullptr) {
            /* Hostname was not found, insert an empty string */
            ipv4_cache.insert(std::pair<uint32_t, std::string>(address.s_addr, name));
            return name;
        }

        /* Insert the aquired hostname */
        name = host->h_name;
        ipv4_cache.insert(std::pair<uint32_t, std::string>(address.s_addr, name));
        return name;
    }
#endif
}

std::string get_hostname_ipv6(struct in6_addr address) {
    std::string name;
    name.clear();
#ifdef DO_NOT_TRANSLATE_IP
    if(address.s6_addr16) {}
    return name;
#else
    struct hostent *host = gethostbyaddr((void *)&address, sizeof(address), AF_INET6);
    if (host == nullptr) return name;
    return name;
#endif
}
