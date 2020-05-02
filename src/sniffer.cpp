/**
 * @file   sniffer.cpp
 * @author Simon Sedlacek, xsedla1h
 * @brief  This module implements the core sniffer functions.
 */ 

#include "sniffer.hpp"


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

    /* Check the link-layer type for the device - ETHERNET only... */
    if (pcap_datalink(handle) != DLT_EN10MB) {
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

    //TODO tcp/udp filter
    if (tcp != udp) {
        //setup filter
    }

    /* Filter the traffic by port if specified... */
    if (port != nullptr) {
        struct bpf_program fp;
        char filter_exp[] = "port 23";
        // TODO: the filter... 

        /* Setup the port filter */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            std::cerr << "Error: Couldn't parse filter " << filter_exp << ": "
                << pcap_geterr(handle) << std::endl;
            return(ERROR_SNIFFER);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
           std::cerr << "Error: Couldn't set filter " << filter_exp << ": "
               << pcap_geterr(handle) << std::endl;
            return(ERROR_SNIFFER);
        }
    }

    /* Start the actual sniffing */
    if (sniff(handle, n_packets) != SUCCESS) {
        return ERROR_SNIFFER;
    }

    return SUCCESS;
}

int sniff(pcap_t *handle, unsigned *n_packets) {
    int retval;
    u_char *user = NULL; //TODO: possibly useful for storing flags??
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
            // TODO: what to do here...
        }


        /* Print out the content of packet_data */
    }

    pcap_close(handle);
    return SUCCESS;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (args) {} /* eliminate the unused parameter warning... */
    int retval;
    const struct ether_header *eth_header;
    pckt_data packet_data;

    packet_data.header = header;
    packet_data.packet = packet;

    eth_header = (struct ether_header *)(packet); /* get the ethernet header */
    u_short type = ntohs(eth_header->ether_type); /* get the ethernet type */

    if (type == ETHERTYPE_IP) {
        retval = process_ipv4(packet + sizeof(ether_header), &packet_data);

    } else if (type == ETHERTYPE_IPV6) {
        retval = process_ipv6(packet + sizeof(ether_header), &packet_data);

    } else {
        return;
    }

    if (retval != 0) {
        return; //TODO
    }

    print_current_packet_data(packet_data);
    return;
}

int process_ipv4(const u_char *packet, pckt_data *packet_data) {
    int retval;
    const struct ip *ip_hdr;
    packet_data->ipv = IP_VER4;

    /* Extract the ip packet */
    ip_hdr = (struct ip *)(packet);

    /* Store the source and destination ip_address */
    packet_data->ip.ipv4_src = ip_hdr->ip_src;
    packet_data->ip.ipv4_dst = ip_hdr->ip_dst;

    /* Determine whether the underlying packet is tcp or udp and trim off the ip
     * header and options.. */
    int offset = ip_hdr->ip_hl - 5;
    if (ip_hdr->ip_p == PRTCL_TCP) {
        retval = process_tcp((const u_char *)ip_hdr + sizeof(struct ip) + offset,
                packet_data);

    } else if (ip_hdr->ip_p == PRTCL_UDP){
        retval = process_udp((const u_char *)ip_hdr + sizeof(struct ip) + offset,
                packet_data);
        
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
    packet_data->ip.ipv6_src = ip_hdr->ip6_src;
    packet_data->ip.ipv6_dst = ip_hdr->ip6_dst;

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
    packet_data->src_port = udp_hdr->source;
    packet_data->dst_port = udp_hdr->dest;

    return retval;
}

int process_tcp(const u_char *packet, pckt_data *packet_data) {
    int retval = SUCCESS;

    /* Get the tcp header */
    const struct tcphdr *tcp_hdr;
    tcp_hdr = (struct tcphdr *)(packet);

    /* Get packet info */
    packet_data->tcp_udp = PRTCL_TCP;
    packet_data->src_port = tcp_hdr->source;
    packet_data->dst_port = tcp_hdr->dest;

    return retval;
}

void print_current_packet_data(const pckt_data packet_data) {
    //std::cout << packet_data.header->ts.tv_sec;

    /* Print the adresses and port numbers */
    if (packet_data.ipv == IP_VER4) {
        printf("%s : %d > ", inet_ntoa(packet_data.ip.ipv4_src), packet_data.src_port);
        printf("%s : %d\n", inet_ntoa(packet_data.ip.ipv4_dst), packet_data.dst_port);

    } else if (packet_data.ipv == IP_VER6) {
        /* Source address and port */
        for (int i = 0; i < 7; i++)
            printf("%x:", packet_data.ip.ipv6_src.s6_addr16[i]);
        printf("%x : %d > ", packet_data.ip.ipv6_src.s6_addr16[7], packet_data.src_port);

        /* Destination address and port */
        for (int i = 0; i < 7; i++)
            printf("%x:", packet_data.ip.ipv6_dst.s6_addr16[i]);
        printf("%x : %d\n", packet_data.ip.ipv6_dst.s6_addr16[7], packet_data.dst_port);

    } else {
        return; /* This should not happen... */
    }

    /* Now print the actual packet data... */
    std::string output; /* Stores the ascii representation of the bytes... */
    output.clear();

    for (unsigned i = 0; i < packet_data.header->caplen; i++) {
        if (i % 8 == 0 && i % 16 != 0) {
            /* Separate the output by 8 octets */
            printf(" ");
            output += ' ';
        }

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
        
        printf("%02x ", c); /* Print the hexa value */
    }

    /* Print the last row */
    int len = output.length();
    if (len != 0) {
        if (len > 8) printf("   ");
        for (int i = len; i < 16; i++) {
            if (i == 8) printf(" ");
            printf("   ");
        }
        printf(" %s\n", output.c_str());
    }
    printf("\n");

}
