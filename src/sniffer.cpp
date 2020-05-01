/**
 * @file   sniffer.cpp
 * @author Simon Sedlacek, xsedla1h
 * @brief 
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
    if (sniff(handle, n_packets, tcp, udp) != SUCCESS) {
        return ERROR_SNIFFER;
    }

    return SUCCESS;
}

int sniff(pcap_t *handle, unsigned *n_packets, bool tcp, bool udp) {
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
            break;
            // TODO: what to do here...
        }
    }

    pcap_close(handle);
    return SUCCESS;
}


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    std::cout << "Got a packet of length " << header->len << std::endl;
    std::cout << packet << std::endl;
}
