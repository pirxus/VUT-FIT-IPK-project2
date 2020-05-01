/**
 * @file   main.cpp
 * @author Simon Sedlacek, xsedla1h
 * @brief  This is the main module of the packet sniffer
 */

#include <iostream>
#include <pcap.h>
#include <string>

#include "resources.hpp"
#include "sniffer.hpp"

int main(int argc, char *argv[]) {

    /* First, parse the program arguments */
    int ret = parse_args(argc, argv);
    if (ret) free_resources_exit(ret);


    /* If no interface is specified, just list them all */
    if (interface == nullptr) {

        pcap_if_t *devices;
        int errcode;
        char errbuf[PCAP_ERRBUF_SIZE];
        if ((errcode = pcap_findalldevs(&devices, errbuf)) != 0) {
            std::cerr << errbuf << std::endl;
            free_resources_exit(errcode);
        }

        /* List all the devices */
        pcap_if_t *device = devices;
        do {
            std::cout << device->name << std::endl;
            device = device->next;
        } while (device->next);

        if (errcode != SUCCESS) std::cout << errcode << std::endl;
        pcap_freealldevs(devices);

    /* Start sniffing on the specified interface */
    } else {

        int retval = sniff_init(interface, port, n_packets, flag_tcp, flag_udp);

        /* Check the return value */
        if (retval != SUCCESS) {
            free_resources_exit(retval);
        }
    }

    /* End the program */
    free_resources();
    return SUCCESS;
}
