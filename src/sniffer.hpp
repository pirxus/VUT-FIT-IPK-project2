/**
 * @file   sniffer.hpp
 * @author Simon Sedlacek, xsedla1h
 * @brief 
 */

#include <iostream>
#include <pcap.h>

#include "resources.hpp"

/**
 * @brief This function opens the desired device, sets up the necessary resources and
 * filters in order to start the sniffing process..
 */
int sniff_init(char *interface, unsigned *port, unsigned *n_packets, bool tcp, bool udp);

/**
 * @brief This function is the top-level function for the sniffing process, the sniffing
 * "loop" with pcap_loop() is situated in here
 */
int sniff(pcap_t *handle, unsigned *n_packets, bool tcp, bool udp);

/**
 * @brief The callback function for pcap_loop() which processes the received packets
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
