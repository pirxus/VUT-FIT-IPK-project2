/**
 * @file   sniffer.hpp
 * @author Simon Sedlacek, xsedla1h
 * @brief  sniffer module header file
 */

#ifndef __SNIFFER_HPP__
#define  __SNIFFER_HPP__

#include <iostream>
#include <map>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>

#include "resources.hpp"

#define PRTCL_TCP 6
#define PRTCL_UDP 17 
#define PRTCL_ICMP 1 

#define IP_VER4 4
#define IP_VER6 6

#define ETH_HDR_SIZE 14

/**
 * @brief This structure holds the information about the currently processed packet and
 * is used to easily print the packet data and metadata once the processing is finished
 */
typedef struct packet_info {
    const struct pcap_pkthdr *header;
    char ipv; /* Either IP_VER4 or IP_VER6 */
    char tcp_udp; /* Either PRTCL_TCP or PRTCL_UDP */
    uint16_t src_port;
    uint16_t dst_port;

    /* Source ip address.. */
    union {
        struct in_addr ipv4_src;
        struct in6_addr ipv6_src;
    } ip_src;

    /* Destination ip address.. */
    union {
        struct in_addr ipv4_dst;
        struct in6_addr ipv6_dst;
    } ip_dst;

    const u_char *packet; /* The whole packet */
    uint8_t eth_len, ip_len, tcp_udp_len; /* Packet header lenghts */
} pckt_data;

/**
 * @brief This function opens the desired device, sets up the necessary resources and
 * packet filters in order to start the sniffing process..
 */
int sniff_init(char *interface, unsigned *port, unsigned *n_packets, bool tcp, bool udp);

/**
 * @brief This function is the top-level function for the sniffing process, the sniffing
 * "loop" with pcap_loop() is situated in here
 */
int sniff(pcap_t *handle, unsigned *n_packets);

/**
 * @brief The callback function for pcap_loop() which processes the received packets
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/**
 * @brief This function processes the ipv4 header and passes on the stripped packet
 * Additionally, the source and destination ipv4 addresses are stored in the
 * packet_data structure
 */
int process_ipv4(const u_char *packet, pckt_data *packet_data);

/**
 * @brief This function processes the ipv6 header and passes on the stripped packet.
 * Additionally, the source and destination ipv6 addresses are stored in the
 * packet_data structure
 */
int process_ipv6(const u_char *packet, pckt_data *packet_data);

/**
 * @brief This function processes the udp header and stores the source and destination
 * ports to the packet_data sturcture
 */
int process_udp(const u_char *packet, pckt_data *packet_data);

/**
 * @brief This function processes the tcp header and stores the source and destination
 * ports to the packet_data sturcture
 */
int process_tcp(const u_char *packet, pckt_data *packet_data);

/**
 * @brief Prints the formated form of packet_data
 */
void print_current_packet_data(const pckt_data packet_data);

/**
 * These two functions are used to translate ip addresses to hostnames. By default,
 * the DO_NOT_TRANSLATE_IP macro is set in the makefile and therefore these two
 * functions will always return nullptr. The reason for this was that as soon as the
 * program tried to fetch the hostname, the request would be immediately caught by the
 * sniffer and queried again.
 */
std::string get_hostname_ipv4(struct in_addr address);
std::string get_hostname_ipv6(struct in6_addr address);

#endif
