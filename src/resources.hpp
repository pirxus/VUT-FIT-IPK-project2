/**
 * @file   resources.hpp
 * @author Simon Sedlacek, xsedla1h
 * @brief  This module contains functions used for allocating program resources
 */

#include <iostream>
#include <getopt.h>
#include <cstring>

#ifndef __RESOURCES_HPP__
#define __RESOURCES_HPP__

#define SUCCESS 0
#define ERROR_ALLOC 99 
#define ERROR_ARG_FORMAT 98
#define ERROR_UNKNOWN_ARG 97

#define ERROR_OPEN_DEVICE 2
#define ERROR_SNIFFER 3

/* These flags deteremine how the sniffer will behave - we parse them from the program
 * arguments */
extern bool flag_tcp;
extern bool flag_udp;
extern char *interface; /* The name of the interface we want to sniff packets from */
extern unsigned *port;
extern unsigned *n_packets;

/**
 * @brief This function parses the program arguments and sets up corresponding
 * global flags and variables
 */
int parse_args(int argc, char *argv[]);

/**
 * @brief This function frees all the program resources
 */
void free_resources();

/**
 * @brief This function frees all the resources and exits the program
 */
void free_resources_exit(int exit_code);

#endif
