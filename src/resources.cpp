/**
 * @file   resources.cpp
 * @author Simon Sedlacek, xsedla1h
 * @brief  This module contains functions used for allocating program resources
 */

#include "resources.hpp"

/* Initialize the program flags */
bool flag_tcp = true;
bool flag_udp = true;
char *interface = nullptr;
unsigned *port = nullptr;
unsigned *n_packets = nullptr;

/**
 * @brief This function parses the program arguments and sets up corresponding
 * global flags and variables
 */
int parse_args(int argc, char *argv[]) {
    int c;
    static struct option long_opts[] = {
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "i:p:tun:", long_opts, nullptr)) != -1) {
        switch (c) {
            case 'i':
            {
                interface = (char *)malloc(strlen(optarg) + 1);
                if (!interface) {
                    std::cerr << "Error: memory allocation error\n";
                    free_resources_exit(ERROR_ALLOC);
                }

                strcpy(interface, optarg);
                break;
            }

            case 'p':
            {
                /* Convert the argument option to a number */
                char *endptr = nullptr;
                port = (unsigned *)malloc(sizeof(unsigned));
                if (!port) {
                    std::cerr << "Error: memory allocation error\n";
                    return ERROR_ALLOC;
                }

                *port = (unsigned)strtoul(optarg, &endptr, 10);
                if (strcmp(endptr, "")) {
                    std::cerr << "Error: The parameter of the program option" <<
                            " '-p' has to be an integer\n";
                    return ERROR_ALLOC;
                }

                if (*port > 65535 || optarg[0] == '-') {
                    std::cerr << "Error: Invalid port number\n";
                    return ERROR_ARG_FORMAT;
                }
                break;
            }

            case 't':
                flag_udp = false;
                break;

            case 'u':
                flag_tcp = false;
                break;

            case 'n':
            {

                /* Convert the argument option to a number */
                char *endptr = nullptr;
                n_packets = (unsigned *)malloc(sizeof(unsigned));
                if (!n_packets) {
                    std::cerr << "Error: memory allocation error\n";
                    return ERROR_ALLOC;
                }

                *n_packets = (unsigned)strtoul(optarg, &endptr, 10);
                if (strcmp(endptr, "")) {
                    std::cerr << "Error: The parameter of the program option" <<
                            " '-n' has to be an integer\n";
                    return ERROR_ALLOC;
                }

                if (optarg[0] == '-') {
                    std::cerr << "Error: Invalid number of packets specified\n";
                    return ERROR_ARG_FORMAT;
                }
                break;
            }

            case '?':
                std::cerr << "Error: unknown argument\n";
                return ERROR_UNKNOWN_ARG;
                break;

            default:
                break;
        }
    }
    return SUCCESS;
}

/**
 * @brief This function frees all the program resources
 */
void free_resources() {
    free(n_packets);
    free(port);
    free(interface);
}

/**
 * @brief This function frees all the resources and exits the program
 */
void free_resources_exit(int exit_code) {
    free_resources();
    exit(exit_code);
}
