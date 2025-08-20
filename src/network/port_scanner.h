#ifndef _PORT_H_
#define _PORT_H_

#include <iostream>
#include <cstdlib>
#include <cstring>

#include "../logs.h"
#include "../memory.h"
#include "../structures.h"

typedef struct port_info
{
    int open_port;
    LIST_ENTRY(port_info);
}PORT_INFO, *PPORT_INFO;

#ifdef __linux__

#include <cerrno>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

LIST<PORT_INFO>* PortInfo = new LIST<PORT_INFO>;

void free_port_info()
{
    if(PortInfo == NULL)
        return;
    delete PortInfo;
}

void print_port_info()
{
    auto print = [](int port)
    {
        LOG_SUCCESS("%d/tcp%s%s%s%s", port, 
            std::string(12 - std::to_string(port).size(), ' ').c_str(), "open",
            std::string(5, ' ').c_str(), "ipp");
    };

    PPORT_INFO port;
    LOG_INFO("PORT\t\tSTATE\tSERVICE");
    LIST_FOREACH(port, PortInfo)
        print(port->open_port);
    
    printf("\033[0;29m");
}


void scan(int argc, char* argv[])
{
    const char* target_ip = argv[1];
    int start_port = std::atoi(argv[2]);
    int end_port = std::atoi(argv[3]);
    end_port = 65535;
    LOG_INFO("Starting port scanner for target ip: %s", target_ip);

    sockaddr_in server_address;
    if(inet_pton(AF_INET, target_ip, &server_address.sin_addr) <= 0)
    {
        LOG_ERROR("[port_scanner] Invalid IP address; %s", target_ip);
        return;
    }
    memory::memzero_explicit(&server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = inet_addr(target_ip);

    int sock;
    for(int port = start_port; port <= end_port; ++port)
    {
        server_address.sin_port = htons(port);
        if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            LOG_ERROR("[port_scanner] Failed in port: %d", port);
            continue;
        }
        if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) == 0) 
        {
            PPORT_INFO port_s = new PORT_INFO;
            port_s->open_port = port;
            PortInfo->LIST_INSERT_HEAD(port_s);
        }
        close(sock);
    }
    print_port_info();
    return;
}


#endif

#endif