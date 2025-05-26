#ifndef PACKET_H
#define PACKET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <signal.h>


#define BUFFER_SIZE 1024
#define SERVER_PORT 8080
#define MAX_Pending 3
//#define LOCALHOST_IPV4 127001

#define LOCALHOST_IPV4 1010101

#include "ebpf.skel.h"
// Message structure for client-server communication
struct message {
    char data[BUFFER_SIZE];
};


static int server_fd, client_fd;
struct sock_key{
    __u32 sip;
    __u32 dip;
    __u32 sport;
    __u32 dport;
    __u32 family;
};

#endif // PACKET_H
