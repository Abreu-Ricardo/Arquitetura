#ifndef PACKET_H
#define PACKET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Structure for packet header
typedef struct {
    int sequence_number;
    int payload_size;
} packet_header;

// Structure for complete packet
typedef struct {
    packet_header header;
    char* payload;
} packet;

#endif
