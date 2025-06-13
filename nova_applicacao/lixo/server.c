// Compile with: gcc -o raw_server raw_server.c -Wall
// Run as root: sudo ./raw_server <interface_name> (e.g., eth0)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>

#define BUF_SIZE 2048
#define SIMULATED_CYCLES 1600000 // Simulate ~1ms processing
//#define SIMULATED_CYCLES 4800000 // Simulate ~3ms processing

/*static __always_inline*/ void busy_wait_cycles(unsigned long long cycles){
    volatile unsigned long long i = 0;
    //for (i = 0; i < cycles; i++) {}
    while(i < SIMULATED_CYCLES){ i++; }
}

uint16_t checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: sudo %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *interface = argv[1];
    int sockfd;
    unsigned char buffer[BUF_SIZE];

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("Socket");
        exit(EXIT_FAILURE);
    }

    // Get interface index
    struct ifreq if_idx, if_mac;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ - 1);
    ioctl(sockfd, SIOCGIFINDEX, &if_idx);

    // Get MAC address
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, interface, IFNAMSIZ - 1);
    ioctl(sockfd, SIOCGIFHWADDR, &if_mac);

    printf("Listening on %s...\n", interface);

    while (1) {
        ssize_t len = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
        if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)) {
            continue;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;
        struct iphdr  *ip  = (struct iphdr  *)(buffer + sizeof(struct ethhdr));
        struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
        char *payload = (char *)(udp + 1);

        if (ntohs(eth->h_proto) != ETH_P_IP || ip->protocol != IPPROTO_UDP) continue;

        // Optional: filter by port
        if (ntohs(udp->dest) != 12345) continue;

        printf("Received packet from %s:%d\n",
               inet_ntoa(*(struct in_addr *)&ip->saddr),
               ntohs(udp->source));

        // Simulate processing
        busy_wait_cycles(SIMULATED_CYCLES);

        // Swap MAC addresses
        unsigned char tmp_mac[ETH_ALEN];
        memcpy(tmp_mac, eth->h_source, ETH_ALEN);
        memcpy(eth->h_source, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);
        memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

        // Swap IPs
        uint32_t tmp_ip = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = tmp_ip;

        // Swap ports
        uint16_t tmp_port = udp->source;
        udp->source = udp->dest;
        udp->dest = tmp_port;

        // Modify payload
        const char *response = "Processed (raw)";
        size_t response_len = strlen(response);
        memcpy((char *)(udp + 1), response, response_len);

        // Adjust lengths
        udp->len = htons(sizeof(struct udphdr) + response_len);
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + response_len);

        // Recalculate checksums
        ip->check = 0;
        ip->check = checksum((uint16_t *)ip, sizeof(struct iphdr));
        udp->check = 0; // UDP checksum optional (set to 0)

        // Send packet
        struct sockaddr_ll sa;
        memset(&sa, 0, sizeof(struct sockaddr_ll));
        sa.sll_ifindex = if_idx.ifr_ifindex;
        sa.sll_halen = ETH_ALEN;
        memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);

        ssize_t sent_len = sendto(sockfd, buffer, sizeof(struct ethhdr) + ntohs(ip->tot_len), 0,
                                  (struct sockaddr *)&sa, sizeof(sa));
        if (sent_len < 0) {
            perror("sendto");
        } else {
            printf("Replied to client.\n");
        }
    }

    close(sockfd);
    return 0;
}

