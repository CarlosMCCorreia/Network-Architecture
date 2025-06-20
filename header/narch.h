
#include <stdio.h>
#include <stdint.h>

#include <winsock2.h>
#include <process.h>
#include <windows.h>
#include <ws2tcpip.h>

#define DEFAULT_TARGET_IP (char*) "192.168.1.229"
#define DEFAULT_MIN_PORT (uint16_t) 22
#define DEFAULT_MAX_PORT (uint16_t) 100

#define SCAN_MODE_TCP (uint8_t) 0
#define SCAN_MODE_TCP_SYN (uint8_t) 1
#define SCAN_MODE_UDP (uint8_t) 2

#pragma comment(lib, "ws2_32.lib")

typedef struct{
    uint16_t min;
    uint16_t max;
} range;

typedef struct{
    struct sockaddr_in target;
    unsigned long localIp;
    range ports;
    uint32_t timeout;
    uint8_t scanMode;
    uint8_t verboseLevel;
} scanWorkerTArgs;


struct ipheader {
    unsigned char ihl:4, version:4;
    unsigned char tos;              //Type-of-Service
    unsigned short total_len;
    unsigned short id;              // Identification
    unsigned short frag_off;        // Fragmentation Offset
    unsigned char ttl;              // Time-to-live
    unsigned char protocol;
    unsigned char checksum;         // Header checksum
    struct in_addr saddr;           // Source Address
    struct in_addr daddr;           // Destination Address
};


struct tcpheader {
    unsigned short sport;           // Source Port
    unsigned short dport;           // Destination Port
    unsigned int seq;               // Sequence Number
    unsigned int ack;               // Acknowledge Number
    unsigned char doff:4, resv:4;   // Data Offset + Reserved
    unsigned char flags;            
    unsigned short window;
    unsigned short checksum;
    unsigned short urg_ptr;         // Urgent Pointer
};


// Needed for TCP checksum
struct pseudoheader {
    unsigned int saddr;             // Source ip address
    unsigned int daddr;             // Destination ip address
    unsigned char placeholder;      // Always zero
    unsigned char protocol;         // IPPROTO_TCP
    unsigned short tcp_len;         // Size of TCP header
};


void buildIpHeader(struct ipheader* iphead, struct sockaddr_in* target, const unsigned long* localIp, char* datagram);
void buildTcpHeader(struct tcpheader* tcphead, struct sockaddr_in* target, const unsigned long* localIp, uint16_t dport);
void scanTCP_SYN(struct sockaddr_in* target, const unsigned long* localIp, const range* ports);
void scanTCP(struct sockaddr_in* target, const range* ports, uint32_t* timeout, uint8_t* verboseLevel);
unsigned __stdcall scanWorker(void* param);
void get_localIp(char * local_ip);
int8_t is_valid_ip(const char* ip);
unsigned short checksum(unsigned short* buffer, int size);
int8_t argparse(int argc, char* argv[], const char** ip, uint8_t* threadcount, range* portrange, uint32_t* timeout, uint8_t scanMode);
int8_t init(char** targetIP, char* localIp, range* portrange, uint32_t* timeout, uint8_t* threadcount, uint8_t* scanMode);


