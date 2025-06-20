#include <narch.h>

// This function builds an IP header for a TCP SYN scan
void buildIpHeader(struct ipheader* iphead, struct sockaddr_in* target, const unsigned long* localIp, char* datagram){

    iphead->version = 4; // IPv4
    iphead->ihl = 5;     // Header length (5 * 4 = 20 bytes)
    iphead->tos = 0;     // Type-of-Service
    iphead->total_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader)); // Total length of the IP packet 
                                                                                   // Note: The total length includes the IP header and TCP header
    iphead->id = htons(54321); // Identification field
    iphead->frag_off = 0; // Fragmentation offset
    iphead->ttl = 64; // Time-to-live
    iphead->protocol = IPPROTO_TCP; // Protocol type (TCP)
    iphead->checksum = 0; // Checksum will be calculated later
    iphead->saddr.s_addr = *localIp; // Source IP address
    iphead->daddr.s_addr = target->sin_addr.S_un.S_addr; // Destination IP address

    iphead->checksum = checksum((unsigned short*)datagram, sizeof(struct ipheader)); // Calculate the checksum for the IP header
 }

// This function builds a TCP header for a SYN scan
void buildTcpHeader(struct tcpheader* tcphead, struct sockaddr_in* target, const unsigned long* localIp, uint16_t dport){

    tcphead->sport = htons(12345);   // Source port (can be any valid port, here we use 12345)
    tcphead->dport = htons(dport);   // Destination port (the port we are scanning)
    tcphead->seq = htonl(0);         // Sequence number (can be set to 0 for SYN scan)
    tcphead->ack = 0;                // Acknowledge number (not used in SYN scan)
    tcphead->doff = 5;               // Data offset (5 * 4 = 20 bytes, no options)
    tcphead->resv = 0;               // Reserved
    tcphead->flags = 0x02;           // SYN flag
    tcphead->window = htons(5840);   // Window size (can be set to a common value, here we use 5840)
    tcphead->checksum = 0;           // Checksum will be calculated later
    tcphead->urg_ptr = 0;            // Urgent Pointer

  
    // The pseudo-header is used to calculate the TCP checksum
    struct pseudoheader pshead;  // Create a pseudo-header for TCP checksum calculation
    pshead.saddr = *localIp;     // Source IP address
    pshead.daddr = target->sin_addr.S_un.S_addr;  // Destination IP address
    pshead.placeholder = 0;      // Placeholder (always zero)
    pshead.protocol = IPPROTO_TCP; // Protocol type (TCP)
    pshead.tcp_len = htons(sizeof(struct tcpheader)); // Length of the TCP header

    // The pseudo-packet consists of the pseudo-header followed by the TCP header
    char pseudo_packet[sizeof(struct pseudoheader) + sizeof(struct tcpheader)]; 
    memcpy(pseudo_packet, &pshead, sizeof(struct pseudoheader));
    memcpy(pseudo_packet + sizeof(struct pseudoheader), tcphead, sizeof(struct tcpheader));
    // Calculate the TCP checksum using the pseudo-packet
    tcphead->checksum = checksum((unsigned short*)pseudo_packet, sizeof(pseudo_packet)); 
 }
/*
    * Function to perform a TCP SYN scan on a target IP address and port range.
    * This function sends SYN packets to the specified ports and waits for responses.
    * It uses raw sockets to send the packets, so it requires root privileges.
    *
    * @param target: Pointer to the sockaddr_in structure containing the target IP address.
    * @param localIp: Pointer to the local IP address in network byte order.
    * @param ports: Pointer to a range structure containing the minimum and maximum port numbers to scan.
*/
void scanTCP_SYN(struct sockaddr_in* target, const unsigned long* localIp, const range* ports){

    for(uint16_t p = ports->min; p < ports->max + 1; p++){ // Iterate through the specified port range

        SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // Create a raw socket for sending packets

        if(sock == INVALID_SOCKET){ // Check if the socket creation was successful
            printf("[-] Failed to create raw socket: %d\n", WSAGetLastError());
            continue;
        }
        // Set the IP_HDRINCL socket option
        int optval = 1;
        if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval)) < 0){  // Set the IP_HDRINCL option to include the IP header in the packet
            printf("[-] Failed to set IP_HDRINCL: %d\n", WSAGetLastError()); 
            continue;
        }

        char datagram[4096] = {0}; // Buffer to hold the complete packet (IP header + TCP header)

        struct ipheader* iphead = (struct ipheader*)datagram; // Pointer to the IP header in the datagram
        struct tcpheader* tcphead = (struct tcpheader*)(datagram + sizeof(struct ipheader)); // Pointer to the TCP header in the datagram

        buildIpHeader(iphead, target, localIp, datagram); // Build the IP header
        buildTcpHeader(tcphead, target, localIp, p);       // Build the TCP header

        // Set the destination address for the packet

        if(sendto(sock, datagram, sizeof(struct ipheader) + sizeof(struct tcpheader), 0, (struct sockaddr*)&target, sizeof(target)) < 0){
             printf("[-] Failed to send packet: %d\n", WSAGetLastError());
        }
        else{
            printf("[+] TCP SYN packet sent to %s:%u\n", inet_ntoa(target->sin_addr), p);
        }

        closesocket(sock);
    }
 }

 /*
  * Function to perform a TCP connect scan on a target IP address and port range.
  * This function attempts to establish a TCP connection to the specified ports.
  * It uses standard sockets, so it does not require root privileges.
  *
  * @param target: Pointer to the sockaddr_in structure containing the target IP address.
  * @param ports: Pointer to a range structure containing the minimum and maximum port numbers to scan.
  * @param timeout: Pointer to a uint32_t variable containing the timeout value in milliseconds.
  * @param verboseLevel: Pointer to a uint8_t variable containing the verbosity level.
  */
void scanTCP(struct sockaddr_in* target, const range* ports, uint32_t* timeout, uint8_t* verboseLevel){

    for(uint16_t p = ports->min; p < ports->max + 1; p++){ // Iterate through the specified port range

        SOCKET sock = socket(target->sin_family, SOCK_STREAM, IPPROTO_TCP);  // Create a TCP socket

        if(sock == INVALID_SOCKET){  // Check if the socket creation was successful
            printf("[-] Failed to create socket: %d\n", WSAGetLastError());
            continue;
        }

        target->sin_port = htons(p); // Set the target port in the sockaddr_in structure

        // Set the socket options for timeout
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

        // Attempt to connect to the target IP and port
        if(connect(sock, (struct sockaddr*)target, sizeof(*target)) == 0){
            if(verboseLevel == 0){
                printf("[+] Port %d is open\n", p);
            }else if(verboseLevel == 1){
                char buffer[512] = {0};
                int bytes = recv(sock, buffer, sizeof(buffer)-1, 0); // Receive data from the socket (banner or response)
                if(bytes > 0) {
                    printf("[+] Port %d is open. Banner: %s\n", p, buffer); // Print the received banner
                } else {
                    printf("[+] Port %d is open. No banner received.\n", p); // Print a message if no banner was received
                }
            }
            
        }else{
            printf("[-] Port %d is closed %d\n", p, WSAGetLastError());
        }

        closesocket(sock); // Close the socket after the scan
    }
}

/* * 
 * Worker function for scanning ports in a separate thread.
 * This function is called by each thread to perform the actual scanning.
 *
 * @param param: Pointer to a scanWorkerTArgs structure containing the scan parameters.
 * @return: Returns 0 on success.
 */
unsigned __stdcall scanWorker(void* param) {
    scanWorkerTArgs* args = (scanWorkerTArgs*)param; // Cast the parameter to a scanWorkerTArgs structure
    if(args->scanMode == 0){
        scanTCP(&args->target, &args->ports, &args->timeout, args->verboseLevel); // Perform a TCP connect scan
    }else if(args->scanMode == 1){
        scanTCP_SYN(&args->target, &args->localIp, &args->ports); // Perform a TCP SYN scan
    }
    free(args);  // Free the allocated memory for the scanWorkerTArgs structure
    return 0;
}

/**
 * Function to get the local IP address of the machine.
 * This function retrieves the hostname and resolves it to an IP address.
 *
 * @param local_ip: Pointer to a character array where the local IP address will be stored.
 */
void get_localIp(char * local_ip){
    
    struct hostent *host_entry;
    char hostbuffer[256];

    gethostname(hostbuffer, sizeof(hostbuffer)); // Get the hostname of the local machine
    host_entry = gethostbyname(hostbuffer);      // Resolve the hostname to an IP address
    
   strcpy(local_ip, inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]))); // Copy the resolved IP address to the local_ip buffer
}

/**
 * Function to validate if a given string is a valid IPv4 address.
 * This function uses inet_pton to check the format of the IP address.
 *
 * @param ip: Pointer to a character array containing the IP address to validate.
 * @return: Returns 1 if the IP address is valid, 0 otherwise.
 */
int8_t is_valid_ip(const char* ip){
    struct sockaddr_in test;
    return inet_pton(AF_INET, ip, (&test.sin_addr)) == 1; // Check if the IP address can be converted to a valid sockaddr_in structure
}

/**
 * Function to calculate the checksum for a given buffer.
 * This function is used to compute the checksum for IP and TCP headers.
 *
 * @param buffer: Pointer to the buffer containing the data for which the checksum is to be calculated.
 * @param size: Size of the buffer in bytes.
 * @return: Returns the calculated checksum as an unsigned short.
 */
unsigned short checksum(unsigned short* buffer, int size){
    unsigned long sum = 0;

    while(size > 1){          // While there are at least two bytes to process
        sum += *buffer++;     // Add two bytes at a time to the sum
        size -= 2;            // Process two bytes at a time
    }
    if(size) sum += *(unsigned char*)buffer;   // If there is an odd byte, add it to the sum
    sum = (sum >> 16) + (sum & 0xFFFF);  // Add the upper 16 bits to the lower 16 bits
    sum += (sum >> 16);                  // Add the carry if any
    return (unsigned short)(~sum);       // Return the one's complement of the sum as the checksum
}

/**
 * Function to parse command-line arguments for the port scanner.
 * This function processes the arguments and sets the appropriate parameters for the scan.
 *
 * @param argc: Number of command-line arguments.
 * @param argv: Array of command-line argument strings.
 * @param ip: Pointer to a character pointer where the target IP address will be stored.
 * @param threadcount: Pointer to a uint8_t variable where the number of threads will be stored.
 * @param portrange: Pointer to a range structure where the port range will be stored.
 * @param timeout: Pointer to a uint32_t variable where the timeout value will be stored.
 * @param scanMode: The scan mode (TCP, SYN, etc.).
 * @return: Returns 0 on success, 1 on failure.
 */
int8_t argparse(int argc, char* argv[], const char** ip, uint8_t* threadcount, range* portrange, uint32_t* timeout, uint8_t scanMode){

    if(argc < 2){
        printf("Usage: %s <ip> [-t <threads>] [-p <min>-<max>] [--timeout <ms>] [--protocol <TCP|SYN|UDP>]\n", argv[0]);
        return 1;
    }

    if(is_valid_ip(argv[1])){
        *ip = argv[1];
    }else{
        printf("[!] Invalid IP format %s\n", argv[1]);
        return 1;
    }

    for(uint8_t i = 2; i < argc; i++){
        if((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--threads") == 0) && i + 1 < argc){
            uint8_t tc = atoi(argv[++i]);
            if(!(tc > *threadcount * 2 || tc > UINT8_MAX - 1 || tc < 1))
                *threadcount = tc;
        }
        else if((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--ports") == 0) && i + 1 < argc){
            range prange;
            sscanf(argv[++i], "%hu-%hu", prange.min, prange.max);
            if(prange.min >= 1 && prange.max <= UINT16_MAX && prange.min < prange.max){
                portrange->min = prange.min;
                portrange->max = prange.max;
            }else{ 
                printf("[!] Invalid Speciefied port range %s\n", argv[i]);
                printf("    Format: -p <min>-<max>");
                printf("    Rule: prange.min >= 1 && prange.max <= %u && prange.min < prange.max", UINT16_MAX);
                return 1;
            }
        }
        else if((strcmp(argv[i], "--timeout") == 0) && i + 1 < argc){
            uint32_t tout = atoi(argv[++i]);
            if(!(tout < 1 || tout > 60*10^3))
                *timeout = tout;
        }
        else if((strcmp(argv[i], "--protocol") == 0) && i + 1 < argc){
            char mode[16] = argv[++i];
            if(strcmp(mode, "TCP") == 0)
                scanMode = SCAN_MODE_TCP;
            else if(strcmp(mode, "SYN"))
                scanMode = SCAN_MODE_TCP;
            else if(strcmp(mode, "UDP"))
                scanMode = SCAN_MODE_TCP;
            else
                continue;
        }
        else{
            printf("[!] Unknown or incomplete argument: %s\n", argv[i]);
            return 1;
        }
    }
    return 0;
}

/**
 * Function to initialize the port scanner.
 * This function sets up the necessary parameters and initializes Winsock.
 *
 * @param targetIP: Pointer to a character pointer where the target IP address will be stored.
 * @param localIp: Pointer to a character array where the local IP address will be stored.
 * @param portrange: Pointer to a range structure where the port range will be stored.
 * @param timeout: Pointer to a uint32_t variable where the timeout value will be stored.
 * @param threadcount: Pointer to a uint8_t variable where the number of threads will be stored.
 * @param scanMode: Pointer to a uint8_t variable where the scan mode will be stored.
 * @return: Returns 0 on success, 1 on failure.
 */
int8_t init(char** targetIP, char* localIp, range* portrange, uint32_t* timeout, uint8_t* threadcount, uint8_t* scanMode){

    SYSTEM_INFO sysinfo;                 // Structure to hold system information
    GetSystemInfo(&sysinfo);              // Get system information, including the number of processors
 
    *threadcount = (uint8_t)sysinfo.dwNumberOfProcessors;  // Set the default thread count to the number of processors

    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2,2), &wsa) != 0){              // Initialize Winsock
        printf("[!] Failed to initialize Winsock.");
        printf("    Error code: %d\n", WSAGetLastError());
        return 1;
    }
    if(wsa.wVersion != MAKEWORD(2,2)){                     // Check if the Winsock version is 2.2
        printf("[!] Winsock version 2.2 is required.\n");
        WSACleanup();
        return 1;
    }
    // Set default values for the parameters
    *targetIP = DEFAULT_TARGET_IP;
    portrange->min = DEFAULT_MIN_PORT;
    portrange->max = DEFAULT_MAX_PORT;
    *timeout = 250;
    *scanMode = SCAN_MODE_TCP;

    get_localIp(localIp); // Get the local IP address of the machine

    return 0;
}


int main(int argc, char* argv[]){

    char* targetIp;
    char localIp[16];
    range portrange;
    uint32_t timeout;
    uint8_t threadcount;
    uint8_t scanMode;

    if(init(&targetIp, localIp, &portrange, &timeout, &threadcount, &scanMode)){
        return EXIT_FAILURE;
    }

    printf("Target: %s\n", targetIp);
    printf("Local: %s\n", localIp);

    // Parse command-line arguments
    if(argparse(argc, argv, &targetIp, &threadcount, &portrange, &timeout, &scanMode)){
        return EXIT_FAILURE;
    }

    uint16_t total_ports = portrange.max  - portrange.min + 1;
    uint16_t ports_per_thread = total_ports / threadcount;    

    HANDLE threads[threadcount];

    for(uint8_t i = 0; i < threadcount; i++){
        scanWorkerTArgs* args = (scanWorkerTArgs*)malloc(sizeof(scanWorkerTArgs));

        args->target.sin_family = AF_INET;
        args->target.sin_addr.s_addr = inet_addr(targetIp);
        args->localIp = inet_addr(localIp);
        args->ports.min = 1 + i * ports_per_thread;
        args->ports.max = (i == threadcount - 1) ? portrange.max : (args->ports.min + ports_per_thread - 1);
        args->timeout = timeout;
        args->scanMode = scanMode;

        threads[i] = (HANDLE)_beginthreadex(NULL, 0, scanWorker, args, 0, NULL);
        if(threads[i] == 0){
            printf("[!] Failed to create thread %d", i);
            free(args);
        }
    }

    WaitForMultipleObjects(threadcount, threads, TRUE, INFINITE);
    for(uint8_t i = 0; i < threadcount; i++){
        CloseHandle(threads[i]);
    }
    WSACleanup();

	return 0;
}