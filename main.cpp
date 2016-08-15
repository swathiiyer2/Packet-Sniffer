//
//  main.cpp
//  packetsniffer
//
//  Created by Swathi Iyer on 8/10/16.
//  Copyright © 2016 Swathi Iyer. All rights reserved.
//

#define PACKETSIZE 65535
#define READTIMEOUT 512

#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>


void extractData(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void handleEthernet(struct ether_header *eptr);
void printAddr(u_char *ptr, std::string str);
void handleIP(struct ip * ipptr);
void handleTCP(struct tcphdr * tcpptr);
void handleUDP(struct udphdr * udpptr);
void handleIGMP(struct igmp * igmpptr);
void handlePayload(u_char * loadptr, int length);

int main(int argc, const char * argv[]) {
    //Find device to sniff on
    char errBuff[PCAP_ERRBUF_SIZE];
    char * device = pcap_lookupdev(errBuff);
    if(device == NULL){
        std::cout << errBuff << std::endl;
        exit(-1);
    }
    std::cout << "Device: " << device << std::endl;
    
    //Create interface handler and open network device for sniffing in promiscuous mode
    pcap_t *handler = pcap_open_live(device, PACKETSIZE, 1, READTIMEOUT, errBuff);
    if(handler == NULL){
        printf("Couldn't open device");
        exit(-1);
    }
    
    //Loop forever and call extractData() for each received packet
    int count = 0;
    pcap_loop(handler, -1, extractData, (u_char *)count);
    
    //End session
    pcap_close(handler);
    return 0;
}

/* Get Data from packet if protocol is IPV4
 */

void extractData(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    static int count = 1;
    printf("-------------------Packet [%d]------------------\n", count++);
    printf("Length: %d\n",header->len);
    struct ether_header *eptr = (struct ether_header *) packet;
    struct ip * ipptr = (struct ip *) (packet + sizeof(struct ether_header));
    struct tcphdr * tcpptr = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
    struct udphdr * udpptr = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
    struct igmp * igmpptr =(struct igmp *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
    u_char * loadptr;
    int length;
    
    //1. Network Access Layer
    handleEthernet(eptr);
    
    //2. Internet Layer
    if(ntohs(eptr->ether_type) == ETHERTYPE_IP){
        handleIP(ipptr);
        
        //3. Transport Layer
        if(ipptr->ip_p == IPPROTO_TCP){
            handleTCP(tcpptr);
            loadptr = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(tcphdr));
            length = ntohs(ipptr->ip_len) - (sizeof(tcphdr) + sizeof(struct ip));
        } else if(ipptr->ip_p == IPPROTO_UDP){
            handleUDP(udpptr);
            loadptr = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(udphdr));
            length = ntohs(ipptr->ip_len) - (sizeof(udphdr) + sizeof(struct ip));
        } else if (ipptr->ip_p == IPPROTO_UDP){
            loadptr = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(igmp));
            length = ntohs(ipptr->ip_len) - (sizeof(igmp) + sizeof(struct ip));
            handleIGMP(igmpptr);
        }
        
        //4. Application Layer
        handlePayload(loadptr, length);
    } else {
        printf("Protocol not Supported.\n");
    }
    printf("\n\n");
}

/* Print Ethernet Header
 */

void handleEthernet(struct ether_header *eptr){
    printf("Ethernet Header\n");
    printAddr(eptr->ether_dhost, "MAC Destination");
    printAddr(eptr->ether_shost, "MAC Source");
}

/* Prints Ethernet Header Source/Destination hosts in MAC MM:MM:MM:SS:SS:SS format
 */

void printAddr(u_char *ptr, std::string str){
    printf("    %s: ", str.c_str());
    for(int i= 0; i < ETHER_ADDR_LEN;i++){
        printf("%x", ptr[i]);
        if(i!= ETHER_ADDR_LEN -1){
            printf(":");
        }
    }
    printf("\n");
}

/* Prints IP Header
 */

void handleIP(struct ip * ipptr){
    printf("IP Header\n");
    printf("    Version: %i\n", ipptr->ip_v);
    printf("    IP Destinaton: %s\n", inet_ntoa(ipptr->ip_dst));
    printf("    IP Source: %s\n", inet_ntoa(ipptr->ip_src));
    printf("    IP Protocol: %i\n", ipptr->ip_p);
}

/* Prints TCP Header
 */

void handleTCP(struct tcphdr * tcpptr){
    printf("TCP Header\n");
    printf("    Destinaton Port: %i\n", htons(tcpptr->th_dport));
    printf("    Source Port: %i\n", htons(tcpptr->th_sport));
}

/* Prints UDP Header
 */

void handleUDP(struct udphdr * udpptr){
    printf("UDP Header\n");
    printf("    Destinaton Port: %i\n", htons(udpptr->uh_dport));
    printf("    Source Port: %i\n", htons(udpptr->uh_sport));
}

/* Prints IGMP Header
 */

void handleIGMP(struct igmp * igmpptr){
    printf("IGMP Header\n");
    printf("    Type: %i\n", htons(igmpptr->igmp_type));
    printf("    Code: %i\n", htons(igmpptr->igmp_code));
}

/* Prints Payload in Hex and ASCII
 */
void handlePayload(u_char * loadptr, int length){
    printf("Payload\n");
    const u_char  *ch = loadptr;
    
    //print hex
    for(int i = 0; i < length; i++){
        printf("%02x ", *ch);
        ch++;
    }
    printf("\n");
    
    //print ascii
    ch = loadptr;
    for(int i = 0; i < length; i++) {
        if (isprint(*ch)){
            printf("%c", *ch);
        } else {
            printf(".");
        }
        ch++;
    }
    printf("\n");
}
