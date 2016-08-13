//
//  main.cpp
//  packetsniffer
//
//  Created by Swathi Iyer on 8/10/16.
//  Copyright © 2016 Swathi Iyer. All rights reserved.
//

#define PACKETSIZE 65535
#define IPTYPE 8

#include <iostream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void extractData(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void handleEthernet(struct ether_header *eptr);
void printAddr(u_char *ptr, std::string str);
void handleIP(struct ip * ipptr);
void handleTCP(struct tcphdr * tcpptr);
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
    pcap_t *handler = pcap_open_live(device, PACKETSIZE, 1, 512, errBuff);
    if(handler == NULL){
        printf("Couldn't open device");
        exit(-1);
    }
    
    //Loop forever and call processPacket() for each received packet
    int count = 0;
    pcap_loop(handler, -1, extractData, (u_char *)count);
    
    //End session
    pcap_close(handler);
    return 0;
}

void extractData(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    static int count = 1;
    printf("-------------------Packet [%d]------------------\n", count++);
    printf("Length: %d\n",header->len);
    struct ether_header *eptr = (struct ether_header *) packet;
    struct ip * ipptr = (struct ip *) (packet + sizeof(struct ether_header));
    struct tcphdr * tcpptr = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
    u_char * loadptr = (u_char *)(packet+ sizeof(struct ether_header) + sizeof(struct ip) + (tcpptr->th_off)*4);
    int length = ntohs(ipptr->ip_len) - ((tcpptr->th_off)*4 + sizeof(struct ip));
    handleEthernet(eptr);
    if(eptr->ether_type == IPTYPE){
        handleIP(ipptr);
        if(ipptr->ip_p == IPPROTO_TCP){
            handleTCP(tcpptr);
            handlePayload(loadptr, length);
        } else if(ipptr->ip_p == IPPROTO_UDP){
//            handleUDP();
//            handlePayload();
        }
    } else {
        printf("No IP Header. Not Supported Yet.\n");
    }
    printf("\n\n");
    
}

void handleEthernet(struct ether_header *eptr){
    printf("Ethernet Header\n");
    printAddr(eptr->ether_dhost, "MAC Destination");
    printAddr(eptr->ether_shost, "MAC Source");
}

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

void handleIP(struct ip * ipptr){
    printf("IP Header\n");
    printf("    Version: %i\n", ipptr->ip_v);
    printf("    IP Destinaton: %s\n", inet_ntoa(ipptr->ip_dst));
    printf("    IP Source: %s\n", inet_ntoa(ipptr->ip_src));
    printf("    IP Protocol: %i\n", ipptr->ip_p);
}

void handleTCP(struct tcphdr * tcpptr){
    printf("TCP Header\n");
    printf("    Destinaton Port: %i\n", htons(tcpptr->th_dport));
    printf("    Source Port: %i\n", htons(tcpptr->th_sport));
}

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
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    
    printf("\n");
}










