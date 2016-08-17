# Packet-Sniffer
Network Traffic and Packet Analyzer supporting TCP/UDP/IGMP

##Usage
Run in command line with

    ./packet-sniffer.exe

##Specs
  Uses libpcap for packet capture. 
  Runs in promiscious mode to capture all traffic on the network, including traffic not addressed to a specific interface 
  and broadcast traffic 
  Prints Ethernet, IP, and TCP/ UDP/ IGMP Headers and Payload. 
  
        
