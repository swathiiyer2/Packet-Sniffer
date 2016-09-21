# Packet-Sniffer
Network Traffic and Packet Analyzer supporting TCP/UDP/IGMP

##Usage
Compile using
    
    gcc --make main.cpp

Run in terminal
    
    ./main  

##Specs
  Uses libpcap for packet capture. 
  Runs in promiscious mode to capture all traffic on the network, including traffic not addressed to a specific interface 
  and broadcast traffic 
  Prints Ethernet, IP, and TCP/ UDP/ IGMP Headers and Payload. 
  
        
