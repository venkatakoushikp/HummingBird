'''
Code for automating the troubleshooting of OSPF via the packets from the pcap file
Created by Lakshmi Priya Saragadam, May 20, 2023.
HummingBird- The deep packet inspection tool
'''
from scapy.all import *
from scapy.contrib.ospf import *
from os import system
packets = rdpcap('/Users/priya.saragadam/Documents/Wireshark_HomePractise/ospf_day1.pcap')
os.system('clear')
interested_flows= list(set(packet[IP].src for packet in packets if packet.haslayer(OSPF_Hdr)))
count=0
# Iterate through the packets
for packet in packets:
    count = count+1
    if packet.haslayer(OSPF_Hdr):
        flow_1 = packet[IP].src
        if count <len(packets):
            p = packets[count]
            flow_2 = p[IP].src
            if flow_1 != flow_2:
                if packet.haslayer(OSPF_Hello) & p.haslayer(OSPF_Hello):
                    if packet[OSPF_Hdr].src == p[OSPF_Hdr].src:
                        print("Router-IDs are same for",flow_1,"and",flow_2,"in packet",count)      #check-1:Router-ID
                    if packet[OSPF_Hdr].area != p[OSPF_Hdr].area:
                        print("Areas are not same for",flow_1,"and",flow_2)                         #check-2:Area 
                    if packet[OSPF_Hdr].authtype != p[OSPF_Hdr].authtype:
                        print("Authtype mismatch in",flow_1,"and",flow_2)                           #check-3:Authtype
                    if packet[OSPF_Hello].mask != p[OSPF_Hello].mask:
                        print("There is a subnet mask mismatch in",flow_1,"and",flow_2)             #check-4:Subnet mask 
                    if packet[OSPF_Hello].hellointerval != p[OSPF_Hello].hellointerval:
                        print("There a hello timer mismatch in",flow_1,"and",flow_2)                #check-5:Hello interval
                    if packet[OSPF_Hello].options != p[OSPF_Hello].options:
                        print("There is mismatch in the area types of",flow_1,"and",flow_2)         #check-6:Options mismatch
                    if packet[OSPF_Hello].deadinterval != p[OSPF_Hello].deadinterval:
                        print("There a dead interval mismatch in",flow_1,"and",flow_2)              #check-7:Dead Interval