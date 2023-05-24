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
count =0
interested_flows= list(set(packet[IP].src for packet in packets if packet.haslayer(OSPF_Hdr)))

packets[0].show()
'''
packet=packets[0]
print(packet[IP].src)
print(packet[OSPF_Hdr].type)
#print(interested_flow)
'''
for flow in interested_flows:
    for packet in packets:
        if packet[IP].src == flow and packet[OSPF_Hdr].type==1:
            count = count+1
    print(count)