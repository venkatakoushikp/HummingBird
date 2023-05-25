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

packet=packets[2]
packet.show()
#

print(packet.id+1)
print(packet[OSPF_Hello].mask)
#print(interested_flow)'''