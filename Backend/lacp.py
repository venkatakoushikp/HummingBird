'''
Code for automating the troubleshooting of LACP via the packets from the pcap file
Created by Lakshmi Priya Saragadam, May 20, 2023.
HummingBird- The deep packet inspection tool
'''
from scapy.all import *
from scapy.contrib.ospf import *
from scapy.contrib.lacp import *
from os import system

packets = rdpcap('/Users/priya.saragadam/Documents/Wireshark_HomePractise/LACP.pcap')
os.system('clear')
count =0
for packet in packets:
    if packet.haslayer(LACP):
        count =count+1
print(count)