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
        count = count+1
        if packet[LACP].actor_system == '00:00:00:00:00:00':
            print("No LACP configs present in",packet.src)
        if packet[LACP].partner_system == '00:00:00:00:00:00':
            print("No LACP configs present in the partner. Check",count,"th packet")
        if packet[LACP].actor_state != packet[LACP].partner_state:
            print("There is mismatch in flags. Check",count,"th packet")
print("Result after verifying",count,"packets in the uploaded pcap")