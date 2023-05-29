from scapy.all import *
from scapy.contrib.ospf import *
from os import system
packets = rdpcap('/Users/priya.saragadam/Documents/Wireshark_HomePractise/ospf_day1.pcap')
os.system('clear')
#interested_flows= list(set(packet[IP].src for packet in packets if packet.haslayer(OSPF_Hdr)))
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
                    if packet[OSPF_Hello].router != '0.0.0.0' and  packet[OSPF_Hello].backup != '0.0.0.0':
                        if packet[OSPF_Hello].router != flow_2 or packet[OSPF_Hello].router != flow_1:
                            print("Stuck in 2-way or The router is establishing neighborship with DROther")
                    if p[OSPF_Hello].router != '0.0.0.0' and  p[OSPF_Hello].backup != '0.0.0.0':
                        if p[OSPF_Hello].router != flow_2 or p[OSPF_Hello].router != flow_1:
                            print("Stuck in 2-way or The router is establishing neighborship with DROther")
                    if packet.haslayer(OSPF_DBDesc) and p.haslayer(OSPF_DBDesc):
                        print("There is unicast reachability. Passed the exstart state")
                        if packet[OSPF_DBDesc].mtu != p[OSPF_DBDesc].mtu:
                            print("There is mtu mismatch. Stuck at exchange state")
