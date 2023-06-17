from scapy.all import *
from scapy.contrib.lacp import *
import pickle

import struct

with open('data_HBD.pkl', 'rb') as f:
    my_object = pickle.load(f)
    print(my_object)

packets = rdpcap(my_object["filename_1"])

dict_ospf={"LACP_packet":[],
          }
analysis=[]
info=[]
ana_t=[]
count=0
def get_bit(byte,bit):
    return byte>>bit & 1
# Walking through the packets and 
# Appending the LACP packets into the Dictionary with Key = LACP_packet
for packet in packets:
    if packet.src==my_object["ip_1"]:
        if packet.haslayer(LACP):
             dict_ospf["LACP_packet"].append(packet)
             hell_1 = packet

if len(dict_ospf["LACP_packet"])==0:
    a="Check if you have uploaded the correct pcap"
    analysis.append(a)
    count+=1
    info.append("No LACP packets found from {}".format(my_object["ip_1"]))
    ana_t.append("The uploaded pcap doesn't have any LACP packets from {}".format(my_object["ip_1"]))

#hell_1 = packets[dict_ospf["LACP_packet"][-1]]

if  (hell_1[LACP].partner_system == '00:00:00:00:00:00'):
        a = "Check if the interface is an L2 interface(Switchport)\nCheck if the following config is given at the interface level:\n''channel-group <oper-key> mode active'' on the partner interface."
        count+=1
        analysis.append(a)
        info.append("Partner Sys-id is 00:00:00:00:00:00")
        ana_t.append("No partner detected by the actor")
        ana_t.append("Inactive interfaces found in port-channel {}".format(packet[LACP].actor_key))

elif (hell_1[LACP].actor_state != hell_1[LACP].partner_state):
    actor_state = hell_1[LACP].actor_state
    expired_bit_1 = get_bit(actor_state, 7)
    aggregation_bit_1 = get_bit(actor_state, 6)
    active_bit_1 = get_bit(actor_state, 5)
    timeout_bit_1 = get_bit(actor_state, 4) 
    synchronization_bit_1 = get_bit(actor_state, 3)
    collecting_bit_1 = get_bit(actor_state, 2)
    distributing_bit_1 = get_bit(actor_state, 1)

    partner_state = hell_1[LACP].partner_state
    expired_bit = get_bit(actor_state, 7)
    aggregation_bit = get_bit(actor_state, 6)
    active_bit = get_bit(actor_state, 5)
    timeout_bit = get_bit(actor_state, 4)
    synchronization_bit = get_bit(actor_state, 3)
    collecting_bit = get_bit(actor_state, 2)
    distributing_bit = get_bit(actor_state, 1)
    if (active_bit_1 == 0) and (active_bit == 0):
        a = "Check if both the actor and partner are given passive-passive configurations\nIf yes, then change the either to active state."
        count+=1
        analysis.append(a)
        info.append("Passive flag set on both actor and partner")
        ana_t.append("Actor-passive and Partner-passive -> No LACP negotiation")
    if (aggregation_bit_1 != aggregation_bit):
        a = "Check the following:\nLink speeds on both the actor and partner systems.\nThe no. of ports per port-channel to be bundelled."
        count+=1
        analysis.append(a)
        info.append("Aggregation bit mismatch")
        ana_t.append("The speed of the links might be different.\nMismatch in the bundelled ports of actor and partner.")
    if (timeout_bit == 1 or timeout_bit_1==1):
        a= "Check if the interfaces are shutdown.\nCheck if the port-channel is shutdown\nCheck if the device is running LACP."
        count+=1
        analysis.append(a)
        info.append("TimeOut bit mismatch")
        ana_t.append("Actor & partner should have same timeouts\nIf not,then LACPDUs are not sent/received at expected timeout frames.")
    if (synchronization_bit_1 == 0) or (synchronization_bit==0):
        a = "Check if the interfaces are shutdown.\nCheck if the port-channel is shutdown.\nCheck if the device is running LACP.\nCheck for ACLs "
        count+=1
        analysis.append(a)
        info.append("Sync bit not set")
        ana_t.append("Partner and the Actor are out of sync.")
    if (expired_bit_1 == 1) or (expired_bit == 1):
        a = "Check the LACP negotiation timeout\nCheck the port's status\nCheck the port's aggregation group membership"
        count+=1
        analysis.append(a)
        info.append("Expired bit set")
        ana_t.append("The LACP negotion failed")
    if (collecting_bit_1 == 0) or (collecting_bit ==0):
        if (hell_1[LACP].actor_system_priority != hell_1[LACP].actor_port_priority) or (hell_1[LACP].partner_system_priority != hell_1[LACP].partner_port_priority):
            a = "Check if the port is configured for LACP\nCheck if the port is connected to a partner port for LACP\nConfigure the same system priority and port priority"
            count+=1
            analysis.append(a)
            info.append("Mismatch in system priority and port priority")
            ana_t.append("The mismatch might be due to:\n1.Port not configured for LACP\n2.Port not connected to partner for LACP")
print(info,analysis)
new_var={"Info":info,"Analysis":analysis,"Ana_t":ana_t}
with open('OSPF_info.pkl', 'wb') as fp:
    pickle.dump(new_var, fp)
    print('Dictionary saved successfully to file')
    
