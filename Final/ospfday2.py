import pickle
import time
tim=time.time()
from netaddr import IPAddress
analysis=[]
info=[]

with open('data_HBD.pkl', 'rb') as f:
    my_object = pickle.load(f)
    print(my_object)

import pyshark
capture_1 = pyshark.FileCapture(my_object['filename_1'])
capture_2 = pyshark.FileCapture(my_object['filename_2'])


dict_ospf_1={"Hello_1":[],
           "Hello_2":[],
           "DBD_1":[],
           "DBD_2":[]
           }
dict_ospf_2={"Hello_1":[],
           "Hello_2":[],
           "DBD_1":[],
           "DBD_2":[]
           }
analysis=[]
info=[]
count=0

capture_1.load_packets()
print(len(capture_1))

capture_2.load_packets()
print(len(capture_2))

for i in range(len(capture_1)):
    if hasattr(capture_1[i],'ospf'):
        if capture_1[i].ospf.msg=='1':
            if capture_1[i].ip.src==my_object["ip_1"]:
                dict_ospf_1['Hello_1'].append(i)
            if capture_1[i].ip.src==my_object["ip_2"]:
                dict_ospf_1['Hello_2'].append(i)
        elif capture_1[i].ospf.msg=='2':
            if capture_1[i].ip.src==my_object["ip_1"]:
                dict_ospf_1['DBD_1'].append(i)
            if capture_1[i].ip.src==my_object["ip_2"]:
                dict_ospf_1['DBD_2'].append(i)

for i in range(len(capture_2)):
    if hasattr(capture_2[i],'ospf'):
        if capture_2[i].ospf.msg=='1':
            if capture_2[i].ip.src==my_object["ip_1"]:
                dict_ospf_2['Hello_1'].append(i)
            if capture_2[i].ip.src==my_object["ip_2"]:
                dict_ospf_2['Hello_2'].append(i)
        elif capture_2[i].ospf.msg=='2':
            if capture_2[i].ip.src==my_object["ip_1"]:
                dict_ospf_2['DBD_1'].append(i)
            if capture_2[i].ip.src==my_object["ip_2"]:
                dict_ospf_2['DBD_2'].append(i)

if len(dict_ospf_1["Hello_1"])==0 and len(dict_ospf_2["Hello_1"])==0:
    a="OSPF Hello packets not Sent and receieved from  {}\nPossible Reasons: \n1.OSPF down on Device 1\n2.Passive Interface might have been configured\n3.Subnet Not Being advertised\n4.SVI could be down\n5.IP address might not have been assigned".format(my_object["ip_1"])
    analysis.append(a)
    count+=1
elif len(dict_ospf_1["Hello_2"])==0 and len(dict_ospf_2["Hello_2"])==0:
    a="OSPF Hello packets not Sent and receieved from  {}\nPossible Reasons: \n1.OSPF down on Device 1\n2.Passive Interface might have been configured\n3.Subnet Not Being advertised\n4.SVI could be down\n5.IP address might not have been assigned".format(my_object["ip_2"])
    analysis.append(a)
    count+=1    
elif len(dict_ospf_1["Hello_1"])!=0 and len(dict_ospf_2["Hello_1"])==0:
    a="OSPF Hello packets not receieved from  {} in pcap2\n\nPossible Reasons: \n1.Intermediate Device might be dropping packets from A".format(my_object["ip_1"])
    analysis.append(a)
    count+=1
elif len(dict_ospf_1["Hello_2"])!=0 and len(dict_ospf_2["Hello_2"])==0:
    a="OSPF Hello packets not receieved from  {} in pcap2\n\nPossible Reasons: \n1.ACL might have been applied on Intermediate Device \n or Device which has IP {}".format(my_object["ip_1"],my_object['ip_2'])
    analysis.append(a)
    count+=1    
else:
    hell_11=capture_1[dict_ospf_1["Hello_1"][-1]]
    hell_12=capture_1[dict_ospf_1["Hello_2"][-1]]    
    hell_21=capture_2[dict_ospf_2["Hello_1"][-1]]
    hell_22=capture_2[dict_ospf_2["Hello_2"][-1]] 
    hell_11=hell_11.ospf._all_fields
    hell_12=hell_12.ospf._all_fields
    hell_21=hell_21.ospf._all_fields
    hell_22=hell_22.ospf._all_fields
    if (hell_11 == hell_21 or hell_11==hell_22) and (hell_12 == hell_21 or hell_12==hell_22):
        if (hell_11['ospf.area_id'] != hell_12['ospf.area_id']):
            a=" Reason : Area Mismatch, \n{}'s  Area :{} <==> {}'s  Area :{} \n\nSolution :\n1.Enable OSPF for the network in same area on both the switches\n#router ospf [Instance_Id]\n#network {}/{} area {} \n".format(my_object["ip_1"],hell_11['ospf.area_id'],my_object["ip_2"],hell_12['ospf.area_id'],my_object["ip_1"],IPAddress(hell_11['ospf.hello.network_mask']).netmask_bits(),hell_11['ospf.area_id'])
            count+=1
            analysis.append(a)
        if hell_11['ospf.auth.type'] != hell_12['ospf.auth.type']:
            a="Reason : Authorization Mismatch \n{}'s  Auth :{} <==> {}'s  Auth :{} \n\nSolution:\n1. Configure the same Authentication type  on both \nthe switches' interfaces\n#interface [interface]\n#ip ospf authentication".format(my_object["ip_1"],hell_11['ospf.auth.type'],my_object["ip_2"],hell_12['ospf.auth.type'])
            count+=1
            analysis.append(a)
        if (hell_11['ospf.hello.network_mask'] != hell_12['ospf.hello.network_mask']):
            a="\nReason : Different Subnet mask \n{}'s  Mask :{} <==> {}'s  Mask :{} \n\nSolution:\n1.Advertise the network with same subnet mask\n#router ospf [Instance_ID]\n#network [network]/[mask] area [area]".format(my_object["ip_1"],hell_11['ospf.hello.network_mask'],my_object["ip_2"],hell_12['ospf.hello.network_mask'])
            count+=1
            analysis.append(a)
        if (hell_11['ospf.hello.hello_interval'] != hell_12['ospf.hello.hello_interval']):
            a="\nReason :Different Hello interval\n{}'s  Hello :{} <==> {}'s   \n\nSolution:\n1.Configure the Same hello Interval on both the switches' interfaces\n#interface [interface]\n#ip ospf hello-interval [interval]".format(my_object["ip_1"],hell_11['ospf.hello.hello_interval'],my_object["ip_2"],hell_12['ospf.hello.hello_interval'])
            count+=1
            analysis.append(a)
        if (hell_11['ospf.hello.router_dead_interval'] != hell_12['ospf.hello.router_dead_interval']):
            a="\nReason :Different deadinterval\n{}'s  Dead :{} <==> {}'s  Dead :{} \n\nSolution:\n1.Configure the Same Dead Interval on both the switches' interfaces\n#interface [interface]\n#ip ospf dead-interval [interval]".format(my_object["ip_1"],hell_11['ospf.hello.router_dead_interval'],my_object["ip_2"],hell_12['ospf.hello.router_dead_interval'])
            count+=1
            analysis.append(a)
        if (hell_11['ospf.srcrouter'] == hell_12['ospf.srcrouter']):
            a="\nReason :Same Router ID\n{}'s  Router ID :{} <==> {}'s  Router ID :{} \n\nSolution:\n1.Change the router-id on either of the switches\n#router ospf [Instance_ID]\n#router-id [router id]".format(my_object["ip_1"],hell_11['ospf.srcrouter'],my_object["ip_2"],hell_12['ospf.srcrouter'])
            count+=1
            analysis.append(a)
            '''
        if hell_11['ospf.hello.designated_router']!=hell_12['ospf.hello.designated_router']:
            a="\nDifferent Broadcast Domain\n{}'s  DR :{} <==> {}'s  DR :{}  ".format(my_object["ip_1"],hell_11['ospf.hello.designated_router'],my_object["ip_2"],hell_12['ospf.hello.designated_router'])
            count+=1
            analysis.append(a)'''
        if count==0:
            info.append("INIT STATE")
        else:
            new_var={"Info":info,"Analysis":analysis}
            print(new_var)
            with open('OSPF_info_twoPcaps.pkl', 'wb') as fp:
                pickle.dump(new_var, fp)
                print('dictionary saved successfully to file')
            print(time.time()-tim)
            import demo_2pcap
            quit()  

        if hell_12['ospf.hello.active_neighbor']!=hell_11['ospf.srcrouter'] and hell_11['ospf.hello.active_neighbor']!=hell_12['ospf.srcrouter']:
            a="(013)Peer is not the active neighbor"
            count+=1
            analysis.append(a)

        if count==0:
            info.append("2 Way")
        else:
            new_var={"Info":info,"Analysis":analysis}
            print(new_var)
            with open('OSPF_info_twoPcaps.pkl', 'wb') as fp:
                pickle.dump(new_var, fp)
                print('dictionary saved successfully to file')
            print(time.time()-tim)
            import demo_2pcap
            quit()  
        if hell_11['ospf.hello.designated_router']!=my_object["ip_1"] and hell_11['ospf.hello.backup_designated_router']!=my_object["ip_1"]:
            count+=1
            a=" Neither DR NOR BDR, Supposed to be in 2 way "
            analysis.append(a)

        if count==0:
            info.append("EX Start")
        else:
            new_var={"Info":info,"Analysis":analysis}
            print(new_var)
            with open('OSPF_info_twoPcaps.pkl', 'wb') as fp:
                pickle.dump(new_var, fp)
                print('dictionary saved successfully to file')
            print(time.time()-tim)
            import demo_2pcap
            quit() 
    else:

        if hell_11 != hell_21:
            print(hell_11)
            print("===================")
            print(hell_21)
            a = "Hello packets from {} are not same on both the pcaps.".format(my_object["ip_1"])
            analysis.append(a)
        elif hell_12 != hell_22:
            print(hell_12)
            print("===================")
            print(hell_22)
            a = "Hello packets from {} are not same on both the pcaps.".format(my_object["ip_2"])
            analysis.append(a)

if len(dict_ospf_1["DBD_1"])==0:
    if len(dict_ospf_2["DBD_1"])==0:
        a = "Couldnt find any DBD packets from {}".format(my_object["ip_1"])
        analysis.append(a)
    if len(dict_ospf_2["DBD_2"])==0:
        a = "Couldnt find any DBD packets from {}".format(my_object["ip_2"])
        analysis.append(a)
        
elif len(dict_ospf_1["DBD_1"])!=0:#!
    if len(dict_ospf_2["DBD_1"])==0:
        a = "Couldnt find DBD packet in pcap2 from {}".format(my_object["ip_1"])
        analysis.append(a)
    else:
        if len(dict_ospf_1["DBD_2"])!=0:

            dbd11=capture_1[dict_ospf_1["DBD_1"][-1]]
            dbd12=capture_1[dict_ospf_1["DBD_2"][-1]]
            dbd21=capture_2[dict_ospf_2["DBD_1"][-1]]
            if len(dict_ospf_2["DBD_2"])!=0:
                dbd22=capture_2[dict_ospf_2["DBD_2"][-1]]  
                dbd11=dbd11.ospf._all_fields
                dbd12=dbd12.ospf._all_fields
                dbd21=dbd21.ospf._all_fields
                dbd22=dbd22.ospf._all_fields
                if dbd11 == dbd21:
                    if dbd11['ospf.db.dd_sequence']!=dbd12['ospf.db.dd_sequence']:
                        print(dbd11['ospf.db.dd_sequence'],dbd12['ospf.db.dd_sequence'])
                        a="Sequence Number Mismatch\n{}'s  SEQ :{} <==> {}'s  SEQ :{} ".format(my_object["ip_1"],dbd11['ospf.db.dd_sequence'],my_object["ip_2"],dbd12['ospf.db.dd_sequence'])
                        count+=1
                        analysis.append(a)

                if count==0:
                    info.append("Exchange")
                else:
                    new_var={"Info":info,"Analysis":analysis}
                    print(new_var)
                    with open('OSPF_info_twoPcaps.pkl', 'wb') as fp:
                        pickle.dump(new_var, fp)
                        print('dictionary saved successfully to file')
                    print(time.time()-tim)
                    import demo_2pcap
                    quit()  


                if dbd11['ospf.db.interface_mtu']!=dbd12['ospf.db.interface_mtu']:
                    print(dbd11['ospf.db.interface_mtu'],dbd12['ospf.db.interface_mtu'])
                    a="MTU Mismatch\n{}'s  MTU :{} <==> {}'s  MTU :{} ".format(my_object["ip_1"],dbd11['ospf.db.interface_mtu'],my_object["ip_2"],dbd12['ospf.db.interface_mtu'])

                    count+=1
                    analysis.append(a)

                print(info,analysis)
                new_var={"Info":info,"Analysis":analysis}
                with open('OSPF_info_twoPcaps.pkl', 'wb') as fp:
                    pickle.dump(new_var, fp)
                    print('dictionary saved successfully to file')
                print(time.time()-tim)

if len(dict_ospf_1["DBD_2"])==0:
    if len(dict_ospf_2["DBD_2"])==0:
        a = "Couldnt find any DBD packets from {}".format(my_object["ip_2"])
        analysis.append(a)
    else:
        a = "Coundn't find DBD packet in pcap1 from {}".format(my_object["ip_2"])
        analysis.append(a)  
elif len(dict_ospf_1["DBD_2"])!=0:
    if len(dict_ospf_2["DBD_2"])==0:
        a = "Couldnt find DBD packet in pcap2 from {}".format(my_object["ip_2"])
        analysis.append(a)

print(info,analysis)
new_var={"Info":info,"Analysis":analysis}
with open('OSPF_info_twoPcaps.pkl', 'wb') as fp:
    pickle.dump(new_var, fp)
    print('dictionary saved successfully to file')
print(time.time()-tim)
import demo_2pcap
