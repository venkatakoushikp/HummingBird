import pyshark
capture = pyshark.FileCapture("/Users/venkata.koushik/ospf_day1.pcap")
for packet in capture:
    print(packet.ospf._all_fields)
    break

import time
import pickle
with open('data_HBD.pkl', 'rb') as f:
    my_object = pickle.load(f)
    print(my_object)
a=time.time()
with open('data_HBD.pkl', 'rb') as f:
    my_object = pickle.load(f)
    print(my_object)

dict_ospf={"Hello_1":[],
           "Hello_2":[],
           "DBD_1":[],
           "DBD_2":[]
           }
analysis=[]
info=[]
count=0

capture.load_packets()
print(len(capture))

for i in range(len(capture)):
    if hasattr(capture[i],'ospf'):
        if capture[i].ospf.msg=='1':
            if capture[i].ip.src==my_object["ip_1"]:
                dict_ospf['Hello_1'].append(i)
            if capture[i].ip.src==my_object["ip_2"]:
                dict_ospf['Hello_2'].append(i)
        elif capture[i].ospf.msg=='2':
            if capture[i].ip.src==my_object["ip_1"]:
                dict_ospf['DBD_1'].append(i)
            if capture[i].ip.src==my_object["ip_2"]:
                dict_ospf['DBD_2'].append(i)
            

if len(dict_ospf["Hello_1"])==0:
    a="OSPF packets not receieved from  {}".format(my_object["ip_1"])
    analysis.append(a)
    count+=1
if len(dict_ospf["Hello_2"])==0:
    a="OSPF packets not receieved from  {}".format(my_object["ip_2"])
    analysis.append(a)
    count+=1
try:
    hell_1=capture[dict_ospf["Hello_1"][-1]]
    hell_2=capture[dict_ospf["Hello_2"][-1]]
except:
    IndexError
    new_var={"Info":info,"Analysis":analysis}
    print(new_var)
    with open('OSPF_info.pkl', 'wb') as fp:
        pickle.dump(new_var, fp)
        print('dictionary saved successfully to file')
    quit()

hell_1=hell_1.ospf._all_fields
hell_2=hell_2.ospf._all_fields

if (hell_1['ospf.area_id'] != hell_2['ospf.area_id']):
    a="(002) Area Mismatch"
    count+=1
    analysis.append(a)
if hell_1['ospf.auth.type'] != hell_2['ospf.auth.type']:
    a="(003) Authorization Mismatch"
    count+=1
    analysis.append(a)
if (hell_1['ospf.hello.network_mask'] != hell_2['ospf.hello.network_mask']):
    a="(004) Different Subnet mask"
    count+=1
    analysis.append(a)
if (hell_1['ospf.hello.hello_interval'] != hell_2['ospf.hello.hello_interval']):
    a="(005) Different hellointerval"
    count+=1
    analysis.append(a)
if (hell_1['ospf.hello.router_dead_interval'] != hell_2['ospf.hello.router_dead_interval']):
    a="(006) Different deadinterval"
    count+=1
    analysis.append(a)
if (hell_1['ospf.srcrouter'] == hell_2['ospf.srcrouter']):
    a="(007) Same Router ID"
    count+=1
    analysis.append(a)

if count==0:
    info.append("INIT STATE")

if hell_2['ospf.hello.active_neighbor']!=hell_1['ospf.srcrouter'] and hell_1['ospf.hello.active_neighbor']!=hell_2['ospf.srcrouter']:
    a="(013)Peer is not the active neighbor"
    count+=1
    analysis.append(a)

if count==0:
    info.append("2 Way")
if hell_1['ospf.srcrouter']!=my_object["ip_1"] and hell_1['ospf.hello.backup_designated_router']!=my_object["ip_1"]:
    count+=1
    a="(008) Neither DR NOR BDR"
    analysis.append(a)
'''if hell_2['ospf.srcrouter']!=my_object["ip_2"] and hell_2['ospf.hello.backup_designated_router']!=my_object["ip_2"]:
    count+=1
    a="(009) Neither DR NOR BDR"
    analysis.append(a)'''

if count==0:
    info.append("EX Start")

if len(dict_ospf["DBD_1"])==0:
    a="(010) DBD packets not received from {}".format(my_object["ip_1"])
    analysis.append(a)
    count+=1
    new_var={"Info":info,"Analysis":analysis}
    with open('OSPF_info.pkl', 'wb') as fp:
        pickle.dump(new_var, fp)
        print('dictionary saved successfully to file')
    quit()
    

if len(dict_ospf["DBD_2"])==0:
    a="(011) DBD packets not received from {}".format(my_object["ip_2"])
    analysis.append(a)
    count+=1
    new_var={"Info":info,"Analysis":analysis}
    with open('OSPF_info.pkl', 'wb') as fp:
        pickle.dump(new_var, fp)
        print('dictionary saved successfully to file')
    quit()

if count==0:
    info.append("Exchange")

try:
    dbd1=capture[dict_ospf["DBD_1"][-1]]
    dbd2=capture[dict_ospf["DBD_2"][-1]]

    if dbd1['ospf.db.interface_mtu']!=dbd2['ospf.db.interface_mtu']:
        a="(012) MTU Mismatch"
        count+=1
        analysis.append(a)
except:
    IndexError
    print(info,analysis)
    new_var={"Info":info,"Analysis":analysis}
    with open('OSPF_info.pkl', 'wb') as fp:
        pickle.dump(new_var, fp)
        print('dictionary saved successfully to file')

print(info,analysis)
new_var={"Info":info,"Analysis":analysis}
with open('OSPF_info.pkl', 'wb') as fp:
    pickle.dump(new_var, fp)
    print('dictionary saved successfully to file')

print(analysis,info)
