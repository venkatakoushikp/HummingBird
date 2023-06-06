
import time

tim=time.time()

import pickle
with open('data_HBD.pkl', 'rb') as f:
    my_object = pickle.load(f)
    print(my_object)

with open('data_HBD.pkl', 'rb') as f:
    my_object = pickle.load(f)
    print(my_object)

import pyshark
capture = pyshark.FileCapture(my_object['filename_1'])


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
    print(time.time()-tim)
    quit()

hell_1=hell_1.ospf._all_fields
hell_2=hell_2.ospf._all_fields
print(hell_1,hell_2,sep="\n\n\n")

if (hell_1['ospf.area_id'] != hell_2['ospf.area_id']):
    a="Area Mismatch, \n{}'s  Area :{} <==> {}'s  Area :{} ".format(my_object["ip_1"],hell_1['ospf.area_id'],my_object["ip_2"],hell_2['ospf.area_id'])
    count+=1
    analysis.append(a)
if hell_1['ospf.auth.type'] != hell_2['ospf.auth.type']:
    a="Authorization Mismatch \n{}'s  Auth :{} <==> {}'s  Auth :{} ".format(my_object["ip_1"],hell_1['ospf.auth.type'],my_object["ip_2"],hell_2['ospf.auth.type'])
    count+=1
    analysis.append(a)
if (hell_1['ospf.hello.network_mask'] != hell_2['ospf.hello.network_mask']):
    a="Different Subnet mask \n{}'s  Mask :{} <==> {}'s  Mask :{} ".format(my_object["ip_1"],hell_1['ospf.hello.network_mask'],my_object["ip_2"],hell_2['ospf.hello.network_mask'])
    count+=1
    analysis.append(a)
if (hell_1['ospf.hello.hello_interval'] != hell_2['ospf.hello.hello_interval']):
    a="Different hellointerval\n{}'s  Hello :{} <==> {}'s  Hellp :{} ".format(my_object["ip_1"],hell_1['ospf.hello.hello_interval'],my_object["ip_2"],hell_2['ospf.hello.hello_interval'])
    count+=1
    analysis.append(a)
if (hell_1['ospf.hello.router_dead_interval'] != hell_2['ospf.hello.router_dead_interval']):
    a="Different deadinterval\n{}'s  Dead :{} <==> {}'s  Dead :{} ".format(my_object["ip_1"],hell_1['ospf.hello.router_dead_interval'],my_object["ip_2"],hell_2['ospf.hello.router_dead_interval'])
    count+=1
    analysis.append(a)
if (hell_1['ospf.srcrouter'] == hell_2['ospf.srcrouter']):
    a="Same Router ID\n{}'s  Router ID :{} <==> {}'s  Router ID :{} ".format(my_object["ip_1"],hell_1['ospf.srcrouter'],my_object["ip_2"],hell_2['ospf.srcrouter'])
    count+=1
    analysis.append(a)
if hell_1['ospf.hello.designated_router']!=hell_2['ospf.hello.designated_router']:
    a="Different Broadcast Domain\n{}'s  DR :{} <==> {}'s  DR :{} ".format(my_object["ip_1"],hell_1['ospf.hello.designated_router'],my_object["ip_2"],hell_2['ospf.hello.designated_router'])
    count+=1
    analysis.append(a)

if count==0:
    info.append("INIT STATE")
else:
    new_var={"Info":info,"Analysis":analysis}
    print(new_var)
    with open('OSPF_info.pkl', 'wb') as fp:
        pickle.dump(new_var, fp)
        print('dictionary saved successfully to file')
    print(time.time()-tim)
    quit()  

if hell_2['ospf.hello.active_neighbor']!=hell_1['ospf.srcrouter'] and hell_1['ospf.hello.active_neighbor']!=hell_2['ospf.srcrouter']:
    a="(013)Peer is not the active neighbor"
    count+=1
    analysis.append(a)

if count==0:
    info.append("2 Way")
else:
    new_var={"Info":info,"Analysis":analysis}
    print(new_var)
    with open('OSPF_info.pkl', 'wb') as fp:
        pickle.dump(new_var, fp)
        print('dictionary saved successfully to file')
    print(time.time()-tim)
    quit()  
if hell_1['ospf.hello.designated_router']!=my_object["ip_1"] and hell_1['ospf.hello.backup_designated_router']!=my_object["ip_1"]:
    count+=1
    a=" Neither DR NOR BDR, Supposed to be in 2 way "
    analysis.append(a)
'''if hell_2['ospf.srcrouter']!=my_object["ip_2"] and hell_2['ospf.hello.backup_designated_router']!=my_object["ip_2"]:
    count+=1
    a="(009) Neither DR NOR BDR"
    analysis.append(a)'''

if count==0:
    info.append("EX Start")
else:
    new_var={"Info":info,"Analysis":analysis}
    print(new_var)
    with open('OSPF_info.pkl', 'wb') as fp:
        pickle.dump(new_var, fp)
        print('dictionary saved successfully to file')
    print(time.time()-tim)
    quit()  

if len(dict_ospf["DBD_1"])==0:
    a="(010) Couldnt find any DBD packets from {}".format(my_object["ip_1"])
    analysis.append(a)
    count+=1
    new_var={"Info":info,"Analysis":analysis}
    with open('OSPF_info.pkl', 'wb') as fp:
        pickle.dump(new_var, fp)
        print('dictionary saved successfully to file')
    print(time.time()-tim)
    quit()
    

if len(dict_ospf["DBD_2"])==0:
    a="(011) Couldnt find any DBD packets from {}".format(my_object["ip_2"])
    analysis.append(a)
    count+=1
    new_var={"Info":info,"Analysis":analysis}
    with open('OSPF_info.pkl', 'wb') as fp:
        pickle.dump(new_var, fp)
        print('dictionary saved successfully to file')
    print(time.time()-tim)
    quit()
try:
    dbd1=capture[dict_ospf["DBD_1"][-1]]
    dbd2=capture[dict_ospf["DBD_2"][-1]]
    
except:
    IndexError
    print(info,analysis)
    new_var={"Info":info,"Analysis":analysis}
    with open('OSPF_info.pkl', 'wb') as fp:
        pickle.dump(new_var, fp)
        print('dictionary saved successfully to file2')
    quit()
dbd1=dbd1.ospf._all_fields
dbd2=dbd2.ospf._all_fields

if dbd1['ospf.db.dd_sequence']!=dbd2['ospf.db.dd_sequence']:
    print(dbd1['ospf.db.dd_sequence'],dbd2['ospf.db.dd_sequence'])
    a="Sequence Number Mismatch\n{}'s  SEQ :{} <==> {}'s  SEQ :{} ".format(my_object["ip_1"],dbd1['ospf.db.dd_sequence'],my_object["ip_2"],dbd2['ospf.db.dd_sequence'])
    count+=1
    analysis.append(a)

if count==0:
    info.append("Exchange")
else:
    new_var={"Info":info,"Analysis":analysis}
    print(new_var)
    with open('OSPF_info.pkl', 'wb') as fp:
        pickle.dump(new_var, fp)
        print('dictionary saved successfully to file')
    print(time.time()-tim)
    quit()  


if dbd1['ospf.db.interface_mtu']!=dbd2['ospf.db.interface_mtu']:
        print(dbd1['ospf.db.interface_mtu'],dbd2['ospf.db.interface_mtu'])
        a="MTU Mismatch\n{}'s  MTU :{} <==> {}'s  MTU :{} ".format(my_object["ip_1"],dbd1['ospf.db.interface_mtu'],my_object["ip_2"],dbd2['ospf.db.interface_mtu'])

        count+=1
        analysis.append(a)

print(info,analysis)
new_var={"Info":info,"Analysis":analysis}
with open('OSPF_info.pkl', 'wb') as fp:
    pickle.dump(new_var, fp)
    print('dictionary saved successfully to file')
print(time.time()-tim)