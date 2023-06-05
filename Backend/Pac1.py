from scapy.all import *
from scapy.contrib.ospf import *
import pickle

with open('data_HBD.pkl', 'rb') as f:
    my_object = pickle.load(f)
    print(my_object)

packets = rdpcap(my_object["filename_1"])

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
for i in range(len(packets)):
    if packets[i][IP].src==my_object["ip_1"]:
        try:
            if packets[i][OSPF_Hello]:
                dict_ospf["Hello_1"].append(i)
        
        except IndexError:
            pass
    if packets[i][IP].src==my_object["ip_2"]:
        try:
            if packets[i][OSPF_Hello]:
                dict_ospf["Hello_2"].append(i)

        except IndexError:
            pass # HERE
    if packets[i][IP].src=="10.1.1.1":
        try:
            if packets[i][OSPF_DBDesc]:
                dict_ospf["DBD_1"].append(i)
        
        except IndexError:
            pass #add here
    if packets[i][IP].src=="10.1.1.2":
        try:
            if packets[i][OSPF_DBDesc]:
                dict_ospf["DBD_2"].append(i)
        
        except IndexError:
            pass #add here

if len(dict_ospf["Hello_1"])==0:
    a="(001) OSPF packets not receieved from  {}".format(my_object["ip_1"])
    analysis.append(a)
    count+=1
if len(dict_ospf["Hello_2"])==0:
    a="(001) OSPF packets not receieved from  {}".format(my_object["ip_2"])
    analysis.append(a)
    count+=1
hell_1=packets[dict_ospf["Hello_1"][-1]]
hell_2=packets[dict_ospf["Hello_2"][-1]]

if (hell_1[OSPF_Hdr].area != hell_2[OSPF_Hdr].area):
    a="(002) Area Mismatch"
    count+=1
    analysis.append(a)
if (hell_1[OSPF_Hdr].authtype != hell_2[OSPF_Hdr].authtype):
    a="(003) Authorization Mismatch"
    count+=1
    analysis.append(a)
if (hell_1[OSPF_Hello].mask != hell_2[OSPF_Hello].mask):
    a="(004) Different Subnet mask"
    count+=1
    analysis.append(a)
if (hell_1[OSPF_Hello].hellointerval != hell_2[OSPF_Hello].hellointerval):
    a="(005) Different hellointerval"
    count+=1
    analysis.append(a)
if (hell_1[OSPF_Hello].deadinterval != hell_2[OSPF_Hello].deadinterval):
    a="(006) Different deadinterval"
    count+=1
    analysis.append(a)
if (hell_1[OSPF_Hdr].src == hell_2[OSPF_Hdr].src):
    a="(007) Same Router ID"
    count+=1
    analysis.append(a)

if count==0:
    info.append("INIT STATE")

if str(hell_2[OSPF_Hello].neighbors)!="[\'"+hell_1[OSPF_Hdr].src+"\']" and str(hell_1[OSPF_Hello].neighbors)=="[\'"+hell_2[OSPF_Hdr].src+"\']":
    a="(013)Peer is not the active neighbor"
    count+=1
    analysis.append(a)

if count==0:
    info.append("2 Way")
if hell_1[OSPF_Hello].router!=my_object["ip_1"] and hell_1[OSPF_Hello].backup!=my_object["ip_1"]:
    count+=1
    a="(008) HERE"
    print(my_object["ip_1"],hell_1[OSPF_Hello].router,hell_1[OSPF_Hello].backup)
    analysis.append(a)
if hell_2[OSPF_Hello].router!=my_object["ip_2"] and hell_2[OSPF_Hello].backup!=my_object["ip_2"]:
    count+=1
    a="(009) HERE"
    analysis.append(a)

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
    dbd1=packets[dict_ospf["DBD_1"][-1]]
    dbd2=packets[dict_ospf["DBD_2"][-1]]

    if dbd1[OSPF_Hdr].mtu!=dbd2[OSPF_Hdr].mtu:
        a="(012) MTU Mismatch"
        count+=1
        analysis.append(a)
except:
    IndexError

print(info,analysis)
new_var={"Info":info,"Analysis":analysis}
with open('OSPF_info_1.pkl', 'wb') as fp:
    pickle.dump(new_var, fp)
    print('dictionary saved successfully to file')

