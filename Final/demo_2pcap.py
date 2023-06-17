import tkinter as tk
from PIL import Image, ImageTk
import tkinter.messagebox as mb
import pickle

with open('data_HBD.pkl', 'rb') as f:
    my_object = pickle.load(f)
    print(my_object)

with open('OSPF_info_twoPcaps.pkl', 'rb') as f:
    my_object3 = pickle.load(f)
    print(my_object3)


humm_bird=tk.Tk()
humm_bird.geometry('1010x750')
humm_bird.resizable(0,0)
humm_bird.title("HummingBird")

image = Image.open("/Users/venkata.koushik/Downloads/aristalogo.png")
image=image.resize((150,40))
image = ImageTk.PhotoImage(image)
label = tk.Label(humm_bird, image=image)
label.place(x=850,y=0)

top_bann=tk.Canvas(humm_bird, border=0,width=845,height=40)
top_bann.place(x=0,y=0)

ana1_bann=tk.Canvas(humm_bird, border=0,width=900,height=130,bg='black')
ana1_bann.place(x=50,y=100)

ana1_text=tk.Label(ana1_bann,text=" Start Report Generation",font=("Times New Roman",15),fg='yellow',bg='black')
ana1_text.place(x=10,y=40)

ana2_bann2=tk.Canvas(humm_bird, border=0,width=900,height=130,bg='black')
ana2_bann2.place(x=50,y=260)

ana2_text=tk.Label(ana2_bann2,text=" Not used",font=("Times New Roman",15),fg='yellow',bg='black')
ana2_text.place(x=10,y=40)

analysis_banner=tk.Canvas(humm_bird,border=0,width=420,height=250,bg='black')
analysis_banner.place(x=50,y=420)

analysis_text=tk.Label(analysis_banner,text="Inference",font=('Times New Roman',15),fg='#00FF00',bg='black')
analysis_text.place(x=10,y=10)

ana_text=tk.Label(analysis_banner,text=" Start Report Generation",font=("Times New Roman",13),fg='yellow',bg='black')
ana_text.place(x=10,y=40)

solutions_banner=tk.Canvas(humm_bird,border=0,width=460,height=250,bg='black')
solutions_banner.place(x=490,y=420)

solns_text=tk.Label(solutions_banner,text="Insights",font=('Times New Roman',15),fg='#00FF00',bg='black')
solns_text.place(x=10,y=10)


sol_text=tk.Label(solutions_banner,text=" Start Report Generation",font=("Times New Roman",13),fg='yellow',bg='black')
sol_text.place(x=10,y=40)

ana_text_ex=tk.Label(ana1_bann,text="From PCAP 1 : ",bg='black',fg='#00FF00',font=('Times New Roman',15))
ana_text_ex.place(x=10,y=10)

ana_text_re=tk.Label(ana2_bann2,text="From PCAP 2 :",bg='black',fg='#00FF00',font=('Times New Roman',15))
ana_text_re.place(x=10,y=10)
## ## ## ## ## ## ##
def on_open():
    humm_bird.destroy()
    import entry_screen

def cap_ana():
    import pyshark
    cap=pyshark.FileCapture(my_object['filename_'],display_filter="lacp")
    print(cap[1])

def on_show_packets():
    import pyshark
    global filename_
    try:
        cap=pyshark.FileCapture(my_object['filename_'])
        new_win=tk.Toplevel()
        new_win.geometry('500x500')
    
        label1=tk.Label(new_win,text=str(cap[0]))
        label1.place(x=0,y=0)
    except:
        FileNotFoundError
        mb.showerror("LACP Humming Bird","Select a valid file")
    


button_open=tk.Button(top_bann,text='Open',command=on_open)
button_open.configure(font=(15))
button_open.place(x=10,y=7)

button_save=tk.Button(top_bann,text='Save')
button_save.configure(font=(15))
button_save.place(x=110,y=7)

button_ref=tk.Button(top_bann,text='Refresh')
button_ref.configure(font=(15))
button_ref.place(x=210,y=7)


button_help=tk.Button(top_bann,text='Help')
button_help.configure(font=(15))
button_help.place(x=320,y=7)

def on_show():
    import packet_show
def on_report():
    if my_object3['Analysis']==[]:
        sol_text.configure(text=" There were no potential issues identified",fg='cyan',font=('Times New Roman',15),justify="left")

        ana_text.configure(text="From the PCAP(s) uploaded it could be infered that \nOSPF neighborship between {} and {} is UP".format(my_object['ip_1'],my_object['ip_2']),justify='left',fg='cyan',font=('Times New Roman',15))
    else:
        final_s=""
        for i in my_object3["Analysis"]:
            final_s+=i
            final_s+='\n'
        sol_text.configure(text=final_s,justify='left',font=('times new roman',15))
    if my_object3["Info"]==[]:
        ana_text.configure(text="Neighbourship not up, hasn't even gotten to the INIT state")
        ana1_text.configure(text="Parameter Mismatch, Check Insights for suggestions")
        ana2_text.configure(text="Parameter Mismatch, Check Insights for suggestions")
        for i in my_object3["Analysis"]:
            if "OSPF packets not receieved from  {}".format(my_object["ip_1"]) in i:
                sol_text.configure(text="Possible Reason(s)\n1.OSPF down on current device",font=('Times New Roman',15))
            if "OSPF packets not receieved from  {}".format(my_object["ip_2"]) in i:
                sol_text.configure(text="Possible Reason(s):\n1.OSPF down on peer\n2.Passive Interface Configured\n3.Intermediate Device Droping Hello packets\n5.SVI Down\n6.Address not advertised",font=('Times New Roman',15))

    else:
        final_s=""
        for i in my_object3["Info"]:
            final_s+=i
            final_s+=' reached \n'
        ana1_text.configure(text=final_s)
        ana2_text.configure(text=final_s)
    if my_object3["Info"]==[]:
        
        if my_object3['Analysis']!=[]:
            ana_text.configure(text="From the PCAP uploaded, the tool could infer that neighborship\nbetween {} and {} has not reached INIT state yet".format(my_object["ip_1"],my_object["ip_2"]),justify="left",anchor='w',font=('times new roman',15)) 
            ana1_text.configure(text="Hello Packets are being Sent and Received from {} and {}".format(my_object["ip_1"],my_object["ip_2"]),justify="left",anchor='w')
            ana2_text.configure(text="Hello Packets are being Sent and Received from {} and {}".format(my_object["ip_1"],my_object["ip_2"]),justify="left",anchor='w')
        for i in my_object3["Analysis"]:
            if "OSPF Hello packets not receieved from  {}".format(my_object["ip_1"]) in i:
                ana2_text.configure(text="OSPF packets from {} are not seen on Packet Capture".format(my_object["ip_1"]),font=('Times New Roman',15))
                #sol_text.configure(text="Possible Reason(s)\n1.OSPF down on current device\n2.Capture is taken on wrong interface\n3.Inappropriate filters were used to capture packet",justify="left",anchor='w')
            if "OSPF Hello packets not receieved from  {}".format(my_object["ip_2"]) in i:
                ana1_text.configure(text="OSPF packets from {} are not seen on Packet Capture".format(my_object["ip_2"]),font=('Times New Roman',15))
                #sol_text.configure(text="Possible Reason(s):\n1.OSPF down on peer\n2.Passive Interface Configured\n3.ACL is blocking hello\n4.Intermediate Device Droping Hello packets\n5.SVI Down\n6.Address not advertised",justify='left')

        
    if str(my_object3["Analysis"])[3:6]=='013':
        sol_text.configure(text="Reason : {}".format(my_object3["Analysis"][0][5:]),font=('Times New Roman',15))
        ana_text.configure(text="Neighbourship stuck in Init State".format(my_object["ip_1"]))
    
    if str(my_object3["Analysis"])[3:6]=='010':
        ana_text.configure(text=my_object3["Analysis"][0][5:],font=('Times New Roman',15))
        sol_text.configure(text="From {}'s side Possible Reasons:\n\n Unicast Reachability Issue or ACL Applied\nHigh CPU utilization\nCongestion in Network".format(my_object["ip_1"]))
    for i in my_object3["Analysis"]:
        if "MTU" in i:
            ana_text.configure(text="From the PCAP uploaded, the tool could infer that neighborship\nbetween {} and {} is Stuck in EXCHANGE STATE".format(my_object['ip_1'],my_object['ip_2']),font=('Times New Roman',15))
            sol_text.configure(text="Reason :\n\n{} \n\n\nSuggestion:\n\n1.Configure the same MTU on both the interfaces \n(OSPF Adjacency is established only when the MTU values of \nthe two routers are matched)".format(my_object3['Analysis'][0]),fg='#FF9C2D',font=('Times New Roman',15))
        if "Seq" in i:
            ana_text.configure(text="Stuck in EX Start STATE")
        if "Couldnt find DBD packet in pcap2 from {}".format(my_object["ip_1"]) in i:
            ana_text.configure(text="1. OSPF neighbourship between the peers is stuck in Ex Start\n2. DBD packets from {} are not seen in PCAP 2".format(my_object["ip_1"]),font=('Times new roman',15),justify='left')
            sol_text.configure(text="Possible Reasons:\n1.ACL might have been applied on intermediate device or the device \nsending DBD packets destined to {}\n2.High CPU utilisation might have led to packet drop".format(my_object['ip_1']).format(my_object["ip_1"]),font=('Times new roman',15),justify='left')
        if "Couldnt find DBD packet in pcap1 from {}".format(my_object["ip_2"]) in i:
            pass 
  
button_report=tk.Button(top_bann,text='Show Report',command=on_report)
button_report.configure(font=(15))
button_report.place(x=415,y=7)

button_packets=tk.Button(top_bann,text='Show Packets',command=on_show,disabledforeground="black")
button_packets.configure(font=(15))
button_packets.place(x=560,y=7)


humm_bird.mainloop()