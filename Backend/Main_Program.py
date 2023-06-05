vars={"filename_1":"",
      "filename_2":"",
      "Pathlength":0,
      "ip_1":"",
      "ip_2":"",
      "protocol":""}
protos = ["OSPF","LACP","BGP","TCP Re-Transmission"] 

import pickle
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from PIL import Image, ImageTk
import tkinter.messagebox as mb


## BASIC CODE  ##

humm_bird=tk.Tk()
humm_bird.geometry('1010x400')
humm_bird.resizable(0,0)
humm_bird.title("Deep Packet Inspection Tool")

image = Image.open("/Users/priya.saragadam/Downloads/arista_logo.ong.png")
image=image.resize((150,40))
image = ImageTk.PhotoImage(image)
label = tk.Label(humm_bird, image=image)
label.place(x=850,y=0)

## ## ## ## ## ##
intro_text=tk.Label(humm_bird,text="Welcome to Deep Packet Inspection Tool",font=('Times new roman',25))
intro_text.place(x=10,y=3)

Proto=tk.Label(humm_bird,text="Select a Protocol :",font=('Bahnschrift',15))
Proto.place(x=250,y=150)

dropdown=ttk.Combobox(humm_bird,values=protos,width=25)
dropdown.place(x=400,y=150)
def on_open():
    from tkinter.filedialog import askopenfilename
    try:
        global vars
        fileselect=askopenfilename(filetypes=(('PCAP','*.pcap'),('PCAPNG','*.pcapng')))
        print(fileselect)
        vars["filename_1"]=fileselect
        
        with open('data_HBD.pkl', 'wb') as fp:
            pickle.dump(vars, fp)
            print('dictionary saved successfully to file')

        selected_fil.configure(text="Selected File 1:{}".format(vars["filename_1"]))

    except:
        TypeError
def on_open2():
    from tkinter.filedialog import askopenfilename
    try:
        global vars
        fileselect=askopenfilename(filetypes=(('PCAP','*.pcap'),('PCAPNG','*.pcapng')))
        print(fileselect)
        vars["filename_2"]=fileselect
        
        with open('data_HBD.pkl', 'wb') as fp:
            pickle.dump(vars, fp)
            print('dictionary saved successfully to file')

        selected_fil2.configure(text="Selected File 2:{}".format(vars["filename_2"]))
    except:
        TypeError 
def on_grab():
    grabber=tk.Toplevel()

    grabber.geometry('500x700')
    grabber.title("GRAB a file from Switch")
    text1=tk.Label(grabber,text="Mention Switch Name or IP:")
    text1.place(x=10,y=20)

    in_1=tk.Entry(grabber,width=25)
    in_1.place(x=210,y=20)

    text2=tk.Label(grabber,text="Mention PCAP Path :")
    text2.place(x=10,y=70)

    in_2=tk.Entry(grabber,width=25)
    in_2.place(x=210,y=70)

    text3=tk.Label(grabber,text="Username :")
    text3.place(x=10,y=120)

    in_3=tk.Entry(grabber,width=25)
    in_3.place(x=210,y=120)

    text4=tk.Label(grabber,text="Password  :")
    text4.place(x=10,y=170)

    in_4=tk.Entry(grabber,width=25)
    in_4.place(x=210,y=170)


    def on_gen():
        try:
            import subprocess
            a=in_3.get()
            cmd = "scp {}@".format(a)+ str(in_1.get())+":/{}".format(in_2.get())+" ." # add username and password , custom location
            output = subprocess.check_output(cmd, shell=True, text=True)
            a=str(in_2.get()).split("/")
            vars['filename_1']=a[-1]
            print(a)
            selected_fil.configure(text="Selected File 1:{}".format(vars["filename_1"]))
        except:
            Exception
            mb.showerror("","Please Recheck the inputs")

    bu1=tk.Button(grabber,text="GET PCAP",command=on_gen)
    bu1.place(x=220,y=220)

    tk.Label(grabber,text="+++++++++++++++++++++++++++++++++++++++++").place(x=100,y=270)
    text11=tk.Label(grabber,text="Mention Switch Name or IP:")
    text11.place(x=10,y=320)

    in_11=tk.Entry(grabber,width=25)
    in_11.place(x=210,y=320)

    text21=tk.Label(grabber,text="Mention PCAP Path :")
    text21.place(x=10,y=370)

    in_21=tk.Entry(grabber,width=25)
    in_21.place(x=210,y=370)

    text31=tk.Label(grabber,text="Username :")
    text31.place(x=10,y=420)

    in_31=tk.Entry(grabber,width=25)
    in_31.place(x=210,y=420)

    text41=tk.Label(grabber,text="Password  :")
    text41.place(x=10,y=470)

    in_41=tk.Entry(grabber,width=25)
    in_41.place(x=210,y=470)


    def on_gen2():
        try:
            import subprocess
            a=in_31.get()
            cmd = "scp {}@".format(a)+ str(in_11.get())+":/{}".format(in_21.get())+" ."  # add username and password , custom location
            output = subprocess.check_output(cmd, shell=True, text=True)
            a=str(in_21.get()).split("/")
            print(a)
            vars['filename_2']=a[-1]


            selected_fil2.configure(text="Selected File 2:{}".format(vars["filename_2"]))
        except:
            Exception
            mb.showerror("","Please Recheck the inputs")

    bu1=tk.Button(grabber,text="GET PCAP",command=on_gen2)
    bu1.place(x=220,y=520)

up_p=tk.Button(humm_bird,text="Upload PCAP 1",width=10,command=on_open,state='disabled')
up_p.place(x=400,y=200)
up_p2=tk.Button(humm_bird,text="Upload PCAP 2",width=10,command=on_open2,state='disabled')
up_p2.place(x=540,y=200)

or_l=tk.Label(humm_bird,text="-- or --")
or_l.place(x=510,y=229)
gb_p=tk.Button(humm_bird,text="Grab PCAP from switch",width=25,command=on_grab,state='disabled')
gb_p.place(x=400,y=250)

def on_att():
    if dropdown.get()=="OSPF":
        vars['protocol']=dropdown.get()
        new_win=tk.Toplevel()
        new_win.title("OSPF")
        new_win.geometry('500x160')
        new_win.resizable(0,0)
        ip1_1_t=tk.Label(new_win,text="Provide IP Address of 1st device (* PCAP 1)",font=("times new roman",16))
        ip1_1_t.place(x=10,y=10)
        ip1_in=tk.Entry(new_win,width=10)
        ip1_in.place(x=350,y=10)
        ip1_2_t=tk.Label(new_win,text="Provide IP Address of 2nd device (* PCAP 2)",font=("times new roman",16))
        ip1_2_t.place(x=10,y=50)
        ip2_in=tk.Entry(new_win,width=10)
        ip2_in.place(x=350,y=50)

        def on_next():
            a=ip1_in.get()
            b=ip2_in.get()
            if (a==b) or (b=="") or (a==""):
                messagebox.showerror("","Mention Valid IP address")
            else:
                vars["ip_1"]=a
                vars["ip_2"]=b
                new_win.destroy()
                up_p.configure(state='active')
                up_p2.configure(state='active')
                gb_p.configure(state='active')

        b2=tk.Button(new_win,text="Proceed",command=on_next)
        b2.place(x=250,y=120)
    elif dropdown.get()=="LACP":
        vars['protocol']=dropdown.get()
        new_win=tk.Toplevel()
        new_win.title("LACP")
        new_win.geometry('500x160')
        new_win.resizable(0,0)
        ip1_1_t=tk.Label(new_win,text="Provide MAC Address of the switch",font=("times new roman",16))
        ip1_1_t.place(x=10,y=1)
        ip1_in=tk.Entry(new_win,width=10)
        ip1_in.place(x=350,y=10)
        def on_next():
            a=ip1_in.get()
            if ip1_in.get()!="":
                vars['ip_1']=ip1_in.get()
                new_win.destroy()
                up_p.configure(state='active')
                up_p2.configure(state='disabled')
                gb_p.configure(state='active')

        b2=tk.Button(new_win,text="Proceed",command=on_next)
        b2.place(x=250,y=120)


    else:
        messagebox.showerror("","Currently, the tool only supports OSPF,LACP")
butt_attributes=tk.Button(humm_bird,text="Mention Attributes",command=on_att)
butt_attributes.place(x=660,y=150)

selected_fil=tk.Label(text="Selected File 1:{}".format(vars["filename_1"]))
selected_fil.place(x=300,y=300)
selected_fil2=tk.Label(text="Selected File 2:{}".format(vars["filename_2"]))
selected_fil2.place(x=300,y=330)
def on_open():
    from tkinter.filedialog import askopenfilename
    try:
        global vars
        fileselect=askopenfilename(filetypes=(('PCAP','*.pcap'),('PCAPNG','*.pcapng')))
        print(fileselect)
        vars["filename_1"]=fileselect
        
        with open('data_HBD.pkl', 'wb') as fp:
            pickle.dump(vars, fp)
            print('dictionary saved successfully to file')

        selected_fil.configure(text="Selected File 1:{}".format(vars["filename_1"]))

    except:
        TypeError
def on_open2():
    from tkinter.filedialog import askopenfilename
    try:
        global vars
        fileselect=askopenfilename(filetypes=(('PCAP','*.pcap'),('PCAPNG','*.pcapng')))
        print(fileselect)
        vars["filename_2"]=fileselect
        
        with open('data_HBD.pkl', 'wb') as fp:
            pickle.dump(vars, fp)
            print('dictionary saved successfully to file')

        selected_fil2.configure(text="Selected File 2:{}".format(vars["filename_2"]))
    except:
        TypeError 
def on_grab():
    grabber=tk.Toplevel()

    grabber.geometry('500x700')
    grabber.title("GRAB a file from Switch")
    text1=tk.Label(grabber,text="Mention Switch Name or IP:")
    text1.place(x=10,y=20)

    in_1=tk.Entry(grabber,width=25)
    in_1.place(x=210,y=20)

    text2=tk.Label(grabber,text="Mention PCAP Path :")
    text2.place(x=10,y=70)

    in_2=tk.Entry(grabber,width=25)
    in_2.place(x=210,y=70)

    text3=tk.Label(grabber,text="Username :")
    text3.place(x=10,y=120)

    in_3=tk.Entry(grabber,width=25)
    in_3.place(x=210,y=120)

    text4=tk.Label(grabber,text="Password  :")
    text4.place(x=10,y=170)

    in_4=tk.Entry(grabber,width=25)
    in_4.place(x=210,y=170)


    def on_gen():
        try:
            import subprocess
            a=in_3.get()
            cmd = "scp {}@".format(a)+ str(in_1.get())+":/{}".format(in_2.get())+" ." # add username and password , custom location
            output = subprocess.check_output(cmd, shell=True, text=True)
            a=str(in_2.get()).split("/")
            vars['filename_1']=a[-1]
            print(a)
            selected_fil.configure(text="Selected File 1:{}".format(vars["filename_1"]))
        except:
            Exception
            mb.showerror("","Please Recheck the inputs")

    bu1=tk.Button(grabber,text="GET PCAP",command=on_gen)
    bu1.place(x=220,y=220)
    if vars['protocol']=='OSPF':
        tk.Label(grabber,text="+++++++++++++++++++++++++++++++++++++++++").place(x=100,y=270)
        text11=tk.Label(grabber,text="Mention Switch Name or IP:")
        text11.place(x=10,y=320)

        in_11=tk.Entry(grabber,width=25)
        in_11.place(x=210,y=320)

        text21=tk.Label(grabber,text="Mention PCAP Path :")
        text21.place(x=10,y=370)

        in_21=tk.Entry(grabber,width=25)
        in_21.place(x=210,y=370)

        text31=tk.Label(grabber,text="Username :")
        text31.place(x=10,y=420)

        in_31=tk.Entry(grabber,width=25)
        in_31.place(x=210,y=420)

        text41=tk.Label(grabber,text="Password  :")
        text41.place(x=10,y=470)

        in_41=tk.Entry(grabber,width=25)
        in_41.place(x=210,y=470)


        def on_gen2():
            try:
                import subprocess
                a=in_31.get()
                cmd = "scp {}@".format(a)+ str(in_11.get())+":/{}".format(in_21.get())+" ."  # add username and password , custom location
                output = subprocess.check_output(cmd, shell=True, text=True)
                a=str(in_21.get()).split("/")
                print(a)
                vars['filename_2']=a[-1]


                selected_fil2.configure(text="Selected File 2:{}".format(vars["filename_2"]))
            except:
                Exception
                mb.showerror("","Please Recheck the inputs")

        bu1=tk.Button(grabber,text="GET PCAP",command=on_gen2)
        bu1.place(x=220,y=520)

up_p=tk.Button(humm_bird,text="Upload PCAP 1",width=10,command=on_open,state='disabled')
up_p.place(x=400,y=200)
up_p2=tk.Button(humm_bird,text="Upload PCAP 2",width=10,command=on_open2,state='disabled')
up_p2.place(x=540,y=200)

or_l=tk.Label(humm_bird,text="-- or --")
or_l.place(x=510,y=229)
gb_p=tk.Button(humm_bird,text="Grab PCAP from switch",width=25,command=on_grab,state='disabled')
gb_p.place(x=400,y=250)

def on_proceed():
    if vars["filename_1"]!="" and vars["filename_2"]!="":
        vars["Pathlength"]=2
    elif vars["filename_1"]!="" or vars["filename_2"]!="":
        vars["Pathlength"]=1
    else:
        vars["Pathlength"]=0
    print(vars)
    if vars["filename_1"]=="":
        mb.showerror("Upload Atleast one Valid PCAP")
    elif dropdown.get() not in protos:
        mb.showerror("INVALID PROTCOL","Select a Protcol")
    else:
        vars["protocol"]=str(dropdown.get())
        with open('data_HBD.pkl', 'wb') as fp:
            pickle.dump(vars, fp)
            print('dictionary saved successfully to file')


        humm_bird.destroy()
        if vars["protocol"]=='LACP':
            import lacp
            import Demo_ 
        elif vars["protocol"]=='OSPF':
            import Pac1
            if vars["filename_2"]!="":
                import Pac2
            import Demo_ospf     
prcd=tk.Button(humm_bird,text="Proceed",command=on_proceed)
prcd.place(x=900,y=350)

humm_bird.mainloop()
