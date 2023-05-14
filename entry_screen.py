vars={"filename_":"",
      "protocol":""}
protos = ["OSPF","LACP", "PVST","OTHERS","DEMO PROTOCOL"] 

import tkinterweb
import pickle
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
import tkinter.messagebox as mb
import subprocess

## BASIC CODE  ##


humm_bird=tk.Tk()
humm_bird.geometry('1010x400')
humm_bird.resizable(0,0)
humm_bird.title("Deep Packet Inspection Tool")

image = Image.open("/Users/venkata.koushik/Downloads/aristalogo.png")
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

selected_fil=tk.Label(text="Selected File :{}".format(vars["filename_"]))
selected_fil.place(x=300,y=300)
def on_open():
    from tkinter.filedialog import askopenfilename  
    try:
        global vars
        fileselect=askopenfilename(filetypes=(('text files', '*.txt'),('PCAP','*.pcap'),('PCAPNG','*.pcapng')))
        print(fileselect)
        vars["filename_"]=fileselect
        with open('data_HBD.pkl', 'wb') as fp:
            pickle.dump(vars, fp)
            print('dictionary saved successfully to file')

        selected_fil.configure(text="Selected File :{}".format(vars["filename_"]))
    except:
        TypeError 
def on_grab():
    grabber=tk.Toplevel()
    mb.showerror("","You will see the PCAP in wireshark window after its pulled")
    grabber.geometry('500x500')
    grabber.title("GRAB a file from Switch")
    text1=tk.Label(grabber,text="Mention Switch Name :")
    text1.place(x=10,y=100)

    in_1=tk.Entry(grabber,width=25)
    in_1.place(x=170,y=100)

    text2=tk.Label(grabber,text="Mention PCAP Name :")
    text2.place(x=10,y=150)

    in_2=tk.Entry(grabber,width=25)
    in_2.place(x=170,y=150)

    lab2=tk.Label(grabber,text="")
    lab2.place(x=250,y=350)
    def on_gen():
        try:
            import subprocess
            cmd = "scp admin@"+ str(in_1.get())+":/mnt/flash/"+in_2.get()+" ."  # add username and password , custom location
            output = subprocess.check_output(cmd, shell=True, text=True)
            cmd = "wireshark "+in_2.get()
            vars['filename_']=str(in_2.get())
            output = subprocess.check_output(cmd, shell=True, text=True)
            selected_fil.configure(text="Selected File :{}".format(vars["filename_"]))
        except:
            Exception
            mb.showerror("","Please Recheck the inputs")

    bu1=tk.Button(grabber,text="GET PCAP",command=on_gen)
    bu1.place(x=220,y=200)



up_p=tk.Button(humm_bird,text="Upload PCAP",width=25,command=on_open)
up_p.place(x=400,y=200)

or_l=tk.Label(humm_bird,text="-- or --")
or_l.place(x=510,y=229)
gb_p=tk.Button(humm_bird,text="Grab PCAP from switch",width=25,command=on_grab)
gb_p.place(x=400,y=250)

def on_proceed():
    if vars["filename_"]=="":
        mb.showerror("INVALID PACKET","Upload A Valid PCAP first")
    elif dropdown.get() not in protos:
        mb.showerror("INVALID PROTCOL","Select a Protcol")
    else:
        vars["protocol"]=str(dropdown.get())
        with open('data_HBD.pkl', 'wb') as fp:
            pickle.dump(vars, fp)
            print('dictionary saved successfully to file')


        humm_bird.destroy()
        import project
        
prcd=tk.Button(humm_bird,text="Proceed",command=on_proceed)
prcd.place(x=900,y=350)

humm_bird.mainloop()
