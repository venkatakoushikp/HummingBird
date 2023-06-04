import tkinter as tk

import tkinter.messagebox as mb
import pickle
import subprocess
from scapy.all import *


with open('data_HBD.pkl', 'rb') as f:
    my_object = pickle.load(f)
    print(my_object)

humm_bird2=tk.Tk()
humm_bird2.geometry('1010x940')
humm_bird2.resizable(0,0)
humm_bird2.title("Packet Viewer - HummingBird")

def on_wireshark():
    cmd = "wireshark "+my_object["filename_1"]
    output = subprocess.check_output(cmd, shell=True, text=True)

wireshark_b=tk.Button(humm_bird2,text="View on Wireshark",width=25,command=on_wireshark)
wireshark_b.place(x=10,y=10)

canv=tk.Canvas(humm_bird2,bg="black",height=790,width=975)
canv.place(x=10,y=100)
text_can=tk.Label(canv,text="k",bg='black')
text_can.place(x=10,y=10)
def on_here():
    packets=rdpcap(my_object['filename_1'])
    a=len(packets)
    l=tk.Scale(humm_bird2,from_=1,to=a,orient="horizontal",length=700)
    l.place(x=10,y=40)
    def on_show_i():
        print(l.get())
        text_can.configure(text=packets[int(l.get())])
        import pickle
        with open('data_HBD.pkl', 'rb') as f:
            my_object = pickle.load(f)
            print(my_object)
        import pyshark
        capture = pyshark.FileCapture(my_object['filename_1'])
        a=capture[int(l.get())-1]
        text_can.configure(text=a,font=('Times new roman',11))

    lb=tk.Button(humm_bird2,text="Show packet",command=on_show_i)
    lb.place(x=750,y=55)

notwireshark_b=tk.Button(humm_bird2,text="View Here",width=25,command=on_here)
notwireshark_b.place(x=300,y=10)

humm_bird2.mainloop()
