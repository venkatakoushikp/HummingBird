

import tkinter as tk
from PIL import Image, ImageTk
import tkinter.messagebox as mb
import pickle



with open('data_HBD.pkl', 'rb') as f:
    my_object = pickle.load(f)
    print(my_object)

humm_bird=tk.Tk()
humm_bird.geometry('1010x700')
humm_bird.resizable(0,0)
humm_bird.title("LACP Analyser - HummingBird")

image = Image.open("/Users/venkata.koushik/Downloads/aristalogo.png")
image=image.resize((150,40))
image = ImageTk.PhotoImage(image)
label = tk.Label(humm_bird, image=image)
label.place(x=850,y=0)

##.  TOP BANNER ##

top_bann=tk.Canvas(humm_bird, border=0,width=845,height=40)
top_bann.place(x=0,y=0)

ana_bann=tk.Canvas(humm_bird, border=0,width=400,height=350,bg='black')
ana_bann.place(x=50,y=100)

ana_bann2=tk.Canvas(humm_bird, border=0,width=400,height=350,bg='black')
ana_bann2.place(x=450,y=100)


ana_text_ex=tk.Label(ana_bann,text="Expected ",bg='black',fg='Green')
ana_text_ex.place(x=150,y=10)

ana_text_re=tk.Label(ana_bann2,text="Received ",bg='black',fg='green')
ana_text_re.place(x=150,y=10)
## ## ## ## ## ## ##
def on_open():
    from tkinter.filedialog import askopenfilename

    
    try:
        global filename_
        fileselect=askopenfilename(filetypes=(('text files', '*.txt'),('PCAP','*.pcap'),('PCAPNG','*.pcapng')))
        print(fileselect)
        filename_=fileselect
    except:
        TypeError 


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
button_report=tk.Button(top_bann,text='Show Report',command=on_show)
button_report.configure(font=(15))
button_report.place(x=415,y=7)

button_packets=tk.Button(top_bann,text='Show Packets',command=on_show,disabledforeground="black")
button_packets.configure(font=(15))
button_packets.place(x=560,y=7)


## TOP BANNER ENDS ##

## Status BAR ##


## Status BAR Ends ##

humm_bird.mainloop()