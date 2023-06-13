

import tkinter as tk
from PIL import Image, ImageTk
import tkinter.messagebox as mb
import pickle



with open('data_HBD.pkl', 'rb') as f:
    my_object = pickle.load(f)
    print(my_object)
with open('OSPF_info.pkl', 'rb') as f:
    my_object2 = pickle.load(f)
    print(my_object2)


humm_bird=tk.Tk()
humm_bird.geometry('1010x750')
humm_bird.resizable(0,0)
humm_bird.title("HummingBird")

image = Image.open("/Users/priya.saragadam/Downloads/arista_logo.ong.png")
image=image.resize((150,40))
image = ImageTk.PhotoImage(image)
label = tk.Label(humm_bird, image=image)
label.place(x=850,y=0)

##.  TOP BANNER ##

top_bann=tk.Canvas(humm_bird, border=0,width=845,height=40)
top_bann.place(x=0,y=0)

ana1_bann=tk.Canvas(humm_bird, border=0,width=900,height=130,bg='black')
ana1_bann.place(x=50,y=100)

ana1_text=tk.Label(ana1_bann,text=" Start Report Generation",font=("Times New Roman",15),fg='yellow',bg='black')
ana1_text.place(x=10,y=40)

ana2_bann2=tk.Canvas(humm_bird, border=0,width=900,height=130,bg='black')
ana2_bann2.place(x=50,y=260)

ana2_text=tk.Label(ana2_bann2,text=" Not used",font=("Times New Roman",15),fg='red',bg='black')
ana2_text.place(x=10,y=40)

analysis_banner=tk.Canvas(humm_bird,border=0,width=420,height=200,bg='black')
analysis_banner.place(x=50,y=420)

analysis_text=tk.Label(analysis_banner,text="Inference Made",font=('Times New Roman',15),fg='#00FF00',bg='black')
analysis_text.place(x=10,y=10)

ana_text=tk.Label(analysis_banner,text=" Start Report Generation",font=("Times New Roman",13),fg='yellow',bg='black')
ana_text.place(x=10,y=40)

solutions_banner=tk.Canvas(humm_bird,border=0,width=420,height=200,bg='black')
solutions_banner.place(x=500,y=420)

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
    import Main_Program


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
    if my_object2['Analysis']==[]:
        sol_text.configure(text="No errors. All checks passed",font=("Times New Roman",15),justify='left',fg='cyan')                 #Insights
    else:
        final_s=""
        for i in my_object2["Analysis"]:
            final_s+=i
            final_s+='\n'
        sol_text.configure(text=final_s,font=("Times New Roman",15),justify='left')
    if my_object2["Info"]==[]:
        ana_text.configure(text="This interface in the port-channel is active",justify='left',font=("Times New Roman",15),fg='cyan')  #Inference made
    else:
        final_s=""
        for i in my_object2["Info"]:
            final_s+=i
            final_s+='\n'
        ana_text.configure(text=final_s,font=("Times New Roman",15),justify='left')
    if my_object2["Ana_t"]==[]:
        ana1_text.configure(text="No erroneous packets found\nAll packets perfect!",justify='left',font=("Times New Roman",15))   #pcap data
    else:
        final_s=""
        for i in my_object2["Ana_t"]:
            final_s+=i
            final_s+='\n'
        ana1_text.configure(text=final_s,font=("Times New Roman",15),justify='left')


    
    
button_report=tk.Button(top_bann,text='Show Report',command=on_report)
button_report.configure(font=(15))
button_report.place(x=415,y=7)

button_packets=tk.Button(top_bann,text='Show Packets',command=on_show,disabledforeground="black")
button_packets.configure(font=(15))
button_packets.place(x=560,y=7)


## TOP BANNER ENDS ##

## Status BAR ##


## Status BAR Ends ##

humm_bird.mainloop()
