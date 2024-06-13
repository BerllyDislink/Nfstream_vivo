import logging
from nfstream import NFStreamer
from multiprocessing import freeze_support
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import threading
import pandas as pd
import os

captured_flows = []  # Global list to store captured flows
stop_thread = False  # Flag to stop the background thread

def display_flow(flow_data, treeview):
    if treeview.get_children():
        treeview.delete(*treeview.get_children())  # Clear the treeview if it's not empty
    for flow in flow_data:
        treeview.insert("", tk.END, values=flow)  # Display each flow in the treeview

def update_display(window, treeview, streamer):
    global captured_flows, stop_thread
    while not stop_thread:
        for flow in streamer:
            if stop_thread:
                break
            flow_data = (
                flow.src_ip,
                flow.dst_ip,
                flow.src_mac,
                flow.dst_mac,
                flow.src_port,
                flow.dst_port,
                flow.bidirectional_packets,
                flow.bidirectional_bytes,
                flow.application_name,
                flow.application_category_name
            )
            captured_flows.append(flow_data)
            if treeview.winfo_exists():  # Check if the treeview still exists
                treeview.insert("", tk.END, values=flow_data)  # Display each flow in the treeview
            window.update_idletasks()  # Update the tkinter window

def save_csv(filename):
    global captured_flows
    df = pd.DataFrame(captured_flows, columns=[
        "src_ip", "dst_ip", "src_mac", "dst_mac", "src_port", "dst_port",
        "bidirectional_packets", "bidirectional_bytes", "application_name",
        "application_category_name"
    ])
    # Crear la carpeta "data" si no existe
    if not os.path.exists("data"):
        os.makedirs("data")
    # Guardar el DataFrame como archivo CSV en la carpeta "data"
    filepath = os.path.join("data", filename)
    df.to_csv(filepath, index=False)
    print(f"DataFrame guardado como archivo CSV en '{filepath}'")

def convert_to_dataframe(entry):
    filename = entry.get()
    save_csv(f"{filename}.csv")

def validate_source(source):
    try:
        # Try to create a streamer to validate the source
        streamer = NFStreamer(
            source=source,
            promiscuous_mode=True,
            snapshot_length=100,  # Maximum packet size to capture
            idle_timeout=10,  # Flows idle for this many seconds will be expired
            active_timeout=1800  # Flows active for this many seconds will be expired
        )
        return streamer
    except Exception as e:
        logging.error(f"Validation error: {e}")
        return None

def start_main_window(streamer):
    global stop_thread
    # Initialize ttkbootstrap window
    window = ttk.Window(themename="cosmo")
    window.title("Flujo de paquetes NFSTREAM")
    window.geometry("1200x600")
    window.columnconfigure(0, weight=1)  # Allow the first column to scale with the window size

    style = ttk.Style()
    style.configure('Treeview', 
                    background='#dbfde7', 
                    foreground='black', 
                    rowheight=25, 
                    fieldbackground='#dbfde7', 
                    font=("Tw Cen MT",10))
    style.map('Treeview', 
              background=[('selected', '#13823c')])

    # Apply rounded style to entry and button
    style.configure('TEntry', 
                    padding=5, 
                    relief="flat", 
                    borderwidth=0, 
                    background='#bcbabf',
                    font=("Tw Cen MT", 10))
    style.configure('TButton', 
                    padding=10, 
                    relief="flat", 
                    borderwidth=0, 
                    background='#2489ec', 
                    foreground='white', 
                    font=("Tw Cen MT", 10))

    treeview = ttk.Treeview(window, style='Treeview')
    treeview["columns"] = ("src_ip", "dst_ip", "src_mac", "dst_mac", "src_port", "dst_port", "bidirectional_packets", "bidirectional_bytes", "application_name", "application_category_name")  # Define the columns
    treeview.column("#0", width=0, stretch=tk.NO)
    treeview.column("src_ip", width=150)
    treeview.column("dst_ip", width=150)
    treeview.column("src_mac", width=150)
    treeview.column("dst_mac", width=150)
    treeview.column("src_port", width=100)
    treeview.column("dst_port", width=100)
    treeview.column("bidirectional_packets", width=150)
    treeview.column("bidirectional_bytes", width=150)
    treeview.column("application_name", width=200)
    treeview.column("application_category_name", width=200)
    
    treeview.heading("#0", text="")
    treeview.heading("src_ip", text="Source IP")
    treeview.heading("dst_ip", text="Destination IP")
    treeview.heading("src_mac", text="Source MAC")
    treeview.heading("dst_mac", text="Destination MAC")
    treeview.heading("src_port", text="Source Port")
    treeview.heading("dst_port", text="Destination Port")
    treeview.heading("bidirectional_packets", text="Bidirectional Packets")
    treeview.heading("bidirectional_bytes", text="Bidirectional Bytes")
    treeview.heading("application_name", text="Application Name")
    treeview.heading("application_category_name", text="Application Category")
    
    treeview.pack(fill=tk.BOTH, expand=True)  # Fill and expand the treeview widget

    # Frame to hold the entry and button
    input_frame = ttk.Frame(window, padding=5, bootstyle="secondary", relief="raised", borderwidth=2)
    input_frame.pack(pady=5)

    # Entry for filename
    filename_entry = ttk.Entry(input_frame, style='TEntry')
    filename_entry.pack(side=tk.LEFT, padx=5)

    # Button to convert captured flows to DataFrame
    convert_button = ttk.Button(input_frame, text="Crear CSV", style='TButton', command=lambda: convert_to_dataframe(filename_entry))
    convert_button.pack(side=tk.LEFT, padx=5)

    def on_close():
        global stop_thread
        stop_thread = True
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", on_close)

    thread = threading.Thread(target=update_display, args=(window, treeview, streamer))
    thread.daemon = True
    thread.start()
    
    window.mainloop()

def main():
    logging.basicConfig(level=logging.INFO)

    def on_submit():
        source = source_entry.get()
        streamer = validate_source(source)
        if streamer:
            root.destroy()
            start_main_window(streamer)
        else:
            error_label.config(text="Error: Origen inaccesible o no válido", foreground="red")

    # Initial window to get the source
    root = tk.Tk()
    root.title("Configurar origen de NFSTREAM")
    root.geometry("400x200")
    root.columnconfigure(0, weight=1)
    root.columnconfigure(1, weight=2)

    ttk.Label(root, text="Ingrese el origen:").grid(column=0, row=0, padx=5, pady=5)
    source_entry = ttk.Entry(root)
    source_entry.grid(column=1, row=0, padx=5, pady=5)

    submit_button = ttk.Button(root, text="Iniciar", command=on_submit)
    submit_button.grid(column=1, row=1, padx=5, pady=5)

    error_label = ttk.Label(root, text="")
    error_label.grid(column=1, row=2, padx=5, pady=5)

    root.mainloop()

if __name__ == '__main__':
    freeze_support()
    main()
