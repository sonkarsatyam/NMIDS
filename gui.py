import tkinter as tk
from tkinter import ttk
from traffic_stats import stats
from top_talkers import talkers
import threading
import time
from tkinter import messagebox
from sniffer import start_sniffer
from host_discovery import discover_hosts
from portscanner import scan_target
from system_info import get_system_info
import sniffer
root = tk.Tk()
from tkinter import filedialog
import csv
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

alert_history = []
scan_results = []
scan_history = []
scan_start_time = 0

packet_counter = 0

style = ttk.Style()
style.theme_use("default")

style.configure(
    "Dark.Treeview",
    background="#101216",
    foreground="white",
    fieldbackground="#101216",
    borderwidth=0,
    rowheight=28,
    font=("Bahnschrift", 10)
)

style.configure(
    "Dark.Treeview.Heading",
    background="#1b1f26",
    foreground="white",
    font=("Bahnschrift",10,"bold")
)

style.map(
    "Dark.Treeview",
    background=[("selected", "#ff3b3b")],
    foreground=[("selected", "white")]
)

root.title("NMIDS Enterprise")

root.geometry("1920x1080")

root.configure(bg="#0b0d10")

root.state("zoomed")

BG = "#0b0d10"
CARD = "#12161c"
BORDER = "#252a33"

RED = "#ff3b3b"
GREEN = "#00ff88"
CYAN = "#00d9ff"
YELLOW = "#ffd633"
WHITE = "#ffffff"

# =========================
# HEADER
# =========================

header = tk.Frame(
    root,
    bg="#0a0a0a",
    height=80
)

header.pack(fill="x")
header.pack_propagate(False)

logo = tk.Label(
    header,
    text="🛡 NMIDS",
    bg="#0a0a0a",
    fg=RED,
    font=("Segoe UI", 20, "bold")
)

logo.pack(
    side="left",
    padx=20
)

title = tk.Label(
    header,
    text="Network Monitoring & Intrusion Detection System",
    bg="#0a0a0a",
    fg=WHITE,
    font=("Segoe UI", 13)
)

title.pack(
    side="left",
    padx=20
)

status = tk.Label(
    header,
    text="● ONLINE",
    bg="#0a0a0a",
    fg=GREEN,
    font=("Segoe UI", 12, "bold")
)

status.pack(
    side="right",
    padx=25
)

body = tk.Frame(
    root,
    bg=BG
)

body.pack(
    fill="both",
    expand=True,
    padx=15,
    pady=15
)

# =========================
# GRID CONFIGURATION
# =========================

for c in range(12):
    body.grid_columnconfigure(c, weight=1, uniform="col")

body.grid_rowconfigure(0, weight=3)
body.grid_rowconfigure(1, weight=5)
body.grid_rowconfigure(2, weight=3)

# =========================
# CARD FUNCTION
# =========================

def create_card(parent, title, title_color=WHITE):

    outer = tk.Frame(
        parent,
        bg="#090909",
        bd=0
    )

    card = tk.Frame(
        outer,
        bg=CARD,
        highlightbackground=BORDER,
        highlightthickness=1,
        bd=0
    )

    card.pack(
        fill="both",
        expand=True,
        padx=2,
        pady=2
    )

    title_frame = tk.Frame(
        card,
        bg=CARD
    )

    title_frame.pack(
        fill="x",
        padx=18,
        pady=(15,5)
    )

    tk.Label(
        title_frame,
        text=title,
        bg=CARD,
        fg=title_color,
        font=("Bahnschrift",12,"bold")
    ).pack(anchor="w")

    tk.Frame(
        title_frame,
        bg=title_color,
        height=2
    ).pack(
        fill="x",
        pady=(6,0)
    )

    # -------------------------
    # CONTENT FRAME
    # -------------------------

    content = tk.Frame(
        card,
        bg=CARD
    )

    content.pack(
        fill="both",
        expand=True,
        padx=18,
        pady=12
    )

    return outer, card, content
# =========================
# TOP ROW CARDS
# =========================

scanner_outer, scanner_card, scanner_content = create_card(body,"🖥 PORT SCANNER",RED)
status_outer, status_card , status_content = create_card(body, "🎯 SCAN STATUS", RED)
progress_outer, progress_card , progress_content = create_card(body, "🛡 SCAN PROGRESS", RED)
traffic_outer, traffic_card , traffic_content = create_card(body, "📊 TRAFFIC STATISTICS", GREEN)
talkers_outer, talkers_card , talkers_content = create_card(body, "👥 TOP TALKERS", CYAN)
alerts_outer, alerts_card , alerts_content = create_card(body, "⚠ ALERTS", YELLOW)

scanner_outer.grid(row=0, column=0, columnspan=2, padx=8, pady=8, sticky="nsew")
status_outer.grid(row=0, column=2, columnspan=2, padx=8, pady=8, sticky="nsew")
progress_outer.grid(row=0, column=4, columnspan=2, padx=8, pady=8, sticky="nsew")
traffic_outer.grid(row=0, column=6, columnspan=2, padx=8, pady=8, sticky="nsew")
talkers_outer.grid(row=0, column=8, columnspan=2, padx=8, pady=8, sticky="nsew")
alerts_outer.grid(row=0, column=10, columnspan=2, padx=8, pady=8, sticky="nsew")

# =========================
# SCAN STATUS CARD
# =========================


status_label = tk.Label(
    status_content,
    text="Status : Ready",
    bg=CARD,
    fg=GREEN,
    font=("Bahnschrift",11,"bold")
)
status_label.pack(anchor="w", pady=(5,10))

toolbar = tk.Frame(
    header,
    bg=BG
)


toolbar.pack(
    side="right",
    padx=15
)

txt_toolbar_btn = tk.Button(
    toolbar,
    text="📄 TXT",
    bg="#2d313a",
    fg="white",
    relief="flat",
    cursor="hand2",
    font=("Bahnschrift",9)
)

txt_toolbar_btn.pack(
    side="left",
    padx=4
)

csv_toolbar_btn = tk.Button(
    toolbar,
    text="📊 CSV",
    bg="#2d313a",
    fg="white",
    relief="flat",
    cursor="hand2",
    font=("Bahnschrift",9)
)

csv_toolbar_btn.pack(
    side="left",
    padx=4
)

pdf_toolbar_btn = tk.Button(
    toolbar,
    text="📑 PDF",
    bg="#2d313a",
    fg="white",
    relief="flat",
    cursor="hand2",
    font=("Bahnschrift",9)
)

pdf_toolbar_btn.pack(
    side="left",
    padx=4
)


ports_scanned_label = tk.Label(
    status_content,
    text="Ports Scanned : 0",
    bg=CARD,
    fg="white",
    font=("Bahnschrift",10)
)
ports_scanned_label.pack(anchor="w", pady=5)


open_ports_label = tk.Label(
    status_content,
    text="Open Ports : 0",
    bg=CARD,
    fg="white",
    font=("Bahnschrift",10)
)
open_ports_label.pack(anchor="w", pady=5)


scan_time_label = tk.Label(
    status_content,
    text="Elapsed : 0 sec",
    bg=CARD,
    fg=CYAN,
    font=("Bahnschrift",10)
)
scan_time_label.pack(anchor="w", pady=5)

# =========================
# SCAN PROGRESS
# =========================

from tkinter import ttk

progress_percent = tk.Label(
    progress_content,
    text="0%",
    bg=CARD,
    fg="white",
    font=("Bahnschrift",26,"bold")
)

progress_percent.pack(
    pady=(10,15)
)

style.configure(
    "Red.Horizontal.TProgressbar",
    troughcolor="#20252d",
    background="#ff3b3b",
    bordercolor="#20252d",
    lightcolor="#ff3b3b",
    darkcolor="#ff3b3b",
    thickness=14
)

progress_bar = ttk.Progressbar(
    progress_content,
    style="Red.Horizontal.TProgressbar",
    orient="horizontal",
    length=250,
    mode="determinate",
    maximum=100
)

progress_bar.pack()

progress_status = tk.Label(
    progress_content,
    text="Ready",
    bg=CARD,
    fg="#9aa3ad",
    font=("Bahnschrift",10)
)

progress_status.pack(
    pady=12
)

# =========================
# TRAFFIC STATISTICS
# =========================

tcp_label = tk.Label(
    traffic_content,
    text="TCP   : 0",
    bg=CARD,
    fg="#00ff88",
    font=("Bahnschrift", 11)
)
tcp_label.pack(anchor="w", pady=4)

udp_label = tk.Label(
    traffic_content,
    text="UDP   : 0",
    bg=CARD,
    fg="#00ff88",
    font=("Bahnschrift", 11)
)
udp_label.pack(anchor="w", pady=4)

icmp_label = tk.Label(
    traffic_content,
    text="ICMP : 0",
    bg=CARD,
    fg="#00ff88",
    font=("Bahnschrift", 11)
)
icmp_label.pack(anchor="w", pady=4)

arp_label = tk.Label(
    traffic_content,
    text="ARP   : 0",
    bg=CARD,
    fg="#00ff88",
    font=("Bahnschrift", 11)
)
arp_label.pack(anchor="w", pady=4)

# Target IP

tk.Label(
    scanner_content,
    text="Target IP",
    bg=CARD,
    fg=WHITE,
    font=("Bahnschrift", 10)
).pack(anchor="w")

target_entry = tk.Entry(
    scanner_content,
    bg="#0f1115",
    fg="white",
    insertbackground="white",
    relief="flat",
    font=("Bahnschrift", 10)
)

target_entry.pack(
    fill="x",
    pady=(4,10)
)

# Start Port

tk.Label(
    scanner_content,
    text="Start Port",
    bg=CARD,
    fg=WHITE,
    font=("Bahnschrift",10)
).pack(anchor="w")

start_entry = tk.Entry(
    scanner_content,
    bg="#0f1115",
    fg="white",
    insertbackground="white",
    relief="flat"
)

start_entry.pack(
    fill="x",
    pady=(4,10)
)

# End Port

tk.Label(
    scanner_content,
    text="End Port",
    bg=CARD,
    fg=WHITE,
    font=("Bahnschrift",10)
).pack(anchor="w")

end_entry = tk.Entry(
    scanner_content,
    bg="#0f1115",
    fg="white",
    insertbackground="white",
    relief="flat"
)

end_entry.pack(
    fill="x",
    pady=(4,15)
)

# =========================
# START SCAN BUTTON
# =========================

scan_btn = tk.Button(
    scanner_content,
    text="START SCAN",
    bg="#d32f2f",
    fg="white",
    activebackground="#ff3b3b",
    activeforeground="white",
    relief="flat",
    font=("Segoe UI", 11, "bold"),
    cursor="hand2",
    bd=0
)

scan_btn.pack(
    fill="x",
    pady=(8, 0),
    ipadx=0,
    ipady=10
)


host_outer, host_card , host_content = create_card(body,"🖧 HOST DISCOVERY (ARP)",CYAN)


host_table = ttk.Treeview(
    host_content,
    columns=("IP","MAC"),
    show="headings",
    style="Dark.Treeview",
    height=10
)

def host_selected(event):

    selected = host_table.focus()

    if not selected:
        return

    values = host_table.item(
        selected,
        "values"
    )

    if not values:
        return

    ip = values[0]

    target_entry.delete(
        0,
        tk.END
    )

    target_entry.insert(
        0,
        ip
    )

discover_btn = tk.Button(
    host_content,
    text="DISCOVER HOSTS",
    bg="#00bcd4",
    fg="white",
    relief="flat",
    font=("Bahnschrift", 10, "bold"),
    cursor="hand2"
)

discover_btn.pack(
    fill="x",
    pady=10
)

discover_btn.config(

    command=lambda:

    threading.Thread(
        target=discover_network,
        daemon=True
    ).start()

)

host_table.heading("IP", text="IP Address")
host_table.heading("MAC", text="MAC Address")

host_table.column("IP", width=180, anchor="center")
host_table.column("MAC", width=180, anchor="center")

host_table.tag_configure(
    "odd",
    background="#111318"
)

host_table.tag_configure(
    "even",
    background="#171b22"
)


host_table.pack(
    fill="both",
    expand=True,
    pady=(5,0)
)

host_table.bind(
    "<Double-1>",
    host_selected
)

ports_outer, ports_card , ports_content = create_card(body,"📋 OPEN PORTS & SERVICES",RED)

# =========================
# OPEN PORTS
# =========================

results_box = ttk.Treeview(
    ports_content,
    columns=(
        "Port",
        "Protocol",
        "Service",
        "State",
        "Risk"
    ),
    show="headings",
    style="Dark.Treeview"
)

results_box.heading(
    "Port",
    text="Port"
)

results_box.heading(
    "Protocol",
    text="Protocol"
)

results_box.heading(
    "Service",
    text="Service"
)

results_box.heading(
    "State",
    text="State"
)

results_box.heading(
    "Risk",
    text="Risk"
)

results_box.column(
    "Port",
    width=60,
    anchor="center"
)

results_box.column(
    "Protocol",
    width=70,
    anchor="center"
)

results_box.column(
    "Service",
    width=220
)

results_box.column(
    "State",
    width=80,
    anchor="center"
)

results_box.column(
    "Risk",
    width=80,
    anchor="center"
)

results_box.pack(
    fill="both",
    expand=True
)

results_box.tag_configure(
    "critical",
    foreground="#ff4040"
)

results_box.tag_configure(
    "high",
    foreground="#ff8800"
)

results_box.tag_configure(
    "medium",
    foreground="#ffd700"
)

results_box.tag_configure(
    "low",
    foreground="#00ff66"
)

results_box.tag_configure(
    "critical",
    foreground="#ff3b3b"
)

results_box.tag_configure(
    "high",
    foreground="#ff9800"
)

results_box.tag_configure(
    "medium",
    foreground="#ffd633"
)

results_box.tag_configure(
    "low",
    foreground="#00ff88"
)

packet_outer, packet_card , packet_content = create_card(body,"📡 PACKET MONITOR (Live)",RED)


host_outer.grid(
    row=1,
    column=0,
    columnspan=3,
    padx=8,
    pady=8,
    sticky="nsew"
)

ports_outer.grid(
    row=1,
    column=3,
    columnspan=5,
    padx=8,
    pady=8,
    sticky="nsew"
)

packet_outer.grid(
    row=1,
    column=8,
    columnspan=4,
    padx=8,
    pady=8,
    sticky="nsew"
)

# =========================
# PACKET MONITOR
# =========================

packet_box = tk.Listbox(
    packet_content,
    bg="#0f1115",
    fg="#00ff88",
    relief="flat",
    borderwidth=0,
    font=("Consolas", 10)
)

packet_box.pack(
    fill="both",
    expand=True
)

# =========================
# BOTTOM ROW
# =========================

history_outer, history_card , history_content = create_card(body,"🕘 SCAN HISTORY","#b266ff")
# =========================
# SCAN HISTORY
# =========================

history_box = tk.Listbox(
    history_content,
    bg="#101216",
    fg="white",
    selectbackground="#ff4040",
    selectforeground="white",
    relief="flat",
    bd=0,
    font=("Consolas", 10)
)

history_box.pack(
    fill="both",
    expand=True
)


graph_outer, graph_card , graph_content = create_card(body,"📈 LIVE TRAFFIC GRAPH","#ffd633")

graph_canvas = tk.Canvas(
    graph_content,
    width=420,
    height=170,
    bg="#101216",
    highlightthickness=0
)

graph_canvas.pack(
    fill="both",
    expand=True
)

traffic_history = []

def draw_graph_grid():

    graph_canvas.delete("grid")

    width = graph_canvas.winfo_width()
    height = graph_canvas.winfo_height()

    # Horizontal Lines
    for y in range(0, height, 30):

        graph_canvas.create_line(
            0,
            y,
            width,
            y,
            fill="#20242d",
            tags="grid"
        )
        
def draw_graph():

    graph_canvas.delete("graph")

    width = graph_canvas.winfo_width()
    height = graph_canvas.winfo_height()

    if len(traffic_history) < 2:
        return

    max_value = max(traffic_history)

    if max_value == 0:
        max_value = 1

    step = width / (len(traffic_history) - 1)

    points = []

    for i, value in enumerate(traffic_history):

        x = i * step

        y = height - ((value / max_value) * (height - 20))

        points.extend([x, y])

    graph_canvas.create_line(
        points,
        fill="#00ff66",
        width=3,
        smooth=True,
        tags="graph"
    )

def update_live_graph():

    global packet_counter

    traffic_history.append(
    sniffer.graph_packet_counter
)

    sniffer.graph_packet_counter = 0

    if len(traffic_history) > 60:
        traffic_history.pop(0)

    draw_graph()

    root.after(
        1000,
        update_live_graph
    )


system_outer, system_card , system_content = create_card(body,"💻 SYSTEM INFO",CYAN)

# =========================
# SYSTEM INFO
# =========================
left_frame = tk.Frame(
    system_content,
    bg=CARD
)

left_frame.pack(
    side="left",
    fill="both",
    expand=True
)

right_frame = tk.Frame(
    system_content,
    bg=CARD
)

right_frame.pack(
    side="right",
    padx=10,
    anchor="n"
)

hostname_label = tk.Label(
    left_frame,
    text="Hostname :",
    bg=CARD,
    fg="white",
    font=("Bahnschrift",10)
)

hostname_label.pack(anchor="w", pady=3)

os_label = tk.Label(
    left_frame,
    text="OS :",
    bg=CARD,
    fg="white",
    font=("Bahnschrift",10)
)

os_label.pack(anchor="w", pady=3)

cpu_label = tk.Label(
    left_frame,
    text="CPU :",
    bg=CARD,
    fg="white",
    font=("Bahnschrift",10)
)

cpu_label.pack(anchor="w", pady=3)

ram_label = tk.Label(
    left_frame,
    text="RAM :",
    bg=CARD,
    fg="white",
    font=("Bahnschrift",10)
)

ram_label.pack(anchor="w", pady=3)

ip_label = tk.Label(
    left_frame,
    text="IP :",
    bg=CARD,
    fg="white",
    font=("Bahnschrift",10)
)

ip_label.pack(anchor="w", pady=3)

tk.Label(
    right_frame,
    text="Risk Score",
    bg=CARD,
    fg="#00e5ff",
    font=("Bahnschrift",10,"bold")
).pack()

risk_score = tk.Label(
    right_frame,
    text="0",
    bg=CARD,
    fg="#00ff88",
    font=("Bahnschrift",26,"bold")
)

risk_score.pack()

risk_level = tk.Label(
    right_frame,
    text="SAFE",
    bg=CARD,
    fg="#00ff88",
    font=("Bahnschrift",11,"bold")
)

risk_level.pack()



sniffer_outer, sniffer_card , sniffer_content = create_card(body,"🛰 SNIFFER CONTROL",GREEN)

# =========================
# SNIFFER CONTROL
# =========================

sniffer_status = tk.Label(
    sniffer_content,
    text="Status : STOPPED",
    bg=CARD,
    fg="#ff5555",
    font=("Bahnschrift",11,"bold")
)

sniffer_status.pack(
    anchor="w",
    pady=(0,10)
)

start_sniffer_btn = tk.Button(
    sniffer_content,
    text="START SNIFFER",
    bg="#00c853",
    fg="white",
    relief="flat",
    font=("Bahnschrift",10,"bold"),
    cursor="hand2",
    command=lambda: threading.Thread(
        target=run_sniffer,
        daemon=True
    ).start()
)

start_sniffer_btn.pack(
    fill="x",
    pady=(0,8)
)

start_sniffer_btn.config(

    command=lambda:

    threading.Thread(
        target=run_sniffer,
        daemon=True
    ).start()

)

history_outer.grid(
    row=2,
    column=0,
    columnspan=4,
    padx=8,
    pady=8,
    sticky="nsew"
)

graph_outer.grid(
    row=2,
    column=4,
    columnspan=3,
    padx=8,
    pady=8,
    sticky="nsew"
)

system_outer.grid(
    row=2,
    column=7,
    columnspan=3,
    padx=8,
    pady=8,
    sticky="nsew"
)

sniffer_outer.grid(
    row=2,
    column=10,
    columnspan=2,
    padx=8,
    pady=8,
    sticky="nsew"
)

# =========================
# ALERTS PANEL
# =========================

alerts_box = tk.Listbox(
    alerts_content,
    bg="#0f1115",
    fg="#ffd633",
    relief="flat",
    borderwidth=0,
    font=("Consolas", 10)
)

alerts_box.pack(
    fill="both",
    expand=True
)

# =========================
# TOP TALKERS PANEL
# =========================

talkers_box = tk.Listbox(
    talkers_content,
    bg="#0f1115",
    fg="#00d9ff",
    relief="flat",
    borderwidth=0,
    font=("Consolas",10)
)

talkers_box.pack(
    fill="both",
    expand=True
)

# =========================
# FOOTER
# =========================

footer = tk.Frame(
    root,
    bg="#0a0a0a",
    height=32
)

footer.pack(
    fill="x",
    side="bottom"
)

footer.pack_propagate(False)

footer_label = tk.Label(
    footer,
    text="NMIDS Enterprise Edition   |   Status: Ready",
    bg="#0a0a0a",
    fg="#aaaaaa",
    font=("Bahnschrift", 10)
)

footer_label.pack(
    side="left",
    padx=20
)

def update_traffic_stats():

    tcp_label.config(
        text=f"TCP   : {stats['TCP']}"
    )

    udp_label.config(
        text=f"UDP   : {stats['UDP']}"
    )

    icmp_label.config(
        text=f"ICMP : {stats['ICMP']}"
    )

    arp_label.config(
        text=f"ARP   : {stats['ARP']}"
    )

    root.after(
        1000,
        update_traffic_stats
    )

def update_talkers():

    talkers_box.delete(
        0,
        tk.END
    )

    sorted_ips = sorted(
        talkers.items(),
        key=lambda x: x[1],
        reverse=True
    )

    for ip,count in sorted_ips[:10]:

        talkers_box.insert(
            tk.END,
            f"{ip}   {count} packets"
        )

    root.after(
        1000,
        update_talkers
    )

def update_hosts(hosts):

    host_table.delete(
        *host_table.get_children()
    )

    for i, (ip, mac) in enumerate(hosts):

        tag = "even" if i % 2 == 0 else "odd"

        host_table.insert(
            "",
            "end",
            values=(ip, mac),
            tags=(tag,)
        )


def discover_network():

    discover_btn.config(
        state="disabled"
    )

    try:

        hosts = discover_hosts()

        root.after(
            0,
            lambda:update_hosts(hosts)
        )

    finally:

        root.after(
            0,
            lambda:discover_btn.config(
                state="normal"
            )
        )

def select_host(event):

    item = host_table.focus()

    if not item:
        return

    values = host_table.item(item)["values"]

    if not values:
        return

    target_entry.delete(0, tk.END)
    target_entry.insert(0, values[0])


def update_results(results):

    global scan_results

    scan_results = results

    # Purane results hatao
    for item in results_box.get_children():
        results_box.delete(item)

    # Risk Mapping
    risk_ports = {
        21: "Medium",
        22: "Low",
        23: "High",
        25: "Medium",
        53: "Low",
        80: "Medium",
        110: "Medium",
        135: "Medium",
        139: "High",
        143: "Medium",
        443: "Low",
        445: "Critical",
        3389: "Critical"
    }

    for port, service, banner in results:

        protocol = "TCP"

        risk = risk_ports.get(port, "Unknown")

        tag = risk.lower()

        results_box.insert(
            "",
            "end",
            values=(
            port,
            protocol,
            service,
            "Open",
            risk
    ),
            tags=(tag,)
)

    open_ports_label.config(
        text=f"Open Ports : {len(results)}"
    )

    status_label.config(
        text="Status : Completed"
    )

    elapsed = round(
        time.time() - scan_start_time,
        2
    )

    scan_time_label.config(
        text=f"Elapsed : {elapsed} sec"
    )

    update_progress(100)

    update_risk_score()

    scan_btn.config(
    text="SCAN AGAIN",
    state="normal",
    bg="#d32f2f"
)
    
def export_txt():

    if not scan_results:

        messagebox.showwarning(
            "Export",
            "No scan results available."
        )

        return

    filename = filedialog.asksaveasfilename(

        defaultextension=".txt",

        filetypes=[
            ("Text File","*.txt")
        ],

        initialfile=f"NMIDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )

    if not filename:

        return

    with open(
        filename,
        "w"
    ) as file:

        file.write(
            "NMIDS ENTERPRISE REPORT\n\n"
        )

        file.write(
            f"Target : {target_entry.get()}\n\n"
        )

        for port, service, banner in scan_results:

            file.write(
                f"{port}/tcp\t{service}\t{banner}\n"
            )

    messagebox.showinfo(
        "Export",
        "TXT Report Exported Successfully."
    )

def export_csv():

    if not scan_results:

        messagebox.showwarning(
            "Export",
            "No scan results available."
        )

        return

    filename = filedialog.asksaveasfilename(

        defaultextension=".csv",

        filetypes=[
            ("CSV File","*.csv")
        ],

        initialfile=f"NMIDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )

    if not filename:

        return

    with open(
        filename,
        "w",
        newline=""
    ) as file:

        writer = csv.writer(file)

        writer.writerow(
            [
                "Port",
                "Protocol",
                "Service",
                "Risk"
            ]
        )

        risk_ports = {
            21:"Medium",
            22:"Low",
            23:"High",
            25:"Medium",
            53:"Low",
            80:"Medium",
            135:"Medium",
            139:"High",
            443:"Low",
            445:"Critical",
            3389:"Critical"
        }

        for port, service, banner in scan_results:

            writer.writerow(

                [
                    port,
                    "TCP",
                    service,
                    risk_ports.get(
                        port,
                        "Unknown"
                    )
                ]
            )

    messagebox.showinfo(

        "Export",

        "CSV Report Exported Successfully."
    )

def export_pdf():

    if not scan_results:

        messagebox.showwarning(
            "Export",
            "No scan results available."
        )

        return

    filename = filedialog.asksaveasfilename(

        defaultextension=".pdf",

        filetypes=[
            ("PDF File","*.pdf")
        ],

        initialfile=f"NMIDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )

    if not filename:
        return

    doc = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph("<b>NMIDS Enterprise Report</b>", styles["Title"])
    )

    story.append(
        Paragraph(f"Target : {target_entry.get()}", styles["Normal"])
    )

    story.append(
        Paragraph(f"Generated : {datetime.now()}", styles["Normal"])
    )

    story.append(
        Paragraph("<br/><b>Open Ports</b>", styles["Heading2"])
    )

    for port, service, banner in scan_results:

        story.append(

            Paragraph(

                f"{port}/TCP - {service}",

                styles["Normal"]

            )

        )

    doc.build(story)

    messagebox.showinfo(

        "Export",

        "PDF Report Exported Successfully."

    )

def update_risk_score():

    port_risk = 0
    syn_risk = 0
    arp_risk = 0
    dns_risk = 0
    malicious_risk = 0

    # Critical Ports
    critical_ports = {
        23: 20,
        135: 10,
        139: 15,
        445: 30,
        3389: 25,
        21: 10,
        25: 10
    }

    for port, service, banner in scan_results:

        port_risk += critical_ports.get(port, 0)

        score = (
        port_risk +
        syn_risk +
        arp_risk +
        dns_risk +
        malicious_risk
)

    # Maximum 100
    score = min(score, 100)

    risk_score.config(
        text=str(score)
    )

    if score < 25:

        risk_level.config(
            text="SAFE",
            fg="#00ff66"
        )

    elif score < 50:

        risk_level.config(
            text="LOW",
            fg="#ffff00"
        )

    elif score < 75:

        risk_level.config(
            text="HIGH",
            fg="#ff9800"
        )

    else:

        risk_level.config(
            text="CRITICAL",
            fg="#ff3b3b"
        )


def update_progress(percent):

    progress_bar["value"] = percent

    progress_percent.config(
        text=f"{percent}%"
    )

    if percent < 100:
        progress_status.config(
            text="Scanning..."
        )
    else:
        progress_status.config(
            text="Completed"
        )

    root.update_idletasks()


def start_scan():

    # progress_bar.configure(value=0)
    # progress_percent.config(text="0%")
    # progress_status.config(text="Scanning...")

    target = target_entry.get().strip()

    if not target:

        messagebox.showerror(
        "Error",
        "Please enter a Target IP."
    )

        return
    
    try:

        start_port = int(start_entry.get())
        end_port = int(end_entry.get())

    except:

        messagebox.showerror(
        "Error",
        "Invalid Port Number."
    )

        return
    
    if start_port > end_port:

        messagebox.showerror(
        "Error",
        "Start Port cannot be greater than End Port."
    )

        return

    if start_port < 1 or end_port > 65535:

        messagebox.showerror(
        "Error",
        "Port range must be between 1 and 65535."
    )

        return

    print("Scan Started")

    global scan_start_time

    scan_start_time = time.time()

    scan_btn.config(
    text="SCANNING...",
    state="disabled",
    bg="#757575"
)

    status_label.config(
        text="Status : Scanning..."
    )

    update_progress(0)

    for item in results_box.get_children():
        results_box.delete(item)

    threading.Thread(
        target=run_scan,
        daemon=True
    ).start()


def run_scan():

    target = target_entry.get().strip()

    try:
        start_port = int(start_entry.get())
        end_port = int(end_entry.get())

    except:

        root.after(
            0,
            lambda: messagebox.showerror(
                "Error",
                "Invalid Ports"
            )
        )

        root.after(
            0,
            lambda: scan_btn.config(
                state="normal"
            )
        )

        return

    print("Target :", target)
    print("Start :", start_port)
    print("End :", end_port)

    results = scan_target(
        target,
        start_port,
        end_port,

        progress_callback=lambda p:
            root.after(
                0,
                lambda percent=p: update_progress(percent)
            ),

        scanned_callback=lambda count:
            root.after(
                0,
                lambda c=count:
                ports_scanned_label.config(
                    text=f"Ports Scanned : {c}"
                )
            )
    )

    print("SCAN RESULTS:", results)

    root.after(
    0,
    lambda: (
        update_results(results),
        add_scan_history(
            target,
            len(results)
        )
    )
)

scan_btn.config(
    command=start_scan
)

def add_alert(alert_text):

    current_time = datetime.now().strftime("%H:%M:%S")

    alert = {
        "time": current_time,
        "text": alert_text,
        "severity": "HIGH"
    }

    alert_history.insert(0, alert)

    alerts_box.insert(
        0,
        f"⚠ {current_time}  {alert_text}"
    )

    if alerts_box.size() > 200:
        alerts_box.delete(200, tk.END)

def add_packet_gui(text):

    packet_box.insert(
        tk.END,
        text
    )

    packet_box.yview(tk.END)

    if packet_box.size() > 500:

        packet_box.delete(
            0
        )

    if (
        "⚠" in text or
        "[HIGH]" in text or
        "Detected" in text
):
        add_alert(text)

def run_sniffer():

    print("RUN SNIFFER CALLED")

    root.after(
    0,
    lambda: sniffer_status.config(
        text="Status : RUNNING",
        fg="#00ff88"
    )
)

    root.after(
    0,
    lambda: start_sniffer_btn.config(
        state="disabled"
    )
)

    root.after(
    0,
    lambda: stop_sniffer_btn.config(
        state="normal"
    )
)

    start_sniffer(

        lambda message:

        root.after(
            0,
            lambda:add_packet_gui(message)
        )

    )

def stop_sniffer_gui():

    sniffer.stop_sniffer()

    sniffer_status.config(
        text="Status : STOPPED",
        fg="#ff5555"
    )

    start_sniffer_btn.config(
        state="normal"
    )

    stop_sniffer_btn.config(
        state="disabled"
    )

def update_system_info():

    info = get_system_info()

    hostname_label.config(
        text=f"Hostname : {info['Hostname']}"
    )

    os_label.config(
        text=f"OS : {info['OS']}"
    )

    cpu_label.config(
        text=f"CPU : {info['CPU']}"
    )

    ram_label.config(
        text=f"RAM : {info['RAM']}"
    )

    ip_label.config(
        text=f"IP : {info['IP']}"
    )

    root.after(
        1000,
        update_system_info
    )

from datetime import datetime


def add_scan_history(target, ports_found):

    current_time = datetime.now().strftime("%H:%M:%S")

    entry = (
        f"{current_time}   "
        f"{target}   "
        f"Open:{ports_found}"
    )

    scan_history.append(entry)

    history_box.insert(
        0,
        entry
    )

def show_alert_details(event):

    selection = alerts_box.curselection()

    if not selection:
        return

    index = selection[0]

    if index >= len(alert_history):
        return

    alert = alert_history[index]

    popup = tk.Toplevel(root)
    popup.title("NMIDS Alert Details")
    popup.geometry("550x420")
    popup.configure(bg="#101216")
    popup.resizable(False, False)

    tk.Label(
        popup,
        text="⚠ ALERT DETAILS",
        bg="#101216",
        fg="#ff4040",
        font=("Bahnschrift",18,"bold")
    ).pack(pady=15)

    tk.Label(
        popup,
        text=f"Time : {alert['time']}",
        bg="#101216",
        fg="white",
        anchor="w",
        font=("Consolas",11)
    ).pack(fill="x", padx=20)

    tk.Label(
        popup,
        text=f"Severity : {alert['severity']}",
        bg="#101216",
        fg="orange",
        anchor="w",
        font=("Consolas",11)
    ).pack(fill="x", padx=20, pady=5)

    tk.Label(
        popup,
        text=f"Message :\n{alert['text']}",
        bg="#101216",
        fg="white",
        justify="left",
        wraplength=500,
        font=("Consolas",11)
    ).pack(fill="x", padx=20, pady=10)


stop_sniffer_btn = tk.Button(
    sniffer_content,
    text="STOP SNIFFER",
    bg="#d32f2f",
    fg="white",
    relief="flat",
    font=("Bahnschrift",10,"bold"),
    cursor="hand2",
    state="disabled",
    command=stop_sniffer_gui
)

stop_sniffer_btn.pack(
    fill="x"
)


update_traffic_stats()
update_talkers()
update_system_info()
root.after(
    300,
    draw_graph_grid
)
txt_toolbar_btn.config(
    command=export_txt
)

csv_toolbar_btn.config(
    command=export_csv
)
alerts_box.bind(
    "<Double-Button-1>",
    show_alert_details
)
update_live_graph()
pdf_toolbar_btn.config(
    command=export_pdf
)
root.mainloop()