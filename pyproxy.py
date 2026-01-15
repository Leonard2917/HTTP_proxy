import socket
import threading
import socketserver
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext
import re
import os
import gzip
import io
from concurrent.futures import ThreadPoolExecutor

# --- CONFIGURARE ---
PROXY_HOST = '0.0.0.0'
PROXY_PORT = 8888
BUFFER_SIZE = 65536  # Buffer mai mare pentru performanta

# Cozi de comunicare
log_queue = queue.Queue() # Pentru a trimite mesaje text catre GUI

# ===========================
# === 1. MODEL & SETTINGS ===
# ===========================
class ProxySettings:
    """
    Singleton care tine minte configuratiile bifate in GUI.
    Orice modificare in GUI se reflecta aici, iar Serverul citeste de aici.
    """
    def __init__(self):
        # Request Settings
        self.spoof_user_agent = False
        self.selected_user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
        self.strip_cookies = False
        
        # Response Settings
        self.rewrite_https = False
        self.censor_enabled = False
        self.censor_word_target = ""
        self.censor_word_replace = "****"
        self.block_images = False
        self.block_images = False
        self.inject_banner = True
        self.blocked_domains = ""

    # User Agents predefiniti
    USER_AGENTS = {
        "iPhone Mobile": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Google Bot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Hacker Console (Curl)": "curl/7.64.1",
        "Windows 98 (Ancient)": "Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)"
    }

global_settings = ProxySettings()

# ===========================
# === 2. SERVICE (Process Management & IPC) ===
# ===========================
import subprocess
import signal
import json
import socket

CPP_PROXY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cpp", "proxy_engine")
if not os.path.exists(CPP_PROXY_PATH):
    # Daca rulam din root, poate calea e diferita
    CPP_PROXY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "HTTP_proxy", "cpp", "proxy_engine")

proxy_process = None

def start_cpp_backend():
    global proxy_process
    try:
        if not os.path.exists(CPP_PROXY_PATH):
            log_queue.put("[ERROR] Executabilul C++ nu a fost gasit!")
            log_queue.put(f"Cale cautata: {CPP_PROXY_PATH}")
            return

        # Start C++ process
        # Use simple Popen without setsid to avoid complex process group issues in simple environments, 
        # or handle properly. For now we trust simple execution.
        proxy_process = subprocess.Popen([CPP_PROXY_PATH, str(PROXY_PORT)], preexec_fn=os.setsid)
        log_queue.put(f"[SYSTEM] Backend C++ pornit (PID: {proxy_process.pid})")
        
        # Give it a moment to start listening
        import time
        time.sleep(0.5)
        
        # Send initial settings
        send_settings_to_cpp()
        
    except Exception as e:
        log_queue.put(f"[ERROR] Nu s-a putut porni C++: {e}")

def stop_cpp_backend():
    global proxy_process
    if proxy_process:
        try:
            os.killpg(os.getpgid(proxy_process.pid), signal.SIGTERM)
            log_queue.put("[SYSTEM] Backend C++ oprit.")
        except:
            pass
        proxy_process = None

def send_settings_to_cpp():
    try:
        settings_dict = {
            "spoof_user_agent": str(global_settings.spoof_user_agent).lower(),
            "selected_user_agent": global_settings.selected_user_agent,
            "strip_cookies": str(global_settings.strip_cookies).lower(),
            "rewrite_https": str(global_settings.rewrite_https).lower(),
            "censor_enabled": str(global_settings.censor_enabled).lower(),
            "censor_word_target": global_settings.censor_word_target,
            "censor_word_replace": global_settings.censor_word_replace,
            "block_images": str(global_settings.block_images).lower(),
            "inject_banner": str(global_settings.inject_banner).lower(),
            "blocked_domains": global_settings.blocked_domains
        }
        
        json_payload = json.dumps(settings_dict) 
        
        # Connect to C++ Control Port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect(('127.0.0.1', 8889))
        sock.sendall(json_payload.encode('utf-8'))
        sock.close()
        
    except Exception as e:
        # log_queue.put(f"[WARN] Nu s-au putut trimite setarile: {e}")
        pass

# --- UDP LOG RECEIVER ---
def start_log_receiver():
    udp_ip = "127.0.0.1"
    udp_port = 8890
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((udp_ip, udp_port))
    sock.settimeout(1.0)
    
    log_queue.put(f"[SYSTEM] Log Receiver asculta pe {udp_ip}:{udp_port}")
    
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            msg = data.decode('utf-8').strip()
            log_queue.put(msg)
        except socket.timeout:
            continue
        except OSError:
            break


# ===========================
# === 3. GUI (CYBERPUNK / MODERN STYLE) - FIXED ===
# ===========================
class AdvancedProxyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"🛡️ SECURE PROXY SUITE v3.0 - Port {PROXY_PORT}")
        self.root.geometry("1000x700")
        
        # --- CULORI & STILURI (THEME CONFIG) ---
        self.colors = {
            "bg": "#1e1e1e",           # Dark Grey
            "fg": "#ffffff",           # White
            "accent": "#007acc",       # Blue VS Code
            "success": "#4caf50",      # Green
            "warning": "#ff9800",      # Orange
            "danger": "#f44336",       # Red
            "panel": "#252526",        # Lighter Grey
            "terminal_bg": "#000000",  # Black
            "terminal_fg": "#00ff41"   # Matrix Green
        }

        # Configurare Stiluri TTK
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Configurare culori generale
        self.root.configure(bg=self.colors["bg"])
        
        # Stil Frame-uri
        self.style.configure("TFrame", background=self.colors["bg"])
        self.style.configure("Card.TFrame", background=self.colors["panel"], relief="flat")
        
        # Stil Label-uri
        self.style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["fg"], font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground=self.colors["accent"])
        self.style.configure("SubHeader.TLabel", font=("Segoe UI", 12, "bold"), foreground=self.colors["warning"])
        
        # Stil Checkbutton
        self.style.configure("TCheckbutton", background=self.colors["panel"], foreground=self.colors["fg"], font=("Segoe UI", 10))
        self.style.map("TCheckbutton", background=[('active', self.colors["panel"])])

        # Stil Notebook (Tab-uri)
        self.style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        self.style.configure("TNotebook.Tab", background=self.colors["panel"], foreground=self.colors["fg"], padding=[15, 5], font=("Segoe UI", 10, "bold"))
        self.style.map("TNotebook.Tab", background=[("selected", self.colors["accent"])], foreground=[("selected", "white")])

        # --- LAYOUT PRINCIPAL ---
        
        # 1. Header
        header_frame = ttk.Frame(root)
        header_frame.pack(fill="x", padx=20, pady=15)
        
        ttk.Label(header_frame, text="🔒 HTTP TRAFFIC INTERCEPTOR", style="Header.TLabel").pack(side="left")
        self.lbl_status = tk.Label(header_frame, text="● ONLINE", bg=self.colors["bg"], fg=self.colors["success"], font=("Segoe UI", 10, "bold"))
        self.lbl_status.pack(side="right")

        # 2. Tabs
        self.tab_control = ttk.Notebook(root)
        self.tab_monitor = ttk.Frame(self.tab_control)
        self.tab_req = ttk.Frame(self.tab_control)
        self.tab_res = ttk.Frame(self.tab_control)
        
        self.tab_control.add(self.tab_monitor, text='📡 MONITOR TRAFIC')
        self.tab_control.add(self.tab_req, text='📤 REGULI REQUEST')
        self.tab_control.add(self.tab_res, text='📥 REGULI RESPONSE')
        self.tab_control.pack(expand=1, fill="both", padx=10, pady=5)

        self._setup_monitor_tab()
        self._setup_request_tab()
        self._setup_response_tab()

        # Footer
        footer = tk.Label(root, text="Proiect Sisteme de Operare | Student Demo Build", bg=self.colors["bg"], fg="#666666", font=("Segoe UI", 8))
        footer.pack(side="bottom", pady=5)

        # Timer Update
        self.root.after(100, self.update_logs)

    def _create_card(self, parent, title):
        """ Helper pentru a crea un chenar frumos (Card) """
        frame = ttk.Frame(parent, style="Card.TFrame", padding=15)
        frame.pack(fill="x", padx=20, pady=10)
        # FIX: Am inlocuit mb=10 cu pady=(0, 10)
        ttk.Label(frame, text=title, style="SubHeader.TLabel", background=self.colors["panel"]).pack(anchor="w", pady=(0, 10))
        return frame

    def _setup_monitor_tab(self):
        # Container principal
        container = ttk.Frame(self.tab_monitor)
        container.pack(fill="both", expand=True, padx=10, pady=10)

        # Log Area (Terminal Style)
        self.log_area = scrolledtext.ScrolledText(
            container, 
            width=100, 
            height=30,
            bg=self.colors["terminal_bg"], 
            fg=self.colors["terminal_fg"],
            font=("Consolas", 10),
            insertbackground="white", 
            relief="flat",
            padx=10, pady=10
        )
        self.log_area.pack(fill="both", expand=True)
        
        self.log_area.insert(tk.END, r"""
  _   _   _______   _____    _____  _____   _______   __ __   __
 | | | | |__   __| |  __ \  |  __ \|  __ \ /  __   \  \ \ / /
 | |_| |    | |    | |__) | | |__) | |__) ||  |  |  |   \ V / 
 |  _  |    | |    |  ___/  |  ___/|  _  / |  |  |  |    > <  
 | | | |    | |    | |      | |    | | \ \ |  |__|  |   / . \ 
 |_| |_|    |_|    |_|      |_|    |_|  \_\ \_______/  /_/ \_\
                                                              
 SYSTEM READY... LISTENING ON PORT """ + str(PROXY_PORT) + "\n\n")

        # Butoane control log
        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill="x", pady=5)
        
        btn_clear = tk.Button(btn_frame, text="STERGE LOGURI", bg="#444", fg="white", command=lambda: self.log_area.delete('1.0', tk.END))
        btn_clear.pack(side="right")

    def _setup_request_tab(self):
        # Card 1: Identitate
        card_id = self._create_card(self.tab_req, "🎭 Identitate & Privacy")
        
        self.var_spoof = tk.BooleanVar()
        cb = ttk.Checkbutton(card_id, text="Activează User-Agent Spoofing (Ascunde Browserul Real)", variable=self.var_spoof, command=self.sync_settings)
        cb.pack(anchor="w", pady=5)
        
        frame_combo = ttk.Frame(card_id, style="Card.TFrame")
        frame_combo.pack(fill="x", pady=5)
        ttk.Label(frame_combo, text="Identitate Falsă:", background=self.colors["panel"]).pack(side="left")
        
        self.combo_ua = ttk.Combobox(frame_combo, values=list(global_settings.USER_AGENTS.keys()), width=40, state="readonly")
        self.combo_ua.current(0)
        self.combo_ua.pack(side="left", padx=10)
        self.combo_ua.bind("<<ComboboxSelected>>", self.sync_settings)

        # Card 2: Security
        card_sec = self._create_card(self.tab_req, "🍪 Securitate")
        
        self.var_cookies = tk.BooleanVar()
        ttk.Checkbutton(card_sec, text="Strip Cookies (Navigare Anonimă - Serverul nu te reține)", variable=self.var_cookies, command=self.sync_settings).pack(anchor="w")

        # Card 3: Firewall (Blocked Domains)
        card_fw = self._create_card(self.tab_req, "🔥 Firewall / Blocare Domenii")
        ttk.Label(card_fw, text="Domenii interzise (separate prin virgulă):", background=self.colors["panel"]).pack(anchor="w")
        
        self.txt_blocked = tk.Text(card_fw, height=3, bg="#333", fg="white", insertbackground="white", font=("Consolas", 10))
        self.txt_blocked.pack(fill="x", pady=5)
        self.txt_blocked.bind("<KeyRelease>", lambda e: self.sync_settings())

    def _setup_response_tab(self):
        # Card 1: Vizual
        card_viz = self._create_card(self.tab_res, "👁️ Modificări Vizuale")
        
        self.var_banner = tk.BooleanVar(value=True)
        ttk.Checkbutton(card_viz, text="Injectează Banner Avertizare (Man-in-the-Middle)", variable=self.var_banner, command=self.sync_settings).pack(anchor="w", pady=2)
        
        self.var_imgs = tk.BooleanVar()
        ttk.Checkbutton(card_viz, text="Blochează Imaginile (Economisire Bandwidth)", variable=self.var_imgs, command=self.sync_settings).pack(anchor="w", pady=2)

        # Card 2: Securitate
        card_sec = self._create_card(self.tab_res, "🔐 Securitate & Link-uri")
        
        self.var_https = tk.BooleanVar()
        ttk.Checkbutton(card_sec, text="Force HTTPS Rewrite (Transformă linkurile http:// în https://)", variable=self.var_https, command=self.sync_settings).pack(anchor="w")

        # Card 3: Cenzura
        card_cens = self._create_card(self.tab_res, "🚫 Cenzură Conținut")
        
        self.var_censor = tk.BooleanVar()
        ttk.Checkbutton(card_cens, text="Activează Filtru Cuvinte", variable=self.var_censor, command=self.sync_settings).pack(anchor="w", pady=5)
        
        f_inputs = ttk.Frame(card_cens, style="Card.TFrame")
        f_inputs.pack(fill="x", pady=5)
        
        ttk.Label(f_inputs, text="Cuvânt Tintă:", background=self.colors["panel"]).grid(row=0, column=0, padx=5)
        self.entry_target = tk.Entry(f_inputs, bg="#333", fg="white", insertbackground="white")
        self.entry_target.grid(row=0, column=1, padx=5)
        self.entry_target.insert(0, "Python")
        self.entry_target.bind("<KeyRelease>", lambda e: self.sync_settings())

        ttk.Label(f_inputs, text="Înlocuiește cu:", background=self.colors["panel"]).grid(row=0, column=2, padx=5)
        self.entry_replace = tk.Entry(f_inputs, bg="#333", fg="white", insertbackground="white")
        self.entry_replace.grid(row=0, column=3, padx=5)
        self.entry_replace.insert(0, "SNAKE")
        self.entry_replace.bind("<KeyRelease>", lambda e: self.sync_settings())

    def sync_settings(self, event=None):
        # Request
        global_settings.spoof_user_agent = self.var_spoof.get()
        global_settings.selected_user_agent = self.combo_ua.get()
        global_settings.strip_cookies = self.var_cookies.get()
        
        # Response
        global_settings.inject_banner = self.var_banner.get()
        global_settings.rewrite_https = self.var_https.get()
        global_settings.block_images = self.var_imgs.get()
        global_settings.censor_enabled = self.var_censor.get()
        global_settings.censor_word_target = self.entry_target.get()
        global_settings.censor_word_target = self.entry_target.get()
        global_settings.censor_word_replace = self.entry_replace.get()
        global_settings.blocked_domains = self.txt_blocked.get("1.0", tk.END).strip().replace("\n", "|").replace(",", "|")
        
        # Trimite update catre C++
        threading.Thread(target=send_settings_to_cpp).start()


    def update_logs(self):
        try:
            while True:
                msg = log_queue.get_nowait()
                self.log_area.insert(tk.END, msg + "\n")
                self.log_area.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(100, self.update_logs)

# ===========================
# === MAIN ===
# ===========================
def on_closing():
    stop_cpp_backend()
    os._exit(0)

def start_server_thread():
    # Pornim Receiver de Loguri
    t_log = threading.Thread(target=start_log_receiver)
    t_log.daemon = True
    t_log.start()
    
    # Pornim Procesul C++
    time.sleep(0.5)
    start_cpp_backend()

if __name__ == "__main__":
    import time
    
    # Pornim server services in thread
    t = threading.Thread(target=start_server_thread)
    t.daemon = True
    t.start()
    
    # Pornim GUI
    root = tk.Tk()
    gui = AdvancedProxyGUI(root)
    root.protocol("WM_DELETE_WINDOW", on_closing)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        on_closing()