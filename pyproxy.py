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
        self.inject_banner = True

    # User Agents predefiniti
    USER_AGENTS = {
        "iPhone Mobile": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Google Bot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Hacker Console (Curl)": "curl/7.64.1",
        "Windows 98 (Ancient)": "Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)"
    }

global_settings = ProxySettings()

# ===========================
# === 2. SERVICE (Backend Logic) ===
# ===========================
# Adaugam un dictionar global pentru a tine minte IP-urile
# --- DICTIONAR GLOBAL PENTRU CACHE (Daca nu il ai deja pus sus) ---
DNS_CACHE = {}

class AdvancedProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        browser_socket = self.request
        remote_socket = None
        
        # 0. Aflam numele Thread-ului curent
        # Python le numeste automat Thread-1, Thread-2 etc.
        t_name = threading.current_thread().name
        # Curatam numele lung dat de Python Executor
        if "ThreadPoolExecutor" in t_name:
            # Extragem doar numarul final (ex: "ThreadPoolExecutor-0_1" -> "POOL-1")
            parts = t_name.split("_")
            t_id = "POOL-" + parts[-1]
        else:
            t_id = t_name

        try:
            # 1. Citim rapid
            browser_socket.settimeout(2.0)
            try:
                request_data = browser_socket.recv(BUFFER_SIZE)
                if not request_data: return
            except: return

            # 2. Parsam Host-ul
            host, port = self._extract_host_port(request_data)
            if not host: return
            
            # --- LOGARE CU THREAD ID ---
            first_line = request_data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
            
            # Verificam daca e fisier static ca sa nu umplem consola, 
            # DAR lasam cateva ca sa se vada ca lucreaza thread-urile
            is_static = any(ext in first_line for ext in [".css", ".js", ".woff"])
            
            # Logam HTML-ul si imaginile (ca sa vezi thread-uri diferite la poze)
            if not is_static:
                 # AICI E MODIFICAREA: Adaugam [{t_id}] la inceput
                 log_queue.put(f"[{t_id}] [REQ] {first_line[:60]}...")

            # 3. Modificam Cererea
            final_request_data = self._modify_request(request_data)

            # --- DNS CACHE ---
            cache_key = (host, port)
            if cache_key in DNS_CACHE:
                remote_address = DNS_CACHE[cache_key]
            else:
                try:
                    remote_ip = socket.gethostbyname(host)
                    remote_address = (remote_ip, port)
                    DNS_CACHE[cache_key] = remote_address
                except:
                    return 

            # 4. Conectare la Server
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.settimeout(5.0) 
            remote_socket.connect(remote_address)
            remote_socket.sendall(final_request_data)

            # 5. STREAMING vs BUFFERING
            remote_socket.settimeout(3.0)
            
            initial_chunk = remote_socket.recv(BUFFER_SIZE)
            if not initial_chunk: return

            is_html = False
            if b"Content-Type: text/html" in initial_chunk:
                is_html = True

            # CAZ A: STATIC FILES (Viteza Maxima - Poze, etc)
            if not is_html:
                browser_socket.sendall(initial_chunk)
                while True:
                    try:
                        chunk = remote_socket.recv(BUFFER_SIZE)
                        if not chunk: break
                        browser_socket.sendall(chunk)
                    except socket.timeout: break
                
                # Optional: Logam si cand termina un fisier static mare, ca sa vezi Thread-ul
                if ".png" in first_line or ".jpg" in first_line:
                    # log_queue.put(f"[{t_id}] [STREAM] Imagine transferata rapid.")
                    pass
            
            # CAZ B: HTML (Modificare)
            else:
                response_buffer = initial_chunk
                while True:
                    try:
                        chunk = remote_socket.recv(BUFFER_SIZE)
                        if not chunk: break
                        response_buffer += chunk
                    except socket.timeout: break
                
                final_response = self._modify_response(response_buffer)
                browser_socket.sendall(final_response)
                
                # AICI E MODIFICAREA: Logam succesul cu ID-ul thread-ului
                log_queue.put(f"[{t_id}] [FILTER] HTML injectat & trimis ({len(final_response)} bytes)")

        except Exception:
            pass
        finally:
            if remote_socket: remote_socket.close()
            browser_socket.close()

    # --- RESTUL METODELOR RAMAN EXACT LA FEL (NU LE STERGE) ---
    def _extract_host_port(self, data):
        data_str = data.decode('utf-8', errors='ignore')
        host = None
        port = 80
        match = re.search(r'Host:\s*([^\r\n]+)', data_str, re.IGNORECASE)
        if match:
            host_part = match.group(1).strip()
            if ':' in host_part:
                h, p = host_part.split(':')
                return h, int(p)
            return host_part, 80
        return None, 80

    def _modify_request(self, data):
        try:
            data_str = data.decode('utf-8', errors='ignore')
            data_str = re.sub(r'Connection: keep-alive', 'Connection: close', data_str, flags=re.IGNORECASE)
            data_str = re.sub(r'Accept-Encoding:.*?\r\n', '', data_str, flags=re.IGNORECASE)
            
            if global_settings.spoof_user_agent:
                fake_agent = global_settings.USER_AGENTS.get(global_settings.selected_user_agent, "MyProxy")
                if "User-Agent:" in data_str:
                    data_str = re.sub(r'User-Agent:.*?\r\n', f'User-Agent: {fake_agent}\r\n', data_str)
            
            if global_settings.strip_cookies:
                data_str = re.sub(r'Cookie:.*?\r\n', '', data_str, flags=re.IGNORECASE)

            return data_str.encode('utf-8')
        except:
            return data

    def _modify_response(self, data):
        # Foloseste varianta optimizata (cea cu stergere Chunked/Gzip)
        try:
            parts = data.split(b'\r\n\r\n', 1)
            if len(parts) < 2: return data
            header = parts[0]
            body = parts[1]
            try:
                body_str = body.decode('utf-8', errors='ignore')
                if global_settings.rewrite_https: body_str = body_str.replace('href="http://', 'href="https://')
                if global_settings.censor_enabled and global_settings.censor_word_target:
                    p = re.compile(re.escape(global_settings.censor_word_target), re.IGNORECASE)
                    body_str = p.sub(global_settings.censor_word_replace, body_str)
                if global_settings.block_images: body_str = re.sub(r'<img[^>]*>', '[IMG BLOCKED]', body_str)
                if global_settings.inject_banner:
                    banner = "<div style='background:red;color:white;text-align:center;padding:10px;font-weight:bold;position:fixed;top:0;left:0;width:100%;z-index:999999;'>⚠️ PROXY ACTIV ⚠️</div><br><br><br>"
                    if "<body" in body_str: body_str = re.sub(r'<body[^>]*>', lambda m: m.group(0) + banner, body_str, count=1)
                    else: body_str = banner + body_str
                
                new_body = body_str.encode('utf-8')
                header_str = header.decode('utf-8', errors='ignore')
                header_str = re.sub(r'Transfer-Encoding:.*?\r\n', '', header_str, flags=re.IGNORECASE)
                header_str = re.sub(r'Content-Encoding:.*?\r\n', '', header_str, flags=re.IGNORECASE)
                if "Connection:" in header_str: header_str = re.sub(r'Connection:.*?\r\n', 'Connection: close\r\n', header_str, flags=re.IGNORECASE)
                else: header_str += "\r\nConnection: close"
                new_len = len(new_body)
                if "Content-Length:" in header_str: header_str = re.sub(r'Content-Length:\s*\d+', f'Content-Length: {new_len}', header_str, flags=re.IGNORECASE)
                else: header_str += f"\r\nContent-Length: {new_len}"
                
                return header_str.encode('utf-8') + b'\r\n\r\n' + new_body
            except: return data
        except: return data

class PooledProxyServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, max_workers=20):
        # Initializam serverul parinte
        super().__init__(server_address, RequestHandlerClass)
        # Cream o echipa fixa de muncitori (Pool)
        self.pool = ThreadPoolExecutor(max_workers=max_workers)

    def process_request(self, request, client_address):
        # Aici este magia: In loc sa cream un thread nou, trimitem sarcina in Pool
        self.pool.submit(self.process_request_thread, request, client_address)

    def process_request_thread(self, request, client_address):
        """Aceasta metoda este executata de unul din muncitorii din Pool"""
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

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
        
        self.log_area.insert(tk.END, """
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
        global_settings.censor_word_replace = self.entry_replace.get()

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
def start_server():
    socketserver.TCPServer.allow_reuse_address = True
    server = PooledProxyServer((PROXY_HOST, PROXY_PORT), AdvancedProxyHandler, max_workers=20)
    server.serve_forever()

def on_closing():
    os._exit(0)

if __name__ == "__main__":
    # Pornim server in thread
    t = threading.Thread(target=start_server)
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