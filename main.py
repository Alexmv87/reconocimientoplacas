import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from datetime import datetime, timedelta
import json, os, csv, time, cv2, numpy as np, pytesseract
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from fpdf import FPDF
import random
import re
import threading
import queue
import socket
import requests
from bs4 import BeautifulSoup
import webbrowser
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configuración inicial
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
APP_VERSION = "2.6.0"
APP_NAME = "SRPV-UNAMAD"
DEVELOPER = "© 2025 YYGR-ESPL"

class LoginSystem:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} - Login")
        self.root.geometry("400x500")
        self.root.resizable(0, 0)
        self.setup_ui()
        self.load_default_users()
        self.center_window()
        self.toggle_password_visibility()
        
    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_ui(self):
        self.bg_color, self.entry_bg, self.entry_fg = "#222222", "#475569", "white"
        self.entry_border, self.button_bg, self.button_active = "#3b82f6", "#3b82f6", "#2563eb"
        
        # Frame principal
        self.login_frame = tk.Frame(self.root, bg=self.bg_color, padx=20, pady=20)
        self.login_frame.pack(expand=1, fill="both")
        
        # Logo y título
        self.setup_logo()
        
        # Campos de entrada
        self.setup_input_fields()
        
        # Tipo de usuario
        self.setup_user_type_selector()
        
        # Botones
        self.setup_buttons()
    
    def setup_logo(self):
        logo_frame = tk.Frame(self.login_frame, bg=self.bg_color)
        logo_frame.pack(pady=(0, 20))
        
        tk.Label(logo_frame, text="🚗", font=("Arial", 24), bg=self.bg_color).pack(side="left", padx=5)
        tk.Label(logo_frame, text=APP_NAME, font=("Arial", 16, "bold"), 
                bg=self.bg_color, fg="white").pack(side="left")
    
    def setup_input_fields(self):
        # Campo de usuario
        self.user_frame = tk.Frame(self.login_frame, bg=self.bg_color)
        self.user_frame.pack(fill="x", pady=5)
        tk.Label(self.user_frame, text="👤", font=("Arial", 12), bg=self.bg_color, fg="gray").pack(side="left", padx=(0, 5))
        
        self.username_entry = tk.Entry(self.user_frame, bg=self.entry_bg, fg=self.entry_fg, 
                                    insertbackground="white", relief="solid", borderwidth=1,
                                    highlightbackground=self.entry_border, highlightthickness=1,
                                    font=("Arial", 12))
        self.username_entry.pack(fill="x", expand=1)
        self.username_entry.insert(0, "Nombre de Usuario")
        self.username_entry.bind("<FocusIn>", lambda e: self.clear_placeholder(e, "Nombre de Usuario"))
        
        # Campo de contraseña
        self.pass_frame = tk.Frame(self.login_frame, bg=self.bg_color)
        self.pass_frame.pack(fill="x", pady=5)
        tk.Label(self.pass_frame, text="🔒", font=("Arial", 12), bg=self.bg_color, fg="gray").pack(side="left", padx=(0, 5))
        
        self.password_entry = tk.Entry(self.pass_frame, bg=self.entry_bg, fg=self.entry_fg, show="", 
                                     insertbackground="white", relief="solid", borderwidth=1,
                                     highlightbackground=self.entry_border, highlightthickness=1,
                                     font=("Arial", 12))
        self.password_entry.pack(fill="x", expand=1)
        self.password_entry.insert(0, "Contraseña")
        self.password_entry.bind("<FocusIn>", self.handle_password_focus)
        self.password_entry.bind("<KeyRelease>", self.handle_password_keyrelease)
        
        # Mostrar/ocultar contraseña
        self.show_pass_var = tk.IntVar()
        self.show_pass_btn = tk.Checkbutton(self.login_frame, text="Mostrar contraseña", 
                                          variable=self.show_pass_var, bg=self.bg_color, fg="white",
                                          selectcolor="#333333", command=self.toggle_password_visibility)
        self.show_pass_btn.pack(anchor="w", pady=(0, 10))
    
    def setup_user_type_selector(self):
        self.user_type = tk.StringVar(value="admin")
        tk.Radiobutton(self.login_frame, text="Administrador", variable=self.user_type, value="admin",
                      bg=self.bg_color, fg="white", selectcolor="#333333", 
                      activebackground=self.bg_color, font=("Arial", 11)).pack(anchor="w", pady=5)
        tk.Radiobutton(self.login_frame, text="Seguridad", variable=self.user_type, value="security",
                      bg=self.bg_color, fg="white", selectcolor="#333333", 
                      activebackground=self.bg_color, font=("Arial", 11)).pack(anchor="w", pady=5)
    
    def setup_buttons(self):
        tk.Button(self.login_frame, text="Iniciar Sesión", font=("Arial", 12, "bold"),
                 bg=self.button_bg, fg="white", activebackground=self.button_active,
                 activeforeground="white", relief="flat", command=self.login).pack(fill="x", pady=(20, 10))
        
        tk.Button(self.login_frame, text="¿Olvidaste tu contraseña?", bg=self.bg_color,
                 fg=self.button_bg, activebackground=self.bg_color, activeforeground=self.button_active,
                 relief="flat", font=("Arial", 10), command=self.recover_password).pack()
    
    def clear_placeholder(self, event, placeholder):
        if event.widget.get() == placeholder:
            event.widget.delete(0, "end")
    
    def handle_password_focus(self, event):
        if self.password_entry.get() == "Contraseña":
            self.password_entry.delete(0, "end")
            self.password_entry.config(show="•")
        elif not self.show_pass_var.get():
            self.password_entry.config(show="•")
    
    def handle_password_keyrelease(self, event):
        if self.password_entry.get() == "":
            if self.show_pass_var.get():
                self.password_entry.config(show="")
            else:
                self.password_entry.config(show="•")
    
    def toggle_password_visibility(self):
        if self.show_pass_var.get():
            self.password_entry.config(show="")
        else:
            if self.password_entry.get() != "Contraseña" and self.password_entry.get() != "":
                self.password_entry.config(show="•")
    
    def recover_password(self):
        email = simpledialog.askstring("Recuperar Contraseña", "Ingrese su correo electrónico registrado:")
        if email:
            if "@" in email and "." in email:
                try:
                    messagebox.showinfo("Éxito", f"Se ha enviado un enlace de recuperación a {email}")
                except Exception as e:
                    messagebox.showerror("Error", f"No se pudo enviar el correo: {str(e)}")
            else:
                messagebox.showerror("Error", "Por favor ingrese un correo electrónico válido")
    
    def load_default_users(self):
        if not os.path.exists("users.json"):
            default_users = [
                {"username": "admin", "password": "admin123", "role": "admin", "email": "admin@placasscan.com"},
                {"username": "security", "password": "security123", "role": "security", "email": "security@placasscan.com"}
            ]
            self.save_users(default_users)
    
    def save_users(self, users):
        try:
            with open("users.json", "w") as f:
                json.dump(users, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar los usuarios: {str(e)}")
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or username == "Nombre de Usuario":
            messagebox.showerror("Error", "Por favor ingrese su nombre de usuario")
            return
        
        if not password or password == "Contraseña":
            messagebox.showerror("Error", "Por favor ingrese su contraseña")
            return
        
        try:
            with open("users.json", "r") as f:
                users = json.load(f)
            
            user = next((u for u in users if u["username"].lower() == username.lower() and u["password"] == password), None)
            
            if user:
                if user["role"] != self.user_type.get():
                    messagebox.showwarning("Advertencia", 
                                         f"Este usuario no tiene permisos de {self.user_type.get()}")
                    return
                
                self.log_login_attempt(username, True)
                messagebox.showinfo("Éxito", f"Bienvenido, {username}")
                self.root.withdraw()
                admin_window = tk.Toplevel(self.root)
                SistemaEscaneoPlacas(admin_window, user["role"], username)
            else:
                self.log_login_attempt(username, False)
                messagebox.showerror("Error", "Credenciales incorrectas")
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar usuarios: {str(e)}")
    
    def log_login_attempt(self, username, success):
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "username": username,
                "success": success,
                "ip": self.get_local_ip()
            }
            
            logs = []
            if os.path.exists("login_logs.json"):
                with open("login_logs.json", "r") as f:
                    logs = json.load(f)
            
            logs.append(log_entry)
            
            with open("login_logs.json", "w") as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            print(f"Error al registrar intento de login: {str(e)}")
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

class SistemaEscaneoPlacas:
    def __init__(self, root:tk.Tk, user_role, username):
        self.root = root
        self.user_role = user_role
        self.username = username
        self.setup_window()
        self.initialize_data()
        self.setup_ui()
        self.setup_modals()
        self.update_ui()
        self.check_for_updates()
        self.estatus = tk.StringVar()

    def setup_window(self):
        self.root.title(f"{APP_NAME} - {'Administrador' if self.user_role == 'admin' else 'Seguridad'}")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1e3a8a")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.sidebar_open = True
        self.current_page = 1
        self.records_per_page = 10
        self.camera_active = False
        self.cap = None
        self.scanning_active = False
        self.camera_thread = None
        self.frame_queue = queue.Queue(maxsize=1)
        
        self.anpr_config = {
            'preprocessing': 1,
            'contour_detection': 1,
            'ocr_enabled': 1,
            'enable_alerts': 1,
            'enable_auto_scan': 1,
            'ocr_language': 'eng',
            'ocr_whitelist': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            'scan_interval': 5,
            'min_confidence': 70,
            'canny_threshold1': 50,
            'canny_threshold2': 150
        }
        
        self.style = ttk.Style()
        self.setup_styles()
    
    def setup_styles(self):
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#f8fafc')
        self.style.configure('TLabel', background='#f8fafc', font=('Segoe UI', 9))
        self.style.configure('TButton', font=('Segoe UI', 9))
        self.style.configure('Treeview', font=('Segoe UI', 9), rowheight=25)
        self.style.configure('Treeview.Heading', font=('Segoe UI', 9, 'bold'))
        self.style.configure('Green.TButton', foreground='white', background='#38a169')
        self.style.configure('Red.TButton', foreground='white', background='#e53e3e')
        self.style.configure('Blue.TButton', foreground='white', background='#3182ce')
        self.style.configure('Yellow.TButton', foreground='black', background='#f6e05e')
        self.style.configure('Subheader.TLabel', font=('Segoe UI', 10, 'bold'))
    
    def initialize_data(self):
        self.users = []
        self.scan_results = []
        self.cameras = []
        self.blacklist = []
        self.whitelist = []
        self.load_data()
        
        if not self.users:
            self.users = [
                {
                    "dni": "12345678", "nombre": "Juan Pérez", "telefono": "987654321",
                    "correo": "juan@example.com", "placa": "ABC-123", "tipoVehiculo": "auto",
                    "marca": "Toyota", "modelo": "Corolla", "observaciones": "Vehículo particular",
                    "fechaRegistro": datetime.now().isoformat(), "estado": "activo"
                },
                {
                    "dni": "87654321", "nombre": "María Gómez", "telefono": "987123456",
                    "correo": "maria@example.com", "placa": "XYZ-789", "tipoVehiculo": "camioneta",
                    "marca": "Nissan", "modelo": "Frontier", "observaciones": "Vehículo de trabajo",
                    "fechaRegistro": (datetime.now() - timedelta(days=1)).isoformat(), "estado": "activo"
                }
            ]
            self.save_data()
    
    def load_data(self):
        try:
            data_files = {
                "users": "usuarios.json",
                "anpr_config": "anpr_config.json",
                "scan_results": "anpr_results.json",
                "cameras": "cameras.json",
                "blacklist": "blacklist.json",
                "whitelist": "whitelist.json"
            }
            
            for attr, filename in data_files.items():
                if os.path.exists(filename):
                    with open(filename, "r") as f:
                        setattr(self, attr, json.load(f))
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar datos: {str(e)}")
    
    def save_data(self):
        try:
            data_files = {
                "users": "usuarios.json",
                "anpr_config": "anpr_config.json",
                "scan_results": "anpr_results.json",
                "cameras": "cameras.json",
                "blacklist": "blacklist.json",
                "whitelist": "whitelist.json"
            }
            
            for attr, filename in data_files.items():
                with open(filename, "w") as f:
                    json.dump(getattr(self, attr), f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar datos: {str(e)}")
    
    def setup_ui(self):
        self.setup_sidebar()
        self.main_content = tk.Frame(self.root, bg="#f8fafc")
        self.main_content.pack(side="right", fill="both", expand=1)
        self.setup_top_bar()
        self.setup_summary_cards()
        self.setup_search_section()
        self.setup_user_table()
        self.setup_graphs()
    
    def setup_sidebar(self):
        self.sidebar = tk.Frame(self.root, bg="#0f172a", width=280)
        self.sidebar.pack(side="left", fill="y")
        
        logo_frame = tk.Frame(self.sidebar, bg="#0f172a")
        logo_frame.pack(pady=20, padx=10, fill="x")
        
        tk.Label(logo_frame, text="🚗", font=("Arial", 20), bg="#0f172a").pack(side="left", padx=5)
        tk.Label(logo_frame, text=APP_NAME, font=("Segoe UI", 12, "bold"), 
                bg="#0f172a", fg="white").pack(side="left")
        
        user_frame = tk.Frame(self.sidebar, bg="#0f172a", padx=10, pady=10)
        user_frame.pack(fill="x")
        
        tk.Label(user_frame, text=f"👤 {self.username}", font=("Segoe UI", 10), 
                bg="#0f172a", fg="white", anchor="w").pack(fill="x")
        tk.Label(user_frame, text=f"Rol: {'Administrador' if self.user_role == 'admin' else 'Seguridad'}", 
                font=("Segoe UI", 8), bg="#0f172a", fg="#a0aec0", anchor="w").pack(fill="x")
        
        menu_items = [
            ("📊 Dashboard", self.show_dashboard),
            ("👥 Usuarios", self.show_users_section),
            ("🚗 Vehículos", self.show_vehicles_section),
            ("📷 Cámaras", self.open_camera_ip),
            ("🔍 Escaneo", self.open_auto_scan),
            ("📊 Reportes", self.open_reports),
            ("⚙️ Configuración", self.open_configuration),
            ("❓ Ayuda", self.open_help)
        ]
        
        for text, command in menu_items:
            btn = tk.Button(self.sidebar, text=f" {text}", font=("Segoe UI", 10),
                          bg="#0f172a", fg="white", bd=0, anchor="w", command=command)
            btn.pack(fill="x", padx=10, pady=5)
            btn.bind("<Enter>", lambda e: e.widget.config(bg="#1e40af"))
            btn.bind("<Leave>", lambda e: e.widget.config(bg="#0f172a"))
        
        tk.Button(self.sidebar, text=" 🔒 Cerrar Sesión", font=("Segoe UI", 10),
                 bg="#0f172a", fg="#f56565", bd=0, anchor="w", 
                 command=self.logout).pack(fill="x", padx=10, pady=(20, 5))
        
        footer_frame = tk.Frame(self.sidebar, bg="#0f172a")
        footer_frame.pack(side="bottom", fill="x", pady=10, padx=10)
        
        tk.Label(footer_frame, text=f"Versión {APP_VERSION}\n{DEVELOPER}", 
                bg="#0f172a", fg="gray", font=("Segoe UI", 8)).pack()
    
    def setup_top_bar(self):
        top_bar = tk.Frame(self.main_content, bg="#1e3a8a", height=60)
        top_bar.pack(fill="x")
        
        self.section_title = tk.Label(top_bar, text="Panel de Administración", 
                                    font=("Segoe UI", 14, "bold"), bg="#1e3a8a", fg="white")
        self.section_title.pack(side="left", padx=20)
        
        right_frame = tk.Frame(top_bar, bg="#1e3a8a")
        right_frame.pack(side="right", padx=20)
        
        self.notification_btn = tk.Button(right_frame, text="🔔", font=("Segoe UI", 12),
                                        bg="#1e3a8a", fg="white", bd=0,
                                        command=self.show_notifications)
        self.notification_btn.pack(side="left", padx=5)
        
        user_frame = tk.Frame(right_frame, bg="#1e3a8a")
        user_frame.pack(side="right", padx=10)
        
        tk.Label(user_frame, text=self.username, font=("Segoe UI", 10), 
                bg="#1e3a8a", fg="white").pack(side="right", padx=10)
        
        tk.Label(user_frame, text="👤", font=("Segoe UI", 12), 
                bg="#1e3a8a", fg="white").pack(side="right")
    
    def setup_summary_cards(self):
        cards_frame = tk.Frame(self.main_content, bg="#f8fafc", padx=20, pady=20)
        cards_frame.pack(fill="x")
        
        self.cards = []
        self.card_vars = []
        
        card_data = [
            {"title": "Usuarios Registrados", "color": "#3b82f6", "icon": "👥"},
            {"title": "Vehículos Activos", "color": "#10b981", "icon": "🚗"},
            {"title": "Escaneos Hoy", "color": "#a855f7", "icon": "📷"},
            {"title": "Alertas", "color": "#f59e0b", "icon": "⚠️"}
        ]
        
        for i, data in enumerate(card_data):
            card = tk.Frame(cards_frame, bg=data["color"], width=200, height=100, bd=0, relief="raised")
            card.grid(row=0, column=i, padx=10, sticky="nsew")
            self.cards.append(card)
            
            icon_frame = tk.Frame(card, bg=data["color"])
            icon_frame.pack(anchor="nw", padx=10, pady=10)
            
            tk.Label(icon_frame, text=data["icon"], font=("Segoe UI", 14), 
                    bg=data["color"], fg="white").pack(side="left", padx=(0, 5))
            
            tk.Label(icon_frame, text=data["title"], font=("Segoe UI", 10), 
                    bg=data["color"], fg="white").pack(side="left")
            
            var = tk.StringVar(value="0")
            self.card_vars.append(var)
            
            tk.Label(card, textvariable=var, font=("Segoe UI", 16, "bold"), 
                    bg=data["color"], fg="white").pack(anchor="nw", padx=10, pady=(0, 10))
    
    def setup_search_section(self):
        self.search_frame = tk.Frame(self.main_content, bg="white", padx=20, pady=20, bd=1, relief="groove")
        self.search_frame.pack(fill="x", padx=20, pady=10)
        
        tk.Label(self.search_frame, text="Buscar Usuario/Vehículo", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        tk.Label(self.search_frame, text="Busque por DNI, nombre, placa o características", 
                font=("Segoe UI", 9), fg="gray").pack(anchor="w")
        
        search_control = tk.Frame(self.search_frame)
        search_control.pack(fill="x", pady=10)
        
        self.search_entry = tk.Entry(search_control, font=("Segoe UI", 10), width=50)
        self.search_entry.pack(side="left", fill="x", expand=1)
        self.search_entry.bind("<KeyRelease>", self.search_user)
        
        tk.Button(search_control, text="🔍 Buscar", font=("Segoe UI", 10),
                 command=self.search_user).pack(side="left", padx=5)
        
        tk.Button(search_control, text="⚙️ Filtros", font=("Segoe UI", 10),
                 command=self.open_filters).pack(side="left", padx=5)
        
        self.search_results = tk.Frame(self.main_content)
        self.search_results.pack(fill="x", padx=20, pady=10)
    
    def setup_user_table(self):
        table_frame = tk.Frame(self.main_content, bg="white", padx=20, pady=20, bd=1, relief="groove")
        table_frame.pack(fill="both", expand=1, padx=20, pady=10)
        
        table_control = tk.Frame(table_frame)
        table_control.pack(fill="x", pady=10)
        
        tk.Label(table_control, text="Base de Datos de Usuarios", font=("Segoe UI", 12, "bold")).pack(side="left")
        tk.Label(table_control, text="Lista completa de usuarios registrados", 
                font=("Segoe UI", 9), fg="gray").pack(side="left", padx=10)
        
        btn_frame = tk.Frame(table_control)
        btn_frame.pack(side="right")
        
        tk.Button(btn_frame, text="➕ Nuevo", command=self.open_add_user_modal, 
                 bg="#38a169", fg="white").pack(side="left", padx=5)
        tk.Button(btn_frame, text="🔄 Actualizar", command=self.update_table, 
                 bg="#3182ce", fg="white").pack(side="left", padx=5)
        tk.Button(btn_frame, text="📁 Exportar", command=self.generate_detailed_report, 
                 bg="#805ad5", fg="white").pack(side="left", padx=5)
        
        tree_frame = tk.Frame(table_frame)
        tree_frame.pack(fill="both", expand=1)
        
        self.tree = ttk.Treeview(tree_frame, columns=("dni", "nombre", "telefono", "placa", "tipo", "registro"), 
                                show="headings", height=15)
        
        for col, text, width in [
            ("dni", "DNI", 100),
            ("nombre", "Nombre", 200),
            ("telefono", "Teléfono", 100),
            ("placa", "Placa", 100),
            ("tipo", "Tipo", 80),
            ("registro", "Registro", 100)
        ]:
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor="center")
        
        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=1)
        scrollbar.pack(side="right", fill="y")
        
        self.setup_tree_context_menu()
        self.setup_pagination(table_frame)
    
    def setup_tree_context_menu(self):
        self.tree_menu = tk.Menu(self.root, tearoff=0)
        self.tree_menu.add_command(label="Ver Detalles", command=self.view_user_details)
        self.tree_menu.add_command(label="Editar", command=self.edit_user)
        self.tree_menu.add_command(label="Eliminar", command=self.delete_user)
        self.tree.bind("<Button-3>", self.show_tree_context_menu)
    
    def show_tree_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.tree_menu.post(event.x_root, event.y_root)
    
    def setup_pagination(self, parent_frame):
        pagination_frame = tk.Frame(parent_frame)
        pagination_frame.pack(fill="x", pady=10)
        
        self.pagination_label = tk.Label(pagination_frame, text="Mostrando 0 de 0 registros", 
                                       font=("Segoe UI", 9))
        self.pagination_label.pack(side="left")
        
        btn_pagination = tk.Frame(pagination_frame)
        btn_pagination.pack(side="right")
        
        self.btn_prev = tk.Button(btn_pagination, text="◀ Anterior", state="disabled",
                                command=lambda: self.change_page(-1))
        self.btn_prev.pack(side="left", padx=5)
        
        self.btn_next = tk.Button(btn_pagination, text="Siguiente ▶", state="disabled",
                                command=lambda: self.change_page(1))
        self.btn_next.pack(side="left", padx=5)
    
    def setup_graphs(self):
        graphs_frame = tk.Frame(self.main_content)
        graphs_frame.pack(fill="both", expand=1, padx=20, pady=10)
        
        self.graph_registros = tk.Frame(graphs_frame, width=400, height=300, bg="white", 
                                      bd=1, relief="groove")
        self.graph_registros.pack(side="left", fill="both", expand=1, padx=5, pady=5)
        
        self.graph_vehiculos = tk.Frame(graphs_frame, width=400, height=300, bg="white", 
                                      bd=1, relief="groove")
        self.graph_vehiculos.pack(side="left", fill="both", expand=1, padx=5, pady=5)
        
        self.init_graphs()
    
    def init_graphs(self):
        self.fig_registros = plt.Figure(figsize=(4, 3), dpi=100)
        self.ax_registros = self.fig_registros.add_subplot(111)
        self.ax_registros.set_title("Registros por Mes")
        
        self.canvas_registros = FigureCanvasTkAgg(self.fig_registros, master=self.graph_registros)
        self.canvas_registros.get_tk_widget().pack(fill="both", expand=1)
        
        self.fig_vehiculos = plt.Figure(figsize=(4, 3), dpi=100)
        self.ax_vehiculos = self.fig_vehiculos.add_subplot(111)
        self.ax_vehiculos.set_title("Tipos de Vehículos")
        
        self.canvas_vehiculos = FigureCanvasTkAgg(self.fig_vehiculos, master=self.graph_vehiculos)
        self.canvas_vehiculos.get_tk_widget().pack(fill="both", expand=1)
    
    def setup_modals(self):
        self.setup_add_user_modal()
        self.setup_user_details_modal()
    
    def setup_add_user_modal(self):
        self.modal_add = tk.Toplevel(self.root)
        self.modal_add.title("Agregar Nuevo Usuario")
        self.modal_add.geometry("1200x500")
        #self.modal_add.resizable(0, 0)
        self.modal_add.withdraw()
        
        tk.Label(self.modal_add, text="Agregar Nuevo Usuario", 
                font=("Segoe UI", 14, "bold")).pack(pady=10)
        
        tk.Label(self.modal_add, text="Complete todos los campos requeridos (*)", 
                font=("Segoe UI", 9), fg="gray").pack()
        
        form_frame = tk.Frame(self.modal_add, padx=20, pady=20)
        form_frame.pack(fill="both", expand=1)
        
        self.form_vars = {}
        self.form_widgets = {}
        
        fields = [
            ("DNI *", "dni", "Ingrese DNI (8 dígitos)"),
            ("Nombre Completo *", "nombre", "Nombres y apellidos"),
            ("Teléfono *", "telefono", "Número de contacto"),
            ("Correo Electrónico", "correo", "correo@ejemplo.com"),
            ("Placa del Vehículo *", "placa", "Ej: ABC-123"),
            ("Tipo de Vehículo *", "tipoVehiculo", "Seleccione...", "combobox", 
             ["auto", "camioneta", "moto", "bus", "camion"]),
            ("Marca", "marca", "Marca del vehículo"),
            ("Modelo", "modelo", "Modelo del vehículo"),
            ("Observaciones", "observaciones", "Notas adicionales...", "textarea")
        ]
        
        for i, field in enumerate(fields):
            row = i // 2 if len(fields) > 4 else i
            col = i % 2 if len(fields) > 4 else 0
            
            frame = tk.Frame(form_frame)
            frame.grid(row=row, column=col, padx=10, pady=5, sticky="ew")
            
            tk.Label(frame, text=field[0], font=("Segoe UI", 9)).pack(anchor="w")
            
            if len(field) > 3 and field[3] == "combobox":
                var = tk.StringVar()
                cb = ttk.Combobox(frame, textvariable=var, values=field[4], font=("Segoe UI", 10))
                cb.pack(fill="x")
                self.form_vars[field[1]] = var
                self.form_widgets[field[1]] = cb
            elif len(field) > 3 and field[3] == "textarea":
                var = tk.StringVar()
                text = tk.Text(frame, height=4, font=("Segoe UI", 10))
                text.pack(fill="x")
                self.form_vars[field[1]] = text
                self.form_widgets[field[1]] = text
            else:
                var = tk.StringVar()
                entry = tk.Entry(frame, textvariable=var, font=("Segoe UI", 10))
                entry.pack(fill="x")
                self.form_vars[field[1]] = var
                self.form_widgets[field[1]] = entry
                
                if field[2]:
                    entry.insert(0, field[2])
                    entry.bind("<FocusIn>", lambda e: e.widget.delete(0, "end") 
                             if e.widget.get() == field[2] else None)
        
        btn_frame = tk.Frame(self.modal_add, pady=10)
        btn_frame.pack(fill="x", padx=20)
        
        tk.Button(btn_frame, text="Cancelar", 
                 command=self.close_add_user_modal).pack(side="right", padx=5)
        
        tk.Button(btn_frame, text="Guardar Usuario", 
                 command=self.add_user).pack(side="right", padx=5)
    
    def setup_user_details_modal(self):
        self.modal_details = tk.Toplevel(self.root)
        self.modal_details.title("Detalles de Usuario")
        self.modal_details.geometry("500x600")
        self.modal_details.resizable(0, 0)
        self.modal_details.withdraw()
        
        tk.Label(self.modal_details, text="Detalles de Usuario", 
                font=("Segoe UI", 14, "bold")).pack(pady=10)
        
        self.details_frame = tk.Frame(self.modal_details, padx=20, pady=10)
        self.details_frame.pack(fill="both", expand=1)
        
        btn_frame = tk.Frame(self.modal_details, pady=10)
        btn_frame.pack(fill="x", padx=20)
        
        tk.Button(btn_frame, text="Cerrar", 
                 command=self.close_user_details_modal).pack(side="right", padx=5)
    
    def update_ui(self):
        self.update_table()
        self.update_summary()
        self.update_graphs()
    
    def update_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        total_pages = (len(self.users) + self.records_per_page - 1) // self.records_per_page
        start = (self.current_page - 1) * self.records_per_page
        end = min(start + self.records_per_page, len(self.users))
        
        self.pagination_label.config(text=f"Mostrando {start+1} a {end} de {len(self.users)} registros")
        
        self.btn_prev.config(state="normal" if self.current_page > 1 else "disabled")
        self.btn_next.config(state="normal" if self.current_page < total_pages else "disabled")
        
        for i in range(start, end):
            user = self.users[i]
            reg_date = datetime.fromisoformat(user["fechaRegistro"]).strftime("%d/%m/%Y")
            self.tree.insert("", "end", values=(
                user["dni"],
                user["nombre"],
                user["telefono"],
                user["placa"],
                user["tipoVehiculo"].capitalize(),
                reg_date
            ))
    
    def update_summary(self):
        today = datetime.now().date()
        today_scans = sum(1 for r in self.scan_results 
                         if datetime.fromisoformat(r["timestamp"]).date() == today)
        
        self.card_vars[0].set(len(self.users))
        self.card_vars[1].set(len(self.users))
        self.card_vars[2].set(today_scans)
        self.card_vars[3].set(len([u for u in self.users if u.get("estado", "activo") != "activo"]))
    
    def update_graphs(self):
        self.ax_registros.clear()
        self.ax_vehiculos.clear()
        
        if not self.users:
            return
        
        reg_by_date = {}
        for user in self.users:
            date = datetime.fromisoformat(user["fechaRegistro"]).strftime("%Y-%m")
            reg_by_date[date] = reg_by_date.get(date, 0) + 1
        
        dates = sorted(reg_by_date.keys())
        counts = [reg_by_date[d] for d in dates]
        
        self.ax_registros.bar(dates, counts, color="#3b82f6")
        self.ax_registros.set_title("Registros por Mes")
        self.ax_registros.set_xlabel("Mes")
        self.ax_registros.set_ylabel("Número de Registros")
        self.ax_registros.tick_params(axis="x", rotation=45)
        self.fig_registros.tight_layout()
        
        types = {"auto": 0, "camioneta": 0, "moto": 0, "bus": 0, "camion": 0}
        for user in self.users:
            types[user["tipoVehiculo"]] += 1
        
        labels = ["Automóviles", "Camionetas", "Motocicletas", "Buses", "Camiones"]
        sizes = [types["auto"], types["camioneta"], types["moto"], types["bus"], types["camion"]]
        colors = ["#3b82f6", "#10b981", "#f59e0b", "#a855f7", "#ef4444"]
        
        self.ax_vehiculos.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90)
        self.ax_vehiculos.axis("equal")
        self.ax_vehiculos.set_title("Tipos de Vehículos")
        
        self.canvas_registros.draw()
        self.canvas_vehiculos.draw()
    
    def search_user(self, event=None):
        term = self.search_entry.get().lower()
        
        if not term:
            self.search_results.pack_forget()
            return
        
        
        def Filtrado(x:dict,busqueda:str)->bool:            
            for valor in x.values():
                if busqueda.lower() in str(valor).lower():
                    return True
            return False            
        
        results = list(filter(lambda x: Filtrado(x,term),self.users))
        
        for widget in self.search_results.winfo_children():
            widget.destroy()
        
        if not results:
            tk.Label(self.search_results, text=f"No se encontraron resultados para '{term}'", 
                    bg="#fef3c7", fg="#92400e", padx=10, pady=5).pack(fill="x")
            self.search_results.pack(fill="x", padx=20, pady=10)
            return
        
        tk.Label(self.search_results, text=f"Resultados de búsqueda ({len(results)} encontrados):", 
                font=("Segoe UI", 9, "bold")).pack(anchor="w")
        
        for user in results:
            frame = tk.Frame(self.search_results, bg="white", bd=1, relief="groove", padx=10, pady=10)
            frame.pack(fill="x", pady=5)
            
            header = tk.Frame(frame)
            header.pack(fill="x")
            
            tk.Label(header, text=user["nombre"], font=("Segoe UI", 10, "bold")).pack(side="left")
            
            color = "#f59e0b" if user["tipoVehiculo"] == "moto" else "#3b82f6"
            tk.Label(header, text=user["placa"], bg=color, fg="white", 
                    font=("Segoe UI", 8), padx=5, pady=2).pack(side="right")
            
            tk.Label(frame, text=f"DNI: {user['dni']} | Tel: {user['telefono']}", 
                    font=("Segoe UI", 8)).pack(anchor="w")
            
            type_text = user["tipoVehiculo"].capitalize()
            brand_model = f"{user['marca'] or 'Sin marca'} {user['modelo'] or ''}"
            tk.Label(frame, text=f"{type_text} - {brand_model}", font=("Segoe UI", 8)).pack(anchor="w")
            
            date = datetime.fromisoformat(user["fechaRegistro"]).strftime("%d/%m/%Y")
            tk.Label(frame, text=f"Registrado: {date}", font=("Segoe UI", 8), fg="gray").pack(anchor="w")
            
            tk.Button(frame, text="Ver detalles", font=("Segoe UI", 8),
                     command=lambda u=user: self.show_user_details(u)).pack(anchor="e")
        
        self.search_results.pack(fill="x", padx=20, pady=10,after=self.search_frame)
    
    def change_page(self, direction):
        total_pages = (len(self.users) + self.records_per_page - 1) // self.records_per_page
        
        self.current_page += direction
        if self.current_page < 1:
            self.current_page = 1
        if self.current_page > total_pages:
            self.current_page = total_pages
        
        self.update_table()
    
    def open_add_user_modal(self):
        for field, var in self.form_vars.items():
            
            if isinstance(var, tk.Text):                
                var.delete("1.0", "end")
            else:
                var.set("")
        
        self.modal_add.title("Agregar Nuevo Usuario")
        self.modal_add.deiconify()
    
    def close_add_user_modal(self):
        self.modal_add.withdraw()
    
    def add_user(self):
        data = {}
        for field, var in self.form_vars.items():
            if isinstance(var, tk.Text):
                data[field] = var.get("1.0", "end").strip()
            else:
                data[field] = var.get().strip()
        
        if not data["dni"].isdigit() or len(data["dni"]) != 8:
            messagebox.showerror("Error", "DNI debe tener 8 dígitos")
            self.form_widgets["dni"].focus()
            return
        
        if any(u["dni"] == data["dni"] for u in self.users):
            messagebox.showerror("Error", "DNI ya registrado")
            self.form_widgets["dni"].focus()
            return
        
        if any(u["placa"] == data["placa"].upper() for u in self.users):
            messagebox.showerror("Error", "Placa ya registrada")
            self.form_widgets["placa"].focus()
            return
        
        if data["correo"] and "@" not in data["correo"]:
            messagebox.showerror("Error", "Correo inválido")
            self.form_widgets["correo"].focus()
            return
        
        if not all([data["dni"], data["nombre"], data["telefono"], data["placa"], data["tipoVehiculo"]]):
            messagebox.showerror("Error", "Complete campos requeridos (*)")
            return
        
        new_user = {
            "dni": data["dni"],
            "nombre": data["nombre"],
            "telefono": data["telefono"],
            "correo": data["correo"],
            "placa": data["placa"].upper(),
            "tipoVehiculo": data["tipoVehiculo"],
            "marca": data["marca"],
            "modelo": data["modelo"],
            "observaciones": data["observaciones"],
            "fechaRegistro": datetime.now().isoformat(),
            "estado": "activo"
        }
        
        self.users.append(new_user)

        self.save_data()
        self.update_ui()
        self.close_add_user_modal()
        
        messagebox.showinfo("Éxito", "Usuario agregado correctamente")
    
    def view_user_details(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Advertencia", "Seleccione un usuario")
            return
        
        dni = self.tree.item(selected[0], "values")[0]
        user = next((u for u in self.users if u["dni"] == dni), None)
        
        if user:
            self.show_user_details(user)
    
    def show_user_details(self, user):
        for widget in self.details_frame.winfo_children():
            widget.destroy()
        
        tk.Label(self.details_frame, text=user["nombre"], 
                font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 10))
        
        details = [
            ("DNI", user["dni"]),
            ("Teléfono", user["telefono"]),
            ("Correo", user["correo"] or "No especificado"),
            ("Placa", user["placa"]),
            ("Tipo de Vehículo", user["tipoVehiculo"].capitalize()),
            ("Marca", user["marca"] or "No especificada"),
            ("Modelo", user["modelo"] or "No especificado"),
            ("Estado", user.get("estado", "activo").capitalize()),
            ("Fecha de Registro", datetime.fromisoformat(user["fechaRegistro"]).strftime("%d/%m/%Y %H:%M"))
        ]
        
        for label, value in details:
            frame = tk.Frame(self.details_frame)
            frame.pack(fill="x", pady=2)
            
            tk.Label(frame, text=f"{label}:", font=("Segoe UI", 9, "bold"), 
                    width=15, anchor="w").pack(side="left")
            tk.Label(frame, text=value, font=("Segoe UI", 9)).pack(side="left")
        
        tk.Label(self.details_frame, text="Observaciones:", 
                font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(10, 0))
        
        obs_frame = tk.Frame(self.details_frame, bd=1, relief="sunken", padx=5, pady=5)
        obs_frame.pack(fill="x")
        
        obs_text = tk.Text(obs_frame, height=4, wrap="word", font=("Segoe UI", 9))
        obs_text.insert("1.0", user["observaciones"] or "No hay observaciones")
        obs_text.config(state="disabled")
        obs_text.pack(fill="x")
        
        btn_frame = tk.Frame(self.details_frame)
        btn_frame.pack(fill="x", pady=(10, 0))
        
        tk.Button(btn_frame, text="Editar", 
                 command=lambda: self.edit_user(user)).pack(side="left", padx=5)
        
        if user.get("estado", "activo") == "activo":
            tk.Button(btn_frame, text="Desactivar", 
                     command=lambda: self.toggle_user_status(user, "inactivo")).pack(side="left", padx=5)
        else:
            tk.Button(btn_frame, text="Activar", 
                     command=lambda: self.toggle_user_status(user, "activo")).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="Eliminar", 
                 command=lambda: self.delete_user(user)).pack(side="left", padx=5)
        
        self.modal_details.title(f"Detalles: {user['nombre']}")
        self.modal_details.deiconify()
    
    def close_user_details_modal(self):
        self.modal_details.withdraw()
    
    def edit_user(self, user=None):
        if not user:
            selected = self.tree.selection()
            if not selected:
                messagebox.showwarning("Advertencia", "Seleccione un usuario")
                return
            
            dni = self.tree.item(selected[0], "values")[0]
            user = next((u for u in self.users if u["dni"] == dni), None)
        
        if not user:
            return
        
        for field, var in self.form_vars.items():
            if isinstance(var, tk.Text):
                var.delete("1.0", "end")
                var.insert("1.0", user.get(field, ""))
            else:
                var.set(user.get(field, ""))
        
        self.modal_add.title(f"Editar Usuario: {user['nombre']}")
        self.form_widgets["dni"].config(state="disabled")
        
        for widget in self.modal_add.winfo_children():
            if isinstance(widget, tk.Frame):
                for btn in widget.winfo_children():
                    if isinstance(btn, tk.Button) and btn["text"] == "Guardar Usuario":
                        btn.config(command=lambda: self.save_user_changes(user))
        
        self.modal_add.deiconify()
    
    def save_user_changes(self, original_user):
        data = {}
        for field, var in self.form_vars.items():
            if isinstance(var, tk.Text):
                data[field] = var.get("1.0", "end").strip()
            else:
                data[field] = var.get().strip()
        
        if not all([data["nombre"], data["telefono"], data["placa"], data["tipoVehiculo"]]):
            messagebox.showerror("Error", "Complete campos requeridos (*)")
            return
        
        if data["correo"] and "@" not in data["correo"]:
            messagebox.showerror("Error", "Correo inválido")
            self.form_widgets["correo"].focus()
            return
        
        if any(u["placa"] == data["placa"].upper() and u["dni"] != original_user["dni"] for u in self.users):
            messagebox.showerror("Error", "Placa ya registrada por otro usuario")
            self.form_widgets["placa"].focus()
            return
        
        for key in original_user:
            if key in data and key != "dni":
                original_user[key] = data[key]
        
        original_user["placa"] = data["placa"].upper()
        
        self.save_data()
        self.update_ui()
        self.close_add_user_modal()
        
        messagebox.showinfo("Éxito", "Usuario actualizado correctamente")
    
    def toggle_user_status(self, user, new_status):
        user["estado"] = new_status
        self.save_data()
        self.update_ui()
        self.show_user_details(user)
        
        messagebox.showinfo("Éxito", f"Usuario {new_status} correctamente")
    
    def delete_user(self, user=None):
        if not user:
            selected = self.tree.selection()
            if not selected:
                messagebox.showwarning("Advertencia", "Seleccione un usuario")
                return
            
            dni = self.tree.item(selected[0], "values")[0]
            user = next((u for u in self.users if u["dni"] == dni), None)
        
        if not user:
            return
        
        if messagebox.askyesno("Confirmar", f"¿Eliminar permanentemente a {user['nombre']}?"):
            self.users = [u for u in self.users if u["dni"] != user["dni"]]
            self.save_data()
            self.update_ui()
            
            if self.modal_details.winfo_viewable():
                self.close_user_details_modal()
            
            messagebox.showinfo("Éxito", "Usuario eliminado correctamente")
    
    def generate_detailed_report(self):
        if not self.users:
            messagebox.showwarning("Advertencia", "No hay datos para generar reporte")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("Excel Files", "*.xlsx"), ("PDF Files", "*.pdf"), ("All Files", "*.*")],
            title="Guardar reporte como"
        )
        
        if not filepath:
            return
        
        try:
            if filepath.endswith(".csv"):
                with open(filepath, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "DNI", "Nombre", "Teléfono", "Correo", "Placa", 
                        "Tipo Vehículo", "Marca", "Modelo", "Observaciones", "Fecha Registro", "Estado"
                    ])
                    
                    for user in self.users:
                        writer.writerow([
                            user["dni"],
                            user["nombre"],
                            user["telefono"],
                            user["correo"] or "",
                            user["placa"],
                            user["tipoVehiculo"],
                            user["marca"] or "",
                            user["modelo"] or "",
                            user["observaciones"] or "",
                            datetime.fromisoformat(user["fechaRegistro"]).strftime("%d/%m/%Y"),
                            user.get("estado", "activo")
                        ])
                
                messagebox.showinfo("Éxito", f"Reporte CSV generado en:\n{filepath}")
            elif filepath.endswith(".pdf"):
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", size=12)
                
                pdf.cell(200, 10, txt="Reporte de Usuarios", ln=1, align='C')
                pdf.ln(10)
                
                pdf.cell(200, 10, txt=f"Generado el: {datetime.now().strftime('%d/%m/%Y %H:%M')}", ln=1)
                pdf.ln(5)
                
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(20, 10, txt="DNI", border=1)
                pdf.cell(50, 10, txt="Nombre", border=1)
                pdf.cell(25, 10, txt="Placa", border=1)
                pdf.cell(25, 10, txt="Tipo", border=1)
                pdf.cell(30, 10, txt="Teléfono", border=1)
                pdf.cell(20, 10, txt="Estado", border=1)
                pdf.ln()
                
                pdf.set_font("Arial", size=10)
                for user in self.users:
                    pdf.cell(20, 10, txt=user["dni"], border=1)
                    pdf.cell(50, 10, txt=user["nombre"], border=1)
                    pdf.cell(25, 10, txt=user["placa"], border=1)
                    pdf.cell(25, 10, txt=user["tipoVehiculo"].capitalize(), border=1)
                    pdf.cell(30, 10, txt=user["telefono"], border=1)
                    pdf.cell(20, 10, txt=user.get("estado", "activo").capitalize(), border=1)
                    pdf.ln()
                
                pdf.output(filepath)
                messagebox.showinfo("Éxito", f"Reporte PDF generado en:\n{filepath}")
            else:
                messagebox.showwarning("Advertencia", "Formato no soportado. Use CSV o PDF.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo generar reporte:\n{str(e)}")
    
    def open_camera_ip(self):
        if hasattr(self, 'camera_window') and self.camera_window.winfo_exists():
            self.camera_window.lift()
            return
        
        self.camera_window = tk.Toplevel(self.root)
        self.camera_window.title("Sistema SRPV - Sistema De Reconocimiento De Placas Vehiculares")
        self.camera_window.geometry("1000x700")
        self.camera_window.protocol("WM_DELETE_WINDOW", self.close_camera_window)
        
        main_frame = ttk.Frame(self.camera_window)
        main_frame.pack(fill='both', expand=1, padx=10, pady=10)
        
        camera_panel = ttk.LabelFrame(main_frame, text="Vista de Cámara")
        camera_panel.pack(fill='both', expand=1, padx=5, pady=5)
        
        self.camera_label = ttk.Label(camera_panel)
        self.camera_label.pack()
        
        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(fill='x', pady=(5, 0))
        
        self.camera_btn = tk.Button(controls_frame, text="Iniciar Cámara", 
                                  command=self.toggle_camera, bg="#020202", 
                                  fg='white', padx=10, pady=5)
        self.camera_btn.pack(side='left', padx=5)
        
        detect_btn = tk.Button(controls_frame, text="Detectar Placa", 
                              command=self.detect_plate_manual, 
                              bg='#3182ce', fg='white', padx=10, pady=5)
        detect_btn.pack(side='left', padx=5)

        cam_select_frame = tk.Frame(controls_frame)
        cam_select_frame.pack(side='left', padx=10)
        
        tk.Label(cam_select_frame, text="Cámara:").pack(side='left')
        self.cam_select = ttk.Combobox(cam_select_frame, values=[f"Cámara {i}" for i in range(4)], width=10)
        self.cam_select.pack(side='left', padx=5)
        
        estatusselectframe = tk.Frame(controls_frame)
        estatusselectframe.pack(side='left', padx=10)
        tk.Label(estatusselectframe, text="Tipo de acceso:").pack(side='left')
        self.estatusselect = ttk.Combobox(estatusselectframe, values=["ENTRADA", "SALIDA"], width=10)
        self.estatusselect.pack(side='left', padx=5)        
        
        last_detection_frame = ttk.LabelFrame(main_frame, text="Última Placa Detectada")
        last_detection_frame.pack(fill=tk.BOTH, pady=(10, 5))
        
        self.detections_list = tk.Listbox(last_detection_frame, bg="#2a2a2a", fg="white", selectbackground="#444")

        self.detections_list.pack(pady=(5, 0),expand=True,fill=tk.BOTH)
        
        self.update_last_detection()
        
        
        self.status_label = ttk.Label(main_frame, text="Estado: Inactivo", 
                                    font=('Arial', 10), foreground='white')
        self.status_label.pack(fill='x', pady=(5, 0))
        
        self.init_camera()
    
    def close_camera_window(self):
        self.stop_camera()
        self.camera_window.destroy()
    
    def init_camera(self):
        try:
            self.cap = cv2.VideoCapture(0)
            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            
            self.camera_thread = threading.Thread(target=self.camera_worker, daemon=True)
            self.camera_thread.start()
            
            self.update_camera_feed()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo inicializar cámara: {str(e)}")
    
    def camera_worker(self):
        while hasattr(self, 'cap') and self.cap is not None:
            if self.camera_active:
                ret, frame = self.cap.read()
                if ret:
                    if not self.frame_queue.empty():
                        try:
                            self.frame_queue.get_nowait()
                        except queue.Empty:
                            pass
                    self.frame_queue.put(frame)
            time.sleep(0.03)
    
    def update_camera_feed(self):
        if hasattr(self, 'camera_window') and self.camera_window.winfo_exists():
            try:
                if not self.frame_queue.empty():
                    frame = self.frame_queue.get_nowait()
                    frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    frame = cv2.resize(frame, (640, 480))
                    
                    img = Image.fromarray(frame)
                    imgtk = ImageTk.PhotoImage(image=img)
                    
                    self.camera_label.imgtk = imgtk
                    self.camera_label.configure(image=imgtk)
                    
                    if self.camera_active and self.anpr_config['enable_auto_scan']:
                        current_time = time.time()
                        if not hasattr(self, 'last_scan_time') or current_time - self.last_scan_time > self.anpr_config['scan_interval']:
                            self.last_scan_time = current_time
                            self.detect_plate_auto(frame)
            
            except queue.Empty:
                pass
            
            self.camera_window.after(10, self.update_camera_feed)
    
    def toggle_camera(self):
        if not self.estatusselect.get()=="":            
            self.camera_active = not self.camera_active            
            if self.camera_active:
                self.camera_btn.config(text="Detener Cámara", bg='#e53e3e')
                self.status_label.config(text="Estado: Cámara activa", foreground='#68d391')
            else:
                self.camera_btn.config(text="Iniciar Cámara", bg='#38a169')
                self.status_label.config(text="Estado: Inactivo", foreground='white')
        else:
            messagebox.showwarning("Advertencia", "Seleccione el estatus primero")
    
    def stop_camera(self):
        self.camera_active = False
        if hasattr(self, 'cap') and self.cap is not None:
            self.cap.release()
            self.cap = None
    
    def detect_plate_manual(self):
        if not self.camera_active:
            messagebox.showwarning("Advertencia", "Active la cámara primero")
            return
        
        if not self.frame_queue.empty():
            frame = self.frame_queue.get_nowait()
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            self.detect_plate_auto(frame)
    
    def detect_plate_auto(self, frame):
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            gray = cv2.blur(gray,(3,3))
            canny = cv2.Canny(gray,50,100)
            canny = cv2.dilate(canny,None,iterations=1)

            cnts,_ = cv2.findContours(canny,cv2.RETR_LIST,cv2.CHAIN_APPROX_SIMPLE)

            cv2.drawContours(frame,cnts,-1,(0,255,0),2)
            
            for c in cnts:
                area = cv2.contourArea(c)
                
                x,y,w,h = cv2.boundingRect(c)
                
                epsilon = 0.1*cv2.arcLength(c,True)
                approx = cv2.approxPolyDP(c,epsilon,True)
                
                if area>9000:  
                    
                    cv2.drawContours(frame,[approx],0,(0,255,0),3)
                    
                    aspect_ratio = float(w)/h
                    
                    if 1.2 < aspect_ratio < 4:      
                        
                        placa = gray[y:y+h,x:x+w]
                        
                        r = pytesseract.image_to_data(placa,config='--oem 3 --psm 11',output_type=pytesseract.Output.DICT)
                        
                        
                        patron1 = re.compile(pattern="^([0-9][0-9][0-9][0-9]-[0-9A-Z])")
                        patron2 = re.compile(pattern="([0-9A-Z][0-9A-Z][0-9A-Z]-[0-9][0-9][0-9])+$")
                        now = datetime.now()
                        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
                        for indice,texto in enumerate( r["text"]):
                        
                            if patron1.match(texto)  and len(texto)>5:          
                                texto = str(texto)[0:6]+"X"
                                result = {
                                    'plate': texto,
                                    'timestamp': timestamp,
                                    'confidence': str(r["conf"][indice])+"%",
                                    'image': None,
                                    'estatus': self.estatusselect.get()
                                }                                

                                self.scan_results.append(result)
                                self.current_plate = result
                                self.update_last_detection()    

                                if self.anpr_config['enable_alerts']:
                                    self.root.bell()                                
                                self.status_label.config(text=f"Placa detectada: {texto}", 
                                                    foreground='#68d391')                                
                                self.check_plate_against_lists(texto)                                            
                                return 0
                            
                            elif patron2.match(texto)  and len(texto)>5:
                                result = {
                                    'plate': texto,
                                    'timestamp': timestamp,
                                    'confidence': str(r["conf"][indice])+"%",
                                    'image': None,
                                    'estatus': self.estatusselect.get()                           
                                }

                                self.scan_results.append(result)
                                self.current_plate = result
                                self.update_last_detection()    

                                if self.anpr_config['enable_alerts']:
                                    self.root.bell()                                
                                self.status_label.config(text=f"Placa detectada: {texto}", 
                                                    foreground='#68d391')                                
                                self.check_plate_against_lists(texto)                                            
                                return 0

        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}", foreground='#fc8181')
    
    def check_plate_against_lists(self, plate):
        plate = plate.upper()
        
        if any(b["placa"] == plate for b in self.blacklist):
            messagebox.showwarning("ALERTA", f"Placa {plate} en lista negra!")
            return
        
        if any(w["placa"] == plate for w in self.whitelist):
            messagebox.showinfo("Información", f"Placa {plate} en lista blanca - Acceso permitido")
            return
        
        user = next((u for u in self.users if u["placa"] == plate), None)
        if user:
            status = user.get("estado", "activo")
            if status == "activo":
                messagebox.showinfo("Información", f"Placa {plate} registrada - Acceso permitido")
            else:
                messagebox.showwarning("ALERTA", f"Placa {plate} registrada pero INACTIVA")
        else:
            messagebox.showwarning("Advertencia", f"Placa {plate} no registrada en el sistema")
    
    def update_last_detection(self):
        
        self.detections_list.delete(0,tk.END)
        resultados = sorted(self.scan_results,key=lambda x:x["timestamp"],reverse=True)
        for i, plate in enumerate(resultados, 1):
            self.detections_list.insert(tk.END, f"{i}. {plate['plate']} - {plate['timestamp']} - {plate['estatus']}")
            
    
    def open_auto_scan(self):
        if hasattr(self, 'auto_scan_window') and self.auto_scan_window.winfo_exists():
            self.auto_scan_window.lift()
            return
        
        self.auto_scan_window = tk.Toplevel(self.root)
        self.auto_scan_window.title("Escaneo Automático de Placas")
        self.auto_scan_window.geometry("800x600")
        self.auto_scan_window.protocol("WM_DELETE_WINDOW", self.close_auto_scan_window)
        
        main_frame = ttk.Frame(self.auto_scan_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        camera_frame = ttk.LabelFrame(main_frame, text="Configuración de Cámaras", padding=10)
        camera_frame.pack(fill=tk.X, pady=10)
        
        ip_frame = ttk.Frame(camera_frame)
        ip_frame.pack(fill=tk.X, pady=5)
        
        self.camera_ip_entry = ttk.Entry(ip_frame)
        self.camera_ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.camera_ip_entry.insert(0, "rtsp://usuario:contraseña@ip:puerto/camara")
        
        add_button = ttk.Button(ip_frame, text="+", command=self.add_camera, style='Green.TButton')
        add_button.pack(side=tk.LEFT)
        
        self.scan_status_label = ttk.Label(camera_frame, text="", foreground="#ff6b6b")
        self.scan_status_label.pack(pady=5)
        
        cameras_connected_label = ttk.Label(camera_frame, text="Cámaras Conectadas:", 
                                          style='Subheader.TLabel')
        cameras_connected_label.pack(pady=(10, 5), anchor=tk.W)
        
        self.camera_listbox = tk.Listbox(camera_frame, bg="#2a2a2a", fg="white", 
                                       selectbackground="#444")
        self.camera_listbox.pack(fill=tk.X, pady=5)
        
        cam_btn_frame = tk.Frame(camera_frame)
        cam_btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(cam_btn_frame, text="Eliminar seleccionada", 
                  command=self.remove_camera).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(cam_btn_frame, text="Probar conexión", 
                  command=self.test_camera).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        scan_frame = ttk.LabelFrame(main_frame, text="Iniciar Escaneo Automático", padding=10)
        scan_frame.pack(fill=tk.X, pady=10)
        
        self.camera_combobox = ttk.Combobox(scan_frame, state="readonly")
        self.camera_combobox.pack(fill=tk.X, pady=5)
        
        interval_frame = tk.Frame(scan_frame)
        interval_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(interval_frame, text="Intervalo de escaneo (segundos):").pack(side=tk.LEFT)
        self.scan_interval_var = tk.StringVar(value=str(self.anpr_config['scan_interval']))
        tk.Entry(interval_frame, textvariable=self.scan_interval_var, width=5).pack(side=tk.LEFT, padx=5)
        
        button_frame = ttk.Frame(scan_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="Iniciar Escaneo", 
                  command=self.start_auto_scanning, style='Blue.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(button_frame, text="Detener Escaneo", 
                  command=self.stop_auto_scanning, style='Red.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.scan_error_label = ttk.Label(scan_frame, text="", foreground="#ff6b6b")
        self.scan_error_label.pack(pady=5)
        
        data_frame = ttk.LabelFrame(main_frame, text="Datos Almacenados", padding=10)
        data_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        search_data_frame = tk.Frame(data_frame)
        search_data_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(search_data_frame, text="Buscar:").pack(side=tk.LEFT)
        self.search_data_entry = tk.Entry(search_data_frame)
        self.search_data_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.search_data_entry.bind("<KeyRelease>", self.search_in_results)
        
        self.data_listbox = tk.Listbox(data_frame, bg="#2a2a2a", fg="white", selectbackground="#444")
        self.data_listbox.pack(fill=tk.BOTH, expand=True)
        
        export_frame = tk.Frame(main_frame)
        export_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(export_frame, text="Descargar Historial en PDF", 
                  command=self.download_history, style='Yellow.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(export_frame, text="Exportar a CSV", 
                  command=self.export_to_csv).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        footer_label = ttk.Label(main_frame, 
                               text=f"{APP_NAME} {APP_VERSION} | {DEVELOPER}", 
                               foreground="#a1a1a1")
        footer_label.pack(pady=10)
        
        self.update_camera_list()
        self.update_data_list()
    
    def close_auto_scan_window(self):
        self.stop_auto_scanning()
        self.auto_scan_window.destroy()
    
    def add_camera(self):
        ip_input = self.camera_ip_entry.get().strip()
        
        if not ip_input or ip_input == "rtsp://usuario:contraseña@ip:puerto/camara":
            self.scan_status_label.config(text="Por favor, ingrese una dirección de cámara válida")
            return
            
        if not ip_input.startswith("rtsp://"):
            self.scan_status_label.config(text="La dirección debe comenzar con rtsp://")
            return
            
        if ip_input in self.cameras:
            self.scan_status_label.config(text="Esta cámara ya está registrada")
            return
            
        self.cameras.append(ip_input)
        self.save_data()
        self.update_camera_list()
        self.camera_ip_entry.delete(0, tk.END)
        self.scan_status_label.config(text="Cámara agregada - Configure usuario/contraseña si es necesario")
    
    def remove_camera(self):
        selection = self.camera_listbox.curselection()
        if not selection:
            return
            
        index = selection[0]
        if 0 <= index < len(self.cameras):
            self.cameras.pop(index)
            self.save_data()
            self.update_camera_list()
    
    def test_camera(self):
        selection = self.camera_listbox.curselection()
        if not selection:
            messagebox.showwarning("Advertencia", "Seleccione una cámara primero")
            return
            
        camera_url = self.cameras[selection[0]]
        
        try:
            cap = cv2.VideoCapture(camera_url)
            if cap.isOpened():
                ret, frame = cap.read()
                cap.release()
                
                if ret:
                    messagebox.showinfo("Éxito", "Cámara conectada correctamente")
                else:
                    messagebox.showerror("Error", "No se pudo obtener imagen de la cámara")
            else:
                messagebox.showerror("Error", "No se pudo conectar a la cámara")
        except Exception as e:
            messagebox.showerror("Error", f"Error al conectar con la cámara: {str(e)}")
    
    def update_camera_list(self):
        self.camera_listbox.delete(0, tk.END)
        self.camera_combobox['values'] = self.cameras
        
        for camera in self.cameras:
            self.camera_listbox.insert(tk.END, camera)
    
    def update_data_list(self):
        self.data_listbox.delete(0, tk.END)
        
        for i, plate in enumerate(self.scan_results, 1):
            self.data_listbox.insert(tk.END, f"{i}. {plate['plate']} - {plate['timestamp']} - {plate['estatus']}")
    
    def search_in_results(self, event=None):
        term = self.search_data_entry.get().lower()
        
        if not term:
            self.update_data_list()
            return
            
        self.data_listbox.delete(0, tk.END)
        
        for i, plate in enumerate(self.scan_results, 1):
            if term in plate['plate'].lower() or term in plate['timestamp'].lower():
                self.data_listbox.insert(tk.END, f"{i}. {plate['plate']} - {plate['timestamp']}")
    
    def start_auto_scanning(self):
        selected_camera = self.camera_combobox.get()
        
        if not selected_camera:
            self.scan_error_label.config(text="Por favor, seleccione una cámara")
            return
        
        try:
            self.anpr_config['scan_interval'] = int(self.scan_interval_var.get())
            if self.anpr_config['scan_interval'] < 1:
                raise ValueError
        except ValueError:
            self.scan_error_label.config(text="Intervalo debe ser un número entero positivo")
            return
            
        if self.scanning_active:
            self.scan_error_label.config(text="El escaneo ya está en progreso")
            return
            
        self.scanning_active = True
        self.scan_error_label.config(text="Escaneo automático iniciado...", foreground="green")
        
        scan_thread = threading.Thread(target=self.auto_scan_worker, args=(selected_camera,), daemon=True)
        scan_thread.start()
    
    def auto_scan_worker(self, camera_url):
        try:
            cap = cv2.VideoCapture(camera_url)
            
            while self.scanning_active and cap.isOpened():
                ret, frame = cap.read()
                if ret:
                    self.process_frame_for_plate(frame)
                
                time.sleep(self.anpr_config['scan_interval'])
            
            cap.release()
        except Exception as e:
            self.scan_error_label.config(text=f"Error: {str(e)}", foreground="red")
            self.scanning_active = False
    
    def process_frame_for_plate(self, frame):
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            
            # Aplicar el algoritmo de Canny para detección de bordes
            edges = cv2.Canny(gray, self.anpr_config['canny_threshold1'], 
                             self.anpr_config['canny_threshold2'])
            
            if self.anpr_config['preprocessing']:
                gray = cv2.GaussianBlur(gray, (5, 5), 0)
                _, gray = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            
            plates = []
            
            if self.anpr_config['contour_detection']:
                # Usar los bordes detectados por Canny para encontrar contornos
                contours, _ = cv2.findContours(edges.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                
                for contour in contours:
                    area = cv2.contourArea(contour)
                    if area > 1000:
                        x, y, w, h = cv2.boundingRect(contour)
                        aspect_ratio = w / h
                        if 2 < aspect_ratio < 5:
                            plates.append((x, y, w, h))
            else:
                plates.append((0, 0, gray.shape[1], gray.shape[0]))
            
            best_plate = None
            
            if self.anpr_config['ocr_enabled']:
                for (x, y, w, h) in plates:
                    plate_roi = gray[y:y+h, x:x+w]
                    plate_roi = cv2.convertScaleAbs(plate_roi, alpha=1.5, beta=-50)
                    
                    custom_config = f'--oem 3 --psm 6 -c tessedit_char_whitelist={self.anpr_config["ocr_whitelist"]}'
                    result = pytesseract.image_to_data(plate_roi, config=custom_config, 
                                                     output_type=pytesseract.Output.DICT)
                    
                    for i in range(len(result['text'])):
                        text = result['text'][i].strip()
                        conf = int(result['conf'][i]) if result['conf'][i] != '-1' else 0
                        
                        if len(text) >= 6 and conf > self.anpr_config['min_confidence']:
                            if not best_plate or conf > best_plate['confidence']:
                                best_plate = {
                                    'text': text,
                                    'confidence': conf,
                                    'coordinates': (x, y, w, h)
                                }
            
            if best_plate:
                now = datetime.now()
                timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
                
                result = {
                    'plate': best_plate['text'],
                    'timestamp': timestamp,
                    'confidence': best_plate['confidence'],
                    'camera': camera_url
                }
                
                self.auto_scan_window.after(0, lambda: self.add_scan_result(result))
        except Exception as e:
            print(f"Error processing frame: {str(e)}")
    
    def add_scan_result(self, result):
        self.scan_results.append(result)
        self.save_data()
        self.update_data_list()
        
        self.scan_error_label.config(text=f"Placa detectada: {result['plate']}", foreground="green")
        
        self.check_plate_against_lists(result['plate'])
    
    def stop_auto_scanning(self):
        self.scanning_active = False
        self.scan_error_label.config(text="Escaneo automático detenido", foreground="white")
    
    def download_history(self):
        if not self.scan_results:
            messagebox.showwarning("Advertencia", "No hay datos para exportar")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")],
            title="Guardar historial como PDF"
        )
        
        if not file_path:
            return
            
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            
            pdf.cell(200, 10, txt="Historial de Escaneos de Placas", ln=1, align='C')
            pdf.ln(10)
            
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(40, 10, txt="Placa", border=1)
            pdf.cell(50, 10, txt="Fecha/Hora", border=1)
            pdf.cell(30, 10, txt="Confianza", border=1)
            pdf.cell(70, 10, txt="Cámara", border=1)
            pdf.ln()
            
            pdf.set_font("Arial", size=10)
            for plate in self.scan_results:
                pdf.cell(40, 10, txt=plate['plate'], border=1)
                pdf.cell(50, 10, txt=plate['timestamp'], border=1)
                pdf.cell(30, 10, txt=f"{plate.get('confidence', 'N/A')}%", border=1)
                pdf.cell(70, 10, txt=plate.get('camera', 'Local'), border=1)
                pdf.ln()
            
            pdf.output(file_path)
            messagebox.showinfo("Éxito", f"Historial exportado a {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo exportar el PDF: {e}")
    
    def export_to_csv(self):
        if not self.scan_results:
            messagebox.showwarning("Advertencia", "No hay datos para exportar")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Guardar historial como CSV"
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Placa', 'Fecha/Hora', 'Confianza', 'Cámara'])
                
                for plate in self.scan_results:
                    writer.writerow([
                        plate['plate'],
                        plate['timestamp'],
                        plate.get('confidence', 'N/A'),
                        plate.get('camera', 'Local')
                    ])
            
            messagebox.showinfo("Éxito", f"Historial exportado a {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo exportar el CSV: {e}")
    
    def open_configuration(self):
        config_window = tk.Toplevel(self.root)
        config_window.title("Configuración del Sistema")
        config_window.geometry("700x500")
        
        notebook = ttk.Notebook(config_window)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        self.setup_ocr_config_tab(notebook)
        self.setup_notifications_tab(notebook)
        self.setup_lists_tab(notebook)
        self.setup_canny_tab(notebook)
        
        btn_frame = ttk.Frame(config_window)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Cancelar", command=config_window.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Guardar", command=lambda: self.save_config(config_window)).pack(side=tk.RIGHT)
    
    def setup_canny_tab(self, notebook):
        canny_frame = ttk.Frame(notebook)
        notebook.add(canny_frame, text="Canny Edge")
        
        ttk.Label(canny_frame, text="Configuración del Algoritmo de Canny", 
                 font=('Arial', 12, 'bold')).pack(pady=10, anchor=tk.W)
        
        ttk.Label(canny_frame, text="Umbral inferior:").pack(anchor=tk.W, pady=5)
        self.canny_threshold1_var = tk.StringVar(value=str(self.anpr_config['canny_threshold1']))
        ttk.Entry(canny_frame, textvariable=self.canny_threshold1_var).pack(anchor=tk.W, fill=tk.X, pady=5)
        
        ttk.Label(canny_frame, text="Umbral superior:").pack(anchor=tk.W, pady=5)
        self.canny_threshold2_var = tk.StringVar(value=str(self.anpr_config['canny_threshold2']))
        ttk.Entry(canny_frame, textvariable=self.canny_threshold2_var).pack(anchor=tk.W, fill=tk.X, pady=5)
        
        ttk.Label(canny_frame, text="Nota: El algoritmo de Canny se usa para detectar bordes en las placas.", 
                 font=('Arial', 9)).pack(anchor=tk.W, pady=10)
    
    def setup_ocr_config_tab(self, notebook):
        ocr_frame = ttk.Frame(notebook)
        notebook.add(ocr_frame, text="Configuración OCR")
        
        ttk.Label(ocr_frame, text="Configuración de Reconocimiento Óptico de Caracteres", 
                 font=('Arial', 12, 'bold')).pack(pady=10, anchor=tk.W)
        
        self.preprocess_var = tk.IntVar(value=self.anpr_config['preprocessing'])
        ttk.Checkbutton(ocr_frame, text="Habilitar preprocesamiento de imagen", 
                       variable=self.preprocess_var).pack(anchor=tk.W, pady=5)
        
        self.contour_var = tk.IntVar(value=self.anpr_config['contour_detection'])
        ttk.Checkbutton(ocr_frame, text="Habilitar detección de contornos", 
                       variable=self.contour_var).pack(anchor=tk.W, pady=5)
        
        ttk.Label(ocr_frame, text="Idioma para OCR:").pack(anchor=tk.W, pady=5)
        self.lang_var = tk.StringVar(value=self.anpr_config['ocr_language'])
        lang_combo = ttk.Combobox(ocr_frame, textvariable=self.lang_var, 
                                 values=['eng', 'spa', 'por', 'fra'])
        lang_combo.pack(anchor=tk.W, fill=tk.X, pady=5)
        
        ttk.Label(ocr_frame, text="Caracteres permitidos:").pack(anchor=tk.W, pady=5)
        self.whitelist_var = tk.StringVar(value=self.anpr_config['ocr_whitelist'])
        ttk.Entry(ocr_frame, textvariable=self.whitelist_var).pack(anchor=tk.W, fill=tk.X, pady=5)
        
        ttk.Label(ocr_frame, text="Confianza mínima (%):").pack(anchor=tk.W, pady=5)
        self.min_conf_var = tk.StringVar(value=str(self.anpr_config['min_confidence']))
        ttk.Entry(ocr_frame, textvariable=self.min_conf_var).pack(anchor=tk.W, fill=tk.X, pady=5)
    
    def setup_notifications_tab(self, notebook):
        notif_frame = ttk.Frame(notebook)
        notebook.add(notif_frame, text="Notificaciones")
        
        ttk.Label(notif_frame, text="Configuración de Notificaciones", 
                 font=('Arial', 12, 'bold')).pack(pady=10, anchor=tk.W)
        
        self.alert_var = tk.IntVar(value=self.anpr_config['enable_alerts'])
        ttk.Checkbutton(notif_frame, text="Habilitar alertas sonoras", 
                       variable=self.alert_var).pack(anchor=tk.W, pady=5)
        
        self.auto_scan_var = tk.IntVar(value=self.anpr_config['enable_auto_scan'])
        ttk.Checkbutton(notif_frame, text="Habilitar escaneo automático", 
                       variable=self.auto_scan_var).pack(anchor=tk.W, pady=5)
        
        ttk.Label(notif_frame, text="Intervalo de escaneo automático (segundos):").pack(anchor=tk.W, pady=5)
        self.scan_int_var = tk.StringVar(value=str(self.anpr_config['scan_interval']))
        ttk.Entry(notif_frame, textvariable=self.scan_int_var).pack(anchor=tk.W, fill=tk.X, pady=5)
        
        ttk.Label(notif_frame, text="Notificaciones por correo:", 
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(20, 5))
        
        self.email_notif_var = tk.IntVar(value=0)
        ttk.Checkbutton(notif_frame, text="Habilitar notificaciones por correo", 
                       variable=self.email_notif_var).pack(anchor=tk.W, pady=5)
        
        ttk.Label(notif_frame, text="Servidor SMTP:").pack(anchor=tk.W, pady=5)
        self.smtp_server_var = tk.StringVar()
        ttk.Entry(notif_frame, textvariable=self.smtp_server_var).pack(anchor=tk.W, fill=tk.X, pady=5)
        
        ttk.Label(notif_frame, text="Puerto:").pack(anchor=tk.W, pady=5)
        self.smtp_port_var = tk.StringVar()
        ttk.Entry(notif_frame, textvariable=self.smtp_port_var).pack(anchor=tk.W, fill=tk.X, pady=5)
        
        ttk.Label(notif_frame, text="Correo electrónico:").pack(anchor=tk.W, pady=5)
        self.smtp_email_var = tk.StringVar()
        ttk.Entry(notif_frame, textvariable=self.smtp_email_var).pack(anchor=tk.W, fill=tk.X, pady=5)
        
        ttk.Label(notif_frame, text="Contraseña:").pack(anchor=tk.W, pady=5)
        self.smtp_pass_var = tk.StringVar()
        ttk.Entry(notif_frame, textvariable=self.smtp_pass_var, show="*").pack(anchor=tk.W, fill=tk.X, pady=5)
        
        ttk.Label(notif_frame, text="Destinatarios (separados por coma):").pack(anchor=tk.W, pady=5)
        self.smtp_recipients_var = tk.StringVar()
        ttk.Entry(notif_frame, textvariable=self.smtp_recipients_var).pack(anchor=tk.W, fill=tk.X, pady=5)
    
    def setup_lists_tab(self, notebook):
        lists_frame = ttk.Frame(notebook)
        notebook.add(lists_frame, text="Listas")
        
        blacklist_frame = ttk.LabelFrame(lists_frame, text="Lista Negra", padding=10)
        blacklist_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.blacklist_listbox = tk.Listbox(blacklist_frame, bg="#2a2a2a", fg="white", selectbackground="#444")
        self.blacklist_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        blacklist_btn_frame = tk.Frame(blacklist_frame)
        blacklist_btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5)
        
        ttk.Button(blacklist_btn_frame, text="Agregar", 
                  command=self.add_to_blacklist).pack(fill=tk.X, pady=2)
        ttk.Button(blacklist_btn_frame, text="Eliminar", 
                  command=self.remove_from_blacklist).pack(fill=tk.X, pady=2)
        
        whitelist_frame = ttk.LabelFrame(lists_frame, text="Lista Blanca", padding=10)
        whitelist_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.whitelist_listbox = tk.Listbox(whitelist_frame, bg="#2a2a2a", fg="white", selectbackground="#444")
        self.whitelist_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        whitelist_btn_frame = tk.Frame(whitelist_frame)
        whitelist_btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5)
        
        ttk.Button(whitelist_btn_frame, text="Agregar", 
                  command=self.add_to_whitelist).pack(fill=tk.X, pady=2)
        ttk.Button(whitelist_btn_frame, text="Eliminar", 
                  command=self.remove_from_whitelist).pack(fill=tk.X, pady=2)
        
        self.update_blacklist()
        self.update_whitelist()
    
    def add_to_blacklist(self):
        plate = simpledialog.askstring("Agregar a lista negra", "Ingrese la placa:")
        if plate:
            plate = plate.upper()
            if not any(b["placa"] == plate for b in self.blacklist):
                self.blacklist.append({"placa": plate, "timestamp": datetime.now().isoformat()})
                self.save_data()
                self.update_blacklist()
    
    def remove_from_blacklist(self):
        selection = self.blacklist_listbox.curselection()
        if selection:
            index = selection[0]
            if 0 <= index < len(self.blacklist):
                self.blacklist.pop(index)
                self.save_data()
                self.update_blacklist()
    
    def update_blacklist(self):
        self.blacklist_listbox.delete(0, tk.END)
        for item in self.blacklist:
            self.blacklist_listbox.insert(tk.END, f"{item['placa']} - {item['timestamp']}")
    
    def add_to_whitelist(self):
        plate = simpledialog.askstring("Agregar a lista blanca", "Ingrese la placa:")
        if plate:
            plate = plate.upper()
            if not any(w["placa"] == plate for w in self.whitelist):
                self.whitelist.append({"placa": plate, "timestamp": datetime.now().isoformat()})
                self.save_data()
                self.update_whitelist()
    
    def remove_from_whitelist(self):
        selection = self.whitelist_listbox.curselection()
        if selection:
            index = selection[0]
            if 0 <= index < len(self.whitelist):
                self.whitelist.pop(index)
                self.save_data()
                self.update_whitelist()
    
    def update_whitelist(self):
        self.whitelist_listbox.delete(0, tk.END)
        for item in self.whitelist:
            self.whitelist_listbox.insert(tk.END, f"{item['placa']} - {item['timestamp']}")
    
    def save_config(self, window):
        try:
            self.anpr_config = {
                'preprocessing': self.preprocess_var.get(),
                'contour_detection': self.contour_var.get(),
                'ocr_enabled': 1,
                'enable_alerts': self.alert_var.get(),
                'enable_auto_scan': self.auto_scan_var.get(),
                'ocr_language': self.lang_var.get(),
                'ocr_whitelist': self.whitelist_var.get(),
                'scan_interval': int(self.scan_int_var.get()),
                'min_confidence': int(self.min_conf_var.get()),
                'canny_threshold1': int(self.canny_threshold1_var.get()),
                'canny_threshold2': int(self.canny_threshold2_var.get())
            }
            
            self.save_data()
            messagebox.showinfo("Éxito", "Configuración guardada correctamente")
            window.destroy()
        except ValueError:
            messagebox.showerror("Error", "Por favor ingrese valores numéricos válidos")
    
    def open_reports(self):
        report_window = tk.Toplevel(self.root)
        report_window.title("Generar Reportes")
        report_window.geometry("600x400")
        
        date_frame = ttk.LabelFrame(report_window, text="Rango de Fechas", padding=10)
        date_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(date_frame, text="Desde:").pack(side=tk.LEFT)
        self.start_date_entry = ttk.Entry(date_frame)
        self.start_date_entry.pack(side=tk.LEFT, padx=5)
        self.start_date_entry.insert(0, datetime.now().strftime("%d/%m/%Y"))
        
        tk.Label(date_frame, text="Hasta:").pack(side=tk.LEFT, padx=(10, 0))
        self.end_date_entry = ttk.Entry(date_frame)
        self.end_date_entry.pack(side=tk.LEFT, padx=5)
        self.end_date_entry.insert(0, datetime.now().strftime("%d/%m/%Y"))
        
        type_frame = ttk.LabelFrame(report_window, text="Tipo de Reporte", padding=10)
        type_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.report_type_var = tk.StringVar(value="scans")
        
        ttk.Radiobutton(type_frame, text="Escaneos de placas", 
                       variable=self.report_type_var, value="scans").pack(anchor=tk.W)
        ttk.Radiobutton(type_frame, text="Registros de usuarios", 
                       variable=self.report_type_var, value="users").pack(anchor=tk.W)
        ttk.Radiobutton(type_frame, text="Actividad del sistema", 
                       variable=self.report_type_var, value="activity").pack(anchor=tk.W)
        
        format_frame = ttk.LabelFrame(report_window, text="Formato", padding=10)
        format_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.report_format_var = tk.StringVar(value="pdf")
        
        ttk.Radiobutton(format_frame, text="PDF", 
                       variable=self.report_format_var, value="pdf").pack(anchor=tk.W)
        ttk.Radiobutton(format_frame, text="CSV", 
                       variable=self.report_format_var, value="csv").pack(anchor=tk.W)
        ttk.Radiobutton(format_frame, text="Excel", 
                       variable=self.report_format_var, value="excel").pack(anchor=tk.W)
        
        ttk.Button(report_window, text="Generar Reporte", 
                  command=self.generate_report).pack(pady=20)
    
    def generate_report(self):
        try:
            start_date = datetime.strptime(self.start_date_entry.get(), "%d/%m/%Y")
            end_date = datetime.strptime(self.end_date_entry.get(), "%d/%m/%Y")
            
            if start_date > end_date:
                messagebox.showerror("Error", "La fecha de inicio debe ser anterior a la fecha final")
                return
        except ValueError:
            messagebox.showerror("Error", "Formato de fecha inválido. Use DD/MM/AAAA")
            return
        
        report_type = self.report_type_var.get()
        report_format = self.report_format_var.get()
        
        filtered_data = []
        if report_type == "scans":
            for scan in self.scan_results:
                scan_date = datetime.fromisoformat(scan["timestamp"]).date()
                if start_date.date() <= scan_date <= end_date.date():
                    filtered_data.append(scan)
        elif report_type == "users":
            for user in self.users:
                reg_date = datetime.fromisoformat(user["fechaRegistro"]).date()
                if start_date.date() <= reg_date <= end_date.date():
                    filtered_data.append(user)
        
        if not filtered_data:
            messagebox.showwarning("Advertencia", "No hay datos en el rango de fechas seleccionado")
            return
        
        file_types = []
        default_ext = ""
        if report_format == "pdf":
            file_types = [("PDF Files", "*.pdf")]
            default_ext = ".pdf"
        elif report_format == "csv":
            file_types = [("CSV Files", "*.csv")]
            default_ext = ".csv"
        elif report_format == "excel":
            file_types = [("Excel Files", "*.xlsx")]
            default_ext = ".xlsx"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=file_types,
            title=f"Guardar reporte como {report_format.upper()}"
        )
        
        if not file_path:
            return
        
        try:
            if report_format == "pdf":
                self.generate_pdf_report(filtered_data, file_path, report_type, start_date, end_date)
            elif report_format == "csv":
                self.generate_csv_report(filtered_data, file_path, report_type)
            elif report_format == "excel":
                self.generate_excel_report(filtered_data, file_path, report_type)
            
            messagebox.showinfo("Éxito", f"Reporte generado en:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo generar el reporte:\n{str(e)}")
    
    def generate_pdf_report(self, data, file_path, report_type, start_date, end_date):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        title = {
            "scans": "Reporte de Escaneos de Placas",
            "users": "Reporte de Registros de Usuarios",
            "activity": "Reporte de Actividad del Sistema"
        }.get(report_type, "Reporte")
        
        pdf.cell(200, 10, txt=title, ln=1, align='C')
        pdf.ln(5)
        
        pdf.cell(200, 10, txt=f"Desde: {start_date.strftime('%d/%m/%Y')} - Hasta: {end_date.strftime('%d/%m/%Y')}", ln=1)
        pdf.ln(10)
        
        if report_type == "scans":
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(40, 10, txt="Placa", border=1)
            pdf.cell(50, 10, txt="Fecha/Hora", border=1)
            pdf.cell(30, 10, txt="Confianza", border=1)
            pdf.cell(70, 10, txt="Cámara", border=1)
            pdf.ln()
            
            pdf.set_font("Arial", size=10)
            for item in data:
                pdf.cell(40, 10, txt=item['plate'], border=1)
                pdf.cell(50, 10, txt=item['timestamp'], border=1)
                pdf.cell(30, 10, txt=f"{item.get('confidence', 'N/A')}%", border=1)
                pdf.cell(70, 10, txt=item.get('camera', 'Local'), border=1)
                pdf.ln()
        
        elif report_type == "users":
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(30, 10, txt="DNI", border=1)
            pdf.cell(60, 10, txt="Nombre", border=1)
            pdf.cell(30, 10, txt="Placa", border=1)
            pdf.cell(30, 10, txt="Tipo", border=1)
            pdf.cell(40, 10, txt="Fecha Registro", border=1)
            pdf.ln()
            
            pdf.set_font("Arial", size=10)
            for item in data:
                pdf.cell(30, 10, txt=item['dni'], border=1)
                pdf.cell(60, 10, txt=item['nombre'], border=1)
                pdf.cell(30, 10, txt=item['placa'], border=1)
                pdf.cell(30, 10, txt=item['tipoVehiculo'].capitalize(), border=1)
                pdf.cell(40, 10, txt=datetime.fromisoformat(item['fechaRegistro']).strftime('%d/%m/%Y'), border=1)
                pdf.ln()
        
        pdf.output(file_path)
    
    def generate_csv_report(self, data, file_path, report_type):
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            if report_type == "scans":
                writer = csv.writer(f)
                writer.writerow(['Placa', 'Fecha/Hora', 'Confianza', 'Cámara'])
                
                for item in data:
                    writer.writerow([
                        item['plate'],
                        item['timestamp'],
                        item.get('confidence', 'N/A'),
                        item.get('camera', 'Local')
                    ])
            elif report_type == "users":
                writer = csv.writer(f)
                writer.writerow(['DNI', 'Nombre', 'Teléfono', 'Correo', 'Placa', 
                                'Tipo Vehículo', 'Marca', 'Modelo', 'Fecha Registro', 'Estado'])
                
                for item in data:
                    writer.writerow([
                        item['dni'],
                        item['nombre'],
                        item['telefono'],
                        item.get('correo', ''),
                        item['placa'],
                        item['tipoVehiculo'],
                        item.get('marca', ''),
                        item.get('modelo', ''),
                        datetime.fromisoformat(item['fechaRegistro']).strftime('%d/%m/%Y'),
                        item.get('estado', 'activo')
                    ])
    
    def generate_excel_report(self, data, file_path, report_type):
        self.generate_csv_report(data, file_path, report_type)
    
    def open_filters(self):
        filter_window = tk.Toplevel(self.root)
        filter_window.title("Filtros Avanzados")
        filter_window.geometry("500x400")
        
        ttk.Label(filter_window, text="Filtros Avanzados", 
                 font=('Arial', 12, 'bold')).pack(pady=10)
        
        type_frame = ttk.LabelFrame(filter_window, text="Tipo de Vehículo", padding=10)
        type_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.filter_type_var = tk.StringVar(value="all")
        
        ttk.Radiobutton(type_frame, text="Todos", 
                       variable=self.filter_type_var, value="all").pack(anchor=tk.W)
        ttk.Radiobutton(type_frame, text="Automóviles", 
                       variable=self.filter_type_var, value="auto").pack(anchor=tk.W)
        ttk.Radiobutton(type_frame, text="Camionetas", 
                       variable=self.filter_type_var, value="camioneta").pack(anchor=tk.W)
        ttk.Radiobutton(type_frame, text="Motocicletas", 
                       variable=self.filter_type_var, value="moto").pack(anchor=tk.W)
        
        status_frame = ttk.LabelFrame(filter_window, text="Estado", padding=10)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.filter_status_var = tk.StringVar(value="all")
        
        ttk.Radiobutton(status_frame, text="Todos", 
                       variable=self.filter_status_var, value="all").pack(anchor=tk.W)
        ttk.Radiobutton(status_frame, text="Activos", 
                       variable=self.filter_status_var, value="active").pack(anchor=tk.W)
        ttk.Radiobutton(status_frame, text="Inactivos", 
                       variable=self.filter_status_var, value="inactive").pack(anchor=tk.W)
        
        date_frame = ttk.LabelFrame(filter_window, text="Rango de Fechas", padding=10)
        date_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(date_frame, text="Desde:").pack(side=tk.LEFT)
        self.filter_start_date = ttk.Entry(date_frame)
        self.filter_start_date.pack(side=tk.LEFT, padx=5)
        
        tk.Label(date_frame, text="Hasta:").pack(side=tk.LEFT, padx=(10, 0))
        self.filter_end_date = ttk.Entry(date_frame)
        self.filter_end_date.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(filter_window, text="Aplicar Filtros", 
                  command=self.apply_filters).pack(pady=20)
    
    def apply_filters(self):
        messagebox.showinfo("Información", "Funcionalidad de filtros en desarrollo")
    
    def open_help(self):
        help_window = tk.Toplevel(self.root)
        help_window.title(f"Ayuda de {APP_NAME}")
        help_window.geometry("600x500")
        
        notebook = ttk.Notebook(help_window)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        manual_frame = ttk.Frame(notebook)
        notebook.add(manual_frame, text="Manual de Usuario")
        
        manual_text = tk.Text(manual_frame, wrap="word", padx=10, pady=10)
        manual_text.pack(fill=tk.BOTH, expand=True)
        
        manual_content = """
        Manual de Usuario - Sistema SRPV-UNAMAD
        
        1. Gestión de Usuarios:
           - Agregar nuevos usuarios con sus vehículos
           - Editar información existente
           - Buscar usuarios por diferentes criterios
        
        2. Escaneo de Placas:
           - Uso de la cámara para detección automática
           - Configuración del sistema ANPR
           - Listas blancas y negras
        
        3. Reportes:
           - Generación de reportes en diferentes formatos
           - Estadísticas de uso
        
        4. Configuración:
           - Ajustes del sistema
           - Personalización de la interfaz
        """
        
        manual_text.insert("1.0", manual_content)
        manual_text.config(state="disabled")
        
        faq_frame = ttk.Frame(notebook)
        notebook.add(faq_frame, text="Preguntas Frecuentes")
        
        faq_text = tk.Text(faq_frame, wrap="word", padx=10, pady=10)
        faq_text.pack(fill=tk.BOTH, expand=True)
        
        faq_content = """
        Preguntas Frecuentes
        
        Q: ¿Cómo agregar un nuevo usuario?
        R: Vaya a la sección Usuarios y haga clic en "Agregar Usuario"
        
        Q: ¿Cómo escanear una placa?
        R: Vaya a la sección Cámaras y active la cámara
        
        Q: ¿Cómo generar un reporte?
        R: Vaya a la sección Reportes y seleccione el tipo de reporte
        """
        
        faq_text.insert("1.0", faq_content)
        faq_text.config(state="disabled")
        
        about_frame = ttk.Frame(notebook)
        notebook.add(about_frame, text="Acerca de")
        
        about_text = tk.Text(about_frame, wrap="word", padx=10, pady=10)
        about_text.pack(fill=tk.BOTH, expand=True)
        
        about_content = f"""
        {APP_NAME} - Versión {APP_VERSION}
        
        Sistema de reconocimiento de placas vehiculares
        
        Características:
        - Detección de placas en tiempo real
        - Base de datos de usuarios y vehículos
        - Generación de reportes
        - Configuración flexible
        
        {DEVELOPER}
        """
        
        about_text.insert("1.0", about_content)
        about_text.config(state="disabled")
        
        ttk.Button(help_window, text="Contactar Soporte", 
                  command=self.contact_support).pack(pady=10)
    
    def contact_support(self):
        webbrowser.open("mailto:soporte@spv.com")
    
    def show_notifications(self):
        notifications = [
            {"title": "Versión Actualizada", "message": "Versión 2.6.0", "time": "17:30 AM"},
            {"title": "Escaneo exitoso", "message": "Placa ABC-123 detectada", "time": "11:15 AM"},
            {"title": "Recordatorio", "message": "Realizar copia de seguridad de la base de datos", "time": "Ayer"}
        ]
        
        notif_window = tk.Toplevel(self.root)
        notif_window.title("Notificaciones")
        notif_window.geometry("300x400")
        
        ttk.Label(notif_window, text="Notificaciones", 
                 font=('Arial', 12, 'bold')).pack(pady=10)
        
        notif_frame = ttk.Frame(notif_window)
        notif_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        canvas = tk.Canvas(notif_frame)
        scrollbar = ttk.Scrollbar(notif_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        for notif in notifications:
            frame = ttk.Frame(scrollable_frame, relief="groove", borderwidth=1)
            frame.pack(fill=tk.X, pady=2, padx=2)
            
            ttk.Label(frame, text=notif["title"], font=('Arial', 9, 'bold')).pack(anchor="w")
            ttk.Label(frame, text=notif["message"], font=('Arial', 8)).pack(anchor="w")
            ttk.Label(frame, text=notif["time"], font=('Arial', 7), foreground="gray").pack(anchor="e")
    
    def show_dashboard(self):
        self.section_title.config(text="Panel de Administración")
    
    def show_users_section(self):
        self.section_title.config(text="Gestión de Usuarios")
    
    def show_vehicles_section(self):
        self.section_title.config(text="Gestión de Vehículos")
    
    def check_for_updates(self):
        try:
            if random.random() < 0.3:
                if messagebox.askyesno("Actualización Disponible", 
                                     "Hay una nueva versión disponible. ¿Desea descargarla ahora?"):
                    webbrowser.open("https://portal.unamad.edu.pe")
        except Exception as e:
            print(f"Error checking for updates: {str(e)}")
    
    def logout(self):
        if messagebox.askyesno("Cerrar Sesión", "¿Está seguro que desea cerrar sesión?"):
            self.stop_camera()
            self.save_data()
            self.root.destroy()
    
    def on_close(self):
        if messagebox.askyesno("Salir", "¿Está seguro que desea salir de la aplicación?"):
            self.stop_camera()
            self.save_data()
            self.root.destroy()

if __name__ == "__main__":
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
    
    root = tk.Tk()
    login_system = LoginSystem(root)
    root.mainloop()

