import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import strongdm
import os
import csv
import json
import logging
from datetime import datetime
import threading
import base64
from pathlib import Path
import io
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class StrongDMManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 StrongDM Resource Manager")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f8f9fa')  # Modern light background
        
        # Set app icon and styling
        self.setup_styling()
        
        self.client = None
        self.authenticated = False
        
        self.tags = []
        self.secret_stores = []
        self.proxy_clusters = []
        self.identity_sets = []
        self.certificate_authorities = []
        self.ssh_key_types = ["RSA-2048", "RSA-4096", "ECDSA-256", "ECDSA-384", "ECDSA-521", "ED25519"]  # fallback
        self.current_row = 6  # Initialize current_row for form management
        
        # Credential storage
        self.config_dir = Path.home() / ".strongdm_manager"
        self.config_file = self.config_dir / "config.json"
        
        # API logging
        self.api_log_buffer = io.StringIO()
        self.api_logging_enabled = tk.BooleanVar(value=True)  # Initialize here
        self.api_logger = self.setup_api_logging()
        
        self.setup_ui()
        self.load_saved_credentials()
        
    def setup_styling(self):
        """Setup modern styling for the application"""
        style = ttk.Style()
        
        # Configure modern theme
        style.theme_use('clam')
        
        # Modern professional color palette - store as instance variables
        self.primary_color = '#2563eb'      # Modern blue
        self.secondary_color = '#64748b'    # Slate gray
        self.success_color = '#059669'      # Emerald green
        self.warning_color = '#d97706'      # Amber
        self.danger_color = '#dc2626'       # Red
        self.bg_color = '#ffffff'           # Pure white background
        self.card_bg = '#f8fafc'            # Very light gray for cards
        self.text_color = '#0f172a'         # Almost black for text
        self.text_muted = '#64748b'         # Muted text
        self.border_color = '#e2e8f0'       # Light border
        
        # Keep local variables for style configuration
        primary_color = self.primary_color
        secondary_color = self.secondary_color
        success_color = self.success_color
        warning_color = self.warning_color
        danger_color = self.danger_color
        bg_color = self.bg_color
        card_bg = self.card_bg
        text_color = self.text_color
        text_muted = self.text_muted
        border_color = self.border_color
        
        # Configure notebook (tabs) - simple blue, no animations
        style.configure('TNotebook', background=bg_color, borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background='#e5e7eb',  # Light gray for inactive
                       foreground=text_color,
                       padding=[20, 10],
                       font=('Segoe UI', 10, 'normal'),
                       borderwidth=0,
                       relief='flat',
                       focuscolor='none')
        # ONLY color changes, NO other effects
        style.map('TNotebook.Tab',
                 background=[('selected', primary_color)],
                 foreground=[('selected', 'white')],
                 padding=[('selected', [20, 10])],  # Keep same padding
                 borderwidth=[('selected', 0)],     # Keep same border
                 relief=[('selected', 'flat')])     # Keep flat relief
        
        # Configure frames - clean, minimal borders
        style.configure('TLabelframe', 
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 10, 'normal'),
                       borderwidth=1,
                       relief='flat')
        style.configure('TLabelframe.Label', 
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 10, 'normal'))
        
        # Configure buttons
        # Modern buttons with rounded corners and shadow effect
        style.configure('Primary.TButton',
                       background=primary_color,
                       foreground='white',
                       font=('Segoe UI', 10, 'bold'),
                       padding=[25, 12],
                       borderwidth=2,
                       relief='raised',
                       focuscolor='none')
        style.map('Primary.TButton',
                 background=[('active', '#1d4ed8'), ('pressed', '#1e40af')],
                 relief=[('pressed', 'sunken'), ('active', 'raised')])
        
        style.configure('Success.TButton',
                       background=success_color,
                       foreground='white',
                       font=('Segoe UI', 10, 'bold'),
                       padding=[25, 12],
                       borderwidth=2,
                       relief='raised',
                       focuscolor='none')
        style.map('Success.TButton',
                 background=[('active', '#10b981'), ('pressed', '#047857')],
                 relief=[('pressed', 'sunken'), ('active', 'raised')])
        
        style.configure('Danger.TButton',
                       background=danger_color,
                       foreground='white',
                       font=('Segoe UI', 10, 'bold'),
                       padding=[25, 12],
                       borderwidth=2,
                       relief='raised',
                       focuscolor='none')
        style.map('Danger.TButton',
                 background=[('active', '#ef4444'), ('pressed', '#b91c1c')],
                 relief=[('pressed', 'sunken'), ('active', 'raised')])
        
        # Configure entry fields - no highlighting or contrasts
        style.configure('TEntry',
                       fieldbackground='white',
                       borderwidth=1,
                       relief='flat',
                       font=('Segoe UI', 9, 'bold'))
        # Remove all focus and selection highlighting
        style.map('TEntry',
                 fieldbackground=[('focus', 'white'), ('!focus', 'white')],
                 selectbackground=[('focus', 'white')],
                 selectforeground=[('focus', 'black')])
        
        # Configure comboboxes
        style.configure('TCombobox',
                       fieldbackground='white',
                       borderwidth=1,
                       relief='flat',
                       font=('Segoe UI', 9, 'bold'))
        # Remove combobox highlighting
        style.map('TCombobox',
                 fieldbackground=[('focus', 'white'), ('!focus', 'white')],
                 selectbackground=[('focus', 'white')],
                 selectforeground=[('focus', 'black')])
        
        # Configure labels - bold text, bigger icons
        style.configure('Heading.TLabel',
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 18, 'bold'))  # Bigger heading
        
        style.configure('Info.TLabel',
                       background=bg_color,
                       foreground=text_muted,
                       font=('Segoe UI', 10, 'bold'))  # Bold info text
        
        # Required field label style - bold 
        style.configure('Required.TLabel',
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 10, 'bold'))  # Bold labels
        
        # Instruction style - bold
        style.configure('Instruction.TLabel',
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 12, 'bold'))  # Bold instructions, bigger
        
        # Configure checkboxes
        style.configure('TCheckbutton',
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 9, 'normal'))
    def create_required_label(self, parent, text, row, column=0):
        """Create a label with red asterisk for required fields"""
        # Remove asterisk from text if present
        base_text = text.replace('*:', ':').replace('*', '')
        
        # Create frame for label and asterisk
        label_frame = ttk.Frame(parent)
        label_frame.grid(row=row, column=column, sticky="w", padx=5, pady=2)
        
        # Main label text
        ttk.Label(label_frame, text=base_text, style='Required.TLabel').pack(side="left")
        
        # Red asterisk
        ttk.Label(label_frame, text="*", foreground=self.danger_color, 
                 background=self.bg_color, font=('Segoe UI', 10, 'bold')).pack(side="left")
        
        return label_frame
                       
    def setup_api_logging(self):
        """Setup API request/response logging"""
        # Create a separate logger for API calls
        api_logger = logging.getLogger('strongdm_api')
        api_logger.setLevel(logging.DEBUG)
        
        # Create handler that writes to our buffer
        handler = logging.StreamHandler(self.api_log_buffer)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        api_logger.addHandler(handler)
        
        return api_logger
        
    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        
        self.setup_login_tab()
        
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
    def setup_login_tab(self):
        self.login_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.login_frame, text="🔑 Login")
        
        # Main login container with padding
        login_container = ttk.Frame(self.login_frame)
        login_container.pack(expand=True, fill="both", padx=40, pady=30)
        
        # Header with icon and title
        header_frame = ttk.Frame(login_container)
        header_frame.pack(fill="x", pady=(0, 30))
        
        ttk.Label(header_frame, text="🔐 StrongDM API Credentials", 
                 style="Heading.TLabel").pack()
        ttk.Label(header_frame, text="Enter your API credentials to connect", 
                 style="Info.TLabel").pack(pady=(5, 0))
        
        # Credentials frame
        cred_frame = ttk.LabelFrame(login_container, text="API Credentials", padding=20)
        cred_frame.pack(fill="x", pady=(0, 20))
        
        # Access Key
        ttk.Label(cred_frame, text="🔑 API Access Key:", font=('Segoe UI', 9, 'bold')).pack(anchor="w", pady=(0, 5))
        self.access_key_var = tk.StringVar()
        access_entry = ttk.Entry(cred_frame, textvariable=self.access_key_var, 
                               width=60, show="*", font=('Consolas', 9))
        access_entry.pack(fill="x", pady=(0, 15))
        
        # Secret Key
        ttk.Label(cred_frame, text="🔐 API Secret Key:", font=('Segoe UI', 9, 'bold')).pack(anchor="w", pady=(0, 5))
        self.secret_key_var = tk.StringVar()
        secret_entry = ttk.Entry(cred_frame, textvariable=self.secret_key_var, 
                               width=60, show="*", font=('Consolas', 9))
        secret_entry.pack(fill="x", pady=(0, 15))
        
        # Save credentials option
        self.save_credentials_var = tk.BooleanVar()
        ttk.Checkbutton(cred_frame, text="💾 Save credentials (stored locally)", 
                       variable=self.save_credentials_var).pack(anchor="w")
        
        # Button frame
        button_frame = ttk.Frame(login_container)
        button_frame.pack(fill="x", pady=20)
        
        ttk.Button(button_frame, text="🚀 Connect", style="Success.TButton",
                  command=self.authenticate).pack(side="left", padx=(0, 10))
        ttk.Button(button_frame, text="🗑️ Clear Saved", style="Danger.TButton",
                  command=self.clear_saved_credentials).pack(side="left")
        
        # Status with better styling
        status_frame = ttk.Frame(login_container)
        status_frame.pack(fill="x", pady=(20, 0))
        
        self.status_label = ttk.Label(status_frame, text="", 
                                     font=('Segoe UI', 9, 'bold'))
        self.status_label.pack()
        
        # Resource list frame (hidden initially)
        self.resource_list_frame = ttk.LabelFrame(login_container, text="📋 Resources", padding=10)
        
        # Create scrollable resource list
        resource_scroll_frame = ttk.Frame(self.resource_list_frame)
        resource_scroll_frame.pack(fill="both", expand=True)
        
        # Resource list with scrollbar
        self.resource_text = tk.Text(resource_scroll_frame, height=12, wrap=tk.WORD,
                                   font=('Consolas', 9), bg='#f8f9fa', fg='#212529')
        resource_scrollbar = ttk.Scrollbar(resource_scroll_frame, orient="vertical", 
                                         command=self.resource_text.yview)
        self.resource_text.configure(yscrollcommand=resource_scrollbar.set)
        
        self.resource_text.pack(side="left", fill="both", expand=True)
        resource_scrollbar.pack(side="right", fill="y")
        
    def authenticate(self):
        try:
            access_key = self.access_key_var.get().strip()
            secret_key = self.secret_key_var.get().strip()
            
            if not access_key or not secret_key:
                self.status_label.config(text="Please enter both access key and secret key")
                return
                
            self.client = strongdm.Client(access_key, secret_key)
            
            # Test connection by listing resources
            resources = list(self.client.resources.list(""))
            
            self.authenticated = True
            self.status_label.config(text=f"Connected successfully! Found {len(resources)} resources.", 
                                   foreground="green")
            
            # Show and populate resource list
            self.resource_list_frame.pack(fill="both", expand=True, pady=(10, 0))
            self.display_resources(resources)
            
            # Save credentials if requested
            if self.save_credentials_var.get():
                self.save_credentials()
            
            # Load tenant data and setup tabs
            self.load_tenant_data()
            
            # Reset tabs to ensure clean recreation
            self.reset_tabs()
            self.setup_main_tabs()
            
        except Exception as e:
            self.status_label.config(text=f"Authentication failed: {str(e)}", 
                                   foreground="red")
            logger.error(f"Authentication error: {e}")
            
    def display_resources(self, resources):
        """Display resources in the scrollable list with details"""
        self.resource_text.config(state=tk.NORMAL)
        self.resource_text.delete(1.0, tk.END)
        
        if not resources:
            self.resource_text.insert(tk.END, "No resources found in this tenant.\n")
            self.resource_text.config(state=tk.DISABLED)
            return
        
        # Header
        header = f"{'Name':<30} {'Type':<15} {'Host':<25} {'Port':<6} {'Tags':<20} {'Details'}\n"
        header += "=" * 100 + "\n"
        self.resource_text.insert(tk.END, header)
        
        for i, resource in enumerate(resources, 1):
            try:
                # Get basic info
                name = getattr(resource, 'name', 'Unknown')[:29]
                resource_type = type(resource).__name__
                hostname = getattr(resource, 'hostname', 'N/A')[:24]
                port = str(getattr(resource, 'port', 'N/A'))[:5]
                
                # Get tags
                tags = getattr(resource, 'tags', {})
                if isinstance(tags, dict):
                    tag_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'None'
                else:
                    tag_str = str(tags) if tags else 'None'
                tag_str = tag_str[:19]
                
                # Get additional details based on resource type
                details = []
                
                # Common attributes to check
                attrs_to_check = ['username', 'database', 'schema', 'subdomain', 'secret_store_id']
                for attr in attrs_to_check:
                    if hasattr(resource, attr):
                        value = getattr(resource, attr)
                        if value and value != 'None':
                            details.append(f"{attr}:{value}")
                
                # Check for health status or last activity
                if hasattr(resource, 'healthy'):
                    healthy = getattr(resource, 'healthy')
                    details.append(f"healthy:{healthy}")
                
                if hasattr(resource, 'bind_interface'):
                    bind_interface = getattr(resource, 'bind_interface')
                    if bind_interface:
                        details.append(f"bind:{bind_interface}")
                
                # Check for proxy cluster
                if hasattr(resource, 'proxy_cluster_id'):
                    proxy_cluster = getattr(resource, 'proxy_cluster_id')
                    if proxy_cluster:
                        details.append(f"proxy:{proxy_cluster}")
                
                details_str = ', '.join(details[:3])  # Limit to first 3 details
                
                # Format the line
                line = f"{name:<30} {resource_type:<15} {hostname:<25} {port:<6} {tag_str:<20} {details_str}\n"
                self.resource_text.insert(tk.END, line)
                
            except Exception as e:
                # Fallback for any resource that fails to parse
                self.resource_text.insert(tk.END, f"Resource {i}: Error parsing - {str(e)[:60]}...\n")
        
        # Summary at the bottom
        self.resource_text.insert(tk.END, f"\n{'-' * 100}\n")
        
        # Count resource types
        type_counts = {}
        for resource in resources:
            resource_type = type(resource).__name__
            type_counts[resource_type] = type_counts.get(resource_type, 0) + 1
        
        self.resource_text.insert(tk.END, f"Resource Summary: ")
        summary_parts = [f"{count} {rtype}" for rtype, count in sorted(type_counts.items())]
        self.resource_text.insert(tk.END, ", ".join(summary_parts) + "\n")
        
        # Make the text read-only
        self.resource_text.config(state=tk.DISABLED)
        
        # Enable it temporarily when we need to update it
        def enable_for_updates():
            self.resource_text.config(state=tk.NORMAL)
        
        # Store reference for future updates
        self.resource_text.enable_for_updates = enable_for_updates
            
    def load_tenant_data(self):
        """Load tags, secret stores, and proxy clusters from tenant"""
        try:
            # Load tags from existing resources
            self.tags = set()  # Use set to avoid duplicates
            try:
                # Get tags from existing resources
                resources = list(self.client.resources.list(""))
                self.log_api_call("LIST", "/resources", None, f"Found {len(resources)} resources")
                logger.info(f"Found {len(resources)} resources to scan for tags")
                
                for resource in resources:
                    # Log each resource details for debugging
                    self.log_api_call("RESOURCE_DETAIL", f"/resources/{getattr(resource, 'id', 'unknown')}", 
                                    None, resource)
                    
                    if hasattr(resource, 'tags') and resource.tags:
                        logger.info(f"Resource {getattr(resource, 'name', 'unknown')} has tags: {resource.tags}")
                        # Create key:value pairs for meaningful tags
                        for tag_key, tag_value in resource.tags.items():
                            if tag_value:
                                # Create key=value format to match GUI format
                                tag_pair = f"{tag_key}={tag_value}"
                                self.tags.add(tag_pair)
                            else:
                                # If no value, just add the key
                                self.tags.add(tag_key)
                
                # Convert to sorted list - DON'T add defaults, only show real tenant tags
                self.tags = sorted(list(self.tags))
                logger.info(f"Extracted tags: {self.tags}")
                
                if not self.tags:
                    logger.info("No tags found in resources - will show empty dropdown")
                    self.tags = []  # Empty list, no dummy values
                    
            except Exception as e:
                logger.error(f"Error loading tags from resources: {e}")
                self.tags = []  # Empty on error, no dummy values
                
            # Load secret stores (including Strong Vault)
            self.secret_stores = ["Strong Vault", "None"]
            try:
                secret_stores_response = self.client.secret_stores.list("")
                for store in secret_stores_response:
                    # Avoid duplicates and put Strong Vault first
                    if store.name not in self.secret_stores:
                        self.secret_stores.append(store.name)
            except:
                self.secret_stores = ["Strong Vault", "None", "AWS Secrets Manager", "HashiCorp Vault"]
                
            # Load proxy clusters
            self.proxy_clusters = ["None (Use Gateway)"]
            try:
                clusters_response = self.client.proxy_clusters.list("")
                clusters_found = False
                for cluster in clusters_response:
                    self.proxy_clusters.append(cluster.name)
                    clusters_found = True
                if not clusters_found:
                    logger.info("No proxy clusters found, defaulting to Gateway only")
            except Exception as e:
                logger.info(f"Could not load proxy clusters: {e}, defaulting to Gateway only")
                # Keep default: ["None (Use Gateway)"]
                
            # Load identity sets for RDP Certificate authentication
            self.identity_sets = []
            try:
                identity_sets_response = self.client.identity_sets.list("")
                for identity_set in identity_sets_response:
                    self.identity_sets.append({
                        'id': identity_set.id,
                        'name': getattr(identity_set, 'name', identity_set.id)
                    })
                logger.info(f"Loaded {len(self.identity_sets)} identity sets")
            except Exception as e:
                logger.error(f"Error loading identity sets: {e}")
                self.identity_sets = []
                
            # Load certificate authorities for RDP Certificate authentication
            self.certificate_authorities = []
            try:
                # Try different possible API endpoints for certificate authorities
                possible_endpoints = ['certificate_authorities', 'certificate_authority', 'ca']
                for endpoint_name in possible_endpoints:
                    if hasattr(self.client, endpoint_name):
                        endpoint = getattr(self.client, endpoint_name)
                        ca_response = endpoint.list("")
                        for ca in ca_response:
                            self.certificate_authorities.append({
                                'id': ca.id,
                                'name': getattr(ca, 'name', ca.id)
                            })
                        logger.info(f"Loaded {len(self.certificate_authorities)} certificate authorities via {endpoint_name}")
                        break
                else:
                    logger.warning("No certificate authorities endpoint found in API")
            except Exception as e:
                logger.error(f"Error loading certificate authorities: {e}")
                self.certificate_authorities = []
            
            # Load SSH key types from API
            try:
                self.load_ssh_key_types()
            except Exception as e:
                logger.error(f"Error loading SSH key types: {e}")
                # Keep fallback values
                
        except Exception as e:
            logger.error(f"Error loading tenant data: {e}")
            # Set fallback values - only real data
            self.tags = []  # Empty, no dummy values
            self.secret_stores = ["Strong Vault", "None"]
            self.proxy_clusters = ["None (Use Gateway)"]
            
    def load_ssh_key_types(self):
        """Load SSH key types from StrongDM API"""
        try:
            # Try to get key types from a test SSH certificate resource creation
            # This will help us understand what key types are supported
            test_cert = strongdm.SSHCert()
            
            # Check if there's a key_type attribute and what values it accepts
            if hasattr(test_cert, 'key_type'):
                # Try different key types to see which ones are valid
                valid_key_types = []
                test_key_types = [
                    "rsa-2048", "rsa-4096", 
                    "ecdsa-p256", "ecdsa-p384", "ecdsa-p521",
                    "ed25519",
                    "RSA-2048", "RSA-4096",
                    "ECDSA-256", "ECDSA-384", "ECDSA-521",
                    "ED25519"
                ]
                
                for key_type in test_key_types:
                    try:
                        test_cert.key_type = key_type
                        # If no error, it's a valid key type
                        valid_key_types.append(key_type)
                    except:
                        continue
                
                if valid_key_types:
                    # Filter to only lowercase/hyphenated format which actually works with the API
                    # Based on error "invalid Key Type RSA-2048", we need lowercase format
                    lowercase_types = [kt for kt in valid_key_types if not kt.isupper() or kt == "ED25519"]
                    if lowercase_types:
                        # Remove duplicates and prefer the working format
                        unique_types = []
                        seen = set()
                        for kt in lowercase_types:
                            # Normalize to avoid duplicates (e.g., "ed25519" and "ED25519")
                            normalized = kt.lower()
                            if normalized not in seen:
                                seen.add(normalized)
                                unique_types.append(kt)
                        self.ssh_key_types = unique_types
                    else:
                        self.ssh_key_types = ["rsa-2048", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "ed25519"]
                    logger.info(f"Loaded SSH key types: {self.ssh_key_types}")
                else:
                    logger.info("Using fallback SSH key types")
            else:
                logger.info("SSHCert has no key_type attribute, using fallback key types")
                
        except Exception as e:
            logger.error(f"Error testing SSH key types: {e}")
            # Keep fallback values
            
    def setup_main_tabs(self):
        """Setup main application tabs after authentication"""
        
        # Check if tabs already exist to prevent duplicates
        if hasattr(self, 'main_tabs_created'):
            logger.info("Main tabs already created, skipping recreation")
            return
            
        logger.info("Creating main application tabs...")
            
        # Single Resource Tab
        self.single_resource_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.single_resource_frame, text="➕ Add Resource")
        self.setup_single_resource_tab()
        
        # CSV Bulk Import Tab
        self.csv_import_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.csv_import_frame, text="📊 Bulk Import")
        self.setup_csv_import_tab()
        
        # Debug Tab
        try:
            self.debug_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.debug_frame, text="🔧 Debug")
            self.setup_debug_tab()
            logger.info("Debug tab created successfully")
        except Exception as e:
            logger.error(f"Failed to create debug tab: {e}")
            # Create a simple debug tab as fallback
            self.debug_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.debug_frame, text="🔧 Debug")
            ttk.Label(self.debug_frame, text=f"Debug tab error: {str(e)}").pack(pady=20)
        
        # API Logs Tab
        self.api_logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.api_logs_frame, text="📡 API Logs")
        self.setup_api_logs_tab()
        
        # Mark tabs as created
        self.main_tabs_created = True
        logger.info("All main tabs created successfully")
        
    def reset_tabs(self):
        """Reset tabs to allow recreation"""
        if hasattr(self, 'main_tabs_created'):
            delattr(self, 'main_tabs_created')
        
        # Remove existing tabs (except login)
        for i in range(self.notebook.index("end") - 1, 0, -1):  # Reverse order to avoid index issues
            try:
                self.notebook.forget(i)
            except:
                pass
        
        logger.info("Tabs reset for recreation")
        
    def setup_single_resource_tab(self):
        """Setup single resource creation tab with scrollable content"""
        
        # Create scrollable canvas for the tab content - full width scaling
        main_canvas = tk.Canvas(self.single_resource_frame)
        main_scrollbar = ttk.Scrollbar(self.single_resource_frame, orient="vertical", command=main_canvas.yview)
        self.scrollable_frame = ttk.Frame(main_canvas)
        
        # Bind both configure events for proper scaling in both dimensions
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        main_canvas.bind(
            "<Configure>",
            lambda e: main_canvas.itemconfig(canvas_window, width=e.width)
        )
        
        canvas_window = main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_canvas.pack(side="left", fill="both", expand=True)
        main_scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel to canvas for scrolling
        def _on_mousewheel(event):
            main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        main_canvas.bind_all("<MouseWheel>", _on_mousewheel)  # Windows
        main_canvas.bind_all("<Button-4>", lambda e: main_canvas.yview_scroll(-1, "units"))  # Linux
        main_canvas.bind_all("<Button-5>", lambda e: main_canvas.yview_scroll(1, "units"))  # Linux
        
        # Resource type selection (now on scrollable frame)
        type_frame = ttk.LabelFrame(self.scrollable_frame, text="Resource Type")
        type_frame.pack(fill="x", padx=10, pady=5)
        
        self.resource_type_var = tk.StringVar(value="SSH")
        ttk.Radiobutton(type_frame, text="SSH", variable=self.resource_type_var, 
                       value="SSH", command=self.update_resource_form).pack(side="left")
        ttk.Radiobutton(type_frame, text="RDP", variable=self.resource_type_var, 
                       value="RDP", command=self.update_resource_form).pack(side="left")
        ttk.Radiobutton(type_frame, text="Database", variable=self.resource_type_var, 
                       value="Database", command=self.update_resource_form).pack(side="left")
        
        # Resource subtype selection
        self.subtype_frame = ttk.LabelFrame(self.scrollable_frame, text="Resource Subtype")
        self.subtype_frame.pack(fill="x", padx=5, pady=5)
        
        # Resource form frame - scale with window
        self.resource_form_frame = ttk.LabelFrame(self.scrollable_frame, text="Resource Details", padding=10)
        self.resource_form_frame.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Configure grid weights for the resource form frame - allow full expansion
        self.resource_form_frame.grid_columnconfigure(0, weight=0)  # Labels column
        self.resource_form_frame.grid_columnconfigure(1, weight=1)  # Input fields expand
        self.resource_form_frame.grid_columnconfigure(2, weight=0)  # Buttons column
        
        self.update_resource_form()
        
    def update_resource_form(self):
        """Update the resource form based on selected type"""
        # Clear existing forms AND any existing button frames
        for widget in self.subtype_frame.winfo_children():
            widget.destroy()
        for widget in self.resource_form_frame.winfo_children():
            widget.destroy()
        
        # Clear any existing button frames from scrollable_frame
        if hasattr(self, 'button_frame') and self.button_frame.winfo_exists():
            self.button_frame.destroy()
            
        resource_type = self.resource_type_var.get()
        
        # Setup subtypes based on main type
        self.setup_subtypes(resource_type)
        
        # Common fields
        self.create_common_fields()
        
        # Type-specific fields based on subtype
        self.create_type_specific_fields()
            
        # Action buttons - pinned to bottom like debug tab
        self.button_frame = ttk.Frame(self.scrollable_frame)
        self.button_frame.pack(fill="x", padx=10, pady=10, side="bottom")
        self.button_frame.grid_columnconfigure(0, weight=1)
        self.button_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Button(self.button_frame, text="🔄 Clear Form", 
                  command=self.update_resource_form).grid(row=0, column=0, padx=5, sticky="ew")
        ttk.Button(self.button_frame, text="✅ Create Resource", style="Success.TButton",
                  command=self.create_single_resource).grid(row=0, column=1, padx=5, sticky="ew")
    
    def on_credential_type_change(self, event=None):
        """Handle credential type change for SSH Certificate"""
        if not hasattr(self, 'ssh_cert_fields'):
            return
            
        credential_type = self.credential_type_var.get()
        
        if credential_type == "Username":
            # Show username fields, hide identity set fields
            self.ssh_cert_fields['username_label'].grid()
            self.ssh_cert_fields['username_entry'].grid()
            self.ssh_cert_fields['identity_label'].grid_remove()
            self.ssh_cert_fields['identity_combo'].grid_remove()
        else:  # Identity Alias
            # Hide username fields, show identity set fields
            self.ssh_cert_fields['username_label'].grid_remove()
            self.ssh_cert_fields['username_entry'].grid_remove()
            self.ssh_cert_fields['identity_label'].grid(row=self.current_row-1, column=0, sticky="w", padx=5, pady=2)
            self.ssh_cert_fields['identity_combo'].grid(row=self.current_row-1, column=1, padx=5, pady=2, sticky="ew")
    
    def on_rdp_credential_type_change(self, event=None):
        """Handle RDP credential type change for Certificate authentication"""
        if not hasattr(self, 'rdp_cert_fields'):
            return
            
        credential_type = self.rdp_credential_type_var.get()
        
        if credential_type == "Leased Credential":
            # Show username fields, hide identity set fields  
            self.rdp_cert_fields['username_label'].grid()
            self.rdp_cert_fields['username_entry'].grid()
            
            # Hide identity alias fields
            self.rdp_cert_fields['identity_label'].grid_remove()
            self.rdp_cert_fields['identity_combo'].grid_remove()
            self.rdp_cert_fields['healthcheck_info'].grid_remove()
            self.rdp_cert_fields['service_account_label'].grid_remove()
            self.rdp_cert_fields['service_account_entry'].grid_remove()
                
        else:  # Identity Alias
            # Hide username fields
            self.rdp_cert_fields['username_label'].grid_remove()
            self.rdp_cert_fields['username_entry'].grid_remove()
            
            # Show identity set field and AD Service Account fields
            # Use a base row that accounts for all RDP Certificate fields properly
            base_row = 9  # Fixed position after CA field (row 8) + 1
            
            # Identity Set
            self.rdp_cert_fields['identity_label'].grid(row=base_row, column=0, sticky="w", padx=5, pady=2)
            self.rdp_cert_fields['identity_combo'].grid(row=base_row, column=1, padx=5, pady=2, sticky="ew")
            self.rdp_cert_fields['healthcheck_info'].grid(row=base_row, column=2, sticky="w", padx=(5, 0), pady=2)
            
            # AD Service Account
            self.rdp_cert_fields['service_account_label'].grid(row=base_row+1, column=0, sticky="w", padx=5, pady=2)
            self.rdp_cert_fields['service_account_entry'].grid(row=base_row+1, column=1, padx=5, pady=2, sticky="ew")
                  
    def setup_subtypes(self, resource_type):
        """Setup subtype selection based on main resource type"""
        if resource_type == "SSH":
            self.subtype_var = tk.StringVar(value="Password")
            ttk.Radiobutton(self.subtype_frame, text="🔐 Password", variable=self.subtype_var, 
                           value="Password", command=self.create_type_specific_fields).pack(side="left", padx=5)
            ttk.Radiobutton(self.subtype_frame, text="🔑 Public Key", variable=self.subtype_var, 
                           value="PublicKey", command=self.create_type_specific_fields).pack(side="left", padx=5)
            ttk.Radiobutton(self.subtype_frame, text="📜 Certificate", variable=self.subtype_var, 
                           value="Certificate", command=self.create_type_specific_fields).pack(side="left", padx=5)
        elif resource_type == "RDP":
            self.subtype_var = tk.StringVar(value="Basic")
            ttk.Radiobutton(self.subtype_frame, text="🔐 Basic Auth", variable=self.subtype_var, 
                           value="Basic", command=self.create_type_specific_fields).pack(side="left", padx=5)
            ttk.Radiobutton(self.subtype_frame, text="📜 Certificate", variable=self.subtype_var, 
                           value="Certificate", command=self.create_type_specific_fields).pack(side="left", padx=5)
        elif resource_type == "Database":
            self.subtype_var = tk.StringVar(value="Standard")
            ttk.Label(self.subtype_frame, text="All database types use standard authentication").pack(side="left", padx=10)
        else:
            self.subtype_var = tk.StringVar(value="Standard")
            
    def create_type_specific_fields(self):
        """Create type and subtype specific fields"""
        # Clear existing type-specific fields (keep common fields)
        if hasattr(self, 'current_row') and self.current_row > 6:  # After common fields
            # Remove widgets after row 6 (common fields end at row 5)
            for widget in self.resource_form_frame.grid_slaves():
                info = widget.grid_info()
                if info and int(info['row']) > 5:
                    widget.destroy()
            self.current_row = 6
        
        resource_type = self.resource_type_var.get()
        subtype = getattr(self, 'subtype_var', tk.StringVar()).get()
        
        if resource_type == "SSH":
            self.create_ssh_fields(subtype)
        elif resource_type == "RDP":
            self.create_rdp_fields(subtype)
        elif resource_type == "Database":
            self.create_database_fields()
            
        # Update buttons remain pinned at bottom - no need to re-add
                  
    def create_common_fields(self):
        """Create common fields for all resource types"""
        
        # Resource Name
        self.create_required_label(self.resource_form_frame, "Resource Name:", 0)
        self.name_var = tk.StringVar()
        ttk.Entry(self.resource_form_frame, textvariable=self.name_var).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        
        # Hostname
        self.create_required_label(self.resource_form_frame, "Hostname:", 1)
        self.hostname_var = tk.StringVar()
        ttk.Entry(self.resource_form_frame, textvariable=self.hostname_var).grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        
        # Port
        self.create_required_label(self.resource_form_frame, "Port:", 2)
        self.port_var = tk.StringVar()
        
        # Set default port based on resource type
        resource_type = self.resource_type_var.get()
        if resource_type == "SSH":
            self.port_var.set("22")
        elif resource_type == "RDP":
            self.port_var.set("3389")
        elif resource_type == "Database":
            self.port_var.set("3306")  # MySQL default
        
        ttk.Entry(self.resource_form_frame, textvariable=self.port_var).grid(row=2, column=1, padx=5, pady=2, sticky="ew")
        
        # Set initial current_row for type-specific fields
        self.current_row = 3
        
        # For database resources, tags will be added after database-specific fields
        # For other resource types, add tags immediately
        resource_type = self.resource_type_var.get()
        if resource_type != "Database":
            self.add_tags_interface()
        
    def add_tags_interface(self):
        """Add tags interface at current row position"""
        # Tags - Improved Multi-select interface
        ttk.Label(self.resource_form_frame, text="Tags:").grid(row=self.current_row, column=0, sticky="nw", padx=5, pady=2)
        
        # Create main tags container with better styling
        tags_container = ttk.LabelFrame(self.resource_form_frame, text="Tag Selection", padding=10)
        tags_container.grid(row=self.current_row, column=1, columnspan=2, padx=5, pady=2, sticky="ew")
        
        # Existing tags section
        if self.tags:
            existing_frame = ttk.LabelFrame(tags_container, text=f"Available Tags ({len(self.tags)})", padding=5)
            existing_frame.pack(fill="both", expand=True, pady=(0, 10))
            
            # Scrollable tags with better sizing
            tags_canvas = tk.Canvas(existing_frame, height=120, width=450, bg='white', relief='sunken', bd=1)
            tags_scrollbar = ttk.Scrollbar(existing_frame, orient="vertical", command=tags_canvas.yview)
            self.tags_checkbox_frame = ttk.Frame(tags_canvas, padding=5)
            
            self.tags_checkbox_frame.bind(
                "<Configure>",
                lambda e: tags_canvas.configure(scrollregion=tags_canvas.bbox("all"))
            )
            
            tags_canvas.create_window((0, 0), window=self.tags_checkbox_frame, anchor="nw")
            tags_canvas.configure(yscrollcommand=tags_scrollbar.set)
            
            tags_canvas.pack(side="left", fill="both", expand=True)
            tags_scrollbar.pack(side="right", fill="y")
                
            # Create checkboxes with better layout
            self.selected_tags = {}
            cols = 3  # Use 3 columns for better space utilization
            for i, tag in enumerate(self.tags):
                var = tk.BooleanVar()
                self.selected_tags[tag] = var
                # Truncate long tags for display
                display_tag = tag[:35] + "..." if len(tag) > 35 else tag
                ttk.Checkbutton(self.tags_checkbox_frame, text=display_tag, variable=var).grid(
                    row=i//cols, column=i%cols, sticky="w", padx=5, pady=2
                )
        else:
            self.selected_tags = {}
            self.tags_checkbox_frame = ttk.Frame(tags_container)
            ttk.Label(tags_container, text="No existing tags found", style="Info.TLabel").pack(pady=10)
        
        # New tag section with better styling
        new_tag_frame = ttk.LabelFrame(tags_container, text="Add New Tag", padding=5)
        new_tag_frame.pack(fill="x", pady=(5, 0))
        
        entry_frame = ttk.Frame(new_tag_frame)
        entry_frame.pack(fill="x")
        
        ttk.Label(entry_frame, text="Tag (key=value format):").pack(side="left")
        self.new_tag_var = tk.StringVar()
        new_tag_entry = ttk.Entry(entry_frame, textvariable=self.new_tag_var)
        new_tag_entry.pack(side="left", padx=(10, 0), fill="x", expand=True)
        
        # Help text
        help_frame = ttk.Frame(new_tag_frame)
        help_frame.pack(fill="x", pady=(5, 0))
        ttk.Label(help_frame, text="💡 Examples: env=prod, team=devops, region=us-east", 
                 style="Info.TLabel").pack(side="left")
        
        # Update current_row to next position after tags interface
        self.current_row += 1
    
    def get_selected_tags(self):
        """Get all selected tags as a dictionary for resource creation"""
        tags_dict = {}
        
        # Get checked existing tags
        if hasattr(self, 'selected_tags'):
            for tag, var in self.selected_tags.items():
                if var.get():  # If checkbox is checked
                    # Parse tag (assuming format: key=value or key:value or just key)
                    if '=' in tag:
                        key, value = tag.split('=', 1)
                        tags_dict[key.strip()] = value.strip()
                    elif ':' in tag:
                        key, value = tag.split(':', 1)
                        tags_dict[key.strip()] = value.strip()
                    else:
                        tags_dict[tag.strip()] = ""
        
        # Get new tag from entry field
        if hasattr(self, 'new_tag_var') and self.new_tag_var.get().strip():
            new_tag = self.new_tag_var.get().strip()
            if '=' in new_tag:
                key, value = new_tag.split('=', 1)
                tags_dict[key.strip()] = value.strip()
            elif ':' in new_tag:
                key, value = new_tag.split(':', 1)
                tags_dict[key.strip()] = value.strip()
            else:
                tags_dict[new_tag.strip()] = ""
                
        return tags_dict
    
    def refresh_certificate_authorities(self, event=None):
        """Refresh certificate authorities from StrongDM API"""
        if not self.client or not hasattr(self, 'rdp_ca_combo'):
            return
            
        try:
            # Reload certificate authorities from API
            ca_list = []
            try:
                # Try the correct StrongDM SDK endpoint
                possible_endpoints = [
                    'certificate_authorities',  # Primary endpoint
                    'ca_certificates',          # Alternative
                    'certificates'              # Alternative
                ]
                
                for endpoint_name in possible_endpoints:
                    if hasattr(self.client, endpoint_name):
                        try:
                            endpoint = getattr(self.client, endpoint_name)
                            # Try list with filter
                            ca_response = endpoint.list("")
                            for ca in ca_response:
                                ca_list.append({
                                    'id': ca.id,
                                    'name': getattr(ca, 'name', getattr(ca, 'display_name', ca.id))
                                })
                            logger.info(f"Refreshed {len(ca_list)} certificate authorities via {endpoint_name}")
                            break
                        except Exception as endpoint_error:
                            logger.debug(f"Failed to access {endpoint_name}: {endpoint_error}")
                            continue
                
                # If no endpoints work, try direct client inspection
                if not ca_list:
                    # Log available client attributes for debugging
                    client_attrs = [attr for attr in dir(self.client) if not attr.startswith('_') and 'cert' in attr.lower()]
                    logger.debug(f"Available certificate-related client attributes: {client_attrs}")
                    
                    # Also check for CA-related attributes
                    ca_attrs = [attr for attr in dir(self.client) if not attr.startswith('_') and 'ca' in attr.lower()]
                    logger.debug(f"Available CA-related client attributes: {ca_attrs}")
                    
                    logger.warning("No certificate authorities endpoint found during refresh")
                    
            except Exception as e:
                logger.error(f"Error refreshing certificate authorities: {e}")
            
            # Update dropdown values
            ca_values = []
            ca_id_map = {}
            
            if ca_list:
                for ca in ca_list:
                    display_name = ca['name']
                    ca_values.append(display_name)
                    ca_id_map[display_name] = ca['id']
            else:
                # Default to Strong CA if no CAs found via API
                ca_values = ["Strong CA"]
                ca_id_map["Strong CA"] = "strong-ca"
                logger.info("Using default certificate authority (Strong CA)")
            
            # Update combobox
            self.rdp_ca_combo['values'] = ca_values
            
            # Store the updated ID mapping
            self.rdp_ca_id_map = ca_id_map
            
            # Set default if nothing selected
            if not self.rdp_certificate_authority_var.get() and ca_values:
                self.rdp_ca_combo.set(ca_values[0])
            
        except Exception as e:
            logger.error(f"Error in refresh_certificate_authorities: {e}")
        
        # Secret Store
        ttk.Label(self.resource_form_frame, text="Secret Store:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.secret_store_var = tk.StringVar(value="Strong Vault")
        secret_store_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.secret_store_var, 
                                         values=self.secret_stores, width=37)
        secret_store_combo.grid(row=4, column=1, padx=5, pady=2, sticky="ew")
        
        # Proxy Cluster
        ttk.Label(self.resource_form_frame, text="Proxy Cluster:").grid(row=5, column=0, sticky="w", padx=5, pady=2)
        self.proxy_cluster_var = tk.StringVar(value="None (Use Gateway)")
        proxy_cluster_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.proxy_cluster_var, 
                                          values=self.proxy_clusters, width=37)
        proxy_cluster_combo.grid(row=5, column=1, padx=5, pady=2, sticky="ew")
        
        self.current_row = 6
        
    def create_ssh_fields(self, subtype="Password"):
        """Create SSH-specific fields based on subtype"""
        
        # Username (not needed for Certificate - it has its own credential handling)
        if subtype != "Certificate":
            ttk.Label(self.resource_form_frame, text="Username*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.username_var = tk.StringVar()
            ttk.Entry(self.resource_form_frame, textvariable=self.username_var).grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
        
        if subtype == "Password":
            # Password authentication
            ttk.Label(self.resource_form_frame, text="Password*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.password_var = tk.StringVar()
            ttk.Entry(self.resource_form_frame, textvariable=self.password_var, 
                     show="*").grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
        elif subtype == "PublicKey":
            # Public key authentication - key pair is auto-generated
            ttk.Label(self.resource_form_frame, text="🔑 SSH Key Pair:", 
                     style="Info.TLabel").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(self.resource_form_frame, text="Will be auto-generated by StrongDM", 
                     style="Info.TLabel").grid(row=self.current_row, column=1, sticky="w", padx=5, pady=2)
            self.current_row += 1
            
        elif subtype == "Certificate":
            # Certificate-based authentication
            
            # Key Type dropdown
            ttk.Label(self.resource_form_frame, text="Key Type*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.key_type_var = tk.StringVar(value=self.ssh_key_types[0] if self.ssh_key_types else "RSA-2048")
            key_type_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.key_type_var, 
                                         values=self.ssh_key_types, width=37, state="readonly")
            key_type_combo.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
            # Credential type selection
            ttk.Label(self.resource_form_frame, text="Credential Type*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.credential_type_var = tk.StringVar(value="Username")
            credential_types = ["Username", "Identity Alias"]
            credential_type_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.credential_type_var, 
                                               values=credential_types, width=37, state="readonly")
            credential_type_combo.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            credential_type_combo.bind("<<ComboboxSelected>>", self.on_credential_type_change)
            self.current_row += 1
            
            # Username field (shown by default)
            self.username_label = ttk.Label(self.resource_form_frame, text="Username*:")
            self.username_label.grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.ssh_cert_username_var = tk.StringVar()
            self.username_entry = ttk.Entry(self.resource_form_frame, textvariable=self.ssh_cert_username_var)
            self.username_entry.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
            # Identity Set dropdown (initially hidden)
            self.identity_label = ttk.Label(self.resource_form_frame, text="Identity Set*:")
            self.identity_set_var = tk.StringVar()
            
            # Create dropdown values from loaded identity sets
            identity_set_values = []
            for identity_set in self.identity_sets:
                display_name = f"{identity_set['name']} ({identity_set['id']})"
                identity_set_values.append(display_name)
            
            if not identity_set_values:
                identity_set_values = ["No identity sets found - check API permissions"]
            
            self.identity_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.identity_set_var, 
                                            values=identity_set_values, state="readonly")
            
            # Store references for toggling visibility
            self.ssh_cert_fields = {
                'username_label': self.username_label,
                'username_entry': self.username_entry,
                'identity_label': self.identity_label,
                'identity_combo': self.identity_combo
            }
        
    def create_rdp_fields(self, subtype="Basic"):
        """Create RDP-specific fields based on subtype"""
        
        if subtype == "Basic":
            # Basic username/password authentication
            # Username
            ttk.Label(self.resource_form_frame, text="Username*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.username_var = tk.StringVar()
            ttk.Entry(self.resource_form_frame, textvariable=self.username_var).grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
            # Password
            ttk.Label(self.resource_form_frame, text="Password*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.password_var = tk.StringVar()
            ttk.Entry(self.resource_form_frame, textvariable=self.password_var, 
                     show="*").grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
        elif subtype == "Certificate":
            # Certificate-based authentication
            
            # Credential type selection
            ttk.Label(self.resource_form_frame, text="Credential Type*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.rdp_credential_type_var = tk.StringVar(value="Leased Credential")
            credential_types = ["Leased Credential", "Identity Alias"]
            credential_type_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.rdp_credential_type_var, 
                                               values=credential_types, width=37, state="readonly")
            credential_type_combo.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            credential_type_combo.bind("<<ComboboxSelected>>", self.on_rdp_credential_type_change)
            self.current_row += 1
            
            # Certificate Authority selection
            ttk.Label(self.resource_form_frame, text="Certificate Authority*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.rdp_certificate_authority_var = tk.StringVar()
            
            # Create dropdown with refresh capability
            self.rdp_ca_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.rdp_certificate_authority_var, 
                                           width=37, state="readonly")
            self.rdp_ca_combo.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            
            # Bind focus event to refresh CA list
            self.rdp_ca_combo.bind("<Button-1>", self.refresh_certificate_authorities)
            self.rdp_ca_combo.bind("<FocusIn>", self.refresh_certificate_authorities)
            
            # Initial load
            self.refresh_certificate_authorities()
            self.current_row += 1
            
            # Leased Credential fields (shown by default) - Username + SID
            self.rdp_username_label = ttk.Label(self.resource_form_frame, text="Username*:")
            self.rdp_username_label.grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.rdp_username_var = tk.StringVar()
            self.rdp_username_entry = ttk.Entry(self.resource_form_frame, textvariable=self.rdp_username_var)
            self.rdp_username_entry.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
            # SID field removed - not supported by StrongDM Python SDK
            # self.rdp_sid_label = ttk.Label(self.resource_form_frame, text="SID (Optional):")
            # self.rdp_sid_var = tk.StringVar()
            # self.rdp_sid_entry = ttk.Entry(self.resource_form_frame, textvariable=self.rdp_sid_var, )
            
            # Identity Alias fields (initially hidden) - Identity Set dropdown
            self.rdp_identity_label = ttk.Label(self.resource_form_frame, text="Identity Set*:")
            self.identity_set_id_var = tk.StringVar()
            
            # Create dropdown values from loaded identity sets
            identity_set_values = []
            for identity_set in self.identity_sets:
                display_name = f"{identity_set['name']} ({identity_set['id']})"
                identity_set_values.append(display_name)
            
            if not identity_set_values:
                identity_set_values = ["No identity sets found - check API permissions"]
            
            self.rdp_identity_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.identity_set_id_var, 
                                                 values=identity_set_values, state="readonly")
            
            self.rdp_healthcheck_info = ttk.Label(self.resource_form_frame, text="💡 e.g. administrator@domain.local", style="Info.TLabel")
            
            # AD Service Account fields (for Identity Alias)
            self.rdp_service_account_label = ttk.Label(self.resource_form_frame, text="AD Service Account:")
            self.service_account_var = tk.StringVar()
            self.rdp_service_account_entry = ttk.Entry(self.resource_form_frame, textvariable=self.service_account_var)
            
            # AD Service Account SID and Domain Controller fields removed - not supported by StrongDM Python SDK
            # self.rdp_service_account_sid_label = ttk.Label(self.resource_form_frame, text="AD Service Account SID (Optional):")
            # self.service_account_sid_var = tk.StringVar()
            # self.rdp_service_account_sid_entry = ttk.Entry(self.resource_form_frame, textvariable=self.service_account_sid_var, )
            # 
            # self.rdp_domain_controller_label = ttk.Label(self.resource_form_frame, text="Domain Controller Hostnames (Optional):")
            # self.domain_controller_var = tk.StringVar()
            # self.rdp_domain_controller_entry = ttk.Entry(self.resource_form_frame, textvariable=self.domain_controller_var, )
            # 
            # self.rdp_domain_controller_info = ttk.Label(self.resource_form_frame, text="💡 Comma-separated hostnames", style="Info.TLabel")
            
            # Store references for toggling visibility (removed unsupported fields)
            self.rdp_cert_fields = {
                'username_label': self.rdp_username_label,
                'username_entry': self.rdp_username_entry,
                'identity_label': self.rdp_identity_label,
                'identity_combo': self.rdp_identity_combo,
                'service_account_label': self.rdp_service_account_label,
                'service_account_entry': self.rdp_service_account_entry,
                'healthcheck_info': self.rdp_healthcheck_info
            }
        
        # Update current_row to be after the RDP Certificate fields if they exist
        if subtype == "Certificate":
            # Certificate fields end at base_row+1 (service account), so set current_row accordingly
            self.current_row = 11  # base_row (9) + 2 fields (identity, service account)
        
        # Downgrade NLA (only for basic auth) - place before lock required
        if subtype == "Basic":
            self.downgrade_nla_var = tk.BooleanVar()
            ttk.Checkbutton(self.resource_form_frame, text="Downgrade NLA Connections", 
                           variable=self.downgrade_nla_var).grid(row=self.current_row, column=1, sticky="w", padx=5, pady=2)
            self.current_row += 1
        
        # Common RDP options - Lock Required (always at bottom before buttons)
        self.lock_required_var = tk.BooleanVar()
        ttk.Checkbutton(self.resource_form_frame, text="Resource Lock Required", 
                       variable=self.lock_required_var).grid(row=self.current_row, column=1, sticky="w", padx=5, pady=2)
        self.current_row += 1
        
    def create_database_fields(self):
        """Create database-specific fields"""
        
        # Move Database Type to the top (after hostname/port, at row 3)
        db_type_row = 3
        self.create_required_label(self.resource_form_frame, "Database Type:", db_type_row)
        self.db_type_var = tk.StringVar(value="mysql")
        db_type_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.db_type_var, 
                                    values=["mysql", "postgresql", "mssql", "redis"], width=37, state="readonly")
        db_type_combo.grid(row=db_type_row, column=1, padx=5, pady=2, sticky="ew")
        db_type_combo.bind("<<ComboboxSelected>>", self.update_db_port)
        
        # Username (required for databases)
        username_row = 4
        self.create_required_label(self.resource_form_frame, "Username:", username_row)
        self.username_var = tk.StringVar()
        ttk.Entry(self.resource_form_frame, textvariable=self.username_var).grid(row=username_row, column=1, padx=5, pady=2, sticky="ew")
        
        # Password (required for databases)
        password_row = 5
        self.create_required_label(self.resource_form_frame, "Password:", password_row)
        self.password_var = tk.StringVar()
        ttk.Entry(self.resource_form_frame, textvariable=self.password_var, 
                 show="*").grid(row=password_row, column=1, padx=5, pady=2, sticky="ew")
        
        # Database Name (optional for some DB types)
        db_name_row = 6
        self.db_name_label = ttk.Label(self.resource_form_frame, text="Database Name:")
        self.db_name_label.grid(row=db_name_row, column=0, sticky="w", padx=5, pady=2)
        self.database_var = tk.StringVar()
        self.db_name_entry = ttk.Entry(self.resource_form_frame, textvariable=self.database_var)
        self.db_name_entry.grid(row=db_name_row, column=1, padx=5, pady=2, sticky="ew")
        
        # Set current_row to continue after database-specific fields
        self.current_row = 7  # Next row after database name
        
        # Add tags interface after database fields
        self.add_tags_interface()
        
        # Initial database type update to set correct port and field requirements
        self.update_db_fields()
        
    def update_db_port(self, event=None):
        """Update port based on database type selection"""
        self.update_db_fields()
        
    def update_db_fields(self):
        """Update port and field requirements based on database type"""
        db_type = self.db_type_var.get()
        
        # Update port based on database type
        port_map = {
            "mysql": "3306",
            "postgresql": "5432", 
            "mssql": "1433",
            "redis": "6379"
        }
        if db_type in port_map:
            self.port_var.set(port_map[db_type])
        
        # Update database name field requirements based on database type
        if hasattr(self, 'db_name_label') and hasattr(self, 'db_name_entry'):
            if db_type == "redis":
                # Redis doesn't typically use database names (uses database numbers)
                self.db_name_label.config(text="Database Number (optional):")
                self.database_var.set("0")  # Default Redis database
            elif db_type == "mssql":
                # MSSQL often requires database name
                self.db_name_label.config(text="Database Name*:")
            else:
                # MySQL and PostgreSQL can be optional
                self.db_name_label.config(text="Database Name:")
        
    def create_single_resource(self):
        """Create a single resource"""
        try:
            resource_type = self.resource_type_var.get()
            subtype = getattr(self, 'subtype_var', tk.StringVar()).get()
            
            # Validate required fields based on type and subtype
            if not self.validate_required_fields(resource_type, subtype):
                return
                
            # Create resource based on type and subtype
            if resource_type == "SSH":
                resource = self.create_ssh_resource(subtype)
            elif resource_type == "RDP":
                resource = self.create_rdp_resource(subtype)
            elif resource_type == "Database":
                resource = self.create_database_resource()
                
            # Debug log the resource object before creation
            if hasattr(self, 'debug_text'):
                from datetime import datetime
                self.debug_text.insert(tk.END, f"[{datetime.now()}] ATTEMPTING RESOURCE CREATION:\n")
                self.debug_text.insert(tk.END, f"  Resource Type: {type(resource).__name__}\n")
                for attr in dir(resource):
                    if not attr.startswith('_') and not callable(getattr(resource, attr)):
                        try:
                            value = getattr(resource, attr)
                            if value:  # Only show non-empty values
                                self.debug_text.insert(tk.END, f"  {attr}: {value}\n")
                        except:
                            pass
                self.debug_text.insert(tk.END, "\n")
                self.debug_text.see(tk.END)
                
            # Add the resource
            self.log_api_call("CREATE", "/resources", resource, None)
            response = self.client.resources.create(resource)
            self.log_api_call("CREATE_RESPONSE", "/resources", None, response)
            success_msg = f"Resource '{self.name_var.get()}' created successfully!"
            messagebox.showinfo("Success", success_msg)
            
            # Don't clear form to allow quick creation of similar resources
            # Only clear the name field to force user to enter a unique name
            self.name_var.set("")
            
        except Exception as e:
            error_msg = f"Failed to create resource: {str(e)}"
            messagebox.showerror("Error", error_msg)
            logger.error(f"Resource creation error: {e}")
            
            # Also log to debug panel if available
            if hasattr(self, 'debug_text'):
                from datetime import datetime
                self.debug_text.insert(tk.END, f"[{datetime.now()}] RESOURCE CREATION ERROR: {str(e)}\n")
                
                # Log the resource details that were attempted
                try:
                    resource_type = self.resource_type_var.get()
                    subtype = getattr(self, 'subtype_var', tk.StringVar()).get()
                    self.debug_text.insert(tk.END, f"  Resource Type: {resource_type}\n")
                    self.debug_text.insert(tk.END, f"  Subtype: {subtype}\n")
                    
                    if resource_type == "RDP" and subtype == "Certificate":
                        credential_type = self.rdp_credential_type_var.get()
                        self.debug_text.insert(tk.END, f"  RDP Credential Type: {credential_type}\n")
                        if credential_type == "Leased Credential":
                            self.debug_text.insert(tk.END, f"  Username: '{self.rdp_username_var.get()}'\n")
                            self.debug_text.insert(tk.END, f"  SID: '{self.rdp_sid_var.get()}'\n")
                        else:
                            self.debug_text.insert(tk.END, f"  Identity Set: '{self.identity_set_id_var.get()}'\n")
                            
                except Exception as debug_e:
                    self.debug_text.insert(tk.END, f"  (Error getting debug details: {debug_e})\n")
                    
                self.debug_text.insert(tk.END, "\n")
                self.debug_text.see(tk.END)
            
    def validate_required_fields(self, resource_type, subtype):
        """Validate required fields based on resource type and subtype"""
        # Common required fields
        if not all([self.name_var.get(), self.hostname_var.get(), self.port_var.get()]):
            messagebox.showerror("Error", "Please fill in Name, Hostname, and Port")
            return False
            
        if resource_type in ["SSH", "RDP"]:
            if resource_type == "SSH":
                if subtype == "Password" and not self.password_var.get():
                    messagebox.showerror("Error", "Password is required for SSH Password authentication")
                    return False
                # PublicKey subtype has no required fields - key pair is auto-generated
                elif subtype == "Certificate":
                    credential_type = self.credential_type_var.get()
                    if credential_type == "Username" and not self.ssh_cert_username_var.get():
                        messagebox.showerror("Error", "Username is required for SSH Certificate authentication")
                        return False
                    elif credential_type == "Identity Alias" and not self.identity_set_var.get():
                        messagebox.showerror("Error", "Identity Set is required for SSH Certificate authentication with Identity Alias")
                        return False
            elif resource_type == "RDP":
                if subtype == "Basic":
                    if not all([self.username_var.get(), self.password_var.get()]):
                        messagebox.showerror("Error", "Username and Password are required for RDP Basic authentication")
                        return False
                elif subtype == "Certificate":
                    credential_type = self.rdp_credential_type_var.get()
                    if credential_type == "Leased Credential" and not self.rdp_username_var.get():
                        messagebox.showerror("Error", "Username is required for RDP Certificate with Leased Credential")
                        return False
                    elif credential_type == "Identity Alias":
                        if not self.identity_set_id_var.get():
                            messagebox.showerror("Error", "Identity Set is required for RDP Certificate with Identity Alias")
                            return False
                        # Check if AD Service Account is provided (recommended for better healthchecks)
                        if not hasattr(self, 'service_account_var') or not self.service_account_var.get().strip():
                            # Show info message but don't block - we have a default
                            logger.info("No AD Service Account specified, using default for healthcheck")
                    # Validate Certificate Authority selection
                    if not self.rdp_certificate_authority_var.get():
                        messagebox.showerror("Error", "Certificate Authority is required for RDP Certificate authentication")
                        return False
        elif resource_type == "Database":
            if not all([self.username_var.get(), self.password_var.get()]):
                messagebox.showerror("Error", "Username and Password are required for Database resources")
                return False
                
        return True
            
    def create_ssh_resource(self, subtype="Password"):
        """Create SSH resource object based on subtype"""
        try:
            # Use specific SSH classes for different authentication types
            if subtype == "Password":
                # SSH with password authentication (SSHPassword class)
                resource = strongdm.SSHPassword(
                    name=self.name_var.get(),
                    hostname=self.hostname_var.get(),
                    port=int(self.port_var.get()),
                    username=self.username_var.get(),
                    password=self.password_var.get()
                )
                    
            elif subtype == "PublicKey":
                # SSH with public key authentication - key pair auto-generated by StrongDM
                resource = strongdm.SSH(
                    name=self.name_var.get(),
                    hostname=self.hostname_var.get(),
                    port=int(self.port_var.get()),
                    username=self.username_var.get()
                    # public_key will be auto-generated by StrongDM
                )
                    
            elif subtype == "Certificate":
                # SSH with certificate authentication (SSHCert class)
                credential_type = self.credential_type_var.get()
                
                if credential_type == "Username":
                    # Use username for certificate authentication
                    resource = strongdm.SSHCert(
                        name=self.name_var.get(),
                        hostname=self.hostname_var.get(),
                        port=int(self.port_var.get()),
                        username=self.ssh_cert_username_var.get()
                    )
                else:  # Identity Alias
                    # Use identity set for certificate authentication
                    resource = strongdm.SSHCert(
                        name=self.name_var.get(),
                        hostname=self.hostname_var.get(),
                        port=int(self.port_var.get())
                    )
                    # Extract ID from the dropdown selection "Name (id-xxx)"
                    identity_selection = self.identity_set_var.get()
                    if '(' in identity_selection and ')' in identity_selection:
                        # Extract ID from "Name (id-xxx)" format
                        identity_id = identity_selection.split('(')[1].split(')')[0]
                        if hasattr(resource, 'identity_set_id'):
                            resource.identity_set_id = identity_id
                    
                # Set key type
                if hasattr(resource, 'key_type'):
                    resource.key_type = self.key_type_var.get()
                    
            elif subtype == "CustomerManagedKey":
                # SSH with customer managed key (might be SSH class with specific attributes)
                private_key_content = self.private_key_text.get("1.0", tk.END).strip()
                resource = strongdm.SSH(
                    name=self.name_var.get(),
                    hostname=self.hostname_var.get(),
                    port=int(self.port_var.get()),
                    username=self.username_var.get(),
                    public_key=private_key_content
                )
                # Set key_type if available
                if hasattr(resource, 'key_type') and hasattr(self, 'key_type_var'):
                    resource.key_type = self.key_type_var.get()
                    
            else:
                raise ValueError(f"Unsupported SSH subtype: {subtype}")
            
            # Add tags if provided
            selected_tags = self.get_selected_tags()
            if selected_tags:
                resource.tags = selected_tags
                
            return resource
            
        except Exception as e:
            logger.error(f"Error creating SSH resource: {e}")
            raise e
        
    def create_rdp_resource(self, subtype="Basic"):
        """Create RDP resource object based on subtype"""
        if subtype == "Basic":
            # Basic RDP with username/password
            resource = strongdm.RDP(
                name=self.name_var.get(),
                hostname=self.hostname_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get(),
                password=self.password_var.get()
            )
            
            # Downgrade NLA option for basic auth
            if hasattr(self, 'downgrade_nla_var'):
                resource.downgrade_nla_connections = self.downgrade_nla_var.get()
                
        elif subtype == "Certificate":
            # RDP with certificate authentication using RDPCert class
            credential_type = self.rdp_credential_type_var.get()
            
            # Get selected certificate authority
            ca_selection = self.rdp_certificate_authority_var.get()
            ca_id = None
            if ca_selection and ca_selection in self.rdp_ca_id_map:
                ca_id = self.rdp_ca_id_map[ca_selection]
            
            if credential_type == "Leased Credential":
                # Leased credential: username + SID (optional)
                resource = strongdm.RDPCert(
                    name=self.name_var.get(),
                    hostname=self.hostname_var.get(),
                    port=int(self.port_var.get()),
                    username=self.rdp_username_var.get()  # Set the username field that API requires
                )
                # Also set the healthcheck username for leased credentials
                resource.identity_alias_healthcheck_username = self.rdp_username_var.get()
                
                # Note: Optional fields removed from UI since they're not supported by StrongDM Python SDK
                    
            else:  # Identity Alias
                # Identity alias: identity set
                resource = strongdm.RDPCert(
                    name=self.name_var.get(),
                    hostname=self.hostname_var.get(),
                    port=int(self.port_var.get())
                )
                # Use identity set for identity alias
                identity_selection = self.identity_set_id_var.get()
                if '(' in identity_selection and ')' in identity_selection:
                    # Extract ID from "Name (id-xxx)" format
                    identity_id = identity_selection.split('(')[1].split(')')[0]
                    resource.identity_set_id = identity_id
                else:
                    # Fallback - use the whole string
                    resource.identity_set_id = identity_selection
                
                # Set the required identity_alias_healthcheck_username
                # Use AD Service Account if provided, otherwise use a default
                healthcheck_username = self.service_account_var.get().strip()
                if not healthcheck_username:
                    # Default to administrator@domain if no service account specified
                    healthcheck_username = "administrator@domain.local"
                resource.identity_alias_healthcheck_username = healthcheck_username
                
                # Note: Optional fields removed from UI since they're not supported by StrongDM Python SDK
                    
            # Debug: Log ALL available attributes for RDPCert
            all_attrs = [attr for attr in dir(resource) if not attr.startswith('_') and not callable(getattr(resource, attr))]
            logger.info(f"ALL RDPCert attributes: {sorted(all_attrs)}")
            
            # Log current values of all attributes
            logger.info("=== RDPCert Current Values ===")
            for attr in sorted(all_attrs):
                try:
                    value = getattr(resource, attr)
                    logger.info(f"  {attr}: {value}")
                except:
                    logger.info(f"  {attr}: <error getting value>")
            logger.info("=== End RDPCert Values ===")
            
            # Note: Certificate Authority is not supported by StrongDM Python SDK RDPCert object
            # Certificate authority is likely managed through StrongDM internally
            if ca_id:
                logger.info(f"NOTE: Certificate Authority '{ca_selection}' not set - not supported by RDPCert object")
                
        else:
            raise ValueError(f"Unsupported RDP subtype: {subtype}")
        
        # Common RDP options
        if hasattr(self, 'lock_required_var'):
            resource.lock_required = self.lock_required_var.get()
            
        # Add tags if provided
        selected_tags = self.get_selected_tags()
        if selected_tags:
            resource.tags = selected_tags
            
        return resource
        
    def create_database_resource(self):
        """Create database resource object"""
        db_type = self.db_type_var.get()
        
        # Create appropriate database resource type  
        if db_type == "mysql":
            resource = strongdm.Mysql(
                name=self.name_var.get(),
                hostname=self.hostname_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get(),
                password=self.password_var.get()
            )
        elif db_type == "postgresql":
            resource = strongdm.Postgres(
                name=self.name_var.get(),
                hostname=self.hostname_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get(),
                password=self.password_var.get()
            )
        elif db_type == "mssql":
            resource = strongdm.SQLServer(
                name=self.name_var.get(),
                hostname=self.hostname_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get(),
                password=self.password_var.get()
            )
        elif db_type == "redis":
            resource = strongdm.Redis(
                name=self.name_var.get(),
                hostname=self.hostname_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get() if self.username_var.get() else "",
                password=self.password_var.get()
            )
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
        
        if hasattr(resource, 'database') and self.database_var.get():
            resource.database = self.database_var.get()
            
        # Add tags if provided
        selected_tags = self.get_selected_tags()
        if selected_tags:
            resource.tags = selected_tags
            
        return resource
        
    def setup_csv_import_tab(self):
        """Setup CSV bulk import tab"""
        
        # Instructions with better styling
        instructions_frame = ttk.LabelFrame(self.csv_import_frame, text="CSV Format Requirements")
        instructions_frame.pack(fill="x", padx=10, pady=5)
        
        # Main instructions text with left alignment and bold style
        instructions_text = """Required columns: type, name, hostname, port, username, password
Optional columns: tags, secret_store, proxy_cluster, database_name, key_type
Supported types: SSH, RDP, RDP Certificate, MySQL, PostgreSQL, MSSQL, Redis
Boolean fields (lock_required, downgrade_nla): use true/false"""
        
        ttk.Label(instructions_frame, text=instructions_text, justify="left", 
                 style="Instruction.TLabel").pack(anchor="w", padx=15, pady=10)
        
        # File selection
        file_frame = ttk.LabelFrame(self.csv_import_frame, text="Select CSV File")
        file_frame.pack(fill="x", padx=10, pady=5)
        
        self.csv_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.csv_file_var).pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(file_frame, text="📁 Browse", style="Primary.TButton",
                  command=self.browse_csv_file).pack(side="left", padx=5)
        
        # Import options
        options_frame = ttk.LabelFrame(self.csv_import_frame, text="Import Options")
        options_frame.pack(fill="x", padx=10, pady=5)
        
        self.skip_errors_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Skip rows with errors and continue", 
                       variable=self.skip_errors_var).pack(anchor="w", padx=10)
        
        self.dry_run_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Dry run (validate only, don't create)", 
                       variable=self.dry_run_var).pack(anchor="w", padx=10)
        
        # Import button
        ttk.Button(self.csv_import_frame, text="🚀 Import Resources", style="Primary.TButton",
                  command=self.import_csv_resources).pack(pady=20)
        
        # Progress
        self.progress_var = tk.StringVar(value="Ready to import")
        ttk.Label(self.csv_import_frame, textvariable=self.progress_var).pack()
        
        self.progress_bar = ttk.Progressbar(self.csv_import_frame, mode='indeterminate')
        self.progress_bar.pack(fill="x", padx=10, pady=5)
        
        # Results
        results_frame = ttk.LabelFrame(self.csv_import_frame, text="Import Results")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.results_text = tk.Text(results_frame, height=15, 
                                   bg='white', fg='black', 
                                   font=('Segoe UI', 9), 
                                   relief='flat', borderwidth=1,
                                   selectbackground='#dbeafe')
        results_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=results_scrollbar.set)
        
        self.results_text.pack(side="left", fill="both", expand=True)
        results_scrollbar.pack(side="right", fill="y")
        
    def browse_csv_file(self):
        """Browse for CSV file"""
        filename = filedialog.askopenfilename(
            title="Select CSV file",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            self.csv_file_var.set(filename)
            
    def import_csv_resources(self):
        """Import resources from CSV file"""
        csv_file = self.csv_file_var.get()
        if not csv_file:
            messagebox.showerror("Error", "Please select a CSV file")
            return
            
        if not os.path.exists(csv_file):
            messagebox.showerror("Error", "CSV file does not exist")
            return
            
        # Start import in separate thread
        thread = threading.Thread(target=self._import_csv_worker, args=(csv_file,))
        thread.daemon = True
        thread.start()
        
    def _import_csv_worker(self, csv_file):
        """Worker thread for CSV import"""
        try:
            self.progress_bar.start()
            self.progress_var.set("Reading CSV file...")
            self.results_text.delete(1.0, tk.END)
            
            with open(csv_file, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
            total_rows = len(rows)
            success_count = 0
            error_count = 0
            
            self.results_text.insert(tk.END, f"Processing {total_rows} resources...\n\n")
            
            for i, row in enumerate(rows, 1):
                try:
                    self.progress_var.set(f"Processing row {i} of {total_rows}")
                    
                    resource = self.create_resource_from_csv_row(row)
                    
                    if not self.dry_run_var.get():
                        response = self.client.resources.create(resource)
                        
                    self.results_text.insert(tk.END, f"✓ Row {i}: {row.get('name', 'Unknown')} - Success\n")
                    success_count += 1
                    
                except Exception as e:
                    error_msg = f"✗ Row {i}: {row.get('name', 'Unknown')} - Error: {str(e)}\n"
                    self.results_text.insert(tk.END, error_msg)
                    error_count += 1
                    
                    if not self.skip_errors_var.get():
                        break
                        
                self.results_text.see(tk.END)
                self.root.update()
                
            # Summary
            summary = f"\n--- Import Complete ---\n"
            summary += f"Total processed: {i}\n"
            summary += f"Successful: {success_count}\n"
            summary += f"Errors: {error_count}\n"
            
            if self.dry_run_var.get():
                summary += "\nDry run completed - no resources were actually created.\n"
                
            self.results_text.insert(tk.END, summary)
            self.results_text.see(tk.END)
            
        except Exception as e:
            error_msg = f"Import failed: {str(e)}\n"
            self.results_text.insert(tk.END, error_msg)
            logger.error(f"CSV import error: {e}")
            
        finally:
            self.progress_bar.stop()
            self.progress_var.set("Import completed")
            
    def create_resource_from_csv_row(self, row):
        """Create resource object from CSV row"""
        resource_type = row.get('type', '').upper()
        
        if resource_type == 'SSH':
            resource = strongdm.SSH(
                name=row['name'],
                hostname=row['hostname'],
                port=int(row['port']),
                username=row['username']
            )
            
            # SSH objects use public_key field, not password
            if row.get('password'):
                if row.get('key_type') == 'private_key' or '-----BEGIN' in row['password']:
                    # This is a private key
                    resource.public_key = row['password']  
                else:
                    # This is a password - but SSH objects don't support password auth
                    # SSH resources typically use key-based authentication in StrongDM
                    logger.warning(f"SSH resource '{row['name']}' password ignored - SSH resources use key-based authentication")
                    resource.public_key = ""  # Set empty key if no key provided
                
        elif resource_type == 'RDP':
            resource = strongdm.RDP(
                name=row['name'],
                hostname=row['hostname'],
                port=int(row['port']),
                username=row['username'],
                password=row['password']
            )
            
            if row.get('lock_required', '').lower() == 'true':
                resource.lock_required = True
            if row.get('downgrade_nla', '').lower() == 'true':
                resource.downgrade_nla_connections = True
                
        elif resource_type == 'RDP CERTIFICATE':
            # Handle RDP Certificate resources
            resource = strongdm.RDPCert(
                name=row['name'],
                hostname=row['hostname'],
                port=int(row['port'])
            )
            
            # Set identity set if provided (skip if it's a friendly name, needs actual ID)
            if row.get('identity_set') and row['identity_set'].startswith('ig-'):
                resource.identity_set_id = row['identity_set']
            elif row.get('identity_set'):
                logger.warning(f"Skipping identity set '{row['identity_set']}' - CSV import requires actual identity set ID (ig-xxxxx format)")
            
            # Set username if provided (for leased credential)
            if row.get('username'):
                resource.username = row['username']
                resource.identity_alias_healthcheck_username = row['username']
            
            # Set service account as healthcheck username if no username provided
            if row.get('service_account') and not row.get('username'):
                resource.identity_alias_healthcheck_username = row['service_account']
            
            if row.get('lock_required', '').lower() == 'true':
                resource.lock_required = True
            
            # Note: RDPCert objects don't support downgrade_nla_connections
            if row.get('downgrade_nla', '').lower() == 'true':
                logger.warning(f"Skipping downgrade_nla for RDP Certificate '{row['name']}' - not supported by RDPCert objects")
                
        elif resource_type in ['MYSQL', 'POSTGRESQL', 'MSSQL', 'REDIS']:
            if resource_type == 'MYSQL':
                resource = strongdm.Mysql(
                    name=row['name'],
                    hostname=row['hostname'],
                    port=int(row['port']),
                    username=row['username'],
                    password=row['password']
                )
            elif resource_type == 'POSTGRESQL':
                resource = strongdm.Postgres(
                    name=row['name'],
                    hostname=row['hostname'],
                    port=int(row['port']),
                    username=row['username'],
                    password=row['password']
                )
            elif resource_type == 'MSSQL':
                resource = strongdm.SQLServer(
                    name=row['name'],
                    hostname=row['hostname'],
                    port=int(row['port']),
                    username=row['username'],
                    password=row['password']
                )
            elif resource_type == 'REDIS':
                resource = strongdm.Redis(
                    name=row['name'],
                    hostname=row['hostname'],
                    port=int(row['port']),
                    username=row.get('username', ''),
                    password=row['password']
                )
            
            if row.get('database_name'):
                resource.database = row['database_name']
                
        else:
            raise ValueError(f"Unsupported resource type: {resource_type}")
            
        # Add tags if provided
        if row.get('tags'):
            tag_input = row['tags'].strip()
            # Handle multiple delimiters: =, :, -, | (= first to match GUI format)
            delimiters = ["=", ":", "-", "|"]
            tag_key = tag_input
            tag_value = ""
            
            for delimiter in delimiters:
                if delimiter in tag_input:
                    parts = tag_input.split(delimiter, 1)
                    tag_key = parts[0].strip()
                    tag_value = parts[1].strip()
                    break
            
            resource.tags = {tag_key: tag_value}
            
        return resource
        
    def setup_debug_tab(self):
        """Setup debug tab"""
        
        # Create scrollable frame for debug buttons - full width scaling
        debug_canvas = tk.Canvas(self.debug_frame)
        debug_scrollbar = ttk.Scrollbar(self.debug_frame, orient="vertical", command=debug_canvas.yview)
        debug_scrollable_frame = ttk.Frame(debug_canvas)
        
        # Bind both configure events for proper scaling in both dimensions
        debug_scrollable_frame.bind(
            "<Configure>",
            lambda e: debug_canvas.configure(scrollregion=debug_canvas.bbox("all"))
        )
        debug_canvas.bind(
            "<Configure>",
            lambda e: debug_canvas.itemconfig(debug_window, width=e.width)
        )
        
        debug_window = debug_canvas.create_window((0, 0), window=debug_scrollable_frame, anchor="nw")
        debug_canvas.configure(yscrollcommand=debug_scrollbar.set)
        
        # API Test Section with grid layout for better button wrapping
        api_test_frame = ttk.LabelFrame(debug_scrollable_frame, text="API Testing")
        api_test_frame.pack(fill="x", padx=10, pady=5)
        api_test_frame.grid_columnconfigure(0, weight=1)
        api_test_frame.grid_columnconfigure(1, weight=1)
        api_test_frame.grid_columnconfigure(2, weight=1)
        
        # Debug buttons in a 3-column grid for better wrapping
        buttons = [
            ("Test Connection", self.test_connection),
            ("List Resources", self.list_resources),
            ("List Tags", self.list_tags),
            ("List Secret Stores", self.list_secret_stores),
            ("List Proxy Clusters", self.debug_proxy_clusters),
            ("Debug Resource Tags", self.debug_resource_tags),
            ("Tag Management", self.debug_tag_management),
        ]
        
        for i, (text, command) in enumerate(buttons):
            row = i // 3
            col = i % 3
            ttk.Button(api_test_frame, text=text, command=command).grid(
                row=row, column=col, padx=5, pady=2, sticky="ew"
            )
        
        # Custom Query Section
        query_frame = ttk.LabelFrame(debug_scrollable_frame, text="Custom Query")
        query_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(query_frame, text="Filter:").pack(side="left")
        self.query_var = tk.StringVar()
        ttk.Entry(query_frame, textvariable=self.query_var).pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(query_frame, text="Execute", 
                  command=self.execute_query).pack(side="left", padx=5)
        
        # Debug Output
        output_frame = ttk.LabelFrame(debug_scrollable_frame, text="Debug Output")
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.debug_text = tk.Text(output_frame, height=20,
                                 bg='white', fg='black', 
                                 font=('Segoe UI', 9), 
                                 relief='flat', borderwidth=1,
                                 selectbackground='#dbeafe')
        debug_output_scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.debug_text.yview)
        self.debug_text.configure(yscrollcommand=debug_output_scrollbar.set)
        
        self.debug_text.pack(side="left", fill="both", expand=True)
        debug_output_scrollbar.pack(side="right", fill="y")
        
        # Add clear debug button at bottom
        clear_frame = ttk.Frame(debug_scrollable_frame)
        clear_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(clear_frame, text="Clear Debug Window", 
                  command=self.clear_debug_window, 
                  style="Danger.TButton").pack(pady=5)
        
        # Pack the scrollable canvas with minimal padding
        debug_canvas.pack(side="left", fill="both", expand=True, padx=(2, 0))
        debug_scrollbar.pack(side="right", fill="y", padx=(0, 2))
        
    def test_connection(self):
        """Test API connection"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Testing connection...\n")
            
            accounts = list(self.client.accounts.list(""))
            if accounts:
                accounts = accounts[:1]  # Take only first account
            self.debug_text.insert(tk.END, f"✓ Connection successful! Found {len(accounts)} account(s)\n")
            
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Connection failed: {str(e)}\n")
            
        self.debug_text.see(tk.END)
    
    def clear_debug_window(self):
        """Clear the debug output window"""
        self.debug_text.delete(1.0, tk.END)
        self.debug_text.insert(tk.END, f"[{datetime.now()}] Debug window cleared.\n")
        
    def list_resources(self):
        """List all resources"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Listing resources...\n")
            
            resources = list(self.client.resources.list(""))
            self.log_api_call("DEBUG_LIST", "/resources", None, f"Found {len(resources)} resources")
            self.debug_text.insert(tk.END, f"Found {len(resources)} resources:\n")
            
            for resource in resources:
                self.debug_text.insert(tk.END, f"  - {resource.name} ({type(resource).__name__})\n")
                
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Failed to list resources: {str(e)}\n")
            
        self.debug_text.see(tk.END)
        
    def list_tags(self):
        """List all tags from existing resources"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Listing tags from resources...\n")
            
            # Get tags from existing resources (same method as load_tenant_data)
            tags = set()
            resources = list(self.client.resources.list(""))
            
            self.debug_text.insert(tk.END, f"Scanning {len(resources)} resources for tags...\n")
            
            for resource in resources:
                if hasattr(resource, 'tags') and resource.tags:
                    for tag_key, tag_value in resource.tags.items():
                        if tag_value:
                            # Create key=value format to match GUI format
                            tag_pair = f"{tag_key}={tag_value}"
                            tags.add(tag_pair)
                        else:
                            # If no value, just add the key
                            tags.add(tag_key)
            
            tags = sorted(list(tags))
            self.debug_text.insert(tk.END, f"Found {len(tags)} unique tags:\n")
            
            if tags:
                for tag in tags:
                    self.debug_text.insert(tk.END, f"  - {tag}\n")
            else:
                self.debug_text.insert(tk.END, "  No tags found on existing resources\n")
                
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Failed to list tags: {str(e)}\n")
            
        self.debug_text.see(tk.END)
        
    def list_secret_stores(self):
        """List all secret stores"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Listing secret stores...\n")
            
            stores = list(self.client.secret_stores.list(""))
            self.debug_text.insert(tk.END, f"Found {len(stores)} secret stores:\n")
            
            for store in stores:
                self.debug_text.insert(tk.END, f"  - {store.name} ({type(store).__name__})\n")
                
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Failed to list secret stores: {str(e)}\n")
            
        self.debug_text.see(tk.END)
        
    def execute_query(self):
        """Execute custom query"""
        try:
            query = self.query_var.get()
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Executing query: '{query}'\n")
            
            resources = list(self.client.resources.list(query))
            self.debug_text.insert(tk.END, f"Query returned {len(resources)} resources:\n")
            
            for resource in resources:
                self.debug_text.insert(tk.END, f"  - {resource.name} ({type(resource).__name__})\n")
                
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Query failed: {str(e)}\n")
            
        self.debug_text.see(tk.END)
        
    def debug_resource_tags(self):
        """Debug detailed resource tag information"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Debugging resource tags in detail...\n")
            
            resources = list(self.client.resources.list(""))
            self.debug_text.insert(tk.END, f"Found {len(resources)} resources:\n\n")
            
            for i, resource in enumerate(resources, 1):
                resource_name = getattr(resource, 'name', f'Resource_{i}')
                resource_type = type(resource).__name__
                
                self.debug_text.insert(tk.END, f"Resource {i}: {resource_name} ({resource_type})\n")
                
                # Check all possible tag attributes
                tag_attrs_found = []
                for attr in ['tags', 'tag', 'labels', 'metadata']:
                    if hasattr(resource, attr):
                        value = getattr(resource, attr)
                        if value:
                            tag_attrs_found.append(f"  - {attr}: {value} (type: {type(value).__name__})")
                
                if tag_attrs_found:
                    self.debug_text.insert(tk.END, "  Tag attributes found:\n")
                    for attr_info in tag_attrs_found:
                        self.debug_text.insert(tk.END, f"{attr_info}\n")
                else:
                    self.debug_text.insert(tk.END, "  - No tag attributes found\n")
                
                # Show all attributes to see what's available
                self.debug_text.insert(tk.END, "  All attributes:\n")
                attrs = [attr for attr in dir(resource) if not attr.startswith('_') and not callable(getattr(resource, attr, None))]
                for attr in attrs[:10]:  # Show first 10 non-callable attributes
                    try:
                        value = getattr(resource, attr)
                        self.debug_text.insert(tk.END, f"    - {attr}: {value}\n")
                    except:
                        self.debug_text.insert(tk.END, f"    - {attr}: (error reading)\n")
                
                if len(attrs) > 10:
                    self.debug_text.insert(tk.END, f"    ... and {len(attrs) - 10} more attributes\n")
                    
                self.debug_text.insert(tk.END, "\n")
            
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Debug resource tags failed: {str(e)}\n")
            
        self.debug_text.see(tk.END)
        
    def debug_proxy_clusters(self):
        """Debug proxy clusters API call"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Testing proxy clusters API call...\n")
            
            # First, let's check what attributes are available on the client
            self.debug_text.insert(tk.END, "Available client attributes:\n")
            client_attrs = [attr for attr in dir(self.client) if not attr.startswith('_')]
            for attr in client_attrs:
                self.debug_text.insert(tk.END, f"  - {attr}\n")
            
            self.debug_text.insert(tk.END, "\nTrying different proxy cluster API approaches...\n")
            
            # Try different possible API endpoints
            possible_endpoints = [
                ('nodes', 'self.client.nodes.list("")'),
                ('proxy_cluster_keys', 'self.client.proxy_cluster_keys.list("")'),
                ('clusters', 'getattr(self.client, "clusters", None)'),
                ('proxies', 'getattr(self.client, "proxies", None)')
            ]
            
            found_clusters = False
            for endpoint_name, endpoint_code in possible_endpoints:
                try:
                    self.debug_text.insert(tk.END, f"\nTrying {endpoint_name}...\n")
                    
                    if endpoint_name == 'nodes':
                        clusters_response = self.client.nodes.list("")
                        clusters_list = list(clusters_response)
                        
                        self.debug_text.insert(tk.END, f"Found {len(clusters_list)} nodes:\n")
                        for node in clusters_list:
                            self.debug_text.insert(tk.END, f"  - {node.name} (Type: {type(node).__name__})\n")
                            # Check if this is a proxy cluster node
                            for attr in ['type', 'kind', 'role']:
                                if hasattr(node, attr):
                                    value = getattr(node, attr)
                                    self.debug_text.insert(tk.END, f"    {attr}: {value}\n")
                        found_clusters = True
                        
                    elif endpoint_name == 'proxy_cluster_keys':
                        clusters_response = self.client.proxy_cluster_keys.list("")
                        clusters_list = list(clusters_response)
                        
                        self.debug_text.insert(tk.END, f"Found {len(clusters_list)} proxy cluster keys:\n")
                        for key in clusters_list:
                            self.debug_text.insert(tk.END, f"  - {getattr(key, 'name', 'unnamed')} (ID: {getattr(key, 'id', 'no-id')})\n")
                        found_clusters = True
                        
                except Exception as e:
                    self.debug_text.insert(tk.END, f"  ✗ {endpoint_name} failed: {str(e)}\n")
            
            if not found_clusters:
                self.debug_text.insert(tk.END, "\n⚠️ No proxy cluster API endpoints found. This might mean:\n")
                self.debug_text.insert(tk.END, "  1. No proxy clusters are configured in this tenant\n")
                self.debug_text.insert(tk.END, "  2. The API endpoint name is different\n")
                self.debug_text.insert(tk.END, "  3. Insufficient permissions to list clusters\n")
                
            # Also show what's currently loaded in the dropdown
            self.debug_text.insert(tk.END, f"\nCurrent dropdown values: {self.proxy_clusters}\n")
            
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Debug proxy clusters failed: {str(e)}\n")
            
        self.debug_text.see(tk.END)
    
    def debug_tag_management(self):
        """Debug tag management and unused tags"""
        from datetime import datetime
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Exploring tag management capabilities...\n")
            
            # First, let's check for tag-related endpoints
            self.debug_text.insert(tk.END, "\n=== Searching for Tag-Related API Endpoints ===\n")
            client_attrs = [attr for attr in dir(self.client) if not attr.startswith('_')]
            tag_related = []
            
            for attr in client_attrs:
                if 'tag' in attr.lower():
                    tag_related.append(attr)
                    endpoint = getattr(self.client, attr)
                    self.debug_text.insert(tk.END, f"🏷️  Found: {attr}")
                    if hasattr(endpoint, 'list'):
                        self.debug_text.insert(tk.END, " (has list method)")
                    if hasattr(endpoint, 'create'):
                        self.debug_text.insert(tk.END, " (has create method)")
                    if hasattr(endpoint, 'delete'):
                        self.debug_text.insert(tk.END, " (has delete method)")
                    self.debug_text.insert(tk.END, "\n")
            
            if not tag_related:
                self.debug_text.insert(tk.END, "❌ No direct tag management endpoints found\n")
            
            # Get all resources and analyze tag usage
            self.debug_text.insert(tk.END, "\n=== Analyzing Tag Usage Across Resources ===\n")
            resources = list(self.client.resources.list(""))
            
            all_tags = {}  # tag_key:tag_value -> count
            resource_count = 0
            
            for resource in resources:
                resource_count += 1
                if hasattr(resource, 'tags') and resource.tags:
                    for tag_key, tag_value in resource.tags.items():
                        tag_combo = f"{tag_key}={tag_value}" if tag_value else tag_key
                        all_tags[tag_combo] = all_tags.get(tag_combo, 0) + 1
            
            self.debug_text.insert(tk.END, f"📊 Analyzed {resource_count} resources\n")
            self.debug_text.insert(tk.END, f"📋 Found {len(all_tags)} unique tag combinations:\n\n")
            
            # Sort tags by usage (most used first)
            sorted_tags = sorted(all_tags.items(), key=lambda x: x[1], reverse=True)
            
            for tag, count in sorted_tags:
                self.debug_text.insert(tk.END, f"  • {tag} (used {count} times)\n")
            
            # Look for potential cleanup candidates
            self.debug_text.insert(tk.END, "\n=== Tag Cleanup Analysis ===\n")
            single_use_tags = [tag for tag, count in sorted_tags if count == 1]
            
            if single_use_tags:
                self.debug_text.insert(tk.END, f"⚠️  Found {len(single_use_tags)} tags used only once:\n")
                for tag in single_use_tags:
                    self.debug_text.insert(tk.END, f"  • {tag}\n")
            else:
                self.debug_text.insert(tk.END, "✅ No single-use tags found\n")
            
            # Note about tag management
            self.debug_text.insert(tk.END, "\n=== Tag Management Notes ===\n")
            self.debug_text.insert(tk.END, "📝 Tags are managed at the resource level in StrongDM\n")
            self.debug_text.insert(tk.END, "📝 To delete unused tags, update/remove them from resources\n")
            self.debug_text.insert(tk.END, "📝 No separate tag entity management endpoint appears to exist\n")
            
            self.debug_text.insert(tk.END, "\n✅ Tag analysis completed\n\n")
            
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Debug tag management failed: {str(e)}\n")
            
        self.debug_text.see(tk.END)
        
    def setup_api_logs_tab(self):
        """Setup API logs tab"""
        
        # Control buttons
        control_frame = ttk.LabelFrame(self.api_logs_frame, text="API Logging Controls")
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="🔄 Refresh Logs", 
                  command=self.refresh_api_logs).pack(side="left", padx=5)
        ttk.Button(control_frame, text="🗑️ Clear Logs", 
                  command=self.clear_api_logs).pack(side="left", padx=5)
        ttk.Button(control_frame, text="📋 Copy All", 
                  command=self.copy_api_logs).pack(side="left", padx=5)
        
        # Enable/Disable logging (use existing variable)
        ttk.Checkbutton(control_frame, text="Enable API Logging", 
                       variable=self.api_logging_enabled).pack(side="left", padx=10)
        
        # API Logs Output
        logs_frame = ttk.LabelFrame(self.api_logs_frame, text="API Request/Response Logs")
        logs_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.api_logs_text = tk.Text(logs_frame, height=25, 
                                    bg='white', fg='black',
                                    font=('Consolas', 9), 
                                    relief='flat', borderwidth=1,
                                    selectbackground='#dbeafe')
        api_scrollbar = ttk.Scrollbar(logs_frame, orient="vertical", command=self.api_logs_text.yview)
        self.api_logs_text.configure(yscrollcommand=api_scrollbar.set)
        
        self.api_logs_text.pack(side="left", fill="both", expand=True)
        api_scrollbar.pack(side="right", fill="y")
        
    def refresh_api_logs(self):
        """Refresh API logs display"""
        logs_content = self.api_log_buffer.getvalue()
        self.api_logs_text.delete(1.0, tk.END)
        self.api_logs_text.insert(1.0, logs_content)
        self.api_logs_text.see(tk.END)
        
    def clear_api_logs(self):
        """Clear API logs"""
        self.api_log_buffer.seek(0)
        self.api_log_buffer.truncate(0)
        self.api_logs_text.delete(1.0, tk.END)
        
    def copy_api_logs(self):
        """Copy API logs to clipboard"""
        logs_content = self.api_log_buffer.getvalue()
        self.root.clipboard_clear()
        self.root.clipboard_append(logs_content)
        messagebox.showinfo("Copied", "API logs copied to clipboard!")
        
    def log_api_call(self, method, endpoint, data=None, response=None):
        """Log API call details"""
        if not self.api_logging_enabled.get():
            return
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        log_entry = f"\n{'='*60}\n"
        log_entry += f"[{timestamp}] {method} {endpoint}\n"
        log_entry += f"{'='*60}\n"
        
        if data:
            log_entry += f"REQUEST DATA:\n{json.dumps(data, indent=2, default=str)}\n\n"
        
        if response:
            if hasattr(response, '__dict__'):
                # Convert object to dict
                response_dict = {}
                for attr in dir(response):
                    if not attr.startswith('_'):
                        try:
                            value = getattr(response, attr)
                            if not callable(value):
                                response_dict[attr] = value
                        except:
                            pass
                log_entry += f"RESPONSE:\n{json.dumps(response_dict, indent=2, default=str)}\n"
            else:
                log_entry += f"RESPONSE:\n{response}\n"
        
        self.api_log_buffer.write(log_entry)
        
        # Auto-refresh API logs display if it exists
        if hasattr(self, 'api_logs_text'):
            try:
                self.root.after_idle(self.refresh_api_logs)
            except:
                pass  # Widget might not exist yet
        
    def save_credentials(self):
        """Save API credentials to local config file"""
        try:
            # Create config directory if it doesn't exist
            self.config_dir.mkdir(exist_ok=True)
            
            # Simple encoding (not encryption, just obfuscation)
            access_key = base64.b64encode(self.access_key_var.get().encode()).decode()
            secret_key = base64.b64encode(self.secret_key_var.get().encode()).decode()
            
            config = {
                "access_key": access_key,
                "secret_key": secret_key,
                "saved_at": datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
                
            logger.info("Credentials saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")
            messagebox.showerror("Error", f"Failed to save credentials: {str(e)}")
            
    def load_saved_credentials(self):
        """Load saved API credentials if they exist"""
        try:
            if not self.config_file.exists():
                return
                
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                
            # Decode credentials
            access_key = base64.b64decode(config["access_key"]).decode()
            secret_key = base64.b64decode(config["secret_key"]).decode()
            
            # Set in UI
            self.access_key_var.set(access_key)
            self.secret_key_var.set(secret_key)
            self.save_credentials_var.set(True)
            
            # Show when credentials were saved
            saved_at = config.get("saved_at", "Unknown")
            self.status_label.config(text=f"Credentials loaded (saved: {saved_at[:10]}) - Attempting auto-login...", 
                                   foreground="blue")
            
            logger.info("Credentials loaded successfully - attempting auto-login")
            
            # Automatically attempt to connect
            try:
                self.authenticate()
            except Exception as auto_login_e:
                logger.error(f"Auto-login failed: {auto_login_e}")
                self.status_label.config(text=f"Auto-login failed: {str(auto_login_e)}", 
                                       foreground="red")
            
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
            # Don't show error to user, just log it
            
    def clear_saved_credentials(self):
        """Clear saved credentials"""
        try:
            if self.config_file.exists():
                self.config_file.unlink()
                
            # Clear UI
            self.access_key_var.set("")
            self.secret_key_var.set("")
            self.save_credentials_var.set(False)
            self.status_label.config(text="Saved credentials cleared", 
                                   foreground="orange")
            
            logger.info("Credentials cleared successfully")
            
        except Exception as e:
            logger.error(f"Failed to clear credentials: {e}")
            messagebox.showerror("Error", f"Failed to clear credentials: {str(e)}")
        
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = StrongDMManager()
    app.run()