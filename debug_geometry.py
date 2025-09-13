#!/usr/bin/env python3
"""
Debug script to identify geometry manager issues
"""
import tkinter as tk
from tkinter import ttk
import sys

# Test the exact issue mentioned
root = tk.Tk()
root.title("Geometry Debug Test")
root.geometry("600x400")

try:
    # Create notebook like in the main app
    notebook = ttk.Notebook(root)
    
    # Login frame (uses pack)
    login_frame = ttk.Frame(notebook)
    notebook.add(login_frame, text="Login")
    
    login_container = ttk.Frame(login_frame)
    login_container.pack(expand=True)
    
    ttk.Label(login_container, text="Test Login Form", 
             font=("Arial", 16, "bold")).pack(pady=20)
    
    # Resource frame (uses pack at top level, grid inside)
    resource_frame = ttk.Frame(notebook)
    notebook.add(resource_frame, text="Resources")
    
    # This should work - pack at top level
    type_frame = ttk.LabelFrame(resource_frame, text="Resource Type")
    type_frame.pack(fill="x", padx=10, pady=5)
    
    # This should work - pack inside type_frame
    ttk.Radiobutton(type_frame, text="SSH", value="SSH").pack(side="left")
    ttk.Radiobutton(type_frame, text="RDP", value="RDP").pack(side="left")
    
    # This should work - pack at top level
    form_frame = ttk.LabelFrame(resource_frame, text="Resource Details")
    form_frame.pack(fill="both", expand=True, padx=10, pady=5)
    form_frame.grid_columnconfigure(1, weight=1)
    
    # This should work - grid inside form_frame
    ttk.Label(form_frame, text="Name:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
    ttk.Entry(form_frame, width=40).grid(row=0, column=1, padx=5, pady=2)
    
    # This should work - grid inside form_frame
    button_frame = ttk.Frame(form_frame)
    button_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=10)
    button_frame.grid_columnconfigure(1, weight=1)
    
    # This should work - grid inside button_frame
    ttk.Button(button_frame, text="Clear").grid(row=0, column=0, padx=5)
    ttk.Button(button_frame, text="Create").grid(row=0, column=1, padx=5, sticky="e")
    
    notebook.pack(fill="both", expand=True, padx=10, pady=10)
    
    print("✓ No geometry manager errors detected")
    print("If you see this message, the geometry is working correctly")
    
    # Auto-close after 2 seconds
    root.after(2000, root.quit)
    root.mainloop()
    
except Exception as e:
    print(f"✗ Geometry manager error: {e}")
    sys.exit(1)

print("Test completed successfully")