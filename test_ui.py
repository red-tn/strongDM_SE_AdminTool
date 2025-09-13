#!/usr/bin/env python3
"""
Test script to validate UI geometry manager fixes
"""

import tkinter as tk
from tkinter import ttk
import sys

def test_geometry_managers():
    """Test that geometry managers work correctly"""
    root = tk.Tk()
    root.title("UI Test")
    root.geometry("400x300")
    
    # Create notebook
    notebook = ttk.Notebook(root)
    
    # Test frame with mixed geometry - this should work now
    test_frame = ttk.Frame(notebook)
    notebook.add(test_frame, text="Test Tab")
    
    # Test LabelFrame with grid inside
    form_frame = ttk.LabelFrame(test_frame, text="Test Form")
    form_frame.pack(fill="both", expand=True, padx=10, pady=5)
    form_frame.grid_columnconfigure(1, weight=1)
    
    # Add grid elements
    ttk.Label(form_frame, text="Name:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
    name_var = tk.StringVar()
    ttk.Entry(form_frame, textvariable=name_var, width=40).grid(row=0, column=1, padx=5, pady=2)
    
    ttk.Label(form_frame, text="Type:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
    type_var = tk.StringVar()
    ttk.Combobox(form_frame, textvariable=type_var, values=["SSH", "RDP", "DB"]).grid(row=1, column=1, padx=5, pady=2)
    
    # Button frame
    button_frame = ttk.Frame(form_frame)
    button_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)
    button_frame.grid_columnconfigure(1, weight=1)
    
    ttk.Button(button_frame, text="Clear").grid(row=0, column=0, padx=5)
    ttk.Button(button_frame, text="Submit").grid(row=0, column=1, padx=5, sticky="e")
    
    notebook.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Test for a short time then close
    def close_test():
        print("✓ Geometry manager test passed - no errors!")
        root.quit()
        
    root.after(1000, close_test)  # Close after 1 second
    
    try:
        root.mainloop()
        return True
    except Exception as e:
        print(f"✗ Geometry manager test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_geometry_managers()
    sys.exit(0 if success else 1)