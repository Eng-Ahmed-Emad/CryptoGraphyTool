import tkinter as tk
from tkinter import ttk, messagebox
from ciphers import *

def create_gui():
    # Create the main window
    root = tk.Tk()
    root.title("Cryptography Tool")
    root.geometry("600x500")
    
    # Create a frame to hold all widgets
    main_frame = ttk.Frame(root, padding="10")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    # Create cipher selection dropdown
    ttk.Label(main_frame, text="Select Cipher:").grid(row=0, column=0, sticky=tk.W)
    cipher_var = tk.StringVar()
    cipher_combo = ttk.Combobox(main_frame, textvariable=cipher_var)
    cipher_combo['values'] = ('Caesar', 'Affine', 'Vigenère', 'Rail Fence')
    cipher_combo.grid(row=0, column=1, sticky=tk.W)
    
    # Create frame for key inputs (will be populated based on cipher selection)
    key_frame = ttk.Frame(main_frame)
    key_frame.grid(row=1, column=0, columnspan=2, sticky=tk.W)
    
    # Create text input area
    ttk.Label(main_frame, text="Input Text:").grid(row=2, column=0, sticky=tk.W)
    input_text = tk.Text(main_frame, height=5, width=50)
    input_text.grid(row=3, column=0, columnspan=2, sticky=tk.W)
    
    # Create buttons frame
    button_frame = ttk.Frame(main_frame)
    button_frame.grid(row=4, column=0, columnspan=2, pady=10)
    
    # Create output area
    ttk.Label(main_frame, text="Output:").grid(row=5, column=0, sticky=tk.W)
    output_text = tk.Text(main_frame, height=5, width=50)
    output_text.grid(row=6, column=0, columnspan=2, sticky=tk.W)
    
    def on_cipher_select(event):
        """Handle cipher selection and create appropriate key input fields"""
        # Clear any existing key inputs
        for widget in key_frame.winfo_children():
            widget.destroy()
            
        # Get selected cipher
        cipher = cipher_var.get()
        
        # Create appropriate key input fields based on selected cipher
        if cipher == 'Caesar':
            # Caesar cipher needs a single shift value
            ttk.Label(key_frame, text="Shift:").pack(side=tk.LEFT)
            ttk.Entry(key_frame, width=5).pack(side=tk.LEFT)
            
        elif cipher == 'Affine':
            # Affine cipher needs two values: a and b
            ttk.Label(key_frame, text="a:").pack(side=tk.LEFT)
            ttk.Entry(key_frame, width=5).pack(side=tk.LEFT)
            ttk.Label(key_frame, text="b:").pack(side=tk.LEFT)
            ttk.Entry(key_frame, width=5).pack(side=tk.LEFT)
            
        elif cipher == 'Vigenère':
            # Vigenère cipher needs a keyword
            ttk.Label(key_frame, text="Key:").pack(side=tk.LEFT)
            ttk.Entry(key_frame, width=20).pack(side=tk.LEFT)
        elif cipher == 'Rail Fence':
            # Rail Fence cipher needs number of rails
            ttk.Label(key_frame, text="Number of Rails:").pack(side=tk.LEFT)
            ttk.Entry(key_frame, width=5).pack(side=tk.LEFT)
    
    def encrypt():
        """Encrypt the input text using the selected cipher"""
        try:
            # Get input text and selected cipher
            text = input_text.get("1.0", tk.END).strip()
            cipher = cipher_var.get()
            
            # Get key values from input fields
            key_widgets = key_frame.winfo_children()
            
            # Perform encryption based on selected cipher
            if cipher == 'Caesar':
                shift = int(key_widgets[1].get())
                result = caesar_encrypt(text, shift)
            elif cipher == 'Affine':
                a = int(key_widgets[1].get())
                b = int(key_widgets[3].get())
                result = affine_encrypt(text, a, b)
            elif cipher == 'Vigenère':
                key = key_widgets[1].get()
                result = vigenere_encrypt(text, key)
            elif cipher == 'Rail Fence':
                rails = int(key_widgets[1].get())
                result = railfence_encrypt(text, rails)
            else:
                messagebox.showerror("Error", "Please select a cipher")
                return
            
            # Display result
            output_text.delete("1.0", tk.END)
            output_text.insert("1.0", result)
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def decrypt():
        """Decrypt the input text using the selected cipher"""
        try:
            # Get input text and selected cipher
            text = input_text.get("1.0", tk.END).strip()
            cipher = cipher_var.get()
            
            # Get key values from input fields
            key_widgets = key_frame.winfo_children()
            
            # Perform decryption based on selected cipher
            if cipher == 'Caesar':
                shift = int(key_widgets[1].get())
                result = caesar_decrypt(text, shift)
            elif cipher == 'Affine':
                a = int(key_widgets[1].get())
                b = int(key_widgets[3].get())
                result = affine_decrypt(text, a, b)
            elif cipher == 'Vigenère':
                key = key_widgets[1].get()
                result = vigenere_decrypt(text, key)
            elif cipher == 'Rail Fence':
                rails = int(key_widgets[1].get())
                result = railfence_decrypt(text, rails)
            else:
                messagebox.showerror("Error", "Please select a cipher")
                return
            
            # Display result
            output_text.delete("1.0", tk.END)
            output_text.insert("1.0", result)
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    # Set up event handlers
    cipher_combo.bind('<<ComboboxSelected>>', on_cipher_select)
    
    # Create encrypt and decrypt buttons
    ttk.Button(button_frame, text="Encrypt", command=encrypt).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="Decrypt", command=decrypt).pack(side=tk.LEFT, padx=5)
    
    return root

# Start the application
if __name__ == "__main__":
    root = create_gui()
    root.mainloop() 