import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ciphers import *

def create_gui():
    root = tk.Tk()
    root.title("Cryptography Tool")
    root.geometry("850x650")
    
    main_frame = ttk.Frame(root, padding="10")
    main_frame.grid(row=0, column=0, sticky="nsew")

    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    main_frame.columnconfigure(1, weight=1)

    # Cipher selection
    ttk.Label(main_frame, text="Select Cipher:").grid(row=0, column=0, sticky="w")
    cipher_var = tk.StringVar()
    cipher_combo = ttk.Combobox(main_frame, textvariable=cipher_var, state="readonly")
    cipher_combo['values'] = ('Caesar', 'Affine', 'Vigenère', 'Rail Fence', 'RSA')
    cipher_combo.grid(row=0, column=1, sticky="w")

    # Key input fields frame
    key_frame = ttk.Frame(main_frame)
    key_frame.grid(row=1, column=0, columnspan=2, sticky="w", pady=5)

    # Text input
    ttk.Label(main_frame, text="Input Text:").grid(row=2, column=0, sticky="w", pady=(10, 0))
    input_text = tk.Text(main_frame, height=6, width=80, wrap="word")
    input_text.grid(row=3, column=0, columnspan=2, sticky="nsew")

    # Encrypt/Decrypt buttons
    button_frame = ttk.Frame(main_frame)
    button_frame.grid(row=4, column=0, columnspan=2, pady=10)

    # Output area
    ttk.Label(main_frame, text="Output:").grid(row=5, column=0, sticky="w")
    output_text = tk.Text(main_frame, height=6, width=80, wrap="word", state="normal")
    output_text.grid(row=6, column=0, columnspan=2, sticky="nsew")

    rsa_keys = {'public': None, 'private': None}
    key_inputs = {}

    def clear_key_inputs():
        key_inputs.clear()
        for widget in key_frame.winfo_children():
            widget.destroy()

    def on_cipher_select(event):
        clear_key_inputs()
        cipher = cipher_var.get()

        def add_field(label, varname, width=10):
            ttk.Label(key_frame, text=label).pack(side=tk.LEFT)
            entry = ttk.Entry(key_frame, width=width)
            entry.pack(side=tk.LEFT, padx=5)
            key_inputs[varname] = entry

        if cipher == 'Caesar':
            add_field("Shift:", "shift")
        elif cipher == 'Affine':
            add_field("a:", "a")
            add_field("b:", "b")
        elif cipher == 'Vigenère':
            add_field("Key:", "key", width=20)
        elif cipher == 'Rail Fence':
            add_field("Number of Rails:", "rails")
        elif cipher == 'RSA':
            btn_frame = ttk.Frame(key_frame)
            btn_frame.pack(fill=tk.X, pady=5)
            ttk.Button(btn_frame, text="Generate Keys", command=handle_rsa_keygen).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Save Public", command=lambda: save_key('public')).pack(side=tk.LEFT)
            ttk.Button(btn_frame, text="Save Private", command=lambda: save_key('private')).pack(side=tk.LEFT)
            ttk.Button(btn_frame, text="Load Public", command=lambda: load_key('public')).pack(side=tk.LEFT)
            ttk.Button(btn_frame, text="Load Private", command=lambda: load_key('private')).pack(side=tk.LEFT)
            key_inputs['status'] = ttk.Label(key_frame, text="No keys loaded")
            key_inputs['status'].pack(pady=5)

    def handle_rsa_keygen():
        try:
            private_key, public_key = generate_rsa_keys()
            rsa_keys['private'] = private_key
            rsa_keys['public'] = public_key
            key_inputs.get('status', ttk.Label(key_frame)).config(text="Keys generated")
        except Exception as e:
            messagebox.showerror("RSA Error", str(e))

    def save_key(kind):
        key_data = rsa_keys.get(kind)
        if not key_data:
            messagebox.showerror("Error", f"No {kind} key to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem")
        if path:
            try:
                with open(path, 'w') as f:
                    f.write(key_data)
                messagebox.showinfo("Saved", f"{kind.capitalize()} key saved.")
            except Exception as e:
                messagebox.showerror("Save Error", str(e))

    def load_key(kind):
        path = filedialog.askopenfilename()
        if path:
            try:
                with open(path, 'r') as f:
                    rsa_keys[kind] = f.read()
                key_inputs.get('status', ttk.Label(key_frame)).config(text=f"{kind.capitalize()} key loaded.")
            except Exception as e:
                messagebox.showerror("Load Error", str(e))

    def encrypt():
        try:
            text = input_text.get("1.0", tk.END).strip()
            cipher = cipher_var.get()
            result = ""

            if not text:
                raise ValueError("Please enter text to encrypt.")

            if cipher == 'Caesar':
                shift = int(key_inputs['shift'].get())
                result = caesar_encrypt(text, shift)
            elif cipher == 'Affine':
                a = int(key_inputs['a'].get())
                b = int(key_inputs['b'].get())
                result = affine_encrypt(text, a, b)
            elif cipher == 'Vigenère':
                key = key_inputs['key'].get()
                result = vigenere_encrypt(text, key)
            elif cipher == 'Rail Fence':
                rails = int(key_inputs['rails'].get())
                result = railfence_encrypt(text, rails)
            elif cipher == 'RSA':
                pub = rsa_keys.get('public')
                if not pub:
                    raise ValueError("Public key not loaded.")
                result = rsa_encrypt(text, pub)
            else:
                raise ValueError("Cipher not selected.")

            output_text.delete("1.0", tk.END)
            output_text.insert(tk.END, result)

        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt():
        try:
            text = input_text.get("1.0", tk.END).strip()
            cipher = cipher_var.get()
            result = ""

            if not text:
                raise ValueError("Please enter text to decrypt.")

            if cipher == 'Caesar':
                shift = int(key_inputs['shift'].get())
                result = caesar_decrypt(text, shift)
            elif cipher == 'Affine':
                a = int(key_inputs['a'].get())
                b = int(key_inputs['b'].get())
                result = affine_decrypt(text, a, b)
            elif cipher == 'Vigenère':
                key = key_inputs['key'].get()
                result = vigenere_decrypt(text, key)
            elif cipher == 'Rail Fence':
                rails = int(key_inputs['rails'].get())
                result = railfence_decrypt(text, rails)
            elif cipher == 'RSA':
                priv = rsa_keys.get('private')
                if not priv:
                    raise ValueError("Private key not loaded.")
                result = rsa_decrypt(text, priv)
            else:
                raise ValueError("Cipher not selected.")

            output_text.delete("1.0", tk.END)
            output_text.insert(tk.END, result)

        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    cipher_combo.bind('<<ComboboxSelected>>', on_cipher_select)
    ttk.Button(button_frame, text="Encrypt", command=encrypt).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="Decrypt", command=decrypt).pack(side=tk.LEFT, padx=5)

    return root

if __name__ == "__main__":
    root = create_gui()
    root.mainloop()
