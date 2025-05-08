import tkinter as tk
from tkinter import ttk, messagebox
import os
from typing import Dict, Any, List, Optional, Tuple, Callable

# Import ciphers module (assumed to contain cipher implementations)
from ciphers import (
    caesar_encrypt, caesar_decrypt,
    affine_encrypt, affine_decrypt,
    vigenere_encrypt, vigenere_decrypt,
    railfence_encrypt, railfence_decrypt,
    columnar_transposition_encrypt, columnar_transposition_decrypt,
    rotato_encrypt, rotato_decrypt,
    des_encrypt, des_decrypt,
    generate_rsa_keys, rsa_encrypt, rsa_decrypt
)

class CipherHandler:
    """Class to handle all cipher operations and configurations"""
    
    SUPPORTED_CIPHERS = [
        'Caesar', 'Affine', 'Vigenère', 'Rail Fence',
        'Columnar Transposition', 'RSA', 'Rotato', 'DES'
    ]
    
    def __init__(self):
        self.rsa_keys: Dict[str, Optional[int]] = {'e': None, 'd': None, 'n': None}
        self.last_des_binary = None
        self.last_des_key = None
        
    def get_key_config(self, cipher_name: str) -> List[Dict[str, Any]]:
        """Return key configuration for the specified cipher"""
        configs = {
            'Caesar': [{'label': 'Shift:', 'width': 10}],
            'Affine': [{'label': 'a:', 'width': 10}, {'label': 'b:', 'width': 10}],
            'Vigenère': [{'label': 'Key:', 'width': 20}],
            'Rail Fence': [{'label': 'Number of Rails:', 'width': 10}],
            'Columnar Transposition': [{'label': 'Key:', 'width': 20}],
            'Rotato': [{'label': 'Rotation Key:', 'width': 10}],
            'DES': [{'label': 'Key:', 'width': 20, 'note': 'Note: Uses binary output'}],
            'RSA': [{'label': 'Public Exponent (e):', 'width': 10}]
        }
        return configs.get(cipher_name, [])
    
    def perform_cipher_operation(self, cipher_name: str, text: str, key_values: List[str], 
                                mode: str = "encrypt") -> str:
        """Perform encryption or decryption based on the selected cipher"""
        if not text:
            raise ValueError("Input text cannot be empty")
            
        if cipher_name == 'Caesar':
            shift = int(key_values[0])
            return caesar_encrypt(text, shift) if mode == "encrypt" else caesar_decrypt(text, shift)
            
        elif cipher_name == 'Affine':
            a, b = int(key_values[0]), int(key_values[1])
            return affine_encrypt(text, a, b) if mode == "encrypt" else affine_decrypt(text, a, b)
            
        elif cipher_name == 'Vigenère':
            key = key_values[0]
            if not key:
                raise ValueError("Vigenère key cannot be empty")
            return vigenere_encrypt(text, key) if mode == "encrypt" else vigenere_decrypt(text, key)
            
        elif cipher_name == 'Rail Fence':
            rails = int(key_values[0])
            if rails < 2:
                raise ValueError("Number of rails must be at least 2")
            return railfence_encrypt(text, rails) if mode == "encrypt" else railfence_decrypt(text, rails)
            
        elif cipher_name == 'Columnar Transposition':
            key = key_values[0]
            if not key:
                raise ValueError("Transposition key cannot be empty")
            return columnar_transposition_encrypt(text, key) if mode == "encrypt" else columnar_transposition_decrypt(text, key)
            
        elif cipher_name == 'Rotato':
            key = int(key_values[0])
            return rotato_encrypt(text, key) if mode == "encrypt" else rotato_decrypt(text, key)
            
        elif cipher_name == 'DES':
            key = key_values[0]
            if not key:
                raise ValueError("DES key is required")
                
            if mode == "encrypt":
                result = des_encrypt(text.encode(), key).hex()
                self.last_des_binary = des_encrypt(text.encode(), key)
                self.last_des_key = key
                return result
            else:
                try:
                    if hasattr(self, 'last_des_binary') and self.last_des_binary:
                        decrypted = des_decrypt(self.last_des_binary, self.last_des_key)
                    else:
                        decrypted = des_decrypt(bytes.fromhex(text), key)
                    return decrypted.decode('utf-8', errors='replace')
                except Exception as e:
                    raise ValueError(f"DES decryption error: {str(e)}")
                    
        elif cipher_name == 'RSA':
            if mode == "encrypt":
                if self.rsa_keys['e'] is None or self.rsa_keys['n'] is None:
                    raise ValueError("Generate RSA keys first")
                return rsa_encrypt(text, self.rsa_keys['e'], self.rsa_keys['n'])
            else:
                if self.rsa_keys['d'] is None or self.rsa_keys['n'] is None:
                    raise ValueError("Generate RSA keys first")
                return rsa_decrypt(text, self.rsa_keys['d'], self.rsa_keys['n'])
                
        else:
            raise ValueError(f"Unsupported cipher: {cipher_name}")

    def generate_rsa_keys(self, e_value: Optional[str] = None) -> Tuple[int, int, int]:
        """Generate RSA key pair"""
        try:
            e = int(e_value) if e_value else None
            e, d, n = generate_rsa_keys(e)
            self.rsa_keys.update({'e': e, 'd': d, 'n': n})
            return e, d, n
        except ValueError as err:
            raise ValueError(f"Invalid value for e: {err}")
        except Exception as err:
            raise RuntimeError(f"Failed to generate RSA keys: {err}")


class ThemeManager:
    """Class to manage application themes and styling"""
    
    def __init__(self, root: tk.Tk, style: ttk.Style):
        self.root = root
        self.style = style
        self.dark_mode = tk.BooleanVar(value=False)
        
    def toggle_theme(self) -> None:
        """Toggle between light and dark themes"""
        self._apply_theme()
        
    def _apply_theme(self) -> None:
        """Apply the current theme to all widgets"""
        theme = 'clam'  # Base theme
        self.style.theme_use(theme)

        if self.dark_mode.get():
            # Dark theme colors
            bg = "#2e2e2e"
            fg = "#ffffff"
            entry_bg = "#3e3e3e"
            button_bg = "#444444"
            highlight_bg = "#555555"
        else:
            # Light theme colors
            bg = "#f0f0f0"
            fg = "#000000"
            entry_bg = "#ffffff"
            button_bg = "#e0e0e0"
            highlight_bg = "#d0d0d0"

        # Configure root and styles
        self.root.configure(bg=bg)
        
        # Configure ttk styles
        self.style.configure("TLabel", background=bg, foreground=fg)
        self.style.configure("TFrame", background=bg)
        self.style.configure("TButton", background=button_bg)
        self.style.configure("TCheckbutton", background=bg, foreground=fg)
        self.style.configure("TEntry", fieldbackground=entry_bg)
        self.style.configure("TCombobox", fieldbackground=entry_bg)
        
        # Configure Text widget colors through root options
        self.root.option_add("*Text.Background", entry_bg)
        self.root.option_add("*Text.Foreground", fg)


class CryptoApp(tk.Tk):
    """Main application class for the Cryptography Tool"""
    
    def __init__(self):
        super().__init__()
        
        # Setup window properties
        self.title("Cryptography Tool")
        self.geometry("650x600")
        self.minsize(650, 600)
        
        # Initialize managers
        self.cipher_handler = CipherHandler()
        self.style = ttk.Style(self)
        self.theme_manager = ThemeManager(self, self.style)
        
        # Create the UI
        self._create_widgets()
    
    def _create_widgets(self) -> None:
        """Create and layout all UI elements"""
        # Main layout frame with padding
        self.main_frame = ttk.Frame(self, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top control bar
        self._create_control_bar()
        
        # Key input frame (will be populated when cipher is selected)
        self.key_frame = ttk.Frame(self.main_frame)
        self.key_frame.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=5)
        self.key_entries = []
        
        # Input text area
        self._create_input_area()
        
        # Action buttons
        self._create_action_buttons()
        
        # Output text area
        self._create_output_area()
        
        # Status bar
        self._create_status_bar()
        
        # Apply initial theme
        self.theme_manager._apply_theme()
    
    def _create_control_bar(self) -> None:
        """Create the top control bar with cipher selection and theme toggle"""
        # Cipher selection
        ttk.Label(self.main_frame, text="Select Cipher:").grid(row=0, column=0, sticky=tk.W)
        
        self.cipher_var = tk.StringVar()
        self.cipher_combo = ttk.Combobox(
            self.main_frame, 
            textvariable=self.cipher_var,
            values=self.cipher_handler.SUPPORTED_CIPHERS,
            state="readonly",
            width=20
        )
        self.cipher_combo.grid(row=0, column=1, sticky=tk.W)
        self.cipher_combo.bind('<<ComboboxSelected>>', self._on_cipher_select)
        
        # Dark mode toggle
        dark_mode_check = ttk.Checkbutton(
            self.main_frame,
            text="Dark Mode",
            variable=self.theme_manager.dark_mode,
            command=self._on_theme_toggle,
            style="TCheckbutton"
        )
        dark_mode_check.grid(row=0, column=2, sticky=tk.E)
    
    def _create_input_area(self) -> None:
        """Create the input text area"""
        input_frame = ttk.Frame(self.main_frame)
        input_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(input_frame, text="Input Text:").pack(anchor=tk.W)
        
        # Create Text widget with scrollbar
        text_frame = ttk.Frame(input_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.input_text = tk.Text(text_frame, height=5, width=70, wrap=tk.WORD)
        self.input_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        input_scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.input_text.yview)
        input_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.input_text['yscrollcommand'] = input_scrollbar.set
    
    def _create_action_buttons(self) -> None:
        """Create the encryption/decryption action buttons"""
        button_frame = ttk.Frame(self.main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)
        
        ttk.Button(
            button_frame,
            text="Encrypt",
            command=self._encrypt
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Decrypt",
            command=self._decrypt
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Clear All",
            command=self._clear_all
        ).pack(side=tk.LEFT, padx=5)
    
    def _create_output_area(self) -> None:
        """Create the output text area"""
        output_frame = ttk.Frame(self.main_frame)
        output_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(output_frame, text="Output:").pack(anchor=tk.W)
        
        # Create Text widget with scrollbar
        text_frame = ttk.Frame(output_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.output_text = tk.Text(text_frame, height=5, width=70, wrap=tk.WORD)
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        output_scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        output_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text['yscrollcommand'] = output_scrollbar.set
    
    def _create_status_bar(self) -> None:
        """Create a status bar at the bottom of the window"""
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _on_cipher_select(self, event) -> None:
        """Handle cipher selection event"""
        self._refresh_key_frame()
        selected_cipher = self.cipher_var.get()
        self.status_var.set(f"Selected cipher: {selected_cipher}")
    
    def _on_theme_toggle(self) -> None:
        """Handle theme toggle event"""
        self.theme_manager.toggle_theme()
        self._refresh_key_frame()  # Refresh key frame to apply new styles
    
    def _refresh_key_frame(self) -> None:
        """Refresh the key input frame based on selected cipher"""
        # Clear existing widgets
        for widget in self.key_frame.winfo_children():
            widget.destroy()
        
        self.key_entries = []
        selected_cipher = self.cipher_var.get()
        
        if not selected_cipher:
            return
            
        # Add key input fields based on selected cipher
        key_configs = self.cipher_handler.get_key_config(selected_cipher)
        
        for config in key_configs:
            ttk.Label(self.key_frame, text=config['label']).pack(side=tk.LEFT)
            entry = ttk.Entry(self.key_frame, width=config.get('width', 10))
            entry.pack(side=tk.LEFT, padx=2)
            self.key_entries.append(entry)
            
            if 'note' in config:
                ttk.Label(self.key_frame, text=config['note']).pack(side=tk.LEFT, padx=5)
        
        # Add RSA key generation button if RSA cipher is selected
        if selected_cipher == 'RSA':
            ttk.Button(
                self.key_frame,
                text="Generate RSA Keys",
                command=self._generate_rsa_keys
            ).pack(side=tk.LEFT, padx=5)
            
            # Display current RSA keys if available
            if self.cipher_handler.rsa_keys['e'] is not None:
                key_info = f"(e,n): ({self.cipher_handler.rsa_keys['e']}, {self.cipher_handler.rsa_keys['n']})"
                ttk.Label(self.key_frame, text=key_info).pack(side=tk.LEFT, padx=5)
    
    def _generate_rsa_keys(self) -> None:
        """Generate RSA keys"""
        try:
            e_entry = self.key_entries[0].get() if self.key_entries else None
            e, d, n = self.cipher_handler.generate_rsa_keys(e_entry)
            self._refresh_key_frame()
            self.status_var.set(f"RSA keys generated: e={e}, d={d}, n={n}")
            messagebox.showinfo("RSA", "Keys generated successfully.")
        except Exception as err:
            self.status_var.set(f"RSA key generation failed: {err}")
            messagebox.showerror("RSA Error", str(err))
    
    def _encrypt(self) -> None:
        """Encrypt the input text"""
        self._process_cipher_operation("encrypt")
    
    def _decrypt(self) -> None:
        """Decrypt the input text"""
        self._process_cipher_operation("decrypt")
    
    def _process_cipher_operation(self, mode: str) -> None:
        """Process encryption or decryption operation"""
        try:
            selected_cipher = self.cipher_var.get()
            
            if not selected_cipher:
                raise ValueError("Please select a cipher")
                
            text = self.input_text.get("1.0", tk.END).strip()
            
            if not text:
                raise ValueError("Input text cannot be empty")
                
            # Get key values from entries
            key_values = [entry.get() for entry in self.key_entries]
            
            # Perform cipher operation
            result = self.cipher_handler.perform_cipher_operation(
                selected_cipher, text, key_values, mode
            )
            
            # Update output text
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            
            operation = "Encryption" if mode == "encrypt" else "Decryption"
            self.status_var.set(f"{operation} completed successfully")
            
        except Exception as err:
            operation = "Encryption" if mode == "encrypt" else "Decryption"
            error_message = f"{operation} Error: {str(err)}"
            self.status_var.set(error_message)
            messagebox.showerror(f"{operation} Error", str(err))
    
    def _clear_all(self) -> None:
        """Clear all input/output fields"""
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        for entry in self.key_entries:
            entry.delete(0, tk.END)
        self.status_var.set("All fields cleared")


if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()