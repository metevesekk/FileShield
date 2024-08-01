import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import base64
from cryptography.fernet import Fernet
import hashlib
import os
from Crypto.Cipher import AES, DES, Blowfish

# Şifreleme Fonksiyonları
def create_key_from_password(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_file(filepath, password, algorithm):
    with open(filepath, 'rb') as file:
        data = file.read()
    data = base64.b64encode(data)

    key = create_key_from_password(password)
    
    if algorithm == 'Fernet':
        cipher = Fernet(base64.urlsafe_b64encode(key))
        encrypted_data = cipher.encrypt(data)
    elif algorithm == 'AES':
        cipher = AES.new(key[:16], AES.MODE_EAX)
        encrypted_data, tag = cipher.encrypt_and_digest(data)
        encrypted_data = cipher.nonce + tag + encrypted_data
    elif algorithm == 'DES':
        cipher = DES.new(key[:8], DES.MODE_EAX)
        encrypted_data, tag = cipher.encrypt_and_digest(data)
        encrypted_data = cipher.nonce + tag + encrypted_data
    elif algorithm == 'Blowfish':
        cipher = Blowfish.new(key[:16], Blowfish.MODE_EAX)
        encrypted_data, tag = cipher.encrypt_and_digest(data)
        encrypted_data = cipher.nonce + tag + encrypted_data
    else:
        messagebox.showerror("Error", "Unsupported algorithm selected.")
        return
    
    encrypted_filepath = filepath + '.encrypted'
    with open(encrypted_filepath, 'wb') as file:
        file.write(encrypted_data)
    
    os.remove(filepath)
    messagebox.showinfo("Success", f"File encrypted and saved to {encrypted_filepath}")

def decrypt_file(filepath, password, algorithm):
    with open(filepath, 'rb') as file:
        encrypted_data = file.read()

    key = create_key_from_password(password)

    try:
        if algorithm == 'Fernet':
            cipher = Fernet(base64.urlsafe_b64encode(key))
            decrypted_data = cipher.decrypt(encrypted_data)
        elif algorithm == 'AES':
            nonce, tag, encrypted_data = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
            cipher = AES.new(key[:16], AES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
        elif algorithm == 'DES':
            nonce, tag, encrypted_data = encrypted_data[:8], encrypted_data[8:16], encrypted_data[16:]
            cipher = DES.new(key[:8], DES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
        elif algorithm == 'Blowfish':
            nonce, tag, encrypted_data = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
            cipher = Blowfish.new(key[:16], Blowfish.MODE_EAX, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
        else:
            messagebox.showerror("Error", "Unsupported algorithm selected.")
            return
        
        decrypted_data = base64.b64decode(decrypted_data)
    except:
        messagebox.showerror("Error", "Failed to decrypt. Check your password and algorithm.")
        return
    
    decrypted_filepath = filepath.replace('.encrypted', '')
    with open(decrypted_filepath, 'wb') as file:
        file.write(decrypted_data)
    
    os.remove(filepath)
    messagebox.showinfo("Success", f"File decrypted and saved to {decrypted_filepath}")

def select_file():
    filepath = filedialog.askopenfilename()
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, filepath)

def protect_file():
    filepath = entry_file_path.get()
    password = entry_password.get()
    confirm_password = entry_confirm_password.get()
    algorithm = algo_var.get()
    if password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match!")
        return
    if filepath and password:
        encrypt_file(filepath, password, algorithm)
    else:
        messagebox.showerror("Error", "Please select a file and enter a password.")

def decrypt_file_action():
    filepath = entry_file_path.get()
    password = entry_password.get()
    algorithm = algo_var.get()
    if filepath and password:
        decrypt_file(filepath, password, algorithm)
    else:
        messagebox.showerror("Error", "Please select a file and enter a password.")

# GUI Tasarımı
root = tk.Tk()
root.title("FileShield")
root.geometry("400x350")
root.configure(bg="#F5F5F5")

# Başlık
title_label = tk.Label(root, text="FileShield", font=("Helvetica Neue", 24, "bold"), fg="black", bg="#F5F5F5")
title_label.pack(pady=20)

# Dosya Seçim Butonu
frame_file_select = tk.Frame(root, bg="#F5F5F5")
frame_file_select.pack(pady=10, fill="x", padx=20)
btn_select_file = tk.Button(frame_file_select, text="Select File", command=select_file, font=("Helvetica Neue", 12), bg="#007AFF", fg="white")
btn_select_file.pack(side="left", padx=10)
entry_file_path = tk.Entry(frame_file_select, width=30, font=("Helvetica Neue", 12))
entry_file_path.pack(side="left", padx=10)

# Parola ve Onay Parolası
frame_password = tk.Frame(root, bg="#F5F5F5")
frame_password.pack(pady=10, fill="x", padx=20)
lbl_password = tk.Label(frame_password, text="Password:", font=("Helvetica Neue", 12), bg="#F5F5F5")
lbl_password.grid(row=0, column=0, padx=10, pady=5)
entry_password = tk.Entry(frame_password, show="*", width=30, font=("Helvetica Neue", 12))
entry_password.grid(row=0, column=1, padx=10, pady=5)

lbl_confirm_password = tk.Label(frame_password, text="Confirm Password:", font=("Helvetica Neue", 12), bg="#F5F5F5")
lbl_confirm_password.grid(row=1, column=0, padx=10, pady=5)
entry_confirm_password = tk.Entry(frame_password, show="*", width=30, font=("Helvetica Neue", 12))
entry_confirm_password.grid(row=1, column=1, padx=10, pady=5)

# Algoritma Seçimi
frame_algo = tk.Frame(root, bg="#F5F5F5")
frame_algo.pack(pady=10, fill="x", padx=20)
lbl_algo = tk.Label(frame_algo, text="Algorithm:", font=("Helvetica Neue", 12), bg="#F5F5F5")
lbl_algo.pack(side="left", padx=10)
algo_var = tk.StringVar(value='Fernet')
algo_combo = ttk.Combobox(frame_algo, textvariable=algo_var, values=['Fernet', 'AES', 'DES', 'Blowfish'], font=("Helvetica Neue", 12))
algo_combo.pack(side="left", padx=10)

# Encrypt ve Decrypt Butonları
frame_buttons = tk.Frame(root, bg="#F5F5F5")
frame_buttons.pack(pady=20, fill="x", padx=20)
btn_encrypt = tk.Button(frame_buttons, text="Encrypt", command=protect_file, font=("Helvetica Neue", 12, "bold"), bg="#34C759", fg="white", width=10)
btn_encrypt.pack(side="left", padx=10)
btn_decrypt = tk.Button(frame_buttons, text="Decrypt", command=decrypt_file_action, font=("Helvetica Neue", 12, "bold"), bg="#FF3B30", fg="white", width=10)
btn_decrypt.pack(side="right", padx=10)

root.mainloop()
