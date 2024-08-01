import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import base64
from cryptography.fernet import Fernet
import hashlib
import os
from Crypto.Cipher import AES, DES, Blowfish
from PIL import Image, ImageTk

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
root.geometry("555x370")
root.configure(bg="#F5F5F5")
root.resizable(False, False)  # Pencereyi yeniden boyutlandırmayı kapatır

# Başlık
title_label = tk.Label(root, text="FileShield", font=("Orbitron", 24, "bold"), fg="black", bg="#F5F5F5")
title_label.pack(pady=(10, 5))

# Logo Container
logo_frame = tk.Frame(root, bg="#F5F5F5")
logo_frame.pack(pady=(0, 10))
# Logo ekle
logo_image = Image.open("/Users/metevesek/Desktop/FileShield/icons/appIcon.png")
logo_image = logo_image.resize((60, 60), Image.Resampling.LANCZOS)  # Logo boyutu küçültüldü
logo_photo = ImageTk.PhotoImage(logo_image)
logo_label = tk.Label(logo_frame, image=logo_photo, bg="#F5F5F5")
logo_label.pack()

# Form Container
form_frame = tk.Frame(root, bg="#F5F5F5")
form_frame.pack(pady=10, fill="x", padx=20)

# Dosya Seçim Butonu
lbl_file = tk.Label(form_frame, text="Select File:", font=("Orbitron", 12, "bold"), bg="#F5F5F5")
lbl_file.grid(row=0, column=0, padx=10, pady=5, sticky="w")
entry_file_path = tk.Entry(form_frame, width=30, font=("Orbitron", 12))
entry_file_path.grid(row=0, column=1, padx=10, pady=5, sticky="w")
btn_select_file = tk.Button(form_frame, text="Browse", command=select_file, font=("Orbitron", 12, "bold"), bg="#007AFF", fg="black", width=80, compound=tk.RIGHT)
btn_select_file.grid(row=0, column=2, padx=10, pady=5)

# Parola ve Onay Parolası
lbl_password = tk.Label(form_frame, text="Password:", font=("Orbitron", 12, "bold"), bg="#F5F5F5")
lbl_password.grid(row=1, column=0, padx=10, pady=5, sticky="w")
entry_password = tk.Entry(form_frame, show="*", width=30, font=("Orbitron", 12))
entry_password.grid(row=1, column=1, padx=10, pady=5, sticky="w")

lbl_confirm_password = tk.Label(form_frame, text="Confirm Password:", font=("Orbitron", 12, "bold"), bg="#F5F5F5")
lbl_confirm_password.grid(row=2, column=0, padx=10, pady=5, sticky="w")
entry_confirm_password = tk.Entry(form_frame, show="*", width=30, font=("Orbitron", 12))
entry_confirm_password.grid(row=2, column=1, padx=10, pady=5, sticky="w")

# Algoritma Seçimi
lbl_algo = tk.Label(form_frame, text="Algorithm:", font=("Orbitron", 12, "bold"), bg="#F5F5F5")
lbl_algo.grid(row=3, column=0, padx=10, pady=5, sticky="w")
algo_var = tk.StringVar(value='Fernet')
algo_combo = ttk.Combobox(form_frame, textvariable=algo_var, values=['Fernet', 'AES', 'DES', 'Blowfish'], font=("Orbitron", 12))
algo_combo.grid(row=3, column=1, padx=10, pady=5, sticky="w")

# Encrypt ve Decrypt Butonları
frame_buttons = tk.Frame(root, bg="#F5F5F5")
frame_buttons.pack(pady=20, fill="x", padx=20)
btn_encrypt = tk.Button(frame_buttons, text="Encrypt", command=protect_file, font=("Orbitron", 12, "bold"), bg="#34C759", fg="black", width=80, compound=tk.RIGHT)
btn_encrypt.pack(side="left", padx=5, pady=(0, 5))
btn_decrypt = tk.Button(frame_buttons, text="Decrypt", command=decrypt_file_action, font=("Orbitron", 12, "bold"), bg="#FF3B30", fg="black", width=80, compound=tk.RIGHT)
btn_decrypt.pack(side="left", padx=5, pady=(0, 5))

# Encrypt, Decrypt ve Browse butonlarına resim ekleme
encrypt_image = Image.open("/Users/metevesek/Desktop/FileShield/icons/encryptIcon.png")
encrypt_image = encrypt_image.resize((20, 20), Image.Resampling.LANCZOS)
encrypt_photo = ImageTk.PhotoImage(encrypt_image)
btn_encrypt.config(image=encrypt_photo, compound="right")

decrypt_image = Image.open("/Users/metevesek/Desktop/FileShield/icons/decryptIcon.png")
decrypt_image = decrypt_image.resize((20, 20), Image.Resampling.LANCZOS)
decrypt_photo = ImageTk.PhotoImage(decrypt_image)
btn_decrypt.config(image=decrypt_photo, compound="right")

browse_image = Image.open("/Users/metevesek/Desktop/FileShield/icons/browseIcon.png")
browse_image = browse_image.resize((20, 20), Image.Resampling.LANCZOS)
browse_photo = ImageTk.PhotoImage(browse_image)
btn_select_file.config(image=browse_photo, compound="right")

root.mainloop()
