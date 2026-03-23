# encrpytion and decryption

import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

key_file = "secret.key"


# generate key (only once)
def generate_key():
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
    log("Key generated and saved")


# load key
def load_key():
    if not os.path.exists(key_file):
        generate_key()
    return open(key_file, "rb").read()


# encrypt file
def encrypt_file():
    file_path = filedialog.askopenfilename()
    if file_path == "":
        return

    key = load_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        data = file.read()

    encrypted = fernet.encrypt(data)

    new_file = file_path + ".enc"

    with open(new_file, "wb") as file:
        file.write(encrypted)

    log("File encrypted: " + new_file)


# decrypt file
def decrypt_file():
    file_path = filedialog.askopenfilename()
    if file_path == "":
        return

    key = load_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        data = file.read()

    try:
        decrypted = fernet.decrypt(data)
    except:
        log("Wrong key or corrupted file")
        return

    new_file = file_path.replace(".enc", "_dec")

    with open(new_file, "wb") as file:
        file.write(decrypted)

    log("File decrypted: " + new_file)


# log function
def log(msg):
    text_box.insert(tk.END, msg + "\n")
    text_box.yview(tk.END)


# GUI
root = tk.Tk()
root.title("File Security Tool")

tk.Button(root, text="Generate Key", command=generate_key).pack(pady=5)

tk.Button(root, text="Encrypt File", command=encrypt_file).pack(pady=5)

tk.Button(root, text="Decrypt File", command=decrypt_file).pack(pady=5)

text_box = tk.Text(root, height=12, width=50)
text_box.pack()

root.mainloop()