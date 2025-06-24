from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import json
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography import x509
import os

default_base_path = "/Users/quinnesser/Documents/"


def Asymetric_Encryption(input_path, output_path, cert_path):

    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        public_key = cert.public_key()

    symmetric_key = Fernet.generate_key()
    fernet = Fernet(symmetric_key)


    with open(input_path, "rb") as file:
        data = file.read()
        encrypted_data = fernet.encrypt(data)


    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


    wrapper = {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "encrypted_data": base64.b64encode(encrypted_data).decode("utf-8")
    }

    with open(output_path, "w") as f:
        json.dump(wrapper, f)


def Asymetric_Decryption(input_path, output_path, key_path):
    with open(key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )


    with open(input_path, "r") as f:
        wrapper = json.load(f)

    encrypted_key = base64.b64decode(wrapper["encrypted_key"])
    encrypted_data = base64.b64decode(wrapper["encrypted_data"])


    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


    fernet = Fernet(symmetric_key)
    decrypted = fernet.decrypt(encrypted_data)

    with open(output_path, "wb") as f:
        f.write(decrypted)


def select_file():
    file_path = filedialog.askopenfilename(title = "Select file to encrypt/decrypt")
    if file_path:
        file_entry.delete(0,tk.END)
        file_entry.insert(0,file_path)


def select_cert():
    cert_path = filedialog.askopenfilename(title="Select certificate for encryption")
    if cert_path:
        cert_entry.delete(0,tk.END)
        cert_entry.insert(0,cert_path)


def select_key():
    key_path=filedialog.askopenfilename(title="Select a key for decryption")
    if key_path:
        key_entry.delete(0,tk.END)
        key_entry.insert(0,key_path)


def select_output():
    out_path = filedialog.asksaveasfilename(title="Select output file")
    if out_path:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, out_path)

def run_action():
    input_text = file_entry.get().strip()
    output_text = output_entry.get().strip()
    operation = operation_var.get()


    input_path = input_text if os.path.sep in input_text else os.path.join(default_base_path, input_text)
    output_path = output_text if os.path.sep in output_text else os.path.join(default_base_path, output_text) if output_text else input_path

    try:
        if not os.path.isfile(input_path):
            messagebox.showerror("Error", "Selected input file does not exist.")
            return

        if operation == "Encrypt":
            cert_path = cert_entry.get()
            if not os.path.isfile(cert_path):
                messagebox.showerror("Error", "Certificate file not found.")
                return
            Asymetric_Encryption(input_path, output_path, cert_path)
            messagebox.showinfo("Success", "File encrypted successfully!")
        elif operation == "Decrypt":
            key_path = key_entry.get()
            if not os.path.isfile(key_path):
                messagebox.showerror("Error", "Private key file not found.")
                return
            Asymetric_Decryption(input_path, output_path, key_path)
            messagebox.showinfo("Success", "File decrypted successfully!")

    except Exception as e:
        messagebox.showerror("Error", str(e))



root = tk.Tk()
root.title("File Selector GUI")

tk.Label(root, text="Input File:").grid(row=0, column=0, sticky="e")
file_entry = tk.Entry(root, width=50)
file_entry.grid(row=0, column=1)
tk.Button(root, text="Browse", command=select_file).grid(row=0, column=2)

tk.Label(root, text="Output File:").grid(row=1, column=0, sticky="e")
output_entry = tk.Entry(root, width=50)
output_entry.grid(row=1, column=1)
tk.Button(root, text="Browse", command=select_output).grid(row=1, column=2)

operation_var = tk.StringVar(value="Encrypt")
tk.Label(root, text="Operation:").grid(row=2, column=0, sticky="e")
tk.OptionMenu(root, operation_var, "Encrypt", "Decrypt").grid(row=2, column=1, sticky="w")

tk.Label(root, text="Cert (for Encryption):").grid(row=3, column=0, sticky="e")
cert_entry = tk.Entry(root, width=50)
cert_entry.grid(row=3, column=1)
tk.Button(root, text="Browse", command=select_cert).grid(row=3, column=2)

tk.Label(root, text="Key (for Decryption):").grid(row=4, column=0, sticky="e")
key_entry = tk.Entry(root, width=50)
key_entry.grid(row=4, column=1)
tk.Button(root, text="Browse", command=select_key).grid(row=4, column=2)

tk.Button(root, text="Run", command=run_action, width=20).grid(row=5, column=1, pady=10)

root.mainloop()
