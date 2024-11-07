import tkinter as tk
from tkinter import messagebox
import socket

# Registered IP addresses, names, and passwords for doctors and nurses
registered_doctor_info = {'Alice': {'ip': '192.168.56.1', 'passwd': 'alice@1234'}, 'Bob': {'ip': '192.168.56.1', 'passwd': 'bob@5678'}}
registered_nurse_info = {'Charlie': {'ip': '192.168.56.1', 'passwd': 'charlie@9876'}, 'Jerry': {'ip': '192.168.56.1', 'passwd': 'jerry@5432'}}

def get_ip_address():
    try:
        # Get the local IP address
        #print(socket.gethostbyname(socket.gethostname()))
        return socket.gethostbyname(socket.gethostname())
    except:
        return None

def authenticate_party(role, name, ip, passwd):
    auth = "0"
    if role == 'doctor' or role == 'Doctor':
        registered_info = registered_doctor_info
    elif role == 'nurse' or role == 'Nurse':
        registered_info = registered_nurse_info
    else:
        messagebox.showerror("Error", "Invalid role specified.")
        return

    if name in registered_info and registered_info[name]['ip'] == ip and registered_info[name]['passwd'] == passwd:
        messagebox.showinfo("Authentication", f"Authentication successful for {role} {name}.")
        auth = "1"
    else:
        messagebox.showerror("Authentication", f"Authentication failed for {role} {name}. Unauthorized IP address or incorrect password.")
        auth = "0"

    return auth

def on_submit():
    role = role_entry.get()
    name = name_entry.get()
    ip = get_ip_address()  # Get the IP address automatically
    passwd = passwd_entry.get()  # Get the password
    auth = authenticate_party(role, name, ip, passwd)

# Create tkinter window
root = tk.Tk()
root.title("Authentication")

# Labels and entries for role, name, and password
tk.Label(root, text="Role (doctor/nurse):").grid(row=0, column=0, padx=5, pady=5)
role_entry = tk.Entry(root)
role_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(root, text="Name:").grid(row=1, column=0, padx=5, pady=5)
name_entry = tk.Entry(root)
name_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(root, text="Password:").grid(row=2, column=0, padx=5, pady=5)
passwd_entry = tk.Entry(root, show="*")  # Show asterisks for password input
passwd_entry.grid(row=2, column=1, padx=5, pady=5)

# Submit button
submit_button = tk.Button(root, text="Submit", command=on_submit)
submit_button.grid(row=3, column=0, columnspan=2, pady=10)

root.mainloop()
