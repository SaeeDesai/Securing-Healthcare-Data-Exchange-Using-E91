import tkinter as tk
from tkinter import filedialog
from functools import partial
import hashlib
import hmac
import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
from datetime import datetime

# List to store blocked IP addresses
blocked_ips = []

with open("final_key_alice.txt", "rb") as key_file:
    aes_key = key_file.read(16)

def delete_key_file():
    try:
        os.remove("final_key_alice.txt")
        print("AES key file deleted.")
    except FileNotFoundError:
        pass  # Ignore if the file doesn't exist


def generate_mac_id_from_key(message, key):
    mac_id = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    return mac_id


def decrypt_message(encrypted_message, key):
    start_time = time.time()
    iv = encrypted_message[:16]  # Extract IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    decrypted_data = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    decryption_time = time.time() - start_time
    print(f"Decryption time for message: {decryption_time:.2f} s")

    return unpadded_data.decode('utf-8', errors='replace').strip()


def decrypt_file(file_content, key):
    try:
        iv = file_content[:16]  # Extract IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        decrypted_data = decryptor.update(file_content[16:]) + decryptor.finalize()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data.decode('utf-8', errors='replace')
    except Exception as e:
        print(f"Error decrypting file content: {e}")
        return None



def create_gui():
    root = tk.Tk()
    root.title("Nurse's Secure Message Viewer")

    message_log_frame = tk.Frame(root)
    message_log_frame.pack(expand=True, fill=tk.BOTH)

    message_log_scrollbar = tk.Scrollbar(message_log_frame)
    message_log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    message_listbox = tk.Listbox(message_log_frame, yscrollcommand=message_log_scrollbar.set, width=50, font=("Segoe UI Emoji", 12))
    message_listbox.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
    message_log_scrollbar.config(command=message_listbox.yview)

    def start_server():
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('127.0.0.3', 12347)
        server_socket.bind(server_address)
        server_socket.listen(2)

        try:
            while True:
                print("\n\nWaiting for a connection...")
                client_socket, client_address = server_socket.accept()
                print("Connected to", client_address)

                if client_address[0] in blocked_ips:
                    print(f"IP Address {client_address[0]} is blocked!")
                    client_socket.close()
                    continue  # Skip further processing for blocked IP addresses

                received_message = b""
                while True:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    received_message += data

                if client_address[0] == '192.168.237.34':
                    blocked_ips.append(client_address[0])

                if received_message.startswith(b"MSG:"):
                    decrypted_message = decrypt_message(received_message[len(b"MSG:"):], aes_key)
                    if not decrypted_message:
                        print("Error decrypting message")
                        continue

                    message_lines = decrypted_message.split('\n')
                    if len(message_lines) > 1:
                        mac_id = message_lines[0].replace("MAC id: ", "")
                        timestamp_str = message_lines[1].replace("Timestamp: ", "")
                        message = message_lines[2].replace("Message: ", "")
                        calculated_mac_id = generate_mac_id_from_key(message, aes_key)
                        if calculated_mac_id == mac_id:
                            print("Validated MAC id... Message is authentic")
                        else:
                            print("Invalid MAC id..")
                        received_timestamp = datetime.strptime(timestamp_str, "%a %b %d %H:%M:%S %Y")
                        current_time = datetime.now()
                        time_window = 30
                        time_difference = current_time - received_timestamp
                        if time_difference.total_seconds() <= time_window and calculated_mac_id == mac_id:
                            print("Received message is within the time window.")
                            print("MAC id: ", mac_id)
                            print("Timestamp:", received_timestamp)
                            #print("Message:", message)
                            message_logbox_entry = f"[{timestamp_str}]"
                            message_listbox.insert(tk.END, message_logbox_entry)
                            message_listbox.see(tk.END)
                        else:
                            print("Received message is outside the time window. Ignoring.")

                        # Displaying all the necessary details in the GUI
                        # message_logbox_entry = f"MAC id: {mac_id}"
                        msg_str = f"Message: {message}"
                        message_listbox.insert(tk.END, msg_str)
                        message_listbox.see(tk.END)
                    else:
                        print("Cannot see mac id verification details")

                elif received_message.startswith(b"FILE:"):
                    file_content = received_message[len(b"FILE:"):]
                    decrypted_text = decrypt_file(file_content, aes_key)
                    if decrypted_text:
                        # Display the content of the file in the GUI
                        message_listbox.insert(tk.END, "******************************************************************************")
                        message_listbox.insert(tk.END, "\t\tFile content: ")
                        message_listbox.insert(tk.END, "")
                        # Split the decrypted text into lines for better formatting
                        lines = decrypted_text.split('\n')
                        for line in lines:
                            message_listbox.insert(tk.END, line)
                        message_listbox.insert(tk.END, "******************************************************************************")
                        message_listbox.see(tk.END)
                        print("File content displayed in GUI.")
                    else:
                        print("Error decrypting file content.")



                client_socket.close()
        finally:
            server_socket.close()

    import threading
    threading.Thread(target=start_server).start()

    root.mainloop()


if __name__ == "__main__":
    create_gui()
    delete_key_file()
