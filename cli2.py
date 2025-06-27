import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import os
from cryptography.fernet import Fernet

# Client configuration
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

# --- AES Encryption Setup ---
# Client needs the same key as the server to decrypt files.
# In a real application, manage this key securely.
KEY_FILE = 'secret.key'
encryption_key = None
cipher_suite = None

try:
    with open(KEY_FILE, 'rb') as kf:
        encryption_key = kf.read()
    cipher_suite = Fernet(encryption_key)
    print("Encryption key loaded successfully.")
except FileNotFoundError:
    print(f"Error: Encryption key file '{KEY_FILE}' not found. Cannot decrypt files.")
    # You might want to disable download functionality if the key is missing
except Exception as e:
    print(f"Error loading encryption key: {e}")
    # Disable download functionality if key loading fails
# --- End AES Encryption Setup ---


class ChatClient:
    def __init__(self, master):
        self.master = master
        master.title("Simple Chat Client")

        # GUI elements
        self.chat_display = scrolledtext.ScrolledText(master, state='disabled', wrap='word')
        self.chat_display.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

        self.message_entry = tk.Entry(master, width=50)
        self.message_entry.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        self.message_entry.bind("<Return>", self.send_message_event) # Bind Enter key

        self.send_button = tk.Button(master, text="Send Message", command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=5, pady=5)

        self.send_file_button = tk.Button(master, text="Send File", command=self.send_file)
        self.send_file_button.grid(row=1, column=2, padx=5, pady=5)

        self.download_file_button = tk.Button(master, text="Download File", command=self.request_download)
        self.download_file_button.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        # Disable download button if key is not loaded
        if cipher_suite is None:
             self.download_file_button.config(state='disabled')


        # Configure grid weights to make the chat display expand
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)

        # Socket connection
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((HOST, PORT))
            self.add_message("--- Connected to server ---")
            # Start a thread to listen for incoming messages
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True # Allow the main thread to exit even if this thread is running
            self.receive_thread.start()
        except ConnectionRefusedError:
            self.add_message("--- Connection refused. Make sure the server is running. ---")
            self.send_button.config(state='disabled')
            self.send_file_button.config(state='disabled')
            self.download_file_button.config(state='disabled')


    def add_message(self, message):
        """Adds a message to the chat display."""
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + '\n')
        self.chat_display.yview(tk.END) # Auto-scroll to the bottom
        self.chat_display.config(state='disabled')

    def send_message_event(self, event):
        """Handles sending message when Enter key is pressed."""
        self.send_message()

    def send_message(self):
        """Sends the message from the entry field."""
        message = self.message_entry.get()
        if message:
            try:
                self.client_socket.sendall(message.encode('utf-8'))
                self.message_entry.delete(0, tk.END) # Clear the entry field
            except Exception as e:
                self.add_message(f"Error sending message: {e}")
                self.disable_controls()


    def send_file(self):
        """Opens a file dialog and sends the selected file."""
        filepath = filedialog.askopenfilename()
        if filepath:
            try:
                filename = os.path.basename(filepath)
                filesize = os.path.getsize(filepath)

                # Send the file transfer command first
                file_transfer_command = f"FILE_TRANSFER:{filename}:{filesize}"
                self.client_socket.sendall(file_transfer_command.encode('utf-8'))

                # Send the file data
                with open(filepath, 'rb') as f:
                    while True:
                        bytes_read = f.read(4096) # Read in chunks
                        if not bytes_read:
                            break # End of file
                        self.client_socket.sendall(bytes_read)

                self.add_message(f"File '{filename}' sent.")
            except Exception as e:
                self.add_message(f"Error sending file: {e}")
                self.disable_controls()

    def request_download(self):
        """Prompts for a filename and requests it from the server."""
        if cipher_suite is None:
            self.add_message("Cannot download files: Encryption key not loaded.")
            return

        filename_to_download = tk.simpledialog.askstring("Download File", "Enter the filename to download:")
        if filename_to_download:
            try:
                # Send the download request command
                download_command = f"DOWNLOAD_FILE:{filename_to_download}"
                self.client_socket.sendall(download_command.encode('utf-8'))
                self.add_message(f"Requested to download file: {filename_to_download}")
            except Exception as e:
                self.add_message(f"Error requesting download: {e}")
                self.disable_controls()


    def receive_messages(self):
        """Listens for and displays incoming messages or handles file downloads."""
        while True:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    break # Server disconnected

                message = data.decode('utf-8')

                # Check if the message is a file download start indicator
                if message.startswith("FILE_DOWNLOAD_START:"):
                    parts = message.split(":", 2)
                    if len(parts) == 3:
                        original_filename = parts[1]
                        encrypted_filesize = int(parts[2])
                        self.add_message(f"Receiving encrypted file '{original_filename}' ({encrypted_filesize} bytes)...")

                        # Prompt user where to save the decrypted file
                        save_filepath = filedialog.asksaveasfilename(initialfile=original_filename, defaultextension="")
                        if not save_filepath:
                            self.add_message("File download cancelled by user.")
                            # Need a way to tell the server to stop sending (more complex)
                            # For now, the server will likely send the data anyway.
                            # A more robust protocol would handle this.
                            continue # Skip receiving data if user cancels

                        encrypted_data = b''
                        bytes_received = 0
                        # Receive the encrypted file data
                        while bytes_received < encrypted_filesize:
                            chunk = self.client_socket.recv(min(4096, encrypted_filesize - bytes_received))
                            if not chunk:
                                self.add_message("Error receiving file data.")
                                break
                            encrypted_data += chunk
                            bytes_received += len(chunk)

                        if bytes_received == encrypted_filesize:
                            try:
                                # Decrypt the received data
                                decrypted_data = cipher_suite.decrypt(encrypted_data)

                                # Save the decrypted data to the chosen location
                                with open(save_filepath, 'wb') as f:
                                    f.write(decrypted_data)

                                self.add_message(f"File '{original_filename}' downloaded and decrypted successfully to {save_filepath}")
                            except Exception as decrypt_error:
                                self.add_message(f"Error decrypting file '{original_filename}': {decrypt_error}")
                        else:
                             self.add_message(f"Incomplete file data received for '{original_filename}'. Expected {encrypted_filesize}, got {bytes_received}.")

                    else:
                        self.add_message(f"Invalid FILE_DOWNLOAD_START command from server: {message}")

                else:
                    # It's a regular chat message
                    self.add_message(message)

            except Exception as e:
                # Handle potential socket errors or server disconnection
                self.add_message(f"Connection error: {e}")
                self.client_socket.close()
                self.disable_controls()
                break

    def disable_controls(self):
         """Disables sending controls when connection is lost."""
         self.send_button.config(state='disabled')
         self.send_file_button.config(state='disabled')
         self.download_file_button.config(state='disabled')


    def on_closing(self):
        """Handles closing the window."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            try:
                self.client_socket.close()
            except:
                pass # Socket might already be closed
            self.master.destroy()

# Main part to run the Tkinter application
if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing) # Handle window closing event
    root.mainloop()
