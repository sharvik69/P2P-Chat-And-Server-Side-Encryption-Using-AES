import socket
import threading
import os
from cryptography.fernet import Fernet

# Server configuration
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)
FILE_STORAGE_DIR = 'server_files' # Directory to store received files

# --- AES Encryption Setup ---
# In a real application, manage this key securely.
# For this example, we'll generate one and use it.
# You might want to save this key to a file and load it.
KEY_FILE = 'secret.key'
encryption_key = None

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'rb') as kf:
        encryption_key = kf.read()
else:
    encryption_key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as kf:
        kf.write(encryption_key)

cipher_suite = Fernet(encryption_key)
print(f"Using encryption key: {encryption_key.decode()}")
# --- End AES Encryption Setup ---


# Create the file storage directory if it doesn't exist
if not os.path.exists(FILE_STORAGE_DIR):
    os.makedirs(FILE_STORAGE_DIR)

# List to keep track of connected clients
clients = []

# Function to handle individual client connections
def handle_client(conn, addr):
    print(f"Connected by {addr}")
    clients.append(conn)

    try:
        while True:
            # Receive data from the client
            data = conn.recv(1024)
            if not data:
                break # Client disconnected

            # Decode the message
            message = data.decode('utf-8')
            print(f"Received from {addr}: {message}")

            # Check if the message is a file transfer command
            if message.startswith("FILE_TRANSFER:"):
                parts = message.split(":", 2)
                if len(parts) == 3:
                    filename = parts[1]
                    filesize = int(parts[2])
                    print(f"Receiving file '{filename}' ({filesize} bytes) from {addr}")

                    # Receive the file data and encrypt it before saving
                    file_path = os.path.join(FILE_STORAGE_DIR, filename + '.encrypted') # Add .encrypted extension
                    encrypted_data = b''
                    bytes_received = 0
                    while bytes_received < filesize:
                        file_data_chunk = conn.recv(4096) # Receive in chunks
                        if not file_data_chunk:
                            break # Error during transfer
                        # Fernet encrypts the whole data, not chunk by chunk for proper token structure.
                        # We need to receive all data first, then encrypt.
                        # This is a simplification for demonstration. For very large files,
                        # a different encryption method or chunking strategy with Fernet would be needed.
                        encrypted_data += file_data_chunk # Accumulate raw data first
                        bytes_received += len(file_data_chunk)

                    if bytes_received == filesize:
                        try:
                            final_encrypted_data = cipher_suite.encrypt(encrypted_data)
                            # Save the encrypted data
                            with open(file_path, 'wb') as f:
                                 f.write(final_encrypted_data)
                            print(f"File '{filename}' received, encrypted, and saved to {file_path}")
                            # Broadcast a message about the received file to all clients
                            broadcast(f"File received from {addr}: {filename} (encrypted)")
                        except Exception as encrypt_error:
                             print(f"Error encrypting file '{filename}': {encrypt_error}")
                             conn.sendall(f"SERVER_ERROR: Failed to encrypt and save file {filename}".encode('utf-8'))

                    else:
                        print(f"Incomplete file data received for '{filename}'. Expected {filesize}, got {bytes_received}.")
                        conn.sendall(f"SERVER_ERROR: Incomplete file transfer for {filename}".encode('utf-8'))


                else:
                    print(f"Invalid FILE_TRANSFER command from {addr}")
                    conn.sendall("SERVER_ERROR: Invalid FILE_TRANSFER command".encode('utf-8'))

            # --- Handle File Download Request ---
            elif message.startswith("DOWNLOAD_FILE:"):
                 if cipher_suite is None:
                     print(f"Download requested but server key not loaded for {addr}")
                     conn.sendall("SERVER_ERROR: Server encryption key not available.".encode('utf-8'))
                     continue

                 parts = message.split(":", 1)
                 if len(parts) == 2:
                     requested_filename = parts[1]
                     encrypted_file_path = os.path.join(FILE_STORAGE_DIR, requested_filename + '.encrypted')

                     if os.path.exists(encrypted_file_path):
                         try:
                             # Read the encrypted data
                             with open(encrypted_file_path, 'rb') as f:
                                 encrypted_data_to_send = f.read()

                             encrypted_filesize = len(encrypted_data_to_send)

                             # Send the download start indicator and file info
                             download_start_command = f"FILE_DOWNLOAD_START:{requested_filename}:{encrypted_filesize}"
                             conn.sendall(download_start_command.encode('utf-8'))

                             # Send the encrypted file data
                             conn.sendall(encrypted_data_to_send)

                             print(f"Sent encrypted file '{requested_filename}.encrypted' ({encrypted_filesize} bytes) to {addr}")

                         except Exception as file_error:
                             print(f"Error reading or sending file {requested_filename}.encrypted: {file_error}")
                             conn.sendall(f"SERVER_ERROR: Failed to read or send file {requested_filename}".encode('utf-8'))

                     else:
                         print(f"Requested file '{requested_filename}.encrypted' not found for {addr}")
                         conn.sendall(f"SERVER_ERROR: File '{requested_filename}' not found.".encode('utf-8'))
                 else:
                     print(f"Invalid DOWNLOAD_FILE command from {addr}")
                     conn.sendall("SERVER_ERROR: Invalid DOWNLOAD_FILE command".encode('utf-8'))
            # --- End Handle File Download Request ---

            else:
                # It's a regular chat message, broadcast it
                broadcast(f"{addr[0]}:{addr[1]} says: {message}")

    except Exception as e:
        print(f"Error with client {addr}: {e}")
    finally:
        # Remove the client from the list and close the connection
        print(f"Client {addr} disconnected")
        clients.remove(conn)
        conn.close()

# Function to broadcast a message to all connected clients
def broadcast(message):
    for client in clients:
        try:
            # Ensure we don't send file data headers as chat messages
            if not message.startswith("FILE_DOWNLOAD_START:"):
                client.sendall(message.encode('utf-8'))
        except:
            # Remove the client if sending fails (likely disconnected)
            try:
                clients.remove(client)
            except ValueError:
                pass # Client already removed


# Main function to start the server
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            # Accept incoming connections
            conn, addr = s.accept()
            # Start a new thread to handle the client
            client_handler = threading.Thread(target=handle_client, args=(conn, addr))
            client_handler.start()

if __name__ == "__main__":
    start_server()
