import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import tkinter
# import customtkinter
# from customtkinter import CTkImage


host = '127.0.0.1'
port = 12345


# Generate a key and IV (Initialization Vector)
key = b'\x04\x03|\xeb\x8dSh\xe0\xc5\xae\xe5\xe1l9\x0co\xca\xb1"\r-Oo\xbaiYa\x1e\xd1\xf7\xa2\xdf'
iv = b'#\xb59\xee\xa7\xc4@n\xe5r\xac\x97lV\xff\xf1'


# Function to encrypt plaintext using AES-CBC
def encrypt(plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


# Function to decrypt ciphertext using AES-CBC
def decrypt(ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode('utf-8')


def receive(client_socket):
    while True:
        try:
            message = client_socket.recv(1024)
            message = decrypt(message)
            if message.startswith("FILE: "):
                file_name = message.split(': ')[1]
                file_data = b''
                while True:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    file_data += chunk

                    with open(file_name, 'wb') as file:
                        file.write(file_data)

                    print(f"File received: {file_name}")
            else:
                print(message)
        except Exception as e:
            print("Error receiving message:", e)
            break


def send(client_socket):
    while True:
        try:
            message = input()
            client_socket.send(encrypt(message))
        except Exception as e:
            print("Error sending message:", e)
            break


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
        print("Connected to server.")

        threading.Thread(target=receive, args=(client_socket,)).start()
        threading.Thread(target=send, args=(client_socket,)).start()
    except Exception as e:
        print("Connection error:", e)


if __name__ == '__main__':
    main()