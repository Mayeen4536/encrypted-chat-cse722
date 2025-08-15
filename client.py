
import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import sys

# === RSA Key Generation ===
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# === Serialize Keys ===
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

# === AES Setup ===
def generate_aes_key():
    return os.urandom(32)  # 256-bit key

def encrypt_message_aes(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message_aes(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.decode('utf-8', errors='replace')

# === Globals ===
peer_public_key = None
aes_shared_key = None
my_private_key, my_public_key = generate_rsa_keys()

def handle_recv(conn):
    global aes_shared_key, peer_public_key

    while True:
        try:
            data = conn.recv(65536)
            if not data:
                print("[!] Connection closed by peer.")
                break

            if data.startswith(b"KEYEXCHANGE:"):
                peer_public_key = deserialize_public_key(data[len(b"KEYEXCHANGE:"):])
                print("[✓] Public key received.")

            elif data.startswith(b"AESKEY:"):
                encrypted_aes_key = data[len(b"AESKEY:"):]
                aes_shared_key = my_private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                print("[✓] AES key received and decrypted. Secure chat established.")

            else:
                if aes_shared_key:
                    try:
                        message = decrypt_message_aes(aes_shared_key, data)
                        print(f"[Peer] {message}")
                    except Exception as e:
                        print(f"[!] Failed to decrypt message: {e}")
                else:
                    print("[!] Received data before AES key exchange.")
        except Exception as e:
            print(f"[!] Receive thread error: {e}")
            break

def start_client(server_ip, port=9999):
    global aes_shared_key
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((server_ip, port))
    except Exception as e:
        print(f"[!] Could not connect to {server_ip}:{port} — {e}")
        sys.exit(1)

    threading.Thread(target=handle_recv, args=(s,), daemon=True).start()

    print("[*] Connected. Type 'sendkey' to exchange RSA keys, 'sendaes' to send AES key, 'quit' to exit.")
    while True:
        try:
            msg = input().strip()
        except EOFError:
            break

        if msg.lower() == "quit":
            try:
                s.shutdown(socket.SHUT_RDWR)
            except:
                pass
            s.close()
            print("[*] Disconnected.")
            break

        if msg == "sendkey":
            s.sendall(b"KEYEXCHANGE:" + serialize_public_key(my_public_key))
            print("[→] Public key sent.")

        elif msg == "sendaes":
            if peer_public_key:
                aes_shared_key = generate_aes_key()
                encrypted_key = peer_public_key.encrypt(
                    aes_shared_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                s.sendall(b"AESKEY:" + encrypted_key)
                print("[→] AES key encrypted and sent.")
            else:
                print("[!] Exchange public keys first with 'sendkey'.")

        else:
            if aes_shared_key:
                try:
                    encrypted = encrypt_message_aes(aes_shared_key, msg)
                    s.sendall(encrypted)
                except Exception as e:
                    print(f"[!] Encryption/send error: {e}")
            else:
                print("[!] AES key not shared. Use 'sendaes' after key exchange.")

def start_server(port=9999):
    global aes_shared_key
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('', port))
    except OSError as e:
        print(f"[!] Could not bind to port {port}: {e}")
        sys.exit(1)

    s.listen(1)
    print(f"[*] Listening on port {port}... (Type 'sendkey'/'sendaes' after a client connects)")
    try:
        conn, addr = s.accept()
    except KeyboardInterrupt:
        print("\n[!] Server interrupted before accepting a connection.")
        s.close()
        sys.exit(1)

    print(f"[✓] Connection established from {addr}")
    threading.Thread(target=handle_recv, args=(conn,), daemon=True).start()

    while True:
        try:
            msg = input().strip()
        except EOFError:
            break

        if msg.lower() == "quit":
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except:
                pass
            conn.close()
            s.close()
            print("[*] Disconnected.")
            break

        if msg == "sendkey":
            conn.sendall(b"KEYEXCHANGE:" + serialize_public_key(my_public_key))
            print("[→] Public key sent.")

        elif msg == "sendaes":
            if peer_public_key:
                aes_shared_key = generate_aes_key()
                encrypted_key = peer_public_key.encrypt(
                    aes_shared_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                conn.sendall(b"AESKEY:" + encrypted_key)
                print("[→] AES key encrypted and sent.")
            else:
                print("[!] Exchange public keys first with 'sendkey'.")

        else:
            if aes_shared_key:
                try:
                    encrypted = encrypt_message_aes(aes_shared_key, msg)
                    conn.sendall(encrypted)
                except Exception as e:
                    print(f"[!] Encryption/send error: {e}")
            else:
                print("[!] AES key not shared. Use 'sendaes' after key exchange.")

def ask_int(prompt, default):
    try:
        raw = input(prompt).strip()
        if not raw:
            return default
        return int(raw)
    except Exception:
        return default

if __name__ == "__main__":
    role = input("Start as (server/client)? ").strip().lower()
    if role == "server":
        port = ask_int("Port to listen on [default 9999]: ", 9999)
        start_server(port=port)
    else:
        ip = input("Enter server IP (e.g., 127.0.0.1): ").strip()
        port = ask_int("Server port [default 9999]: ", 9999)
        start_client(ip, port=port)
