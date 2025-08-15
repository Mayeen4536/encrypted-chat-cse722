# 🔐 CSE722 Project 1 — Encrypted Chat Application (RSA + AES-256)

## 📌 Overview
This project is a **two-way encrypted chat application** built in Python for the CSE722 Applied Cryptography course.  
It demonstrates the use of:
- **RSA-2048** for secure public key exchange.
- **AES-256 (CFB mode)** for encrypting chat messages after key exchange.
- **TCP sockets** for communication.
- **Wireshark** for verification.

---

## 🎯 Purpose
The goal of this project is to implement **hybrid encryption** in a real-time chat environment:
- **Asymmetric encryption (RSA)** is used to securely exchange a randomly generated symmetric key.
- **Symmetric encryption (AES)** is used for all subsequent communication for speed and efficiency.
- **Wireshark** is used to confirm that messages after the handshake are encrypted.

---

## 🛠 Technologies Used
- **Language:** Python 3.13
- **Libraries:** [cryptography](https://cryptography.io/), socket, threading
- **Protocol:** TCP
- **Algorithms:** RSA-2048 (OAEP, SHA-256), AES-256 (CFB mode)
- **Verification:** Wireshark

---

## 📥 Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/encrypted-chat-cse722.git
   cd encrypted-chat-cse722
   ```
2. Install dependencies:
   ```bash
   pip install cryptography
   ```

---

## 🚀 Usage

### 1️⃣ Start the Server
```bash
python client.py
# Start as (server/client)? server
# Port to listen on [default 9999]: 50000
```

### 2️⃣ Start the Client
```bash
python client.py
# Start as (server/client)? client
# Enter server IP: 127.0.0.1   (or LAN IPv4 if on separate devices)
# Server port [default 9999]: 50000
```

---

## 🔄 Commands Inside Chat
- `sendkey` → Exchange RSA public keys (plaintext in Wireshark)
- `sendaes` → Send AES-256 key encrypted with peer's RSA public key
- Any other text → Sends AES-256 encrypted message
- `quit` → Close connection

---

## 🧪 Verifying Encryption with Wireshark
1. **Start Wireshark** and select:
   - **Npcap Loopback Adapter** (for local testing) or your **Wi-Fi/Ethernet adapter** (for two devices)
2. Apply filter:
   ```
   tcp.port == 50000
   ```
   *(Replace `50000` with your chosen port)*
3. Capture:
   - **Before Encryption**: Run `sendkey`, then view packet in **Follow → TCP Stream** → RSA public key will be visible.
   - **After Encryption**: After `sendaes`, send a message → ciphertext will be unreadable.

---

## 📂 Project Structure
```
client.py       # Main chat application
README.md       # Project documentation
```

---

## 📷 Sample Screenshots
**Before Encryption — RSA Public Key (plaintext)**  
*(Insert Wireshark screenshot here)*

**After Encryption — AES Ciphertext (unreadable)**  
*(Insert Wireshark screenshot here)*

---

## 📜 License
This project is for academic purposes only under the CSE722 course at BRAC University.

---

## 👤 Author
- **Name:** Mayeen Abedin Sajid  
- **ID:** 24266036  
- **Course:** CSE722 Applied Cryptography
