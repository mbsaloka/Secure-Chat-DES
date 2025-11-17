import socket
import threading
import argparse
import sys
import base64
import string
import random

from des import des_encrypt, des_decrypt
import rsa

def send_line(sock: socket.socket, data: bytes):
    sock.sendall(data + b"\n")

def recv_line(sock: socket.socket):
    buffer = b""
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            return None
        buffer += chunk
        if b"\n" in buffer:
            line, rest = buffer.split(b"\n", 1)
            return line

# Handshake (server)
def server_handshake(conn: socket.socket, provided_key: str = None) -> str:
    if provided_key:
        print("[INFO] Menggunakan DES key dari argumen.")
        return provided_key

    print("[INFO] Membuat RSA keypair (this may take a bit)...")
    pub, priv = rsa.generate_keypair(bits=256)
    pub_bytes = rsa.serialize_public(pub)

    send_line(conn, pub_bytes)
    print("[INFO] Public key terkirim. Menunggu DES key terenkripsi...")

    enc_b64 = recv_line(conn)
    if enc_b64 is None:
        raise ConnectionError("Client menutup koneksi saat handshake.")
    try:
        enc = base64.b64decode(enc_b64)
        decrypted_padded = rsa.rsa_decrypt(enc, priv)
        stripped = decrypted_padded.lstrip(b'\x00')

        # if empty, fallback to decrypted_padded
        if not stripped:
            stripped = decrypted_padded
        # ensure we take at most 8 bytes (DES key length)
        if len(stripped) > 8:
            des_key_bytes = stripped[-8:]
        else:
            des_key_bytes = stripped
        des_key = des_key_bytes.decode('ascii', errors='ignore')
        # if decoded length < 8, pad with 'A' (should not happen if client sends correct)
        if len(des_key) < 8:
            des_key = des_key.ljust(8, "A")
        print("[INFO] Handshake selesai. DES key diterima.")
        return des_key
    except Exception as e:
        raise RuntimeError(f"Handshake gagal di server: {e}")

# Handshake (client)
def client_handshake(sock: socket.socket, provided_key: str = None) -> str:
    if provided_key:
        print("[INFO] Menggunakan DES key dari argumen.")
        return provided_key

    print("[INFO] Menunggu public key dari server...")
    pub_line = recv_line(sock)
    if pub_line is None:
        raise ConnectionError("Server menutup koneksi saat handshake.")
    pub = rsa.deserialize_public(pub_line)
    # generate DES key (8 printable ASCII chars)
    alphabet = string.ascii_letters + string.digits
    des_key = ''.join(random.choice(alphabet) for _ in range(8))
    print(f"[INFO] Menghasilkan DES Key = {des_key}")

    # encrypt with RSA
    try:
        ciphertext = rsa.rsa_encrypt(des_key.encode('ascii'), pub)
        send_line(sock, base64.b64encode(ciphertext))
        print("[INFO] DES key terenkripsi terkirim ke server.")
        return des_key
    except Exception as e:
        raise RuntimeError(f"Handshake gagal di client: {e}")

# Chat functions (DES)
def send_message(sock, msg: str, key: str):
    try:
        ciphertext = des_encrypt(msg, key, mode="multiple")
        sock.sendall((ciphertext + "\n").encode())
    except Exception as e:
        print(f"[ERROR] gagal kirim: {e}")

def recv_messages(sock, key: str, name: str):
    buffer = ""
    try:
        while True:
            data = sock.recv(1024)
            if not data:
                print("\n[INFO] Koneksi terputus.")
                break
            buffer += data.decode()
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                try:
                    plaintext = des_decrypt(line, key, mode="multiple")
                    print(f"\n[{name}] {plaintext}\n> ", end="", flush=True)
                except Exception as e:
                    print(f"\n[ERROR] Gagal dekripsi: {e}")
    except Exception as e:
        print(f"[ERROR] Thread penerima: {e}")
    finally:
        sock.close()

def send_input(sock, key: str):
    try:
        while True:
            msg = input("> ")
            if msg.strip().lower() in ("/quit", "/exit"):
                print("[INFO] Keluar.")
                sock.close()
                break
            send_message(sock, msg, key)
    except KeyboardInterrupt:
        sock.close()
    except Exception as e:
        print(f"[ERROR] Thread pengirim: {e}")
        sock.close()

def run_server(host: str, port: int, key: str = None):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    print(f"[INFO] Menunggu koneksi di {host}:{port}")
    conn, addr = server.accept()
    print(f"[INFO] Terhubung dengan {addr[0]}:{addr[1]}")

    try:
        des_key = server_handshake(conn, provided_key=key)
    except Exception as e:
        print(f"[ERROR] Handshake gagal: {e}")
        conn.close()
        server.close()
        return

    recv_thread = threading.Thread(target=recv_messages, args=(conn, des_key, "Client"), daemon=True)
    send_thread = threading.Thread(target=send_input, args=(conn, des_key), daemon=True)

    recv_thread.start()
    send_thread.start()
    send_thread.join()
    conn.close()
    server.close()

def run_client(host: str, port: int, key: str = None):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[INFO] Menghubungkan ke server {host}:{port}")
    client.connect((host, port))
    print("[INFO] Terhubung ke server.")

    try:
        des_key = client_handshake(client, provided_key=key)
    except Exception as e:
        print(f"[ERROR] Handshake gagal: {e}")
        client.close()
        return

    recv_thread = threading.Thread(target=recv_messages, args=(client, des_key, "Server"), daemon=True)
    send_thread = threading.Thread(target=send_input, args=(client, des_key), daemon=True)

    recv_thread.start()
    send_thread.start()
    send_thread.join()
    client.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["server", "client"], required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8989)
    parser.add_argument("--key", required=False, help="(Optional) DES key. Jika tidak disediakan, RSA handshake akan dilakukan.")
    args = parser.parse_args()

    print(f"[Mode: {args.mode}] [Key: {'(provided)' if args.key else '(handshake)'}]")

    if args.mode == "server":
        run_server(args.host, args.port, args.key)
    else:
        run_client(args.host, args.port, args.key)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
