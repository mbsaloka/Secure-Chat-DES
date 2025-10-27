import socket
import threading
import argparse
import sys
from des import des_encrypt, des_decrypt

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

def run_server(host: str, port: int, key: str):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    print(f"[INFO] Menunggu koneksi di {host}:{port}")
    conn, addr = server.accept()
    print(f"[INFO] Terhubung dengan {addr[0]}:{addr[1]}")

    recv_thread = threading.Thread(target=recv_messages, args=(conn, key, "Client"), daemon=True)
    send_thread = threading.Thread(target=send_input, args=(conn, key), daemon=True)

    recv_thread.start()
    send_thread.start()
    send_thread.join()
    conn.close()
    server.close()

def run_client(host: str, port: int, key: str):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[INFO] Menghubungkan ke server {host}:{port}")
    client.connect((host, port))
    print("[INFO] Terhubung ke server.")

    recv_thread = threading.Thread(target=recv_messages, args=(client, key, "Server"), daemon=True)
    send_thread = threading.Thread(target=send_input, args=(client, key), daemon=True)

    recv_thread.start()
    send_thread.start()
    send_thread.join()
    client.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["server", "client"], required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8989)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()

    print(f"[Mode: {args.mode}] [Key: {args.key}]")

    if args.mode == "server":
        run_server(args.host, args.port, args.key)
    else:
        run_client(args.host, args.port, args.key)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
