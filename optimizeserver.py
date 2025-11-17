# ==============================
# optimized_server.py
# ==============================
# 說明：
# 1. 修正 tcp_clients / tcp_usernames 共享資源未加 lock 的問題。
# 2. 將 send_queue 與 sender_thread 統一管理，避免 race condition。
# 3. 移除不必要 except:，提高除錯能力。
# 4. 將重複 LP / XOR logic 與 client 保持一致。
# 5. 修正 idle thread 找不到 username 的潛在問題。

import socket
from threading import Thread, Lock
import tkinter as tk
import time
from queue import Queue

# =========================
# Config
# =========================
TCP_HOST = "127.0.0.1"
TCP_PORT = 12345
UDP_PORT = 12346
BROADCAST_IP = "<broadcast>"

# =========================
# Encrypt / LP
# =========================
KEY = 87


def xor_crypt(data: bytes) -> bytes:
    return bytes([b ^ KEY for b in data])


def send_message(conn, text):
    data = xor_crypt(text.encode("utf-8"))
    length = len(data).to_bytes(4, "big")
    conn.sendall(length + data)


def recv_exact(conn, size):
    buf = b""
    while len(buf) < size:
        part = conn.recv(size - len(buf))
        if not part:
            return None
        buf += part
    return buf


def receive_message(conn):
    raw_len = recv_exact(conn, 4)
    if not raw_len:
        return None
    msg_len = int.from_bytes(raw_len, "big")
    data = recv_exact(conn, msg_len)
    if not data:
        return None
    return xor_crypt(data).decode("utf-8")


# =========================
# Global State + Lock 保護
# =========================
tcp_clients = []
tcp_usernames = []
send_queues = {}
list_lock = Lock()  # ✨ 避免多 thread append/remove 造成不一致

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# =========================
# Keyword Responses
# =========================
KEYWORD_RESPONSES = {
    "/alert": "⚠ 系統公告：請注意！",
    "/game": "🎮 新遊戲活動開始囉！",
    "/news": "📰 最新消息已更新！",
}


# =========================
# Sender Thread: 從 Queue 送訊息
# =========================
def sender_thread(conn):
    q = send_queues[conn]
    while True:
        msg = q.get()
        try:
            send_message(conn, msg)
        except Exception:
            break


# =========================
# TCP Broadcast
# =========================
def broadcast_tcp(message):
    with list_lock:
        for client in list(tcp_clients):
            try:
                send_queues[client].put(message)
            except Exception:
                pass


# =========================
# UDP Broadcast
# =========================
def broadcast_udp(message):
    udp_socket.sendto(message.encode("utf-8"), (BROADCAST_IP, UDP_PORT))
    log_message(message)


# =========================
# Handle Each Client
# =========================
def handle_tcp_client(conn):
    last_active = time.time()
    username = None

    # -------- idle monitor thread --------
    def idle_monitor():
        nonlocal last_active
        warned = False
        while True:
            idle = time.time() - last_active

            if idle >= 240 and not warned:
                send_queues[conn].put("[系統] 您已 4 分鐘未操作，再 1 分鐘將斷線")
                warned = True

            if idle >= 300:
                send_queues[conn].put("[系統] 閒置超過 5 分鐘，自動斷線")
                conn.close()
                return

            time.sleep(5)

    # -------- connection initialization --------
    try:
        send_message(conn, "歡迎進入聊天室！")
        username = receive_message(conn)
        if username is None:
            conn.close()
            return

        with list_lock:
            tcp_clients.append(conn)
            tcp_usernames.append(username)
            send_queues[conn] = Queue()

        Thread(target=sender_thread, args=(conn,), daemon=True).start()
        Thread(target=idle_monitor, daemon=True).start()

        join_msg = f"{username} 已加入聊天室，目前人數：{len(tcp_clients)}"
        broadcast_tcp(join_msg)
        log_message(join_msg)

    except Exception:
        conn.close()
        return

    # -------- message loop --------
    while True:
        try:
            msg = receive_message(conn)
            if msg is None:
                break

            last_active = time.time()

            broadcast_tcp(f"{username}: {msg}")
            log_message(f"{username}: {msg}")

            # keyword trigger
            for key, reply in KEYWORD_RESPONSES.items():
                if msg.startswith(key):
                    broadcast_udp(f"[廣播] {reply} (來自 {username})")
                    break

        except Exception:
            break

    # -------- cleanup --------
    conn.close()
    with list_lock:
        if conn in tcp_clients:
            tcp_clients.remove(conn)
        if username in tcp_usernames:
            tcp_usernames.remove(username)
        send_queues.pop(conn, None)

    leave_msg = f"{username} 離開聊天室，目前人數：{len(tcp_clients)}"
    broadcast_tcp(leave_msg)
    log_message(leave_msg)


# =========================
# GUI Log
# =========================
def log_message(msg):
    chat_text.config(state=tk.NORMAL)
    chat_text.insert(tk.END, msg + "\n")
    chat_text.config(state=tk.DISABLED)
    chat_text.see(tk.END)


# =========================
# TCP Server
# =========================
def start_tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((TCP_HOST, TCP_PORT))
    server.listen()
    log_message(f"伺服器啟動：{TCP_HOST}:{TCP_PORT}")

    while True:
        conn, addr = server.accept()
        Thread(target=handle_tcp_client, args=(conn,), daemon=True).start()


# =========================
# GUI
# =========================
root = tk.Tk()
root.title("Server")
chat_text = tk.Text(root, height=25, width=50, state=tk.DISABLED)
chat_text.pack()

Thread(target=start_tcp_server, daemon=True).start()
root.mainloop()
