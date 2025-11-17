# ===== Modified server.py with non-blocking send queues =====
import socket
from threading import Thread
import tkinter as tk
import time
from queue import Queue

# =========================
# 伺服器主機與通訊埠設定
# =========================
TCP_HOST = "127.0.0.1"  # TCP 聊天服務
TCP_PORT = 12345
BUFFER_SIZE = 1024

UDP_PORT = 12346  # UDP 廣播服務
BROADCAST_IP = "<broadcast>"  # 255.255.255.255

# =========================
# 加密金鑰與函式
# =========================
KEY = 87  # 任意 0~255 的整數，用來 XOR 加密

def xor_crypt(data: bytes) -> bytes:
    return bytes([b ^ KEY for b in data])

# =========================
# 儲存 TCP client 與名稱 + 傳送 Queue
# =========================
tcp_clients = []
tcp_usernames = []
send_queues = {}  # 每一個 client 一個 Queue

# =========================
# 建立 UDP 廣播 socket
# =========================
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# -----------------------
# 關鍵字對應回覆訊息
# -----------------------
KEYWORD_RESPONSES = {
    "/alert": "⚠ 系統公告：請注意！",
    "/game": "🎮 新遊戲活動開始囉！",
    "/news": "📰 最新消息已更新！",
    "!嚴厲斥責": "嚴厲斥責你發瘋啦\n這什麼東西啦不可以啊\n不要再亂搞了啦\n不要再蝦幾把搞了啦\n你幹嘛這樣\
    \n啊怎麼這麼激烈啊\n不可以這樣子啊發瘋了是不是啊\n啥小啦\n不要不可以不可以講什麼話啊\n操擊敗勒啦冷靜一點啦\
    \n幹這到底又是什麼東西不可以啦\n這是能講的話嗎絕對不可以的啊",
}

# -----------------------
# Length-Prefix 傳輸
# -----------------------
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
# 非阻塞傳送 Thread：從 Queue 取出訊息再送
# =========================
def sender_thread(conn):
    q = send_queues[conn]
    while True:
        msg = q.get()  # Blocking，但不會卡住主程式
        try:
            send_message(conn, msg)
        except:
            break

# =========================
# 廣播 TCP：改為送到 Queue，而不是直接 sendall
# =========================
def broadcast_tcp(message):
    for client in tcp_clients:
        try:
            send_queues[client].put(message)
        except:
            pass

# =========================
# 廣播 UDP
# =========================
def broadcast_udp(message):
    udp_socket.sendto(message.encode("utf-8"), (BROADCAST_IP, UDP_PORT))
    log_message(message)

# =========================
# handle client
# =========================
def handle_tcp_client(conn):
    last_active_time = time.time()

    def idle_monitor():
        nonlocal last_active_time, conn, username
        warned = False
        while True:
            now = time.time()
            idle_time = now - last_active_time

            if idle_time >= 240 and not warned:
                send_queues[conn].put("[系統] 您已 4 分鐘未操作，再 1 分鐘將自動斷線。")
                warned = True

            if idle_time >= 300:
                send_queues[conn].put("[系統] 您因閒置超過 5 分鐘被斷線。")
                conn.close()
                return
            time.sleep(5)

    try:
        send_message(conn, "歡迎進入聊天室！")
        username = receive_message(conn)
        if username is None:
            conn.close()
            return

        tcp_clients.append(conn)
        tcp_usernames.append(username)
        send_queues[conn] = Queue()  # 建立 Queue

        Thread(target=sender_thread, args=(conn,), daemon=True).start()  # 啟動 sender
        Thread(target=idle_monitor, daemon=True).start()                # 啟動 idle thread

        join_msg = f"{username} 已加入聊天室！目前聊天室人數：{len(tcp_clients)}"
        broadcast_tcp(join_msg)
        log_message(join_msg)

    except:
        conn.close()
        return

    while True:
        try:
            msg = receive_message(conn)
            if msg is None:
                break

            last_active_time = time.time()

            broadcast_tcp(f"{username}: {msg}")
            log_message(f"{username}: {msg}")

            for keyword, reply in KEYWORD_RESPONSES.items():
                if msg.startswith(keyword):
                    broadcast_udp(f"[廣播] {reply} (來自 {username})")
                    break
        except:
            break

    conn.close()
    if conn in tcp_clients:
        tcp_clients.remove(conn)
    if username in tcp_usernames:
        tcp_usernames.remove(username)

    leave_msg = f"{username} 離開聊天室。目前聊天室人數：{len(tcp_clients)}"
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
    log_message(f"伺服器已啟動：{TCP_HOST}:{TCP_PORT}")

    while True:
        conn, addr = server.accept()
        Thread(target=handle_tcp_client, args=(conn,), daemon=True).start()

# =========================
# GUI 啟動
# =========================
root = tk.Tk()
root.title("server")
chat_text = tk.Text(root, height=25, width=50, state=tk.DISABLED)
chat_text.pack()

Thread(target=start_tcp_server, daemon=True).start()
root.mainloop()
