import socket
from threading import Thread
import tkinter as tk

# 伺服器主機位置與通訊埠設定
HOST = "127.0.0.1"  # 本機 IP
PORT = 12345  # 伺服器監聽的 port
BUFFER_SIZE = 1024  # 每次收訊息的最大長度

# 儲存已連線的 client socket 與其名稱
clients = []
usernames = []


# -----------------------------------------
# 新增：Length-Prefix 傳輸協定
# -----------------------------------------
def send_message(conn, text):
    """
    使用 length-prefix 機制傳送訊息：
    1. 先傳送 4 bytes 表示訊息長度
    2. 再傳送真正訊息內容
    """
    data = text.encode("utf-8")
    length = len(data).to_bytes(4, "big")
    conn.sendall(length + data)


def recv_exact(conn, size):
    """
    從 socket 中精確讀取指定長度 bytes。
    """
    buf = b""
    while len(buf) < size:
        part = conn.recv(size - len(buf))
        if not part:
            return None
        buf += part
    return buf


def receive_message(conn):
    """
    接收 length-prefix 格式的完整訊息：
    1. 先讀 4 bytes 的訊息長度
    2. 再讀取對應長度的完整訊息
    """
    raw_len = recv_exact(conn, 4)
    if not raw_len:
        return None

    msg_len = int.from_bytes(raw_len, "big")
    data = recv_exact(conn, msg_len)
    if not data:
        return None

    return data.decode("utf-8")


# 廣播訊息給所有 client（改成 length-prefix 版本）
def broadcast(message):
    for client in clients:
        try:
            send_message(client, message)
        except:
            pass


# --- 處理每個 client 的行為 ---
def handle_client(conn):
    """
    為每個新連線的 client 建立 Thread 處理：
    - 發送歡迎訊息
    - 接收使用者名稱
    - 廣播加入訊息
    - 持續接收並廣播訊息
    - 處理離線事件
    """
    try:
        # 一連線就先送歡迎訊息
        send_message(conn, "歡迎進入聊天室！")

        # 接收使用者名稱（使用 length-prefix）
        username = receive_message(conn)
        if username is None:
            conn.close()
            return

        # 記錄 client socket 與名稱
        clients.append(conn)
        usernames.append(username)

        # 廣播加入訊息
        current_count = len(clients)
        join_msg = f"{username} 已加入聊天室！目前聊天室人數：{current_count}"
        broadcast(join_msg)
        log_message(join_msg)

    except:
        conn.close()
        return

    # --- 主訊息接收迴圈 ---
    while True:
        try:
            msg = receive_message(conn)
            if msg is None:
                break

            # 廣播訊息給所有 client
            broadcast(f"{username}: {msg}")
            log_message(f"{username}: {msg}")
        except:
            break

    # --- 離線處理 ---
    conn.close()
    if conn in clients:
        clients.remove(conn)
    if username in usernames:
        usernames.remove(username)

    current_count = len(clients)
    leave_msg = f"{username} 離開聊天室。目前聊天室人數：{current_count}"
    broadcast(leave_msg)
    log_message(leave_msg)


# --- GUI 日誌顯示 ---
def log_message(msg):
    chat_text.config(state=tk.NORMAL)
    chat_text.insert(tk.END, msg + "\n")
    chat_text.config(state=tk.DISABLED)
    chat_text.see(tk.END)


# --- 伺服器啟動與監聽 ---
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    log_message(f"伺服器啟動，等待連線 {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        Thread(target=handle_client, args=(conn,), daemon=True).start()


# --- GUI 介面設定 ---
root = tk.Tk()
root.title("伺服器聊天室")

chat_text = tk.Text(root, height=25, width=50, state=tk.DISABLED)
chat_text.pack()

Thread(target=start_server, daemon=True).start()

root.mainloop()
