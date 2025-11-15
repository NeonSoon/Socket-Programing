import tkinter as tk
from tkinter import simpledialog
from threading import Thread
import socket

# -------------------
# TCP 伺服器設定
# -------------------
TCP_HOST = "127.0.0.1"  # TCP 伺服器 IP
TCP_PORT = 12345  # TCP Port
BUFFER_SIZE = 1024  # TCP 接收 buffer

tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_client.connect((TCP_HOST, TCP_PORT))

# -------------------
# UDP 廣播設定
# -------------------
UDP_PORT = 12346  # UDP 廣播 Port
udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
udp_client.bind(("", UDP_PORT))  # 監聽所有廣播訊息

# =========================
# 加密金鑰與函式
# =========================
KEY = 87  # 任意 0~255 的整數，用來 XOR 加密


def xor_crypt(data: bytes) -> bytes:
    return bytes([b ^ KEY for b in data])


# -------------------
# Length-Prefix 訊息機制
# -------------------
def send_message_lp(conn, text):
    """傳送 length-prefix 訊息"""
    data = xor_crypt(text.encode("utf-8"))
    length = len(data).to_bytes(4, "big")
    conn.sendall(length + data)


def recv_exact(conn, size):
    """精確接收指定 bytes"""
    buf = b""
    while len(buf) < size:
        part = conn.recv(size - len(buf))
        if not part:
            return None
        buf += part
    return buf


def receive_message_lp(conn):
    """接收 length-prefix 訊息"""
    raw_len = recv_exact(conn, 4)
    if not raw_len:
        return None
    msg_len = int.from_bytes(raw_len, "big")
    data = recv_exact(conn, msg_len)
    if not data:
        return None
    return xor_crypt(data).decode("utf-8")


# -------------------
# TCP 訊息接收
# -------------------
def receive_tcp_messages():
    """接收 TCP 訊息並更新 GUI"""
    while True:
        try:
            msg = receive_message_lp(tcp_client)
            if msg:
                chat_text.config(state=tk.NORMAL)
                chat_text.insert(tk.END, msg + "\n")
                chat_text.config(state=tk.DISABLED)
                chat_text.see(tk.END)
        except:
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, "[系統] 您已與伺服器中斷連線。\n")
            chat_text.config(state=tk.DISABLED)
            break


# -------------------
# UDP 廣播接收
# -------------------
def receive_udp_broadcasts():
    """接收 UDP 廣播訊息並更新 GUI"""
    while True:
        try:
            data, _ = udp_client.recvfrom(4096)  # 接收廣播
            msg = data.decode("utf-8")
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, msg + "\n")
            chat_text.config(state=tk.DISABLED)
            chat_text.see(tk.END)
        except:
            break


# -------------------
# 發送 TCP 訊息
# -------------------
def send_message():
    """將輸入框訊息送到 TCP 伺服器"""
    msg = message_entry.get()
    if msg:
        try:
            send_message_lp(tcp_client, msg)
        except:
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, "[系統] 無法送出訊息，請確認連線\n")
            chat_text.config(state=tk.DISABLED)
        message_entry.delete(0, tk.END)


# -------------------
# GUI 主程式
# -------------------
root = tk.Tk()
root.title("聊天室 Client")

# 聊天訊息顯示區
chat_text = tk.Text(root, height=20, width=50, state=tk.DISABLED)
chat_text.pack(padx=10, pady=10)

# 訊息輸入區
frame = tk.Frame(root)
frame.pack(padx=10, pady=5)

message_entry = tk.Entry(frame, width=40)
message_entry.pack(side=tk.LEFT, padx=(0, 5))

send_button = tk.Button(frame, text="送出", width=8, command=send_message)
send_button.pack(side=tk.LEFT)

# -------------------
# 輸入暱稱並傳送到 TCP 伺服器
# -------------------
username = simpledialog.askstring("暱稱", "請輸入你的暱稱:")
if username:
    send_message_lp(tcp_client, username)
else:
    send_message_lp(tcp_client, "匿名")

# -------------------
# 啟動 TCP 與 UDP 接收 thread
# -------------------
Thread(target=receive_tcp_messages, daemon=True).start()
Thread(target=receive_udp_broadcasts, daemon=True).start()

# 開始 GUI 事件迴圈
root.mainloop()
