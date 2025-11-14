import tkinter as tk
from tkinter import simpledialog
from threading import Thread
import socket

# -------------------
# 伺服器設定
# -------------------
HOST = "127.0.0.1"  # 伺服器 IP
PORT = 12345  # 伺服器 Port
BUFFER_SIZE = 1024  # 每次接收的資料最大 bytes 數

# 建立 client socket 並連線到伺服器
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))


# -------------------
# Length-Prefix 訊息機制（與 Server 相同）
# -------------------
def send_message_lp(conn, text):
    """
    傳送 length-prefix 格式訊息：
    1. 前 4 bytes 放訊息長度
    2. 後面接完整訊息內容
    """
    data = text.encode("utf-8")
    length = len(data).to_bytes(4, "big")
    conn.sendall(length + data)


def recv_exact(conn, size):
    """
    精確接收指定長度的 bytes。
    """
    buf = b""
    while len(buf) < size:
        part = conn.recv(size - len(buf))
        if not part:
            return None
        buf += part
    return buf


def receive_message_lp(conn):
    """
    接收 length-prefix 訊息：
    1. 先讀 4 bytes 訊息長度
    2. 再讀完整訊息內容
    """
    raw_len = recv_exact(conn, 4)
    if not raw_len:
        return None

    msg_len = int.from_bytes(raw_len, "big")
    data = recv_exact(conn, msg_len)
    if not data:
        return None

    return data.decode("utf-8")


# -------------------
# GUI 功能
# -------------------
def receive_messages():
    """
    不斷接收伺服器訊息（採用 length-prefix），並更新 GUI。
    在獨立 Thread 執行以避免 GUI 卡住。
    """
    while True:
        try:
            msg = receive_message_lp(client)
            if msg:
                chat_text.config(state=tk.NORMAL)
                chat_text.insert(tk.END, msg + "\n")
                chat_text.config(state=tk.DISABLED)
                chat_text.see(tk.END)
        except:
            break


def send_message():
    """
    將輸入框文字送到伺服器（使用 length-prefix）。
    若傳送失敗則顯示錯誤訊息。
    """
    msg = message_entry.get()
    if msg:
        try:
            send_message_lp(client, msg)
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

# 下方輸入區
frame = tk.Frame(root)
frame.pack(padx=10, pady=5)

message_entry = tk.Entry(frame, width=40)
message_entry.pack(side=tk.LEFT, padx=(0, 5))

send_button = tk.Button(frame, text="送出", width=8, command=send_message)
send_button.pack(side=tk.LEFT)

# -------------------
# 輸入暱稱並傳送到伺服器
# -------------------
username = simpledialog.askstring("暱稱", "請輸入你的暱稱:")

if username:
    send_message_lp(client, username)
else:
    send_message_lp(client, "匿名")

# -------------------
# 啟動接收訊息 Thread
# -------------------
Thread(target=receive_messages, daemon=True).start()

# 開始 GUI 事件迴圈
root.mainloop()
