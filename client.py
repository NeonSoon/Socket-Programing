import tkinter as tk
from tkinter import simpledialog
from threading import Thread
import socket

connected = False

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


def receive_message_lp(conn):
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
    global connected

    while True:
        try:
            msg = receive_message_lp(tcp_client)
            if msg:
                chat_text.config(state=tk.NORMAL)
                chat_text.insert(tk.END, msg + "\n")
                chat_text.config(state=tk.DISABLED)
                chat_text.see(tk.END)
        except:
            connected = False
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(
                tk.END, "[系統] 您已與伺服器中斷連線。 輸入 /reconnect 以重新連線\n"
            )
            chat_text.config(state=tk.DISABLED)
            break


# -------------------
# UDP 廣播接收
# -------------------
def receive_udp_broadcasts():
    while True:
        try:
            data, _ = udp_client.recvfrom(4096)
            msg = data.decode("utf-8")
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, msg + "\n")
            chat_text.config(state=tk.DISABLED)
            chat_text.see(tk.END)
        except:
            break


# -------------------
# 重新連線（僅斷線或手動使用）
# -------------------
def reconnect():
    global tcp_client, connected

    try:
        if tcp_client:
            try:
                tcp_client.close()
            except:
                pass

        chat_text.config(state=tk.NORMAL)
        chat_text.insert(tk.END, "[系統] 正在嘗試重新連線...\n")
        chat_text.config(state=tk.DISABLED)

        new_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_client.connect((TCP_HOST, TCP_PORT))

        tcp_client = new_client
        connected = True

        send_message_lp(tcp_client, username)
        Thread(target=receive_tcp_messages, daemon=True).start()

        chat_text.config(state=tk.NORMAL)
        chat_text.insert(tk.END, "[系統] 已成功重新連線！\n")
        chat_text.config(state=tk.DISABLED)
        chat_text.see(tk.END)

    except Exception as e:
        chat_text.config(state=tk.NORMAL)
        chat_text.insert(tk.END, f"[系統] 重新連線失敗：{e}\n")
        chat_text.config(state=tk.DISABLED)
        connected = False


# -------------------
# 發送 TCP 訊息
# -------------------
def send_message():
    global connected
    msg = message_entry.get()
    message_entry.delete(0, tk.END)

    if not msg:
        return

    if msg.strip() == "/reconnect":
        if connected == False:
            reconnect()
            return
        else:
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, "[系統] 已在伺服器中\n")
            chat_text.config(state=tk.DISABLED)
            return

    try:
        if connected:
            send_message_lp(tcp_client, msg)
        else:
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, "[系統] 未連線，請輸入 /reconnect\n")
            chat_text.config(state=tk.DISABLED)
    except:
        chat_text.config(state=tk.NORMAL)
        chat_text.insert(tk.END, "[系統] 傳送失敗，請輸入 /reconnect\n")
        chat_text.config(state=tk.DISABLED)
        connected = False


# -------------------
# TCP / UDP 設定
# -------------------
TCP_HOST = "127.0.0.1"
TCP_PORT = 12345
BUFFER_SIZE = 1024
tcp_client = None
connected = False

UDP_PORT = 12346
udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
udp_client.setsockopt(
    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
)  # 允許多個 socket 綁定同 port
udp_client.bind(("", UDP_PORT))  # 固定 12346

# -------------------
# GUI 主程式
# -------------------
root = tk.Tk()
root.title("聊天室 Client")

chat_text = tk.Text(root, height=20, width=50, state=tk.DISABLED)
chat_text.pack(padx=10, pady=10)

frame = tk.Frame(root)
frame.pack(padx=10, pady=5)

message_entry = tk.Entry(frame, width=40)
message_entry.pack(side=tk.LEFT, padx=(0, 5))

send_button = tk.Button(frame, text="送出", width=8, command=send_message)
send_button.pack(side=tk.LEFT)

# -------------------
# 輸入暱稱
# -------------------
username = simpledialog.askstring("暱稱", "請輸入你的暱稱:")
if not username:
    username = "匿名"

# -------------------
# 第一次連線（不使用 reconnect）
# -------------------
try:
    tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_client.connect((TCP_HOST, TCP_PORT))
    connected = True
    send_message_lp(tcp_client, username)
except Exception as e:
    chat_text.config(state=tk.NORMAL)
    chat_text.insert(tk.END, f"[系統] 連線失敗：{e}\n")
    chat_text.insert(tk.END, "[系統] 請使用 /reconnect 嘗試重新連線\n")
    chat_text.config(state=tk.DISABLED)
    connected = False

# -------------------
# 啟動 TCP / UDP 接收 thread
# -------------------
Thread(target=receive_tcp_messages, daemon=True).start()
Thread(target=receive_udp_broadcasts, daemon=True).start()

root.mainloop()
