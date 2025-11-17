# ==============================
# optimized_client.py
# ==============================
# 說明：
# 1. 將所有 UI 更新集中到 thread-safe 的 append_chat()，避免 Tkinter 在多執行緒下出錯。
# 2. 重構 thread 啟動流程，使 reconnect() 能完整重啟 TCP/UDP 接收執行緒。
# 3. 修正原程式過多 except:，改成 except Exception 以便除錯。
# 4. 將重複邏輯抽出，程式結構更清晰。
# 5. 移除不必要的 global 使用，降低耦合度。

import tkinter as tk
from tkinter import simpledialog
from threading import Thread
import socket

# =========================
# 加密與 LP 處理（和 server.py 的保持一致）
# =========================
KEY = 87


def xor_crypt(data: bytes) -> bytes:
    return bytes([b ^ KEY for b in data])


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


# -----------------------------
# Thread-safe UI 更新
# -----------------------------
def append_chat(msg):
    chat_text.after(0, lambda: _append(msg))


def _append(msg):
    chat_text.config(state=tk.NORMAL)
    chat_text.insert(tk.END, msg + "\n")
    chat_text.config(state=tk.DISABLED)
    chat_text.see(tk.END)


# =========================
# TCP / UDP 接收 Thread
# =========================
tcp_client = None
udp_client = None
connected = False
stop_threads = False


def tcp_listener():
    global connected
    while not stop_threads:
        try:
            msg = receive_message_lp(tcp_client)
            if msg:
                append_chat(msg)
            else:
                raise Exception("Connection lost")
        except Exception:
            if connected:
                append_chat("[系統] 與伺服器斷線。請輸入 /reconnect")
            connected = False
            break


def udp_listener():
    while not stop_threads:
        try:
            data, _ = udp_client.recvfrom(4096)
            append_chat(data.decode("utf-8"))
        except Exception:
            break


# =========================
# 重構後的 reconnect
# =========================
def reconnect():
    global tcp_client, connected, stop_threads

    append_chat("[系統] 正在嘗試重新連線...")

    try:
        # 停止舊 thread
        stop_threads = True

        # 建立新 TCP
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.connect((TCP_HOST, TCP_PORT))

        tcp_client = tcp
        connected = True

        # 傳送暱稱給 server
        send_message_lp(tcp_client, username)

        # 重啟 threads
        stop_threads = False
        Thread(target=tcp_listener, daemon=True).start()
        Thread(target=udp_listener, daemon=True).start()

        append_chat("[系統] 已成功恢復連線！")

    except Exception as e:
        connected = False
        append_chat(f"[系統] 重新連線失敗：{e}")


# =========================
# 傳送訊息
# =========================
def send_message():
    global connected

    msg = message_entry.get().strip()
    message_entry.delete(0, tk.END)

    if not msg:
        return

    # 熱鍵：重新連線
    if msg == "/reconnect":
        if not connected:
            reconnect()
        else:
            append_chat("[系統] 已在伺服器中")
        return

    # 一般訊息
    try:
        if connected:
            send_message_lp(tcp_client, msg)
        else:
            append_chat("[系統] 未連線，請輸入 /reconnect")
    except Exception:
        append_chat("[系統] 傳送失敗，請輸入 /reconnect")
        connected = False


# =========================
# 初始化 TCP / UDP
# =========================
TCP_HOST = "127.0.0.1"
TCP_PORT = 12345
UDP_PORT = 12346

udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
udp_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp_client.bind(("", UDP_PORT))

# =========================
# GUI
# =========================
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

# 暱稱輸入
username = simpledialog.askstring("暱稱", "請輸入你的暱稱:") or "匿名"

# ========== 第一次連線 ==========
try:
    tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_client.connect((TCP_HOST, TCP_PORT))
    connected = True
    send_message_lp(tcp_client, username)
except Exception as e:
    append_chat(f"[系統] 連線失敗：{e}")
    append_chat("[系統] 請輸入 /reconnect 嘗試重新連線")
    connected = False

# 啟動 Threads
stop_threads = False
Thread(target=tcp_listener, daemon=True).start()
Thread(target=udp_listener, daemon=True).start()

root.mainloop()
