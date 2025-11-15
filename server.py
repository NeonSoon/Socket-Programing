import socket
from threading import Thread
import tkinter as tk

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
# 儲存 TCP client 與名稱
# =========================
tcp_clients = []
tcp_usernames = []

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


# -----------------------------------------
# 長訊息傳輸函數（TCP length-prefix）
# -----------------------------------------
def send_message(conn, text):
    """
    使用 length-prefix 傳送訊息：
    - 先傳 4 bytes 表示訊息長度
    - 再傳送真正訊息內容
    """
    data = xor_crypt(text.encode("utf-8"))  # 加密
    length = len(data).to_bytes(4, "big")
    conn.sendall(length + data)


def recv_exact(conn, size):
    """
    從 socket 精確讀取指定 bytes
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
    接收 length-prefix 格式完整訊息
    """
    raw_len = recv_exact(conn, 4)
    if not raw_len:
        return None
    msg_len = int.from_bytes(raw_len, "big")
    data = recv_exact(conn, msg_len)
    if not data:
        return None
    return xor_crypt(data).decode("utf-8")  # 解密


# =========================
# 廣播 TCP 訊息給所有 TCP client
# =========================
def broadcast_tcp(message):
    for client in tcp_clients:
        try:
            send_message(client, message)
        except:
            pass


# =========================
# 廣播 UDP 訊息給所有 client
# =========================
def broadcast_udp(message):
    """
    廣播訊息給所有 client，並在 server GUI 顯示
    """
    udp_socket.sendto(message.encode("utf-8"), (BROADCAST_IP, UDP_PORT))
    # 在 server GUI 顯示
    log_message(f"{message}")


# =========================
# 處理每個 TCP client
# =========================
def handle_tcp_client(conn):
    """
    TCP client handler thread：
    - 發送歡迎訊息
    - 接收使用者名稱
    - 廣播加入訊息
    - 接收並廣播訊息
    - 離線處理
    - 支援特定指令觸發 UDP 廣播
    """
    try:
        # 歡迎訊息
        send_message(conn, "歡迎進入聊天室！")

        # 接收使用者名稱
        username = receive_message(conn)
        if username is None:
            conn.close()
            return

        # 記錄 TCP client 與名稱
        tcp_clients.append(conn)
        tcp_usernames.append(username)

        # 廣播加入訊息
        current_count = len(tcp_clients)
        join_msg = f"{username} 已加入聊天室！目前聊天室人數：{current_count}"
        broadcast_tcp(join_msg)
        log_message(join_msg)

    except:
        conn.close()
        return

    # 主訊息接收迴圈
    while True:
        try:
            msg = receive_message(conn)
            if msg is None:
                break

            # 廣播 TCP 訊息
            broadcast_tcp(f"{username}: {msg}")
            log_message(f"{username}: {msg}")

            # --- 自動關鍵字觸發 UDP 廣播 ---
            for keyword, reply in KEYWORD_RESPONSES.items():
                if msg.startswith(keyword):  # 若訊息符合關鍵字
                    broadcast_udp(f"[廣播] {reply} (來自 {username})")
                    break  # 一次只觸發一個關鍵字

        except:
            break

    # 離線處理
    conn.close()
    if conn in tcp_clients:
        tcp_clients.remove(conn)
    if username in tcp_usernames:
        tcp_usernames.remove(username)

    current_count = len(tcp_clients)
    leave_msg = f"{username} 離開聊天室。目前聊天室人數：{current_count}"
    broadcast_tcp(leave_msg)
    log_message(leave_msg)


# =========================
# GUI 日誌顯示
# =========================
def log_message(msg):
    chat_text.config(state=tk.NORMAL)
    chat_text.insert(tk.END, msg + "\n")
    chat_text.config(state=tk.DISABLED)
    chat_text.see(tk.END)


# =========================
# TCP server 啟動
# =========================
def start_tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((TCP_HOST, TCP_PORT))
    server.listen()
    log_message(f"聊天室伺服器啟動，等待連線 {TCP_HOST}:{TCP_PORT}")

    while True:
        conn, addr = server.accept()
        Thread(target=handle_tcp_client, args=(conn,), daemon=True).start()


# =========================
# GUI 介面設定
# =========================
root = tk.Tk()
root.title("server")

chat_text = tk.Text(root, height=25, width=50, state=tk.DISABLED)
chat_text.pack()

# 啟動 TCP server thread
Thread(target=start_tcp_server, daemon=True).start()

root.mainloop()
