import socket
import ssl
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter as tk
from tkinter import ttk, messagebox
import threading

class DUKPT:
    def __init__(self, bdk):
        # 初始化主密鑰（Base Derivation Key）
        self.bdk = bdk
        self.counter = 0  # 交易計數器

    def next_ksn(self):
        # 產生下一筆交易的唯一序號（KSN）
        self.counter += 1
        return self.counter.to_bytes(3, 'big')

    def derive_key(self, ksn):
        # 根據 KSN 派生出本次交易的唯一密鑰（PEK）
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=ksn,
            iterations=10000,
        )
        return kdf.derive(self.bdk)

class ATMClientGUI:
    def __init__(self):
        # 設定主密鑰與 DUKPT 實例
        self.bdk = b'bankdemo1234567890bankdemo1234567' # 32 bytes
        self.dukpt = DUKPT(self.bdk)
        self.sock = None  # 網路連線物件

        # 初始化 Tkinter 主視窗
        self.root = tk.Tk()
        self.root.title("量子安全ATM系統 (TLS 1.3 + DUKPT)")
        self.root.geometry("420x350")

        # 建立連線畫面與主功能畫面
        self.create_connect_frame()
        self.create_main_frame()
        self.show_connect_frame()

    def create_connect_frame(self):
        # 建立連線設定畫面
        self.connect_frame = ttk.Frame(self.root)
        ttk.Label(self.connect_frame, text="伺服器IP:").grid(row=0, column=0, padx=5, pady=10)
        self.ip_entry = ttk.Entry(self.connect_frame)
        self.ip_entry.insert(0, "localhost")
        self.ip_entry.grid(row=0, column=1, padx=5, pady=10)
        ttk.Label(self.connect_frame, text="埠號:").grid(row=1, column=0, padx=5, pady=5)
        self.port_entry = ttk.Entry(self.connect_frame)
        self.port_entry.insert(0, "5000")
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.connect_frame, text="連線", command=self.connect_server).grid(row=2, column=0, columnspan=2, pady=15)

    def create_main_frame(self):
        # 建立主功能畫面（餘額、功能按鈕、日誌）
        self.main_frame = ttk.Frame(self.root)
        self.balance_var = tk.StringVar(value="--")
        ttk.Label(self.main_frame, text="當前餘額:").pack(pady=5)
        self.balance_label = ttk.Label(self.main_frame, textvariable=self.balance_var, font=("Arial", 16))
        self.balance_label.pack(pady=5)
        btn_frame = ttk.Frame(self.main_frame)
        ttk.Button(btn_frame, text="存款", width=8, command=self.show_deposit).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取款", width=8, command=self.show_withdraw).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="轉賬", width=8, command=self.show_transfer).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="查餘額", width=8, command=self.query_balance).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="創建帳號", width=8, command=self.show_create_account).pack(side=tk.LEFT, padx=5) # 新增按鈕
        btn_frame.pack(pady=10)
        self.log = tk.Text(self.main_frame, height=8, width=52, state="disabled")
        self.log.pack(pady=10)
        ttk.Button(self.main_frame, text="退出", command=self.exit).pack()

    def show_connect_frame(self):
        # 顯示連線設定畫面
        self.main_frame.pack_forget()
        self.connect_frame.pack(expand=True)

    def show_main_frame(self):
        # 顯示主功能畫面
        self.connect_frame.pack_forget()
        self.main_frame.pack(expand=True, fill=tk.BOTH)
        self.log_message("連線成功，已建立安全通道。")
        self.query_balance()

    def connect_server(self):
        # 取得 IP 與埠號，開啟新執行緒連線
        host = self.ip_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("錯誤", "請輸入正確的埠號")
            return
        threading.Thread(target=self._connect_server, args=(host, port), daemon=True).start()

    def _connect_server(self, host, port):
        # 建立 TLS 1.3 安全連線
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations('cert.pem')
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            plain_sock = socket.socket()
            self.sock = context.wrap_socket(plain_sock, server_hostname=host)
            self.sock.connect((host, port))
            self.root.after(0, self.show_main_frame)
        except Exception as e:
            self.sock = None
            self.root.after(0, lambda: messagebox.showerror("連線失敗", str(e)))

    def _encrypt_send(self, data):
        # 傳送資料前先加密
        ksn = self.dukpt.next_ksn()  # 取得本次交易 KSN
        pek = self.dukpt.derive_key(ksn)  # 派生唯一密鑰
        iv = get_random_bytes(16)  # 產生隨機 IV
        cipher = AES.new(pek, AES.MODE_CBC, iv=iv)
        encrypted = cipher.encrypt(pad(json.dumps(data).encode(), 16))  # JSON 格式資料加密
        payload = ksn + iv + encrypted  # 將 KSN、IV、密文合併
        header = len(payload).to_bytes(4, 'big')  # 長度標頭
        self.sock.sendall(header + payload)  # 傳送

    def _decrypt_receive(self):
        # 接收資料並解密
        header = self.sock.recv(4)
        data_len = int.from_bytes(header, 'big')
        payload = b''
        while len(payload) < data_len:
            chunk = self.sock.recv(data_len - len(payload))
            if not chunk:
                raise ConnectionError("連線中斷")
            payload += chunk
        ksn = payload[:3]
        iv = payload[3:19]
        encrypted = payload[19:]
        pek = self.dukpt.derive_key(ksn)
        cipher = AES.new(pek, AES.MODE_CBC, iv=iv)
        try:
            decrypted = unpad(cipher.decrypt(encrypted), 16)
            return json.loads(decrypted.decode())  # 回傳解密後的 JSON 物件
        except Exception as e:
            self.log_message(f"解密失敗: {e}")
            return {"success": False, "message": "解密失敗"}

    def log_message(self, msg):
        # 將訊息顯示於日誌區
        self.log.config(state="normal")
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        self.log.config(state="disabled")


if __name__ == "__main__":
    # 啟動 GUI 主迴圈
    ATMClientGUI().root.mainloop()
