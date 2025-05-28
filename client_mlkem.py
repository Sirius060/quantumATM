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
        self.bdk = bdk
        self.counter = 0

    def next_ksn(self):
        self.counter += 1
        return self.counter.to_bytes(3, 'big')

    def derive_key(self, ksn):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=ksn,
            iterations=10000,
        )
        return kdf.derive(self.bdk)

class ATMClientGUI:
    def __init__(self):
        self.bdk = b'bankdemo1234567890bankdemo1234567' # 32 bytes
        self.dukpt = DUKPT(self.bdk)
        self.sock = None

        self.root = tk.Tk()
        self.root.title("量子安全ATM系統 (TLS 1.3 + DUKPT)")
        self.root.geometry("420x350")

        self.create_connect_frame()
        self.create_main_frame()
        self.show_connect_frame()

    def create_connect_frame(self):
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
        ttk.Button(btn_frame, text="創建帳號", width=8, command=self.show_create_account).pack(side=tk.LEFT, padx=5)
        btn_frame.pack(pady=10)
        self.log = tk.Text(self.main_frame, height=8, width=52, state="disabled")
        self.log.pack(pady=10)
        ttk.Button(self.main_frame, text="退出", command=self.exit).pack()

    def show_connect_frame(self):
        self.main_frame.pack_forget()
        self.connect_frame.pack(expand=True)

    def show_main_frame(self):
        self.connect_frame.pack_forget()
        self.main_frame.pack(expand=True, fill=tk.BOTH)
        self.log_message("連線成功，已建立安全通道。")
        self.query_balance()

    def connect_server(self):
        host = self.ip_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("錯誤", "請輸入正確的埠號")
            return
        threading.Thread(target=self._connect_server, args=(host, port), daemon=True).start()

    def _connect_server(self, host, port):
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
        ksn = self.dukpt.next_ksn()
        pek = self.dukpt.derive_key(ksn)
        iv = get_random_bytes(16)
        cipher = AES.new(pek, AES.MODE_CBC, iv=iv)
        encrypted = cipher.encrypt(pad(json.dumps(data).encode(), 16))
        payload = ksn + iv + encrypted
        header = len(payload).to_bytes(4, 'big')
        self.sock.sendall(header + payload)

    def _decrypt_receive(self):
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
            return json.loads(decrypted.decode())
        except Exception as e:
            self.log_message(f"解密失敗: {e}")
            return {"success": False, "message": "解密失敗"}

    def log_message(self, msg):
        self.log.config(state="normal")
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        self.log.config(state="disabled")

    def show_deposit(self):
        self._show_amount_dialog("存款金額", self.deposit)

    def show_withdraw(self):
        self._show_amount_dialog("取款金額", self.withdraw)

    def show_transfer(self):
        win = tk.Toplevel(self.root)
        win.title("轉賬")
        ttk.Label(win, text="對方帳號:").pack(pady=5)
        target_entry = ttk.Entry(win)
        target_entry.pack(pady=5)
        ttk.Label(win, text="轉賬金額:").pack(pady=5)
        amount_entry = ttk.Entry(win)
        amount_entry.pack(pady=5)
        def submit():
            try:
                target = target_entry.get()
                amount = float(amount_entry.get())
                if amount <= 0:
                    raise ValueError
                win.destroy()
                threading.Thread(target=self.transfer, args=(target, amount), daemon=True).start()
            except:
                messagebox.showerror("錯誤", "請輸入有效帳號與金額")
        ttk.Button(win, text="確認", command=submit).pack(pady=10)

    def show_create_account(self):
        win = tk.Toplevel(self.root)
        win.title("創建帳號")
        ttk.Label(win, text="新帳號:").pack(pady=5)
        account_entry = ttk.Entry(win)
        account_entry.pack(pady=5)
        account_entry.focus_set()
        def submit():
            try:
                account = account_entry.get()
                if not account:
                    raise ValueError
                win.destroy()
                threading.Thread(target=self.create_account, args=(account,), daemon=True).start()
            except:
                messagebox.showerror("錯誤", "請輸入有效帳號")
        ttk.Button(win, text="確認", command=submit).pack(pady=10)

    def _show_amount_dialog(self, label, action):
        win = tk.Toplevel(self.root)
        win.title(label)
        ttk.Label(win, text=label + ":").pack(pady=5)
        amount_entry = ttk.Entry(win)
        amount_entry.pack(pady=5)
        amount_entry.focus_set()
        def submit():
            try:
                amount = float(amount_entry.get())
                if amount <= 0:
                    raise ValueError
                win.destroy()
                threading.Thread(target=action, args=(amount,), daemon=True).start()
            except:
                messagebox.showerror("錯誤", "請輸入有效正數金額")
        ttk.Button(win, text="確認", command=submit).pack(pady=10)

    def deposit(self, amount):
        try:
            self._encrypt_send({'type': 'deposit', 'amount': amount})
            response = self._decrypt_receive()
            if response.get('success'):
                self.log_message(f"存款{amount}元成功。餘額：{response.get('balance')}")
                self.balance_var.set(str(response.get('balance')))
            else:
                self.log_message(f"存款失敗：{response.get('message')}")
        except Exception as e:
            self.log_message(f"存款異常: {e}")

    def withdraw(self, amount):
        try:
            self._encrypt_send({'type': 'withdraw', 'amount': amount})
            response = self._decrypt_receive()
            if response.get('success'):
                self.log_message(f"取款{amount}元成功。餘額：{response.get('balance')}")
                self.balance_var.set(str(response.get('balance')))
            else:
                self.log_message(f"取款失敗：{response.get('message')}")
        except Exception as e:
            self.log_message(f"取款異常: {e}")

    def transfer(self, target, amount):
        try:
            self._encrypt_send({'type': 'transfer', 'target': target, 'amount': amount})
            response = self._decrypt_receive()
            if response.get('success'):
                self.log_message(f"已成功轉賬{amount}元至{target}。餘額：{response.get('balance')}")
                self.balance_var.set(str(response.get('balance')))
            else:
                self.log_message(f"轉賬失敗：{response.get('message')}")
        except Exception as e:
            self.log_message(f"轉賬異常: {e}")

    def create_account(self, account):
        try:
            self._encrypt_send({'type': 'create_account', 'account': account})
            response = self._decrypt_receive()
            if response.get('success'):
                self.log_message(f"帳號 {account} 創建成功")
            else:
                self.log_message(f"創建帳號失敗：{response.get('message')}")
        except Exception as e:
            self.log_message(f"創建帳號異常: {e}")

    def query_balance(self):
        try:
            self._encrypt_send({'type': 'balance'})
            response = self._decrypt_receive()
            if response.get('success'):
                self.balance_var.set(str(response.get('balance')))
                self.log_message(f"查詢餘額：{response.get('balance')}元")
            else:
                self.log_message(f"查詢餘額失敗：{response.get('message')}")
        except Exception as e:
            self.log_message(f"查詢餘額異常: {e}")

    def exit(self):
        try:
            self._encrypt_send({'type': 'exit'})
        except:
            pass
        if self.sock:
            self.sock.close()
        self.root.destroy()

if __name__ == "__main__":
    ATMClientGUI().root.mainloop()
