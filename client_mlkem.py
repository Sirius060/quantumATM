import socket
import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from kyber_py.ml_kem import ML_KEM_768
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from dilithium_py.dilithium import Dilithium2
from datetime import datetime
import base64
import time

class QuantumATMClient:
    def __init__(self):
        self.sock = None
        self.session_key = None
        self.dilithium_class = Dilithium2
        self.sig_pk, self.sig_sk = self.dilithium_class.keygen()
        self.root = tk.Tk()
        self.root.title("🛡️ 量子安全ATM系統")
        self.root.geometry("600x700")
        self.lock = threading.Lock()
        self.retry_count = 0
        self.max_retries = 3
        self.last_balance = 0.0
        self._setup_styles()
        self._setup_interface()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Arial', 20, 'bold'), foreground='#2c3e50')
        style.configure('Balance.TLabel', font=('Arial', 24, 'bold'), foreground='#27ae60')
        style.configure('Status.TLabel', font=('Arial', 10), foreground='#7f8c8d')
        style.configure('Action.TButton', font=('Arial', 12, 'bold'), padding=10)

    def _setup_interface(self):
        main_container = ttk.Frame(self.root)
        main_container.pack(fill='both', expand=True, padx=20, pady=20)

        title_frame = ttk.Frame(main_container)
        title_frame.pack(fill='x', pady=(0, 20))
        ttk.Label(title_frame, text="🛡️ 量子安全ATM系統", style='Title.TLabel').pack()
        ttk.Label(title_frame, text="Post-Quantum Cryptography Secure Banking", 
                 font=('Arial', 10), foreground='#95a5a6').pack()

        self.connect_frame = ttk.LabelFrame(main_container, text="🔗 伺服器連線", padding=15)
        self.connect_frame.pack(fill='x', pady=(0, 20))
        
        conn_inner = ttk.Frame(self.connect_frame)
        conn_inner.pack()
        
        ttk.Label(conn_inner, text="伺服器IP:", font=('Arial', 11)).grid(row=0, column=0, sticky='e', padx=(0, 10))
        self.ip_entry = ttk.Entry(conn_inner, width=20, font=('Arial', 11))
        self.ip_entry.insert(0, "localhost")
        self.ip_entry.grid(row=0, column=1, padx=(0, 10))
        
        self.connect_btn = ttk.Button(conn_inner, text="🔐 建立量子安全連線", 
                                    command=self._start_handshake, style='Action.TButton')
        self.connect_btn.grid(row=0, column=2)

        self.main_frame = ttk.Frame(main_container)
        self._build_transaction_ui()

        self.status_frame = ttk.Frame(main_container)
        self.status_frame.pack(fill='x', side='bottom', pady=(20, 0))
        ttk.Separator(self.status_frame, orient='horizontal').pack(fill='x', pady=(0, 5))
        self.status_var = tk.StringVar(value="🔴 未連線 - 等待建立量子安全通道")
        ttk.Label(self.status_frame, textvariable=self.status_var, style='Status.TLabel').pack(side='left')
        self.time_var = tk.StringVar()
        ttk.Label(self.status_frame, textvariable=self.time_var, style='Status.TLabel').pack(side='right')
        self._update_time()

    def _build_transaction_ui(self):
        account_frame = ttk.LabelFrame(self.main_frame, text="💰 帳戶資訊", padding=20)
        account_frame.pack(fill='x', pady=(0, 20))
        self.balance_var = tk.StringVar(value="--")
        ttk.Label(account_frame, text="即時餘額:", font=('Arial', 14)).pack()
        ttk.Label(account_frame, textvariable=self.balance_var, style='Balance.TLabel').pack(pady=10)

        transaction_frame = ttk.LabelFrame(self.main_frame, text="🔧 交易操作", padding=20)
        transaction_frame.pack(fill='x', pady=(0, 20))
        btn_container = ttk.Frame(transaction_frame)
        btn_container.pack()
        
        buttons = [
            ("💰 存款", self._deposit),
            ("💸 取款", self._withdraw),
            ("🔄 轉賬", self._transfer),
            ("📊 查詢餘額", self._execute_query_balance)
        ]
        
        for i, (text, cmd) in enumerate(buttons):
            row = i // 2
            col = i % 2
            btn = ttk.Button(btn_container, text=text, command=cmd, 
                           style='Action.TButton', width=15)
            btn.grid(row=row, column=col, padx=10, pady=10)

        log_frame = ttk.LabelFrame(self.main_frame, text="📋 交易記錄", padding=10)
        log_frame.pack(fill='both', expand=True)
        log_scroll_frame = ttk.Frame(log_frame)
        log_scroll_frame.pack(fill='both', expand=True)
        self.log_text = tk.Text(log_scroll_frame, height=8, wrap='word', 
                               font=('Consolas', 9), state='disabled')
        log_scrollbar = ttk.Scrollbar(log_scroll_frame, orient='vertical', 
                                     command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        self.log_text.pack(side='left', fill='both', expand=True)
        log_scrollbar.pack(side='right', fill='y')

    def _start_handshake(self):
        self.connect_btn.configure(state='disabled', text="🔄 連線中...")
        self._update_status("🟡 正在建立量子安全通道...")
        threading.Thread(target=self._perform_handshake, daemon=True).start()

    def _perform_handshake(self):
        try:
            with self.lock:
                if self.retry_count >= self.max_retries:
                    raise ConnectionError("❌ 超過最大重試次數")

                if self.sock:
                    self.sock.close()
                self.sock = socket.create_connection(
                    (self.ip_entry.get(), 5000), 
                    timeout=10
                )
                
                self.ek, self.dk = ML_KEM_768.keygen()
                self.sock.sendall(len(self.ek).to_bytes(2, 'big') + self.ek)
                
                ct_len_bytes = self._recv_all(2)
                ct_len = int.from_bytes(ct_len_bytes, 'big')
                ct = self._recv_all(ct_len)
                
                if len(ct) != 1088:
                    raise ValueError(f"密文長度異常: 預期 1088 bytes, 實際 {len(ct)} bytes")
                
                self.session_key = ML_KEM_768.decaps(self.dk, ct)
                
                sig_pk_b64 = base64.b64encode(self.sig_pk).decode()
                self.sock.sendall(len(sig_pk_b64).to_bytes(2, 'big') + sig_pk_b64.encode())
                
                hkdf = HKDF(
                    algorithm=hashes.SHA384(),
                    length=32,
                    salt=None,
                    info=b'quantum-banking'
                )
                self.session_key = hkdf.derive(self.session_key)
                
                self.retry_count = 0
                self.root.after(0, self._on_connection_success)

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self._on_connection_failed(error_msg))

    def _encrypt_send(self, data):
        with self.lock:
            try:
                key = HKDF(
                    algorithm=hashes.SHA384(),
                    length=32,
                    salt=None,
                    info=b'quantum-banking'
                ).derive(self.session_key)
                
                nonce = get_random_bytes(12)
                signature = self.dilithium_class.sign(self.sig_sk, json.dumps(data).encode())
                signed_data = {
                    'data': data,
                    'sig': signature.hex(),
                    'params': (self.dilithium_class.k, self.dilithium_class.l)
                }
                
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(json.dumps(signed_data).encode())
                payload = nonce + tag + ciphertext
                self.sock.sendall(len(payload).to_bytes(4, 'big') + payload)
            except Exception as e:
                self._log(f"發送失敗: {str(e)}", "error")

    def _decrypt_receive(self):
        with self.lock:
            try:
                header = self._recv_all(4)
                if not header:
                    return None
                payload_len = int.from_bytes(header, 'big')
                payload = self._recv_all(payload_len)
                
                if len(payload) < 28:
                    raise ValueError(f"封包長度不足: {len(payload)} bytes")
                
                nonce = payload[:12]
                tag = payload[12:28]
                ciphertext = payload[28:]
                
                key = HKDF(
                    algorithm=hashes.SHA384(),
                    length=32,
                    salt=None,
                    info=b'quantum-banking'
                ).derive(self.session_key)
                
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                response = json.loads(plaintext.decode())
                
                if not isinstance(response, dict) or 'data' not in response:
                    raise ValueError("無效響應格式")
                return response['data']
                
            except json.JSONDecodeError as e:
                self._log(f"JSON解析失敗: {str(e)}", "error")
            except ValueError as e:
                self._log(f"解密失敗: {str(e)}", "error")
            except Exception as e:
                self._log(f"接收異常: {str(e)}", "critical")
            return None

    def _recv_all(self, length):
        data = bytearray()
        while len(data) < length:
            try:
                chunk = self.sock.recv(min(4096, length - len(data)))
                if not chunk:
                    raise ConnectionAbortedError("連線已中斷")
                data.extend(chunk)
            except ConnectionResetError:
                raise ConnectionAbortedError("連線被重置")
        return bytes(data)

    def _update_balance(self, response):
        try:
            if response is None:
                self.balance_var.set(f"{self.last_balance:,.2f} 元 (連線異常)")
                return
                
            required_keys = {'success', 'balance', 'message'}
            if not all(key in response for key in required_keys):
                missing = required_keys - response.keys()
                raise ValueError(f"缺少必要字段: {missing}")
            
            if not isinstance(response['success'], bool):
                raise TypeError("success 字段類型錯誤")
                
            balance = response['balance']
            if not isinstance(balance, (int, float)):
                raise TypeError("balance 字段類型錯誤")
                
            self.last_balance = balance
            formatted_balance = f"{balance:,.2f} 元"
            self.balance_var.set(formatted_balance)
            
            if response['success']:
                messagebox.showinfo("交易成功", 
                    f"{response['message']}\n最新餘額: {formatted_balance}")
            else:
                messagebox.showerror("交易失敗", 
                    f"{response['message']}\n當前餘額: {formatted_balance}")
            
            self.root.update_idletasks()
            
        except Exception as e:
            self.balance_var.set(f"{self.last_balance:,.2f} 元 (更新失敗)")
            self._log(f"餘額更新異常: {str(e)}", "error")
            messagebox.showerror("系統錯誤", "無法解析伺服器響應")

    def _execute_query_balance(self):
        try:
            if not self._check_connection():
                return
                
            start_time = time.time()
            self._encrypt_send({'type': 'balance', 'account': '1001'})
            response = self._decrypt_receive()
            
            if time.time() - start_time > 5:
                raise TimeoutError("伺服器響應超時")
                
            self._update_balance(response)
            
        except TimeoutError as e:
            self._log(f"❌ {str(e)}", "error")
            self.balance_var.set(f"{self.last_balance:,.2f} 元 (超時)")
        except Exception as e:
            self._log(f"❌ 查詢失敗: {str(e)}", "error")

    def _check_connection(self):
        if self.sock is None or self.sock.fileno() == -1:
            self._log("未建立有效連線", "error")
            messagebox.showerror("錯誤", "請先建立伺服器連線")
            return False
        return True

    def _log(self, message, level="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        level_prefix = {
            "info": "ℹ️",
            "success": "✅", 
            "warning": "⚠️",
            "error": "❌"
        }.get(level, "📝")
        log_entry = f"[{timestamp}] {level_prefix} {message}"
        
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, f"{log_entry}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')
        print(log_entry)

    def _update_status(self, status):
        self.status_var.set(status)

    def _update_time(self):
        self.time_var.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.root.after(1000, self._update_time)

    def _on_connection_success(self):
        self.connect_frame.pack_forget()
        self.main_frame.pack(fill='both', expand=True)
        self._update_status("🟢 已連線 - 量子安全通道已建立")
        self._execute_query_balance()

    def _on_connection_failed(self, error):
        self.connect_btn.configure(state='normal', text="🔐 建立量子安全連線")
        self._update_status("🔴 連線失敗")
        messagebox.showerror("連線失敗", f"錯誤原因：{error}")

    def _deposit(self):
        self._show_amount_dialog("存款", self._execute_deposit)

    def _withdraw(self):
        self._show_amount_dialog("取款", self._execute_withdraw)

    def _transfer(self):
        self._show_transfer_dialog()

    def _show_amount_dialog(self, action, callback):
        dialog = tk.Toplevel(self.root)
        dialog.title(action)
        ttk.Label(dialog, text="金額:").pack(side=tk.LEFT)
        amount_entry = ttk.Entry(dialog)
        amount_entry.pack(side=tk.LEFT)
        
        def on_confirm():
            try:
                amount = float(amount_entry.get())
                if amount <= 0:
                    raise ValueError("金額需大於零")
                dialog.destroy()
                callback(amount)
            except ValueError as e:
                messagebox.showerror("輸入錯誤", str(e))
        
        ttk.Button(dialog, text="確認", command=on_confirm).pack(side=tk.LEFT)

    def _show_transfer_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("轉賬")
        ttk.Label(dialog, text="目標帳號:").grid(row=0, column=0)
        target_entry = ttk.Entry(dialog)
        target_entry.grid(row=0, column=1)
        ttk.Label(dialog, text="金額:").grid(row=1, column=0)
        amount_entry = ttk.Entry(dialog)
        amount_entry.grid(row=1, column=1)
        
        def on_confirm():
            try:
                target = target_entry.get()
                if not target:
                    raise ValueError("目標帳號不能為空")
                amount = float(amount_entry.get())
                if amount <= 0:
                    raise ValueError("轉帳金額需大於零")
                dialog.destroy()
                self._execute_transfer(target, amount)
            except ValueError as e:
                messagebox.showerror("輸入錯誤", str(e))
        
        ttk.Button(dialog, text="確認", command=on_confirm).grid(row=2, columnspan=2)

    def _execute_deposit(self, amount):
        try:
            self._encrypt_send({'type': 'deposit', 'amount': amount, 'account': '1001'})
            response = self._decrypt_receive()
            self._update_balance(response)
            self._log(f"💰 存款成功: +{amount:.2f}元", "success")
        except Exception as e:
            self._log(f"❌ 存款失敗: {str(e)}", "error")

    def _execute_withdraw(self, amount):
        try:
            self._encrypt_send({'type': 'withdraw', 'amount': amount, 'account': '1001'})
            response = self._decrypt_receive()
            self._update_balance(response)
            self._log(f"💸 取款成功: -{amount:.2f}元", "success")
        except Exception as e:
            self._log(f"❌ 取款失敗: {str(e)}", "error")

    def _execute_transfer(self, target, amount):
        try:
            self._encrypt_send({
                'type': 'transfer',
                'target': target,
                'amount': amount,
                'account': '1001'
            })
            
            start_time = time.time()
            response = self._decrypt_receive()
            
            if time.time() - start_time > 5:
                raise TimeoutError("伺服器響應超時")
                
            self._update_balance(response)
            
            if response.get('success'):
                self._log(f"🔄 轉賬成功: 向{target}轉出{amount:.2f}元", "success")
            else:
                self._log(f"❌ 轉賬失敗: {response.get('message')}", "error")
                
        except ValueError as e:
            messagebox.showerror("輸入錯誤", str(e))
        except TimeoutError as e:
            self._log(f"❌ 轉帳超時: {str(e)}", "error")
            messagebox.showerror("錯誤", "交易逾時，請檢查網路連線")
        except Exception as e:
            self._log(f"❌ 轉帳異常: {str(e)}", "error")
            messagebox.showerror("錯誤", "交易處理發生未知錯誤")

if __name__ == "__main__":
    QuantumATMClient().root.mainloop()
