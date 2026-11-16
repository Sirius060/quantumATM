"""
quantumATM 客戶端（Tkinter GUI）

    python client_mlkem.py

連線流程：ML-KEM-768 握手 → 驗證伺服器 ML-DSA-65 簽章 → 比對已釘選的伺服器公鑰
（第一次連線會顯示指紋請使用者確認，之後存在 known_servers.json）→ 帳號 + PIN 登入。
"""

from __future__ import annotations

import json
import queue
import socket
import threading
from datetime import datetime
from decimal import Decimal, InvalidOperation

from protocol import DEFAULT_PORT, ProtocolError, SecureChannel, client_handshake, fingerprint

KNOWN_SERVERS_FILE = "known_servers.json"
NET_TIMEOUT = 10  # 秒
MAX_TX_AMOUNT = Decimal("1000000")


# ================================================================ 非 GUI 核心
class KnownServers:
    """TOFU（Trust On First Use）伺服器公鑰釘選，概念同 SSH known_hosts。"""

    def __init__(self, path: str = KNOWN_SERVERS_FILE):
        self.path = path
        try:
            with open(path, encoding="utf-8") as f:
                self._data = json.load(f)
        except (FileNotFoundError, ValueError):
            self._data = {}

    def check(self, server: str, pk: bytes) -> str:
        known = self._data.get(server)
        if known is None:
            return "new"
        return "match" if known == pk.hex() else "mismatch"

    def trust(self, server: str, pk: bytes) -> None:
        self._data[server] = pk.hex()
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)


class ATMSession:
    """純網路/協定邏輯，與 GUI 分離，方便測試與重用。"""

    def __init__(self):
        self.channel: SecureChannel | None = None
        self.server_pk: bytes | None = None
        self._lock = threading.Lock()

    @property
    def connected(self) -> bool:
        return self.channel is not None

    def connect(self, host: str, port: int = DEFAULT_PORT) -> bytes:
        self.close()
        sock = socket.create_connection((host, port), timeout=NET_TIMEOUT)
        try:
            self.channel, self.server_pk = client_handshake(sock)
        except Exception:
            sock.close()
            raise
        return self.server_pk

    def request(self, payload: dict) -> dict:
        with self._lock:
            if self.channel is None:
                raise ConnectionError("尚未連線")
            try:
                self.channel.send(payload)
                resp = self.channel.recv()
            except (OSError, ProtocolError):
                self.close()  # 通道狀態已不可信，必須重新握手
                raise
        if not isinstance(resp.get("success"), bool) or not isinstance(resp.get("message"), str):
            raise ProtocolError("伺服器回應格式錯誤")
        return resp

    def close(self) -> None:
        if self.channel is not None:
            self.channel.close()
            self.channel = None


def parse_amount_input(text: str) -> str:
    try:
        amount = Decimal(text.strip().replace(",", ""))
    except InvalidOperation:
        raise ValueError("請輸入有效數字") from None
    if not amount.is_finite() or amount <= 0:
        raise ValueError("金額需大於零")
    if amount > MAX_TX_AMOUNT:
        raise ValueError(f"單筆金額上限為 {MAX_TX_AMOUNT:,} 元")
    if amount != amount.quantize(Decimal("0.01")):
        raise ValueError("金額最多到小數點後兩位")
    return f"{amount:.2f}"  # 以字串傳輸，避免浮點誤差


# ================================================================ GUI
def run_gui() -> None:
    import tkinter as tk
    from tkinter import messagebox, ttk

    class QuantumATMClient:
        def __init__(self):
            self.session = ATMSession()
            self.known = KnownServers()
            self.account_no = ""
            self.busy = False
            self._ui_queue: "queue.Queue" = queue.Queue()

            self.root = tk.Tk()
            self.root.title("🛡️ 量子安全ATM系統")
            self.root.geometry("600x720")
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)
            self._setup_styles()
            self._setup_interface()
            self._poll_ui_queue()

        # ---------------- threading helpers
        def _run_bg(self, work, on_done, on_error=None):
            """在背景執行網路工作，結果丟回主執行緒，避免 GUI 凍結。"""
            if self.busy:
                return
            self._set_busy(True)

            def runner():
                try:
                    result = work()
                    self._ui_queue.put(lambda: on_done(result))
                except Exception as e:  # noqa: BLE001
                    self._ui_queue.put(lambda e=e: (on_error or self._on_request_error)(e))
                finally:
                    self._ui_queue.put(lambda: self._set_busy(False))

            threading.Thread(target=runner, daemon=True).start()

        def _poll_ui_queue(self):
            try:
                while True:
                    self._ui_queue.get_nowait()()
            except queue.Empty:
                pass
            self.root.after(50, self._poll_ui_queue)

        def _set_busy(self, busy: bool):
            self.busy = busy
            state = "disabled" if busy else "normal"
            for btn in self.action_buttons:
                btn.configure(state=state)
            self.root.configure(cursor="watch" if busy else "")

        # ---------------- layout
        def _setup_styles(self):
            style = ttk.Style()
            style.theme_use("clam")
            style.configure("Title.TLabel", font=("Arial", 20, "bold"), foreground="#2c3e50")
            style.configure("Balance.TLabel", font=("Arial", 24, "bold"), foreground="#27ae60")
            style.configure("Status.TLabel", font=("Arial", 10), foreground="#7f8c8d")
            style.configure("Action.TButton", font=("Arial", 12, "bold"), padding=10)

        def _setup_interface(self):
            main = ttk.Frame(self.root)
            main.pack(fill="both", expand=True, padx=20, pady=20)

            title = ttk.Frame(main)
            title.pack(fill="x", pady=(0, 20))
            ttk.Label(title, text="🛡️ 量子安全ATM系統", style="Title.TLabel").pack()
            ttk.Label(title, text="ML-KEM-768 · ML-DSA-65 · AES-256-GCM",
                      font=("Arial", 10), foreground="#95a5a6").pack()

            # 連線 + 登入
            self.connect_frame = ttk.LabelFrame(main, text="🔗 連線與登入", padding=15)
            self.connect_frame.pack(fill="x", pady=(0, 20))
            grid = ttk.Frame(self.connect_frame)
            grid.pack()
            fields = [("伺服器IP:", "localhost", ""), ("帳號:", "1001", ""), ("PIN:", "", "•")]
            self.ip_entry, self.acct_entry, self.pin_entry = (
                self._labeled_entry(grid, r, label, default, show)
                for r, (label, default, show) in enumerate(fields)
            )
            self.pin_entry.bind("<Return>", lambda _e: self._start_connect())
            self.connect_btn = ttk.Button(grid, text="🔐 建立量子安全連線",
                                          command=self._start_connect, style="Action.TButton")
            self.connect_btn.grid(row=3, column=0, columnspan=2, pady=(10, 0))

            # 交易畫面
            self.main_frame = ttk.Frame(main)
            self._build_transaction_ui()
            self.action_buttons.append(self.connect_btn)

            # 狀態列
            status = ttk.Frame(main)
            status.pack(fill="x", side="bottom", pady=(20, 0))
            ttk.Separator(status, orient="horizontal").pack(fill="x", pady=(0, 5))
            self.status_var = tk.StringVar(value="🔴 未連線 - 等待建立量子安全通道")
            ttk.Label(status, textvariable=self.status_var, style="Status.TLabel").pack(side="left")
            self.time_var = tk.StringVar()
            ttk.Label(status, textvariable=self.time_var, style="Status.TLabel").pack(side="right")
            self._update_time()

        @staticmethod
        def _labeled_entry(parent, row, label, default, show):
            ttk.Label(parent, text=label, font=("Arial", 11)).grid(
                row=row, column=0, sticky="e", padx=(0, 10), pady=3)
            entry = ttk.Entry(parent, width=22, font=("Arial", 11), show=show)
            entry.insert(0, default)
            entry.grid(row=row, column=1, pady=3)
            return entry

        def _build_transaction_ui(self):
            acct_frame = ttk.LabelFrame(self.main_frame, text="💰 帳戶資訊", padding=20)
            acct_frame.pack(fill="x", pady=(0, 20))
            self.account_var = tk.StringVar(value="")
            ttk.Label(acct_frame, textvariable=self.account_var, font=("Arial", 12)).pack()
            self.balance_var = tk.StringVar(value="--")
            ttk.Label(acct_frame, textvariable=self.balance_var, style="Balance.TLabel").pack(pady=10)

            tx_frame = ttk.LabelFrame(self.main_frame, text="🔧 交易操作", padding=20)
            tx_frame.pack(fill="x", pady=(0, 20))
            box = ttk.Frame(tx_frame)
            box.pack()
            buttons = [
                ("💰 存款", lambda: self._amount_dialog("存款", "deposit")),
                ("💸 取款", lambda: self._amount_dialog("取款", "withdraw")),
                ("🔄 轉帳", self._transfer_dialog),
                ("📊 查詢餘額", self._query_balance),
                ("🚪 登出", self._logout),
            ]
            self.action_buttons = []
            for i, (text, cmd) in enumerate(buttons):
                btn = ttk.Button(box, text=text, command=cmd, style="Action.TButton", width=15)
                btn.grid(row=i // 2, column=i % 2, padx=10, pady=10)
                self.action_buttons.append(btn)

            log_frame = ttk.LabelFrame(self.main_frame, text="📋 交易記錄", padding=10)
            log_frame.pack(fill="both", expand=True)
            self.log_text = tk.Text(log_frame, height=8, wrap="word",
                                    font=("Consolas", 9), state="disabled")
            sb = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
            self.log_text.configure(yscrollcommand=sb.set)
            self.log_text.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")

        # ---------------- connect / login
        def _start_connect(self):
            host = self.ip_entry.get().strip()
            acct = self.acct_entry.get().strip()
            pin = self.pin_entry.get()
            if not host or not acct or not pin:
                messagebox.showerror("輸入錯誤", "請輸入伺服器、帳號與 PIN")
                return
            self.connect_btn.configure(text="🔄 連線中...")
            self._update_status("🟡 正在建立量子安全通道...")
            server_id = f"{host}:{DEFAULT_PORT}"

            def done(pk):
                verdict = self.known.check(server_id, pk)
                if verdict == "mismatch":
                    self.session.close()
                    self._connect_failed(
                        "⚠️ 伺服器公鑰與先前記錄不符，可能遭中間人攻擊！\n"
                        f"指紋：{fingerprint(pk)}\n若伺服器確實更換金鑰，請刪除 {KNOWN_SERVERS_FILE} 中的對應項目。")
                    return
                if verdict == "new":
                    ok = messagebox.askyesno(
                        "首次連線",
                        f"第一次連線到 {server_id}\n伺服器公鑰指紋：\n{fingerprint(pk)}\n\n"
                        "請與伺服器啟動時顯示的指紋比對，確認後是否信任？")
                    if not ok:
                        self.session.close()
                        self._connect_failed("使用者拒絕信任伺服器")
                        return
                    self.known.trust(server_id, pk)
                self._login(acct, pin)

            self._run_bg(lambda: self.session.connect(host), done,
                         lambda e: self._connect_failed(str(e)))

        def _login(self, acct, pin):
            def done(resp):
                if not resp["success"]:
                    self.session.close()
                    self._connect_failed(resp["message"])
                    return
                self.account_no = acct
                self.pin_entry.delete(0, "end")
                self.connect_frame.pack_forget()
                self.main_frame.pack(fill="both", expand=True)
                self.account_var.set(f"帳號 {acct}")
                self._update_status("🟢 已連線 - 量子安全通道已建立")
                self._log(f"登入成功（伺服器 {fingerprint(self.session.server_pk)[:19]}…）", "success")
                self._show_balance(resp)

            self._run_bg(lambda: self.session.request(
                {"type": "login", "account": acct, "pin": pin}), done,
                lambda e: self._connect_failed(str(e)))

        def _connect_failed(self, error):
            self.connect_btn.configure(text="🔐 建立量子安全連線")
            self._update_status("🔴 連線失敗")
            messagebox.showerror("連線失敗", f"錯誤原因：{error}")

        def _logout(self):
            def finish(_=None):
                self.session.close()
                self.main_frame.pack_forget()
                self.connect_frame.pack(fill="x", pady=(0, 20), before=self.main_frame)
                self.connect_btn.configure(text="🔐 建立量子安全連線")
                self.balance_var.set("--")
                self._update_status("🔴 已登出")

            self._run_bg(lambda: self.session.request({"type": "logout"}), finish, finish)

        # ---------------- transactions
        def _send_tx(self, payload, desc):
            def done(resp):
                self._show_balance(resp)
                if resp["success"]:
                    self._log(f"{desc}：{resp['message']}", "success")
                    if payload["type"] != "balance":
                        messagebox.showinfo("交易成功", f"{resp['message']}\n最新餘額：{self.balance_var.get()}")
                else:
                    self._log(f"{desc}失敗：{resp['message']}", "error")
                    messagebox.showerror("交易失敗", resp["message"])

            self._run_bg(lambda: self.session.request(payload), done)

        def _query_balance(self):
            self._send_tx({"type": "balance"}, "📊 查詢餘額")

        def _show_balance(self, resp):
            if "balance" in resp:
                try:
                    self.balance_var.set(f"{Decimal(resp['balance']):,.2f} 元")
                except (InvalidOperation, TypeError):
                    self._log("伺服器回傳的餘額格式錯誤", "error")

        def _on_request_error(self, e):
            self._log(f"通訊錯誤：{e}", "error")
            if not self.session.connected:
                self._update_status("🔴 連線中斷 - 請重新登入")
                messagebox.showerror("連線中斷", f"{e}\n\n安全通道已關閉，請重新登入。")
                self.main_frame.pack_forget()
                self.connect_frame.pack(fill="x", pady=(0, 20), before=self.main_frame)
                self.connect_btn.configure(text="🔐 建立量子安全連線")

        def _dialog(self, title, fields, on_ok):
            dlg = tk.Toplevel(self.root)
            dlg.title(title)
            dlg.transient(self.root)
            dlg.grab_set()
            dlg.resizable(False, False)
            frm = ttk.Frame(dlg, padding=15)
            frm.pack()
            entries = []
            for r, label in enumerate(fields):
                ttk.Label(frm, text=label).grid(row=r, column=0, sticky="e", padx=5, pady=5)
                e = ttk.Entry(frm, width=20)
                e.grid(row=r, column=1, pady=5)
                entries.append(e)
            entries[0].focus_set()

            def confirm(_e=None):
                try:
                    on_ok(*[e.get() for e in entries])
                except ValueError as err:
                    messagebox.showerror("輸入錯誤", str(err), parent=dlg)
                    return
                dlg.destroy()

            ttk.Button(frm, text="確認", command=confirm).grid(row=len(fields), columnspan=2, pady=(10, 0))
            dlg.bind("<Return>", confirm)
            dlg.bind("<Escape>", lambda _e: dlg.destroy())

        def _amount_dialog(self, title, tx_type):
            icon = "💰" if tx_type == "deposit" else "💸"

            def ok(amount_text):
                amount = parse_amount_input(amount_text)
                self._send_tx({"type": tx_type, "amount": amount}, f"{icon} {title}")

            self._dialog(title, ["金額:"], ok)

        def _transfer_dialog(self):
            def ok(target, amount_text):
                target = target.strip()
                if not target:
                    raise ValueError("目標帳號不能為空")
                if target == self.account_no:
                    raise ValueError("不可轉帳給自己")
                amount = parse_amount_input(amount_text)
                if not messagebox.askyesno("確認轉帳", f"轉帳 {Decimal(amount):,.2f} 元至 {target}？"):
                    return
                self._send_tx({"type": "transfer", "target": target, "amount": amount}, "🔄 轉帳")

            self._dialog("轉帳", ["目標帳號:", "金額:"], ok)

        # ---------------- misc
        def _log(self, message, level="info"):
            prefix = {"info": "ℹ️", "success": "✅", "warning": "⚠️", "error": "❌"}.get(level, "📝")
            entry = f"[{datetime.now():%H:%M:%S}] {prefix} {message}"
            self.log_text.configure(state="normal")
            self.log_text.insert(tk.END, entry + "\n")
            self.log_text.see(tk.END)
            self.log_text.configure(state="disabled")

        def _update_status(self, status):
            self.status_var.set(status)

        def _update_time(self):
            self.time_var.set(f"{datetime.now():%Y-%m-%d %H:%M:%S}")
            self.root.after(1000, self._update_time)

        def _on_close(self):
            self.session.close()
            self.root.destroy()

    QuantumATMClient().root.mainloop()


if __name__ == "__main__":
    run_gui()
