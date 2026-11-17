"""
quantumATM 客戶端（Tkinter GUI）

    python client_mlkem.py

連線流程：ML-KEM-768 握手 → 驗證伺服器 ML-DSA-65 簽章 → 比對已釘選的伺服器公鑰
（第一次連線會顯示指紋請使用者確認，之後存在 known_servers.json）→ 帳號 + PIN 登入。

這個檔案只負責畫面與互動；連線與輸入解析在 atm_client.py，訊息格式在 wire.py。
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from datetime import datetime
from decimal import Decimal, InvalidOperation
from tkinter import messagebox, ttk

import wire
from atm_client import KNOWN_SERVERS_FILE, ATMSession, KnownServers, parse_amount_input, parse_server_input


class QuantumATMClient:
    CONNECT_TEXT = "🔐 建立量子安全連線"

    def __init__(self, known_servers_path: str = KNOWN_SERVERS_FILE):
        self.session = ATMSession()
        self.known = KnownServers(known_servers_path)
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

        def finish(callback, value):
            # 先解除忙碌狀態再呼叫回呼，回呼裡才能接著啟動下一個背景工作
            # （例如握手完成後接著登入）。
            self._set_busy(False)
            callback(value)

        def runner():
            try:
                result = work()
            except Exception as e:  # noqa: BLE001
                self._ui_queue.put(lambda e=e: finish(on_error or self._on_request_error, e))
            else:
                self._ui_queue.put(lambda: finish(on_done, result))

        threading.Thread(target=runner, daemon=True).start()

    def _poll_ui_queue(self):
        try:
            while True:
                callback = self._ui_queue.get_nowait()
                try:
                    callback()
                except Exception as e:  # noqa: BLE001 — 單一回呼出錯不能讓輪詢停掉
                    self._set_busy(False)
                    self._log(f"介面更新錯誤：{e}", "error")
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

        title = self.title_frame = ttk.Frame(main)
        title.pack(fill="x", pady=(0, 20))
        ttk.Label(title, text="🛡️ 量子安全ATM系統", style="Title.TLabel").pack()
        ttk.Label(title, text="ML-KEM-768 · ML-DSA-65 · AES-256-GCM",
                  font=("Arial", 10), foreground="#95a5a6").pack()

        # 連線 + 登入
        self.connect_frame = ttk.LabelFrame(main, text="🔗 連線與登入", padding=15)
        self.connect_frame.pack(fill="x", pady=(0, 20))
        grid = ttk.Frame(self.connect_frame)
        grid.pack()
        fields = [("伺服器:", "localhost", ""), ("帳號:", "1001", ""), ("PIN:", "", "•")]
        self.ip_entry, self.acct_entry, self.pin_entry = (
            self._labeled_entry(grid, r, label, default, show)
            for r, (label, default, show) in enumerate(fields)
        )
        self.pin_entry.bind("<Return>", lambda _e: self._start_connect())
        self.connect_btn = ttk.Button(grid, text=self.CONNECT_TEXT,
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
            ("💰 存款", lambda: self._amount_dialog("💰 存款", wire.deposit)),
            ("💸 取款", lambda: self._amount_dialog("💸 取款", wire.withdraw)),
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
        if self.busy:
            return
        acct = self.acct_entry.get().strip()
        pin = self.pin_entry.get()
        try:
            host, port = parse_server_input(self.ip_entry.get())
            if not acct or not pin:
                raise ValueError("請輸入帳號與 PIN")
        except ValueError as err:
            messagebox.showerror("輸入錯誤", str(err))
            return
        self.connect_btn.configure(text="🔄 連線中...")
        self._update_status("🟡 正在建立量子安全通道...")
        server_id = f"{host}:{port}"

        def done(pk):
            verdict = self.known.check(server_id, pk)
            if verdict == "mismatch":
                self.session.close()
                self._connect_failed(
                    "⚠️ 伺服器公鑰與先前記錄不符，可能遭中間人攻擊！\n"
                    f"指紋：{self.session.fingerprint}\n若伺服器確實更換金鑰，請刪除 {self.known.path} 中的對應項目。")
                return
            if verdict == "new":
                ok = messagebox.askyesno(
                    "首次連線",
                    f"第一次連線到 {server_id}\n伺服器公鑰指紋：\n{self.session.fingerprint}\n\n"
                    "請與伺服器啟動時顯示的指紋比對，確認後是否信任？")
                if not ok:
                    self.session.close()
                    self._connect_failed("使用者拒絕信任伺服器")
                    return
                self.known.trust(server_id, pk)
            self._login(acct, pin)

        self._run_bg(lambda: self.session.connect(host, port), done,
                     lambda e: self._connect_failed(str(e)))

    def _login(self, acct, pin):
        def done(resp):
            if not resp["success"]:
                self.session.close()
                self._connect_failed(resp["message"])
                return
            self.account_no = acct
            self.pin_entry.delete(0, "end")
            self.connect_btn.configure(text=self.CONNECT_TEXT)
            self.connect_frame.pack_forget()
            self.main_frame.pack(fill="both", expand=True)
            self.account_var.set(f"帳號 {acct}")
            self._update_status("🟢 已連線 - 量子安全通道已建立")
            self._log(f"登入成功（伺服器 {self.session.fingerprint[:19]}…）", "success")
            self._show_balance(resp)

        self._run_bg(lambda: self.session.request(wire.login(acct, pin)), done,
                     lambda e: self._connect_failed(str(e)))

    def _connect_failed(self, error):
        self.connect_btn.configure(text=self.CONNECT_TEXT)
        self._update_status("🔴 連線失敗")
        messagebox.showerror("連線失敗", f"錯誤原因：{error}")

    def _show_login_screen(self, status):
        """回到連線／登入畫面（登出或連線中斷時）。"""
        self.session.close()
        self.account_no = ""
        self.main_frame.pack_forget()
        self.connect_frame.pack(fill="x", pady=(0, 20), after=self.title_frame)
        self.connect_btn.configure(text=self.CONNECT_TEXT)
        self.account_var.set("")
        self.balance_var.set("--")
        self._update_status(status)

    def _logout(self):
        def finish(_=None):
            self._show_login_screen("🔴 已登出")

        self._run_bg(lambda: self.session.request(wire.logout()), finish, finish)

    # ---------------- transactions
    def _send_tx(self, payload, desc, notify=True):
        """送出交易；notify=False 時成功不跳視窗（只更新餘額與記錄）。"""
        def done(resp):
            self._show_balance(resp)
            if resp["success"]:
                self._log(f"{desc}：{resp['message']}", "success")
                if notify:
                    messagebox.showinfo("交易成功", f"{resp['message']}\n最新餘額：{self.balance_var.get()}")
            else:
                self._log(f"{desc}失敗：{resp['message']}", "error")
                messagebox.showerror("交易失敗", resp["message"])

        self._run_bg(lambda: self.session.request(payload), done)

    def _query_balance(self):
        self._send_tx(wire.balance(), "📊 查詢餘額", notify=False)

    def _show_balance(self, resp):
        if "balance" in resp:
            try:
                self.balance_var.set(f"{Decimal(resp['balance']):,.2f} 元")
            except (InvalidOperation, TypeError):
                self._log("伺服器回傳的餘額格式錯誤", "error")

    def _on_request_error(self, e):
        self._log(f"通訊錯誤：{e}", "error")
        if not self.session.connected:
            self._show_login_screen("🔴 連線中斷 - 請重新登入")
            messagebox.showerror("連線中斷", f"{e}\n\n安全通道已關閉，請重新登入。")

    def _dialog(self, title, fields, on_ok):
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.resizable(False, False)
        frm = ttk.Frame(dlg, padding=15)
        frm.pack()
        entries = []
        for r, label in enumerate(fields):
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="e", padx=5, pady=5)
            e = ttk.Entry(frm, width=20)
            e.grid(row=r, column=1, pady=5)
            entries.append(e)
        dlg.wait_visibility()  # 視窗顯示後才能 grab，否則部分平台會報錯
        dlg.grab_set()
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

    def _amount_dialog(self, label, make_request):
        """label 形如 "💰 存款"：去掉圖示的部分當對話框標題，完整字串寫進交易記錄。"""
        def ok(amount_text):
            self._send_tx(make_request(parse_amount_input(amount_text)), label)

        self._dialog(label.split()[-1], ["金額:"], ok)

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
            self._send_tx(wire.transfer(target, amount), "🔄 轉帳")

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


def create_app(known_servers_path: str = KNOWN_SERVERS_FILE) -> QuantumATMClient:
    """建立 GUI 但不進入主迴圈（測試可以直接操作回傳的物件）。"""
    return QuantumATMClient(known_servers_path)


def run_gui() -> None:
    create_app().root.mainloop()


if __name__ == "__main__":
    run_gui()
