"""GUI 流程測試：用真正的 Tkinter 視窗操作客戶端，對接一台測試伺服器。

沒有 Tkinter 或沒有顯示器（例如無桌面的 Linux）時會自動略過；
在那種環境可以用 `xvfb-run python -m unittest discover tests` 執行。
"""
import gc
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
    _probe = tk.Tk()
    _probe.destroy()
    HAVE_TK = True
except Exception:  # noqa: BLE001 — 沒有 tkinter 或沒有顯示器
    HAVE_TK = False

from client_mlkem import create_app  # noqa: E402
from protocol import ServerIdentity  # noqa: E402
from server_mlkem import QuantumBankServer  # noqa: E402


@unittest.skipUnless(HAVE_TK, "需要 Tkinter 與顯示器")
class GuiFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.srv = self._start_server("id.key")
        self.known_path = os.path.join(self.tmp, "known.json")

        # 訊息視窗是 modal 的，測試時換成記錄用的替身
        self.dialogs = []
        self.answer_yes = True
        self._saved = {n: getattr(messagebox, n) for n in ("askyesno", "showinfo", "showerror")}
        messagebox.askyesno = lambda title, msg, **k: (self.dialogs.append(("ask", title, msg)), self.answer_yes)[1]
        messagebox.showinfo = lambda title, msg, **k: self.dialogs.append(("info", title, msg))
        messagebox.showerror = lambda title, msg, **k: self.dialogs.append(("error", title, msg))

        self.app = create_app(self.known_path)

    def tearDown(self):
        self.app.session.close()
        try:
            self.app.root.destroy()
        except tk.TclError:
            pass
        for name, fn in self._saved.items():
            setattr(messagebox, name, fn)
        self.srv.shutdown()
        self.srv.server_close()
        # Tk 物件必須在主執行緒回收；若留給之後某個背景執行緒觸發的 GC，Tcl 會直接中止程式
        del self.app
        gc.collect()

    # ---------------------------------------------------------------- helpers
    def _start_server(self, key_name, port=0):
        identity = ServerIdentity.load_or_create(os.path.join(self.tmp, key_name))
        srv = QuantumBankServer(("127.0.0.1", port), identity)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def pump(self, until, timeout=15, what="條件"):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.app.root.update()
            if until():
                return
            time.sleep(0.01)
        self.fail(f"等不到：{what}；dialogs={self.dialogs}")

    def idle(self):
        self.pump(lambda: not self.app.busy, what="背景工作結束")

    def login(self, pin="1234", acct="1001"):
        app = self.app
        port = self.srv.server_address[1]
        for entry, value in ((app.ip_entry, f"127.0.0.1:{port}"), (app.acct_entry, acct), (app.pin_entry, pin)):
            entry.delete(0, "end")
            entry.insert(0, value)
        n = len(self.dialogs)
        app.connect_btn.invoke()
        # 成功 → 進入交易畫面；失敗 → 跳出錯誤視窗
        self.pump(lambda: not app.busy and (app.main_frame.winfo_ismapped()
                                            or any(d[0] == "error" for d in self.dialogs[n:])),
                  what="登入結果")

    def fill_dialog(self, *values):
        """填寫剛開啟的輸入對話框並按「確認」。"""
        dlg = next(w for w in self.app.root.winfo_children() if isinstance(w, tk.Toplevel))
        widgets = []

        def walk(w):
            widgets.append(w)
            for c in w.winfo_children():
                walk(c)
        walk(dlg)
        entries = [w for w in widgets if isinstance(w, ttk.Entry)]
        for entry, value in zip(entries, values):
            entry.insert(0, value)
        next(w for w in widgets if isinstance(w, ttk.Button)).invoke()
        return dlg

    def button(self, text):
        return next(b for b in self.app.action_buttons if text in str(b.cget("text")))

    # ---------------------------------------------------------------- tests
    def test_first_connect_trust_then_login_and_transactions(self):
        app = self.app
        self.login()
        self.assertEqual([d[:2] for d in self.dialogs], [("ask", "首次連線")])
        self.assertTrue(app.main_frame.winfo_ismapped())
        self.assertFalse(app.connect_frame.winfo_ismapped())
        self.assertEqual(app.balance_var.get(), "100,000.00 元")
        self.assertEqual(app.pin_entry.get(), "")  # PIN 不留在畫面上
        self.assertTrue(os.path.exists(self.known_path))

        # 存款
        self.button("存款").invoke()
        self.fill_dialog("250.50")
        self.idle()
        self.assertEqual(app.balance_var.get(), "100,250.50 元")
        self.assertEqual(self.dialogs[-1][:2], ("info", "交易成功"))

        # 取款超過餘額 → 失敗訊息、餘額不變
        self.button("取款").invoke()
        self.fill_dialog("999999")
        self.idle()
        self.assertEqual(self.dialogs[-1][:2], ("error", "交易失敗"))
        self.assertEqual(app.balance_var.get(), "100,250.50 元")

        # 輸入非法金額 → 對話框留著、不送出
        self.button("取款").invoke()
        dlg = self.fill_dialog("-5")
        self.assertEqual(self.dialogs[-1][:2], ("error", "輸入錯誤"))
        self.assertTrue(dlg.winfo_exists())
        dlg.destroy()

        # 轉帳（含確認視窗）
        self.button("轉帳").invoke()
        self.fill_dialog("1002", "250.50")
        self.idle()
        self.assertEqual(app.balance_var.get(), "100,000.00 元")
        self.assertEqual(self.srv.bank.accounts["1002"].balance, 50250.50)

        # 交易記錄：成功與失敗都要如實記錄
        log_text = app.log_text.get("1.0", "end")
        self.assertIn("成功存入", log_text)
        self.assertIn("取款失敗：餘額不足", log_text)

    def test_wrong_pin_then_retry(self):
        self.login(pin="0000")
        self.assertEqual(self.dialogs[-1][:2], ("error", "連線失敗"))
        self.assertIn("PIN 錯誤", self.dialogs[-1][2])
        self.assertFalse(self.app.main_frame.winfo_ismapped())
        self.assertIn("建立量子安全連線", self.app.connect_btn.cget("text"))
        self.login(pin="1234")
        self.assertTrue(self.app.main_frame.winfo_ismapped())

    def test_logout_and_login_again(self):
        app = self.app
        self.login()
        self.button("登出").invoke()
        self.pump(lambda: not app.busy and app.connect_frame.winfo_ismapped(), what="回到登入畫面")
        self.assertFalse(app.main_frame.winfo_ismapped())
        self.assertFalse(app.session.connected)
        self.login(acct="1002", pin="5678")
        self.assertEqual(app.balance_var.get(), "50,000.00 元")
        self.assertEqual(len([d for d in self.dialogs if d[0] == "ask"]), 1)  # 第二次不再詢問指紋

    def test_declining_fingerprint_does_not_send_pin(self):
        self.answer_yes = False
        self.login()
        self.assertFalse(self.app.main_frame.winfo_ismapped())
        self.assertFalse(os.path.exists(self.known_path))
        self.assertEqual(self.srv.bank.accounts["1001"].failed_attempts, 0)
        self.assertFalse(self.app.session.connected)

    def test_changed_server_key_is_refused(self):
        self.login()
        port = self.srv.server_address[1]
        self.button("登出").invoke()
        self.pump(lambda: not self.app.busy and self.app.connect_frame.winfo_ismapped(), what="登出")
        # 同一個位址換成另一把身分金鑰的伺服器（模擬中間人）
        self.srv.shutdown()
        self.srv.server_close()
        self.srv = self._start_server("other.key", port)
        self.login()
        self.assertFalse(self.app.main_frame.winfo_ismapped())
        self.assertIn("公鑰與先前記錄不符", self.dialogs[-1][2])

    def test_server_drop_returns_to_login_screen(self):
        app = self.app
        self.login()
        app.session.channel.sock.close()  # 模擬連線中斷
        self.button("查詢餘額").invoke()
        self.pump(lambda: not app.busy and app.connect_frame.winfo_ismapped(), what="回到登入畫面")
        self.assertEqual(self.dialogs[-1][:2], ("error", "連線中斷"))
        self.login()
        self.assertTrue(app.main_frame.winfo_ismapped())


if __name__ == "__main__":
    unittest.main()
