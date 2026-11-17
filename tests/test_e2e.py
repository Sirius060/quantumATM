"""端到端測試（真的開伺服器、走完整加密通道）。在專案根目錄執行：python -m unittest discover -v tests"""
import os
import socket
import tempfile
import threading
import time
import unittest

import wire
from atm_client import ATMSession, KnownServers, parse_amount_input, parse_server_input
from bank import Bank
from protocol import DEFAULT_PORT, ProtocolError, ServerIdentity, client_handshake
from server_mlkem import QuantumBankServer


def start_server(tmp, **kwargs):
    identity = ServerIdentity.load_or_create(os.path.join(tmp, "id.key"))
    srv = QuantumBankServer(("127.0.0.1", 0), identity, **kwargs)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class Tap:
    """包住 socket，記錄送出的原始封包；corrupt_next=True 時把下一個封包翻轉一個位元。"""

    def __init__(self, sock):
        self.sock, self.sent, self.corrupt_next = sock, [], False

    def sendall(self, data):
        if self.corrupt_next:
            data, self.corrupt_next = data[:-1] + bytes([data[-1] ^ 1]), False
        self.sent.append(data)
        self.sock.sendall(data)

    def __getattr__(self, name):
        return getattr(self.sock, name)


class E2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.srv = start_server(cls.tmp)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def login(self, acct="1001", pin="1234"):
        s = ATMSession()
        self.assertEqual(s.connect("127.0.0.1", self.port), self.srv.identity.pk)
        return s, s.request(wire.login(acct, pin))

    def tapped_channel(self, acct, pin):
        tap = Tap(socket.create_connection(("127.0.0.1", self.port), timeout=5))
        ch, _ = client_handshake(tap)
        ch.send(wire.login(acct, pin))
        self.assertTrue(ch.recv()["success"])
        return tap, ch

    def assert_server_hangs_up(self, tap):
        self.assertEqual(tap.recv(1), b"")
        tap.close()

    def test_basic_flow(self):
        s, r = self.login()
        self.assertTrue(r["success"])
        start = float(r["balance"])
        r = s.request(wire.deposit("100.10"))
        self.assertAlmostEqual(float(r["balance"]), start + 100.10, places=2)
        r = s.request(wire.withdraw("0.10"))
        self.assertAlmostEqual(float(r["balance"]), start + 100.00, places=2)
        r = s.request(wire.transfer("1002", "100"))
        self.assertTrue(r["success"])
        self.assertAlmostEqual(float(r["balance"]), start, places=2)
        self.assertTrue(s.request(wire.logout())["success"])
        self.assertFalse(s.request(wire.balance())["success"])
        s.close()

    def test_rejects_bad_requests(self):
        s, _ = self.login()
        for bad in ["-100", "0", "NaN", "Infinity", "1e400", "1e999999999", "1000000.01", "1.001", "abc", 1.5, True, None]:
            for make in (wire.deposit, wire.withdraw):
                self.assertFalse(s.request(make(bad))["success"], f"{make.__name__} {bad!r} should fail")
        self.assertFalse(s.request(wire.transfer("9999", "1"))["success"])
        self.assertFalse(s.request(wire.transfer("1001", "1"))["success"])
        for kind in ("nonsense", None, ["deposit"], {"a": 1}):  # 未知或型別錯誤的操作不能讓連線崩潰
            self.assertEqual(s.request({"type": kind})["message"], "無效操作類型")
        s.close()

    def test_requires_login(self):
        s = ATMSession()
        s.connect("127.0.0.1", self.port)
        self.assertFalse(s.request(wire.balance())["success"])
        self.assertFalse(s.request(wire.login("nope", "1"))["success"])
        s.close()

    def test_pin_lockout_and_expiry(self):
        bank = Bank(lockout_seconds=0.3)
        for _ in range(3):
            self.assertIsNone(bank.login("1001", "0000")[0])
        acct, result = bank.login("1001", "1234")  # 鎖定期間正確 PIN 也無法登入
        self.assertIsNone(acct)
        self.assertIn("鎖定", result.message)
        time.sleep(0.4)
        self.assertIsNotNone(bank.login("1001", "1234")[0])
        # 過長或空的 PIN 直接拒絕，不會消耗嘗試次數
        self.assertIsNone(bank.login("1002", "9" * 5000)[0])
        self.assertIsNone(bank.login("1002", "")[0])
        self.assertEqual(bank.accounts["1002"].failed_attempts, 0)

    def test_input_parsing(self):
        self.assertEqual(parse_amount_input("1,000.5"), "1000.50")
        for bad in ["-1", "0", "abc", "nan", "1e999999999", "1.001"]:
            with self.assertRaises(ValueError):
                parse_amount_input(bad)
        self.assertEqual(parse_server_input(" localhost "), ("localhost", DEFAULT_PORT))
        self.assertEqual(parse_server_input("192.168.1.5:6000"), ("192.168.1.5", 6000))
        self.assertEqual(parse_server_input("[::1]:6000"), ("::1", 6000))
        self.assertEqual(parse_server_input("::1"), ("::1", DEFAULT_PORT))
        for bad in ["", ":5000", "host:abc", "host:0", "host:70000"]:
            with self.assertRaises(ValueError):
                parse_server_input(bad)

    def test_tampered_frame_is_rejected(self):
        tap, ch = self.tapped_channel("1001", "1234")
        tap.corrupt_next = True
        ch.send(wire.balance())
        self.assert_server_hangs_up(tap)

    def test_replay_is_rejected(self):
        tap, ch = self.tapped_channel("1002", "5678")
        ch.send(wire.withdraw("1.00"))
        self.assertTrue(ch.recv()["success"])
        before = self.srv.bank.accounts["1002"].balance
        tap.sock.sendall(tap.sent[-1])  # 原封不動重送同一筆取款
        self.assert_server_hangs_up(tap)
        self.assertEqual(self.srv.bank.accounts["1002"].balance, before)

    def test_known_servers_detects_key_change(self):
        other = ServerIdentity.load_or_create(os.path.join(self.tmp, "other.key"))
        path = os.path.join(self.tmp, "known.json")
        known = KnownServers(path)
        self.assertEqual(known.check("bank", self.srv.identity.pk), "new")
        known.trust("bank", self.srv.identity.pk)
        known = KnownServers(path)  # 重新讀檔
        self.assertEqual(known.check("bank", self.srv.identity.pk), "match")
        self.assertEqual(known.check("bank", other.pk), "mismatch")

    def test_concurrent_transfers_conserve_money(self):
        def total():
            return sum(a.balance for a in self.srv.bank.accounts.values())
        before = total()

        def worker(src, pin, dst):
            s, _ = self.login(src, pin)
            for _ in range(20):
                s.request(wire.transfer(dst, "1.00"))
            s.close()
        threads = [threading.Thread(target=worker, args=a) for a in
                   [("1001", "1234", "1002"), ("1002", "5678", "1001")] * 2]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(total(), before)

    def test_corrupt_identity_file_is_reported(self):
        path = os.path.join(self.tmp, "broken.key")
        with open(path, "wb") as f:
            f.write(b"not a key")
        with self.assertRaises(ProtocolError):
            ServerIdentity.load_or_create(path)


class ServerLimitsTest(unittest.TestCase):
    """握手逾時與連線數上限。"""

    def setUp(self):
        self.srv = start_server(tempfile.mkdtemp(), max_connections=2, handshake_timeout=0.5)
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_silent_client_is_dropped(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        t0 = time.monotonic()
        self.assertEqual(sock.recv(1), b"")  # 沒送 HELLO → 伺服器主動斷線
        self.assertLess(time.monotonic() - t0, 3)
        sock.close()

    def test_connection_limit_and_slot_release(self):
        a, b, c = ATMSession(), ATMSession(), ATMSession()
        a.connect("127.0.0.1", self.port)
        b.connect("127.0.0.1", self.port)
        with self.assertRaises((OSError, ProtocolError)):
            c.connect("127.0.0.1", self.port)
        a.close()
        for _ in range(50):  # 等伺服器釋放名額
            try:
                c.connect("127.0.0.1", self.port)
                break
            except (OSError, ProtocolError):
                time.sleep(0.1)
        self.assertTrue(c.connected)
        self.assertTrue(c.request(wire.login("1001", "1234"))["success"])
        b.close()
        c.close()


if __name__ == "__main__":
    unittest.main()
