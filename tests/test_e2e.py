"""端到端測試：python -m unittest discover tests"""
import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client_mlkem import ATMSession, KnownServers  # noqa: E402
from protocol import ServerIdentity, client_handshake, recv_frame, send_frame  # noqa: E402
from server_mlkem import QuantumBankServer  # noqa: E402


class E2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.identity = ServerIdentity.load_or_create(os.path.join(cls.tmp, "id.key"))
        cls.srv = QuantumBankServer(("127.0.0.1", 0), cls.identity)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def login(self, acct="1001", pin="1234"):
        s = ATMSession()
        pk = s.connect("127.0.0.1", self.port)
        self.assertEqual(pk, self.identity.pk)
        r = s.request({"type": "login", "account": acct, "pin": pin})
        return s, r

    def test_basic_flow(self):
        s, r = self.login()
        self.assertTrue(r["success"])
        start = float(r["balance"])
        r = s.request({"type": "deposit", "amount": "100.10"})
        self.assertAlmostEqual(float(r["balance"]), start + 100.10, places=2)
        r = s.request({"type": "withdraw", "amount": "0.10"})
        self.assertAlmostEqual(float(r["balance"]), start + 100.00, places=2)
        r = s.request({"type": "transfer", "target": "1002", "amount": "100"})
        self.assertTrue(r["success"])
        self.assertAlmostEqual(float(r["balance"]), start, places=2)
        s.close()

    def test_rejects_bad_amounts(self):
        s, _ = self.login()
        for bad in ["-100", "0", "NaN", "Infinity", "1e400", "1e999999999", "1000000.01", "1.001", "abc", 1.5, True, None]:
            for t in ("deposit", "withdraw"):
                r = s.request({"type": t, "amount": bad})
                self.assertFalse(r["success"], f"{t} {bad!r} should fail")
        r = s.request({"type": "transfer", "target": "9999", "amount": "1"})
        self.assertFalse(r["success"])
        r = s.request({"type": "transfer", "target": "1001", "amount": "1"})
        self.assertFalse(r["success"])
        s.close()

    def test_requires_login_and_pin_lockout(self):
        s = ATMSession()
        s.connect("127.0.0.1", self.port)
        self.assertFalse(s.request({"type": "balance"})["success"])
        self.assertFalse(s.request({"type": "login", "account": "nope", "pin": "1"})["success"])
        s.close()
        from server_mlkem import Bank
        bank = Bank()
        for _ in range(3):
            self.assertIsNone(bank.login("1001", "0000")[0])
        acct, resp = bank.login("1001", "1234")  # 正確 PIN 也無法登入
        self.assertIsNone(acct)
        self.assertIn("鎖定", resp["message"])

    def test_client_amount_parsing(self):
        from client_mlkem import parse_amount_input
        self.assertEqual(parse_amount_input("1,000.5"), "1000.50")
        for bad in ["-1", "0", "abc", "nan", "1e999999999", "1.001"]:
            with self.assertRaises(ValueError):
                parse_amount_input(bad)

    def test_tampered_frame_is_rejected(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        ch, _ = client_handshake(sock)
        ch.send({"type": "login", "account": "1001", "pin": "1234"})
        ch.recv()
        # 竄改一個位元 → 伺服器應立即斷線
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key, ch._send_chain = ch._ratchet(ch._send_chain)
        nonce, aad = ch._nonce_aad(ch._send_seq)
        ct = bytearray(AESGCM(key).encrypt(nonce, b'{"type":"balance"}', aad))
        ct[0] ^= 1
        send_frame(sock, bytes(ct))
        with self.assertRaises(ConnectionError):
            recv_frame(sock)
        sock.close()

    def test_replay_is_rejected(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        ch, _ = client_handshake(sock)
        import protocol
        sent = []
        orig = protocol.send_frame
        protocol.send_frame = lambda sk, b: (sent.append(b), orig(sk, b))[1]
        try:
            ch.send({"type": "login", "account": "1002", "pin": "5678"})
            ch.recv()
            ch.send({"type": "withdraw", "amount": "1.00"})
            ch.recv()
        finally:
            protocol.send_frame = orig
        send_frame(sock, sent[-1])  # 重送同一筆取款
        with self.assertRaises(ConnectionError):
            recv_frame(sock)
        sock.close()

    def test_mitm_key_substitution_detected(self):
        other = ServerIdentity.load_or_create(os.path.join(self.tmp, "other.key"))
        ks = KnownServers(os.path.join(self.tmp, "known.json"))
        ks.trust("bank", self.identity.pk)
        self.assertEqual(ks.check("bank", self.identity.pk), "match")
        self.assertEqual(ks.check("bank", other.pk), "mismatch")

    def test_concurrent_transfers_conserve_money(self):
        def total():
            return sum(a.balance for a in self.srv.bank.accounts.values())
        before = total()

        def worker(src, pin, dst):
            s, _ = self.login(src, pin)
            for _ in range(20):
                s.request({"type": "transfer", "target": dst, "amount": "1.00"})
            s.close()
        ts = [threading.Thread(target=worker, args=a) for a in
              [("1001", "1234", "1002"), ("1002", "5678", "1001")] * 2]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(total(), before)


if __name__ == "__main__":
    unittest.main()
