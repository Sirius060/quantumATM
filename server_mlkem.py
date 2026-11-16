"""
quantumATM 銀行核心伺服器

    python server_mlkem.py [--host 0.0.0.0] [--port 5000]

第一次啟動會產生長期 ML-DSA-65 身分金鑰 server_identity.key（請勿上傳 Git），
並印出公鑰指紋，供 ATM 端比對。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import logging
import os
import socket
import socketserver
import threading
import time
from decimal import Decimal, InvalidOperation

from protocol import (
    DEFAULT_PORT,
    ProtocolError,
    SecureChannel,
    ServerIdentity,
    fingerprint,
    server_handshake,
)

log = logging.getLogger("quantum-bank")

CENT = Decimal("0.01")
MAX_TX_AMOUNT = Decimal("1000000")   # 單筆上限
MAX_PIN_ATTEMPTS = 3
IDLE_TIMEOUT = 120                   # 秒；閒置連線自動斷開


# ---------------------------------------------------------------- bank state
def _hash_pin(pin: str, salt: bytes) -> bytes:
    return hashlib.scrypt(pin.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


class Account:
    def __init__(self, number: str, balance: str, pin: str):
        self.number = number
        self.balance = Decimal(balance)
        self.salt = os.urandom(16)
        self.pin_hash = _hash_pin(pin, self.salt)
        self.failed_attempts = 0
        self.lock = threading.Lock()

    def check_pin(self, pin: str) -> bool:
        return hmac.compare_digest(_hash_pin(pin, self.salt), self.pin_hash)


class Bank:
    """所有帳務操作都在帳戶鎖內完成，避免多執行緒競爭造成餘額錯誤。"""

    def __init__(self):
        # 示範帳戶（帳號, 初始餘額, PIN）
        self.accounts = {
            a.number: a
            for a in (
                Account("1001", "100000.00", "1234"),
                Account("1002", "50000.00", "5678"),
            )
        }

    # -- helpers
    @staticmethod
    def parse_amount(raw) -> Decimal:
        if isinstance(raw, bool) or not isinstance(raw, (str, int)):
            raise ValueError("金額格式錯誤")
        try:
            amount = Decimal(str(raw))
        except InvalidOperation:
            raise ValueError("金額格式錯誤") from None
        if not amount.is_finite():
            raise ValueError("金額格式錯誤")
        if amount <= 0:
            raise ValueError("金額需大於零")
        if amount > MAX_TX_AMOUNT:  # 先檢查範圍，避免極大指數讓 quantize 出錯
            raise ValueError(f"單筆金額上限為 {MAX_TX_AMOUNT:,} 元")
        if amount != amount.quantize(CENT):
            raise ValueError("金額最多到小數點後兩位")
        return amount.quantize(CENT)

    @staticmethod
    def _ok(acct: Account, message: str) -> dict:
        return {"success": True, "balance": f"{acct.balance:.2f}", "message": message}

    @staticmethod
    def _fail(acct: Account | None, message: str) -> dict:
        resp = {"success": False, "message": message}
        if acct is not None:
            resp["balance"] = f"{acct.balance:.2f}"
        return resp

    # -- auth
    def login(self, number, pin) -> tuple[Account | None, dict]:
        acct = self.accounts.get(number) if isinstance(number, str) else None
        if acct is None or not isinstance(pin, str):
            # 不透露帳號是否存在
            return None, self._fail(None, "帳號或 PIN 錯誤")
        with acct.lock:
            if acct.failed_attempts >= MAX_PIN_ATTEMPTS:
                return None, self._fail(None, "帳戶已鎖定，請洽臨櫃")
            if not acct.check_pin(pin):
                acct.failed_attempts += 1
                left = MAX_PIN_ATTEMPTS - acct.failed_attempts
                return None, self._fail(None, f"帳號或 PIN 錯誤（剩餘 {left} 次）")
            acct.failed_attempts = 0
            return acct, self._ok(acct, "登入成功")

    # -- transactions
    def balance(self, acct: Account) -> dict:
        with acct.lock:
            return self._ok(acct, "餘額查詢成功")

    def deposit(self, acct: Account, amount: Decimal) -> dict:
        with acct.lock:
            acct.balance += amount
            return self._ok(acct, f"成功存入 {amount:,.2f} 元")

    def withdraw(self, acct: Account, amount: Decimal) -> dict:
        with acct.lock:
            if acct.balance < amount:
                return self._fail(acct, "餘額不足")
            acct.balance -= amount
            return self._ok(acct, f"成功取出 {amount:,.2f} 元")

    def transfer(self, src: Account, target_no, amount: Decimal) -> dict:
        target = self.accounts.get(target_no) if isinstance(target_no, str) else None
        if target is None:
            with src.lock:
                return self._fail(src, "目標帳號不存在")
        if target is src:
            with src.lock:
                return self._fail(src, "不可轉帳給自己")
        # 依帳號排序取鎖，避免兩筆反向轉帳互相死結
        first, second = sorted((src, target), key=lambda a: a.number)
        with first.lock, second.lock:
            if src.balance < amount:
                return self._fail(src, "餘額不足")
            src.balance -= amount
            target.balance += amount
            return self._ok(src, f"成功轉帳 {amount:,.2f} 元至 {target.number}")


# ---------------------------------------------------------------- session
class Session:
    def __init__(self, bank: Bank, channel: SecureChannel, peer: str):
        self.bank = bank
        self.channel = channel
        self.peer = peer
        self.account: Account | None = None

    def run(self) -> None:
        while True:
            try:
                req = self.channel.recv()
            except ConnectionError:
                return
            resp = self.handle(req)
            self.channel.send(resp)

    def handle(self, req: dict) -> dict:
        req_type = req.get("type")
        if req_type == "login":
            acct, resp = self.bank.login(req.get("account"), req.get("pin"))
            self.account = acct
            log.info("%s login %s -> %s", self.peer, req.get("account"), resp["message"])
            return resp
        if req_type == "logout":
            self.account = None
            return {"success": True, "message": "已登出"}

        if self.account is None:
            return Bank._fail(None, "請先登入")
        acct = self.account

        try:
            if req_type == "balance":
                resp = self.bank.balance(acct)
            elif req_type == "deposit":
                resp = self.bank.deposit(acct, Bank.parse_amount(req.get("amount")))
            elif req_type == "withdraw":
                resp = self.bank.withdraw(acct, Bank.parse_amount(req.get("amount")))
            elif req_type == "transfer":
                resp = self.bank.transfer(
                    acct, req.get("target"), Bank.parse_amount(req.get("amount"))
                )
            else:
                resp = Bank._fail(acct, "無效操作類型")
        except ValueError as e:
            resp = Bank._fail(acct, str(e))
        except Exception:  # noqa: BLE001 — 任何非預期錯誤都不應讓連線崩潰或洩漏內部資訊
            log.exception("%s 處理請求時發生未預期錯誤", self.peer)
            resp = Bank._fail(acct, "伺服器內部錯誤")
        log.info("%s [%s] %s -> %s", self.peer, acct.number, req_type, resp["message"])
        return resp


class BankRequestHandler(socketserver.BaseRequestHandler):
    server: "QuantumBankServer"

    def handle(self) -> None:
        peer = "%s:%d" % self.client_address[:2]
        sock: socket.socket = self.request
        sock.settimeout(IDLE_TIMEOUT)
        try:
            t0 = time.perf_counter()
            channel = server_handshake(sock, self.server.identity)
            log.info("%s 量子安全通道建立（%.0f ms）", peer, (time.perf_counter() - t0) * 1000)
            Session(self.server.bank, channel, peer).run()
        except socket.timeout:
            log.info("%s 閒置逾時，中斷連線", peer)
        except (ProtocolError, ValueError) as e:
            log.warning("%s 協定錯誤：%s", peer, e)
        except (ConnectionError, OSError) as e:
            log.info("%s 連線中斷：%s", peer, e)
        finally:
            log.info("%s 已斷線", peer)


class QuantumBankServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, identity: ServerIdentity, bank: Bank | None = None):
        self.identity = identity
        self.bank = bank or Bank()
        super().__init__(addr, BankRequestHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="quantumATM 銀行核心伺服器")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--identity", default="server_identity.key",
                        help="伺服器長期 ML-DSA 身分金鑰檔")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    identity = ServerIdentity.load_or_create(args.identity)
    log.info("伺服器公鑰指紋：%s", fingerprint(identity.pk))

    with QuantumBankServer((args.host, args.port), identity) as srv:
        log.info("量子銀行核心系統啟動 @ %s:%d", args.host, args.port)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            log.info("伺服器關閉")


if __name__ == "__main__":
    main()
