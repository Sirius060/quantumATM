"""
quantumATM 銀行核心伺服器（網路層 + 請求分派）

    python server_mlkem.py [--host 0.0.0.0] [--port 5000]

第一次啟動會產生長期 ML-DSA-65 身分金鑰 server_identity.key（請勿上傳 Git），
並印出公鑰指紋，供 ATM 端比對。帳務邏輯在 bank.py，訊息格式在 wire.py。
"""

from __future__ import annotations

import argparse
import logging
import socket
import socketserver
import threading
import time

from bank import Bank, Result
from protocol import (
    DEFAULT_PORT,
    ProtocolError,
    SecureChannel,
    ServerIdentity,
    fingerprint,
    server_handshake,
)
from wire import parse_amount, reply

log = logging.getLogger("quantum-bank")

HANDSHAKE_TIMEOUT = 10  # 秒；握手必須在這段時間內完成
IDLE_TIMEOUT = 120      # 秒；閒置連線自動斷開
MAX_CONNECTIONS = 64    # 同時連線上限（握手運算成本高，避免被灌爆）

# 登入後可用的操作：type → (bank, 帳戶, 請求) → bank.Result。新增交易類型只要在這裡加一行。
HANDLERS = {
    "balance": lambda bank, acct, req: bank.balance(acct),
    "deposit": lambda bank, acct, req: bank.deposit(acct, parse_amount(req.get("amount"))),
    "withdraw": lambda bank, acct, req: bank.withdraw(acct, parse_amount(req.get("amount"))),
    "transfer": lambda bank, acct, req: bank.transfer(acct, req.get("target"), parse_amount(req.get("amount"))),
}


def _clip(value, limit: int = 32) -> str:
    """客戶端送來的值寫進日誌前先轉成 repr 並截短，避免偽造日誌行或灌爆日誌。"""
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "…"


class Session:
    """一條連線的狀態：目前登入的帳戶。"""

    def __init__(self, bank: Bank, channel: SecureChannel, peer: str):
        self.bank = bank
        self.channel = channel
        self.peer = peer
        self.account = None

    def run(self) -> None:
        while True:
            try:
                req = self.channel.recv()
            except ConnectionError:
                return
            self.channel.send(reply(*self.handle(req)))

    def handle(self, req: dict) -> Result:
        kind = req.get("type")
        if kind == "login":
            self.account, result = self.bank.login(req.get("account"), req.get("pin"))
            log.info("%s login %s -> %s", self.peer, _clip(req.get("account")), result.message)
            return result
        if kind == "logout":
            self.account = None
            return Result(True, "已登出")
        if self.account is None:
            return Result(False, "請先登入")

        acct = self.account
        handler = HANDLERS.get(kind) if isinstance(kind, str) else None
        try:
            result = handler(self.bank, acct, req) if handler else Bank.reject(acct, "無效操作類型")
        except ValueError as e:  # 輸入不合法；訊息可直接給使用者
            result = Bank.reject(acct, str(e))
        except Exception:  # noqa: BLE001 — 任何非預期錯誤都不應讓連線崩潰或洩漏內部資訊
            log.exception("%s 處理請求時發生未預期錯誤", self.peer)
            result = Bank.reject(acct, "伺服器內部錯誤")
        log.info("%s [%s] %s -> %s", self.peer, acct.number, _clip(kind), result.message)
        return result


class BankRequestHandler(socketserver.BaseRequestHandler):
    server: "QuantumBankServer"

    def handle(self) -> None:
        peer = "%s:%d" % self.client_address[:2]
        sock: socket.socket = self.request
        try:
            sock.settimeout(self.server.handshake_timeout)
            t0 = time.perf_counter()
            channel = server_handshake(sock, self.server.identity)
            log.info("%s 量子安全通道建立（%.0f ms）", peer, (time.perf_counter() - t0) * 1000)
            sock.settimeout(self.server.idle_timeout)
            Session(self.server.bank, channel, peer).run()
        except socket.timeout:
            log.info("%s 逾時，中斷連線", peer)
        except (ProtocolError, ValueError) as e:
            log.warning("%s 協定錯誤：%s", peer, e)
        except (ConnectionError, OSError) as e:
            log.info("%s 連線中斷：%s", peer, e)
        finally:
            log.info("%s 已斷線", peer)


class QuantumBankServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, identity: ServerIdentity, bank: Bank | None = None, *,
                 max_connections: int = MAX_CONNECTIONS,
                 handshake_timeout: float = HANDSHAKE_TIMEOUT,
                 idle_timeout: float = IDLE_TIMEOUT):
        self.identity = identity
        self.bank = bank or Bank()
        self.handshake_timeout = handshake_timeout
        self.idle_timeout = idle_timeout
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__(addr, BankRequestHandler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            log.warning("%s:%d 連線數已達上限，拒絕連線", *client_address[:2])
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


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
