"""
ATM 客戶端核心（不含 GUI）：伺服器公鑰釘選、安全連線、使用者輸入解析。

GUI（client_mlkem.py）只透過這個模組和 wire.py 與伺服器互動。
"""

from __future__ import annotations

import json
import socket
import threading

import wire
from protocol import DEFAULT_PORT, ProtocolError, SecureChannel, client_handshake, fingerprint

KNOWN_SERVERS_FILE = "known_servers.json"
NET_TIMEOUT = 10  # 秒


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
    """一條到伺服器的安全連線：connect() 握手，request() 一問一答。"""

    def __init__(self):
        self.channel: SecureChannel | None = None
        self.server_pk: bytes | None = None
        self._lock = threading.Lock()

    @property
    def connected(self) -> bool:
        return self.channel is not None

    @property
    def fingerprint(self) -> str:
        """最近一次握手對象的公鑰指紋（給使用者比對用）。"""
        return fingerprint(self.server_pk)

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
        if not wire.is_reply(resp):
            raise ProtocolError("伺服器回應格式錯誤")
        return resp

    def close(self) -> None:
        if self.channel is not None:
            self.channel.close()
            self.channel = None


def parse_amount_input(text: str) -> str:
    """使用者輸入的金額 → 傳輸用字串；不合法時丟 ValueError(給使用者看的訊息)。"""
    return wire.format_amount(wire.parse_amount(text.strip().replace(",", ""), invalid="請輸入有效數字"))


def parse_server_input(text: str) -> tuple[str, int]:
    """接受 `host` 或 `host:port`，回傳 (host, port)。"""
    text = text.strip()
    if text.startswith("["):  # [IPv6] 或 [IPv6]:port
        host, _, rest = text[1:].partition("]")
        if rest and not rest.startswith(":"):
            raise ValueError("伺服器位址格式錯誤")
        port_text = rest[1:]
    elif text.count(":") == 1:
        host, port_text = text.split(":")
    else:  # 純主機名稱，或未加括號的 IPv6 位址
        host, port_text = text, ""
    if not host:
        raise ValueError("請輸入伺服器位址")
    if not port_text:
        return host, DEFAULT_PORT
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise ValueError("埠號需為 1–65535 的數字")
    return host, int(port_text)
