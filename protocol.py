"""
quantumATM 共用安全通道協定（v2）

握手流程（抗量子 + 伺服器身分驗證）：

    Client                                         Server
    ------                                         ------
    HELLO = version || client_nonce(32) || ek  -->
                                               <-- ct || server_sig_pk || sig
                     sig = ML-DSA-65.Sign(server_sk, transcript_hash)
                     transcript_hash = SHA-384(HELLO || ct || server_sig_pk)

    雙方：shared = ML-KEM-768 共享秘密
          (c2s_chain, s2c_chain) = HKDF-SHA384(shared, salt=transcript_hash)

資料通道：
  * 每個方向獨立的鏈金鑰（chain key），每送出一則訊息就向前推進一次
    → 每筆交易使用唯一金鑰（DUKPT 精神的 key ratchet），且具前向安全性。
  * AES-256-GCM，nonce 與 AAD 綁定訊息序號 → 重放、重排、刪除訊息都會被偵測。
  * 封包長度上限，避免惡意長度欄位造成記憶體耗盡。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

PROTOCOL_VERSION = 2
DEFAULT_PORT = 5000
SIG_CONTEXT = b"quantumATM-handshake-v2"

KEM = ML_KEM_768
SIG = ML_DSA_65

EK_LEN = 1184          # ML-KEM-768 封裝公鑰
CT_LEN = 1088          # ML-KEM-768 密文
SIG_PK_LEN = 1952      # ML-DSA-65 公鑰
SIG_LEN = 3309         # ML-DSA-65 簽章
NONCE_LEN = 32

MAX_FRAME = 64 * 1024  # 單一封包上限（握手訊息約 7 KB，交易訊息 < 1 KB）


class ProtocolError(Exception):
    """協定或密碼驗證失敗；發生時應立即中斷連線。"""


# ---------------------------------------------------------------- framing
def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("連線已被對方關閉")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock: socket.socket, data: bytes) -> None:
    if len(data) > MAX_FRAME:
        raise ProtocolError("封包過大")
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock: socket.socket) -> bytes:
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    if length > MAX_FRAME:
        raise ProtocolError(f"封包長度 {length} 超過上限")
    return recv_exact(sock, length)


# ---------------------------------------------------------------- keys
def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA384(), length=length, salt=salt, info=info).derive(ikm)


def _derive_channel_keys(shared: bytes, transcript_hash: bytes) -> tuple[bytes, bytes]:
    okm = _hkdf(shared, transcript_hash, b"quantumATM v2 channel keys", 64)
    return okm[:32], okm[32:]  # (client->server, server->client)


def _transcript_hash(hello: bytes, ct: bytes, server_pk: bytes) -> bytes:
    return hashlib.sha384(b"quantumATM-v2" + hello + ct + server_pk).digest()


def fingerprint(pk: bytes) -> str:
    """公鑰指紋（給人眼比對用）。"""
    h = hashlib.sha256(pk).hexdigest()[:32]
    return ":".join(h[i:i + 4] for i in range(0, len(h), 4))


@dataclass
class ServerIdentity:
    pk: bytes
    sk: bytes

    @classmethod
    def load_or_create(cls, path: str) -> "ServerIdentity":
        """長期身分金鑰：第一次啟動時產生並保存，之後重複使用，讓客戶端可以釘選。"""
        if os.path.exists(path):
            with open(path, "rb") as f:
                blob = f.read()
            pk, sk = blob[:SIG_PK_LEN], blob[SIG_PK_LEN:]
        else:
            pk, sk = SIG.keygen()
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pk + sk)
        return cls(pk, sk)


# ---------------------------------------------------------------- channel
class SecureChannel:
    """建立在握手金鑰上的 AEAD 通道。每個方向一條金鑰鏈 + 序號。"""

    def __init__(self, sock: socket.socket, send_chain: bytes, recv_chain: bytes):
        self.sock = sock
        self._send_chain = send_chain
        self._recv_chain = recv_chain
        self._send_seq = 0
        self._recv_seq = 0

    @staticmethod
    def _ratchet(chain: bytes) -> tuple[bytes, bytes]:
        msg_key = hmac.new(chain, b"\x01msg", hashlib.sha256).digest()
        next_chain = hmac.new(chain, b"\x02chain", hashlib.sha256).digest()
        return msg_key, next_chain

    @staticmethod
    def _nonce_aad(seq: int) -> tuple[bytes, bytes]:
        seq_bytes = struct.pack(">Q", seq)
        return b"\x00" * 4 + seq_bytes, b"qatm2" + seq_bytes

    def send(self, obj: dict) -> None:
        msg_key, self._send_chain = self._ratchet(self._send_chain)
        nonce, aad = self._nonce_aad(self._send_seq)
        self._send_seq += 1
        plaintext = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
        send_frame(self.sock, AESGCM(msg_key).encrypt(nonce, plaintext, aad))

    def recv(self) -> dict:
        frame = recv_frame(self.sock)
        msg_key, next_chain = self._ratchet(self._recv_chain)
        nonce, aad = self._nonce_aad(self._recv_seq)
        try:
            plaintext = AESGCM(msg_key).decrypt(nonce, frame, aad)
        except Exception as exc:  # InvalidTag
            raise ProtocolError("訊息驗證失敗（遭竄改、重放或順序錯誤）") from exc
        self._recv_chain = next_chain
        self._recv_seq += 1
        try:
            obj = json.loads(plaintext)
        except ValueError as exc:
            raise ProtocolError("訊息格式錯誤") from exc
        if not isinstance(obj, dict):
            raise ProtocolError("訊息格式錯誤")
        return obj

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- handshake
def client_handshake(sock: socket.socket) -> tuple[SecureChannel, bytes]:
    """回傳 (通道, 伺服器簽章公鑰)。呼叫端必須自行比對公鑰是否可信。"""
    ek, dk = KEM.keygen()
    hello = bytes([PROTOCOL_VERSION]) + os.urandom(NONCE_LEN) + ek
    send_frame(sock, hello)

    reply = recv_frame(sock)
    if len(reply) != CT_LEN + SIG_PK_LEN + SIG_LEN:
        raise ProtocolError("伺服器握手回應長度錯誤")
    ct = reply[:CT_LEN]
    server_pk = reply[CT_LEN:CT_LEN + SIG_PK_LEN]
    sig = reply[CT_LEN + SIG_PK_LEN:]

    th = _transcript_hash(hello, ct, server_pk)
    if not SIG.verify(server_pk, th, sig, ctx=SIG_CONTEXT):
        raise ProtocolError("伺服器握手簽章驗證失敗")

    shared = KEM.decaps(dk, ct)
    c2s, s2c = _derive_channel_keys(shared, th)
    return SecureChannel(sock, send_chain=c2s, recv_chain=s2c), server_pk


def server_handshake(sock: socket.socket, identity: ServerIdentity) -> SecureChannel:
    hello = recv_frame(sock)
    if len(hello) != 1 + NONCE_LEN + EK_LEN or hello[0] != PROTOCOL_VERSION:
        raise ProtocolError("不支援的協定版本或 HELLO 格式錯誤")
    ek = hello[1 + NONCE_LEN:]

    shared, ct = KEM.encaps(ek)
    th = _transcript_hash(hello, ct, identity.pk)
    sig = SIG.sign(identity.sk, th, ctx=SIG_CONTEXT)
    send_frame(sock, ct + identity.pk + sig)

    c2s, s2c = _derive_channel_keys(shared, th)
    return SecureChannel(sock, send_chain=s2c, recv_chain=c2s)
