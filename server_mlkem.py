import socket
import ssl
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# DUKPT簡化版（實際應用需HSM與KSN同步）
class DUKPT:
    def __init__(self, bdk):
        self.bdk = bdk

    def derive_key(self, ksn):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=ksn,
            iterations=10000,
        )
        return kdf.derive(self.bdk)

class BankServer:
    def __init__(self):
        self.users = {"1001": {"balance": 10000.0}, "1002": {"balance": 5000.0}}
        self.bdk = b'bankdemo1234567890bankdemo1234567'  # 32 bytes
        self.dukpt = DUKPT(self.bdk)

    def start(self, host='0.0.0.0', port=5000):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('cert.pem', 'key.pem')
        sock = socket.socket()
        sock.bind((host, port))
        sock.listen(5)
        ssock = context.wrap_socket(sock, server_side=True)
        print("TLS 1.3 伺服器啟動...")
        while True:
            conn, addr = ssock.accept()
            print(f"新連線：{addr}")
            self.handle_client(conn)

    def recv_all(self, conn, length):
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def handle_client(self, conn):
        try:
            while True:
                # 1. 收4字節長度標頭
                header = self.recv_all(conn, 4)
                if not header:
                    break
                data_len = int.from_bytes(header, 'big')
                payload = self.recv_all(conn, data_len)
                if not payload or len(payload) < 19:
                    break
                # 2. 解析KSN、IV、密文
                ksn = payload[:3]
                iv = payload[3:19]
                encrypted = payload[19:]
                # 3. 派生唯一密鑰
                pek = self.dukpt.derive_key(ksn)
                cipher = AES.new(pek, AES.MODE_CBC, iv=iv)
                try:
                    data = json.loads(unpad(cipher.decrypt(encrypted), 16).decode())
                except Exception as e:
                    print(f"解密失敗: {e}")
                    break
                # 4. 處理請求
                response = self.process_request(data)
                response_json = json.dumps(response).encode()
                # 5. 每筆回應也用新KSN/PEK
                resp_ksn = get_random_bytes(3)
                resp_pek = self.dukpt.derive_key(resp_ksn)
                resp_iv = get_random_bytes(16)
                resp_cipher = AES.new(resp_pek, AES.MODE_CBC, iv=resp_iv)
                resp_enc = resp_cipher.encrypt(pad(response_json, 16))
                resp_payload = resp_ksn + resp_iv + resp_enc
                resp_header = len(resp_payload).to_bytes(4, 'big')
                conn.sendall(resp_header + resp_payload)
                if data.get('type') == 'exit':
                    break
        finally:
            conn.close()

    def process_request(self, data):
        account = "1001"
        t = data.get('type')
        if t == 'deposit':
            amt = data.get('amount', 0)
            self.users[account]['balance'] += amt
            return {"success": True, "balance": self.users[account]['balance'], "message": f"存款{amt}元成功"}
        elif t == 'withdraw':
            amt = data.get('amount', 0)
            if self.users[account]['balance'] >= amt:
                self.users[account]['balance'] -= amt
                return {"success": True, "balance": self.users[account]['balance']}
            else:
                return {"success": False, "message": "餘額不足"}
        elif t == 'transfer':
            target = data.get('target')
            amt = data.get('amount', 0)
            if target not in self.users:
                return {"success": False, "message": "目標帳號不存在"}
            if self.users[account]['balance'] >= amt:
                self.users[account]['balance'] -= amt
                self.users[target]['balance'] += amt
                return {"success": True, "balance": self.users[account]['balance']}
            else:
                return {"success": False, "message": "餘額不足"}
        elif t == 'balance':
            return {"success": True, "balance": self.users[account]['balance']}
        elif t == 'exit':
            return {"success": True, "message": "已登出"}
        else:
            return {"success": False, "message": "未知操作"}

if __name__ == "__main__":
    BankServer().start()
