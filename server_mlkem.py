import socket
import ssl
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# DUKPT 類別：負責根據主密鑰與 KSN 派生每筆交易的唯一密鑰
class DUKPT:
    def __init__(self, bdk):
        # 主密鑰（Base Derivation Key）
        self.bdk = bdk

    def derive_key(self, ksn):
        # 根據 KSN（密鑰序號）派生本次交易的唯一密鑰
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=ksn,
            iterations=10000,
        )
        return kdf.derive(self.bdk)

# BankServer 類別：管理用戶資料、密鑰，處理網路連線與交易
class BankServer:
    def __init__(self):
        # 用戶資料庫（帳號與餘額）
        self.users = {"1001": {"balance": 10000.0}, "1002": {"balance": 5000.0}}
        # 主密鑰（32 bytes）
        self.bdk = b'bankdemo1234567890bankdemo1234567'
        # 建立 DUKPT 實例
        self.dukpt = DUKPT(self.bdk)

    # 啟動伺服器，監聽指定埠號
    def start(self, host='0.0.0.0', port=5000):
        # 建立 TLS 1.3 安全連線
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('cert.pem', 'key.pem')
        sock = socket.socket()
        sock.bind((host, port))
        sock.listen(5)
        ssock = context.wrap_socket(sock, server_side=True)
        print("TLS 1.3 伺服器啟動...")
        while True:
            # 接受新連線
            conn, addr = ssock.accept()
            print(f"新連線：{addr}")
            # 處理客戶端連線
            self.handle_client(conn)

    # 確保收到指定長度的資料
    def recv_all(self, conn, length):
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data

    # 處理單一客戶端連線
    def handle_client(self, conn):
        try:
            while True:
                # 1. 接收4字節長度標頭
                header = self.recv_all(conn, 4)
                if not header:
                    break
                data_len = int.from_bytes(header, 'big')
                # 2. 接收完整資料
                payload = self.recv_all(conn, data_len)
                if not payload or len(payload) < 19:
                    break
                print(f"[Server] 收到密文 (HEX): {payload.hex().upper()}")
                # 3. 解析KSN、IV、密文
                ksn = payload[:3]
                iv = payload[3:19]
                encrypted = payload[19:]
                # 4. 派生唯一密鑰並解密
                pek = self.dukpt.derive_key(ksn)
                cipher = AES.new(pek, AES.MODE_CBC, iv=iv)
                try:
                    decrypted = unpad(cipher.decrypt(encrypted), 16)
                    data = json.loads(decrypted.decode())
                    print(f"[Server] 解密後明文: {data}")
                except Exception as e:
                    print(f"[Server] 解密失敗: {e}")
                    break
                # 5. 處理請求
                response = self.process_request(data)
                print(f"[Server] 處理結果: {response}")
                response_json = json.dumps(response).encode()
                # 6. 每筆回應也用新KSN/PEK
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

    # 處理交易請求
    def process_request(self, data):
        # 預設帳號為1001（實際可擴充多帳號登入）
        account = "1001"
        t = data.get('type')
        if t == 'create_account':
            # 創建新帳號
            new_account = data.get('account')
            if new_account in self.users:
                return {"success": False, "message": "帳號已存在"}
            self.users[new_account] = {"balance": 0.0}
            print(f"[Server] 新增帳號: {new_account}")
            return {"success": True, "message": f"帳號 {new_account} 創建成功"}
        elif t == 'deposit':
            # 存款
            amt = data.get('amount', 0)
            self.users[account]['balance'] += amt
            return {"success": True, "balance": self.users[account]['balance'], "message": f"存款{amt}元成功"}
        elif t == 'withdraw':
            # 取款
            amt = data.get('amount', 0)
            if self.users[account]['balance'] >= amt:
                self.users[account]['balance'] -= amt
                return {"success": True, "balance": self.users[account]['balance']}
            else:
                return {"success": False, "message": "餘額不足"}
        elif t == 'transfer':
            # 轉賬
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
            # 查詢餘額
            return {"success": True, "balance": self.users[account]['balance']}
        elif t == 'exit':
            # 登出
            return {"success": True, "message": "已登出"}
        else:
            # 未知操作
            return {"success": False, "message": "未知操作"}

if __name__ == "__main__":
    # 啟動伺服器
    BankServer().start()
