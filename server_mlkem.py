import socket
import json
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from kyber_py.ml_kem import ML_KEM_768
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from dilithium_py.dilithium import Dilithium2
import base64
from datetime import datetime

class QuantumBankServer:
    def __init__(self):
        self.accounts = {
            '1001': {'balance': 100000.0},  # 原帳號
            '1002': {'balance': 50000.0},   # 新增轉帳用帳號
        }
        self.active_sessions = {}
        self.server_sig_pk, self.server_sig_sk = Dilithium2.keygen()

    def start(self, host='0.0.0.0', port=5000):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(5)
            print(f"量子銀行核心系統啟動 @ {host}:{port}")
            while True:
                conn, addr = sock.accept()
                threading.Thread(target=self._handle_client, args=(conn,)).start()

    def _handle_client(self, conn):
        try:
            ek_len_bytes = self._recv_all(conn, 2)
            ek_len = int.from_bytes(ek_len_bytes, 'big')
            ek = self._recv_all(conn, ek_len)
            
            session_key, ct = ML_KEM_768.encaps(ek)
            conn.sendall(len(ct).to_bytes(2, 'big') + ct)
            
            hkdf = HKDF(
                algorithm=hashes.SHA384(),
                length=32,
                salt=None,
                info=b'quantum-banking'
            )
            session_key = hkdf.derive(session_key)
            
            sig_pk_len = int.from_bytes(self._recv_all(conn, 2), 'big')
            sig_pk_encoded = self._recv_all(conn, sig_pk_len)
            sig_pk = base64.b64decode(sig_pk_encoded)
            
            self.active_sessions[conn] = {
                'key': session_key,
                'sig_pk': sig_pk,
                'dilithium_ver': Dilithium2
            }

            while True:
                header = self._recv_all(conn, 4)
                if not header:
                    break
                payload = self._recv_all(conn, int.from_bytes(header, 'big'))
                decrypted = self._quantum_decrypt(payload, session_key, conn)
                response = self._process_request(decrypted)
                self._send_response(conn, response, session_key)

        except Exception as e:
            print(f"[{datetime.now().isoformat()}] 客戶端處理異常: {str(e)}")
        finally:
            conn.close()
            self.active_sessions.pop(conn, None)

    def _process_request(self, data):
        try:
            req_type = data.get('type')
            account = data.get('account', '1001')
            
            if account not in self.accounts:
                self.accounts[account] = {'balance': 0.0}
                
            if req_type == 'deposit':
                return self._handle_deposit(data, account)
            elif req_type == 'withdraw':
                return self._handle_withdraw(data, account)
            elif req_type == 'transfer':
                return self._handle_transfer(data, account)
            elif req_type == 'balance':
                return self._handle_balance(account)
            else:
                return {
                    "success": False,
                    "message": "無效操作類型",
                    "balance": self.accounts[account]['balance']
                }
        except Exception as e:
            return {
                "success": False,
                "message": f"伺服器錯誤: {str(e)}",
                "balance": self.accounts[account].get('balance', 0.0)
            }

    def _handle_deposit(self, data, account):
        amount = float(data.get('amount', 0))
        self.accounts[account]['balance'] += amount
        return {
            "success": True,
            "balance": self.accounts[account]['balance'],
            "message": f"成功存入 {amount:.2f} 元"
        }

    def _handle_withdraw(self, data, account):
        amount = float(data.get('amount', 0))
        if self.accounts[account]['balance'] >= amount:
            self.accounts[account]['balance'] -= amount
            return {
                "success": True,
                "balance": self.accounts[account]['balance'],
                "message": f"成功取出 {amount:.2f} 元"
            }
        else:
            return {
                "success": False,
                "message": "餘額不足",
                "balance": self.accounts[account]['balance']
            }

    def _handle_transfer(self, data, account):
        target = data.get('target')
        amount = float(data.get('amount', 0))
        
        # 強化帳號存在性檢查
        if target not in self.accounts:
            return {
                "success": False,
                "message": f"目標帳號 {target} 不存在",
                "balance": self.accounts[account]['balance']
            }
            
        try:
            # 強化金額驗證
            if amount <= 0:
                raise ValueError("轉帳金額需大於零")
                
            if self.accounts[account]['balance'] >= amount:
                # 原子操作保證數據一致性
                self.accounts[account]['balance'] -= amount
                self.accounts[target]['balance'] += amount
                return {
                    "success": True,
                    "balance": self.accounts[account]['balance'],
                    "message": f"成功轉賬 {amount:.2f} 元至 {target}"
                }
            else:
                return {
                    "success": False,
                    "message": "餘額不足",
                    "balance": self.accounts[account]['balance']
                }
        except ValueError as e:
            return {
                "success": False,
                "message": f"無效操作: {str(e)}",
                "balance": self.accounts[account]['balance']
            }

    def _handle_balance(self, account):
        return {
            "success": True,
            "balance": self.accounts[account]['balance'],
            "message": "餘額查詢成功"
        }

    def _quantum_decrypt(self, payload, session_key, conn):
        if len(payload) < 28:
            raise ValueError("封包長度不足28字節")
        
        nonce = payload[:12]
        tag = payload[12:28]
        ciphertext = payload[28:]
        
        key = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=None,
            info=b'quantum-banking'
        ).derive(session_key)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        data = json.loads(plaintext.decode())
        
        session_data = self.active_sessions[conn]
        if not Dilithium2.verify(
            session_data['sig_pk'],
            json.dumps(data['data']).encode(),
            bytes.fromhex(data['sig'])
        ):
            raise ValueError("量子簽章驗證失敗")
        return data['data']

    def _send_response(self, conn, data, session_key):
        nonce = get_random_bytes(12)
        key = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=None,
            info=b'quantum-banking'
        ).derive(session_key)
        
        signature = Dilithium2.sign(self.server_sig_sk, json.dumps(data).encode())
        payload = {
            'data': data,
            'sig': signature.hex(),
            'timestamp': datetime.now().isoformat()
        }
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(json.dumps(payload).encode())
        full_payload = nonce + tag + ciphertext
        conn.sendall(len(full_payload).to_bytes(4, 'big') + full_payload)

    def _recv_all(self, conn, length):
        data = bytearray()
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                raise ConnectionAbortedError("連線非正常終止")
            data.extend(chunk)
        return bytes(data)

if __name__ == "__main__":
    QuantumBankServer().start()
