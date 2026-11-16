# 後量子密碼 ATM 系統
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen)](https://www.python.org/)

以後量子密碼學實作的 ATM 交易協議示範：ML-KEM-768 金鑰交換、ML-DSA-65 伺服器身分簽章、
AES-256-GCM 加密通道，並以「每則訊息一把金鑰」的金鑰棘輪實現交易唯一金鑰。

> ⚠️ 教學／研究用途的示範系統，帳戶資料存在記憶體中，並未經過正式安全稽核，請勿用於真實金融環境。

## 核心功能
- ✅ 帳號 + PIN 登入（scrypt 雜湊、3 次錯誤鎖定）
- ✅ 存款 / 取款 / 轉帳 / 餘額查詢
- ✅ 抗量子金鑰交換（ML-KEM-768, FIPS 203）
- ✅ 伺服器身分驗證：ML-DSA-65（FIPS 204）簽署握手內容，客戶端釘選伺服器公鑰，可偵測中間人攻擊
- ✅ 每則訊息獨立金鑰（HMAC 金鑰棘輪，具前向安全性）
- ✅ AES-256-GCM + 訊息序號，可偵測竄改、重放、重排
- ✅ 金額以 `Decimal` 處理（無浮點誤差），伺服器端完整驗證輸入
- ✅ 多執行緒安全的帳務操作（含防死結的轉帳鎖順序）
- ✅ GUI 網路操作在背景執行，介面不會凍結

## 協定流程
```mermaid
sequenceDiagram
    participant A as ATM 客戶端
    participant B as 銀行伺服器
    A->>B: HELLO = 版本 ‖ nonce ‖ ML-KEM 公鑰 ek
    B->>A: 密文 ct ‖ 伺服器 ML-DSA 公鑰 ‖ Sign(transcript)
    Note over A: 驗證簽章 + 比對已釘選公鑰
    Note over A,B: HKDF-SHA384(共享秘密, salt=transcript) → 雙向金鑰鏈
    A->>B: AES-GCM{login: 帳號, PIN}
    B->>A: AES-GCM{登入結果, 餘額}
    A->>B: AES-GCM{交易}（每則訊息金鑰前推一次）
```

## 快速開始
```bash
pip install -r requirements.txt

# 1. 啟動伺服器（第一次會產生 server_identity.key 並顯示公鑰指紋）
python server_mlkem.py            # 可加 --host / --port

# 2. 啟動客戶端（需要 Tkinter）
python client_mlkem.py
```
第一次連線時，客戶端會顯示伺服器公鑰指紋，請與伺服器終端機上顯示的指紋比對後再按「是」。
之後指紋會記錄在 `known_servers.json`，若伺服器公鑰改變會拒絕連線。

示範帳戶：

| 帳號 | PIN  | 初始餘額   |
|------|------|-----------|
| 1001 | 1234 | 100,000   |
| 1002 | 5678 | 50,000    |

## 測試
```bash
python -m unittest discover -v tests
```
涵蓋：正常交易流程、非法金額（負數、NaN、Infinity、超大數、超過兩位小數）、未登入操作、
PIN 鎖定、封包竄改、封包重放、伺服器公鑰替換、並發轉帳總額守恆。

## 安全機制
| 技術 | 實現目標 |
|------|---------|
| ML-KEM-768 | 後量子安全的金鑰交換 |
| ML-DSA-65 簽署握手 transcript + 公鑰釘選 | 伺服器身分驗證，防中間人攻擊 |
| HKDF-SHA384（salt = transcript hash） | 金鑰與本次握手內容綁定 |
| HMAC 金鑰棘輪 | 每則訊息唯一金鑰、前向安全 |
| AES-256-GCM + 序號（nonce / AAD） | 機密性、完整性、防重放 |
| scrypt PIN 雜湊 + 錯誤鎖定 | 防暴力破解 PIN |

## 專案結構
```
protocol.py        共用握手與加密通道
server_mlkem.py    銀行伺服器（帳務邏輯、登入、交易）
client_mlkem.py    ATM 客戶端（ATMSession 協定核心 + Tkinter GUI）
tests/             端到端測試
```

## 未來擴展
- [ ] 帳戶資料持久化（SQLite）與交易日誌
- [ ] ATM 端身分驗證（每台 ATM 註冊 ML-DSA 公鑰）
- [ ] 整合硬體安全模組（HSM）
- [ ] 支援 EMV 晶片卡動態驗證
- [ ] 混合金鑰交換（X25519 + ML-KEM）
