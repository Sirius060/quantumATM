# 後量子密碼 ATM 系統
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen)](https://www.python.org/)

本系統實現基於後量子密碼學的 ATM 交易協議，結合 ML-KEM-512、TLS 1.3 與 DUKPT 機制，提供抗量子計算攻擊的金融安全解決方案。

## 核心功能
- ✅ 存款/取款/轉賬/餘額查詢
- ✅ TLS 1.3 加密傳輸層
- ✅ 每筆交易唯一密鑰派生（DUKPT）
- ✅ 隨機 IV 的 AES-CBC 加密
- ✅ 完整日誌與異常處理

## 技術架構
graph TD
A[ATM 客戶端] -- TLS 1.3 --> B[伺服器]
B -- ML-KEM-512 密鑰交換 --> A
A -- 交易唯一密鑰 + 隨機 IV --> B

## 快速開始
### 依賴安裝
pip install -r requirements.txt

### 啟動伺服器
python server_mlkem.py

### 啟動客戶端
python client_mlkem.py

## 安全機制
| 技術                 | 實現目標                      |
|----------------------|------------------------------|
| ML-KEM-512           | 後量子安全的密鑰交換          |
| DUKPT                | 每筆交易獨立加密密鑰          |
| AES-256-CBC + 隨機IV | 防止重放攻擊與密文分析        |
| TLS 1.3              | 傳輸層端到端加密與身份驗證    |

## 未來擴展
- [ ] 整合硬體安全模組（HSM）
- [ ] 支援 EMV 晶片卡動態驗證
- [ ] 實現 PCI-DSS 合規性審計工具
