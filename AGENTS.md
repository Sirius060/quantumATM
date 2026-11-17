# quantumATM 維護規則

給之後接手的 AI 模型與開發者。**先讀完這一份，再依第 3 節只開需要的檔案**，不要把整個專案讀一遍。

## 1. 不可改變的對外行為

除非任務明確要求，否則下列項目一律維持原狀：

- **啟動方式**：`python server_mlkem.py [--host --port --identity]`、`python client_mlkem.py`。
- **畫面**：版面、元件順序、文字、圖示、顏色、字型、對話框與訊息視窗的標題和內容、操作流程。
- **伺服器回應的 `message` 文字**：客戶端會原樣顯示給使用者，改字就是改畫面。
- **傳輸相容**：`wire.py` 的訊息欄位、`protocol.py` 的握手與封包格式。新舊版客戶端與伺服器要能互通；
  真的必須改握手時把 `PROTOCOL_VERSION` 加 1，並在 commit 訊息註明兩端要一起更新。
- **執行期檔案格式**：`server_identity.key`、`known_servers.json`。
- **相依套件**：只有 `requirements.txt` 那三個。不新增套件、不新增框架。

## 2. 模組與依賴方向

| 檔案 | 職責 | 可以 import 的專案模組 |
|---|---|---|
| `wire.py` | 訊息契約：請求建構函式、`reply()`、金額驗證與格式 | 無 |
| `protocol.py` | 握手、金鑰棘輪、AES-GCM 通道、伺服器身分金鑰 | 無 |
| `bank.py` | 帳戶、PIN 鎖定、存提款與轉帳；回傳 `Result` | 無 |
| `server_mlkem.py` | 連線管理、逾時與連線上限、請求分派表 `HANDLERS`、日誌 | wire、protocol、bank |
| `atm_client.py` | 客戶端核心：`ATMSession`、`KnownServers`、輸入解析 | wire、protocol |
| `client_mlkem.py` | Tkinter 畫面與互動，其他什麼都不做 | wire、atm_client |

```
client_mlkem ──▶ atm_client ──▶ protocol ◀── server_mlkem ──▶ bank
      └──────────────┴────────▶  wire   ◀──────────┘
```

- 依賴只能照箭頭方向。`tkinter` 只能出現在 `client_mlkem.py`；密碼學套件只能出現在 `protocol.py`。
- 單一檔案上限 400 行，超過就依職責拆檔。
- 以上由 `tests/test_architecture.py` 自動檢查。新增或拆分模組時，同時更新該測試的 `ALLOWED` 和上面這張表。

## 3. 要改什麼 → 只需要讀哪些檔

| 任務 | 讀／改 | 測試 |
|---|---|---|
| 畫面、文字、對話框 | `client_mlkem.py` | `tests/test_gui.py` |
| 新增交易類型 | `wire.py`（建構函式＋檔頭的表）→ `bank.py`（方法）→ `server_mlkem.py`（`HANDLERS` 加一行）→ `client_mlkem.py`（按鈕） | `test_e2e.py`、`test_gui.py` |
| 金額規則、單筆上限 | `wire.py` | `test_e2e.py` |
| 帳務規則、PIN 鎖定、示範帳戶 | `bank.py` | `test_e2e.py` |
| 逾時、連線上限、日誌 | `server_mlkem.py` | `test_e2e.py` |
| 連線、公鑰釘選、輸入解析 | `atm_client.py` | `test_e2e.py` |
| 加密、握手 | `protocol.py`（先讀檔頭的流程說明） | `test_e2e.py` |

## 4. 寫法規則

- **訊息格式以 `wire.py` 為準**。請求一律用 `wire.login()`、`wire.deposit()` 等建構函式產生，回應一律用
  `wire.reply()` 產生，不要手寫 `{"type": ...}`（測試故意送壞資料時例外）。讀取端（`HANDLERS`、GUI 顯示回應）
  用到的欄位名稱以 `wire.py` 檔頭的表為準，改欄位時三處一起改。
- **金額**全程使用 `Decimal`，傳輸時是字串。驗證只走 `wire.parse_amount()`，兩端共用，不要另寫一份；
  不合法時它會丟 `ValueError(給使用者看的訊息)`，伺服器會轉成失敗回應。
- **`bank.py` 不知道網路和訊息格式**：方法回傳 `Result(success, message, balance)`，餘額變動都在帳戶鎖內；
  同時動到兩個帳戶時依帳號排序取鎖。
- **GUI 不直接做網路 I/O**：一律經 `_run_bg(work, on_done, on_error)` 在背景執行，回呼回到主執行緒才動元件。
  背景工作不可以碰任何 Tk 物件。
- **跨模組只用公開名稱**，不存取別的模組裡底線開頭的屬性；測試也一樣。
- **設定值**放在所屬模組檔頭的常數（例如 `IDLE_TIMEOUT`、`PIN_LOCKOUT_SECONDS`），不要散在函式裡，也不要新增設定檔。
- **錯誤處理**：協定或驗證失敗丟 `ProtocolError` 並斷線，不嘗試修復通道；伺服器不把內部例外內容回傳給客戶端。
- **保持精簡**：不為「以後可能用到」加抽象層、基底類別、外掛機制或選項；重複出現第三次再抽共用。
  註解只寫「為什麼」，不重述程式碼。修改時優先刪減，新增行數要有對應的需求。
- 註解、文件與使用者訊息用繁體中文；識別字、commit 訊息用英文。

## 5. 更新流程

1. 依第 3 節找出要讀的檔案；需要定位時用搜尋，不要整檔通讀無關模組。
2. 動手前先跑一次測試，確認基準是綠的。
3. 做最小的修改。行為有變就補或改對應測試；修 bug 先寫一個會失敗的測試。
4. 跑測試（見第 6 節），全部通過才算完成。
5. 模組職責、訊息欄位或啟動方式有變 → 同步更新這份文件、`wire.py` 檔頭和 `README.md`。
6. 一個主題一個 commit，訊息格式：第一行英文祈使句摘要，之後條列改了什麼、為什麼。
   不要提交 `server_identity.key`、`known_servers.json`、任何 `*.pem`／`*.key`。

## 6. 測試

```bash
python -m unittest discover -v tests            # 在專案根目錄執行
xvfb-run python -m unittest discover -v tests   # 沒有桌面的 Linux，讓 GUI 測試也能跑
```

- `test_e2e.py`：真的開伺服器走完整加密通道（交易、非法輸入、鎖定、竄改、重放、並發、逾時、連線上限）。
- `test_gui.py`：操作真正的 Tkinter 視窗；沒有 Tkinter 或顯示器時自動略過。**只要動到 `client_mlkem.py`，
  就必須在有顯示器（或 xvfb）的環境跑過這一組**，略過不算通過。
- `test_architecture.py`：第 2 節的規則。
- GUI 測試依賴這些屬性名稱，改名時要一起改測試：`ip_entry`、`acct_entry`、`pin_entry`、`connect_btn`、
  `connect_frame`、`main_frame`、`action_buttons`、`balance_var`、`log_text`、`session`、`busy`、`root`。

## 7. 已知限制（不是 bug，別順手「修」）

- 帳戶資料只在記憶體，伺服器重啟就還原成 `bank.DEMO_ACCOUNTS`。
- 只驗證伺服器身分（首次連線信任並釘選公鑰）；ATM 端沒有裝置憑證，靠帳號＋PIN。
- `kyber-py`、`dilithium-py` 是純 Python 教學實作，非常數時間，不適合正式環境。
- Git 歷史裡有一把早期誤傳的 `key.pem`，視為已外洩，任何地方都不要使用。
