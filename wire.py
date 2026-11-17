"""
客戶端與伺服器之間的訊息契約 —— 欄位名稱與金額規則的唯一來源。只依賴標準函式庫。

  請求（client → server）           回應（server → client）
    login     account, pin            success  bool
    logout                            message  str，直接顯示給使用者
    balance                           balance  "123.45"，與帳戶有關時才有
    deposit   amount
    withdraw  amount
    transfer  target, amount

金額一律以字串 "123.45" 傳輸，兩端都用 Decimal 處理，不經過浮點數。
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

CENT = Decimal("0.01")
MAX_TX_AMOUNT = Decimal("1000000")  # 單筆上限


def parse_amount(raw, invalid: str = "金額格式錯誤") -> Decimal:
    """驗證金額（正數、最多兩位小數、不超過單筆上限）；不合格時丟 ValueError(給使用者看的訊息)。"""
    if isinstance(raw, bool) or not isinstance(raw, (str, int)):
        raise ValueError(invalid)
    try:
        amount = Decimal(str(raw))
    except InvalidOperation:
        raise ValueError(invalid) from None
    if not amount.is_finite():
        raise ValueError(invalid)
    if amount <= 0:
        raise ValueError("金額需大於零")
    if amount > MAX_TX_AMOUNT:  # 先檢查範圍，避免極大指數讓 quantize 出錯
        raise ValueError(f"單筆金額上限為 {MAX_TX_AMOUNT:,} 元")
    if amount != amount.quantize(CENT):
        raise ValueError("金額最多到小數點後兩位")
    return amount.quantize(CENT)


def format_amount(amount: Decimal) -> str:
    return f"{amount:.2f}"


# ---------------------------------------------------------------- 請求
def login(account: str, pin: str) -> dict:
    return {"type": "login", "account": account, "pin": pin}


def logout() -> dict:
    return {"type": "logout"}


def balance() -> dict:
    return {"type": "balance"}


def deposit(amount: str) -> dict:
    return {"type": "deposit", "amount": amount}


def withdraw(amount: str) -> dict:
    return {"type": "withdraw", "amount": amount}


def transfer(target: str, amount: str) -> dict:
    return {"type": "transfer", "target": target, "amount": amount}


# ---------------------------------------------------------------- 回應
def reply(success: bool, message: str, balance: Decimal | None = None) -> dict:
    resp = {"success": success, "message": message}
    if balance is not None:
        resp["balance"] = format_amount(balance)
    return resp


def is_reply(resp: dict) -> bool:
    return isinstance(resp.get("success"), bool) and isinstance(resp.get("message"), str)
