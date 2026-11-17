"""
帳務邏輯：帳戶、PIN 驗證與鎖定、存提款與轉帳。

不碰網路也不碰訊息格式；每個操作回傳 Result(success, message, balance)，
由 server_mlkem.py 轉成回應。所有餘額變動都在帳戶鎖內完成。
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import threading
import time
from decimal import Decimal
from typing import NamedTuple

MAX_PIN_ATTEMPTS = 3
PIN_LOCKOUT_SECONDS = 300  # 連續輸錯後的鎖定時間
MAX_PIN_LENGTH = 12

# 示範帳戶：(帳號, 初始餘額, PIN)
DEMO_ACCOUNTS = (
    ("1001", "100000.00", "1234"),
    ("1002", "50000.00", "5678"),
)


class Result(NamedTuple):
    success: bool
    message: str
    balance: Decimal | None = None


def _hash_pin(pin: str, salt: bytes) -> bytes:
    return hashlib.scrypt(pin.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


class Account:
    def __init__(self, number: str, balance: str, pin: str):
        self.number = number
        self.balance = Decimal(balance)
        self.salt = os.urandom(16)
        self.pin_hash = _hash_pin(pin, self.salt)
        self.failed_attempts = 0
        self.locked_until = 0.0  # time.monotonic() 時間點
        self.lock = threading.Lock()

    def check_pin(self, pin: str) -> bool:
        return hmac.compare_digest(_hash_pin(pin, self.salt), self.pin_hash)


class Bank:
    def __init__(self, accounts=DEMO_ACCOUNTS, lockout_seconds: float = PIN_LOCKOUT_SECONDS):
        self.lockout_seconds = lockout_seconds
        self.accounts = {number: Account(number, balance, pin) for number, balance, pin in accounts}

    # -- auth
    def login(self, number, pin) -> tuple[Account | None, Result]:
        acct = self.accounts.get(number) if isinstance(number, str) else None
        if acct is None or not isinstance(pin, str) or not 0 < len(pin) <= MAX_PIN_LENGTH:
            return None, Result(False, "帳號或 PIN 錯誤")
        with acct.lock:
            remaining = acct.locked_until - time.monotonic()
            if remaining > 0:
                return None, Result(False, f"帳戶已鎖定，請於 {math.ceil(remaining)} 秒後再試")
            if not acct.check_pin(pin):
                acct.failed_attempts += 1
                left = MAX_PIN_ATTEMPTS - acct.failed_attempts
                if left > 0:
                    return None, Result(False, f"帳號或 PIN 錯誤（剩餘 {left} 次）")
                # 限時鎖定而非永久鎖定：擋得住暴力猜 PIN，又不會讓任何人都能把帳戶永久鎖死
                acct.failed_attempts = 0
                acct.locked_until = time.monotonic() + self.lockout_seconds
                return None, Result(
                    False, f"PIN 連續錯誤 {MAX_PIN_ATTEMPTS} 次，帳戶已鎖定 {math.ceil(self.lockout_seconds)} 秒")
            acct.failed_attempts = 0
            return acct, Result(True, "登入成功", acct.balance)

    # -- transactions
    @staticmethod
    def reject(acct: Account, message: str) -> Result:
        """操作被拒（輸入不合法等）；回應仍附上目前餘額。"""
        return Result(False, message, acct.balance)

    def balance(self, acct: Account) -> Result:
        with acct.lock:
            return Result(True, "餘額查詢成功", acct.balance)

    def deposit(self, acct: Account, amount: Decimal) -> Result:
        with acct.lock:
            acct.balance += amount
            return Result(True, f"成功存入 {amount:,.2f} 元", acct.balance)

    def withdraw(self, acct: Account, amount: Decimal) -> Result:
        with acct.lock:
            if acct.balance < amount:
                return Result(False, "餘額不足", acct.balance)
            acct.balance -= amount
            return Result(True, f"成功取出 {amount:,.2f} 元", acct.balance)

    def transfer(self, src: Account, target_no, amount: Decimal) -> Result:
        target = self.accounts.get(target_no) if isinstance(target_no, str) else None
        if target is None:
            return self.reject(src, "目標帳號不存在")
        if target is src:
            return self.reject(src, "不可轉帳給自己")
        # 依帳號排序取鎖，避免兩筆反向轉帳互相死結
        first, second = sorted((src, target), key=lambda a: a.number)
        with first.lock, second.lock:
            if src.balance < amount:
                return Result(False, "餘額不足", src.balance)
            src.balance -= amount
            target.balance += amount
            return Result(True, f"成功轉帳 {amount:,.2f} 元至 {target.number}", src.balance)
