"""架構守門：模組依賴方向、檔案大小上限、AGENTS.md 是否同步。規則說明見 AGENTS.md。"""
import ast
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAX_LINES = 400

# 模組 → 允許 import 的專案內模組。新增模組時要在這裡登記，並更新 AGENTS.md 的模組表。
ALLOWED = {
    "wire": set(),
    "protocol": set(),
    "bank": set(),
    "atm_client": {"wire", "protocol"},
    "server_mlkem": {"wire", "protocol", "bank"},
    "client_mlkem": {"wire", "atm_client"},
}
# 模組 → 允許使用的非標準函式庫（tkinter 雖是標準函式庫，但只有 GUI 可以用）
EXTERNAL = {
    "protocol": {"cryptography", "kyber_py", "dilithium_py"},
    "client_mlkem": {"tkinter"},
}


def imports_of(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            yield node.module.split(".")[0]


class ArchitectureTest(unittest.TestCase):
    def test_modules_follow_the_rules(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        modules = sorted(p for p in ROOT.glob("*.py"))
        self.assertEqual({p.stem for p in modules}, set(ALLOWED), "根目錄的模組必須和 ALLOWED 一致")
        for path in modules:
            name = path.stem
            with self.subTest(module=name):
                self.assertIn(f"`{path.name}`", agents, "AGENTS.md 的模組表沒有列出這個檔案")
                self.assertLessEqual(len(path.read_text(encoding="utf-8").splitlines()), MAX_LINES,
                                     "檔案太長，請依職責拆分")
                for imported in set(imports_of(path)):
                    if imported in ALLOWED:
                        self.assertIn(imported, ALLOWED[name], f"{name} 不可以 import {imported}")
                    elif imported == "tkinter" or imported not in sys.stdlib_module_names:
                        self.assertIn(imported, EXTERNAL.get(name, ()), f"{name} 不可以使用 {imported}")


if __name__ == "__main__":
    unittest.main()
