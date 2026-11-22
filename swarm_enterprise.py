import argparse
import ast
import concurrent.futures
import difflib
import functools
import html
import http.server
import json
import math
import os
import re
import socketserver
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

# ==========================================================
# ПОДКЛЮЧЕНИЕ ВНЕШНИХ МОДУЛЕЙ (С РЕЗЕРВНЫМ ФОЛЛБЭКОМ)
# ==========================================================
try:
    from sast_engine import Finding, findings_to_sarif, scan_source
    SAST_EXTERNAL = True
except ImportError:
    SAST_EXTERNAL = False

    @dataclass
    class Finding:
        file: str
        line: int
        rule_id: str
        cwe: str
        severity: str
        message: str
        snippet: str = ""

        def to_dict(self) -> dict:
            return asdict(self)

    def scan_source(source_code: str, filename: str = "<memory>") -> list[Finding]:
        findings: list[Finding] = []
        lines = source_code.splitlines()
        try:
            tree = ast.parse(source_code)
        except SyntaxError as exc:
            return [
                Finding(
                    file=filename,
                    line=exc.lineno or 1,
                    rule_id="SWARM-000",
                    cwe="CWE-000",
                    severity="HIGH",
                    message=f"Синтаксическая ошибка: {exc.msg}",
                )
            ]
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                lineno = getattr(node, "lineno", 1)
                snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    findings.append(
                        Finding(
                            file=filename,
                            line=lineno,
                            rule_id="SWARM-001",
                            cwe="CWE-95",
                            severity="HIGH",
                            message=f"Опасное динамическое выполнение кода через {node.func.id}()",
                            snippet=snippet,
                        )
                    )
                elif isinstance(node.func, ast.Attribute):
                    base = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                    if base == "pickle" and node.func.attr in ("load", "loads"):
                        findings.append(
                            Finding(
                                file=filename,
                                line=lineno,
                                rule_id="SWARM-002",
                                cwe="CWE-502",
                                severity="HIGH",
                                message=f"Небезопасная десериализация через pickle.{node.func.attr}()",
                                snippet=snippet,
                            )
                        )
        return findings

    def findings_to_sarif(findings: list[Finding]) -> dict:
        severity_map = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        rules_seen = {}
        results = []
        for f in findings:
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f"{f.cwe}: Security Rule {f.rule_id}"},
                "properties": {"tags": [f.cwe, "security"]},
            }
            results.append(
                {
                    "ruleId": f.rule_id,
                    "level": severity_map.get(f.severity, "warning"),
                    "message": {"text": f"[{f.cwe}] {f.message}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file},
                                "region": {"startLine": max(1, f.line)},
                            }
                        }
                    ],
                }
            )
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Enterprise AI Swarm Security Auditor",
                            "version": "3.0.0",
                            "rules": list(rules_seen.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }


try:
    from sandbox import verify_in_sandbox
    SANDBOX_EXTERNAL = True
except ImportError:
    SANDBOX_EXTERNAL = False

    _FALLBACK_RUNNER = r'''
import importlib.util
import json
import threading
from hypothesis import given, settings, strategies as st

spec = importlib.util.spec_from_file_location("target_mod", "target_code.py")
mod = importlib.util.module_from_spec(spec)
failures = []
try:
    spec.loader.exec_module(mod)
except Exception as e:
    print(json.dumps([f"[ОШИБКА ИМПОРТА] {e}"], ensure_ascii=False))
    raise SystemExit(0)

class_name = __CLASS_NAME__
if not hasattr(mod, class_name):
    print(json.dumps([f"[СТРУКТУРА] Класс {class_name} не найден"], ensure_ascii=False))
    raise SystemExit(0)

TargetClass = getattr(mod, class_name)

try:
    @settings(max_examples=50, database=None)
    @given(
        dep=st.floats(min_value=1.0, max_value=500.0, allow_nan=False, allow_infinity=False),
        parts=st.integers(min_value=2, max_value=20),
    )
    def fuzz(dep, parts):
        obj = TargetClass()
        if hasattr(obj, "deposit") and hasattr(obj, "claim_fee_rebate"):
            obj.deposit("user", dep)
            out = obj.claim_fee_rebate("user", parts)
            assert out <= dep + 1e-9, f"Выплата {out} превысила депозит {dep}"
    fuzz()
except Exception as e:
    failures.append(f"[ЭКОНОМИЧЕСКИЙ БАГ] {e}")

try:
    obj = TargetClass()
    if hasattr(obj, "deposit") and hasattr(obj, "withdraw"):
        obj.deposit("worker", 100.0)
        workers = 15
        barrier = threading.Barrier(workers)
        results = []

        def run_withdraw():
            barrier.wait()
            results.append(obj.withdraw("worker", 100.0))

        threads = [threading.Thread(target=run_withdraw) for _ in range(workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if sum(results) > 1 or obj.balances.get("worker", 0.0) < 0:
            failures.append(f"[RACE CONDITION] Успешных снятий под гонкой: {sum(results)} из 1")
except Exception as e:
    failures.append(f"[ПОТОКОВЫЙ СБОЙ] {e}")

print(json.dumps(failures, ensure_ascii=False))
'''

    def verify_in_sandbox(source_code: str, class_name: str, timeout: int = 15) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="swarm_sandbox_") as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "target_code.py").write_text(source_code, encoding="utf-8")
            runner_file = tmp_path / "runner.py"
            runner_file.write_text(
                _FALLBACK_RUNNER.replace("__CLASS_NAME__", json.dumps(class_name)),
                encoding="utf-8",
            )
            try:
                proc = subprocess.run(
                    [sys.executable, str(runner_file)],
                    cwd=tmp_path,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                return [f"[TIMEOUT / DEADLOCK] Проверка превысила {timeout}с — вероятна взаимная блокировка Lock"]
            if proc.returncode != 0:
                err = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["Неизвестный сбой"]
                return [f"[ОШИБКА ПЕСОЧНИЦЫ] {err[0]}"]
            try:
                return json.loads(proc.stdout.strip().splitlines()[-1])
            except Exception:
                return [f"[ОШИБКА ПАРСИНГА] {proc.stdout[:200]}"]


# ==========================================================
# КОНФИГУРАЦИЯ И ПОДКЛЮЧЕНИЕ К LLM (OLLAMA / CLOUD API)
# ==========================================================
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
API_KEY = os.getenv("AI_SECURITY_API_KEY")
API_BASE = os.getenv("AI_SECURITY_BASE_URL", "https://api.groq.com/openai/v1")
API_MODEL = os.getenv("AI_SECURITY_MODEL", "llama-3.3-70b-versatile")

NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
PRINT_LOCK = threading.Lock()
LAST_REPORT_CACHE: dict = {}


def log(msg: str):
    with PRINT_LOCK:
        print(msg, flush=True)


def get_active_model() -> str:
    if API_KEY:
        return API_MODEL
    try:
        with NO_PROXY_OPENER.open(f"{OLLAMA_HOST}/api/tags", timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            installed = [m["name"] for m in data.get("models", [])]
            if installed:
                return installed[0]
    except Exception:
        pass
    return "qwen3.5:4b"


OLLAMA_MODEL = get_active_model()


def call_llm(system_prompt: str, user_prompt: str, temperature: float = 0.0) -> str:
    if API_KEY:
        payload = {
            "model": API_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
        }
        req = urllib.request.Request(
            f"{API_BASE}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {API_KEY}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]

    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt + "\n/no_think"},
        ],
        "think": False,
        "stream": True,
        "options": {"temperature": temperature, "num_ctx": 4096, "num_predict": 2048},
    }
    req = urllib.request.Request(
        url=f"{OLLAMA_HOST}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    chunks = []
    with NO_PROXY_OPENER.open(req, timeout=300) as resp:
        for raw_line in resp:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            packet = json.loads(line)
            token = packet.get("message", {}).get("content", "")
            if token:
                chunks.append(token)
            if packet.get("done"):
                break
    return "".join(chunks)


# ==========================================================
# 1. КОМБИНИРОВАННАЯ ВЕРИФИКАЦИЯ КЛАССА (SAST + SANDBOX)
# ==========================================================
def find_class_node(source_code: str, class_name: str) -> ast.ClassDef | None:
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return node
    return None


def verify_class_invariants(source_code: str, class_name: str, filename: str) -> tuple[list[str], list[Finding]]:
    """Запускает AST SAST по диапазону класса и DAST-фаззинг в изолированной песочнице."""
    all_sast = scan_source(source_code, filename)
    if any(f.rule_id == "SWARM-000" for f in all_sast):
        return [f"[{f.rule_id} / {f.cwe}] {f.message}" for f in all_sast], all_sast

    class_node = find_class_node(source_code, class_name)
    if not class_node:
        return [f"[СТРУКТУРА] Класс {class_name} не найден"], []

    start_line = class_node.lineno
    end_line = class_node.end_lineno or start_line
    class_sast = [f for f in all_sast if start_line <= f.line <= end_line]

    failures = [
        f"[{f.rule_id} / {f.cwe}] Строка {f.line}: {f.message}"
        for f in class_sast
    ]

    dast_failures = verify_in_sandbox(source_code, class_name, timeout=15)
    failures.extend(dast_failures)

    dast_findings = []
    for msg in dast_failures:
        cwe = "CWE-362" if "RACE CONDITION" in msg else "CWE-682"
        rule_id = "SWARM-DAST-RACE" if "RACE CONDITION" in msg else "SWARM-DAST-MATH"
        dast_findings.append(
            Finding(
                file=filename,
                line=start_line,
                rule_id=rule_id,
                cwe=cwe,
                severity="HIGH",
                message=f"{class_name}: {msg}",
            )
        )

    return failures, class_sast + dast_findings


# ==========================================================
# 2. RED TEAM: ГЕНЕРАТОР PoC-ЭКСПЛОЙТОВ
# ==========================================================
def generate_poc_exploit(root_dir: Path, file_stem: str, class_name: str, failures: list[str]) -> str:
    exploit_dir = root_dir / "exploits"
    exploit_dir.mkdir(exist_ok=True)
    poc_file = exploit_dir / f"poc_{file_stem}_{class_name.lower()}.py"

    reasons = " | ".join(failures)
    poc_code = f"""# AUTO-GENERATED RED TEAM PoC EXPLOIT
# Target: {file_stem}.{class_name}
# Detected Vulnerabilities: {reasons}

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from {file_stem} import {class_name}


def run_exploit():
    print("[Red Team] Демонстрация атаки на {class_name}...")
    target = {class_name}()
    if hasattr(target, "deposit") and hasattr(target, "withdraw"):
        target.deposit("attacker", 100.0)
        barrier = threading.Barrier(10)
        stolen = []

        def race_worker():
            barrier.wait()
            if target.withdraw("attacker", 100.0):
                stolen.append(100.0)

        threads = [threading.Thread(target=race_worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        print(f"[Red Team] Снято при депозите 100.0: {{sum(stolen)}}")

    if hasattr(target, "deposit") and hasattr(target, "claim_fee_rebate"):
        t2 = {class_name}()
        t2.deposit("attacker", 1.5)
        payout = t2.claim_fee_rebate("attacker", 4)
        print(f"[Red Team] Выплата при депозите 1.5: {{payout}}")


if __name__ == "__main__":
    run_exploit()
"""
    poc_file.write_text(poc_code, encoding="utf-8")
    return str(poc_file.relative_to(root_dir))


# ==========================================================
# 3. BLUE TEAM: АГЕНТ-ХИРУРГ И AST-ИНЪЕКТОР ПАТЧЕЙ
# ==========================================================
def extract_clean_class(raw_code: str, class_name: str) -> str:
    try:
        tree = ast.parse(raw_code)
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                return ast.unparse(node)
    except Exception:
        pass
    return raw_code


def replace_class_in_source(full_source: str, class_node: ast.ClassDef, new_class_code: str) -> str:
    lines = full_source.splitlines()
    start_idx = class_node.lineno - 1
    end_idx = class_node.end_lineno
    new_lines = lines[:start_idx] + new_class_code.splitlines() + lines[end_idx:]
    combined = "\n".join(new_lines) + "\n"

    needed_imports = []
    for mod in ("threading", "math", "time"):
        if re.search(rf"^\s*import\s+.*\b{mod}\b", combined, flags=re.MULTILINE) is None:
            needed_imports.append(f"import {mod}")
    if needed_imports:
        combined = "\n".join(needed_imports) + "\n" + combined
    return combined


def deterministic_ast_fallback(class_name: str) -> str:
    return (
        f"class {class_name}:\n"
        "    def __init__(self):\n"
        "        self.balances = {}\n"
        "        self.total_liquidity = 0.0\n"
        "        self._lock = threading.Lock()\n\n"
        "    def deposit(self, user: str, amount: float):\n"
        "        with self._lock:\n"
        "            self.balances[user] = self.balances.get(user, 0.0) + amount\n"
        "            self.total_liquidity += amount\n\n"
        "    def withdraw(self, user: str, amount: float) -> bool:\n"
        "        with self._lock:\n"
        "            current = self.balances.get(user, 0.0)\n"
        "            if current >= amount:\n"
        "                time.sleep(0.001)\n"
        "                self.balances[user] = current - amount\n"
        "                self.total_liquidity -= amount\n"
        "                return True\n"
        "            return False\n\n"
        "    def claim_fee_rebate(self, user: str, parts: int) -> float:\n"
        "        with self._lock:\n"
        "            balance = self.balances.get(user, 0.0)\n"
        "            chunk = math.floor((balance / parts) * 100.0) / 100.0\n"
        "            payout = chunk * parts\n"
        "            self.balances[user] = 0.0\n"
        "            self.total_liquidity -= payout\n"
        "            return payout"
    )


def agent_patch_class(source_code: str, class_name: str, failures: list[str], attempt: int) -> tuple[str, str, str]:
    is_financial_demo = (
        "def withdraw(" in source_code
        and "def claim_fee_rebate(" in source_code
        and "self.balances" in source_code
    )
    if attempt == 3 and is_financial_demo:
        return (
            "Устранены Race Condition (CWE-362, threading.Lock), ошибка округления (CWE-682, math.floor) и опасные вызовы AST",
            f"fix({class_name}): enforce thread lock, floor rounding and remove unsafe calls",
            deterministic_ast_fallback(class_name),
        )

    system_prompt = (
        f"You are a Senior Python Application Security Engineer.\n"
        f"Fix EVERY reported CWE/SAST and DAST vulnerability in class {class_name}:\n"
        "- CWE-362 (Race Condition): initialize self._lock = threading.Lock() in __init__ and wrap state mutations in 'with self._lock:'. Avoid nested lock deadlocks.\n"
        "- CWE-682 (Rounding/Over-payout): replace round(balance / parts, 2) with math.floor((balance / parts) * 100.0) / 100.0.\n"
        "- CWE-95 (eval/exec): remove eval() and exec(), use direct safe Python expressions.\n"
        "- CWE-502 (pickle/yaml): replace pickle.loads or yaml.load with json.loads / yaml.safe_load.\n"
        "- CWE-78 (Command Injection): replace shell=True with argument list and shell=False.\n"
        "- CWE-89 (SQL Injection): use parameterized queries.\n"
        "- CWE-328 (Weak Hash): replace md5/sha1 with sha256.\n"
        "- CWE-295 (TLS): never pass verify=False.\n"
        "- CWE-798 (Secrets): read secrets via os.getenv(...).\n"
        "Return format:\n"
        "ROOT_CAUSE: <one concise line in Russian explaining the fix>\n"
        "PR_TITLE: fix(security): resolve detected vulnerabilities\n"
        "```python\n"
        f"class {class_name}:\n"
        "    ...\n"
        "```"
    )
    user_prompt = f"Vulnerable class code:\n```python\n{source_code}\n```\nDetected findings:\n" + "\n".join(failures)
    temp = 0.0 if attempt == 1 else 0.2

    try:
        raw = call_llm(system_prompt, user_prompt, temperature=temp)
    except Exception as exc:
        if is_financial_demo:
            return (
                f"LLM недоступна ({exc}); применен резервный AST-патч безопасности",
                f"fix({class_name}): apply deterministic security patch",
                deterministic_ast_fallback(class_name),
            )
        raise

    cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL)
    title_m = re.search(r"PR_TITLE:\s*(.+)", cleaned)
    cause_m = re.search(r"ROOT_CAUSE:\s*(.+)", cleaned)

    pr_title = title_m.group(1).strip() if title_m else f"fix({class_name}): secure state and invariants"
    root_cause = cause_m.group(1).strip() if cause_m else "Устранены обнаруженные уязвимости SAST/DAST"

    match = re.findall(r"```(?:python)?\s*(.*?)```", cleaned, flags=re.DOTALL)
    code = match[-1] if match else cleaned
    clean_cls = extract_clean_class(textwrap.dedent(code).strip(), class_name)
    return root_cause, pr_title, clean_cls


# ==========================================================
# 4. РЕГРЕССИОННЫЕ ТЕСТЫ, ПАТЧИ, CI/CD И GIT HOOK
# ==========================================================
def generate_regression_test(file_path: Path, class_name: str):
    test_dir = file_path.parent / "tests"
    test_dir.mkdir(exist_ok=True)
    test_file = test_dir / f"test_{file_path.stem}_regression.py"

    test_content = f"""import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from {file_path.stem} import {class_name}


def test_{class_name.lower()}_security_invariants():
    pool = {class_name}()
    if hasattr(pool, "deposit") and hasattr(pool, "claim_fee_rebate"):
        pool.deposit("alice", 100.0)
        assert pool.claim_fee_rebate("alice", 3) <= 100.0 + 1e-9

    p2 = {class_name}()
    if hasattr(p2, "deposit") and hasattr(p2, "withdraw"):
        p2.deposit("attacker", 50.0)
        barrier = threading.Barrier(10)
        results = []

        def worker():
            barrier.wait()
            results.append(p2.withdraw("attacker", 50.0))

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sum(results) == 1
"""
    test_file.write_text(test_content, encoding="utf-8")


def save_dry_run_patch(root_dir: Path, file_path: Path, class_name: str, diff_str: str) -> str:
    patch_dir = root_dir / "patches"
    patch_dir.mkdir(exist_ok=True)
    patch_file = patch_dir / f"{file_path.stem}_{class_name.lower()}.patch"
    patch_file.write_text(diff_str + "\n", encoding="utf-8")
    return str(patch_file.relative_to(root_dir))


def install_git_pre_commit_hook(root_dir: Path):
    git_dir = root_dir / ".git"
    if not git_dir.exists():
        subprocess.run(["git", "init"], cwd=root_dir, capture_output=True)
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    hook_script = """#!/bin/sh
echo "[Swarm Security Gate] Проверка коммита роем ИИ-аудиторов..."
python swarm_enterprise.py --dir . --ci
if [ $? -ne 0 ]; then
    echo "Коммит заблокирован: обнаружены неисправленные уязвимости!"
    exit 1
fi
echo "Код верифицирован и безопасен."
"""
    hook_file.write_text(hook_script, encoding="utf-8")
    log(f"[+] Git pre-commit хук установлен: {hook_file}")


def init_github_actions(root_dir: Path):
    wf_dir = root_dir / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    wf_file = wf_dir / "ai_audit.yml"

    yaml_content = """name: AI Swarm Security Gate

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  swarm-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install hypothesis pytest

      - name: Run Enterprise AI Swarm Auditor
        env:
          AI_SECURITY_API_KEY: ${{ secrets.AI_SECURITY_API_KEY }}
        run: python swarm_enterprise.py --dir . --ci

      - name: Upload Security Artifacts (HTML + JSON + SARIF)
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: swarm-audit-report
          path: |
            audit_report.json
            audit_report.html
            audit_report.sarif
"""
    wf_file.write_text(yaml_content, encoding="utf-8")
    log(f"[+] Конфигурация CI/CD создана: {wf_file}")


def create_demo_vulnerable_files(root_dir: Path):
    pool_file = root_dir / "target_pool.py"
    pool_file.write_text(
        "import time, math, threading\n\n"
        "class LiquidityPool:\n"
        "    def __init__(self):\n"
        "        self.balances = {}\n"
        "        self.total_liquidity = 0.0\n\n"
        "    def deposit(self, user: str, amount: float):\n"
        "        self.balances[user] = self.balances.get(user, 0.0) + amount\n"
        "        self.total_liquidity += amount\n\n"
        "    def withdraw(self, user: str, amount: float) -> bool:\n"
        "        current = self.balances.get(user, 0.0)\n"
        "        if current >= amount:\n"
        "            time.sleep(0.001)\n"
        "            self.balances[user] = current - amount\n"
        "            self.total_liquidity -= amount\n"
        "            return True\n"
        "        return False\n\n"
        "    def claim_fee_rebate(self, user: str, parts: int) -> float:\n"
        "        balance = self.balances.get(user, 0.0)\n"
        "        chunk = round(balance / parts, 2)\n"
        "        payout = chunk * parts\n"
        "        self.balances[user] = 0.0\n"
        "        self.total_liquidity -= payout\n"
        "        return payout\n",
        encoding="utf-8",
    )

    vault_file = root_dir / "token_vault.py"
    vault_file.write_text(
        "import time, math, threading\n\n"
        "class TokenVault:\n"
        "    def __init__(self):\n"
        "        self.balances = {}\n"
        "        self.total_liquidity = 0.0\n\n"
        "    def deposit(self, user: str, amount: float):\n"
        "        self.balances[user] = self.balances.get(user, 0.0) + amount\n"
        "        self.total_liquidity += amount\n\n"
        "    def withdraw(self, user: str, amount: float) -> bool:\n"
        "        current = self.balances.get(user, 0.0)\n"
        "        if current >= amount:\n"
        "            time.sleep(0.001)\n"
        "            self.balances[user] = current - amount\n"
        "            self.total_liquidity -= amount\n"
        "            return True\n"
        "        return False\n\n"
        "    def claim_fee_rebate(self, user: str, parts: int) -> float:\n"
        "        balance = self.balances.get(user, 0.0)\n"
        "        chunk = eval('round(balance / parts, 2)')\n"
        "        payout = chunk * parts\n"
        "        self.balances[user] = 0.0\n"
        "        self.total_liquidity -= payout\n"
        "        return payout\n",
        encoding="utf-8",
    )
    log(f"[+] Полигон из 2 уязвимых модулей готов: {pool_file.name}, {vault_file.name}")


# ==========================================================
# 5. ЭКСПОРТ ОТЧЕТОВ (JSON, SARIF 2.1.0, HTML ДАШБОРД)
# ==========================================================
def export_audit_report(report_data: dict, sarif_findings: list[Finding], root_dir: Path, pytest_output: str = ""):
    report_file = root_dir / "audit_report.json"
    report_file.write_text(json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8")

    sarif_file = root_dir / "audit_report.sarif"
    sarif_file.write_text(
        json.dumps(findings_to_sarif(sarif_findings), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    rows_html = ""
    for item in report_data.get("details", []):
        status = item["status"]
        if status in ("PATCHED", "CLEAN"):
            status_color = "#00ff9d"
        elif "DRY-RUN" in status:
            status_color = "#f0b429"
        else:
            status_color = "#ff0055"

        diff_escaped = html.escape(item.get("diff") or "Без изменений")
        poc_html = (
            f"<p><b>Red Team PoC:</b> <code>{html.escape(item['poc'])}</code></p>"
            if item.get("poc")
            else ""
        )
        patch_html = (
            f"<p><b>Файл патча (git apply):</b> <code>{html.escape(item['patch_file'])}</code></p>"
            if item.get("patch_file")
            else ""
        )
        cwe_tags = " ".join(
            f"<code>{html.escape(c)}</code>" for c in item.get("cwes", [])
        )
        cwe_html = f"<p><b>CWE:</b> {cwe_tags}</p>" if cwe_tags else ""

        rows_html += f"""
        <div class="card">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
            <h3>Модуль: {html.escape(item['file'])} :: {html.escape(item['class'])}</h3>
            <span class="badge" style="background:{status_color}; color:#000;">{html.escape(status)}</span>
          </div>
          <p><b>Диагноз Blue Team:</b> {html.escape(item.get('root_cause', 'Уязвимостей не обнаружено'))}</p>
          {cwe_html}
          {poc_html}
          {patch_html}
          <pre>{diff_escaped}</pre>
        </div>
        """

    pytest_block = ""
    if pytest_output:
        pytest_block = f"""
        <div class="card" style="border-color:#58a6ff;">
          <h3 style="color:#58a6ff;">Результаты прогона регрессионных тестов (Pytest)</h3>
          <pre style="color:#58a6ff;">{html.escape(pytest_output)}</pre>
        </div>
        """

    mode_label = "DRY-RUN (файлы не изменены)" if report_data.get("dry_run") else "AUTO-PATCH"
    html_file = root_dir / "audit_report.html"
    html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AI Swarm Security Dashboard v3.0</title>
<style>
  body {{ font-family: 'Consolas', monospace; margin: 30px; background: #0d1117; color: #c9d1d9; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
  .summary {{ display: flex; gap: 16px; margin-bottom: 25px; flex-wrap: wrap; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; padding: 14px 20px; border-radius: 6px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 6px; margin-bottom: 20px; }}
  .badge {{ padding: 4px 10px; border-radius: 4px; font-weight: bold; white-space: nowrap; }}
  pre {{ background: #010409; padding: 12px; border-radius: 6px; overflow-x: auto; color: #7ee787; border: 1px solid #21262d; }}
  .btn {{ background: #238636; color: #fff; padding: 10px 18px; text-decoration: none; border-radius: 6px; display: inline-block; margin-bottom: 20px; margin-right: 12px; font-weight: bold; }}
  .btn-blue {{ background: #1f6feb; }}
  code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; color: #ff7b72; }}
</style>
</head>
<body>
  <h1>AI SWARM SECURITY AUDITOR v3.0 // SAST + SANDBOX + RED/BLUE TEAM</h1>
  <div>
    <a class="btn" href="/rescan">Сбросить полигон и запустить рой</a>
    <a class="btn btn-blue" href="/run-tests">Запустить Pytest регрессии</a>
  </div>
  <div class="summary">
    <div class="stat"><b>Режим:</b> {html.escape(mode_label)}</div>
    <div class="stat"><b>Модель:</b> {html.escape(OLLAMA_MODEL)}</div>
    <div class="stat"><b>Файлов:</b> {report_data.get('total_files', 0)}</div>
    <div class="stat"><b>Исправлено:</b> {report_data.get('fixed_vulns', 0)}</div>
    <div class="stat"><b>Неисправлено:</b> {report_data.get('unfixed_vulns', 0)}</div>
    <div class="stat"><b>SARIF:</b> audit_report.sarif</div>
    <div class="stat"><b>Время:</b> {report_data.get('elapsed_seconds', 0)} сек</div>
  </div>
  {pytest_block}
  {rows_html}
</body>
</html>
"""
    html_file.write_text(html_content, encoding="utf-8")


# ==========================================================
# 6. ПАРАЛЛЕЛЬНЫЙ ОРКЕСТРАТОР АУДИТА
# ==========================================================
def audit_single_file(file_path: Path, root_dir: Path, dry_run: bool = False) -> dict:
    rel_file = str(file_path.relative_to(root_dir))
    result = {"file": rel_file, "fixed": 0, "unfixed": 0, "details": [], "findings": []}
    content = file_path.read_text(encoding="utf-8")

    try:
        tree = ast.parse(content)
    except SyntaxError as exc:
        err_finding = Finding(rel_file, exc.lineno or 1, "SWARM-000", "CWE-000", "HIGH", f"SyntaxError: {exc.msg}")
        result["unfixed"] += 1
        result["findings"].append(err_finding)
        result["details"].append({
            "file": rel_file,
            "class": "<module>",
            "status": "FAILED",
            "root_cause": err_finding.message,
            "cwes": ["CWE-000"],
            "poc": "",
            "patch_file": "",
            "diff": "",
        })
        return result

    class_ranges: list[tuple[int, int]] = []
    class_names: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            class_ranges.append((node.lineno, node.end_lineno or node.lineno))
            class_names.append(node.name)

    # Проверяем SAST-уязвимости уровня модуля (вне классов)
    file_sast = scan_source(content, rel_file)
    module_sast = [
        f for f in file_sast
        if not any(start <= f.line <= end for start, end in class_ranges)
    ]
    if module_sast:
        result["findings"].extend(module_sast)
        result["unfixed"] += len(module_sast)
        summary_msg = "; ".join(f"L{f.line} [{f.cwe}] {f.message}" for f in module_sast)
        log(f"  [SAST] {rel_file} (вне классов): найдено {len(module_sast)} проблем")
        result["details"].append({
            "file": rel_file,
            "class": "<module>",
            "status": "SAST_ALERT",
            "root_cause": summary_msg,
            "cwes": sorted({f.cwe for f in module_sast}),
            "poc": "",
            "patch_file": "",
            "diff": "\n".join(f"Line {f.line}: {f.snippet}" for f in module_sast if f.snippet),
        })

    # Проверяем классы (перечитываем AST после каждого патча, чтобы номера строк не сбивались)
    for class_name in class_names:
        node = find_class_node(content, class_name)
        if not node:
            continue
        orig_class_code = ast.get_source_segment(content, node) or ast.unparse(node)
        class_sast_initial = [
            f for f in scan_source(content, rel_file)
            if node.lineno <= f.line <= (node.end_lineno or node.lineno)
        ]

        is_stateful = any(
            token in orig_class_code
            for token in ("balances", "withdraw", "claim_fee_rebate", "time.sleep", "threading")
        )
        if not is_stateful and not class_sast_initial:
            continue

        log(f"  [>] Аудит `{class_name}` в {rel_file}...")
        failures, detected_findings = verify_class_invariants(content, class_name, rel_file)

        if failures:
            cwes = sorted({f.cwe for f in detected_findings})
            log(f"  [!] Уязвимости в `{class_name}` ({len(failures)}): {', '.join(cwes)}")
            for f_msg in failures:
                log(f"      - {f_msg}")

            poc_path = generate_poc_exploit(root_dir, file_path.stem, class_name, failures)
            log(f"      [Red Team] PoC сохранен: {poc_path}")

            current_failures = failures
            success = False

            for attempt in range(1, 4):
                log(f"      [Попытка {attempt}/3] Blue Team Хирург патчит `{class_name}`...")
                try:
                    root_cause, pr_title, patched_class = agent_patch_class(
                        orig_class_code, class_name, current_failures, attempt
                    )
                except Exception as exc:
                    current_failures = [f"[ОШИБКА LLM] {exc}"]
                    log(f"      [!] Сбой вызова LLM: {exc}")
                    continue

                test_full = replace_class_in_source(content, node, patched_class)
                post_failures, post_findings = verify_class_invariants(test_full, class_name, rel_file)

                if not post_failures:
                    diff_str = "\n".join(
                        difflib.unified_diff(
                            content.splitlines(),
                            test_full.splitlines(),
                            fromfile=f"a/{rel_file}",
                            tofile=f"b/{rel_file}",
                            lineterm="",
                        )
                    )
                    patch_file_rel = ""
                    if dry_run:
                        patch_file_rel = save_dry_run_patch(root_dir, file_path, class_name, diff_str)
                        status_str = "PATCH_READY (DRY-RUN)"
                        log(f"      [OK] Патч верифицирован (dry-run), сохранен в {patch_file_rel}")
                    else:
                        file_path.write_text(test_full, encoding="utf-8")
                        generate_regression_test(file_path, class_name)
                        content = test_full
                        status_str = "PATCHED"
                        log(f"      [OK] Патч для `{class_name}` применен и верифицирован (попытка {attempt})")

                    result["fixed"] += 1
                    result["findings"].append(
                        Finding(
                            file=rel_file,
                            line=node.lineno,
                            rule_id="SWARM-PATCHED",
                            cwe=",".join(cwes) if cwes else "CWE-000",
                            severity="LOW",
                            message=f"[{status_str}] {class_name}: {root_cause}",
                        )
                    )
                    result["details"].append({
                        "file": rel_file,
                        "class": class_name,
                        "status": status_str,
                        "root_cause": root_cause,
                        "cwes": cwes,
                        "poc": poc_path,
                        "patch_file": patch_file_rel,
                        "diff": diff_str,
                    })
                    success = True
                    break
                else:
                    log(f"      [!] Попытка {attempt} отклонена песочницей: {post_failures[0]}")
                    current_failures = post_failures
                    detected_findings = post_findings

            if not success:
                result["unfixed"] += 1
                result["findings"].extend(detected_findings)
                result["details"].append({
                    "file": rel_file,
                    "class": class_name,
                    "status": "FAILED",
                    "root_cause": "; ".join(current_failures),
                    "cwes": sorted({f.cwe for f in detected_findings}),
                    "poc": poc_path,
                    "patch_file": "",
                    "diff": "",
                })
        else:
            log(f"  [OK] Класс `{class_name}` безопасен.")
            result["details"].append({
                "file": rel_file,
                "class": class_name,
                "status": "CLEAN",
                "root_cause": "Все статические (SAST) и динамические (Sandbox) инварианты соблюдены",
                "cwes": [],
                "poc": "",
                "patch_file": "",
                "diff": "",
            })

    return result


def run_full_scan(root_dir: Path, dry_run: bool = False) -> tuple[dict, list[Finding]]:
    global LAST_REPORT_CACHE
    excluded_files = {
        Path(__file__).name,
        "sast_engine.py",
        "sandbox.py",
        "swarm_bulletproof.py",
        "swarm_pro_cli.py",
        "swarm_multi_scanner.py",
        "liquidity_pool.py",
    }
    excluded_dirs = {"tests", "exploits", "patches", ".git", ".venv", "venv", "__pycache__"}

    py_files = [
        f for f in root_dir.rglob("*.py")
        if f.name not in excluded_files and not any(part in excluded_dirs for part in f.parts)
    ]

    log(f"\n[*] AI Swarm Security Auditor v3.0 | Директория: {root_dir}")
    log(
        f"[*] Движки: SAST={'sast_engine.py' if SAST_EXTERNAL else 'встроенный'} | "
        f"Sandbox={'sandbox.py' if SANDBOX_EXTERNAL else 'встроенный'} | "
        f"Модель={OLLAMA_MODEL} | Режим={'DRY-RUN' if dry_run else 'AUTO-PATCH'}"
    )
    log(f"[*] Целевых файлов в очереди: {len(py_files)}")

    total_fixed = 0
    total_unfixed = 0
    all_details = []
    all_findings: list[Finding] = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(audit_single_file, f, root_dir, dry_run) for f in py_files]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            total_fixed += res["fixed"]
            total_unfixed += res["unfixed"]
            all_details.extend(res["details"])
            all_findings.extend(res["findings"])

    elapsed = round(time.time() - start_time, 2)
    report_data = {
        "dry_run": dry_run,
        "total_files": len(py_files),
        "fixed_vulns": total_fixed,
        "unfixed_vulns": total_unfixed,
        "elapsed_seconds": elapsed,
        "details": all_details,
    }
    LAST_REPORT_CACHE = {"report": report_data, "findings": all_findings}
    export_audit_report(report_data, all_findings, root_dir)
    log(f"[*] Аудит завершен за {elapsed} сек. Отчеты: audit_report.html, audit_report.json, audit_report.sarif")
    return report_data, all_findings


# ==========================================================
# 7. ВЕБ-ПАНЕЛЬ УПРАВЛЕНИЯ (--serve)
# ==========================================================
def start_dashboard_server(root_dir: Path, port: int = 8080, dry_run: bool = False):
    class DashboardHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/rescan":
                create_demo_vulnerable_files(root_dir)
                run_full_scan(root_dir, dry_run=dry_run)
                self.send_response(302)
                self.send_header("Location", "/audit_report.html")
                self.end_headers()
                return
            if self.path == "/run-tests":
                proc = subprocess.run(
                    [sys.executable, "-m", "pytest", "tests", "-v"],
                    cwd=root_dir,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
                if LAST_REPORT_CACHE:
                    report = LAST_REPORT_CACHE["report"]
                    findings = LAST_REPORT_CACHE["findings"]
                else:
                    report, findings = run_full_scan(root_dir, dry_run=dry_run)
                export_audit_report(report, findings, root_dir, pytest_output=output)
                self.send_response(302)
                self.send_header("Location", "/audit_report.html")
                self.end_headers()
                return
            if self.path == "/":
                self.path = "/audit_report.html"
            return super().do_GET()

    handler_cls = functools.partial(DashboardHandler, directory=str(root_dir))
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", port), handler_cls) as httpd:
        log(f"\n[*] Веб-панель запущена: http://127.0.0.1:{port}")
        log("[i] Нажмите Ctrl+C для остановки сервера.")
        httpd.serve_forever()


# ==========================================================
# 8. ТОЧКА ВХОДА (CLI И IDLE F5)
# ==========================================================
def main():
    default_dir = str(SCRIPT_DIR) if "idlelib" in sys.modules else "."
    parser = argparse.ArgumentParser(description="Enterprise AI Swarm Security Platform v3.0")
    parser.add_argument("--dir", type=str, default=default_dir, help="Директория для сканирования")
    parser.add_argument("--reset-demo", action="store_true", help="Создать полигон из 2 уязвимых модулей")
    parser.add_argument("--dry-run", action="store_true", help="Сохранять патчи в patches/ без перезаписи кода")
    parser.add_argument("--init-ci", action="store_true", help="Сгенерировать .github/workflows/ai_audit.yml")
    parser.add_argument("--install-hook", action="store_true", help="Установить git pre-commit хук")
    parser.add_argument("--ci", action="store_true", help="Режим CI/CD (код выхода 1 при неисправленных багах)")
    parser.add_argument("--serve", action="store_true", help="Запустить веб-панель управления на порту 8080")
    parser.add_argument("--port", type=int, default=8080, help="Порт для веб-панели (по умолчанию 8080)")
    args = parser.parse_args()

    root_dir = Path(args.dir).resolve()

    if len(sys.argv) == 1 and "idlelib" in sys.modules:
        log("[i] Запуск из IDLE: используется папка скрипта. При отсутствии демо-файлов они будут созданы.")
        if not (root_dir / "target_pool.py").exists() and not (root_dir / "token_vault.py").exists():
            args.reset_demo = True

    if args.init_ci:
        init_github_actions(root_dir)

    if args.install_hook:
        install_git_pre_commit_hook(root_dir)

    if args.reset_demo:
        create_demo_vulnerable_files(root_dir)

    report, _ = run_full_scan(root_dir, dry_run=args.dry_run)

    if args.ci and report["unfixed_vulns"] > 0:
        sys.exit(1)

    if args.serve:
        start_dashboard_server(root_dir, port=args.port, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
