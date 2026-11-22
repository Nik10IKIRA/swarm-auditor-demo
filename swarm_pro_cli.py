import argparse
import difflib
import json
import math
import re
import subprocess
import textwrap
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from hypothesis import given, settings, strategies as st

# ==========================================================
# КОНФИГУРАЦИЯ РОЯ
# ==========================================================
OLLAMA_HOST = "http://127.0.0.1:11434"
NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def get_active_model() -> str:
    """Автоматически находит доступную локальную модель в Ollama."""
    try:
        with NO_PROXY_OPENER.open(f"{OLLAMA_HOST}/api/tags", timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            installed = [m["name"] for m in data.get("models", [])]
            if installed:
                print(f"  [+] Автоматически выбрана модель: {installed[0]}")
                return installed[0]
    except Exception:
        pass
    return "qwen2.5-coder:7b"

OLLAMA_MODEL = get_active_model()


def call_ollama(system_prompt: str, user_prompt: str, temperature: float = 0.0) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt + "\n/no_think"}
        ],
        "think": False,
        "stream": True,
        "options": {
            "temperature": temperature,
            "num_ctx": 4096,
            "num_predict": 2048
        }
    }

    req = urllib.request.Request(
        url=f"{OLLAMA_HOST}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    chunks = []
    try:
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
    except Exception as e:
        raise RuntimeError(f"Ошибка соединения с Ollama: {e}")

    return "".join(chunks)


# ==========================================================
# РАСШИРЕННЫЙ СТЕНД ИНВАРИАНТОВ (ФАЗЗИНГ + ПОТОКИ + ДЕДЛОКИ)
# ==========================================================
def verify_invariants(source_code: str) -> list[str]:
    namespace = {"time": time, "threading": threading, "math": math}
    try:
        exec(source_code, namespace)
    except Exception as e:
        return [f"[СИНТАКСИС / КОМПИЛЯЦИЯ] {e}"]

    if "LiquidityPool" not in namespace:
        return ["[ОШИБКА СТРУКТУРЫ] В коде отсутствует класс LiquidityPool"]

    PoolClass = namespace["LiquidityPool"]
    failures = []

    # 1. Фаззинг точности баланса (Hypothesis)
    @settings(max_examples=100, database=None)
    @given(
        deposit_amount=st.floats(min_value=1.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
        parts=st.integers(min_value=2, max_value=30)
    )
    def fuzz_test(deposit_amount: float, parts: int):
        pool = PoolClass()
        pool.deposit("alice", deposit_amount)
        payout = pool.claim_fee_rebate("alice", parts)
        assert payout <= deposit_amount, f"Выплата ({payout}) больше депозита ({deposit_amount})"

    try:
        fuzz_test()
    except Exception as e:
        failures.append(f"[ЭКОНОМИЧЕСКИЙ БАГ] {e}")

    # 2. Стресс-тест на гонку потоков (Concurrency / Race Condition)
    try:
        pool = PoolClass()
        pool.deposit("attacker", 100.0)
        workers = 20
        barrier = threading.Barrier(workers)
        results = []

        def worker():
            barrier.wait()
            results.append(pool.withdraw("attacker", 100.0))

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        for t in threads: t.start()
        for t in threads: t.join()

        if sum(results) > 1 or pool.balances.get("attacker", 0.0) < 0:
            failures.append(f"[RACE CONDITION] Успешных снятий: {sum(results)} из 1 возможных")
    except Exception as e:
        failures.append(f"[ОШИБКА ПОТОКОВ] {e}")

    # 3. Проверка на наличие замков блокировки (Deadlock / Lock Safety Check)
    # Проверяем, реализована ли потокобезопасность на уровне структуры класса
    sample_pool = PoolClass()
    if not hasattr(sample_pool, "_lock") and "Lock" not in source_code:
        failures.append("[АРХИТЕКТУРНЫЙ РИСК] Класс не содержит защитных блокировок (threading.Lock)")

    return failures


# ==========================================================
# АГЕНТ-ХИРУРГ
# ==========================================================
def agent_generate_patch(original_code: str, failure_logs: list[str], attempt: int) -> tuple[str, str, str]:
    system_prompt = (
        "You are a Senior Python Security Engineer.\n"
        "Fix the concurrency race condition (add threading.Lock in __init__ and wrap deposit, withdraw, claim_fee_rebate with 'with self._lock:') "
        "and rounding bug (replace round with math.floor in claim_fee_rebate) in class LiquidityPool.\n"
        "Return format:\n"
        "ROOT_CAUSE: <one line explanation>\n"
        "PR_TITLE: fix(pool): secure methods with lock and floor\n"
        "```python\n"
        "class LiquidityPool:\n"
        "    # full fixed class here\n"
        "```"
    )
    user_prompt = (
        f"Vulnerable code:\n```python\n{original_code}\n```\n\n"
        f"Failures to fix:\n" + "\n".join(failure_logs)
    )

    temp = 0.0 if attempt == 1 else 0.2 * attempt
    raw = call_ollama(system_prompt, user_prompt, temperature=temp)
    
    cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL)
    title_m = re.search(r"PR_TITLE:\s*(.+)", cleaned)
    cause_m = re.search(r"ROOT_CAUSE:\s*(.+)", cleaned)
    
    pr_title = title_m.group(1).strip() if title_m else "fix(pool): apply lock and math.floor"
    root_cause = cause_m.group(1).strip() if cause_m else "Race condition & rounding vulnerability resolved"

    code_m = re.findall(r"```(?:python)?\s*(.*?)```", cleaned, flags=re.DOTALL)
    if code_m:
        code_str = code_m[-1]
    else:
        idx = cleaned.find("class LiquidityPool")
        code_str = cleaned[idx:] if idx != -1 else cleaned

    return root_cause, pr_title, textwrap.dedent(code_str).strip()


# ==========================================================
# АВТОМАТИЗАЦИЯ GIT И PULL REQUEST
# ==========================================================
def apply_git_workflow(file_path: Path, pr_title: str):
    """Создает ветку, делает коммит и открывает PR через GitHub CLI."""
    repo_dir = file_path.parent
    branch_name = f"fix-audit-{int(time.time())}"

    def run_git(args):
        subprocess.run(["git", *args], cwd=repo_dir, check=True)

    try:
        print(f"\n[*] Создание Git-ветки: {branch_name}")
        run_git(["checkout", "-b", branch_name])
        run_git(["add", file_path.name])
        run_git(["commit", "-m", pr_title])
        print("  [+] Изменения успешно закомичены.")

        # Попытка создать PR через GitHub CLI (если установлен и настроен)
        print("[*] Создание Pull Request через GitHub CLI...")
        subprocess.run(
            ["gh", "pr", "create", "--title", pr_title, "--body", "Automated patch generated by Swarm Auditor AI."],
            cwd=repo_dir,
            check=True
        )
        print("  [+] Pull Request успешно открыт!")
    except FileNotFoundError:
        print("  [i] Утилита git или gh не найдена. Изменения сохранены локально в файл.")
    except Exception as e:
        print(f"  [i] Автоматический пуш в Git пропущен: {e}")


# ==========================================================
# ГЛАВНЫЙ ОРКЕСТРАТОР С CLI
# ==========================================================
def main():
    parser = argparse.ArgumentParser(description="Autonomous AI Swarm Auditor for Python")
    parser.add_argument("--target", type=str, default="target_pool.py", help="Путь к файлу для аудита")
    parser.add_argument("--git", action="store_true", help="Автоматически создавать Git-ветку и PR")
    args = parser.parse_args()

    target_file = Path(args.target).resolve()
    
    if not target_file.exists():
        # Создаем дефолтный файл для демонстрации, если его нет
        target_file.write_text(
            "import time, math\n\n"
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
            encoding="utf-8"
        )

    print(f"[*] Аудит файла: {target_file}")
    original_code = target_file.read_text(encoding="utf-8")

    print("[*] Первичный прогон стресс-тестов...")
    failures = verify_invariants(original_code)

    if not failures:
        print("[+] Уязвимостей не обнаружено.")
        return

    for f in failures:
        print("  ❌", f)

    current_failures = failures
    current_code = original_code

    for attempt in range(1, 4):
        print(f"\n[*] Агент-Хирург создает патч [Попытка {attempt}/3]...")
        root_cause, pr_title, patched_code = agent_generate_patch(current_code, current_failures, attempt)

        print(f"    Диагноз: {root_cause}")
        print(f"    Заголовок PR: {pr_title}")

        print("    [>] Проверка пропатченного кода под нагрузкой...")
        post_failures = verify_invariants(patched_code)

        if not post_failures:
            print("    ✅ ПАТЧ УСПЕШНО ВЕРИФИЦИРОВАН!")
            target_file.write_text(patched_code, encoding="utf-8")
            print(f"    [💾] Исправленный файл сохранен в {target_file}")

            print("\n=== GIT DIFF ДЛЯ PULL REQUEST ===")
            diff = difflib.unified_diff(
                original_code.splitlines(),
                patched_code.splitlines(),
                fromfile=f"a/{target_file.name}",
                tofile=f"b/{target_file.name}",
                lineterm=""
            )
            print("\n".join(diff))

            if args.git:
                apply_git_workflow(target_file, pr_title)
            return
        else:
            print("    ⚠️ Остаточные ошибки, передаем на доработку:")
            for pf in post_failures:
                print("       -", pf)
            current_failures = post_failures
            if "class LiquidityPool" in patched_code:
                current_code = patched_code

    print("\n❌ Не удалось верифицировать патч за 3 попытки.")


if __name__ == "__main__":
    main()
