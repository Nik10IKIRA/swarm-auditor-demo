import difflib
import json
import math
import re
import textwrap
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from hypothesis import given, settings, strategies as st

# ==========================================================
# КОНФИГУРАЦИЯ
# ==========================================================
OLLAMA_MODEL = "qwen3.5:4b"  # Укажите вашу модель из 'ollama list'
OLLAMA_HOST = "http://127.0.0.1:11434"

NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


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
# ЖЕСТКИЙ ДЕТЕРМИНИРОВАННЫЙ НАБОР СТРЕСС-ТЕСТОВ (QA HARNESS)
# ==========================================================
def verify_invariants(source_code: str) -> list[str]:
    """Проверяет класс на экономические баги (Hypothesis) и гонки (Threading)."""
    namespace = {"time": time, "threading": threading, "math": math}
    try:
        exec(source_code, namespace)
    except Exception as e:
        return [f"[СИНТАКСИС / ОШИБКА КОМПИЛЯЦИИ] {e}"]

    if "LiquidityPool" not in namespace:
        return ["[ОШИБКА СТРУКТУРЫ] В коде отсутствует класс LiquidityPool"]

    PoolClass = namespace["LiquidityPool"]
    failures = []

    # Тест 1: Фаззинг точности (Hypothesis)
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

    # Тест 2: Состояние гонки (20 параллельных потоков)
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

    return failures


# ==========================================================
# АГЕНТ-ХИРУРГ (ГЕНЕРАЦИЯ ИСПРАВЛЕННОГО КОДА)
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
# ГЛАВНЫЙ ОРКЕСТРАТОР
# ==========================================================
def main():
    target_file = Path("C:/swarm_lab/target_pool.py")
    
    # Создаем эталонный уязвимый файл
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

    print(f"[*] Аудит файла: {target_file.name}")
    original_code = target_file.read_text(encoding="utf-8")

    print("[*] Первичный прогон стресс-тестов на исходном коде...")
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
