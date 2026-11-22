import difflib
import json
import math
import re
import textwrap
import threading
import time
import urllib.error
import urllib.request
from hypothesis import given, settings, strategies as st

# ==========================================================
# 1. ПОДКЛЮЧЕНИЕ К OLLAMA (БЕЗ ОБРЕЗКИ ТОКЕНОВ)
# ==========================================================
OLLAMA_MODEL = "qwen3.1:4b"
OLLAMA_HOST = "http://127.0.0.1:11434"

NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def check_ollama_ready(expected_model: str) -> str:
    """Проверяет связь с Ollama и выбирает установленную модель."""
    try:
        with NO_PROXY_OPENER.open(f"{OLLAMA_HOST}/api/tags", timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            installed = [m["name"] for m in data.get("models", [])]
    except Exception as e:
        raise RuntimeError(
            f"Не удалось подключиться к Ollama ({OLLAMA_HOST}). "
            f"Убедитесь, что Ollama запущена. Детали: {e}"
        )

    if expected_model in installed:
        return expected_model

    for name in installed:
        if "qwen" in name.lower():
            print(f"  [!] Модель '{expected_model}' не найдена, автоматически выбрана: '{name}'")
            return name

    if installed:
        print(f"  [!] Модель '{expected_model}' не найдена, выбрана первая доступная: '{installed[0]}'")
        return installed[0]

    raise RuntimeError(
        f"В Ollama нет скачанных моделей. Выполните в cmd: ollama pull {expected_model}"
    )


def ollama_chat_stream(model: str, system_prompt: str, user_prompt: str, temperature: float = 0.0) -> str:
    """
    Отправляет запрос в Ollama с отключенным режимом <think> и увеличенным лимитом токенов.
    """
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt + "\n/no_think"}
        ],
        "think": False,  # Отключает скрытые рассуждения на уровне API Ollama
        "stream": True,
        "options": {
            "temperature": temperature,
            "num_ctx": 4096,
            "num_predict": 2048  # Достаточный запас, чтобы код никогда не обрезался
        }
    }

    req = urllib.request.Request(
        url=f"{OLLAMA_HOST}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    chunks = []
    print("  [>] Генерация патча моделью:\n  ---")
    try:
        with NO_PROXY_OPENER.open(req, timeout=300) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                packet = json.loads(line)
                token = packet.get("message", {}).get("content", "")
                if token:
                    print(token, end="", flush=True)
                    chunks.append(token)
                if packet.get("done"):
                    break
    except urllib.error.HTTPError as e:
        # Если старая версия Ollama не поддерживает поле "think", повторяем запрос без него
        if e.code == 400 and "think" in payload:
            del payload["think"]
            req = urllib.request.Request(
                url=f"{OLLAMA_HOST}/api/chat",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with NO_PROXY_OPENER.open(req, timeout=300) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    packet = json.loads(line)
                    token = packet.get("message", {}).get("content", "")
                    if token:
                        print(token, end="", flush=True)
                        chunks.append(token)
                    if packet.get("done"):
                        break
        else:
            error_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ошибка сервера Ollama (HTTP {e.code}): {error_body}")

    print("\n  ---")
    return "".join(chunks)


# ==========================================================
# 2. УЯЗВИМЫЙ КОД ПРОТОКОЛА (МИШЕНЬ АУДИТА)
# ==========================================================
VULNERABLE_CODE = """
class LiquidityPool:
    def __init__(self):
        self.balances = {}
        self.total_liquidity = 0.0

    def deposit(self, user: str, amount: float):
        self.balances[user] = self.balances.get(user, 0.0) + amount
        self.total_liquidity += amount

    def withdraw(self, user: str, amount: float) -> bool:
        current = self.balances.get(user, 0.0)
        if current >= amount:
            time.sleep(0.001)
            self.balances[user] = current - amount
            self.total_liquidity -= amount
            return True
        return False

    def claim_fee_rebate(self, user: str, parts: int) -> float:
        balance = self.balances.get(user, 0.0)
        chunk = round(balance / parts, 2)
        payout = chunk * parts
        self.balances[user] = 0.0
        self.total_liquidity -= payout
        return payout
"""


# ==========================================================
# 3. НАДЕЖНЫЙ ПАРСЕР ОТВЕТА МОДЕЛИ
# ==========================================================
def extract_patch_from_response(raw_text: str) -> tuple[str, str, str]:
    # Удаляем как закрытые, так и незакрытые блоки <think>
    cleaned = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL)
    cleaned = re.sub(r"<think>.*", "", cleaned, flags=re.DOTALL).strip()

    title_match = re.search(r"PR_TITLE:\s*(.+)", cleaned)
    pr_title = title_match.group(1).strip() if title_match else "fix(pool): add thread lock and floor rounding"

    cause_match = re.search(r"ROOT_CAUSE:\s*(.+)", cleaned)
    root_cause = cause_match.group(1).strip() if cause_match else "Устранены состояние гонки (Lock) и ошибка округления (math.floor)"

    # Ищем все блоки кода ```python ... ``` и берем тот, где есть class LiquidityPool
    code_blocks = re.findall(r"```(?:python)?\s*(.*?)```", cleaned, flags=re.DOTALL)
    code_str = ""
    for block in code_blocks:
        if "class LiquidityPool" in block:
            code_str = block
            break

    if not code_str and code_blocks:
        code_str = code_blocks[-1]

    if not code_str:
        # Если модель не закрыла ``` или написала код без кавычек
        class_idx = cleaned.find("class LiquidityPool")
        if class_idx != -1:
            code_str = cleaned[class_idx:].replace("```", "")
        else:
            code_str = cleaned

    return root_cause, pr_title, textwrap.dedent(code_str).strip()


# ==========================================================
# 4. СТЕНД СТРЕСС-ТЕСТИРОВАНИЯ (HYPOTHESIS + MULTITHREADING)
# ==========================================================
def verify_invariants(code_str: str) -> list[str]:
    namespace = {"time": time, "threading": threading, "math": math}
    try:
        exec(code_str, namespace)
    except Exception as e:
        return [f"[ОШИБКА СИНТАКСИСА В ПАТЧЕ] {type(e).__name__}: {e}"]

    if "LiquidityPool" not in namespace:
        return ["[ОШИБКА СТРУКТУРЫ] В ответе модели отсутствует 'class LiquidityPool:'"]

    PoolClass = namespace["LiquidityPool"]
    failures = []

    @settings(max_examples=200, database=None)
    @given(
        deposit_amount=st.floats(min_value=1.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
        parts=st.integers(min_value=2, max_value=50)
    )
    def fuzz_accounting(deposit_amount: float, parts: int):
        pool = PoolClass()
        pool.deposit("alice", deposit_amount)
        payout = pool.claim_fee_rebate("alice", parts)
        assert payout <= deposit_amount, (
            f"Выплата ({payout}) превысила депозит ({deposit_amount}) при дроблении на parts={parts}"
        )

    try:
        fuzz_accounting()
    except Exception as e:
        failures.append(f"[ЭКОНОМИЧЕСКИЙ БАГ] {e}")

    try:
        pool = PoolClass()
        pool.deposit("user_1", 100.0)
        workers = 20
        barrier = threading.Barrier(workers)
        results = []

        def attack_worker():
            barrier.wait()
            results.append(pool.withdraw("user_1", 100.0))

        threads = [threading.Thread(target=attack_worker) for _ in range(workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        if sum(results) != 1 or pool.balances.get("user_1", 0.0) < 0:
            failures.append(
                f"[СОСТОЯНИЕ ГОНКИ] Пробита защита потока: успешных снятий {sum(results)} из 1, "
                f"итоговый баланс: {pool.balances.get('user_1')}"
            )
    except Exception as e:
        failures.append(f"[СБОЙ В МНОГОПОТОЧНОМ ТЕСТЕ] {e}")

    return failures


# ==========================================================
# 5. ВЫЗОВ ЛОКАЛЬНОГО АГЕНТА-ПАТЧЕРА (С РАБОТОЙ НАД ОШИБКАМИ)
# ==========================================================
def request_ai_patch(
    active_model: str,
    code_to_fix: str,
    failure_logs: list[str],
    attempt: int
) -> tuple[str, str, str]:
    system_prompt = (
        "Return ONLY valid Python code inside a ```python ... ``` block.\n"
        "Fix both bugs in class LiquidityPool:\n"
        "1. In __init__, add: self._lock = threading.Lock()\n"
        "2. In deposit, withdraw, and claim_fee_rebate, wrap all logic inside: with self._lock:\n"
        "3. In claim_fee_rebate, replace 'chunk = round(balance / parts, 2)' with:\n"
        "   chunk = math.floor((balance / parts) * 100) / 100.0\n"
        "Do NOT omit any methods. Keep class name LiquidityPool."
    )

    user_prompt = (
        f"Broken code:\n```python\n{code_to_fix.strip()}\n```\n\n"
        f"Test failures to fix:\n" + "\n".join(failure_logs) + "\n\n"
        "Output format:\n"
        "ROOT_CAUSE: <short explanation>\n"
        "PR_TITLE: fix(pool): add thread lock and floor rounding\n"
        "```python\n"
        "class LiquidityPool:\n"
        "    ...\n"
        "```"
    )

    # С каждой попыткой слегка повышаем температуру, чтобы модель не повторяла ошибку
    temp = 0.0 if attempt == 1 else 0.2 * attempt
    raw_output = ollama_chat_stream(active_model, system_prompt, user_prompt, temperature=temp)
    return extract_patch_from_response(raw_output)


# ==========================================================
# 6. ЗАПУСК КОНВЕЙЕРА
# ==========================================================
def main():
    print("=== ЭТАП 0: ПРОВЕРКА СВЯЗИ С ЛОКАЛЬНОЙ OLLAMA ===")
    active_model = check_ollama_ready(OLLAMA_MODEL)
    print(f"  [+] Агент подключен к локальной модели: {active_model}")

    print("\n=== ЭТАП 1: АТАКА ФАЗЗЕРОМ И ПОТОКАМИ НА ИСХОДНЫЙ КОД ===")
    failures = verify_invariants(VULNERABLE_CODE)

    if not failures:
        print("Уязвимостей не обнаружено.")
        return

    for f in failures:
        print("  ❌", f)

    current_failures = failures
    current_code = VULNERABLE_CODE

    for attempt in range(1, 4):
        print(f"\n=== ЭТАП 2: ГЕНЕРАЦИЯ ПАТЧА МОДЕЛЬЮ {active_model} [Попытка {attempt}/3] ===")
        root_cause, pr_title, patched_code = request_ai_patch(
            active_model, current_code, current_failures, attempt
        )

        print(f"  [*] Диагноз: {root_cause}")
        print(f"  [*] Заголовок PR: {pr_title}")
        print("  [>] Повторный прогон стресс-тестов на пропатченном коде...")

        post_failures = verify_invariants(patched_code)

        if not post_failures:
            print("  ✅ ВСЕ СТРЕСС-ТЕСТЫ ПРОЙДЕНЫ! Патч доказанно закрыл обе уязвимости.")
            print("\n=== ЭТАП 3: ГОТОВЫЙ GIT DIFF ДЛЯ PULL REQUEST ===")
            diff = difflib.unified_diff(
                VULNERABLE_CODE.strip().splitlines(),
                patched_code.splitlines(),
                fromfile="a/liquidity_pool.py",
                tofile="b/liquidity_pool.py",
                lineterm=""
            )
            print("\n".join(diff))
            return
        else:
            print("  ⚠️ Патч не выдержал нагрузки. Причина отказа:")
            for pf in post_failures:
                print("     -", pf)
            current_failures = post_failures
            # Если модель выдала непустой код, передаем ей на доработку её же черновик
            if "class LiquidityPool" in patched_code:
                current_code = patched_code

    print("\n❌ За 3 попытки модель не смогла выдать рабочий патч.")


if __name__ == "__main__":
    main()
