import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

RUNNER_TEMPLATE = r"""
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
"""


def verify_in_sandbox(source_code: str, class_name: str, timeout: int = 15) -> list[str]:
    """Запускает динамическую верификацию класса в отдельном изолированном процессе."""
    with tempfile.TemporaryDirectory(prefix="swarm_sandbox_") as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "target_code.py").write_text(source_code, encoding="utf-8")
        runner_code = RUNNER_TEMPLATE.replace("__CLASS_NAME__", json.dumps(class_name))
        runner_file = tmp_path / "runner.py"
        runner_file.write_text(runner_code, encoding="utf-8")

        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        try:
            proc = subprocess.run(
                [sys.executable, str(runner_file)],
                cwd=tmp_path,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return [f"[TIMEOUT / DEADLOCK] Проверка превысила {timeout}с — вероятна взаимная блокировка Lock"]

        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["Неизвестный сбой"]
            return [f"[ОШИБКА ПЕСОЧНИЦЫ] {err[0]}"]

        try:
            last_line = proc.stdout.strip().splitlines()[-1]
            return json.loads(last_line)
        except Exception:
            return [f"[ОШИБКА ПАРСИНГА] Некорректный вывод песочницы: {proc.stdout[:200]}"]
