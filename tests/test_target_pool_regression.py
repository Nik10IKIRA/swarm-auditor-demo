import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from target_pool import LiquidityPool


def test_liquiditypool_security_invariants():
    pool = LiquidityPool()
    if hasattr(pool, "deposit") and hasattr(pool, "claim_fee_rebate"):
        pool.deposit("alice", 100.0)
        assert pool.claim_fee_rebate("alice", 3) <= 100.0 + 1e-9

    p2 = LiquidityPool()
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
