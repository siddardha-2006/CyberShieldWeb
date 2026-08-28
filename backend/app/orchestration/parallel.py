import asyncio
import time
from typing import Dict, Any, Coroutine
from app.schemas.analysis import EngineResult


class ParallelExecutor:
    """
    Executes multiple async detection engine tasks concurrently using asyncio.gather.
    Includes timeout guardrails, exception containment, and partial-result resilience.
    """

    @classmethod
    async def run_with_timeout(
        cls, 
        engine_name: str, 
        coro: Coroutine, 
        timeout_seconds: float
    ) -> EngineResult:
        start_time = time.perf_counter()
        try:
            res = await asyncio.wait_for(coro, timeout=timeout_seconds)
            return res
        except asyncio.TimeoutError:
            latency = int((time.perf_counter() - start_time) * 1000)
            return EngineResult(
                engine=engine_name, # type: ignore
                status="timeout",
                score=0,
                confidence=0.0,
                evidence=[],
                latency_ms=latency,
                error_message=f"Engine exceeded maximum execution allowance ({timeout_seconds}s)"
            )
        except Exception as exc:
            latency = int((time.perf_counter() - start_time) * 1000)
            return EngineResult(
                engine=engine_name, # type: ignore
                status="error",
                score=0,
                confidence=0.0,
                evidence=[],
                latency_ms=latency,
                error_message=str(exc)
            )

