import sys
import os
import asyncio

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.normalization.normalizer import ContentNormalizer
from app.orchestration.analyzer import SecurityAnalyzer

async def test_full_myspace():
    url = "myspace.com/video/vid/30602581"
    norm = ContentNormalizer.normalize_url(url)
    res = await SecurityAnalyzer.analyze(norm)
    print("====================================================================")
    print("           FULL 4-ENGINE FUSED ANALYSIS FOR MYSPACE URL             ")
    print("====================================================================")
    print(f"Target: {url}")
    print(f"Overall Risk Score: {res.assessment.risk_score} / 100")
    print(f"Severity: {res.assessment.severity}")
    print(f"Recommended Action: {res.assessment.recommended_action}")
    print(f"Category: {res.assessment.category}")
    print("\n--- 4 ENGINES BREAKDOWN ---")
    for name, eng in res.engines.items():
        print(f" • {name:<20}: Score = {eng.score:<4} | Status = {eng.status} | Findings = {len(eng.evidence)}")
    print("\n--- EXPLAINABILITY SUMMARY ---")
    print(res.explainability.summary)
    print("====================================================================")

if __name__ == "__main__":
    asyncio.run(test_full_myspace())

