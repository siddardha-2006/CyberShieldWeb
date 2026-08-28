import sys
import os
import asyncio

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.normalization.normalizer import ContentNormalizer
from app.detection.behavior.engine import BehavioralAnalysisEngine

async def test_myspace():
    url = "myspace.com/video/vid/30602581"
    norm = ContentNormalizer.normalize_url(url)
    res = await BehavioralAnalysisEngine.analyze(norm)
    print("====================================================================")
    print("          BEHAVIORAL SANDBOX INSPECTION FOR MYSPACE URL             ")
    print("====================================================================")
    print(f"Target URL: {url}")
    print(f"Engine: {res.engine}")
    print(f"Status: {res.status}")
    print(f"Risk Score: {res.score} / 100")
    print(f"Confidence: {res.confidence}")
    print(f"Latency: {res.latency_ms} ms")
    print("\nObservations Recorded:")
    if res.observations:
        for k, v in res.observations.items():
            print(f"  - {k}: {v}")
    print("\nEvidence Findings:")
    if res.evidence:
        for ev in res.evidence:
            print(f"  - [{ev.code}] {ev.title} (weight: {ev.weight}, severity: {ev.severity})")
            print(f"    {ev.description}")
    else:
        print("  - (No malicious behaviors, credential hijacking, or redirect anomalies detected)")
    print("====================================================================")

if __name__ == "__main__":
    asyncio.run(test_myspace())

