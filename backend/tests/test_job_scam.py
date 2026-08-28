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

async def test_job():
    text = (
        "Congratulations! Your profile has been shortlisted for a remote job.\n"
        "Earn ₹5,000–₹10,000 per day from home.\n"
        "Pay ₹499 as a one-time registration fee.\n"
        "Reply “YES” to continue."
    )
    norm = ContentNormalizer.normalize_social(text, "telegram")
    res = await SecurityAnalyzer.analyze(norm)
    print("====================================================================")
    print("                SOCIAL JOB SCAM DM ANALYSIS TEST                    ")
    print("====================================================================")
    print("Risk Score:", res.assessment.risk_score)
    print("Severity:", res.assessment.severity)
    print("Category:", res.assessment.category)
    print("Explainability Summary:", res.explainability.summary)
    print("\nEngine Breakdown:")
    for k, v in res.engines.items():
        print(f" - {k:<20}: score={v.score}, findings={len(v.evidence)}")
        for ev in v.evidence:
            print(f"    -> [{ev.code}] {ev.title}: {ev.description}")
    print("====================================================================")

if __name__ == "__main__":
    asyncio.run(test_job())

