import sys
import os
import asyncio

# Set UTF-8 output encoding for windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.normalization.normalizer import ContentNormalizer
from app.detection.rules.engine import RuleEngine
from app.detection.nlp.engine import NlpEngine
from app.detection.threat_intel.engine import ThreatIntelligenceEngine
from app.detection.behavior.engine import BehavioralAnalysisEngine
from app.orchestration.analyzer import SecurityAnalyzer
from app.core.security import generate_hmac_identifier


async def run_all_tests():
    print("========================================")
    print("CYBER SHIELD ENGINE INTEGRATION TEST SUITE")
    print("========================================")

    # 1. Test HMAC Privacy Identifier
    print("\n[TEST 1] Testing HMAC Privacy Identifier...")
    hmac1 = generate_hmac_identifier("https://fake-bank-login.com/auth")
    hmac2 = generate_hmac_identifier("https://fake-bank-login.com/auth")
    assert hmac1 == hmac2, "HMAC should be deterministic"
    assert len(hmac1) == 64, "HMAC-SHA256 must produce a 64-character hex digest"
    print("[PASS] HMAC Privacy Generation Passed (HMAC-SHA-256 length=64).")

    # 2. Test Rule Engine
    print("\n[TEST 2] Testing Rule-Based Engine (IP host & Credential Path)...")
    norm_url = ContentNormalizer.normalize_url("http://192.168.1.100/secure/bank-login.php")
    res_rules = await RuleEngine.analyze(norm_url)
    assert res_rules.engine == "rules"
    assert res_rules.status == "completed"
    assert res_rules.score >= 35, f"Expected score >= 35, got {res_rules.score}"
    assert any(e.code == "RULE_URL_IP_HOST" for e in res_rules.evidence), "Must flag raw IP host rule"
    print(f"[PASS] Rule Engine Passed: Score={res_rules.score}/100, Findings={len(res_rules.evidence)}")

    # 3. Test AI/NLP Engine
    print("\n[TEST 3] Testing AI/NLP Intent Engine (Urgency & Credential Harvesting)...")
    norm_msg = ContentNormalizer.normalize_message(
        "URGENT ALERT: Your account has been suspended. Enter your OTP and verify password immediately."
    )
    res_nlp = await NlpEngine.analyze(norm_msg)
    assert res_nlp.engine == "nlp"
    assert res_nlp.status == "completed"
    assert res_nlp.score >= 60, f"Expected NLP score >= 60, got {res_nlp.score}"
    assert res_nlp.classifications.get("credential_theft", 0) >= 0.60, "Must detect credential theft"
    print(f"[PASS] AI/NLP Engine Passed: Score={res_nlp.score}/100, PhishingProb={res_nlp.classifications.get('phishing')}")

    # 4. Test Threat Intelligence Engine
    print("\n[TEST 4] Testing Threat Intelligence Engine...")
    norm_threat = ContentNormalizer.normalize_url("https://fake-example.test/phish/update")
    res_threat = await ThreatIntelligenceEngine.analyze(norm_threat)
    assert res_threat.engine == "threat_intelligence"
    assert res_threat.status == "completed"
    print(f"[PASS] Threat Intel Engine Passed: Score={res_threat.score}/100, Sources={res_threat.sources}")

    # 5. Test Behavioral Engine & SSRF Guardrail
    print("\n[TEST 5] Testing Behavioral Engine & SSRF Policy Enforcement...")
    norm_ssrf = ContentNormalizer.normalize_url("http://127.0.0.1:8080/admin/dump")
    res_behavior = await BehavioralAnalysisEngine.analyze(norm_ssrf)
    assert res_behavior.engine == "behavior"
    assert res_behavior.status == "completed"
    assert any(e.code == "BEHAVIOR_SSRF_PROHIBITED" for e in res_behavior.evidence), "Must block localhost/SSRF"
    print(f"[PASS] Behavioral Sandbox & SSRF Policy Passed: Blocked prohibited origin as expected.")

    # 6. Test Full Parallel Orchestration & Risk Fusion
    print("\n[TEST 6] Testing Full Parallel Orchestration (asyncio.gather) & Evidence Fusion...")
    malicious_input = (
        "URGENT ALERT: State Bank account blocked due to KYC. Verify OTP within 24 hours: https://fake-example.test/login"
    )
    norm_full = ContentNormalizer.normalize_message(malicious_input)
    analysis = await SecurityAnalyzer.analyze(norm_full)

    print(f"  - Risk Score: {analysis.assessment.risk_score}/100")
    print(f"  - Confidence: {int(analysis.assessment.confidence * 100)}%")
    print(f"  - Severity: {analysis.assessment.severity.upper()}")
    print(f"  - Category: {analysis.assessment.category}")
    print(f"  - Recommended Action: {analysis.assessment.recommended_action}")
    print(f"  - Telemetry Duration: {analysis.duration_ms}ms")
    print(f"  - Key Evidence Points: {len(analysis.explainability.key_reasons)}")

    assert analysis.assessment.risk_score >= 70, "Expected high risk score for urgent credential phishing"
    assert analysis.assessment.severity in ["high_risk", "critical"]
    assert analysis.assessment.recommended_action in ["DO_NOT_INTERACT", "REPORT"]
    assert len(analysis.explainability.key_reasons) > 0
    assert len(analysis.explainability.safe_steps) > 0

    print("\n========================================")
    print("ALL 6 TEST PHASES PASSED WITH ZERO ERRORS!")
    print("========================================")


if __name__ == "__main__":
    asyncio.run(run_all_tests())

