import time
from typing import List, Dict, Any
from app.schemas.analysis import NormalizedInput, EngineResult, EvidenceItem
from app.detection.behavior.page_analyzer import SandboxPageAnalyzer


class BehavioralAnalysisEngine:
    name = "behavior"

    @classmethod
    async def analyze(cls, data: NormalizedInput) -> EngineResult:
        start_time = time.perf_counter()

        # Check if input supports behavioral analysis
        targets = data.urls
        if not targets:
            latency = int((time.perf_counter() - start_time) * 1000)
            return EngineResult(
                engine="behavior",
                status="not_applicable",
                score=0,
                confidence=0.0,
                evidence=[],
                latency_ms=latency
            )

        target_url = targets[0]
        obs = await SandboxPageAnalyzer.inspect(target_url)

        evidence: List[EvidenceItem] = []
        score = 0

        if obs.get("blocked"):
            evidence.append(
                EvidenceItem(
                    engine="behavior",
                    code="BEHAVIOR_SSRF_PROHIBITED",
                    title="Blocked Internal / Restricted IP Destination",
                    description=obs.get("block_reason", "Target violated behavioral security network policies."),
                    weight=50,
                    severity="critical",
                    category="malicious_infrastructure"
                )
            )
            score += 50

        if obs.get("redirect_count", 0) >= 2:
            evidence.append(
                EvidenceItem(
                    engine="behavior",
                    code="BEHAVIOR_EXCESSIVE_REDIRECTS",
                    title="Multi-Hop Redirection Chain",
                    description=f"Destination navigated through {obs['redirect_count']} hops before landing, commonly used to evade static scanners.",
                    weight=25,
                    severity="medium",
                    category="evasion"
                )
            )
            score += 25

        if obs.get("has_password_field"):
            evidence.append(
                EvidenceItem(
                    engine="behavior",
                    code="BEHAVIOR_PASSWORD_INPUT",
                    title="Active Credential / Password Entry Field",
                    description="Webpage renders password authentication fields.",
                    weight=30,
                    severity="high",
                    category="credential_theft"
                )
            )
            score += 30

        if obs.get("has_otp_field"):
            evidence.append(
                EvidenceItem(
                    engine="behavior",
                    code="BEHAVIOR_OTP_INTERCEPTION",
                    title="Active OTP / 2FA Capture Prompt",
                    description="Interactive DOM structure actively prompts user for live one-time authorization tokens.",
                    weight=40,
                    severity="critical",
                    category="credential_theft"
                )
            )
            score += 40

        if obs.get("cross_domain_submission"):
            evidence.append(
                EvidenceItem(
                    engine="behavior",
                    code="BEHAVIOR_CROSS_DOMAIN_EXFIL",
                    title="Cross-Domain Form Action Exfiltration",
                    description="Form input is configured to post sensitive form data to an unrelated external domain.",
                    weight=35,
                    severity="high",
                    category="exfiltration"
                )
            )
            score += 35

        final_score = min(100, score)
        confidence = 0.93 if evidence else 0.80
        latency = int((time.perf_counter() - start_time) * 1000)

        return EngineResult(
            engine="behavior",
            status="completed",
            score=final_score,
            confidence=confidence,
            evidence=evidence,
            observations=obs,
            latency_ms=latency
        )

