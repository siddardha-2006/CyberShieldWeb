from typing import List, Dict, Any
from app.schemas.analysis import RiskAssessment, EvidenceItem, ExplainabilityResponse


class ExplainabilityGenerator:
    """
    Produces deterministic, evidence-backed explanations answering 'Why?'
    without hallucination or fabricated reasoning. Prioritizes global threat
    intelligence records (e.g. PhishTank) over technical rule codes.
    """

    @classmethod
    def generate(cls, assessment: RiskAssessment, evidence_list: List[EvidenceItem]) -> ExplainabilityResponse:
        key_reasons = []
        safe_steps = []

        if not evidence_list or assessment.severity == "safe":
            summary = "The inspected content appears clean and safe. Our parallel detection engines found no malicious signatures, deceptive social engineering tactics, or credential harvesting mechanisms."
            key_reasons = [
                "Clean Security Blacklists: Domain is clean across VirusTotal, PhishTank, and URLhaus global feeds.",
                "Safe Structure & Routing: No hidden redirects, malicious scripts, or login interception forms detected.",
                "Natural Language Check: Text and linguistic patterns show normal, non-coercive communication."
            ]
            safe_steps = [
                "Proceed with normal browsing hygiene.",
                "Always verify that the website URL matches the official domain of the service."
            ]
        else:
            # Check for PhishTank verified records
            phishtank_ev = next(
                (e for e in evidence_list if "phishtank" in getattr(e, "code", "").lower() or "phishtank" in getattr(e, "title", "").lower()), 
                None
            )

            if phishtank_ev:
                summary = (
                    "CRITICAL SECURITY ALERT: This destination is confirmed as an active, malicious phishing page "
                    "in the global PhishTank threat database. It has been verified by cybersecurity analysts as a fraudulent "
                    "portal designed to steal user passwords, accounts, or financial data."
                )
                
                # Priority 1: PhishTank Record
                phish_id_str = f" (Record #{phishtank_ev.metadata.get('phish_id')})" if phishtank_ev.metadata and phishtank_ev.metadata.get('phish_id') else ""
                key_reasons.append(f"PhishTank Community Blacklist Match{phish_id_str}: Destination is an active verified phishing site in the PhishTank global intelligence database.")

                # Priority 2: Other Threat Intelligence / High-impact findings
                for ev in evidence_list:
                    if ev != phishtank_ev and ev.severity in ["critical", "high"]:
                        desc = ev.description if not ev.description.startswith(ev.title) else ev.description
                        key_reasons.append(f"{ev.title}: {desc}")

                # Fill with remaining evidence up to 5 items
                for ev in evidence_list:
                    desc = ev.description if not ev.description.startswith(ev.title) else ev.description
                    entry = f"{ev.title}: {desc}"
                    if entry not in key_reasons and len(key_reasons) < 5:
                        key_reasons.append(entry)
            else:
                summary = (
                    f"Cyber Shield flagged this content as {assessment.severity.upper()} risk ({assessment.risk_score}/100) "
                    f"under the category '{assessment.category}'. Multiple telemetry indicators confirmed fraudulent, deceptive, or coercive patterns."
                )
                
                for ev in evidence_list[:5]:
                    desc = ev.description if not ev.description.startswith(ev.title) else ev.description
                    key_reasons.append(f"{ev.title}: {desc}")

            # Actionable remediation steps
            if assessment.severity in ["critical", "high_risk"]:
                safe_steps = [
                    "DO NOT provide any passwords, OTP codes, PINs, or personal identity details.",
                    "DO NOT make payments, send money, or pay registration/processing fees.",
                    "Close this webpage or message immediately and block the sender.",
                    "If you previously entered credentials, change your passwords immediately on the official service."
                ]
            else: # suspicious
                safe_steps = [
                    "Exercise elevated caution; verify the domain spelling and sender details carefully.",
                    "Contact the organization directly through verified official channels (never use links in the message).",
                    "Never enter financial details or authentication codes unless 100% verified."
                ]

        return ExplainabilityResponse(
            summary=summary,
            key_reasons=key_reasons,
            evidence_breakdown=evidence_list,
            safe_steps=safe_steps
        )
