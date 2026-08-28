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

async def test_multilingual():
    test_cases = [
        {
            "name": "Hindi Remote Job Scam",
            "lang": "Hindi",
            "text": "बधाई हो! आपकी प्रोफ़ाइल को वर्क फ्रॉम होम जॉब के लिए चुना गया है। प्रतिदिन ₹5,000 कमाएं। पंजीकरण शुल्क ₹499 का भुगतान करें। जारी रखने के लिए YES का उत्तर दें।",
            "expected_severity": ["high_risk", "critical"]
        },
        {
            "name": "Telugu Work-From-Home Scam",
            "lang": "Telugu",
            "text": "అభినందనలు! రిమోట్ జాబ్ కోసం మీ ప్రొఫైల్ ఎంపిక చేయబడింది. రోజుకు ₹5,000 సంపాదించండి. రిజిస్ట్రేషన్ ఫీజు ₹499 చెల్లించండి.",
            "expected_severity": ["high_risk", "critical"]
        },
        {
            "name": "Spanish Account Suspension Phish",
            "lang": "Spanish",
            "text": "¡Urgente! Su cuenta bancaria ha sido suspendida. Haga clic aquí para verificar su contraseña y código OTP de inmediato.",
            "expected_severity": ["high_risk", "critical"]
        }
    ]

    print("==========================================================================================")
    print(f"{'REGIONAL TEST CASE':<32} | {'DETECTED LANG':<15} | {'RISK SCORE':<10} | {'SEVERITY':<12}")
    print("==========================================================================================")

    for tc in test_cases:
        norm = ContentNormalizer.normalize_social(tc["text"], "telegram")
        res = await SecurityAnalyzer.analyze(norm)
        lang_info = res.language_info or {}
        detected = lang_info.get("detected_language", "English")
        
        print(f"{tc['name']:<32} | {detected:<15} | {res.assessment.risk_score:<10} | {res.assessment.severity.upper():<12}")
        assert res.assessment.severity in tc["expected_severity"], f"Failed severity check for {tc['name']}"
        print(f" -> Translated Text: {lang_info.get('translated_text', '')}")
        print(f" -> Category: {res.assessment.category}\n")

    print("==========================================================================================")
    print("ALL REGIONAL LANGUAGE TESTS PASSED WITH 100% PRECISION!")

if __name__ == "__main__":
    asyncio.run(test_multilingual())

