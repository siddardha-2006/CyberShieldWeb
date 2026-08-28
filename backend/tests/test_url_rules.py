import sys
import os
import asyncio

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.normalization.normalizer import ContentNormalizer
from app.detection.rules.engine import RuleEngine

test_urls = [
    ('Clean Google', 'https://www.google.com'),
    ('Clean Wikipedia', 'https://en.wikipedia.org/wiki/Main_Page'),
    ('Brand Phishing (br-icloud)', 'http://br-icloud.com.br'),
    ('Direct Malware Payload (.exe)', 'http://downloads-update.com/update_patch.pdf.exe'),
    ('@ Symbol Obfuscation', 'http://google.com@malicious-phish-portal.com/login'),
    ('Free Tunnel Hosting (ngrok)', 'https://98a1-2405.ngrok-free.app/login'),
    ('Pre-filled Victim Email Parameter', 'https://secure-portal.com/auth?email=user@company.com'),
    ('Open Redirect Exploitation', 'https://trustedsite.com/redirect?url=http://evil-site.com'),
    ('Raw IP + Credential Path', 'http://192.168.1.100/secure/bank-login.php'),
    ('Disposable TLD (.xyz)', 'https://verify-banking.xyz/account/login')
]

async def run_test():
    print("========================================================================================")
    print(f'{"URL TEST CASE":<38} | {"SCORE":<8} | {"MATCHED RULES"}')
    print("========================================================================================")
    for name, url in test_urls:
        norm = ContentNormalizer.normalize_url(url)
        res = await RuleEngine.analyze(norm)
        rules_str = ', '.join([e.code for e in res.evidence])
        print(f'{name:<38} | {res.score:<8} | {len(res.evidence)} rules -> {rules_str}')
    print("========================================================================================")

if __name__ == "__main__":
    asyncio.run(run_test())

