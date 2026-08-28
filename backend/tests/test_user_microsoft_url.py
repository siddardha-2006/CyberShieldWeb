import sys
import os
import asyncio
import httpx

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main import app

async def test_api():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
        res = await client.post('/api/v1/analyze/url', json={'url': 'http://microsoft.security-login.example.com'})
        print(f'Status: {res.status_code}')
        data = res.json()
        print(f'Fused Risk Score: {data["assessment"]["risk_score"]}')
        print(f'Severity: {data["assessment"]["severity"]}')
        ti = data["engines"]["threat_intelligence"]
        print(f'Threat Intel Score: {ti["score"]}')
        print(f'Threat Intel Sources: {ti["sources"]}')
        print(f'Threat Intel Evidence Count: {len(ti["evidence"])}')
        for ev in ti["evidence"]:
            print(f'  -> {ev["title"]}: {ev["description"]}')

if __name__ == "__main__":
    asyncio.run(test_api())

