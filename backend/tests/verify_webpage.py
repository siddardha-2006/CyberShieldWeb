import sys
import httpx

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

client = httpx.Client(base_url='http://127.0.0.1:8000', timeout=10.0)

test_cases = [
    # Normal URLs
    ('Normal URL 1 (Google)', 'url', {'url': 'https://www.google.com'}),
    ('Normal URL 2 (Wikipedia)', 'url', {'url': 'https://en.wikipedia.org/wiki/Computer_security'}),
    ('Normal URL 3 (GitHub)', 'url', {'url': 'https://github.com/torvalds/linux'}),

    # Malicious URLs
    ('Malicious URL 1 (br-icloud typosquat)', 'url', {'url': 'http://br-icloud.com.br'}),
    ('Malicious URL 2 (PayPal Phishing .xyz)', 'url', {'url': 'https://paypal-verify-account.xyz/login'}),
    ('Malicious URL 3 (IP host & path)', 'url', {'url': 'http://192.168.1.50/account/login-verify.php'}),

    # Normal Messages
    ('Normal Text 1 (Work Planning)', 'message', {'text': 'Hi team, please find attached the meeting minutes from our Tuesday planning session.'}),
    ('Normal Text 2 (Family Greeting)', 'message', {'text': 'Hey Mom, dinner was great, let me know when you arrive home safely!'}),

    # Malicious Messages
    ('Malicious Text 1 (Bank KYC Phish)', 'message', {'text': 'URGENT: State Bank account blocked due to pending KYC. Verify OTP within 24 hours: https://sbi-secure-kyc-update.com/login', 'sender': '+18005550199'}),
    ('Malicious Text 2 (Netflix Expire Scam)', 'message', {'text': 'ALERT: Your Netflix subscription has expired. Update your credit card details immediately: http://netflix-renew.top/auth', 'sender': 'ALERT'}),

    # Malicious Email
    ('Malicious Email (Executive BEC Wire)', 'email', {
        'sender': 'ceo@corporate-tech.com',
        'reply_to': 'hacker-mailbox@gmail.com',
        'subject': 'CONFIDENTIAL: Urgent Wire Transfer Required',
        'body': 'Are you at your desk? I need an urgent wire transfer of $45,000 processed before 3pm.'
    })
]

print('========================================================================================')
print(f'{"TEST CASE":<40} | {"RISK SCORE":<10} | {"SEVERITY":<12} | {"ACTION":<12}')
print('========================================================================================')

for name, endpoint, payload in test_cases:
    try:
        res = client.post(f'/api/v1/analyze/{endpoint}', json=payload)
        if res.status_code != 200:
            print(f'{name:<40} | ERROR {res.status_code}')
            continue
        data = res.json()
        score = data['assessment']['risk_score']
        severity = data['assessment']['severity'].upper()
        action = data['assessment']['recommended_action']
        print(f'{name:<40} | {score:<10} | {severity:<12} | {action:<12}')
    except Exception as e:
        print(f'{name:<40} | EXCEPTION: {e}')

print('========================================================================================')

try:
    frontend_res = httpx.get('http://127.0.0.1:5173/')
    print(f'Frontend Webpage Check (http://127.0.0.1:5173/): HTTP {frontend_res.status_code}')
except Exception as e:
    print(f'Frontend Webpage Check: ERROR {e}')

print('========================================================================================')

