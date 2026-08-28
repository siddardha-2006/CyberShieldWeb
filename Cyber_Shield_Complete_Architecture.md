# Cyber Shield — Complete Full-Stack Website Architecture

> **Build specification:** This document is the clean, current architecture for developing the Cyber Shield web application. It intentionally contains only the current design decisions and does not preserve superseded architecture choices.

---

# 1. Project Overview

Cyber Shield is a privacy-first cybersecurity analysis platform that accepts multiple forms of potentially malicious digital content and produces an explainable security assessment.

Supported inputs:

- URL
- SMS / text message
- Email
- QR code
- Webpage
- Social-media message

The system uses **exactly four detection engines**:

1. Rule-Based Detection Engine
2. AI/NLP Detection Engine
3. Threat Intelligence Engine
4. Behavioral Analysis Engine

The four engines are independent evidence producers and are executed **in parallel whenever the input supports the corresponding analysis**.

There is:

- No threat fingerprinting module
- No additional detection engine
- No blockchain layer
- No quantum-security layer
- No LLM-only detection architecture

The core objective is:

```text
Extract → Normalize → Analyze in Parallel → Fuse Evidence
→ Calculate Risk → Explain → Recommend Safe Action
```

---

# 2. Core Architecture

```text
                         USER
                          |
                          v
              +-----------------------+
              | React + TypeScript    |
              | Vite + Tailwind CSS   |
              +-----------+-----------+
                          |
                         HTTPS
                          |
                          v
              +-----------------------+
              | NGINX Reverse Proxy   |
              +-----------+-----------+
                          |
                          v
              +-----------------------+
              | FastAPI Backend       |
              | Python + Uvicorn      |
              +-----------+-----------+
                          |
                          v
              +-----------------------+
              | Validation & Auth     |
              +-----------+-----------+
                          |
                          v
              +-----------------------+
              | Content Extraction    |
              +-----------+-----------+
                          |
                          v
              +-----------------------+
              | Normalization         |
              +-----------+-----------+
                          |
                +---------+---------+
                |                   |
                v                   v
        Privacy Identifier     Temporary Raw Data
        HMAC-SHA-256                |
                                    |
             ===== FOUR PARALLEL DETECTION ENGINES =====
                  |          |          |          |
                  v          v          v          v
               RULES      AI/NLP     THREAT     BEHAVIOR
                                     INTEL       ANALYSIS
                  |          |          |          |
                  +----------+----------+----------+
                                     |
                                     v
                             Evidence Fusion
                                     |
                                     v
                             Risk Aggregator
                                     |
                       +-------------+-------------+
                       |             |             |
                       v             v             v
                   Risk Score    Confidence    Category
                       |
                       v
                  Explainability
                       |
                       v
                  Safe Action
                       |
                       v
                    MongoDB
                       |
                       v
                  React Result
```

**Important:** The diagram represents the logical architecture. The four applicable engines must be launched concurrently rather than as a serial chain.

---

# 3. Final Technology Stack

## Frontend

```text
React
TypeScript
Vite
Tailwind CSS
Axios
React Router
```

## Backend

```text
Python
FastAPI
Uvicorn
Pydantic
PyMongo
```

## Database

```text
MongoDB
```

## Parallel execution

```text
Python asyncio
asyncio.gather()
```

## AI / NLP

```text
PyTorch
Hugging Face Transformers
scikit-learn
```

## Rule engine

```text
Python
Regex
JSON rule definitions
urllib.parse
tldextract
```

## Threat intelligence

```text
VirusTotal API
URLhaus
PhishTank
```

## Behavioral analysis

```text
Playwright
Chromium
```

## Content extraction

```text
BeautifulSoup
urllib.parse
tldextract
dnspython
urlextract
phonenumbers
Python email package
dkimpy
ZXing
```

## Security

```text
JWT
Argon2
HMAC-SHA-256
SSRF protection
Rate limiting
Input validation
Secure HTTP headers
```

## Optional cache

```text
Redis
```

## Reverse proxy

```text
NGINX
```

## Deployment

```text
Native development environment
Docker/container isolation for browser analysis when required
```

---

# 4. Why This Technology Stack

## React + TypeScript

Used for:

- Responsive cybersecurity dashboard
- Multi-input analyzer
- Real-time analysis status
- Risk visualization
- Evidence display
- Analysis history
- Reporting

TypeScript provides compile-time safety for API response structures.

---

## FastAPI

Used because the backend requires:

- High-performance APIs
- Async processing
- Easy Pydantic validation
- Native Python AI/ML integration
- Concurrent engine execution
- Easy API documentation

FastAPI is the central application backend.

---

## MongoDB

MongoDB is used as the persistent database because the output of the four engines is naturally document-oriented.

Engine results can contain different evidence structures:

```text
Rules:
    rule_id
    matched_pattern
    weight

AI/NLP:
    classification
    probability
    semantic evidence

Threat Intelligence:
    provider
    reputation
    malicious indicators

Behavior:
    redirects
    forms
    network behavior
```

MongoDB allows these heterogeneous results to be represented cleanly in analysis documents.

---

## Python asyncio

The four engines are independent analysis tasks.

Therefore:

```python
results = await asyncio.gather(
    run_rules(),
    run_nlp(),
    run_threat_intelligence(),
    run_behavior()
)
```

This avoids unnecessary sequential waiting.

---

# 5. Input Types

## URL

Examples:

```text
https://example.com
http://192.168.1.10/login
```

Extract:

```text
scheme
hostname
registered domain
subdomain
port
path
query
fragment
IP address
DNS information
```

---

## SMS / Message

Extract:

```text
URLs
domains
phone numbers
email addresses
urgency terms
financial terms
credential requests
OTP requests
social-engineering indicators
```

---

## Email

Extract:

```text
From
Reply-To
Subject
Body
Headers
URLs
Domains
Authentication-related signals
```

---

## QR Code

Flow:

```text
QR image
   |
   v
ZXing
   |
   v
Decoded payload
   |
   +---- URL ------> URL analysis
   |
   +---- Text -----> Message analysis
```

---

## Webpage

Extract:

```text
HTML
visible text
links
forms
metadata
scripts
redirects
network activity
```

Static extraction uses BeautifulSoup.

Dynamic analysis uses Playwright.

---

## Social Message

Treat social messages as structured message input:

```text
text
URLs
domains
phone numbers
email addresses
attachments/metadata where available
```

The application should only analyze data that the user or an authorized integration legitimately provides.

---

# 6. Content Extraction Layer

The extraction layer is independent from the four detection engines.

Structure:

```text
backend/app/extraction/
├── url.py
├── message.py
├── email.py
├── qr.py
└── webpage.py
```

Its only responsibility is:

```text
Raw Input
   ↓
Extract Indicators
   ↓
Structured Analysis Object
```

It should not make the final malicious/safe decision.

---

# 7. Normalization Layer

Different inputs must be converted to a common representation.

Example:

```json
{
  "analysis_id": "uuid",
  "input_type": "email",
  "text": "...",
  "urls": [
    "https://example.com/login"
  ],
  "domains": [
    "example.com"
  ],
  "emails": [],
  "phones": [],
  "headers": {},
  "metadata": {}
}
```

The four engines consume this normalized representation.

---

# 8. Privacy-First Data Architecture

Cyber Shield should follow:

> **Process raw data temporarily, persist derived security information.**

The system should avoid permanently storing:

```text
Raw SMS
Raw email
Private message
Full webpage content
Unnecessary URL history
```

Instead:

```text
Normalized indicator
        |
        v
HMAC-SHA-256
        |
        v
Cryptographic identifier
        |
        v
MongoDB
```

Use:

```text
HMAC-SHA-256(server_secret, normalized_value)
```

rather than relying only on ordinary SHA-256 for sensitive low-entropy values.

The HMAC secret must never be stored inside MongoDB.

Store it in protected environment/secret configuration:

```text
CYBER_SHIELD_HMAC_SECRET
```

---

# 9. Temporary Data Lifecycle

```text
User Input
    |
    v
Temporary memory
    |
    v
Extraction
    |
    v
Normalization
    |
    v
Four Engines
    |
    v
Derived Evidence
    |
    v
Persist Required Results
    |
    v
Delete / Expire Raw Data
```

Raw content should exist only for the minimum time necessary.

Application logs must also avoid logging raw user messages, emails, tokens, or sensitive URLs.

---

# 10. Detection Architecture

The four engines are the core security system.

```text
                         NORMALIZED INPUT
                                |
          +---------------------+---------------------+
          |                     |                     |
          v                     v                     v
      RULE ENGINE           AI/NLP ENGINE       THREAT INTEL
          |                     |                     |
          +---------------------+---------------------+
                                |
                         BEHAVIOR ENGINE
                                |
                                v
                         EVIDENCE FUSION
```

Implementation principle:

```python
results = await asyncio.gather(
    rules_engine.analyze(data),
    nlp_engine.analyze(data),
    threat_intelligence_engine.analyze(data),
    behavioral_engine.analyze(data),
    return_exceptions=True
)
```

The production implementation must include:

```text
Timeout handling
Exception handling
Engine status
Resource limits
Cancellation
Partial-result support
```

---

# 11. Engine Applicability

Not every input requires every engine.

## SMS

```text
Rules               ✓
AI/NLP              ✓
Threat Intelligence ✓
Behavior            Not applicable
```

## URL

```text
Rules               ✓
AI/NLP              ✓ when contextual text exists
Threat Intelligence ✓
Behavior            ✓
```

## Email

```text
Rules               ✓
AI/NLP              ✓
Threat Intelligence ✓
Behavior            ✓ when URLs/webpages are present
```

## QR

```text
QR Decode
    ↓
URL/Text
    ↓
Applicable engines
```

This is an optimization, not a change to the four-engine architecture.

---

# 12. Engine 1 — Rule-Based Detection

## Purpose

Detect known suspicious patterns deterministically.

Technology:

```text
Python
Regex
JSON
urllib.parse
tldextract
```

Directory:

```text
backend/app/detection/rules/
├── engine.py
├── rule_loader.py
├── rule_schema.py
├── url_rules.py
├── message_rules.py
├── email_rules.py
└── webpage_rules.py
```

Rules can detect:

```text
IP-based URL hosts
Suspicious URL encoding
Excessive subdomains
Suspicious URL structure
Credential requests
OTP requests
Urgency language
Financial pressure
Brand impersonation indicators
Obfuscated URLs
Suspicious form fields
```

Example rule:

```json
{
  "id": "OTP_REQUEST",
  "description": "Request for one-time password detected",
  "weight": 20,
  "category": "credential_theft"
}
```

Output:

```json
{
  "engine": "rules",
  "status": "completed",
  "score": 82,
  "confidence": 0.91,
  "evidence": [
    {
      "rule_id": "OTP_REQUEST",
      "description": "Request for one-time password detected",
      "weight": 20
    }
  ],
  "latency_ms": 25
}
```

---

# 13. Engine 2 — AI/NLP Detection

## Purpose

Understand semantic meaning and user-manipulation intent.

Technology:

```text
PyTorch
Hugging Face Transformers
scikit-learn
```

Directory:

```text
backend/app/detection/nlp/
├── engine.py
├── model.py
├── tokenizer.py
├── preprocessing.py
├── classifier.py
└── model_manager.py
```

Detect:

```text
Phishing
Scams
Social engineering
Credential theft
Financial manipulation
Urgency
Threatening language
Impersonation
Fraudulent intent
```

Pipeline:

```text
Text
  |
  v
Preprocessing
  |
  v
Tokenizer
  |
  v
Transformer Model
  |
  v
Classifier
  |
  v
Probabilities
  |
  v
Security Evidence
```

Example output:

```json
{
  "engine": "nlp",
  "status": "completed",
  "score": 94,
  "confidence": 0.96,
  "classifications": {
    "phishing": 0.94,
    "scam": 0.88,
    "social_engineering": 0.97,
    "credential_theft": 0.91
  },
  "latency_ms": 310
}
```

---

# 14. Engine 3 — Threat Intelligence

## Purpose

Check extracted indicators against known external threat intelligence.

Providers:

```text
VirusTotal
URLhaus
PhishTank
```

Directory:

```text
backend/app/detection/threat_intel/
├── engine.py
├── virustotal.py
├── urlhaus.py
├── phishtank.py
├── normalizer.py
└── cache.py
```

Architecture:

```text
Indicator
   |
   +----> VirusTotal
   |
   +----> URLhaus
   |
   +----> PhishTank
   |
   v
Provider Result Normalization
   |
   v
Threat Intelligence Evidence
```

Example:

```json
{
  "engine": "threat_intelligence",
  "status": "completed",
  "score": 100,
  "confidence": 0.98,
  "malicious": true,
  "sources": [
    "VirusTotal",
    "URLhaus"
  ],
  "latency_ms": 480
}
```

Provider failures must be represented honestly:

```json
{
  "engine": "threat_intelligence",
  "status": "unavailable"
}
```

An unavailable provider must not automatically produce either a safe or malicious verdict.

---

# 15. Engine 4 — Behavioral Analysis

## Purpose

Observe what a webpage actually does.

Technology:

```text
Playwright
Chromium
```

Directory:

```text
backend/app/detection/behavior/
├── engine.py
├── browser.py
├── page_analyzer.py
├── network_analyzer.py
├── form_analyzer.py
├── redirect_analyzer.py
└── policy.py
```

Detect:

```text
Redirect chains
Login forms
Password fields
OTP fields
Payment forms
External form submission
Suspicious scripts
Network destinations
Unexpected downloads
Suspicious navigation
```

Flow:

```text
URL
 |
 v
SSRF validation
 |
 v
Playwright
 |
 v
Chromium
 |
 +---- Redirect analysis
 +---- Form analysis
 +---- Network analysis
 +---- Script observations
 +---- Navigation analysis
 |
 v
Behavior Evidence
```

Example:

```json
{
  "engine": "behavior",
  "status": "completed",
  "score": 95,
  "confidence": 0.93,
  "observations": {
    "redirect_count": 3,
    "login_form": true,
    "password_field": true,
    "otp_field": true,
    "payment_request": true
  },
  "latency_ms": 850
}
```

---

# 16. Behavioral Worker Security

Behavioral analysis is the highest-risk subsystem because it interacts with potentially hostile webpages.

Do not give arbitrary webpages access to the application infrastructure.

Required protections:

```text
SSRF protection
Private IP blocking
Localhost blocking
Cloud metadata endpoint blocking
Redirect limits
Navigation timeout
Page-size limits
Download restrictions
Browser permission restrictions
Network policy
Resource limits
```

Production architecture:

```text
FastAPI
   |
   v
Behavior Analysis Job
   |
   v
Isolated Browser Environment
   |
   +-- Playwright
   +-- Chromium
   |
   v
Structured Behavioral Result
```

Docker or another isolation technology should be introduced specifically for this worker when stronger production isolation is required. It does not need to be a requirement for the entire application during development.

---

# 17. Standard Engine Contract

All four engines must return a common structure:

```json
{
  "engine": "rules",
  "status": "completed",
  "score": 82,
  "confidence": 0.91,
  "evidence": [],
  "latency_ms": 25
}
```

Allowed statuses:

```text
completed
timeout
error
unavailable
not_applicable
```

This makes the orchestration layer predictable.

---

# 18. Evidence Fusion

The four engines produce independent evidence.

Example:

```text
Rules              = 82
AI/NLP             = 94
Threat Intelligence= 100
Behavior           = 95
```

Evidence Fusion creates a unified internal representation.

It must preserve:

```text
Engine
Score
Confidence
Evidence
Status
Latency
```

Do not discard evidence merely because the final score is calculated.

---

# 19. Risk Aggregation

Initial weighting:

```text
Rules                 25%
AI/NLP                30%
Threat Intelligence   25%
Behavior              20%
```

Formula:

```text
Risk =
    0.25 × Rules
  + 0.30 × AI/NLP
  + 0.25 × Threat Intelligence
  + 0.20 × Behavior
```

Example:

```text
Rules                 82
AI/NLP                94
Threat Intelligence   100
Behavior              95
```

Approximate result:

```text
Risk = 93
```

These weights are initial engineering values and should later be calibrated against labelled validation data.

---

# 20. Risk Categories

```text
0–29     SAFE
30–59    SUSPICIOUS
60–79    HIGH RISK
80–100   CRITICAL
```

Possible threat categories:

```text
Phishing
Scam
Credential Theft
Financial Fraud
Malware
Social Engineering
Brand Impersonation
Suspicious URL
Malicious Webpage
QR Scam
Identity Theft
```

---

# 21. Risk vs Confidence

Keep these as separate values.

Example:

```text
Risk:
94 / 100

Confidence:
97%
```

Meaning:

```text
Risk       = estimated danger
Confidence = confidence in the assessment
```

---

# 22. Explainability Layer

The system must explain the decision using structured evidence.

Example:

```text
CRITICAL RISK
94 / 100

Category:
Phishing

Confidence:
97%

Why?

✓ Suspicious URL structure
✓ Known malicious reputation
✓ Urgency language
✓ Credential request
✓ OTP field
✓ Suspicious redirect behavior

Recommended Action:

Do not enter credentials or OTP.
Close the webpage.
Report the content.
```

The explanation layer should be deterministic and evidence-backed.

It must not invent reasons that were not produced by the engines.

---

# 23. Safe Action Engine

The result should map to a recommended user action:

```text
ALLOW
WARN
DO_NOT_INTERACT
REPORT
BLOCK
```

Example:

```text
Risk 0–29
    → Allow / Normal caution

Risk 30–59
    → Warn

Risk 60–79
    → Do not interact

Risk 80–100
    → Do not interact + Report
```

The exact policy should be configurable.

---

# 24. MongoDB Architecture

Suggested collections:

```text
users
analyses
engine_results
evidence
reports
```

Example analysis document:

```json
{
  "_id": "...",
  "analysis_id": "...",

  "input": {
    "type": "url",
    "indicator_hmac": "..."
  },

  "result": {
    "risk_score": 94,
    "confidence": 0.97,
    "severity": "critical",
    "category": "phishing",
    "recommended_action": "do_not_interact"
  },

  "engines": {
    "rules": {
      "score": 82,
      "confidence": 0.91,
      "status": "completed"
    },

    "nlp": {
      "score": 94,
      "confidence": 0.96,
      "status": "completed"
    },

    "threat_intelligence": {
      "score": 100,
      "confidence": 0.98,
      "status": "completed"
    },

    "behavior": {
      "score": 95,
      "confidence": 0.93,
      "status": "completed"
    }
  },

  "evidence": [],
  "created_at": "..."
}
```

No threat fingerprint field is required.

---

# 25. Redis Usage

Redis is optional.

If included, use it for:

```text
Threat-intelligence caching
Rate limiting
Temporary analysis state
Short-lived results
```

Do not use Redis as a replacement for MongoDB's persistent result storage.

---

# 26. Authentication

Use:

```text
JWT
Argon2
FastAPI security utilities
```

Flow:

```text
Register
   |
   v
Password hashing
   |
   v
MongoDB
```

Login:

```text
Credentials
   |
   v
Verify password
   |
   v
JWT
   |
   v
Authorized API access
```

Never store plaintext passwords.

---

# 27. API Architecture

Suggested endpoints:

```text
POST /api/v1/auth/register
POST /api/v1/auth/login
GET  /api/v1/auth/me

POST /api/v1/analyze/url
POST /api/v1/analyze/message
POST /api/v1/analyze/email
POST /api/v1/analyze/qr
POST /api/v1/analyze/webpage

GET  /api/v1/analysis/{analysis_id}
GET  /api/v1/history

POST /api/v1/reports
```

The frontend communicates only with the FastAPI backend.

Threat-intelligence API keys remain server-side.

---

# 28. Complete Backend File Organization

```text
backend/
├── app/
│   ├── main.py
│   │
│   ├── api/
│   │   ├── auth.py
│   │   ├── analyze.py
│   │   ├── history.py
│   │   └── reports.py
│   │
│   ├── core/
│   │   ├── config.py
│   │   ├── security.py
│   │   └── logging.py
│   │
│   ├── extraction/
│   │   ├── url.py
│   │   ├── message.py
│   │   ├── email.py
│   │   ├── qr.py
│   │   └── webpage.py
│   │
│   ├── normalization/
│   │   └── normalizer.py
│   │
│   ├── privacy/
│   │   ├── hmac.py
│   │   ├── sanitizer.py
│   │   └── retention.py
│   │
│   ├── detection/
│   │   ├── rules/
│   │   │   ├── engine.py
│   │   │   ├── rule_loader.py
│   │   │   ├── rule_schema.py
│   │   │   ├── url_rules.py
│   │   │   ├── message_rules.py
│   │   │   ├── email_rules.py
│   │   │   └── webpage_rules.py
│   │   │
│   │   ├── nlp/
│   │   │   ├── engine.py
│   │   │   ├── model.py
│   │   │   ├── tokenizer.py
│   │   │   ├── preprocessing.py
│   │   │   ├── classifier.py
│   │   │   └── model_manager.py
│   │   │
│   │   ├── threat_intel/
│   │   │   ├── engine.py
│   │   │   ├── virustotal.py
│   │   │   ├── urlhaus.py
│   │   │   ├── phishtank.py
│   │   │   ├── normalizer.py
│   │   │   └── cache.py
│   │   │
│   │   └── behavior/
│   │       ├── engine.py
│   │       ├── browser.py
│   │       ├── page_analyzer.py
│   │       ├── network_analyzer.py
│   │       ├── form_analyzer.py
│   │       ├── redirect_analyzer.py
│   │       └── policy.py
│   │
│   ├── orchestration/
│   │   ├── analyzer.py
│   │   ├── parallel.py
│   │   └── schemas.py
│   │
│   ├── risk/
│   │   ├── aggregator.py
│   │   ├── confidence.py
│   │   └── categories.py
│   │
│   ├── explainability/
│   │   └── explanations.py
│   │
│   ├── database/
│   │   ├── mongodb.py
│   │   └── repositories/
│   │       ├── users.py
│   │       ├── analyses.py
│   │       └── reports.py
│   │
│   ├── models/
│   │   ├── user.py
│   │   ├── analysis.py
│   │   ├── engine_result.py
│   │   ├── evidence.py
│   │   └── report.py
│   │
│   └── schemas/
│       ├── auth.py
│       ├── analysis.py
│       └── report.py
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── security/
│
├── requirements.txt
└── .env.example
```

---

# 29. Complete Frontend File Organization

```text
frontend/
├── public/
│
├── src/
│   ├── components/
│   │   ├── analysis/
│   │   │   ├── InputSelector.tsx
│   │   │   ├── UrlAnalyzer.tsx
│   │   │   ├── MessageAnalyzer.tsx
│   │   │   ├── EmailAnalyzer.tsx
│   │   │   ├── QrUploader.tsx
│   │   │   ├── WebpageAnalyzer.tsx
│   │   │   ├── AnalysisProgress.tsx
│   │   │   ├── EngineStatus.tsx
│   │   │   ├── RiskScore.tsx
│   │   │   ├── SeverityBadge.tsx
│   │   │   ├── EvidenceList.tsx
│   │   │   └── RecommendationCard.tsx
│   │   │
│   │   ├── dashboard/
│   │   ├── history/
│   │   ├── reports/
│   │   └── common/
│   │
│   ├── pages/
│   │   ├── Dashboard.tsx
│   │   ├── Analyze.tsx
│   │   ├── Result.tsx
│   │   ├── History.tsx
│   │   ├── Reports.tsx
│   │   ├── Login.tsx
│   │   └── Register.tsx
│   │
│   ├── services/
│   │   ├── api.ts
│   │   ├── analysis.ts
│   │   └── auth.ts
│   │
│   ├── hooks/
│   ├── types/
│   ├── utils/
│   ├── layouts/
│   ├── App.tsx
│   └── main.tsx
│
├── package.json
├── tsconfig.json
└── vite.config.ts
```

---

# 30. Rule Configuration

Keep rules outside Python code:

```text
rules/
├── url_rules.json
├── message_rules.json
├── email_rules.json
└── webpage_rules.json
```

Benefits:

```text
Easy rule updates
Versioning
Testing
Auditing
Transparent detection
```

---

# 31. ML Model Organization

```text
ml/
├── datasets/
├── training/
├── evaluation/
└── models/
```

The training pipeline should be separate from production inference.

Production backend loads a tested model rather than training during an analysis request.

---

# 32. Parallel Analysis Lifecycle

Example URL:

```text
User submits URL
       |
       v
Validate
       |
       v
Extract
       |
       v
Normalize
       |
       +-------------------+
       |                   |
       v                   v
Generate HMAC       Temporary Data
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
       Rules            AI/NLP        Threat Intel
          |                |                |
          +----------------+----------------+
                           |
                           v
                      Behavior
                           |
                           v
                    Evidence Fusion
                           |
                           v
                    Risk Aggregator
                           |
                           v
                     Explanation
                           |
                           v
                      Safe Action
                           |
                           v
                       MongoDB
```

Implementation should use concurrent execution for the four applicable engines.

---

# 33. Handling Slow Engines

The system must not fail just because one engine is slow.

Example:

```text
Rules              completed
AI/NLP             completed
Threat Intelligence timeout
Behavior            completed
```

Return:

```json
{
  "status": "partial",
  "engines": {
    "rules": "completed",
    "nlp": "completed",
    "threat_intelligence": "timeout",
    "behavior": "completed"
  }
}
```

The Risk Aggregator must know which engines actually contributed evidence.

Do not treat a timeout as a malicious verdict.

---

# 34. Security Architecture

## API security

```text
HTTPS
JWT
Rate limiting
Input validation
Secure headers
Authentication
Authorization
```

## URL security

```text
Validate scheme
Normalize URL
Resolve destination safely
Block private IPs
Block localhost
Block metadata endpoints
Limit redirects
Limit response size
Apply timeouts
```

## Browser security

```text
Isolated browser context
Restricted permissions
No unnecessary downloads
Network restrictions
CPU limits
Memory limits
Execution timeout
```

## Database security

```text
Authentication
Least-privilege database account
Encrypted connections
No raw sensitive data unless required
HMAC-based identifiers
Retention policies
```

---

# 35. Logging Policy

Never log:

```text
Raw SMS
Full email bodies
Passwords
OTP values
Authentication tokens
HMAC secret
Sensitive personal data
```

Log:

```text
Analysis ID
Input type
Engine status
Latency
Risk score
Category
Error code
Request timestamp
```

Example:

```text
analysis_id=a81f
input_type=url
engine=behavior
status=completed
latency=842ms
```

---

# 36. Monitoring

Use application-level metrics.

Track:

```text
API latency
Total analysis latency
Rules latency
NLP latency
Threat-intelligence latency
Behavior latency
Engine failure rate
Engine timeout rate
Threat-intelligence cache hit rate
Database latency
```

The project can expose metrics for Prometheus when production monitoring is required.

---

# 37. Testing

## Unit testing

Test:

```text
URL extraction
Email extraction
QR decoding
Message extraction
Normalization
HMAC generation
Rule matching
NLP inference
Threat-intelligence normalization
Behavior analysis
Risk calculation
Explanation generation
```

## Integration testing

Test:

```text
API → extraction
API → normalization
API → four engines
Four engines → evidence fusion
Evidence fusion → risk aggregation
Risk result → MongoDB
```

## Security testing

Test:

```text
SSRF
Private IP access
Malformed URLs
Oversized input
Malicious HTML
Rate limiting
JWT validation
Authorization
Secret leakage
Injection attempts
Browser escape attempts
```

---

# 38. Development Setup

## Required local software

```text
Node.js
Python
MongoDB
Git
Chromium / Playwright
```

Redis is optional.

Docker is not required for the normal development environment.

---

# 39. Local Application Startup

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Backend:

```bash
cd backend
python -m venv .venv
```

Activate the virtual environment and install:

```bash
pip install -r requirements.txt
```

Start FastAPI:

```bash
uvicorn app.main:app --reload
```

Install Playwright browsers:

```bash
playwright install chromium
```

---

# 40. Environment Configuration

`.env.example`:

```text
MONGODB_URI=
MONGODB_DATABASE=cyber_shield

JWT_SECRET=
CYBER_SHIELD_HMAC_SECRET=

VIRUSTOTAL_API_KEY=

REDIS_URL=

CORS_ORIGINS=
ENVIRONMENT=development
```

Never commit real credentials.

---

# 41. Example Complete Detection

Input:

```text
URGENT!
Your bank account will be blocked.
Verify KYC and enter OTP:
https://fake-example.test/login
```

Extraction:

```text
Text
URL
Domain
Bank context
KYC
OTP
Urgency
```

Parallel engines:

```text
RULES
├── Urgency
├── OTP request
└── Suspicious URL

AI/NLP
├── Phishing intent
├── Social engineering
└── Credential theft

THREAT INTELLIGENCE
└── Reputation result

BEHAVIOR
├── Login form
├── OTP field
└── Redirect behavior
```

Fusion:

```text
Rules              82
AI/NLP             94
Threat Intelligence 100
Behavior            95
```

Risk:

```text
93 / 100
```

Result:

```text
CRITICAL
Phishing
Confidence: 97%

Action:
Do not interact.
Do not enter credentials or OTP.
Report the content.
```

---

# 42. Website User Experience

The main dashboard should provide:

```text
+--------------------------------------+
|             CYBER SHIELD             |
+--------------------------------------+
| What do you want to analyze?         |
|                                      |
| [ URL ] [ MESSAGE ] [ EMAIL ] [ QR ] |
| [ WEBPAGE ] [ SOCIAL MESSAGE ]       |
|                                      |
|        [ START ANALYSIS ]             |
+--------------------------------------+
```

During analysis:

```text
Analyzing...

✓ Content Extraction
✓ Normalization
✓ Rule Engine
✓ AI/NLP Engine
✓ Threat Intelligence
◉ Behavioral Analysis
```

Result:

```text
┌──────────────────────────────────────┐
│          CRITICAL RISK               │
│             94 / 100                 │
│                                      │
│ Category: Phishing                   │
│ Confidence: 97%                      │
├──────────────────────────────────────┤
│ RULE ENGINE              82           │
│ AI / NLP                 94           │
│ THREAT INTELLIGENCE     100           │
│ BEHAVIOR                 95           │
├──────────────────────────────────────┤
│ WHY?                                 │
│ • Suspicious URL                     │
│ • Credential request                 │
│ • Malicious reputation               │
│ • Suspicious webpage behavior        │
├──────────────────────────────────────┤
│ ACTION: DO NOT INTERACT              │
└──────────────────────────────────────┘
```

---

# 43. Architecture Principles

## Principle 1 — Four engines only

```text
Rules
AI/NLP
Threat Intelligence
Behavior
```

These are the only detection engines.

---

## Principle 2 — Parallel analysis

The four engines independently analyze the normalized input.

```text
                    Input
                      |
        +-------------+-------------+
        |             |             |
      Rules         AI/NLP       Threat
        |             |           Intel
        +-------------+-------------+
                      |
                  Behavior
                      |
                      v
                Evidence Fusion
```

The implementation should use concurrency rather than unnecessary sequential dependencies.

---

## Principle 3 — Evidence before verdict

The system should produce:

```text
Evidence
   ↓
Engine score
   ↓
Confidence
   ↓
Risk
```

not:

```text
AI guess
   ↓
Final answer
```

---

## Principle 4 — Privacy by design

```text
Raw data
   ↓
Temporary processing
   ↓
Derived security result
   ↓
HMAC identifier
   ↓
Persistent storage
```

---

## Principle 5 — Explainability

Every high-risk result should have evidence-backed reasons.

---

## Principle 6 — Fail safely

An unavailable engine must not fabricate a result.

---

## Principle 7 — Isolate hostile webpage execution

Behavioral Analysis must have stronger isolation than ordinary API processing.

---

# 44. Development Roadmap

Build in this sequence:

```text
Phase 1
Project structure
Frontend
FastAPI
MongoDB

Phase 2
Authentication
Input APIs
Extraction
Normalization

Phase 3
Rule Engine

Phase 4
AI/NLP Engine

Phase 5
Threat Intelligence Engine

Phase 6
Behavioral Analysis

Phase 7
Parallel Orchestration

Phase 8
Evidence Fusion
Risk Aggregation

Phase 9
Explainability
Safe Actions

Phase 10
History
Reports
Privacy/retention

Phase 11
Security hardening

Phase 12
Testing
Monitoring
Deployment
```

---

# 45. Definition of Done

The implementation is complete when:

- React frontend is functional.
- FastAPI backend is functional.
- MongoDB persistence works.
- Users can authenticate.
- URL analysis works.
- Message analysis works.
- Email analysis works.
- QR decoding works.
- Webpage analysis works.
- Social-message analysis works.
- Content extraction is separated from detection.
- Normalization produces a common analysis structure.
- Sensitive identifiers use HMAC-SHA-256 where appropriate.
- Raw content is not unnecessarily persisted.
- Rule Engine works.
- AI/NLP Engine works.
- Threat Intelligence Engine works.
- Behavioral Analysis Engine works.
- Four engines execute concurrently when applicable.
- Engine timeouts and failures are handled.
- Evidence is preserved.
- Risk is calculated.
- Confidence is calculated separately.
- Threat category is generated.
- Explainable reasons are generated from evidence.
- Safe action is recommended.
- Analysis history works.
- Reporting works.
- SSRF protection is implemented.
- Browser execution is isolated appropriately.
- Secrets are not committed.
- Security tests exist.
- The application can run locally without requiring Docker for the general stack.

---

# 46. Final Architecture Summary

```text
                         CYBER SHIELD
                              |
                              v
                     React + TypeScript
                              |
                              v
                       FastAPI Backend
                              |
                              v
                    Input Validation/Auth
                              |
                              v
                     Content Extraction
                              |
                              v
                       Normalization
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
           RULES           AI/NLP       THREAT INTEL
              |               |               |
              +---------------+---------------+
                              |
                         BEHAVIOR
                              |
                              v
                       Evidence Fusion
                              |
                              v
                       Risk Aggregator
                              |
                  +-----------+-----------+
                  |           |           |
                  v           v           v
                Risk     Confidence    Category
                              |
                              v
                        Explainability
                              |
                              v
                         Safe Action
                              |
                              v
                           MongoDB
```

## Final technology decision

```text
Frontend:
React + TypeScript + Vite + Tailwind

Backend:
Python + FastAPI + Uvicorn + Pydantic + PyMongo

Database:
MongoDB

Parallelism:
Python asyncio

Detection:
Rules + AI/NLP + Threat Intelligence + Behavioral Analysis

AI:
PyTorch + Transformers + scikit-learn

Threat Intelligence:
VirusTotal + URLhaus + PhishTank

Behavior:
Playwright + Chromium

Extraction:
BeautifulSoup + urllib.parse + tldextract
+ dnspython + urlextract + phonenumbers
+ email + dkimpy + ZXing

Security:
JWT + Argon2 + HMAC-SHA-256
+ SSRF protection + rate limiting

Infrastructure:
NGINX
Redis optional
Docker only where isolation is needed
```

**This is the authoritative architecture for the current Cyber Shield implementation.**
