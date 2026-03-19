# LLMGuardT2

> OWASP LLM Top 10 scanner with semantic similarity detection

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)
![GCP](https://img.shields.io/badge/GCP-Cloud_Run-red?logo=googlecloud)
![OWASP](https://img.shields.io/badge/OWASP-LLM_Top_10-orange)

---

## Overview

LLMGuardT2 is the Tier 2 evolution of LLMGuard — an OWASP LLM Top 10 red-teaming scanner that adds **semantic similarity detection** using sentence-transformers. Where the original scanner uses pattern matching, T2 uses embedding-based comparison to catch paraphrased, obfuscated, and semantically equivalent attacks that bypass literal string detection.

This closes a real gap in LLM security validation: attackers who know your detection patterns can trivially rephrase payloads to evade them. Semantic detection makes that significantly harder.

---

## Architecture

```
User → Web UI (Vanilla JS + Bootstrap)
    │
    ▼
Flask Backend (app.py)
    ├── Rate Limiter (IP-based, time-window)
    └── SSE Generator (_scan_generator)
            │
            ▼
        LLM Dispatcher (_dispatch)
            ├── _call_anthropic()   →  Claude
            └── _call_openai()      →  GPT-4
            │
            ▼
        Payload Library (scanner.py)
            ├── OWASP Category Filtering
            └── Payload Metadata (id, name, severity, prompt)
            │
            ▼
        Response Analyzer (analyze_response)
            ├── Semantic Detector (sentence-transformers)
            │   └── Cosine similarity vs. known vulnerability signals
            └── Status → VULNERABLE / PARTIAL / RESISTANT / REVIEW
            │
            ▼
    Real-Time SSE Results → Dashboard
```

---

## Key Upgrade: Semantic Detection

Traditional LLM scanners rely on substring matching — if the response contains `"I cannot"` it passes, otherwise it fails. This approach breaks when:

- The model rephrases a refusal in an unexpected way
- An attacker slightly paraphrases a known payload
- The response is contextually equivalent but not literally matching

**LLMGuardT2 uses sentence-transformers to compute semantic embeddings and cosine similarity**, comparing responses against known vulnerability signal patterns rather than literal strings.

```python
# semantic_detector.py
from sentence_transformers import SentenceTransformer, util

model = SentenceTransformer('all-MiniLM-L6-v2')

def is_semantically_vulnerable(response: str, signals: list[str]) -> bool:
    response_emb = model.encode(response, convert_to_tensor=True)
    signal_embs = model.encode(signals, convert_to_tensor=True)
    scores = util.cos_sim(response_emb, signal_embs)
    return float(scores.max()) > SIMILARITY_THRESHOLD
```

---

## OWASP LLM Top 10 Coverage

| # | Category | Detection |
|---|----------|-----------|
| LLM01 | Prompt Injection | Semantic + pattern matching |
| LLM02 | Insecure Output Handling | HTML/code injection signals |
| LLM03 | Training Data Poisoning | Consistency probes |
| LLM04 | Model Denial of Service | Latency + token analysis |
| LLM05 | Supply Chain Vulnerabilities | External dependency acceptance |
| LLM06 | Sensitive Information Disclosure | Prompt leakage embeddings |
| LLM07 | Insecure Plugin Design | Tool invocation signals |
| LLM08 | Excessive Agency | Action commitment detection |
| LLM09 | Overreliance | Context injection analysis |
| LLM10 | Model Theft | Extraction probe signals |

---

## Features

- Full OWASP LLM Top 10 coverage
- Semantic similarity detection — catches paraphrased and obfuscated attacks
- Real-time SSE streaming — results appear as each payload fires
- Multi-provider — Claude (Anthropic) and GPT-4 (OpenAI)
- Severity-weighted risk scoring (Critical / High / Medium / Low)
- Rate limiting and API quota handling
- Docker-ready, GCP Cloud Run compatible

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, Flask 3.0.3 |
| Semantic Detection | sentence-transformers >= 2.7 |
| LLM APIs | Anthropic (Claude), OpenAI (GPT-4) |
| Streaming | Server-Sent Events (SSE) |
| Production WSGI | Gunicorn 22.0 |
| Deployment | Docker, GCP Cloud Run |

---

## Getting Started

```bash
git clone https://github.com/BadAsh99/llmguardt2.git
cd llmguardt2
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add API keys
python app.py
# Open http://localhost:5000
```

### Docker

```bash
docker build -t llmguardt2:latest .
docker run -p 8080:8080 \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -e OPENAI_API_KEY=sk-... \
  llmguardt2:latest
```

---

## Environment Variables

```env
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
SIMILARITY_THRESHOLD=0.75   # cosine similarity threshold for semantic detection
```

---

## Related

- **[LLMGuard](https://github.com/BadAsh99/llmguard)** — the original pattern-matching version

---

## Author

**Ash Clements** — Sr. Principal Security Consultant | Cloud & AI Security
[github.com/BadAsh99](https://github.com/BadAsh99)
