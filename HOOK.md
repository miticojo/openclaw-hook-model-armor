---
name: model-armor
description: Google Cloud Model Armor guardrails for LLM input/output sanitization
metadata:
  openclaw:
    events:
      - "message:received"
      - "message:sent"
    requires:
      anyBins:
        - "gcloud"
        - "node"
    emoji: "\U0001F6E1\uFE0F"
---

# Model Armor Hook

Sanitizes incoming user prompts and outgoing model responses using
[Google Cloud Model Armor](https://cloud.google.com/security/products/model-armor).

## Filters

- **Responsible AI (RAI)** — hate speech, harassment, sexually explicit, dangerous content
- **Sensitive Data Protection (SDP)** — PII, credentials, secrets
- **Prompt Injection & Jailbreak (PI)** — injection attacks and jailbreak attempts
- **Malicious URIs** — phishing and malware links
- **CSAM** — child safety violations

## Modes

| Mode | Behavior |
|------|----------|
| `inspect` (default) | Log warnings, allow message through |
| `block` | Log warnings, clear content, push warning message |
