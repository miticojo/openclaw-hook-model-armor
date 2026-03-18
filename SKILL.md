---
name: model-armor-hook
description: >
  Google Cloud Model Armor hook for OpenClaw — sanitizes LLM inputs and outputs
  against prompt injection, PII leakage, harmful content, and malicious URLs.
  Install as a hook (not a skill) via: git clone into ~/.openclaw/hooks/model-armor/
metadata:
  openclaw:
    tags: "security,google-cloud,model-armor,llm-safety,prompt-injection,hook"
    install:
      - id: "git"
        kind: "git"
        url: "https://github.com/miticojo/openclaw-hook-model-armor"
        path: "~/.openclaw/hooks/model-armor"
        label: "Clone into hooks directory"
---

# 🛡️ Model Armor Hook

OpenClaw hook that integrates [Google Cloud Model Armor](https://cloud.google.com/security/products/model-armor) for real-time sanitization of LLM inputs and outputs.

> **Note:** This is a **hook**, not a skill. Install it in `~/.openclaw/hooks/model-armor/`, not in the skills directory.

## Installation

```bash
git clone https://github.com/miticojo/openclaw-hook-model-armor.git \
  ~/.openclaw/hooks/model-armor
openclaw hooks enable model-armor
```

## What It Does

Intercepts `message:received` and `message:sent` events and sends content to Model Armor for analysis:

- **Responsible AI** — hate speech, harassment, sexually explicit, dangerous content
- **Sensitive Data Protection** — PII, credentials, API keys
- **Prompt Injection & Jailbreak** — injection attacks, jailbreak attempts
- **Malicious URIs** — phishing links, malware URLs
- **CSAM** — child safety violations (always on)

## Modes

- **`inspect`** (default) — log warnings, allow message through
- **`block`** — clear content, push warning to user

## Requirements

- Google Cloud project with Model Armor API enabled
- Model Armor template created in GCP Console
- Auth: SA JSON key or `gcloud` CLI

## Configuration

```bash
export MODEL_ARMOR_PROJECT="your-project-id"
export MODEL_ARMOR_TEMPLATE="your-template-id"
export MODEL_ARMOR_LOCATION="europe-west4"  # or us-central1
export MODEL_ARMOR_ENFORCE="inspect"        # or "block"
```

## Key Features

- 🔒 Fail-open design — API errors never block messages
- 📦 Zero npm dependencies — native fetch() + Node.js crypto
- ⚡ Token caching (55 min) + auto-chunking for long messages
- 💰 Free tier: 2M tokens/month

Full documentation: [GitHub](https://github.com/miticojo/openclaw-hook-model-armor)
