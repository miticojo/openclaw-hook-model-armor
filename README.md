# 🛡️ Model Armor Hook for OpenClaw

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An [OpenClaw](https://docs.openclaw.ai) hook that integrates [Google Cloud Model Armor](https://cloud.google.com/security/products/model-armor) for real-time sanitization of LLM inputs and outputs.

## What It Does

Intercepts messages flowing through OpenClaw and sends them to Model Armor for analysis against five filter categories:

| Filter | Detects |
|--------|---------|
| **Responsible AI (RAI)** | Hate speech, harassment, sexually explicit, dangerous content |
| **Sensitive Data Protection (SDP)** | PII, credentials, API keys, financial data |
| **Prompt Injection & Jailbreak (PI)** | Injection attacks, jailbreak attempts |
| **Malicious URIs** | Phishing links, malware URLs |
| **CSAM** | Child safety violations (always on) |

Two enforcement modes:

- **`inspect`** (default) — log warnings, allow message through
- **`block`** — log warnings, clear content, push warning message to user

## Key Features

- 🔒 **Fail-open design** — API errors never block your messages
- 🔑 **Flexible auth** — SA JSON key (with optional domain-wide delegation) or `gcloud` CLI fallback
- 📦 **Zero dependencies** — uses native `fetch()` and Node.js `crypto`
- ⚡ **Token caching** — access tokens cached for 55 minutes
- 📏 **Auto-chunking** — long messages split for PI filter's 512-token limit

## Quick Start

```bash
# 1. Clone the hook
git clone https://github.com/miticojo/openclaw-hook-model-armor.git \
  ~/.openclaw/hooks/model-armor

# 2. Set required env vars (add to your shell profile or deployment)
export MODEL_ARMOR_PROJECT="your-gcp-project-id"
export MODEL_ARMOR_TEMPLATE="your-template-id"

# 3. Enable the hook
openclaw hooks enable model-armor

# 4. Verify
openclaw hooks list   # should show ✓ ready for model-armor
```

That's it — all messages will now be screened by Model Armor.

## Full Setup Guide

### Prerequisites

- [OpenClaw](https://docs.openclaw.ai) installed and running
- A Google Cloud project with **billing enabled**
- `gcloud` CLI or a service account JSON key

### Step 1 — Enable the Model Armor API

```bash
gcloud services enable modelarmor.googleapis.com --project=YOUR_PROJECT
```

### Step 2 — Grant IAM permissions

The identity calling Model Armor needs the `modelarmor.user` role:

```bash
# For a service account:
gcloud projects add-iam-policy-binding YOUR_PROJECT \
  --member="serviceAccount:YOUR_SA@YOUR_PROJECT.iam.gserviceaccount.com" \
  --role="roles/modelarmor.user"

# For your user account (if using gcloud auth):
gcloud projects add-iam-policy-binding YOUR_PROJECT \
  --member="user:you@example.com" \
  --role="roles/modelarmor.user"
```

### Step 3 — Create a Model Armor template

Via [GCP Console → Security → Model Armor](https://console.cloud.google.com/security/model-armor), or via CLI:

```bash
gcloud model-armor templates create my-guardrail \
  --project=YOUR_PROJECT \
  --location=europe-west4 \
  --rai-settings-filters='[
    {"filterType":"HATE_SPEECH","confidenceLevel":"MEDIUM_AND_ABOVE"},
    {"filterType":"HARASSMENT","confidenceLevel":"MEDIUM_AND_ABOVE"},
    {"filterType":"SEXUALLY_EXPLICIT","confidenceLevel":"HIGH"},
    {"filterType":"DANGEROUS","confidenceLevel":"MEDIUM_AND_ABOVE"}
  ]' \
  --pi-and-jailbreak-filter-settings-enforcement=ENABLED \
  --pi-and-jailbreak-filter-settings-confidence-level=LOW_AND_ABOVE \
  --malicious-uri-filter-settings-enforcement=ENABLED \
  --basic-config-filter-enforcement=ENABLED
```

Note the template ID (e.g., `my-guardrail`).

### Step 4 — Install the hook

```bash
git clone https://github.com/miticojo/openclaw-hook-model-armor.git \
  ~/.openclaw/hooks/model-armor
```

### Step 5 — Configure environment variables

```bash
# Required
export MODEL_ARMOR_PROJECT="your-project-id"
export MODEL_ARMOR_TEMPLATE="your-template-id"

# Optional
export MODEL_ARMOR_LOCATION="europe-west4"      # default; or us-central1
export MODEL_ARMOR_ENFORCE="inspect"             # default; or "block"
export MODEL_ARMOR_SKIP_DIRECT="false"           # skip private/DM chats
export MODEL_ARMOR_MAX_LENGTH="50000"            # max chars to sanitize

# Authentication (pick one):

# Option A — Service account JSON key (recommended for containers)
export MODEL_ARMOR_SA_KEY_PATH="/path/to/service-account.json"
export MODEL_ARMOR_IMPERSONATE_USER="user@example.com"  # optional: domain-wide delegation

# Option B — gcloud CLI (for local dev)
# Just have `gcloud auth login` done; no extra env vars needed
```

### Step 6 — Enable the hook

```bash
openclaw hooks enable model-armor
```

### Step 7 — Verify it works

```bash
# Check the hook is loaded
openclaw hooks list
# You should see: ✓ ready │ 🛡️ model-armor

# Send a test message to your agent, then check the GCP Console:
# Security → Model Armor → Monitoring — interactions should increment
```

## Kubernetes / Flux Deployment

If you run OpenClaw on Kubernetes with a ConfigMap-based `openclaw.json`:

> ⚠️ **Important:** `openclaw hooks enable` writes to the PVC copy of `openclaw.json`. If your init container copies the ConfigMap to the PVC on every restart, **the hook enablement will be lost**. You must add the hooks config to your ConfigMap source:

```json
{
  "hooks": {
    "internal": {
      "enabled": true,
      "entries": {
        "model-armor": {
          "enabled": true
        }
      }
    }
  }
}
```

Add the env vars to your Deployment manifest:

```yaml
env:
  - name: MODEL_ARMOR_PROJECT
    value: "your-project-id"
  - name: MODEL_ARMOR_TEMPLATE
    value: "your-template-id"
  - name: MODEL_ARMOR_LOCATION
    value: "europe-west4"
  - name: MODEL_ARMOR_ENFORCE
    value: "inspect"
  - name: MODEL_ARMOR_SA_KEY_PATH
    value: "/path/to/mounted/service-account.json"
  - name: MODEL_ARMOR_IMPERSONATE_USER
    value: "user@example.com"
```

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MODEL_ARMOR_PROJECT` | Yes | — | GCP project ID |
| `MODEL_ARMOR_TEMPLATE` | Yes | — | Model Armor template ID |
| `MODEL_ARMOR_LOCATION` | No | `europe-west4` | GCP region |
| `MODEL_ARMOR_ENFORCE` | No | `inspect` | `inspect` or `block` |
| `MODEL_ARMOR_SKIP_DIRECT` | No | `false` | Skip private/direct chats |
| `MODEL_ARMOR_MAX_LENGTH` | No | `50000` | Max chars to sanitize |
| `MODEL_ARMOR_SA_KEY_PATH` | No | — | Path to SA JSON key file |
| `MODEL_ARMOR_IMPERSONATE_USER` | No | — | Email for domain-wide delegation |

## How It Works

1. **`message:received`** → calls `sanitizeUserPrompt` — screens incoming user messages
2. **`message:sent`** → calls `sanitizeModelResponse` — screens outgoing agent responses
3. Text longer than 2000 chars is chunked for the PI filter's 512-token limit
4. Auth tokens are cached for 55 minutes (GCP tokens expire after 60 min)
5. On any error, the hook **fails open** — logs the error and allows the message through

## Pricing

Model Armor offers a **free tier of 2 million tokens/month**. After that, it's **$0.10 per 1 million tokens**. See [Model Armor pricing](https://cloud.google.com/security/products/model-armor#pricing).

## Available Regions

- `us-central1`
- `europe-west4`

## Limitations

- **512-token limit** on prompt injection detection — long messages are chunked automatically
- **Text-only** — does not scan tool calls, file operations, or browser actions
- **Latency** — adds ~100-400ms per message (same-region); fail-open prevents blocking on timeout
- **Not a complete security solution** — complements (doesn't replace) OpenClaw's built-in approval system

## Troubleshooting

### Hook shows `✓ ready` but metrics don't increase

- Verify env vars are set **in the gateway process** (not just your shell)
- On K8s: check that hooks config is in the ConfigMap (see [K8s section](#kubernetes--flux-deployment))
- Check gateway logs: `kubectl logs <pod> | grep -i "hook\|armor"`

### "MODEL_ARMOR_PROJECT and MODEL_ARMOR_TEMPLATE env vars are required"

Set both required environment variables and restart the gateway.

### Auth failures (401/403)

- **SA key auth**: Verify the SA has `roles/modelarmor.user` on the project
- **gcloud auth**: Run `gcloud auth login` and ensure proper permissions
- **Domain delegation**: Verify the SA has domain-wide delegation configured in Google Workspace Admin

### API returns 404

The template doesn't exist in the specified region. Templates are regional — make sure `MODEL_ARMOR_LOCATION` matches where you created it.

### High latency

Model Armor adds per-request latency (~100-400ms). Use `inspect` mode to avoid blocking the message pipeline.

## Contributing

Contributions are welcome! Please open an issue or submit a PR.

## License

[MIT](LICENSE)
