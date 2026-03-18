import { execSync } from "child_process";
import { readFileSync, existsSync } from "fs";
import { createSign } from "crypto";

// ── Types ──────────────────────────────────────────────────────────────────

interface HookEvent {
  type: "message" | "command" | "session" | "agent" | "gateway";
  action: string;
  sessionKey: string;
  timestamp: Date;
  messages: string[];
  context: {
    from?: string;
    to?: string;
    content?: string;
    channelId?: string;
    success?: boolean;
    cfg?: any;
  };
}

interface FilterResult {
  matchState: string;
  [key: string]: any;
}

interface SanitizationResponse {
  sanitizationResult: {
    filterMatchState: "MATCH_FOUND" | "NO_MATCH_FOUND";
    filterResults: {
      rai?: { raiFilterResult: FilterResult };
      sdp?: { sdpFilterResult: FilterResult };
      pi_and_jailbreak?: { piAndJailbreakFilterResult: FilterResult };
      malicious_uris?: { maliciousUriFilterResult: FilterResult };
      csam?: { csamFilterResult: FilterResult };
    };
    invocationResult: string;
  };
}

// ── Token Cache ────────────────────────────────────────────────────────────

let cachedToken: string | null = null;
let cachedTokenTimestamp = 0;
const TOKEN_TTL_MS = 55 * 60 * 1000; // 55 minutes

/**
 * Creates a signed JWT for Google OAuth2 service account auth.
 * Supports domain-wide delegation via `subject` claim.
 * @param sa Service account JSON key object.
 * @param subject Optional: user to impersonate via domain delegation.
 * @returns Signed JWT string.
 */
function createJwt(
  sa: { client_email: string; private_key: string },
  subject?: string
): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload: Record<string, any> = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/cloud-platform",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  if (subject) {
    payload.sub = subject;
  }

  const b64 = (obj: any) =>
    Buffer.from(JSON.stringify(obj)).toString("base64url");
  const unsigned = b64(header) + "." + b64(payload);

  const sign = createSign("RSA-SHA256");
  sign.update(unsigned);
  const signature = sign.sign(sa.private_key, "base64url");

  return unsigned + "." + signature;
}

/**
 * Exchanges a signed JWT for a Google OAuth2 access token.
 * @param jwt The signed JWT.
 * @returns Access token string.
 */
async function exchangeJwtForToken(jwt: string): Promise<string> {
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  if (!response.ok) {
    throw new Error(
      `OAuth token exchange failed: ${response.status} ${await response.text()}`
    );
  }
  const data = (await response.json()) as { access_token: string };
  return data.access_token;
}

/**
 * Retrieves a GCP access token, caching it for 55 minutes.
 *
 * Auth strategy (in order):
 * 1. Service account JSON key (MODEL_ARMOR_SA_KEY_PATH or default path)
 *    with optional domain-wide delegation (MODEL_ARMOR_IMPERSONATE_USER)
 * 2. gcloud auth print-access-token (fallback)
 *
 * @returns The bearer token string.
 */
async function getAccessToken(): Promise<string> {
  const now = Date.now();
  if (cachedToken && now - cachedTokenTimestamp < TOKEN_TTL_MS) {
    return cachedToken;
  }

  let token: string;

  // Strategy 1: Service Account JSON key
  const saKeyPath = process.env.MODEL_ARMOR_SA_KEY_PATH || "";

  if (saKeyPath && existsSync(saKeyPath)) {
    const sa = JSON.parse(readFileSync(saKeyPath, "utf-8"));
    const subject = process.env.MODEL_ARMOR_IMPERSONATE_USER || undefined;
    const jwt = createJwt(sa, subject);
    token = await exchangeJwtForToken(jwt);
  } else {
    // Strategy 2: gcloud CLI fallback
    token = execSync("gcloud auth print-access-token", {
      encoding: "utf-8",
      timeout: 10_000,
    }).trim();
  }

  cachedToken = token;
  cachedTokenTimestamp = now;
  return token;
}

// ── Config ─────────────────────────────────────────────────────────────────

interface ModelArmorConfig {
  project: string;
  location: string;
  template: string;
  enforce: "inspect" | "block";
  skipDirect: boolean;
  maxLength: number;
}

/**
 * Reads Model Armor configuration from environment variables.
 * @returns Resolved configuration object.
 * @throws If required env vars (PROJECT, TEMPLATE) are missing.
 */
function getConfig(): ModelArmorConfig {
  const project = process.env.MODEL_ARMOR_PROJECT;
  const template = process.env.MODEL_ARMOR_TEMPLATE;

  if (!project || !template) {
    throw new Error(
      "Model Armor: MODEL_ARMOR_PROJECT and MODEL_ARMOR_TEMPLATE env vars are required"
    );
  }

  return {
    project,
    template,
    location: process.env.MODEL_ARMOR_LOCATION || "europe-west4",
    enforce:
      process.env.MODEL_ARMOR_ENFORCE === "block" ? "block" : "inspect",
    skipDirect: process.env.MODEL_ARMOR_SKIP_DIRECT === "true",
    maxLength: parseInt(process.env.MODEL_ARMOR_MAX_LENGTH || "50000", 10),
  };
}

// ── Chunking ───────────────────────────────────────────────────────────────

/** Threshold above which text is chunked for the PI filter's 512-token limit. */
const CHUNK_THRESHOLD = 2000;
/** Target chunk size in characters (well under 512 tokens). */
const CHUNK_SIZE = 1800;

/**
 * Splits text into chunks if it exceeds the threshold.
 * The prompt-injection filter has a 512-token limit, so we chunk long text
 * and send each chunk separately, returning MATCH_FOUND if any chunk matches.
 * @param text The text to potentially chunk.
 * @returns Array of text chunks.
 */
function chunkText(text: string): string[] {
  if (text.length <= CHUNK_THRESHOLD) {
    return [text];
  }

  const chunks: string[] = [];
  for (let i = 0; i < text.length; i += CHUNK_SIZE) {
    chunks.push(text.slice(i, i + CHUNK_SIZE));
  }
  return chunks;
}

// ── API Calls ──────────────────────────────────────────────────────────────

/**
 * Builds the Model Armor API endpoint URL.
 * @param config Hook configuration.
 * @param action API action: "sanitizeUserPrompt" or "sanitizeModelResponse".
 * @returns Fully qualified URL.
 */
function buildEndpoint(
  config: ModelArmorConfig,
  action: "sanitizeUserPrompt" | "sanitizeModelResponse"
): string {
  return (
    `https://modelarmor.${config.location}.rep.googleapis.com/v1/` +
    `projects/${config.project}/locations/${config.location}/` +
    `templates/${config.template}:${action}`
  );
}

/**
 * Calls the Model Armor sanitization API for a single text chunk.
 * @param endpoint The full API URL.
 * @param body The JSON request body.
 * @param token Bearer token.
 * @returns Parsed sanitization response.
 */
async function callModelArmor(
  endpoint: string,
  body: Record<string, unknown>,
  token: string
): Promise<SanitizationResponse> {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(
      `Model Armor API returned ${response.status}: ${await response.text()}`
    );
  }

  return (await response.json()) as SanitizationResponse;
}

// ── Result Processing ──────────────────────────────────────────────────────

/** Names of individual filters for log output. */
const FILTER_LABELS: Record<string, string> = {
  rai: "Responsible AI",
  sdp: "Sensitive Data Protection",
  pi_and_jailbreak: "Prompt Injection / Jailbreak",
  malicious_uris: "Malicious URIs",
  csam: "CSAM",
};

/**
 * Extracts matched filter names from a sanitization response.
 * @param result The sanitization response.
 * @returns Array of human-readable filter names that matched.
 */
function getMatchedFilters(result: SanitizationResponse): string[] {
  const matched: string[] = [];
  const filters = result.sanitizationResult?.filterResults;
  if (!filters) return matched;

  for (const [key, label] of Object.entries(FILTER_LABELS)) {
    const filterObj = filters[key as keyof typeof filters] as
      | Record<string, FilterResult>
      | undefined;
    if (!filterObj) continue;

    // Each filter wrapper has a single key like "raiFilterResult"
    const inner = Object.values(filterObj)[0];
    if (inner?.matchState === "MATCH_FOUND") {
      matched.push(label);
    }
  }

  return matched;
}

// ── Sanitize Orchestrator ──────────────────────────────────────────────────

/**
 * Runs sanitization for a given text, handling chunking.
 * Returns the aggregate result: MATCH_FOUND if any chunk matches.
 * @param text The full text to sanitize.
 * @param apiAction Which API endpoint to call.
 * @param config Hook configuration.
 * @param token Bearer token.
 * @returns Object with overall match state and matched filter names.
 */
async function sanitize(
  text: string,
  apiAction: "sanitizeUserPrompt" | "sanitizeModelResponse",
  config: ModelArmorConfig,
  token: string
): Promise<{ matched: boolean; filters: string[] }> {
  const endpoint = buildEndpoint(config, apiAction);
  const bodyKey =
    apiAction === "sanitizeUserPrompt"
      ? "user_prompt_data"
      : "model_response_data";

  const chunks = chunkText(text);
  const allMatchedFilters: Set<string> = new Set();

  for (const chunk of chunks) {
    const result = await callModelArmor(
      endpoint,
      { [bodyKey]: { text: chunk } },
      token
    );

    if (result.sanitizationResult?.filterMatchState === "MATCH_FOUND") {
      for (const f of getMatchedFilters(result)) {
        allMatchedFilters.add(f);
      }
    }
  }

  return {
    matched: allMatchedFilters.size > 0,
    filters: Array.from(allMatchedFilters),
  };
}

// ── Hook Handler ───────────────────────────────────────────────────────────

/**
 * OpenClaw hook handler for Model Armor integration.
 *
 * Listens to `message:received` and `message:sent` events, sending content to
 * Google Cloud Model Armor for sanitization. In inspect mode (default), matches
 * are logged as warnings. In block mode, matched content is cleared and a
 * warning message is pushed to the event.
 *
 * Fail-open: any error in the sanitization pipeline is logged and the message
 * is allowed through unmodified.
 *
 * @param event The OpenClaw hook event.
 * @returns The (potentially modified) event.
 */
async function handler(event: HookEvent): Promise<HookEvent> {
  // Only handle message events
  if (event.type !== "message") {
    return event;
  }

  // Determine API action based on event action
  let apiAction: "sanitizeUserPrompt" | "sanitizeModelResponse";
  if (event.action === "received") {
    apiAction = "sanitizeUserPrompt";
  } else if (event.action === "sent") {
    apiAction = "sanitizeModelResponse";
  } else {
    return event;
  }

  const content = event.context?.content;
  if (!content || content.trim().length === 0) {
    return event;
  }

  try {
    const config = getConfig();

    // Skip direct/private chats if configured
    if (config.skipDirect && !event.context.channelId) {
      return event;
    }

    // Truncate to max length
    const text =
      content.length > config.maxLength
        ? content.slice(0, config.maxLength)
        : content;

    const token = await getAccessToken();
    const direction =
      apiAction === "sanitizeUserPrompt" ? "input" : "output";

    const { matched, filters } = await sanitize(
      text,
      apiAction,
      config,
      token
    );

    if (matched) {
      const filterList = filters.join(", ");
      console.warn(
        `[Model Armor] MATCH_FOUND on ${direction} ` +
          `(session: ${event.sessionKey}): ${filterList}`
      );

      if (config.enforce === "block") {
        event.messages.push(
          `[Model Armor] Blocked ${direction}: content flagged by ${filterList}`
        );
        event.context.content = "";
        console.warn(
          `[Model Armor] Blocked ${direction} content ` +
            `(session: ${event.sessionKey})`
        );
      }
    }
  } catch (err: unknown) {
    // Fail-open: log the error and allow message through
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[Model Armor] Error during sanitization — failing open: ${message}`);
  }

  return event;
}

export default handler;
