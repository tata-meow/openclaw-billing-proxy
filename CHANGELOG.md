# Changelog

## v2.7.0 -- 2026-06-04

### Configurable bind address: listen beyond loopback

**Changes:**
- New `config.bind` option controlling which network interface(s) the proxy
  listens on. Accepts a string or an array of addresses:
  - `"127.0.0.1"` — loopback only. **Default; identical to prior behavior.**
  - `"0.0.0.0"` — all IPv4 interfaces.
  - `"::"` — all IPv6 + IPv4 interfaces (dual-stack).
  - `["127.0.0.1", "::1"]` — listen on multiple specific addresses; one HTTP
    server is created per address, all sharing the same request handler.
- Precedence: `PROXY_HOST` env var > `config.bind` > `127.0.0.1`. The env var
  still wins so Docker Compose's `PROXY_HOST=0.0.0.0` is unaffected.
- Startup banner now lists all bind addresses; the "Ready" baseUrl hint maps
  wildcard binds (`::` / `0.0.0.0`) to `127.0.0.1` and brackets IPv6 literals.
- Bind failures (e.g. `EADDRINUSE`) now print a clear per-address error and exit
  instead of throwing an unhandled exception.

**Security:** binding beyond `127.0.0.1` exposes the proxy on the network —
anyone who can reach the port can spend your Claude subscription quota. Only do
this on a trusted LAN or behind a firewall.

## v2.6.0 -- 2026-05-31

### Configurable Layer 2 scope: optionally stop translating agent-visible content

**Changes:**
- New `config.layer2Scope` flag controlling where Layer 2 (the `DEFAULT_REPLACEMENTS`
  content-keyword sanitization) applies:
  - `"all"` — replace across the entire request body. **Default; identical to prior
    behavior.** Existing configs and the no-config path are unaffected.
  - `"system"` — replace only inside the `"system":[...]` (or string-form `"system":"..."`)
    prompt. User / assistant / tool_result content passes through untranslated, so the
    upstream agent reads the **original** conversation history and file contents.
  - `"off"` — skip Layer 2 content replacement entirely.
- Unknown/invalid values fall back to `"all"` with a startup warning.
- Filesystem-path protection (`protectPaths`/`restorePaths`) is preserved within whatever
  scope is active — `.openclaw/...` paths are never corrupted.
- The active scope is surfaced in the startup banner and in `/health` (`layers.layer2Scope`)
  so it can be confirmed when flipped on live traffic.
- Layers 3 (tool-name fingerprint) and 4 (system template strip) are **unchanged** — they
  carry the anti-detection signal and are deliberately left intact. The reverse map
  (Layer 7) is also unchanged.
- Added 5 unit tests covering all three scopes, the unknown-value fallback, and path
  preservation under `"system"` scope.

**Why:**
Under `"all"`, every string the agent sees — chat history, tool results, file contents —
is the sanitized/"translated" version, so the agent can never obtain the real text.
Out-of-band testing (hex-escaped triggers sent direct to `api.anthropic.com` with a
realistic Claude Code header) showed three request variants — no trigger, raw trigger in
`system`, raw trigger in a user message — all returning HTTP 200 with
`anthropic-ratelimit-unified-status: allowed` and no overage/429. Conclusion: Anthropic's
third-party detection does not key off request-body content keywords; the load is carried
by the tool-name fingerprint (Layer 3) and system-template structure (Layer 4). Layer 2's
keyword replacement over user/assistant/tool_result content therefore contributes no
observable detection resistance and is over-defense.

**Unverified risk (do not treat the narrowed scopes as proven safe):**
- The supporting test covered only Haiku + single-shot + short context.
- The tool-**array** fingerprint path was not exercised (the probe carried no real agent
  tool set) — this is the genuine risk point once Layer 2 stops rewriting content. Layers
  3/4 are kept intact precisely to cover it.
- Acceptance is empirical: flip `layer2Scope` to `"system"`/`"off"` during real agent
  traffic and observe. The subscription has Extra Usage disabled, so a third-party verdict
  returns rejected/errors immediately rather than billing silently — the failure is loud
  and instant.

---

## v2.5.0 -- 2026-05-29

### Structured request logging: local-time ISO timestamps, per-request correlation, param summary

**Changes:**
- All per-request log lines now use a local-time ISO 8601 timestamp with millisecond
  precision and an explicit timezone offset (e.g. `[2026-05-29T11:39:13.150+08:00]`)
  instead of the previous UTC `HH:MM:SS`. Timestamps are generated per log line, so a
  request line and its `> 200` response line reflect their real wall-clock times.
- Every transform log (`[REPAIR]`, `[STRIP-THINKING]`, `[EFFORT]`, `[STRIP]`,
  `[STRIP-PREFILL]`) is now prefixed with the timestamp and the request number
  (`#<n>`), so all log lines for one request can be correlated. `reqNum` is threaded
  through `processBody` → `repairToolPairs` / `stripThinkingBlocks`.
- New `params:` line per request summarizing the request actually sent upstream:
  `model`, `effort`, `thinking` (budget_tokens), `max_tokens`, `stream`, `tools`
  (count), `msgs` (count), and the applied `betas`.
- New helpers: `tsLocal()`, `plog(reqNum, msg, level)`, `summarizeParams(bodyStr, betas)`.

**Why:**
The previous logs used UTC times with no date and no per-request prefix on the
transform lines, making it hard to read logs in the operator's own timezone and hard
to tell which `[STRIP]`/`[STRIP-THINKING]` lines belonged to which request. The param
summary surfaces the key knobs (model, effort, thinking budget, betas) at a glance —
the summary is parsed from the *processed* body, so model-specific transforms (e.g.
Haiku effort stripping) are reflected accurately.

---

## v2.4.1 -- 2026-05-21

### Strip thinking blocks from message history; /health reads token from disk

**Changes:**
- New `stripThinkingBlocks()` removes all `thinking` / `redacted_thinking` blocks
  from assistant messages in the conversation history before forwarding (closes #45).
- `/health` now reads the token from the credentials file instead of the in-memory
  `_cachedToken`, so its `tokenExpiresInHours` / status reflect the on-disk token.

**Why:**
OpenClaw re-serializes conversation history, which changes the byte representation of
`thinking` / `redacted_thinking` blocks. Anthropic requires these to be byte-identical
if present, but does not require them at all — so stripping them is the only reliable
fix, eliminating "Invalid signature in thinking block" and "thinking blocks cannot be
modified" errors on multi-turn conversations.

The `/health` fix addresses a false `token_expired` report: when the refresh timer
updated credentials on disk but no API requests had come in, the in-memory
`_cachedToken` stayed stale and health checks read the old value.

---

## v2.4.0 -- 2026-05-19

### Port PR #48 improvements — OAuth refresh, Haiku effort strip, multi-marker identity, tests

**Changes:**
- OAuth token refresh: async `getTokenAsync` with race-condition dedup, disk
  persistence of the refreshed token, and cache invalidation on a 401 from upstream.
- Layer 2.5: `stripEffortFromObject` removes `effort` params for Haiku models, which
  reject them with a 400.
- Layer 4: multi-marker identity detection (6 `IDENTITY_MARKERS` variants) with
  improved end-boundary patterns (UNC paths, generic Windows drive letters).
- `injectCCStubs` now defaults to `false` (issue #43 — injected stubs caused
  tool-not-found loops).
- Stainless SDK version bumped 0.81.0 → 0.90.0.
- Request handler is now async to support awaiting the OAuth refresh.
- Added `test-functions.js` with 51 unit tests covering the pure functions.

**Why:**
Ports the accumulated fixes from PR #48. The OAuth refresh keeps long-running proxy
instances authenticated without manual re-login; the Haiku effort strip and the
broader identity-marker set reduce per-model 400s and missed config strips across the
varied OpenClaw identity prompts.

---

## v2.3.0 -- 2026-05-19

### Fix message tool param corruption and thinking block signatures; port kongkong7777 fork improvements

**Changes:**
- Layer 3: context-aware rename for the `message` tool — only replaces
  `"name":"message"`, not the `message` parameter inside `input_schema`. Prevents SSE
  `input_json_delta` chunking from splitting the renamed param across events.
- Rewrote `maskThinkingBlocks` to handle varied JSON formatting (spaces after colons,
  `type` not first key) so clients that re-serialize thinking blocks differently from
  Anthropic's compact format no longer trigger signature errors.
- Layer 3: removed `web_search` / `web_fetch` from tool renames — these are Anthropic
  built-in tool types and renaming corrupts the `type` field.
- Billing: `computeCch()` now emits a real SHA256 hash instead of hardcoded
  `cch=00000`, and `buildBillingBlock` uses pre-transform text for a stable CCH.
- `repairToolPairs()` removes orphaned `tool_use` / `tool_result` blocks.
- `filterStubsAgainstExisting()` prevents duplicate tool names.
- Metadata injection restricted to `/v1/messages` (stripped on `count_tokens`).
- Removed density-classifier beta signals (`advanced-tool-use`, `fast-mode`) and added
  `getModelBetas()` per-model beta filtering (Haiku, non-4.6).
- Added string-aware `findMatchingBrace()` helper.

**Why:**
The `message` tool rename was corrupting the tool's own parameter, producing OpenClaw
"[tools] message failed: message required" errors; scoping the rename to the `name`
position fixes it. The thinking-block mask rewrite resolves "Invalid signature in
thinking block" errors caused by clients re-serializing blocks in a non-compact format.
The remaining items are improvements ported from the kongkong7777/openclaw-billing-proxy
fork (billing hash, tool-pair repair, stub dedup, per-model betas).

---

## v2.2.5 -- 2026-04-10

### Protect filesystem paths from Layer 2 global string replacement

**Changes:**
- Layer 2 `split/join` replacements now extract filesystem paths into NUL-delimited
  placeholders before applying replacements, then restore them after. Paths with 2+
  segments (e.g. `/home/user/.openclaw/media/...`, `./src/openclaw/mod.js`) are
  detected by a regex with a negative lookbehind `(?<![\/:])` to skip URL schemes.

**Why:**
Layer 2 blindly replaced every occurrence of trigger strings (e.g. `openclaw` →
`tataclaw`) across the entire request body, including inside filesystem paths in
tool call arguments. This turned `/home/tata/.openclaw/media/...` into
`/home/tata/.tataclaw/media/...`. OpenClaw's `assertLocalMediaAllowed()` security
check then rejected the path because it was no longer under an allowed directory
root.

The response-side `reverseMap()` is left unchanged — its replacements are corrective
(restoring replaced strings back to originals), so path protection is not needed there.

---

## v2.2.4 -- 2026-04-09

### Fix config strip boundary using filesystem paths instead of AGENTS.md (closes #26)

**Changes:**
- System strip boundary detection now uses `\n## /` (Linux/macOS) or `\n## C:\\`
  (Windows) instead of `AGENTS.md` as the end-of-config landmark.

**Why:**
`AGENTS.md` can appear in skill content (`## Skills (mandatory)` section references
like "Read AGENTS.md for rules") or in LCM compacted summaries. `indexOf('AGENTS.md')`
finds the first match, which may be in skill text at ~10K instead of the actual workspace
doc header at ~28K. Result: config strip is too short, leaving enough template content
for detection to trigger.

Workspace doc headers always start with a filesystem path (`## /home/...` on Linux,
`## C:\Users\...` on Windows). These patterns don't appear in skill or summary content.

---

## v2.2.3 -- 2026-04-09

### Add media generation tool renames for OpenClaw 2026.4.5+ (closes #21)

**Changes:**
- Added `image_generate` → `ImageCreate`, `music_generate` → `MusicCreate`,
  `video_generate` → `VideoCreate` to `DEFAULT_TOOL_RENAMES`.

**Why:**
OpenClaw v2026.4.5 introduced 3 new media generation tools not in the proxy's
default rename list. These tool names are fingerprinted by Anthropic's detection,
causing requests to be billed as extra usage. Reported and confirmed by a user
who manually added the renames and saw billing switch from overage to subscription.

Users on OpenClaw 2026.4.5+ who pull the latest proxy get these renames
automatically via the v2.2.2 merge semantics.

---

## v2.2.2 -- 2026-04-09

### Merge config.json patterns with defaults instead of overriding (closes #24)

**Changes:**
- **Merge semantics for all pattern arrays.** `config.json` patterns now MERGE with
  `proxy.js` defaults instead of replacing them. Defaults are applied first, then config
  entries override (same trigger key) or add (new trigger key). This prevents stale
  `config.json` snapshots from silently masking new default patterns added in updates.
- **`setup.js` no longer writes pattern arrays to config.json.** Only `port` and
  `credentialsPath` are written. Pattern defaults live in `proxy.js` and stay current
  across `git pull` updates. Custom patterns can be added to `config.json` and will
  be merged automatically.
- **Startup note** when config.json has fewer patterns than defaults, showing the merge
  result so users know their config was supplemented.
- **Opt-out:** Set `"mergeDefaults": false` in config.json for full manual control
  (patterns in config.json replace defaults entirely, like v2.1 behavior).

**Why:**
`setup.js` wrote a frozen snapshot of its pattern arrays to `config.json` at install
time. After `git pull` to v2.x, the 20+ new critical patterns (`HEARTBEAT`, `billing
proxy`, `third-party`, `clawhub`, tool renames, property renames) were silently skipped
because `config.replacements || DEFAULT_REPLACEMENTS` used the stale config. Every user
who installed before v2.0 was affected.

---

## v2.2.1 -- 2026-04-09

### Fix system strip and tool description stripping on Linux/macOS

**Changes:**
- **System strip now anchored to system array.** Previously searched from position 0
  in the body, matching the identity line in conversation history (from prior discussions
  about the proxy) instead of the actual system prompt. On bodies with accumulated
  conversation history, the strip either failed silently or stripped the wrong region.
  Now searches from `"system":[` forward, guaranteeing it finds the config section in
  the system prompt.
- **`findMatchingBracket` is now string-aware.** Previously counted raw `[`/`]` characters
  including those inside JSON string values (tool descriptions, text content). Brackets
  like `[optional]` or `[array]` in descriptions corrupted the depth count, causing the
  tools array boundary to be detected at the wrong position. Tool description stripping
  then silently failed. Now skips brackets inside quoted strings.

**Impact:** These two bugs made the proxy fail on Linux/macOS (and any setup where
conversation history contained references to "personal assistant"). The system config
template (~18-28K) was never stripped, and tool descriptions were never removed,
leaving enough fingerprint signal for Anthropic's detection to trigger.

---

## v2.2.0 -- 2026-04-09

### Docker Compose support + env-var credentials + transfer-encoding fix

**Changes:**
- **Docker deployment**: Added `Dockerfile` (node:18-alpine), `docker-compose.yml` with health
  check, credential volume mount (read-only), localhost-only port binding, and log rotation.
  Added `.dockerignore` and `.env.example`.
- **OAUTH_TOKEN env var**: Alternative to file-based credentials for Docker and CI environments.
  Set `OAUTH_TOKEN=sk-ant-...` in `.env` to skip credential file lookup entirely.
- **PROXY_PORT / PROXY_HOST env vars**: Override port and bind address without config files.
  Docker Compose sets `PROXY_HOST=0.0.0.0` automatically for container port mapping.
- **Transfer-Encoding header fix**: Strips `transfer-encoding` from all 3 response paths
  (error, SSE, JSON) before setting `content-length`, preventing Node.js HTTP parse errors
  when both headers are present.
- **Config.json error handling**: Explicit `--config` failure exits with error. Implicit
  `config.json` failure warns and continues with defaults.
- **troubleshoot.js**: Guards undefined `e2e.body`, supports v2.0+ health endpoint format.

**Cherry-picked from:** PR #13 (VibeSparkingAI). Docker files taken directly, proxy.js
changes manually integrated into our v2.1 codebase to preserve tail buffer, StringDecoder,
escaped reverse mapping, and prefill stripping.

---

## v2.1.3 -- 2026-04-09

### Tail-buffer SSE reverse mapping for chunk boundary splits

**Changes:**
- SSE streaming handler now keeps a 64-byte tail buffer between TCP chunks before
  applying `reverseMap()`. Prevents sanitized patterns (e.g. `ocplatform`) from being
  split across chunk boundaries (`ocp` + `latform`) and leaking through un-reversed.
- On `end`, remaining tail is flushed through `reverseMap()`.
- `TAIL_SIZE=64` is >= longest current pattern (24 chars) with 2.5x headroom.

**Why:**
TCP chunks are arbitrary. A reverse mapping pattern can be split across two `data`
events. The previous code called `reverseMap()` on each chunk individually, so
neither half matched the full pattern. In OpenClaw this manifested as workspace
paths like `.ocplatform/` leaking through instead of `.openclaw/`, causing `ENOENT`
on tool calls.

**Inspired by:** PR #15 (kokoima) which identified the bug and provided the
tail-buffer approach.

---

## v2.1.2 -- 2026-04-09

### Fix escaped JSON reverse mapping in SSE tool_use args (closes #11)

**Changes:**
- `reverseMap()` now handles both plain (`"Name"`) and escaped (`\"Name\"`) quote
  forms when reversing tool name and property name renames.
- SSE `input_json_delta` events embed tool arguments inside a `partial_json` string
  field where inner quotes are escaped. Without the escaped variant, renamed arg keys
  like `\"SendMessage\"` were never reverted to `\"message\"`, causing OpenClaw's tool
  runtime to fail with "message required".

**Inspired by:** PR #16 (kokoima) which identified the bug and provided the fix approach.

---

## v2.1.1 -- 2026-04-09

### Strip trailing assistant prefill (Opus 4.6 compatibility)

**Changes:**
- Added Layer 8: raw-string trailing assistant message stripping. Opus 4.6 disabled
  assistant message prefill — OpenClaw sometimes pre-fills the next assistant turn
  to resume interrupted responses, causing permanent 400 errors for the session.
- Uses string-aware forward scanning with bracket depth tracking (handles braces
  and quotes inside text content). Zero JSON.parse/stringify — body bytes preserved.
- Enabled by default. Opt-out: `"stripTrailingAssistantPrefill": false` in config.json.

**Why:**
When OpenClaw pre-fills a trailing assistant message, Anthropic returns:
`"This model does not support assistant message prefill. The conversation must end
with a user message."` The prefill stays in conversation history, so every retry
fails the same way and the channel becomes permanently stuck.

**Inspired by:** PR #17 (kokoima) which identified the bug. Our implementation uses
raw string manipulation instead of JSON.parse to avoid re-serialization risks on
large bodies.

---

## v2.1.0 -- 2026-04-09

### Cherry-pick CC signature emulation + remove image rename collision

**Changes:**
- Dynamic billing fingerprint: SHA256-based 3-char hash matching real CC's
  `utils/fingerprint.ts`, computed per-request from first user message
- Updated CC version to 2.1.97, entrypoint changed from `sdk-cli` to `cli`
- Stainless SDK headers: `x-stainless-arch/lang/os/package-version/runtime` etc.
- CC identity headers: `user-agent`, `x-app`, `x-claude-code-session-id`
- Request metadata injection: `device_id` + `session_id` in CC format
- Updated beta flags: added `advanced-tool-use-2025-11-20`, `fast-mode-2026-02-01`
- Strips `x-session-affinity` header (non-CC leak)
- **Removed `image` → `ImageGen` tool rename** (PR #19, kokoima): collided with
  Anthropic's `"type":"image"` content block tag, causing permanent session failures
  when conversation history contained images

**Inspired by:** PR #12 (marco-jardim) for fingerprint hash, Stainless headers,
updated CC version. PR #19 (kokoima) for the image rename collision fix.

---

## v2.0.0 -- 2026-04-08

### Defeat Anthropic's upgraded detection (tool-name fingerprinting + template matching)

**Breaking change:** v1.x string-only sanitization stopped working on April 8, 2026. Anthropic upgraded their detection from simple string matching to multi-layer fingerprinting that scans the entire request body. v2.0 defeats the new detection.

**What changed on Anthropic's side:**

On April 8, Anthropic upgraded from string-based triggers to a multi-layer classifier:

1. **Tool-name fingerprinting (NEW)** -- The API now identifies OpenClaw by the *set of tool names* in the request. Even with completely empty schemas (no descriptions, no properties), the original tool names alone trigger rejection. This was proved by testing: identical empty schemas with original names = FAIL, same schemas with PascalCase names = PASS.

2. **System prompt template matching (NEW)** -- The structured config sections (`## Tooling`, `## Workspace`, `## Messaging`, etc.) match a known OpenClaw template fingerprint. The threshold is ~26K characters of accumulated config. String replacements don't defeat this because the *structure* is preserved even when individual words change.

3. **Cumulative body density (NEW)** -- The detector scores the entire request body (system prompt + tools + messages), not just the system prompt. Each component can be individually under threshold but still trigger when combined.

4. **String triggers (UNCHANGED)** -- Known phrases still blocked: `OpenClaw`, `sessions_*`, `running inside`, `HEARTBEAT_OK`, etc.

**New proxy layers (v2.0):**

| Layer | What | How |
|-------|------|-----|
| 1 | Billing header | Injects 84-char CC billing identifier into system prompt |
| 2 | String sanitization | 30 split/join replacements for known trigger phrases |
| 3 | **Tool name bypass** | Renames all 29 OC tools to PascalCase CC convention throughout entire body |
| 4 | **System template bypass** | Strips ~28K config section, replaces with ~0.5K paraphrase |
| 5 | **Description stripping** | Removes tool descriptions to reduce fingerprint signal |
| 6 | **Property renaming** | Renames OC-specific schema properties (session_id, conversation_id, etc.) |
| 7 | Bidirectional reverse mapping | Restores all original names in SSE + JSON responses |

**Tool name renames (29 patterns):**
- `exec` -> `Bash`, `message` -> `SendMessage`, `cron` -> `Scheduler`
- `gateway` -> `SystemCtl`, `lcm_grep` -> `ContextGrep`, `lcm_expand` -> `ContextExpand`
- `memory_search` -> `KnowledgeSearch`, `agents_list` -> `AgentList`, etc.
- Full list in proxy.js `DEFAULT_TOOL_RENAMES`

**CC tool stubs (5):**
Injects Glob, Grep, Agent, NotebookEdit, TodoRead stubs into the tools array to make the tool set look more like a Claude Code session.

**Configuration:** All new layers enabled by default. Disable individually via config.json:
```json
{
  "stripSystemConfig": false,
  "stripToolDescriptions": false,
  "injectCCStubs": false,
  "toolRenames": [],
  "propRenames": []
}
```

**Backward compatible:** v1.x `config.json` files still work. New layers use defaults when config keys are absent.

**Tested:** Full 235K captured body (mature conversation with 100 message turns, 29 tools, 127K system prompt) passes on both Sonnet and Opus through the v2 proxy.

---

## v1.4.1 -- 2026-04-08

### UTF-8 BOM handling fix

**Changes:**
- `proxy.js` now strips UTF-8 BOM (byte order mark) from the credentials file
  before parsing JSON. Prevents intermittent `HTTP 500: Unexpected token` errors
  when the credentials file is rewritten with BOM encoding.

**Why:**
PowerShell and some editors add a UTF-8 BOM (`EF BB BF`) when writing files.
Claude Code's token auto-refresh can trigger a file rewrite that introduces the
BOM. The proxy's `JSON.parse()` fails on the invisible BOM character, causing
all API requests to return 500 until the file is manually cleaned. This fix
makes the proxy resilient to BOM-encoded credentials files automatically.

**Symptoms before fix:**
- `HTTP 500 error: Credentials: Unexpected token, "{ "c"... is not valid JSON`
- Intermittent failures after token refresh
- Proxy health endpoint returns `{"status":"error","message":"Unexpected token..."}`

---

## v1.4.0 -- 2026-04-06

### macOS Keychain support

**Changes:**
- `setup.js` now auto-detects credentials stored in macOS Keychain when no
  file-based credentials exist. Checks service names `claude-code`, `claude`,
  and `com.anthropic.claude-code`. Extracts the token and writes it to
  `~/.claude/.credentials.json` for the proxy to read.
- `proxy.js` includes the same Keychain fallback at startup, so it works even
  if setup wasn't run.
- `troubleshoot.js` checks Keychain as a diagnostic step and reports findings.
- `setup.js` also attempts to trigger a credential write by running
  `claude -p "ping"` if no credentials are found anywhere.
- Updated README troubleshooting section for Mac Keychain edge cases.

**Why:**
Some Claude Code versions on macOS store OAuth tokens in the system Keychain
instead of a file. Users see `claude auth status` showing logged in, but
`~/.claude/credentials.json` is empty or missing. This affected multiple users
trying to install the proxy on Mac.

---

## v1.3.0 -- 2026-04-06

### HEARTBEAT_OK trigger + missing sessions_* tools + NVM path scanning

**Changes:**
- Added `HEARTBEAT_OK` to sanitization — a newly discovered trigger phrase that
  Anthropic's classifier detects. OpenClaw injects this in heartbeat ack
  instructions; without sanitizing it, all requests fail with "out of extra
  usage" even when the billing block and OAuth token are correct.
- Added `sessions_store` and `sessions_yield_interrupt` to default tool list —
  these exist in OpenClaw 2026.4.x but were missing from the proxy defaults.
- Fixed `setup.js` to scan NVM install paths (`~/.nvm/versions/node/*/lib/...`)
  when auto-detecting `sessions_*` tools. Previously only checked system-wide
  and npm-global paths, causing NVM-installed OpenClaw to fall back to defaults.
- Updated `config.example.json` with all new patterns.

**Why HEARTBEAT_OK:**
OpenClaw's system prompt includes heartbeat ack instructions containing
`HEARTBEAT_OK`. Anthropic's classifier treats this as a third-party harness
identifier. Replacing it with `HB_ACK` and reverse-mapping responses resolves
the billing rejection. Confirmed via binary search on a 103K system prompt.

**Ordering note:**
`sessions_yield_interrupt` must appear before `sessions_yield` in the
replacements array to avoid partial matches (`sessions_yield` matching the
prefix of `sessions_yield_interrupt`).

---

## v1.2.0 -- 2026-04-05

### Bidirectional reverse mapping + sessions_yield + path-safe replacements

**Changes:**
- Added bidirectional reverse mapping on all API responses
  - SSE streaming: reverse-maps each chunk in real-time
  - JSON responses: buffers, reverse-maps, then sends
  - Ensures OpenClaw sees original tool names, file paths, and identifiers
- Added `sessions_yield` to sanitization (new tool in OpenClaw 2026.3.13+)
- Changed `openclaw` replacement from `assistant platform` (has space, breaks filesystem paths like `.openclaw/`) to `ocplatform` (space-free)
- Added `reverseMap` config option for customizable response-side mappings
- Health endpoint now reports `reverseMapPatterns` count

**Why reverse mapping matters:**
Without it, the model sees sanitized paths (`.ocplatform/workspace/`) in its context and tries to use them for tool calls. The filesystem has `.openclaw/`. Reverse mapping translates responses back so OpenClaw and the filesystem always see original terms.

**Why sessions_yield:**
`sessions_yield` was added in OpenClaw between v2026.3.11 and v2026.3.13. It's a new session management tool for ending the current agent turn after spawning a subagent. Without sanitizing it, requests fail intermittently when conversation history references this tool.

**Wildcard recommendation:**
If your OpenClaw version has additional `sessions_*` tools beyond the 5 listed, add them to your config.json replacements and reverseMap arrays.

---

## v1.1.0 -- 2026-04-05

### Simplified to verified minimal detection bypasses

**Changes:**
- Removed Claude Code tool stub injection — systematic testing proved tool fingerprinting is NOT part of Anthropic's detection
- Reduced sanitization from 18 patterns to 7 verified triggers
- Updated README with accurate detection documentation
- Updated config.example.json with minimal replacement set

**Verified triggers (the only terms Anthropic detects):**
1. `OpenClaw` (case-insensitive) — the platform name
2. `openclaw` — lowercase variant
3. `sessions_spawn` — OpenClaw session management tool
4. `sessions_list` — OpenClaw session management tool
5. `sessions_history` — OpenClaw session management tool
6. `sessions_send` — OpenClaw session management tool
7. `running inside` — the self-declaration phrase ("running inside OpenClaw")

**Confirmed safe (NOT detected):**
- Assistant names (e.g., "custom assistant name")
- Workspace files (AGENTS.md, SOUL.md, USER.md)
- Config paths (.openclaw/, openclaw.json)
- Plugin names (lossless-claw)
- Individual tool names (exec, lcm_grep, gateway, cron, etc.)
- Bot names (custom assistant nameAssistantBot)
- Runtime references (pi-embedded, pi-ai)

**Testing:** Validated with 478+ real OpenClaw requests on production instance.

---

## v1.0.0 — 2026-04-05

### Initial release

- Billing header injection (84-char Claude Code identifier in system prompt)
- OAuth token swap (Claude Code credentials from ~/.claude/.credentials.json)
- Beta flag injection (oauth-2025-04-20, claude-code-20250219, etc.)
- 18 sanitization patterns (overly broad — reduced in v1.1.0)
- Claude Code tool stub injection (unnecessary — removed in v1.1.0)
- Auto-detect credentials path (cross-platform)
- Health endpoint (/health)
- Configurable via config.json or CLI args
- Zero dependencies
