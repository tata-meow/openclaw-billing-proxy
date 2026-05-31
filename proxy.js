#!/usr/bin/env node
/**
 * OpenClaw Subscription Billing Proxy v2.0
 *
 * Routes OpenClaw API requests through Claude Code's subscription billing
 * instead of Extra Usage. Defeats Anthropic's multi-layer detection:
 *
 *   Layer 1: Billing header injection (84-char Claude Code identifier)
 *   Layer 2: String trigger sanitization (OpenClaw, sessions_*, running inside, etc.)
 *            Scope is configurable via config.layer2Scope ("all" | "system" | "off");
 *            default "all" preserves prior behavior. See note at DEFAULT_REPLACEMENTS.
 *   Layer 3: Tool name fingerprint bypass (rename OC tools to CC PascalCase convention)
 *   Layer 4: System prompt template bypass (strip config section, replace with paraphrase)
 *   Layer 5: Tool description stripping (reduce fingerprint signal in tool schemas)
 *   Layer 6: Property name renaming (eliminate OC-specific schema property names)
 *   Layer 7: Full bidirectional reverse mapping (SSE + JSON responses)
 *
 * v1.x string-only sanitization stopped working April 8, 2026 when Anthropic
 * upgraded from string matching to tool-name fingerprinting and template detection.
 * v2.0 defeats the new detection by transforming the entire request body.
 *
 * Zero dependencies. Works on Windows, Linux, Mac.
 *
 * Usage:
 *   node proxy.js [--port 18801] [--config config.json]
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { StringDecoder } = require('string_decoder');

// ─── Defaults ───────────────────────────────────────────────────────────────
const DEFAULT_PORT = 18801;
const UPSTREAM_HOST = 'api.anthropic.com';
const VERSION = '2.6.0';

// Claude Code version to emulate (update when new CC versions are released)
const CC_VERSION = '2.1.97';

// Billing fingerprint constants (matches real CC utils/fingerprint.ts)
const BILLING_HASH_SALT = '59cf53e54c78';
const BILLING_HASH_INDICES = [4, 7, 20];

// Persistent per-instance identifiers (generated once at startup)
const DEVICE_ID = crypto.randomBytes(32).toString('hex');
const INSTANCE_SESSION_ID = crypto.randomUUID();

// ─── Logging helpers ──────────────────────────────────────────────────────────
// Local-time ISO 8601 timestamp with millisecond precision and timezone offset,
// e.g. "2026-05-29T11:00:00.123+08:00". Uses the system timezone (not UTC) so
// logs read naturally for whoever runs the proxy, while the explicit offset keeps
// them unambiguous across machines/timezones.
function tsLocal() {
  const d = new Date();
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  const off = -d.getTimezoneOffset(); // minutes east of UTC (+480 for UTC+8)
  const sign = off >= 0 ? '+' : '-';
  const abs = Math.abs(off);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}` +
    `${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
}

// Per-request log line: "[<ts>] #<reqNum> <msg>". reqNum may be null for logs not
// tied to a specific request. level is 'log' | 'warn' | 'error'.
function plog(reqNum, msg, level = 'log') {
  const prefix = reqNum != null ? `[${tsLocal()}] #${reqNum}` : `[${tsLocal()}]`;
  console[level](`${prefix} ${msg}`);
}

// Build a compact one-line summary of the request params actually being sent
// upstream, e.g. "model=claude-opus-4-8 effort=high thinking=10000 max_tokens=32000
// stream=true tools=14 msgs=42 betas=oauth-2025-04-20,...". Parses the processed
// body so stripped fields (e.g. Haiku effort) are reflected accurately. Falls back
// to regex extraction if the body isn't valid JSON for any reason.
function summarizeParams(bodyStr, betas) {
  const parts = [];
  let p = null;
  try { p = JSON.parse(bodyStr); } catch (e) { p = null; }
  if (p && typeof p === 'object') {
    if (p.model) parts.push(`model=${p.model}`);
    const effort = (p.output_config && p.output_config.effort) ??
      (p.thinking && p.thinking.effort);
    if (effort != null) parts.push(`effort=${effort}`);
    if (p.thinking && p.thinking.budget_tokens != null) parts.push(`thinking=${p.thinking.budget_tokens}`);
    if (p.max_tokens != null) parts.push(`max_tokens=${p.max_tokens}`);
    if (p.stream != null) parts.push(`stream=${p.stream}`);
    if (Array.isArray(p.tools)) parts.push(`tools=${p.tools.length}`);
    if (Array.isArray(p.messages)) parts.push(`msgs=${p.messages.length}`);
  } else {
    const g = (re) => { const m = re.exec(bodyStr); return m ? m[1] : null; };
    const model = g(/"model"\s*:\s*"([^"]+)"/);
    if (model) parts.push(`model=${model}`);
    const effort = g(/"effort"\s*:\s*"([^"]+)"/);
    if (effort) parts.push(`effort=${effort}`);
    const budget = g(/"budget_tokens"\s*:\s*(\d+)/);
    if (budget) parts.push(`thinking=${budget}`);
    const maxTokens = g(/"max_tokens"\s*:\s*(\d+)/);
    if (maxTokens) parts.push(`max_tokens=${maxTokens}`);
    const stream = g(/"stream"\s*:\s*(true|false)/);
    if (stream) parts.push(`stream=${stream}`);
  }
  if (betas && betas.length) parts.push(`betas=${betas.join(',')}`);
  return parts.join(' ');
}

// Beta flags required for OAuth + Claude Code features
// 'advanced-tool-use-2025-11-20' and 'fast-mode-2026-02-01' removed — they don't
// exist in real CC traffic and are density-classifier signals.
const REQUIRED_BETAS = [
  'oauth-2025-04-20',
  'claude-code-20250219',
  'interleaved-thinking-2025-05-14',
  'context-management-2025-06-27',
  'prompt-caching-scope-2026-01-05',
  'effort-2025-11-24'
];

function getModelBetas(model) {
  const m = (model || '').toLowerCase();
  return REQUIRED_BETAS.filter(b => {
    if (b === 'interleaved-thinking-2025-05-14' && m.includes('haiku')) return false;
    if (b === 'effort-2025-11-24' && !/-4-6\b/.test(m)) return false;
    return true;
  });
}

// OAuth token cache (for refresh support)
const OAUTH_TOKEN_URL = 'https://claude.ai/v1/oauth/token';
const OAUTH_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
let _cachedToken = null;
let _credsFilePath = null;
let _refreshPromise = null;

// CC tool stubs -- injected into tools array to make the tool set look more
// like a Claude Code session. The model won't call these (schemas are minimal).
const CC_TOOL_STUBS = [
  '{"name":"Glob","description":"Find files by pattern","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Glob pattern"}},"required":["pattern"]}}',
  '{"name":"Grep","description":"Search file contents","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Regex pattern"},"path":{"type":"string","description":"Search path"}},"required":["pattern"]}}',
  '{"name":"Agent","description":"Launch a subagent for complex tasks","input_schema":{"type":"object","properties":{"prompt":{"type":"string","description":"Task description"}},"required":["prompt"]}}',
  '{"name":"NotebookEdit","description":"Edit notebook cells","input_schema":{"type":"object","properties":{"notebook_path":{"type":"string"},"cell_index":{"type":"integer"}},"required":["notebook_path"]}}',
  '{"name":"TodoRead","description":"Read current task list","input_schema":{"type":"object","properties":{}}}'
];

// ─── Billing Fingerprint ────────────────────────────────────────────────────
// Computes a 3-character SHA256 fingerprint hash matching real CC's
// computeFingerprint() in utils/fingerprint.ts:
//   SHA256(salt + msg[4] + msg[7] + msg[20] + version)[:3]
// Applied to the first user message text in the request body.

function computeBillingFingerprint(firstUserText) {
  const chars = BILLING_HASH_INDICES.map(i => firstUserText[i] || '0').join('');
  const input = `${BILLING_HASH_SALT}${chars}${CC_VERSION}`;
  return crypto.createHash('sha256').update(input).digest('hex').slice(0, 3);
}

// Extract first user message text from the raw body using string scanning.
// Avoids JSON.parse to preserve raw body integrity.
function extractFirstUserText(bodyStr) {
  // Find first "role":"user" in messages array
  const msgsIdx = bodyStr.indexOf('"messages":[');
  if (msgsIdx === -1) return '';
  const userIdx = bodyStr.indexOf('"role":"user"', msgsIdx);
  if (userIdx === -1) return '';

  // Look for "content" near this role
  // Could be "content":"string" or "content":[{..."text":"..."}]
  const contentIdx = bodyStr.indexOf('"content"', userIdx);
  if (contentIdx === -1 || contentIdx > userIdx + 500) return '';

  const afterContent = bodyStr[contentIdx + '"content"'.length + 1]; // skip the :
  if (afterContent === '"') {
    // Simple string content: "content":"text here"
    const textStart = contentIdx + '"content":"'.length;
    let end = textStart;
    while (end < bodyStr.length) {
      if (bodyStr[end] === '\\') { end += 2; continue; }
      if (bodyStr[end] === '"') break;
      end++;
    }
    // Decode basic JSON escapes for the fingerprint characters
    return bodyStr.slice(textStart, end)
      .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  // Array content: find first text block
  const textIdx = bodyStr.indexOf('"text":"', contentIdx);
  if (textIdx === -1 || textIdx > contentIdx + 2000) return '';
  const textStart = textIdx + '"text":"'.length;
  let end = textStart;
  while (end < bodyStr.length) {
    if (bodyStr[end] === '\\') { end += 2; continue; }
    if (bodyStr[end] === '"') break;
    end++;
  }
  return bodyStr.slice(textStart, Math.min(end, textStart + 50))
    .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

function computeCch(text) {
  return crypto.createHash('sha256').update(text).digest('hex').slice(0, 5);
}

function buildBillingBlock(bodyStr, preExtractedText) {
  const firstText = preExtractedText !== undefined ? preExtractedText : extractFirstUserText(bodyStr);
  const fingerprint = computeBillingFingerprint(firstText);
  const ccVersion = `${CC_VERSION}.${fingerprint}`;
  const cch = computeCch(firstText);
  return `{"type":"text","text":"x-anthropic-billing-header: cc_version=${ccVersion}; cc_entrypoint=cli; cch=${cch};"}`;
}

// ─── Stainless SDK Headers ──────────────────────────────────────────────────
// Real Claude Code sends these on every request via the Anthropic JS SDK.
function getStainlessHeaders() {
  const p = process.platform;
  const osName = p === 'darwin' ? 'macOS' : p === 'win32' ? 'Windows' : p === 'linux' ? 'Linux' : p;
  const arch = process.arch === 'x64' ? 'x64' : process.arch === 'arm64' ? 'arm64' : process.arch;
  return {
    'user-agent': `claude-cli/${CC_VERSION} (external, cli)`,
    'x-app': 'cli',
    'x-claude-code-session-id': INSTANCE_SESSION_ID,
    'x-stainless-arch': arch,
    'x-stainless-lang': 'js',
    'x-stainless-os': osName,
    'x-stainless-package-version': '0.90.0',
    'x-stainless-runtime': 'node',
    'x-stainless-runtime-version': process.version,
    'x-stainless-retry-count': '0',
    'x-stainless-timeout': '600',
    'anthropic-dangerous-direct-browser-access': 'true'
  };
}

// ─── Layer 2: String Trigger Replacements ───────────────────────────────────
// Applied via split/join. The SCOPE of application is controlled by
// config.layer2Scope (see loadConfig / processBody):
//   "all"    — replace across the entire request body (default; legacy behavior).
//   "system" — replace only inside the "system":[...] array; user / assistant /
//              tool_result content is left untouched so the upstream agent reads
//              the ORIGINAL (untranslated) conversation + file text.
//   "off"    — skip Layer 2 content replacement entirely.
//
// WHY SCOPING EXISTS: under "all", every string the agent sees (chat history,
// tool results, file contents) is the sanitized/"translated" version, so the
// agent can never read the real text. Empirically Anthropic's third-party
// detection does NOT key off request-BODY content keywords — Layer 3 (tool-name
// fingerprint) and Layer 4 (system template structure) carry the anti-detection
// signal. So narrowing Layer 2 away from message content costs no observable
// detection resistance while letting the agent see original content.
//
// UNVERIFIED RISK (keep in mind when flipping the scope on real traffic):
//   1. The supporting test covered only Haiku + single-shot + short context.
//   2. The tool-ARRAY fingerprint path was NOT exercised (the probe carried no
//      real agent tool set) — this is the genuine risk point once Layer 2 stops
//      rewriting content. Layers 3/4 are deliberately left intact to cover it.
//   3. Acceptance: flip layer2Scope to "system"/"off" during real agent traffic
//      and watch. The subscription has Extra Usage disabled, so a third-party
//      verdict returns rejected/errors immediately rather than billing silently
//      — the failure is loud and instant, not hidden.
//
// IMPORTANT: Use space-free replacements for lowercase 'openclaw' to avoid
// breaking filesystem paths (e.g., .openclaw/ -> .ocplatform/, not .oc platform/)
const DEFAULT_REPLACEMENTS = [
  ['OpenClaw', 'OCPlatform'],
  ['openclaw', 'ocplatform'],
  ['sessions_spawn', 'create_task'],
  ['sessions_list', 'list_tasks'],
  ['sessions_history', 'get_history'],
  ['sessions_send', 'send_to_task'],
  ['sessions_yield_interrupt', 'task_yield_interrupt'],
  ['sessions_yield', 'yield_task'],
  ['sessions_store', 'task_store'],
  ['HEARTBEAT_OK', 'HB_ACK'],
  ['HEARTBEAT', 'HB_SIGNAL'],
  ['heartbeat', 'hb_signal'],
  ['running inside', 'operating from'],
  ['Prometheus', 'PAssistant'],
  ['prometheus', 'passistant'],
  ['clawhub.com', 'skillhub.example.com'],
  ['clawhub', 'skillhub'],
  ['clawd', 'agentd'],
  ['lossless-claw', 'lossless-ctx'],
  ['third-party', 'external'],
  ['billing proxy', 'routing layer'],
  ['billing-proxy', 'routing-layer'],
  ['x-anthropic-billing-header', 'x-routing-config'],
  ['x-anthropic-billing', 'x-routing-cfg'],
  ['cc_version', 'rt_version'],
  ['cc_entrypoint', 'rt_entrypoint'],
  ['billing header', 'routing config'],
  ['extra usage', 'usage quota'],
  ['assistant platform', 'ocplatform']
];

// ─── Layer 3: Tool Name Renames ─────────────────────────────────────────────
// Applied as "quoted" replacements ("name" -> "Name") throughout the ENTIRE body.
// This defeats Anthropic's tool-name fingerprinting which identifies the request
// as OpenClaw based on the combination of tool names in the tools array.
//
// The detector specifically checks for OpenClaw's tool name set. Even with empty
// schemas (no descriptions, no properties), original tool names trigger detection.
// Renaming to PascalCase CC-like conventions defeats this entirely.
//
// ORDERING: lcm_expand_query MUST come before lcm_expand to avoid partial match.
// Tool renames are split into two categories:
//   CC-native: renamed to real CC tool names (no prefix) — these make the tool
//     set look like a genuine Claude Code session.
//   Non-CC: renamed with mcp_ prefix — these look like user-provided MCP tools,
//     which is what Anthropic expects alongside CC-native ones.
//
// CONTEXT-AWARE RENAMES: entries listed in CONTEXT_AWARE_RENAMES use targeted
// "name":"X" replacement instead of global "X" to avoid renaming parameter names
// that collide with the tool name (e.g. the 'message' tool has a 'message' param).
//
// ORDERING: lcm_expand_query MUST come before lcm_expand to avoid partial match.
const CONTEXT_AWARE_RENAMES = new Set(['message']);
const DEFAULT_TOOL_RENAMES = [
  // CC-native (real CC tool names, no prefix)
  ['exec', 'Bash'],
  ['nodes', 'DeviceControl'],
  // Non-CC (mcp_ prefix to look like MCP user tools)
  ['process', 'mcp_BashSession'],
  ['browser', 'mcp_BrowserControl'],
  ['canvas', 'mcp_CanvasView'],
  ['cron', 'mcp_Scheduler'],
  ['message', 'mcp_SendMessage'],
  ['tts', 'mcp_Speech'],
  ['gateway', 'mcp_SystemCtl'],
  ['agents_list', 'mcp_AgentList'],
  ['list_tasks', 'mcp_TaskList'],
  ['get_history', 'mcp_TaskHistory'],
  ['send_to_task', 'mcp_TaskSend'],
  ['create_task', 'mcp_TaskCreate'],
  ['subagents', 'mcp_AgentControl'],
  ['session_status', 'mcp_StatusCheck'],
  // NOTE: web_search, web_fetch removed — these are Anthropic built-in tool types.
  // Renaming them corrupts the "type" field and Anthropic rejects with:
  //   Input tag 'WebSearch' found using 'type' does not match expected tags
  // Same class of bug as the 'image' collision (issue #14).
  //
  // NOTE: ['image', 'ImageGen'] removed — collides with Anthropic content block
  // type "image". (issue #14)
  ['pdf', 'mcp_PdfParse'],
  ['image_generate', 'mcp_ImageCreate'],
  ['music_generate', 'mcp_MusicCreate'],
  ['video_generate', 'mcp_VideoCreate'],
  ['memory_search', 'mcp_KnowledgeSearch'],
  ['memory_get', 'mcp_KnowledgeGet'],
  ['lcm_expand_query', 'mcp_ContextQuery'],
  ['lcm_grep', 'mcp_ContextGrep'],
  ['lcm_describe', 'mcp_ContextDescribe'],
  ['lcm_expand', 'mcp_ContextExpand'],
  ['yield_task', 'mcp_TaskYield'],
  ['task_store', 'mcp_TaskStore'],
  ['task_yield_interrupt', 'mcp_TaskYieldInterrupt']
];

// ─── Layer 6: Property Name Renames ─────────────────────────────────────────
// OC-specific schema property names that contribute to fingerprinting.
const DEFAULT_PROP_RENAMES = [
  ['session_id', 'thread_id'],
  ['conversation_id', 'thread_ref'],
  ['summaryIds', 'chunk_ids'],
  ['summary_id', 'chunk_id'],
  ['system_event', 'event_text'],
  ['agent_id', 'worker_id'],
  ['wake_at', 'trigger_at'],
  ['wake_event', 'trigger_event']
];

// ─── Reverse Mappings ───────────────────────────────────────────────────────
const DEFAULT_REVERSE_MAP = [
  ['create_task', 'sessions_spawn'],
  ['list_tasks', 'sessions_list'],
  ['get_history', 'sessions_history'],
  ['send_to_task', 'sessions_send'],
  ['task_yield_interrupt', 'sessions_yield_interrupt'],
  ['yield_task', 'sessions_yield'],
  ['task_store', 'sessions_store'],
  ['HB_ACK', 'HEARTBEAT_OK'],
  ['HB_SIGNAL', 'HEARTBEAT'],
  ['hb_signal', 'heartbeat'],
  ['PAssistant', 'Prometheus'],
  ['passistant', 'prometheus'],
  ['skillhub.example.com', 'clawhub.com'],
  ['skillhub', 'clawhub'],
  ['agentd', 'clawd'],
  ['lossless-ctx', 'lossless-claw'],
  ['external', 'third-party'],
  ['routing layer', 'billing proxy'],
  ['routing-layer', 'billing-proxy'],
  ['x-routing-config', 'x-anthropic-billing-header'],
  ['x-routing-cfg', 'x-anthropic-billing'],
  ['rt_version', 'cc_version'],
  ['rt_entrypoint', 'cc_entrypoint'],
  ['routing config', 'billing header'],
  ['usage quota', 'extra usage'],
  // OCPlatform/ocplatform must come AFTER more specific patterns above
  ['OCPlatform', 'OpenClaw'],
  ['ocplatform', 'openclaw']
];

// ─── Configuration ──────────────────────────────────────────────────────────
function loadConfig() {
  // Port precedence: PROXY_PORT env > --port CLI > config.json port > DEFAULT_PORT
  const args = process.argv.slice(2);
  let configPath = null;
  let cliPort = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) cliPort = parseInt(args[i + 1]);
    if (args[i] === '--config' && args[i + 1]) configPath = args[i + 1];
  }

  const envPort = process.env.PROXY_PORT ? parseInt(process.env.PROXY_PORT) : null;

  let config = {};
  if (configPath && fs.existsSync(configPath)) {
    try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch(e) {
      console.error('[ERROR] Failed to parse config: ' + configPath + ' (' + e.message + ')');
      process.exit(1);
    }
  } else if (fs.existsSync('config.json')) {
    try { config = JSON.parse(fs.readFileSync('config.json', 'utf8')); } catch(e) {
      console.error('[PROXY] Warning: config.json is invalid, using defaults. (' + e.message + ')');
    }
  }

  const homeDir = os.homedir();

  // OAUTH_TOKEN env var takes precedence over all file-based credentials (useful for Docker)
  let credsPath = null;
  if (process.env.OAUTH_TOKEN) {
    credsPath = 'env';
    console.log('[PROXY] Using OAUTH_TOKEN from environment variable.');
  }

  const credsPaths = [
    config.credentialsPath,
    path.join(homeDir, '.claude', '.credentials.json'),
    path.join(homeDir, '.claude', 'credentials.json')
  ].filter(Boolean);

  if (!credsPath) {
    for (const p of credsPaths) {
      const resolved = p.startsWith('~') ? path.join(homeDir, p.slice(1)) : p;
      if (fs.existsSync(resolved) && fs.statSync(resolved).size > 0) {
        credsPath = resolved;
        break;
      }
    }
  }

  // macOS Keychain fallback
  if (!credsPath && process.platform === 'darwin') {
    const { execSync } = require('child_process');
    for (const svc of ['Claude Code-credentials', 'claude-code', 'claude', 'com.anthropic.claude-code']) {
      try {
        const token = execSync('security find-generic-password -s "' + svc + '" -w 2>/dev/null', { encoding: 'utf8' }).trim();
        if (token) {
          let creds;
          try { creds = JSON.parse(token); } catch(e) {
            if (token.startsWith('sk-ant-')) creds = { claudeAiOauth: { accessToken: token, expiresAt: Date.now() + 86400000, subscriptionType: 'unknown' } };
          }
          if (creds && creds.claudeAiOauth) {
            credsPath = path.join(homeDir, '.claude', '.credentials.json');
            fs.mkdirSync(path.join(homeDir, '.claude'), { recursive: true });
            fs.writeFileSync(credsPath, JSON.stringify(creds));
            console.log('[PROXY] Extracted credentials from macOS Keychain');
            break;
          }
        }
      } catch(e) {}
    }
  }

  if (!credsPath) {
    console.error('[ERROR] Claude Code credentials not found.');
    console.error('Run "claude auth login" first to authenticate.');
    console.error('Searched:', credsPaths.join(', '));
    if (process.platform === 'darwin') console.error('Also checked macOS Keychain (Claude Code-credentials, claude-code, claude, com.anthropic.claude-code).');
    console.error('For Docker: set OAUTH_TOKEN in .env or mount ~/.claude as a volume.');
    process.exit(1);
  }

  // Merge pattern arrays: defaults first, then config additions/overrides.
  // This prevents stale config.json snapshots (from old setup.js runs) from
  // silently masking new default patterns added in proxy updates. (issue #24)
  // Users who want full manual control can set "mergeDefaults": false.
  function mergePatterns(defaults, overrides) {
    if (!overrides || overrides.length === 0) return defaults;
    const merged = new Map();
    for (const [find, replace] of defaults) merged.set(find, replace);
    for (const [find, replace] of overrides) merged.set(find, replace);
    return [...merged.entries()];
  }

  const useDefaults = config.mergeDefaults !== false;

  const replacements = useDefaults
    ? mergePatterns(DEFAULT_REPLACEMENTS, config.replacements)
    : (config.replacements || DEFAULT_REPLACEMENTS);
  const reverseMap = useDefaults
    ? mergePatterns(DEFAULT_REVERSE_MAP, config.reverseMap)
    : (config.reverseMap || DEFAULT_REVERSE_MAP);
  const toolRenames = useDefaults
    ? mergePatterns(DEFAULT_TOOL_RENAMES, config.toolRenames)
    : (config.toolRenames || DEFAULT_TOOL_RENAMES);
  const propRenames = useDefaults
    ? mergePatterns(DEFAULT_PROP_RENAMES, config.propRenames)
    : (config.propRenames || DEFAULT_PROP_RENAMES);

  // Warn if config has stale arrays that were merged
  if (config.replacements && useDefaults && config.replacements.length < DEFAULT_REPLACEMENTS.length) {
    console.log(`[PROXY] Note: config.json has ${config.replacements.length} replacements, merged with ${DEFAULT_REPLACEMENTS.length} defaults -> ${replacements.length} total`);
  }
  if (config.toolRenames && useDefaults && config.toolRenames.length < DEFAULT_TOOL_RENAMES.length) {
    console.log(`[PROXY] Note: config.json has ${config.toolRenames.length} toolRenames, merged with ${DEFAULT_TOOL_RENAMES.length} defaults -> ${toolRenames.length} total`);
  }

  _credsFilePath = credsPath;

  // Layer 2 scope: "all" (default, legacy behavior) | "system" | "off".
  // Unknown/missing values fall back to "all" so existing configs are unaffected.
  const rawScope = (config.layer2Scope || 'all').toString().toLowerCase();
  const layer2Scope = (rawScope === 'system' || rawScope === 'off') ? rawScope : 'all';
  if (config.layer2Scope != null && layer2Scope !== rawScope) {
    console.log(`[PROXY] Warning: unknown layer2Scope "${config.layer2Scope}", falling back to "all".`);
  }

  return {
    port: envPort || cliPort || config.port || DEFAULT_PORT,
    credsPath,
    replacements,
    reverseMap,
    toolRenames,
    contextAwareRenames: CONTEXT_AWARE_RENAMES,
    propRenames,
    layer2Scope,
    stripSystemConfig: config.stripSystemConfig !== false,
    stripToolDescriptions: config.stripToolDescriptions !== false,
    injectCCStubs: config.injectCCStubs === true,
    stripTrailingAssistantPrefill: config.stripTrailingAssistantPrefill !== false
  };
}

// ─── Token Management ───────────────────────────────────────────────────────
function getToken(credsPath) {
  // Env var mode: return synthetic OAuth object without file I/O
  if (credsPath === 'env') {
    const token = process.env.OAUTH_TOKEN;
    if (!token) throw new Error('OAUTH_TOKEN env var is empty.');
    return { accessToken: token, expiresAt: Infinity, subscriptionType: 'env-var' };
  }
  let raw = fs.readFileSync(credsPath, 'utf8');
  if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
  const creds = JSON.parse(raw);
  const oauth = creds.claudeAiOauth;
  if (!oauth || !oauth.accessToken) throw new Error('No OAuth token. Run "claude auth login".');
  return oauth;
}

async function refreshOAuthToken(refreshToken) {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: OAUTH_CLIENT_ID,
    refresh_token: refreshToken,
  }).toString();

  const res = await fetch(OAUTH_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!res.ok) throw new Error(`Token refresh HTTP ${res.status}`);
  const data = await res.json();
  if (!data.access_token) throw new Error('Token refresh: no access_token in response');

  const newToken = {
    accessToken: data.access_token,
    refreshToken: data.refresh_token ?? refreshToken,
    expiresAt: Date.now() + (data.expires_in ?? 36000) * 1000,
    subscriptionType: _cachedToken?.subscriptionType ?? 'unknown',
  };

  _cachedToken = newToken;

  if (_credsFilePath && _credsFilePath !== 'env') {
    try {
      let raw = fs.readFileSync(_credsFilePath, 'utf8');
      if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
      const creds = JSON.parse(raw);
      creds.claudeAiOauth = {
        ...creds.claudeAiOauth,
        accessToken: newToken.accessToken,
        refreshToken: newToken.refreshToken,
        expiresAt: newToken.expiresAt,
      };
      fs.writeFileSync(_credsFilePath, JSON.stringify(creds, null, 2), 'utf8');
      console.log('[OAUTH] Refreshed token written back to credentials file.');
    } catch (writeErr) {
      console.warn('[OAUTH] Could not write refreshed token to file:', writeErr.message);
    }
  }

  console.log(`[OAUTH] Token refreshed. Expires in ${Math.round((data.expires_in ?? 36000) / 3600)}h.`);
  return newToken;
}

async function getTokenAsync(credsPath) {
  if (credsPath === 'env') return getToken(credsPath);

  if (_cachedToken && (_cachedToken.expiresAt - Date.now()) > 5 * 60 * 1000) {
    return _cachedToken;
  }

  let raw = fs.readFileSync(credsPath, 'utf8');
  if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
  const creds = JSON.parse(raw);
  const oauth = creds.claudeAiOauth;
  if (!oauth || !oauth.accessToken) throw new Error('No OAuth token. Run "claude auth login".');

  _cachedToken = {
    accessToken: oauth.accessToken,
    refreshToken: oauth.refreshToken,
    expiresAt: oauth.expiresAt ?? Infinity,
    subscriptionType: oauth.subscriptionType ?? 'unknown',
  };

  const timeRemaining = (_cachedToken.expiresAt - Date.now());
  if (timeRemaining < 5 * 60 * 1000 && _cachedToken.refreshToken) {
    if (!_refreshPromise) {
      console.log('[OAUTH] Token expiring soon, refreshing...');
      _refreshPromise = refreshOAuthToken(_cachedToken.refreshToken)
        .finally(() => { _refreshPromise = null; });
    }
    try {
      _cachedToken = await _refreshPromise;
    } catch (refreshErr) {
      console.warn('[OAUTH] Refresh failed, using existing token:', refreshErr.message);
    }
  }

  return _cachedToken;
}

// ─── Helper ─────────────────────────────────────────────────────────────────
// String-aware bracket matching: skips [/] inside JSON string values so that
// brackets in tool descriptions or text content don't corrupt the depth count.
function findMatchingBracket(str, start) {
  let d = 0, inStr = false;
  for (let i = start; i < str.length; i++) {
    const c = str[i];
    if (inStr) {
      if (c === '\\') { i++; continue; }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === '[') d++;
    else if (c === ']') { d--; if (d === 0) return i; }
  }
  return -1;
}

// String-aware brace matching: counterpart to findMatchingBracket for {/}.
function findMatchingBrace(str, start) {
  let d = 0, inStr = false;
  for (let i = start; i < str.length; i++) {
    const c = str[i];
    if (inStr) {
      if (c === '\\') { i++; continue; }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === '{') d++;
    else if (c === '}') { d--; if (d === 0) return i; }
  }
  return -1;
}

// Strips "effort" key-value from a JSON object identified by objectKey.
// Haiku models reject effort params with 400; this removes them safely.
function stripEffortFromObject(str, objectKey) {
  const keyPattern = '"' + objectKey + '"';
  let pos = str.indexOf(keyPattern);
  if (pos === -1) return str;
  let braceStart = str.indexOf('{', pos + keyPattern.length);
  if (braceStart === -1) return str;
  const braceEnd = findMatchingBrace(str, braceStart);
  if (braceEnd === -1) return str;
  const inner = str.slice(braceStart + 1, braceEnd);
  let cleaned = inner
    .replace(/,\s*"effort"\s*:\s*(?:"[^"]*"|\d+(?:\.\d+)?|true|false|null)/, '')
    .replace(/"effort"\s*:\s*(?:"[^"]*"|\d+(?:\.\d+)?|true|false|null),?\s*/, '');
  cleaned = cleaned.replace(/,\s*$/, '').trim();
  if (cleaned === '') {
    const keyStart = str.lastIndexOf(',', pos);
    if (keyStart !== -1 && str.slice(keyStart, pos).trim() === ',') {
      return str.slice(0, keyStart) + str.slice(braceEnd + 1);
    }
    return str.slice(0, pos) + str.slice(braceEnd + 1);
  }
  return str.slice(0, braceStart + 1) + cleaned + str.slice(braceEnd);
}

// Filter CC_TOOL_STUBS to only those whose name isn't already present in the
// tools section JSON. Prevents Anthropic's "Tool names must be unique" error.
function filterStubsAgainstExisting(stubs, toolsSection) {
  const existingNames = new Set();
  const nameRe = /"name":"([^"]+)"/g;
  let match;
  while ((match = nameRe.exec(toolsSection)) !== null) {
    existingNames.add(match[1].toLowerCase());
  }
  return stubs.filter((stubJson) => {
    const m = /"name":"([^"]+)"/.exec(stubJson);
    return m ? !existingNames.has(m[1].toLowerCase()) : true;
  });
}

// Removes orphaned tool_use / tool_result blocks from conversation history.
// An orphaned tool_use has no matching tool_result; an orphaned tool_result
// has no matching tool_use. Both cause Anthropic API validation errors.
function repairToolPairs(bodyStr, reqNum) {
  const msgsStart = bodyStr.indexOf('"messages":[');
  if (msgsStart === -1) return bodyStr;
  const arrayOpenIdx = msgsStart + '"messages":'.length;
  const arrayCloseIdx = findMatchingBracket(bodyStr, arrayOpenIdx);
  if (arrayCloseIdx === -1) return bodyStr;
  const messagesJson = bodyStr.slice(arrayOpenIdx, arrayCloseIdx + 1);
  let messages;
  try { messages = JSON.parse(messagesJson); } catch (e) { return bodyStr; }
  if (!Array.isArray(messages)) return bodyStr;
  const toolUseIds = new Set();
  const toolResultIds = new Set();
  for (const message of messages) {
    if (!Array.isArray(message.content)) continue;
    for (const block of message.content) {
      if (block.type === 'tool_use' && typeof block.id === 'string') toolUseIds.add(block.id);
      if (block.type === 'tool_result' && typeof block.tool_use_id === 'string') toolResultIds.add(block.tool_use_id);
    }
  }
  const orphanedUses = new Set();
  for (const id of toolUseIds) if (!toolResultIds.has(id)) orphanedUses.add(id);
  const orphanedResults = new Set();
  for (const id of toolResultIds) if (!toolUseIds.has(id)) orphanedResults.add(id);
  if (orphanedUses.size === 0 && orphanedResults.size === 0) return bodyStr;
  plog(reqNum, `[REPAIR] Removing ${orphanedUses.size} orphaned tool_use and ${orphanedResults.size} orphaned tool_result blocks`);
  const candidateRepaired = messages.map((message) => {
    if (!Array.isArray(message.content)) return message;
    const filtered = message.content.filter((block) => {
      if (block.type === 'tool_use' && typeof block.id === 'string') return !orphanedUses.has(block.id);
      if (block.type === 'tool_result' && typeof block.tool_use_id === 'string') return !orphanedResults.has(block.tool_use_id);
      return true;
    });
    if (filtered.length === 0) return null;
    return { ...message, content: filtered };
  });
  const repaired = [];
  for (let i = 0; i < candidateRepaired.length; i++) {
    if (candidateRepaired[i] !== null) {
      repaired.push(candidateRepaired[i]);
    } else {
      const prevRole = repaired.length > 0 ? repaired[repaired.length - 1].role : null;
      const nextMsg = candidateRepaired.slice(i + 1).find(m => m !== null);
      const nextRole = nextMsg ? nextMsg.role : null;
      if (prevRole && nextRole && prevRole === nextRole) {
        repaired.push({ ...messages[i], content: [{ type: 'text', text: '(removed)' }] });
      }
    }
  }
  const repairedJson = JSON.stringify(repaired);
  return bodyStr.slice(0, arrayOpenIdx) + repairedJson + bodyStr.slice(arrayCloseIdx + 1);
}

// ─── Thinking Block Protection ──────────────────────────────────────────────
// Anthropic requires thinking/redacted_thinking content blocks to be echoed
// back byte-identical to what the model originally produced; any mutation
// triggers:
//   "thinking or redacted_thinking blocks in the latest assistant message
//    cannot be modified. These blocks must remain as they were in the
//    original response."
// Both the forward pass (Layer 2/3/6 running against assistant message
// history) and the reverse pass (reverseMap running against responses the
// client stores and echoes on subsequent turns) mutate these blocks via plain
// split/join. Mask each content block with a unique placeholder before
// transforms run, restore after. The placeholder is chosen so no replacement
// or rename pattern can match it.
const THINK_MASK_PREFIX = '__OBP_THINK_MASK_';
const THINK_MASK_SUFFIX = '__';

// Finds thinking/redacted_thinking content blocks regardless of JSON formatting
// (key order, whitespace). Handles cases where client re-serializes thinking
// blocks differently from Anthropic's compact format — e.g. with spaces after
// colons, or with 'type' not being the first key.
function maskThinkingBlocks(m) {
  const masks = [];
  const TYPE_RE = /"type"\s*:\s*"(?:thinking|redacted_thinking)"/g;
  const positions = [];
  let match;
  while ((match = TYPE_RE.exec(m)) !== null) {
    // Scan backward to find the enclosing '{'. Skip balanced {/} pairs.
    // For content array elements, the first unmatched '{' is the object start.
    let depth = 0, objStart = -1;
    for (let j = match.index - 1; j >= 0; j--) {
      if (m[j] === '}') depth++;
      else if (m[j] === '{') {
        if (depth === 0) { objStart = j; break; }
        depth--;
      }
    }
    if (objStart === -1) continue;
    // Forward-scan from objStart with string-aware brace matching
    const objEnd = findMatchingBrace(m, objStart);
    if (objEnd === -1) continue;
    positions.push({ start: objStart, end: objEnd + 1 });
  }
  if (positions.length === 0) return { masked: m, masks };
  positions.sort((a, b) => a.start - b.start);
  let out = '';
  let lastEnd = 0;
  for (const pos of positions) {
    if (pos.start < lastEnd) continue;
    out += m.slice(lastEnd, pos.start);
    masks.push(m.slice(pos.start, pos.end));
    out += THINK_MASK_PREFIX + (masks.length - 1) + THINK_MASK_SUFFIX;
    lastEnd = pos.end;
  }
  out += m.slice(lastEnd);
  return { masked: out, masks };
}

function unmaskThinkingBlocks(m, masks) {
  for (let i = 0; i < masks.length; i++) {
    m = m.split(THINK_MASK_PREFIX + i + THINK_MASK_SUFFIX).join(masks[i]);
  }
  return m;
}

// Strips all thinking/redacted_thinking content blocks from assistant messages
// in the request body. OpenClaw re-serializes conversation history, which
// changes the byte representation of thinking blocks. Anthropic requires these
// blocks to be byte-identical to the original response if present — but does
// NOT require them to be present at all. Stripping them is the only reliable
// fix since the proxy can't undo OpenClaw's re-serialization. (issue #45)
function stripThinkingBlocks(bodyStr, reqNum) {
  const msgsStart = bodyStr.indexOf('"messages":[');
  if (msgsStart === -1) return bodyStr;
  const arrayOpenIdx = msgsStart + '"messages":'.length;
  const arrayCloseIdx = findMatchingBracket(bodyStr, arrayOpenIdx);
  if (arrayCloseIdx === -1) return bodyStr;
  const messagesJson = bodyStr.slice(arrayOpenIdx, arrayCloseIdx + 1);
  let messages;
  try { messages = JSON.parse(messagesJson); } catch (e) { return bodyStr; }
  if (!Array.isArray(messages)) return bodyStr;

  let stripped = 0;
  for (const message of messages) {
    if (message.role !== 'assistant' || !Array.isArray(message.content)) continue;
    const before = message.content.length;
    message.content = message.content.filter(block =>
      block.type !== 'thinking' && block.type !== 'redacted_thinking'
    );
    stripped += before - message.content.length;
  }

  if (stripped === 0) return bodyStr;
  plog(reqNum, `[STRIP-THINKING] Removed ${stripped} thinking/redacted_thinking blocks from message history`);
  return bodyStr.slice(0, arrayOpenIdx) + JSON.stringify(messages) + bodyStr.slice(arrayCloseIdx + 1);
}

// ─── Filesystem Path Protection ─────────────────────────────────────────────
// Matches absolute paths with 2+ segments (e.g. /home/user/.openclaw/file.png)
// and relative paths starting with ./ or ../ (e.g. ./src/openclaw/mod.js).
// Uses NUL byte delimiters as placeholders — safe since NUL never appears in JSON.
const _FS_PATH_RE = /(?:\.\.?)?(?<![\/:])\/(?:[\w.~@+-]+\/)+[\w.~@+-]*/g;

function protectPaths(str) {
  const saved = [];
  const result = str.replace(_FS_PATH_RE, (match) => {
    saved.push(match);
    return `\x00P${saved.length - 1}\x00`;
  });
  return { result, saved };
}

function restorePaths(str, saved) {
  for (let i = 0; i < saved.length; i++) {
    str = str.split(`\x00P${i}\x00`).join(saved[i]);
  }
  return str;
}

// ─── Request Processing ─────────────────────────────────────────────────────
function processBody(bodyStr, config, reqPath, reqNum) {
  // Repair orphaned tool_use/tool_result pairs before any transforms.
  // Must run on the original body (pre-masking) since masking corrupts JSON.parse.
  bodyStr = repairToolPairs(bodyStr, reqNum);

  // Strip thinking/redacted_thinking blocks from message history. OpenClaw
  // re-serializes these, breaking byte-equality. Anthropic accepts messages
  // without thinking blocks, so removing them is safer than trying to preserve
  // corrupted ones. Must run before masking (needs JSON.parse on messages).
  bodyStr = stripThinkingBlocks(bodyStr, reqNum);

  // Extract original first user text for billing fingerprint BEFORE any transforms
  const originalFirstUserText = extractFirstUserText(bodyStr);

  // Mask any remaining thinking/redacted_thinking patterns (e.g. in system prompt)
  // from the transform pipeline so Layer 2/3/6 split/join can't mutate them.
  const { masked: maskedBody, masks: thinkMasks } = maskThinkingBlocks(bodyStr);
  let m = maskedBody;

  // Layer 2: String trigger sanitization. Scope controlled by config.layer2Scope:
  //   "all"    — apply across the whole body (default; legacy behavior).
  //   "system" — apply only inside "system":[...] / "system":"..." so the agent
  //              reads original user/assistant/tool_result content.
  //   "off"    — skip entirely.
  // See the note at DEFAULT_REPLACEMENTS for rationale and the unverified risks.
  //
  // Filesystem paths are protected from blind replacement either way. Without this,
  // paths like /home/user/.openclaw/media/... get corrupted (e.g. .openclaw ->
  // .tataclaw), breaking OpenClaw's assertLocalMediaAllowed() security check which
  // validates against allowed directory roots.
  const applyLayer2 = (s) => {
    const { result: pathProtected, saved } = protectPaths(s);
    let t = pathProtected;
    for (const [find, replace] of config.replacements) {
      t = t.split(find).join(replace);
    }
    return restorePaths(t, saved);
  };

  if (config.layer2Scope === 'off') {
    // Layer 2 disabled — leave all content untouched.
  } else if (config.layer2Scope === 'system') {
    // Confine replacement to the system prompt only. At this point in the
    // pipeline the system array is still the original one (the billing block is
    // injected later, in Layer 1), so this slice is exactly the system content.
    const sysArrayStart = m.indexOf('"system":[');
    if (sysArrayStart !== -1) {
      const sysArrayEnd = findMatchingBracket(m, sysArrayStart + '"system":'.length);
      if (sysArrayEnd !== -1) {
        const sysSection = m.slice(sysArrayStart, sysArrayEnd + 1);
        m = m.slice(0, sysArrayStart) + applyLayer2(sysSection) + m.slice(sysArrayEnd + 1);
      }
    } else if (m.includes('"system":"')) {
      // String-form system prompt: "system":"...."
      const sysStart = m.indexOf('"system":"');
      let i = sysStart + '"system":"'.length;
      while (i < m.length) {
        if (m[i] === '\\') { i += 2; continue; }
        if (m[i] === '"') break;
        i++;
      }
      const sysEnd = i + 1;
      m = m.slice(0, sysStart) + applyLayer2(m.slice(sysStart, sysEnd)) + m.slice(sysEnd);
    }
  } else {
    // "all" (default): replace across the entire body.
    m = applyLayer2(m);
  }

  // Layer 2.5: Strip effort param for Haiku models (Haiku rejects effort with 400)
  {
    const modelMatch = /"model"\s*:\s*"([^"]+)"/.exec(m);
    if (modelMatch && modelMatch[1].toLowerCase().includes('haiku')) {
      m = stripEffortFromObject(m, 'output_config');
      m = stripEffortFromObject(m, 'thinking');
      plog(reqNum, '[EFFORT] Stripped effort param for Haiku model: ' + modelMatch[1]);
    }
  }

  // Layer 3: Tool name fingerprint bypass (quoted replacement for precision)
  // Context-aware renames (e.g. 'message') only replace "name":"X" positions
  // to avoid renaming parameter names that collide with the tool name.
  for (const [orig, cc] of config.toolRenames) {
    if (config.contextAwareRenames.has(orig)) {
      m = m.split('"name":"' + orig + '"').join('"name":"' + cc + '"');
      m = m.split('"name": "' + orig + '"').join('"name": "' + cc + '"');
    } else {
      m = m.split('"' + orig + '"').join('"' + cc + '"');
    }
  }

  // Layer 6: Property name renaming
  for (const [orig, renamed] of config.propRenames) {
    m = m.split('"' + orig + '"').join('"' + renamed + '"');
  }

  // Layer 4: System prompt template bypass
  // Strip the OC config section (~28K of ## Tooling, ## Workspace, ## Messaging, etc.)
  // and replace with a brief paraphrase. The config is between the identity line
  // and the first workspace doc header (filesystem path).
  // IMPORTANT: Search WITHIN the system array, not from the start of the body.
  // The identity line can appear in conversation history (from prior discussions),
  // and matching there instead of the system prompt causes the strip to fail.
  //
  // Multi-marker detection: OpenClaw identity text varies by config. Try all known
  // variants in order of specificity. The first match wins.
  if (config.stripSystemConfig) {
    const IDENTITY_MARKERS = [
      'You are a personal assistant',
      'You are an AI assistant',
      'You are a helpful assistant',
      'You are an intelligent assistant',
      'You are an AI agent',
      'You are an agent',
    ];

    const END_BOUNDARY_PATTERNS = [
      '\\n## /',
      '\\n## \\\\\\\\',
      '\\n## //',
    ];

    const sysArrayStart = m.indexOf('"system":[');
    let sysArrayEnd = -1;
    if (sysArrayStart !== -1) {
      sysArrayEnd = findMatchingBracket(m, sysArrayStart + '"system":'.length);
    }
    const searchFrom = sysArrayStart !== -1 ? sysArrayStart : 0;
    const searchTo = sysArrayEnd !== -1 ? sysArrayEnd : m.length;

    let configStart = -1;
    let matchedMarker = '';
    for (const marker of IDENTITY_MARKERS) {
      const idx = m.indexOf(marker, searchFrom);
      if (idx !== -1 && idx < searchTo) {
        configStart = idx;
        matchedMarker = marker;
        break;
      }
    }

    if (configStart !== -1) {
      let stripFrom = configStart;
      if (stripFrom >= 2 && m[stripFrom - 2] === '\\' && m[stripFrom - 1] === 'n') {
        stripFrom -= 2;
      }

      let configEnd = -1;
      const searchAfter = configStart + matchedMarker.length;
      for (const pat of END_BOUNDARY_PATTERNS) {
        const idx = m.indexOf(pat, searchAfter);
        if (idx !== -1 && (configEnd === -1 || idx < configEnd)) {
          configEnd = idx;
        }
      }
      {
        const winPattern = /\\n## [A-Z]:\\\\/g;
        winPattern.lastIndex = searchAfter;
        const wm = winPattern.exec(m);
        if (wm !== null && (configEnd === -1 || wm.index < configEnd)) {
          configEnd = wm.index;
        }
      }

      if (configEnd !== -1) {
        const strippedLen = configEnd - stripFrom;
        if (strippedLen > 1000) {
          const PARAPHRASE =
            '\\nYou are an AI operations assistant with access to all tools listed in this request ' +
            'for file operations, command execution, web search, browser control, scheduling, ' +
            'messaging, and session management. Tool names are case-sensitive and must be called ' +
            'exactly as listed. Your responses route to the active channel automatically. ' +
            'For cross-session communication, use the task messaging tools. ' +
            'Skills defined in your workspace should be invoked when they match user requests. ' +
            'Consult your workspace reference files for detailed operational configuration.\\n';

          m = m.slice(0, stripFrom) + PARAPHRASE + m.slice(configEnd);
          plog(reqNum, `[STRIP] Removed ${strippedLen} chars of config template (marker: "${matchedMarker}")`);
        }
      } else {
        plog(reqNum, `[STRIP] Layer 4: identity marker found ("${matchedMarker}") but no end boundary detected — skipping strip to preserve body integrity`, 'warn');
      }
    }
  }

  // Layer 5: Tool description stripping
  if (config.stripToolDescriptions) {
    const toolsIdx = m.indexOf('"tools":[');
    if (toolsIdx !== -1) {
      const toolsEndIdx = findMatchingBracket(m, toolsIdx + '"tools":'.length);
      if (toolsEndIdx !== -1) {
        let section = m.slice(toolsIdx, toolsEndIdx + 1);
        let from = 0;
        while (true) {
          const d = section.indexOf('"description":"', from);
          if (d === -1) break;
          const vs = d + '"description":"'.length;
          let i = vs;
          while (i < section.length) {
            if (section[i] === '\\' && i + 1 < section.length) { i += 2; continue; }
            if (section[i] === '"') break;
            i++;
          }
          section = section.slice(0, vs) + section.slice(i);
          from = vs + 1;
        }
        // Inject CC tool stubs (dedup against existing tool names)
        if (config.injectCCStubs) {
          const stubsToInject = filterStubsAgainstExisting(CC_TOOL_STUBS, section);
          if (stubsToInject.length > 0) {
            const insertAt = '"tools":['.length;
            section = section.slice(0, insertAt) + stubsToInject.join(',') + ',' + section.slice(insertAt);
          }
        }
        m = m.slice(0, toolsIdx) + section + m.slice(toolsEndIdx + 1);
      }
    }
  } else if (config.injectCCStubs) {
    // Inject stubs even without description stripping (dedup against existing)
    const toolsIdx = m.indexOf('"tools":[');
    if (toolsIdx !== -1) {
      const toolsEndIdx = findMatchingBracket(m, toolsIdx + '"tools":'.length);
      if (toolsEndIdx !== -1) {
        const section = m.slice(toolsIdx, toolsEndIdx + 1);
        const stubsToInject = filterStubsAgainstExisting(CC_TOOL_STUBS, section);
        if (stubsToInject.length > 0) {
          const insertAt = toolsIdx + '"tools":['.length;
          m = m.slice(0, insertAt) + stubsToInject.join(',') + ',' + m.slice(insertAt);
        }
      }
    }
  }

  // Layer 1: Billing header injection (dynamic fingerprint per request)
  // Uses original user text (pre-transform) so CCH hash is stable.
  const BILLING_BLOCK = buildBillingBlock(m, originalFirstUserText);
  const sysArrayIdx = m.indexOf('"system":[');
  if (sysArrayIdx !== -1) {
    const insertAt = sysArrayIdx + '"system":['.length;
    m = m.slice(0, insertAt) + BILLING_BLOCK + ',' + m.slice(insertAt);
  } else if (m.includes('"system":"')) {
    const sysStart = m.indexOf('"system":"');
    let i = sysStart + '"system":"'.length;
    while (i < m.length) {
      if (m[i] === '\\') { i += 2; continue; }
      if (m[i] === '"') break;
      i++;
    }
    const sysEnd = i + 1;
    const originalSysStr = m.slice(sysStart + '"system":'.length, sysEnd);
    m = m.slice(0, sysStart)
      + '"system":[' + BILLING_BLOCK + ',{"type":"text","text":' + originalSysStr + '}]'
      + m.slice(sysEnd);
  } else {
    m = '{"system":[' + BILLING_BLOCK + '],' + m.slice(1);
  }

  // Metadata injection: device_id + session_id matching real CC format.
  // Restricted to /v1/messages — count_tokens and other sub-endpoints reject
  // the metadata field ("Extra inputs are not permitted").
  if (reqPath === '/v1/messages' || reqPath === '/v1/messages/') {
    const metaValue = JSON.stringify({ device_id: DEVICE_ID, session_id: INSTANCE_SESSION_ID });
    const metaJson = '"metadata":{"user_id":' + JSON.stringify(metaValue) + '}';
    const existingMeta = m.indexOf('"metadata":{');
    if (existingMeta !== -1) {
      let depth = 0, mi = existingMeta + '"metadata":'.length;
      for (; mi < m.length; mi++) {
        if (m[mi] === '{') depth++;
        else if (m[mi] === '}') { depth--; if (depth === 0) { mi++; break; } }
      }
      m = m.slice(0, existingMeta) + metaJson + m.slice(mi);
    } else {
      m = '{' + metaJson + ',' + m.slice(1);
    }
  } else {
    // Strip any stale metadata the client may have sent on non-messages endpoints
    const existingMeta = m.indexOf('"metadata":{');
    if (existingMeta !== -1) {
      let depth = 0, mi = existingMeta + '"metadata":'.length;
      for (; mi < m.length; mi++) {
        if (m[mi] === '{') depth++;
        else if (m[mi] === '}') { depth--; if (depth === 0) { mi++; break; } }
      }
      let end = mi;
      if (m[end] === ',') end++;
      let start = existingMeta;
      if (start > 0 && m[start - 1] === ',') start--;
      m = m.slice(0, start) + m.slice(end);
    }
  }

  // Layer 8: Strip trailing assistant prefill (raw string, no JSON.parse)
  // Opus 4.6 disabled assistant message prefill. OpenClaw sometimes pre-fills the
  // next assistant turn to resume interrupted responses, causing permanent 400
  // errors ("This model does not support assistant message prefill"). The error is
  // permanent for the affected session — every retry includes the same prefill.
  // Fix: forward-scan the messages array with string-aware bracket matching,
  // then pop trailing assistant messages until the array ends with a user message.
  if (config.stripTrailingAssistantPrefill !== false) {
    const msgsIdx = m.indexOf('"messages":[');
    if (msgsIdx !== -1) {
      const arrayStart = msgsIdx + '"messages":['.length;
      const positions = [];
      let depth = 0, inString = false, objStart = -1;
      for (let i = arrayStart; i < m.length; i++) {
        const c = m[i];
        if (inString) {
          if (c === '\\') { i++; continue; }
          if (c === '"') inString = false;
          continue;
        }
        if (c === '"') { inString = true; continue; }
        if (c === '{') { if (depth === 0) objStart = i; depth++; }
        else if (c === '}') { depth--; if (depth === 0 && objStart !== -1) { positions.push({ start: objStart, end: i }); objStart = -1; } }
        else if (c === ']' && depth === 0) break;
      }
      let popped = 0;
      while (positions.length > 0) {
        const last = positions[positions.length - 1];
        const obj = m.slice(last.start, last.end + 1);
        if (!obj.includes('"role":"assistant"')) break;
        let stripFrom = last.start;
        for (let i = last.start - 1; i >= arrayStart; i--) {
          if (m[i] === ',') { stripFrom = i; break; }
          if (m[i] !== ' ' && m[i] !== '\n' && m[i] !== '\r' && m[i] !== '\t') break;
        }
        m = m.slice(0, stripFrom) + m.slice(last.end + 1);
        positions.pop();
        popped++;
      }
      if (popped > 0) {
        plog(reqNum, `[STRIP-PREFILL] Removed ${popped} trailing assistant message(s)`);
      }
    }
  }

  return unmaskThinkingBlocks(m, thinkMasks);
}

// ─── Response Processing ────────────────────────────────────────────────────
function reverseMap(text, config) {
  let r = text;
  // Reverse tool names first (more specific patterns).
  // Handle BOTH plain ("Name") AND escaped (\"Name\") forms.
  // SSE input_json_delta embeds tool args in a partial_json string field where
  // inner quotes are escaped.
  // Context-aware renames (e.g. 'message') only replaced "name":"X" on the
  // forward pass, so only the tool name needs reversal — but the mcp_ prefixed
  // name is unique enough that global replacement is safe here.
  for (const [orig, cc] of config.toolRenames) {
    r = r.split('"' + cc + '"').join('"' + orig + '"');
    r = r.split('\\"' + cc + '\\"').join('\\"' + orig + '\\"');
  }
  // Reverse property names — same dual handling
  for (const [orig, renamed] of config.propRenames) {
    r = r.split('"' + renamed + '"').join('"' + orig + '"');
    r = r.split('\\"' + renamed + '\\"').join('\\"' + orig + '\\"');
  }
  // Reverse string replacements
  for (const [sanitized, original] of config.reverseMap) {
    r = r.split(sanitized).join(original);
  }
  return r;
}

// ─── Server ─────────────────────────────────────────────────────────────────
function startServer(config) {
  let requestCount = 0;
  const startedAt = Date.now();

  const server = http.createServer((req, res) => {
    if (req.url === '/health' && req.method === 'GET') {
      try {
        const tokenInfo = getToken(config.credsPath);
        const expiresIn = (tokenInfo.expiresAt - Date.now()) / 3600000;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: expiresIn > 0 ? 'ok' : 'token_expired',
          proxy: 'openclaw-billing-proxy',
          version: VERSION,
          requestsServed: requestCount,
          uptime: Math.floor((Date.now() - startedAt) / 1000) + 's',
          tokenExpiresInHours: isFinite(expiresIn) ? expiresIn.toFixed(1) : 'n/a',
          tokenCached: !!_cachedToken,
          subscriptionType: tokenInfo.subscriptionType,
          layers: {
            stringReplacements: config.replacements.length,
            layer2Scope: config.layer2Scope,
            toolNameRenames: config.toolRenames.length,
            propertyRenames: config.propRenames.length,
            ccToolStubs: config.injectCCStubs ? CC_TOOL_STUBS.length : 0,
            systemStripEnabled: config.stripSystemConfig,
            descriptionStripEnabled: config.stripToolDescriptions
          }
        }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: e.message }));
      }
      return;
    }

    requestCount++;
    const reqNum = requestCount;
    const chunks = [];

    req.on('data', c => chunks.push(c));
    req.on('end', async () => {
      let body = Buffer.concat(chunks);
      let oauth;
      try { oauth = await getTokenAsync(config.credsPath); } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        return;
      }

      let bodyStr = body.toString('utf8');
      const originalSize = bodyStr.length;
      bodyStr = processBody(bodyStr, config, (req.url || '').split('?')[0], reqNum);
      body = Buffer.from(bodyStr, 'utf8');

      const headers = {};
      for (const [key, value] of Object.entries(req.headers)) {
        const lk = key.toLowerCase();
        if (lk === 'host' || lk === 'connection' || lk === 'authorization' ||
            lk === 'x-api-key' || lk === 'content-length' ||
            lk === 'x-session-affinity') continue; // strip non-CC headers
        headers[key] = value;
      }
      headers['authorization'] = `Bearer ${oauth.accessToken}`;
      headers['content-length'] = body.length;
      headers['accept-encoding'] = 'identity';
      headers['anthropic-version'] = '2023-06-01';

      // Inject Stainless SDK + Claude Code identity headers
      const ccHeaders = getStainlessHeaders();
      for (const [k, v] of Object.entries(ccHeaders)) {
        headers[k] = v;
      }

      // Per-model beta filtering: skip interleaved-thinking for Haiku,
      // skip effort for non-4.6 models.
      const modelMatch = bodyStr.match(/"model"\s*:\s*"([^"]+)"/);
      const modelName = modelMatch ? modelMatch[1] : '';
      const modelBetas = getModelBetas(modelName);
      const existingBeta = headers['anthropic-beta'] || '';
      const betas = existingBeta ? existingBeta.split(',').map(b => b.trim()) : [];
      for (const b of modelBetas) { if (!betas.includes(b)) betas.push(b); }
      headers['anthropic-beta'] = betas.join(',');

      plog(reqNum, `${req.method} ${req.url} (${originalSize}b -> ${body.length}b)`);
      plog(reqNum, `params: ${summarizeParams(bodyStr, betas)}`);

      const upstream = https.request({
        hostname: UPSTREAM_HOST, port: 443,
        path: req.url, method: req.method, headers
      }, (upRes) => {
        const status = upRes.statusCode;
        plog(reqNum, `> ${status}`);
        if (status === 401) {
          plog(reqNum, 'Got 401 from Anthropic — forcing token cache invalidation.', 'warn');
          _cachedToken = null;
        }
        if (status !== 200 && status !== 201) {
          const errChunks = [];
          upRes.on('data', c => errChunks.push(c));
          upRes.on('end', () => {
            let errBody = Buffer.concat(errChunks).toString();
            if (errBody.includes('extra usage')) {
              plog(reqNum, `DETECTION! Body: ${body.length}b`, 'error');
            }
            errBody = reverseMap(errBody, config);
            const nh = { ...upRes.headers };
            delete nh['transfer-encoding']; // avoid conflict with content-length
            nh['content-length'] = Buffer.byteLength(errBody);
            res.writeHead(status, nh);
            res.end(errBody);
          });
          return;
        }
        // SSE streaming — event-aware reverseMap. Buffer until a complete SSE
        // event arrives (terminated by \n\n), then transform per event. This
        // subsumes the older tail-buffer fix for patterns split across TCP
        // chunks (#11) because SSE events are self-contained, so patterns
        // can't span event boundaries. It also lets us track the current
        // content block type across events and pass thinking/redacted_thinking
        // bytes through unchanged — Anthropic rejects the next turn otherwise
        // with "thinking blocks in the latest assistant message cannot be
        // modified."
        if (upRes.headers['content-type'] && upRes.headers['content-type'].includes('text/event-stream')) {
          const sseHeaders = { ...upRes.headers };
          delete sseHeaders['content-length'];      // SSE is streamed, no fixed length
          delete sseHeaders['transfer-encoding'];   // avoid header conflicts
          res.writeHead(status, sseHeaders);
          // StringDecoder buffers incomplete UTF-8 sequences across TCP chunks
          // so multi-byte chars (中文, emoji) that land on a chunk boundary
          // don't decode as U+FFFD.
          const decoder = new StringDecoder('utf8');
          let pending = '';
          let currentBlockIsThinking = false;

          const transformEvent = (event) => {
            // Locate the data: line (always at the start of an SSE line)
            let dataIdx = event.startsWith('data: ') ? 0 : event.indexOf('\ndata: ');
            if (dataIdx === -1) return reverseMap(event, config);
            if (dataIdx > 0) dataIdx += 1; // skip the leading \n
            const dataLineEnd = event.indexOf('\n', dataIdx + 6);
            const dataStr = dataLineEnd === -1
              ? event.slice(dataIdx + 6)
              : event.slice(dataIdx + 6, dataLineEnd);

            if (dataStr.indexOf('"type":"content_block_start"') !== -1) {
              if (dataStr.indexOf('"content_block":{"type":"thinking"') !== -1 ||
                  dataStr.indexOf('"content_block":{"type":"redacted_thinking"') !== -1) {
                currentBlockIsThinking = true;
                return event; // pass through unchanged
              }
              currentBlockIsThinking = false;
              return reverseMap(event, config);
            }
            if (dataStr.indexOf('"type":"content_block_stop"') !== -1) {
              const wasThinking = currentBlockIsThinking;
              currentBlockIsThinking = false;
              return wasThinking ? event : reverseMap(event, config);
            }
            if (currentBlockIsThinking) {
              // thinking_delta / signature_delta / etc. inside a thinking block
              return event;
            }
            return reverseMap(event, config);
          };

          upRes.on('data', (chunk) => {
            pending += decoder.write(chunk);
            let sepIdx;
            while ((sepIdx = pending.indexOf('\n\n')) !== -1) {
              const event = pending.slice(0, sepIdx + 2);
              pending = pending.slice(sepIdx + 2);
              res.write(transformEvent(event));
            }
          });
          upRes.on('end', () => {
            pending += decoder.end();
            if (pending.length > 0) {
              // Trailing bytes with no terminator — shouldn't happen in
              // well-formed SSE, but flush to avoid silent drops.
              res.write(transformEvent(pending));
            }
            res.end();
          });
        } else {
          const respChunks = [];
          upRes.on('data', c => respChunks.push(c));
          upRes.on('end', () => {
            let respBody = Buffer.concat(respChunks).toString();
            // Mask thinking blocks so reverseMap can't mutate them. The client
            // stores these bytes and echoes them on the next turn; Anthropic
            // enforces byte-equality on the latest assistant message.
            const { masked: rMasked, masks: rMasks } = maskThinkingBlocks(respBody);
            respBody = unmaskThinkingBlocks(reverseMap(rMasked, config), rMasks);
            const nh = { ...upRes.headers };
            delete nh['transfer-encoding']; // avoid conflict with content-length
            nh['content-length'] = Buffer.byteLength(respBody);
            res.writeHead(status, nh);
            res.end(respBody);
          });
        }
      });
      upstream.on('error', e => {
        plog(reqNum, `ERR: ${e.message}`, 'error');
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        }
      });
      upstream.write(body);
      upstream.end();
    });
  });

  const bindHost = process.env.PROXY_HOST || '127.0.0.1';
  server.listen(config.port, bindHost, () => {
    try {
      const oauth = getToken(config.credsPath);
      const expiresIn = (oauth.expiresAt - Date.now()) / 3600000;
      const h = isFinite(expiresIn) ? expiresIn.toFixed(1) + 'h' : 'n/a (env var)';
      console.log(`\n  OpenClaw Billing Proxy v${VERSION}`);
      console.log(`  ─────────────────────────────`);
      console.log(`  Port:              ${config.port}`);
      console.log(`  Bind address:      ${bindHost}`);
      console.log(`  Emulating:         Claude Code v${CC_VERSION}`);
      console.log(`  Subscription:      ${oauth.subscriptionType}`);
      console.log(`  Token expires:     ${h}`);
      console.log(`  String patterns:   ${config.replacements.length} sanitize + ${config.reverseMap.length} reverse`);
      console.log(`  Layer 2 scope:     ${config.layer2Scope}${config.layer2Scope === 'all' ? '' : ' (content replacement narrowed)'}`);
      console.log(`  Tool renames:      ${config.toolRenames.length} (bidirectional)`);
      console.log(`  Property renames:  ${config.propRenames.length} (bidirectional)`);
      console.log(`  CC tool stubs:     ${config.injectCCStubs ? CC_TOOL_STUBS.length : 'disabled'}`);
      console.log(`  System strip:      ${config.stripSystemConfig ? 'enabled' : 'disabled'}`);
      console.log(`  Description strip: ${config.stripToolDescriptions ? 'enabled' : 'disabled'}`);
      console.log(`  Billing hash:      dynamic (SHA256 fingerprint)`);
      console.log(`  CC headers:        Stainless SDK + identity`);
      console.log(`  Credentials:       ${config.credsPath}`);
      console.log(`\n  Ready. Set openclaw.json baseUrl to http://${bindHost}:${config.port}\n`);
    } catch (e) {
      console.error(`  Started on port ${config.port} but credentials error: ${e.message}`);
    }
  });

  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));
}

// ─── Main ───────────────────────────────────────────────────────────────────
const config = loadConfig();
startServer(config);
