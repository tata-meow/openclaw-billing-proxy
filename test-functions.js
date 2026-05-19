'use strict';
const assert = require('assert');
const crypto = require('crypto');

// --- Extract functions from proxy.js without starting the server ---
const proxySource = require('fs').readFileSync(require('path').join(__dirname, 'proxy.js'), 'utf8');
const wrappedSource = proxySource
  .replace(/^#!.*\n/, '')
  .replace(/^(const config = loadConfig\(\);)$/m, '// $1')
  .replace(/^(startServer\(config\);)$/m, '// $1');

const sandbox = {
  require, process, console,
  fetch: globalThis.fetch,
  __filename, __dirname,
  module: { exports: {} }, exports: {},
};

new Function(...Object.keys(sandbox),
  wrappedSource + `\n
  this._test = {
    computeCch, computeBillingFingerprint, extractFirstUserText,
    getModelBetas, findMatchingBrace, findMatchingBracket, stripEffortFromObject,
    repairToolPairs, stripThinkingBlocks, maskThinkingBlocks, unmaskThinkingBlocks, reverseMap,
    filterStubsAgainstExisting, protectPaths, restorePaths,
    CONTEXT_AWARE_RENAMES, DEFAULT_TOOL_RENAMES, DEFAULT_REVERSE_MAP, DEFAULT_PROP_RENAMES,
    CC_TOOL_STUBS, REQUIRED_BETAS,
  };
`).call(sandbox, ...Object.values(sandbox));

const T = sandbox._test;

// --- test helper ---
let passed = 0, failed = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`  PASS: ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL: ${name}`);
    if (e.expected !== undefined) console.log(`    Expected: ${JSON.stringify(e.expected)}`);
    if (e.actual !== undefined) console.log(`    Actual:   ${JSON.stringify(e.actual)}`);
    console.log(`    Error:    ${e.message}`);
    failed++;
  }
}

console.log('\n=== proxy.js Unit Tests (v2.4.0) ===\n');

// A. computeCch
console.log('--- computeCch ---');
test('returns 5-char hex', () => {
  const r = T.computeCch('hello');
  assert.strictEqual(r.length, 5);
  assert.match(r, /^[0-9a-f]{5}$/);
});
test('deterministic', () => {
  assert.strictEqual(T.computeCch('test'), T.computeCch('test'));
});
test('different inputs differ', () => {
  assert.notStrictEqual(T.computeCch('abc'), T.computeCch('xyz'));
});
test('empty string works', () => {
  assert.match(T.computeCch(''), /^[0-9a-f]{5}$/);
});

// B. computeBillingFingerprint
console.log('\n--- computeBillingFingerprint ---');
test('returns 3-char hex', () => {
  const r = T.computeBillingFingerprint('some text here for testing');
  assert.strictEqual(r.length, 3);
  assert.match(r, /^[0-9a-f]{3}$/);
});
test('deterministic', () => {
  assert.strictEqual(
    T.computeBillingFingerprint('hello world test'),
    T.computeBillingFingerprint('hello world test')
  );
});
test('short text uses 0 padding', () => {
  const r = T.computeBillingFingerprint('hi');
  assert.strictEqual(r.length, 3);
});

// C. extractFirstUserText
console.log('\n--- extractFirstUserText ---');
test('simple string content', () => {
  const body = JSON.stringify({ messages: [{ role: 'user', content: 'hello' }] });
  assert.strictEqual(T.extractFirstUserText(body), 'hello');
});
test('content array format', () => {
  const body = JSON.stringify({ messages: [
    { role: 'user', content: [{ type: 'text', text: 'from array' }] }
  ]});
  assert.strictEqual(T.extractFirstUserText(body), 'from array');
});
test('no user message returns empty', () => {
  const body = JSON.stringify({ messages: [{ role: 'assistant', content: 'reply' }] });
  assert.strictEqual(T.extractFirstUserText(body), '');
});
test('no messages key returns empty', () => {
  assert.strictEqual(T.extractFirstUserText('{"model":"claude"}'), '');
});
test('skips system to find user', () => {
  const body = JSON.stringify({ messages: [
    { role: 'system', content: 'sys' },
    { role: 'user', content: 'hi' }
  ]});
  assert.strictEqual(T.extractFirstUserText(body), 'hi');
});

// D. getModelBetas
console.log('\n--- getModelBetas ---');
test('haiku excludes interleaved-thinking', () => {
  const b = T.getModelBetas('claude-haiku-4-5');
  assert.ok(!b.includes('interleaved-thinking-2025-05-14'));
});
test('sonnet-4-6 includes effort', () => {
  assert.ok(T.getModelBetas('claude-sonnet-4-6').includes('effort-2025-11-24'));
});
test('sonnet-4-5 excludes effort', () => {
  assert.ok(!T.getModelBetas('claude-sonnet-4-5').includes('effort-2025-11-24'));
});
test('opus-4-6 includes effort', () => {
  assert.ok(T.getModelBetas('claude-opus-4-6').includes('effort-2025-11-24'));
});
test('all include oauth and claude-code betas', () => {
  for (const m of ['claude-haiku-4-5', 'claude-sonnet-4-6', 'claude-opus-4-6']) {
    const b = T.getModelBetas(m);
    assert.ok(b.includes('oauth-2025-04-20'), `${m} missing oauth`);
    assert.ok(b.includes('claude-code-20250219'), `${m} missing claude-code`);
  }
});
test('no fake betas', () => {
  for (const m of ['claude-haiku-4-5', 'claude-sonnet-4-6']) {
    const b = T.getModelBetas(m);
    assert.ok(!b.includes('advanced-tool-use-2025-11-20'));
    assert.ok(!b.includes('fast-mode-2026-02-01'));
  }
});

// E. stripEffortFromObject
console.log('\n--- stripEffortFromObject ---');
test('removes effort from output_config', () => {
  const input = '{"model":"claude-haiku","output_config":{"effort":"high","other":"value"}}';
  const r = T.stripEffortFromObject(input, 'output_config');
  assert.ok(!r.includes('"effort"'));
  assert.ok(r.includes('"other":"value"'));
});
test('removes effort from thinking', () => {
  const input = '{"thinking":{"effort":"high","type":"enabled"}}';
  const r = T.stripEffortFromObject(input, 'thinking');
  assert.ok(!r.includes('"effort"'));
  assert.ok(r.includes('"type":"enabled"'));
});
test('key not present returns original', () => {
  const input = '{"model":"claude-haiku"}';
  assert.strictEqual(T.stripEffortFromObject(input, 'output_config'), input);
});
test('effort-only object removed', () => {
  const input = '{"model":"claude-haiku","output_config":{"effort":"high"}}';
  const r = T.stripEffortFromObject(input, 'output_config');
  assert.ok(!r.includes('"effort"'));
  assert.ok(!r.includes('output_config'));
});
test('input without effort is unchanged', () => {
  const input = '{"output_config":{"max_tokens":1000}}';
  const r = T.stripEffortFromObject(input, 'output_config');
  assert.ok(r.includes('"max_tokens":1000'));
});

// F. repairToolPairs
console.log('\n--- repairToolPairs ---');
test('matched pair unchanged', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'assistant', content: [{ type: 'tool_use', id: 'tu_1', name: 'exec', input: {} }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'tu_1', content: 'ok' }] }
    ]
  });
  const r = T.repairToolPairs(body);
  assert.ok(r.includes('"tu_1"'));
});
test('orphaned tool_use removed', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'assistant', content: [{ type: 'tool_use', id: 'tu_orphan', name: 'exec', input: {} }] }
    ]
  });
  assert.ok(!T.repairToolPairs(body).includes('"tu_orphan"'));
});
test('orphaned tool_result removed', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'tu_missing', content: 'result' }] }
    ]
  });
  assert.ok(!T.repairToolPairs(body).includes('"tu_missing"'));
});
test('no messages key returns original', () => {
  const body = '{"model":"claude"}';
  assert.strictEqual(T.repairToolPairs(body), body);
});

// G. stripThinkingBlocks
console.log('\n--- stripThinkingBlocks ---');
test('strips thinking blocks from assistant messages', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'user', content: [{ type: 'text', text: 'hello' }] },
      { role: 'assistant', content: [
        { type: 'thinking', thinking: 'internal reasoning', signature: 'sig123' },
        { type: 'text', text: 'response' }
      ]}
    ]
  });
  const r = T.stripThinkingBlocks(body);
  assert.ok(!r.includes('"thinking"'), 'thinking block should be stripped');
  assert.ok(r.includes('"response"'), 'text block should remain');
});
test('strips redacted_thinking blocks', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'assistant', content: [
        { type: 'redacted_thinking', data: 'encrypted==' },
        { type: 'text', text: 'hi' }
      ]}
    ]
  });
  const r = T.stripThinkingBlocks(body);
  assert.ok(!r.includes('redacted_thinking'));
  assert.ok(r.includes('"hi"'));
});
test('leaves user messages untouched', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'user', content: [{ type: 'text', text: 'hello' }] }
    ]
  });
  const r = T.stripThinkingBlocks(body);
  assert.ok(r.includes('"hello"'));
});
test('no-op when no thinking blocks', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'assistant', content: [{ type: 'text', text: 'plain' }] }
    ]
  });
  assert.strictEqual(T.stripThinkingBlocks(body), body);
});
test('no messages key returns original', () => {
  const body = '{"model":"claude"}';
  assert.strictEqual(T.stripThinkingBlocks(body), body);
});

// H. maskThinkingBlocks / unmaskThinkingBlocks
console.log('\n--- maskThinkingBlocks ---');
test('round-trip preserves content', () => {
  const orig = 'before {"type":"thinking","thinking":"secret"} after';
  const { masked, masks } = T.maskThinkingBlocks(orig);
  assert.ok(!masked.includes('"thinking"'));
  assert.strictEqual(T.unmaskThinkingBlocks(masked, masks), orig);
});
test('no thinking blocks unchanged', () => {
  const input = '{"type":"text","text":"normal"}';
  const { masked, masks } = T.maskThinkingBlocks(input);
  assert.strictEqual(masked, input);
  assert.strictEqual(masks.length, 0);
});
test('redacted_thinking round-trip', () => {
  const orig = 'x {"type":"redacted_thinking","data":"enc=="} y';
  const { masked, masks } = T.maskThinkingBlocks(orig);
  assert.ok(!masked.includes('"redacted_thinking"'));
  assert.strictEqual(T.unmaskThinkingBlocks(masked, masks), orig);
});
test('multiple blocks round-trip', () => {
  const orig = '{"type":"thinking","t":"a"} mid {"type":"thinking","t":"b"}';
  const { masked, masks } = T.maskThinkingBlocks(orig);
  assert.strictEqual(masks.length, 2);
  assert.strictEqual(T.unmaskThinkingBlocks(masked, masks), orig);
});
test('handles re-serialized JSON with spaces', () => {
  const orig = '{"type" : "thinking", "thinking" : "content here"}';
  const { masked, masks } = T.maskThinkingBlocks(orig);
  assert.strictEqual(masks.length, 1);
  assert.strictEqual(T.unmaskThinkingBlocks(masked, masks), orig);
});

// H. reverseMap
console.log('\n--- reverseMap ---');
test('restores Bash to exec (CC-native, no mcp_ prefix)', () => {
  const config = { toolRenames: T.DEFAULT_TOOL_RENAMES, propRenames: [], reverseMap: [] };
  const input = '{"name":"Bash","input":{}}';
  const r = T.reverseMap(input, config);
  assert.ok(r.includes('"exec"'), `Expected "exec", got: ${r}`);
});
test('restores mcp_SendMessage to message', () => {
  const config = { toolRenames: T.DEFAULT_TOOL_RENAMES, propRenames: [], reverseMap: [] };
  const input = '{"name":"mcp_SendMessage"}';
  const r = T.reverseMap(input, config);
  assert.ok(r.includes('"message"'));
});
test('restores OCPlatform to OpenClaw', () => {
  const config = { toolRenames: [], propRenames: [], reverseMap: T.DEFAULT_REVERSE_MAP };
  assert.ok(T.reverseMap('OCPlatform is running', config).includes('OpenClaw'));
});
test('handles escaped quotes', () => {
  const config = { toolRenames: T.DEFAULT_TOOL_RENAMES, propRenames: [], reverseMap: [] };
  const input = '{"partial_json":"{\\"name\\":\\"Bash\\"}"}';
  const r = T.reverseMap(input, config);
  assert.ok(r.includes('\\"exec\\"'));
});
test('empty input unchanged', () => {
  const config = { toolRenames: T.DEFAULT_TOOL_RENAMES, propRenames: [], reverseMap: T.DEFAULT_REVERSE_MAP };
  assert.strictEqual(T.reverseMap('', config), '');
});

// I. Context-aware renames
console.log('\n--- Context-aware renames ---');
test('message is in CONTEXT_AWARE_RENAMES set', () => {
  assert.ok(T.CONTEXT_AWARE_RENAMES.has('message'));
});
test('exec is NOT in CONTEXT_AWARE_RENAMES (global rename)', () => {
  assert.ok(!T.CONTEXT_AWARE_RENAMES.has('exec'));
});

// J. Tool rename structure
console.log('\n--- Tool rename structure ---');
test('exec -> Bash (CC-native, no mcp_ prefix)', () => {
  const entry = T.DEFAULT_TOOL_RENAMES.find(([o]) => o === 'exec');
  assert.ok(entry);
  assert.strictEqual(entry[1], 'Bash');
});
test('nodes -> DeviceControl (CC-native, no mcp_ prefix)', () => {
  const entry = T.DEFAULT_TOOL_RENAMES.find(([o]) => o === 'nodes');
  assert.ok(entry);
  assert.strictEqual(entry[1], 'DeviceControl');
});
test('message -> mcp_SendMessage (non-CC, mcp_ prefix)', () => {
  const entry = T.DEFAULT_TOOL_RENAMES.find(([o]) => o === 'message');
  assert.ok(entry);
  assert.strictEqual(entry[1], 'mcp_SendMessage');
});
test('web_search and web_fetch are NOT in tool renames', () => {
  assert.ok(!T.DEFAULT_TOOL_RENAMES.find(([o]) => o === 'web_search'));
  assert.ok(!T.DEFAULT_TOOL_RENAMES.find(([o]) => o === 'web_fetch'));
});

// K. filterStubsAgainstExisting
console.log('\n--- filterStubsAgainstExisting ---');
test('filters out duplicate tool names', () => {
  const stubs = [
    '{"name":"Glob","description":"test"}',
    '{"name":"NewTool","description":"new"}'
  ];
  const existingTools = '"tools":[{"name":"Glob","input_schema":{}}]';
  const result = T.filterStubsAgainstExisting(stubs, existingTools);
  assert.strictEqual(result.length, 1);
  assert.ok(result[0].includes('NewTool'));
});
test('case-insensitive dedup', () => {
  const stubs = ['{"name":"Grep","description":"test"}'];
  const existingTools = '"name":"grep"';
  assert.strictEqual(T.filterStubsAgainstExisting(stubs, existingTools).length, 0);
});

// L. Filesystem path protection
console.log('\n--- protectPaths / restorePaths ---');
test('round-trip preserves paths', () => {
  const input = 'text /home/user/.openclaw/file.png more';
  const { result, saved } = T.protectPaths(input);
  assert.ok(!result.includes('/home/user'));
  assert.strictEqual(T.restorePaths(result, saved), input);
});

// M. findMatchingBrace / findMatchingBracket
console.log('\n--- findMatchingBrace / findMatchingBracket ---');
test('findMatchingBrace: simple object', () => {
  assert.strictEqual(T.findMatchingBrace('{"a":1}', 0), 6);
});
test('findMatchingBrace: nested', () => {
  // '{"a":{"b":2}}' has length 14, closing brace at index 13
  // Actually: { at 0, { at 5, } at 10, } at 12... let's check
  // {"a":{"b":2}}
  // 0123456789012
  //              ^ index 12 is the outer closing brace (length 13 string, 0-12)
  assert.strictEqual(T.findMatchingBrace('{"a":{"b":2}}', 0), 12);
});
test('findMatchingBrace: skips strings', () => {
  assert.strictEqual(T.findMatchingBrace('{"a":"{not a brace}"}', 0), 20);
});
test('findMatchingBracket: simple array', () => {
  assert.strictEqual(T.findMatchingBracket('[1,2]', 0), 4);
});
test('findMatchingBracket: nested', () => {
  assert.strictEqual(T.findMatchingBracket('[[1],[2]]', 0), 8);
});

// --- summary ---
console.log(`\nResults: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
if (failed > 0) process.exit(1);
