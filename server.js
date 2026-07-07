// pulsefy.tools v3 — multi-tenant
'use strict';
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const url = require('node:url');
const crypto = require('node:crypto');
const { execSync } = require('node:child_process');

const PORT = 8093;
const EVENTS_DB = '/root/.friday-asa/asa.db';
const ROOT = '/opt/pulsefy';
const STATE_DIR = ROOT + '/state';
const CONFIG_DIR = ROOT + '/config';
const PUBLIC_DIR = ROOT + '/public';
const PULSEFY_DB = STATE_DIR + '/pulsefy.db';
const RULES_FILE = CONFIG_DIR + '/rules.json';
const INTEGRATIONS_FILE = CONFIG_DIR + '/integrations.json';
const ALARMS_LOG = STATE_DIR + '/alarms.jsonl';
const DEDUP_FILE = STATE_DIR + '/dedup.json';
const PW_SALT = 'pulsefy-2026-alarms';

function ensureDir(d) { try { fs.mkdirSync(d, { recursive: true }); } catch (e) {} }
ensureDir(STATE_DIR); ensureDir(CONFIG_DIR); ensureDir(PUBLIC_DIR);

function readJson(p, dflt) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return dflt; } }
function writeJson(p, obj) { fs.writeFileSync(p, JSON.stringify(obj, null, 2)); }

function sqliteQuery(dbPath, sql) {
  const q = '/tmp/pulsefy_q_' + process.pid + '_' + Date.now() + Math.random() + '.sql';
  fs.writeFileSync(q, sql);
  try {
    const out = execSync(`sqlite3 -header -json ${dbPath} < ${q}`, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    fs.unlinkSync(q);
    return out ? JSON.parse(out) : [];
  } catch (e) {
    try { fs.unlinkSync(q); } catch {}
    console.error('[sqlite]', dbPath, e.message);
    return [];
  }
}

function sqliteExec(dbPath, sql) {
  const q = '/tmp/pulsefy_exec_' + process.pid + '_' + Date.now() + Math.random() + '.sql';
  fs.writeFileSync(q, sql);
  try {
    execSync(`sqlite3 ${dbPath} < ${q}`, { encoding: 'utf8' });
    fs.unlinkSync(q);
    return true;
  } catch (e) {
    try { fs.unlinkSync(q); } catch {}
    console.error('[sqlite-exec]', dbPath, e.message);
    return false;
  }
}

// Bootstrap pulsefy DB
sqliteExec(PULSEFY_DB, `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  created_at TEXT NOT NULL,
  last_login TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS apps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  asa_account_id INTEGER NOT NULL,
  display_name TEXT NOT NULL,
  app_token TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(user_id, asa_account_id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_apps_user ON apps(user_id);
CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT, description TEXT, events TEXT, app_versions TEXT, filter_props TEXT,
  window_min INTEGER, threshold INTEGER, severity TEXT, channels TEXT, cooldown_min INTEGER,
  message_template TEXT, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS integrations (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  telegram TEXT NOT NULL DEFAULT '{}', slack TEXT NOT NULL DEFAULT '{}', webhook TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alarms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rule_id TEXT, rule_name TEXT, severity TEXT, message TEXT, count INTEGER, window_min INTEGER,
  last_error TEXT, fired_at TEXT NOT NULL, channels TEXT, sample_events TEXT
);
CREATE INDEX IF NOT EXISTS idx_rules_user ON rules(user_id);
CREATE INDEX IF NOT EXISTS idx_alarms_user ON alarms(user_id);
CREATE INDEX IF NOT EXISTS idx_alarms_fired ON alarms(fired_at);
`);

function hashPassword(pw) { return crypto.createHash('sha256').update(pw + PW_SALT).digest('hex'); }
function makeToken() { return crypto.randomBytes(24).toString('hex'); }
function sqlEscape(s) { return String(s).replace(/'/g, "''"); }

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  const parts = raw.split(';').map(s => s.trim());
  for (const p of parts) {
    const i = p.indexOf('=');
    if (i > 0 && p.slice(0, i) === name) return decodeURIComponent(p.slice(i + 1));
  }
  return null;
}

function getUser(req) {
  const tok = getCookie(req, 'pulsefy_session');
  if (!tok) return null;
  const rows = sqliteQuery(PULSEFY_DB, `SELECT u.id, u.email, u.name FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = '${sqlEscape(tok)}' AND s.expires_at > datetime('now') LIMIT 1;`);
  return rows[0] || null;
}

function getUserApps(userId) {
  return sqliteQuery(PULSEFY_DB, `SELECT id, asa_account_id, display_name, app_token, created_at FROM apps WHERE user_id = ${parseInt(userId, 10)} ORDER BY id DESC;`);
}

function getUserAccountIds(userId) {
  const apps = getUserApps(userId);
  return apps.map(a => a.asa_account_id);
}

function sendJson(res, code, obj, extra) {
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, extra || {}));
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve) => {
    let d = ''; req.on('data', c => d += c); req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch { resolve({}); } });
  });
}

function serveStatic(res, filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.isFile()) {
      const ext = path.extname(filePath).slice(1);
      const mime = { html: 'text/html', css: 'text/css', js: 'application/javascript', json: 'application/json', svg: 'image/svg+xml', png: 'image/png' }[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': ext === 'html' ? 'no-store' : 'max-age=3600' });
      res.end(fs.readFileSync(filePath));
      return true;
    }
  } catch {}
  return false;
}

// ---------- default configs ----------

const DEFAULT_RULES = [
  { id: 'purchase-fail-critical', enabled: true, name: 'Purchase fail spike (critical)', description: 'StoreKit / RC purchase failure retry loop detection', events: ['subscribe_fail'], app_versions: [], filter_props: {}, window_min: 10, threshold: 3, severity: 'red', channels: ['telegram'], cooldown_min: 30, message_template: '🔴 {count} subscribe_fail in {window}m. Last error: "{last_error}"', created_at: new Date().toISOString() },
  { id: 'paywall-offerings-error', enabled: true, name: 'Paywall offerings load error', description: 'RC offerings config broken', events: ['paywall_offerings_error'], app_versions: [], filter_props: {}, window_min: 15, threshold: 1, severity: 'red', channels: ['telegram'], cooldown_min: 60, message_template: '🔴 paywall_offerings_error — RC config broken. Error: "{last_error}"', created_at: new Date().toISOString() },
];
const DEFAULT_INTEGRATIONS = { telegram: { enabled: false, bot_token: '', chat_id: '' }, slack: { enabled: false, webhook_url: '' }, webhook: { enabled: false, url: '' } };

function loadDedup() { return readJson(DEDUP_FILE, {}); }
function saveDedup(d) { writeJson(DEDUP_FILE, d); }

// ---------- per-user rules / integrations / alarms (SQLite-backed) ----------

function rowToRule(r) {
  return {
    id: r.id, user_id: r.user_id, name: r.name, description: r.description,
    events: JSON.parse(r.events || '[]'), app_versions: JSON.parse(r.app_versions || '[]'),
    filter_props: JSON.parse(r.filter_props || '{}'), window_min: r.window_min, threshold: r.threshold,
    severity: r.severity, channels: JSON.parse(r.channels || '[]'), cooldown_min: r.cooldown_min,
    message_template: r.message_template, enabled: !!r.enabled, created_at: r.created_at,
  };
}
function getUserRules(userId) {
  return sqliteQuery(PULSEFY_DB, `SELECT * FROM rules WHERE user_id = ${parseInt(userId, 10)} ORDER BY created_at DESC;`).map(rowToRule);
}
function getAllEnabledRules() {
  return sqliteQuery(PULSEFY_DB, `SELECT * FROM rules WHERE enabled = 1;`).map(rowToRule);
}
function insertRule(userId, body) {
  const id = 'rule-' + crypto.randomBytes(8).toString('hex');
  const now = new Date().toISOString();
  sqliteExec(PULSEFY_DB, `INSERT INTO rules(id, user_id, name, description, events, app_versions, filter_props, window_min, threshold, severity, channels, cooldown_min, message_template, enabled, created_at) VALUES(
    '${sqlEscape(id)}', ${parseInt(userId, 10)}, '${sqlEscape(body.name || '')}', '${sqlEscape(body.description || '')}',
    '${sqlEscape(JSON.stringify(body.events || []))}', '${sqlEscape(JSON.stringify(body.app_versions || []))}', '${sqlEscape(JSON.stringify(body.filter_props || {}))}',
    ${parseInt(body.window_min, 10) || 15}, ${parseInt(body.threshold, 10) || 1}, '${sqlEscape(body.severity || 'yellow')}',
    '${sqlEscape(JSON.stringify(body.channels || []))}', ${parseInt(body.cooldown_min, 10) || 30}, '${sqlEscape(body.message_template || '')}',
    ${body.enabled === false ? 0 : 1}, '${now}');`);
  return sqliteQuery(PULSEFY_DB, `SELECT * FROM rules WHERE id = '${sqlEscape(id)}' LIMIT 1;`).map(rowToRule)[0];
}
function updateRule(userId, id, body) {
  const owned = sqliteQuery(PULSEFY_DB, `SELECT * FROM rules WHERE id = '${sqlEscape(id)}' AND user_id = ${parseInt(userId, 10)} LIMIT 1;`)[0];
  if (!owned) return null;
  const cur = rowToRule(owned);
  const merged = Object.assign({}, cur, body, { id: cur.id, user_id: cur.user_id });
  sqliteExec(PULSEFY_DB, `UPDATE rules SET name='${sqlEscape(merged.name || '')}', description='${sqlEscape(merged.description || '')}',
    events='${sqlEscape(JSON.stringify(merged.events || []))}', app_versions='${sqlEscape(JSON.stringify(merged.app_versions || []))}',
    filter_props='${sqlEscape(JSON.stringify(merged.filter_props || {}))}', window_min=${parseInt(merged.window_min, 10) || 15},
    threshold=${parseInt(merged.threshold, 10) || 1}, severity='${sqlEscape(merged.severity || 'yellow')}',
    channels='${sqlEscape(JSON.stringify(merged.channels || []))}', cooldown_min=${parseInt(merged.cooldown_min, 10) || 30},
    message_template='${sqlEscape(merged.message_template || '')}', enabled=${merged.enabled === false ? 0 : 1}
    WHERE id='${sqlEscape(id)}' AND user_id=${parseInt(userId, 10)};`);
  return sqliteQuery(PULSEFY_DB, `SELECT * FROM rules WHERE id = '${sqlEscape(id)}' LIMIT 1;`).map(rowToRule)[0];
}
function deleteRule(userId, id) {
  sqliteExec(PULSEFY_DB, `DELETE FROM rules WHERE id = '${sqlEscape(id)}' AND user_id = ${parseInt(userId, 10)};`);
}
function seedDefaultRulesForUser(userId) {
  for (const r of DEFAULT_RULES) insertRule(userId, r);
}

function rowToIntegrations(r) {
  if (!r) return JSON.parse(JSON.stringify(DEFAULT_INTEGRATIONS));
  try { return { telegram: JSON.parse(r.telegram || '{}'), slack: JSON.parse(r.slack || '{}'), webhook: JSON.parse(r.webhook || '{}') }; }
  catch { return JSON.parse(JSON.stringify(DEFAULT_INTEGRATIONS)); }
}
function getUserIntegrations(userId) {
  const row = sqliteQuery(PULSEFY_DB, `SELECT * FROM integrations WHERE user_id = ${parseInt(userId, 10)} LIMIT 1;`)[0];
  return rowToIntegrations(row);
}
function saveUserIntegrations(userId, obj) {
  const now = new Date().toISOString();
  const merged = Object.assign({}, DEFAULT_INTEGRATIONS, obj);
  sqliteExec(PULSEFY_DB, `INSERT INTO integrations(user_id, telegram, slack, webhook, updated_at) VALUES(${parseInt(userId, 10)}, '${sqlEscape(JSON.stringify(merged.telegram || {}))}', '${sqlEscape(JSON.stringify(merged.slack || {}))}', '${sqlEscape(JSON.stringify(merged.webhook || {}))}', '${now}')
    ON CONFLICT(user_id) DO UPDATE SET telegram=excluded.telegram, slack=excluded.slack, webhook=excluded.webhook, updated_at=excluded.updated_at;`);
  return merged;
}
function seedDefaultIntegrationsForUser(userId) {
  saveUserIntegrations(userId, DEFAULT_INTEGRATIONS);
}

function insertAlarm(userId, alarm) {
  sqliteExec(PULSEFY_DB, `INSERT INTO alarms(user_id, rule_id, rule_name, severity, message, count, window_min, last_error, fired_at, channels, sample_events) VALUES(
    ${parseInt(userId, 10)}, '${sqlEscape(alarm.rule_id)}', '${sqlEscape(alarm.rule_name)}', '${sqlEscape(alarm.severity)}', '${sqlEscape(alarm.message)}',
    ${parseInt(alarm.count, 10) || 0}, ${parseInt(alarm.window_min, 10) || 0}, '${sqlEscape(alarm.last_error || '')}', '${alarm.fired_at}',
    '${sqlEscape(JSON.stringify(alarm.channels || []))}', '${sqlEscape(JSON.stringify(alarm.sample_events || []))}');`);
}
function getUserAlarms(userId, limit) {
  const rows = sqliteQuery(PULSEFY_DB, `SELECT * FROM alarms WHERE user_id = ${parseInt(userId, 10)} ORDER BY id DESC LIMIT ${parseInt(limit, 10) || 100};`);
  return rows.map(r => ({ rule_id: r.rule_id, rule_name: r.rule_name, severity: r.severity, message: r.message, count: r.count, window_min: r.window_min, last_error: r.last_error, fired_at: r.fired_at, channels: JSON.parse(r.channels || '[]'), sample_events: JSON.parse(r.sample_events || '[]') }));
}

// One-time migration: legacy global config/rules.json + integrations.json → earliest user's own rows
function migrateLegacyGlobalConfig() {
  const anyRules = sqliteQuery(PULSEFY_DB, `SELECT COUNT(*) as n FROM rules;`)[0];
  if (anyRules && anyRules.n > 0) return;
  const firstUser = sqliteQuery(PULSEFY_DB, `SELECT id FROM users ORDER BY id ASC LIMIT 1;`)[0];
  if (!firstUser) return;
  const legacyRules = readJson(RULES_FILE, null);
  if (legacyRules && legacyRules.length) { for (const r of legacyRules) insertRule(firstUser.id, r); }
  const legacyIntegrations = readJson(INTEGRATIONS_FILE, null);
  if (legacyIntegrations) saveUserIntegrations(firstUser.id, legacyIntegrations);
}
migrateLegacyGlobalConfig();

// ---------- rule engine (per-user: each rule scoped to its owner's claimed apps) ----------

function evaluateRules() {
  const rules = getAllEnabledRules();
  const dedup = loadDedup();
  const now = Date.now();
  const integrationsCache = new Map();
  const accountIdsCache = new Map();
  for (const rule of rules) {
    if (!accountIdsCache.has(rule.user_id)) accountIdsCache.set(rule.user_id, getUserAccountIds(rule.user_id));
    const acctIds = accountIdsCache.get(rule.user_id);
    if (!acctIds.length) continue; // owner has no claimed apps — nothing to scan
    const windowStart = new Date(now - rule.window_min * 60 * 1000).toISOString();
    const eventList = rule.events.map(e => `'${sqlEscape(e)}'`).join(',');
    if (!eventList) continue;
    let sql = `SELECT created_at, user_id, name, props, app_version, bundle_id FROM events WHERE name IN (${eventList}) AND created_at >= '${windowStart}' AND account_id IN (${acctIds.join(',')})`;
    if (rule.app_versions && rule.app_versions.length) {
      const versList = rule.app_versions.map(v => `'${sqlEscape(v)}'`).join(',');
      sql += ` AND app_version IN (${versList})`;
    }
    sql += ` ORDER BY created_at DESC LIMIT 200;`;
    let rows = sqliteQuery(EVENTS_DB, sql);
    if (rule.filter_props && rule.filter_props.error_contains) {
      const needle = String(rule.filter_props.error_contains).toLowerCase();
      rows = rows.filter(r => { try { const p = JSON.parse(r.props || '{}'); return String(p.error || '').toLowerCase().includes(needle); } catch { return false; } });
    }
    if (rows.length >= rule.threshold) {
      let lastError = ''; let apps = new Set();
      try { for (const r of rows) { const p = JSON.parse(r.props || '{}'); if (!lastError && p.error) lastError = String(p.error).slice(0, 200); if (r.bundle_id) apps.add(r.bundle_id); } } catch {}
      const sig = rule.id + ':' + lastError.slice(0, 60);
      if (now - (dedup[sig] || 0) < rule.cooldown_min * 60 * 1000) continue;
      const message = (rule.message_template || 'Alarm: {count} events in {window}m').replace('{count}', rows.length).replace('{window}', rule.window_min).replace('{last_error}', lastError || 'n/a').replace('{apps}', Array.from(apps).join(',') || 'n/a');
      const alarm = { rule_id: rule.id, rule_name: rule.name, severity: rule.severity, message, count: rows.length, window_min: rule.window_min, last_error: lastError, fired_at: new Date(now).toISOString(), channels: rule.channels, sample_events: rows.slice(0, 5).map(r => ({ time: r.created_at, user: r.user_id, name: r.name, app_version: r.app_version })) };
      dedup[sig] = now;
      if (!integrationsCache.has(rule.user_id)) integrationsCache.set(rule.user_id, getUserIntegrations(rule.user_id));
      const integrations = integrationsCache.get(rule.user_id);
      for (const ch of rule.channels) {
        if (ch === 'telegram') fireTelegram(integrations.telegram, alarm);
        else if (ch === 'slack') fireSlack(integrations.slack, alarm);
        else if (ch === 'webhook') fireWebhook(integrations.webhook, alarm);
      }
      insertAlarm(rule.user_id, alarm);
    }
  }
  saveDedup(dedup);
}
function fireTelegram(cfg, alarm) { if (!cfg || !cfg.enabled || !cfg.bot_token || !cfg.chat_id) return; const text = `*[pulsefy]* ${alarm.rule_name}\n${alarm.message}`; const body = JSON.stringify({ chat_id: cfg.chat_id, text, parse_mode: 'Markdown' }); const req = https.request(`https://api.telegram.org/bot${cfg.bot_token}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => { if (res.statusCode !== 200) console.error('[telegram]', res.statusCode, d.slice(0, 200)); }); }); req.on('error', e => console.error('[telegram] err', e.message)); req.write(body); req.end(); }
function fireSlack(cfg, alarm) { if (!cfg || !cfg.enabled || !cfg.webhook_url) return; const color = alarm.severity === 'red' ? '#d92222' : alarm.severity === 'yellow' ? '#d9822b' : '#3ba55c'; const body = JSON.stringify({ attachments: [{ color, title: `[pulsefy] ${alarm.rule_name}`, text: alarm.message, ts: Math.floor(Date.now() / 1000) }] }); const u = new URL(cfg.webhook_url); const req = https.request({ host: u.host, path: u.pathname + u.search, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => { if (res.statusCode >= 300) console.error('[slack]', res.statusCode, d.slice(0, 200)); }); }); req.on('error', e => console.error('[slack] err', e.message)); req.write(body); req.end(); }
function fireWebhook(cfg, alarm) { if (!cfg || !cfg.enabled || !cfg.url) return; const body = JSON.stringify(alarm); const u = new URL(cfg.url); const lib = u.protocol === 'https:' ? https : http; const req = lib.request({ host: u.host, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => { if (res.statusCode >= 300) console.error('[webhook]', res.statusCode); }); }); req.on('error', e => console.error('[webhook] err', e.message)); req.write(body); req.end(); }

// SSE — per-user filtering
const SSE_CLIENTS = new Map(); // res -> {userId, accountIds}
function broadcastSSE(event) {
  for (const [c, meta] of SSE_CLIENTS) {
    if (meta.accountIds.length === 0) continue;
    if (!meta.accountIds.includes(event.account_id)) continue;
    try { c.write('data: ' + JSON.stringify(event) + '\n\n'); } catch {}
  }
}
let lastLiveEventId = 0;
function pollLiveEvents() {
  const rows = sqliteQuery(EVENTS_DB, `SELECT id, account_id, created_at, user_id, name, props, app_version, bundle_id, country FROM events WHERE id > ${lastLiveEventId} ORDER BY id ASC LIMIT 200;`);
  for (const r of rows) {
    lastLiveEventId = Math.max(lastLiveEventId, r.id);
    if (SSE_CLIENTS.size > 0) broadcastSSE(r);
  }
}
function initLastEventId() {
  const rows = sqliteQuery(EVENTS_DB, `SELECT MAX(id) as maxid FROM events;`);
  if (rows[0] && rows[0].maxid) lastLiveEventId = rows[0].maxid;
}

// ---------- HTTP ----------
const server = http.createServer(async (req, res) => {
  const u = url.parse(req.url, true);
  const p = u.pathname;
  const method = req.method;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ============ AUTH ============
  if (p === '/api/auth/register' && method === 'POST') {
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const name = String(body.name || '').trim();
    if (!email.match(/^[^@\s]+@[^@\s]+\.[^@\s]+$/)) return sendJson(res, 400, { ok: false, error: 'Geçersiz email' });
    if (password.length < 6) return sendJson(res, 400, { ok: false, error: 'Şifre en az 6 karakter olmalı' });
    const existing = sqliteQuery(PULSEFY_DB, `SELECT id FROM users WHERE email = '${sqlEscape(email)}' LIMIT 1;`);
    if (existing.length) return sendJson(res, 400, { ok: false, error: 'Bu email zaten kayıtlı' });
    const hash = hashPassword(password);
    const now = new Date().toISOString();
    sqliteExec(PULSEFY_DB, `INSERT INTO users(email, password_hash, name, created_at, last_login) VALUES('${sqlEscape(email)}', '${sqlEscape(hash)}', '${sqlEscape(name)}', '${now}', '${now}');`);
    const user = sqliteQuery(PULSEFY_DB, `SELECT id FROM users WHERE email = '${sqlEscape(email)}' LIMIT 1;`)[0];
    const token = makeToken();
    const expires = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
    sqliteExec(PULSEFY_DB, `INSERT INTO sessions(token, user_id, created_at, expires_at) VALUES('${token}', ${user.id}, '${now}', '${expires}');`);
    seedDefaultRulesForUser(user.id);
    seedDefaultIntegrationsForUser(user.id);
    res.setHeader('Set-Cookie', `pulsefy_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${30 * 24 * 3600}`);
    return sendJson(res, 200, { ok: true, user: { id: user.id, email, name } });
  }

  if (p === '/api/auth/login' && method === 'POST') {
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const rows = sqliteQuery(PULSEFY_DB, `SELECT id, email, name FROM users WHERE email = '${sqlEscape(email)}' AND password_hash = '${sqlEscape(hashPassword(password))}' LIMIT 1;`);
    if (!rows.length) return sendJson(res, 401, { ok: false, error: 'Email veya şifre hatalı' });
    const now = new Date().toISOString();
    const token = makeToken();
    const expires = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
    sqliteExec(PULSEFY_DB, `INSERT INTO sessions(token, user_id, created_at, expires_at) VALUES('${token}', ${rows[0].id}, '${now}', '${expires}'); UPDATE users SET last_login = '${now}' WHERE id = ${rows[0].id};`);
    res.setHeader('Set-Cookie', `pulsefy_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${30 * 24 * 3600}`);
    return sendJson(res, 200, { ok: true, user: rows[0] });
  }

  if (p === '/api/auth/logout' && method === 'POST') {
    const tok = getCookie(req, 'pulsefy_session');
    if (tok) sqliteExec(PULSEFY_DB, `DELETE FROM sessions WHERE token = '${sqlEscape(tok)}';`);
    res.setHeader('Set-Cookie', 'pulsefy_session=; Path=/; HttpOnly; Max-Age=0');
    return sendJson(res, 200, { ok: true });
  }

  if (p === '/api/auth/me' && method === 'GET') {
    const user = getUser(req);
    if (!user) return sendJson(res, 401, { ok: false });
    const apps = getUserApps(user.id);
    return sendJson(res, 200, { ok: true, user, apps });
  }

  // ============ APPS management ============
  if (p === '/api/apps' && method === 'GET') {
    const user = getUser(req);
    if (!user) return sendJson(res, 401, { ok: false });
    return sendJson(res, 200, { ok: true, apps: getUserApps(user.id) });
  }

  if (p === '/api/apps' && method === 'POST') {
    const user = getUser(req);
    if (!user) return sendJson(res, 401, { ok: false });
    const body = await readBody(req);
    const appToken = String(body.app_token || '').trim();
    const displayName = String(body.display_name || '').trim();
    if (!appToken || !displayName) return sendJson(res, 400, { ok: false, error: 'app_token ve display_name zorunlu' });
    // Verify app_token exists in asa_accounts
    const acct = sqliteQuery(EVENTS_DB, `SELECT id, label, org_name FROM asa_accounts WHERE app_token = '${sqlEscape(appToken)}' LIMIT 1;`);
    if (!acct.length) return sendJson(res, 400, { ok: false, error: 'Geçersiz app token — bu token için kayıt yok' });
    // Check if this user already claimed this app
    const existing = sqliteQuery(PULSEFY_DB, `SELECT id FROM apps WHERE user_id = ${user.id} AND asa_account_id = ${acct[0].id} LIMIT 1;`);
    if (existing.length) return sendJson(res, 400, { ok: false, error: 'Bu app zaten hesabına eklenmiş' });
    // Check if another user already claimed
    const otherClaim = sqliteQuery(PULSEFY_DB, `SELECT user_id FROM apps WHERE asa_account_id = ${acct[0].id} LIMIT 1;`);
    if (otherClaim.length && otherClaim[0].user_id !== user.id) {
      return sendJson(res, 400, { ok: false, error: 'Bu app başka bir hesaba bağlanmış — token sahibiyseniz support ile iletişime geçin' });
    }
    const now = new Date().toISOString();
    sqliteExec(PULSEFY_DB, `INSERT INTO apps(user_id, asa_account_id, display_name, app_token, created_at) VALUES(${user.id}, ${acct[0].id}, '${sqlEscape(displayName)}', '${sqlEscape(appToken)}', '${now}');`);
    return sendJson(res, 200, { ok: true, app: { asa_account_id: acct[0].id, display_name: displayName, app_token: appToken, orig_label: acct[0].label, org_name: acct[0].org_name } });
  }

  const appIdMatch = p.match(/^\/api\/apps\/(\d+)$/);
  if (appIdMatch && method === 'DELETE') {
    const user = getUser(req);
    if (!user) return sendJson(res, 401, { ok: false });
    sqliteExec(PULSEFY_DB, `DELETE FROM apps WHERE id = ${parseInt(appIdMatch[1], 10)} AND user_id = ${user.id};`);
    return sendJson(res, 200, { ok: true });
  }

  // ============ Events (all filtered by user's apps) ============
  const needsAuth = p.startsWith('/api/') && !p.startsWith('/api/auth/');
  if (needsAuth) {
    const user = getUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'auth required' });
    req._user = user;
    req._accountIds = getUserAccountIds(user.id);
  }

  if (p === '/api/events' && method === 'GET') {
    if (req._accountIds.length === 0) return sendJson(res, 200, { ok: true, rows: [], sinceMin: 0, no_apps: true });
    const limit = Math.min(parseInt(u.query.limit || '100', 10), 500);
    const filterName = u.query.name || '';
    const filterVersion = u.query.app_version || '';
    const filterUser = u.query.user_id || '';
    const sinceMin = parseInt(u.query.since_min || '1440', 10);
    const since = new Date(Date.now() - sinceMin * 60 * 1000).toISOString();
    const acctList = req._accountIds.join(',');
    let where = [`created_at >= '${since}'`, `account_id IN (${acctList})`];
    if (filterName) where.push(`name = '${sqlEscape(filterName)}'`);
    if (filterVersion) where.push(`app_version = '${sqlEscape(filterVersion)}'`);
    if (filterUser) where.push(`user_id LIKE '%${sqlEscape(filterUser)}%'`);
    const sql = `SELECT id, created_at, user_id, name, props, app_version, bundle_id, country FROM events WHERE ${where.join(' AND ')} ORDER BY id DESC LIMIT ${limit};`;
    return sendJson(res, 200, { ok: true, rows: sqliteQuery(EVENTS_DB, sql), sinceMin });
  }

  if (p === '/api/events/live' && method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', 'Connection': 'keep-alive' });
    res.write(': connected\n\n');
    SSE_CLIENTS.set(res, { userId: req._user.id, accountIds: req._accountIds });
    req.on('close', () => SSE_CLIENTS.delete(res));
    return;
  }

  if (p === '/api/events/summary' && method === 'GET') {
    if (req._accountIds.length === 0) return sendJson(res, 200, { ok: true, rows: [], sinceMin: 0, no_apps: true });
    const sinceMin = parseInt(u.query.since_min || '1440', 10);
    const since = new Date(Date.now() - sinceMin * 60 * 1000).toISOString();
    const acctList = req._accountIds.join(',');
    const rows = sqliteQuery(EVENTS_DB, `SELECT name, COUNT(*) as n, COUNT(DISTINCT user_id) as users FROM events WHERE created_at >= '${since}' AND account_id IN (${acctList}) GROUP BY name ORDER BY n DESC;`);
    return sendJson(res, 200, { ok: true, rows, sinceMin });
  }

  if (p === '/api/rules' && method === 'GET') return sendJson(res, 200, { ok: true, rules: getUserRules(req._user.id) });
  if (p === '/api/rules' && method === 'POST') {
    const body = await readBody(req);
    const rule = insertRule(req._user.id, body);
    return sendJson(res, 200, { ok: true, rule });
  }
  const ruleIdMatch = p.match(/^\/api\/rules\/([^\/]+)$/);
  if (ruleIdMatch && method === 'PUT') {
    const body = await readBody(req);
    const rule = updateRule(req._user.id, ruleIdMatch[1], body);
    if (!rule) return sendJson(res, 404, { ok: false, error: 'not found' });
    return sendJson(res, 200, { ok: true, rule });
  }
  if (ruleIdMatch && method === 'DELETE') {
    deleteRule(req._user.id, ruleIdMatch[1]);
    return sendJson(res, 200, { ok: true });
  }

  if (p === '/api/integrations' && method === 'GET') return sendJson(res, 200, { ok: true, integrations: getUserIntegrations(req._user.id) });
  if (p === '/api/integrations' && method === 'PUT') {
    const body = await readBody(req);
    const integrations = saveUserIntegrations(req._user.id, body);
    return sendJson(res, 200, { ok: true, integrations });
  }
  if (p === '/api/integrations/test' && method === 'POST') {
    const body = await readBody(req);
    const cfg = getUserIntegrations(req._user.id);
    const testAlarm = { rule_name: 'Test integration', severity: 'green', message: 'pulsefy.tools test mesajı', fired_at: new Date().toISOString() };
    if (body.channel === 'telegram') fireTelegram(cfg.telegram, testAlarm);
    else if (body.channel === 'slack') fireSlack(cfg.slack, testAlarm);
    else if (body.channel === 'webhook') fireWebhook(cfg.webhook, testAlarm);
    return sendJson(res, 200, { ok: true });
  }

  if (p === '/api/alarms' && method === 'GET') {
    try { return sendJson(res, 200, { ok: true, alarms: getUserAlarms(req._user.id, 100) }); }
    catch (e) { return sendJson(res, 500, { ok: false, error: e.message }); }
  }

  // ============ Pages ============
  const user = getUser(req);

  if (p === '/') {
    if (user) { res.writeHead(302, { Location: '/app' }); res.end(); return; }
    if (serveStatic(res, PUBLIC_DIR + '/landing.html')) return;
  }
  if (p === '/login' || p === '/register') {
    if (user) { res.writeHead(302, { Location: '/app' }); res.end(); return; }
    if (serveStatic(res, PUBLIC_DIR + '/auth.html')) return;
  }
  if (p === '/onboarding') {
    if (!user) { res.writeHead(302, { Location: '/login' }); res.end(); return; }
    if (serveStatic(res, PUBLIC_DIR + '/onboarding.html')) return;
  }
  if (p === '/app' || p.startsWith('/app/')) {
    if (!user) { res.writeHead(302, { Location: '/login' }); res.end(); return; }
    const apps = getUserApps(user.id);
    if (apps.length === 0) { res.writeHead(302, { Location: '/onboarding' }); res.end(); return; }
    if (serveStatic(res, PUBLIC_DIR + '/app.html')) return;
  }

  const asb = path.join(PUBLIC_DIR, p);
  if (asb.startsWith(PUBLIC_DIR) && serveStatic(res, asb)) return;

  res.writeHead(404); res.end('not found');
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('[pulsefy] v3 listening on 127.0.0.1:' + PORT);
  initLastEventId();
});

setInterval(() => { try { evaluateRules(); } catch (e) { console.error('[rule-engine]', e.message); } }, 60 * 1000);
setInterval(() => { try { pollLiveEvents(); } catch (e) { console.error('[live-poll]', e.message); } }, 3000);
