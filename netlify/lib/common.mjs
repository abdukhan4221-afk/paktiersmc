import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { getStore } from '@netlify/blobs';

export const SESSION_COOKIE = 'eclipsemc_admin_session';
export const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const STORE_NAME = 'eclipsemc-lifesteal-data';

// A shared, strongly consistent Netlify Blobs store replaces local JSON files,
// which are not durable or shared between serverless invocations.
export function dataStore() {
  return getStore({ name: STORE_NAME, consistency: 'strong' });
}

export function json(statusCode, payload, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'same-origin',
      ...extraHeaders
    },
    body: JSON.stringify(payload)
  };
}

export function methodNotAllowed(allowed) {
  return json(405, { ok: false, error: 'Method not allowed.' }, { Allow: allowed });
}

export function parseBody(event) {
  if (!event || !event.body) return {};
  let raw = event.body;
  if (event.isBase64Encoded) raw = Buffer.from(raw, 'base64').toString('utf8');
  if (Buffer.byteLength(raw, 'utf8') > 16 * 1024) {
    const error = new Error('Request body is too large.');
    error.statusCode = 413;
    throw error;
  }
  try {
    const body = JSON.parse(raw);
    return body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  } catch (_error) {
    const error = new Error('Request body must be valid JSON.');
    error.statusCode = 400;
    throw error;
  }
}

export function cleanText(value, maxLength) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/<[^>]*>/g, ' ')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);
}

export function validEmail(email) {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

function headersOf(event) {
  return event && event.headers ? event.headers : {};
}

export function parseCookies(event) {
  const headers = headersOf(event);
  const raw = headers.cookie || headers.Cookie || '';
  const result = Object.create(null);
  for (const item of String(raw).split(';')) {
    const separator = item.indexOf('=');
    if (separator < 1) continue;
    const key = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();
    try { result[key] = decodeURIComponent(value); } catch (_error) { result[key] = value; }
  }
  return result;
}

function sessionSecret() {
  // Set a distinct ADMIN_SESSION_SECRET in Netlify for best practice.
  // Falling back to ADMIN_PASSWORD keeps first-time setup simple.
  return process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_PASSWORD || '';
}

function signPayload(payload) {
  return createHmac('sha256', sessionSecret()).update(payload).digest('base64url');
}

function secureCookie(event) {
  const headers = headersOf(event);
  const forwardedProto = String(headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const urlIsHttps = String(event.rawUrl || '').startsWith('https://');
  return forwardedProto === 'https' || urlIsHttps || process.env.NETLIFY === 'true';
}

export function expiredSessionCookie(event) {
  const secure = secureCookie(event) ? '; Secure' : '';
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secure}`;
}

export async function createAdminSession(event) {
  if (!process.env.ADMIN_PASSWORD || !sessionSecret()) {
    throw new Error('Set ADMIN_PASSWORD and ADMIN_SESSION_SECRET in Netlify environment variables.');
  }
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const id = randomBytes(24).toString('hex');
  const encodedPayload = Buffer.from(JSON.stringify({ id, expiresAt })).toString('base64url');
  const signature = signPayload(encodedPayload);
  const token = `${encodedPayload}.${signature}`;
  await dataStore().setJSON(`session:${id}`, { id, expiresAt, createdAt: Date.now() });
  const secure = secureCookie(event) ? '; Secure' : '';
  const cookie = `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}${secure}`;
  return { id, expiresAt, cookie };
}

// Signed, expiring, revocable cookies work across stateless function instances.
export async function getAdminSession(event) {
  if (!process.env.ADMIN_PASSWORD || !sessionSecret()) return null;
  const token = parseCookies(event)[SESSION_COOKIE];
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encodedPayload, suppliedSignature] = parts;
  const expectedSignature = signPayload(encodedPayload);
  const supplied = Buffer.from(suppliedSignature, 'base64url');
  const expected = Buffer.from(expectedSignature, 'base64url');
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return null;

  let payload;
  try { payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8')); }
  catch (_error) { return null; }
  if (!payload || typeof payload.id !== 'string' || !/^[a-f0-9]{48}$/.test(payload.id)) return null;
  if (!Number.isFinite(payload.expiresAt) || payload.expiresAt <= Date.now()) return null;

  const session = await dataStore().get(`session:${payload.id}`, { type: 'json' });
  if (!session || session.expiresAt !== payload.expiresAt || session.expiresAt <= Date.now()) return null;
  return { id: payload.id, expiresAt: payload.expiresAt };
}

export async function revokeAdminSession(event) {
  const session = await getAdminSession(event);
  if (session) await dataStore().delete(`session:${session.id}`);
}

// Shared best-effort rate limiting across Netlify invocations. Client IPs are
// hashed before storage; counter updates are not a substitute for edge WAF rules.
export async function checkRateLimit(event, label, limit, windowMs) {
  const headers = headersOf(event);
  const ip = String(
    headers['x-nf-client-connection-ip'] ||
    headers['x-forwarded-for'] ||
    headers['client-ip'] ||
    'unknown'
  ).split(',')[0].trim();
  const ipHash = createHash('sha256').update(ip).digest('hex').slice(0, 32);
  const key = `limit:${label}:${ipHash}`;
  const store = dataStore();
  const now = Date.now();
  const current = await store.get(key, { type: 'json' });
  if (current && current.resetAt > now && current.count >= limit) {
    return { allowed: false, retryAfter: Math.max(1, Math.ceil((current.resetAt - now) / 1000)) };
  }
  const next = current && current.resetAt > now
    ? { count: current.count + 1, resetAt: current.resetAt }
    : { count: 1, resetAt: now + windowMs };
  await store.setJSON(key, next);
  return { allowed: true, retryAfter: 0 };
}

export async function listNotes() {
  const store = dataStore();
  const { blobs } = await store.list({ prefix: 'note:' });
  const notes = await Promise.all(blobs.map((blob) => store.get(blob.key, { type: 'json' })));
  return notes.filter((note) => note && typeof note.id === 'string')
    .sort((a, b) => Date.parse(b.receivedAt) - Date.parse(a.receivedAt));
}

export function serverError(error) {
  console.error('[eclipsemc-netlify] Function failed:', error && error.message ? error.message : 'Unknown error');
  if (error && error.statusCode === 413) return json(413, { ok: false, error: 'Request body is too large.' });
  if (error && error.statusCode === 400) return json(400, { ok: false, error: 'Request body must be valid JSON.' });
  return json(500, { ok: false, error: 'An unexpected server error occurred. Please try again later.' });
}
