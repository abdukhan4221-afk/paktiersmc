'use strict';

// EclipseMC Lifesteal website and secure admin inbox.
// Contact submissions are stored in DATA_DIR/contacts.json and may optionally
// be forwarded to CONTACT_WEBHOOK_URL. For Railway persistence, mount a volume
// at /data and set DATA_DIR=/data.

const path = require('node:path');
const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = Number.parseInt(process.env.PORT || '3000', 10);
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const NOTES_FILE = path.join(DATA_DIR, 'contacts.json');
const CONTACT_WEBHOOK_URL = process.env.CONTACT_WEBHOOK_URL || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_COOKIE = 'eclipsemc_admin_session';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const adminSessions = new Map();
let notesMutationQueue = Promise.resolve();

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error('PORT must be a valid TCP port between 1 and 65535.');
}

// Railway runs behind a trusted reverse proxy. This lets Express use the
// forwarded client IP for rate limiting when deployed there.
if (process.env.RAILWAY_ENVIRONMENT || process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}

// Security headers. Inline CSS and JS are required by the self-contained site.
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      imgSrc: ["'self'", 'data:', 'blob:'],
      objectSrc: ["'none'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false
}));

// Same-origin requests work by default. Set CORS_ORIGIN to a comma-separated
// allowlist only when an independently hosted, trusted client needs this API.
const corsOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
app.use(cors({
  origin(origin, callback) {
    if (!origin || corsOrigins.length === 0 || corsOrigins.includes(origin)) {
      return callback(null, corsOrigins.length === 0 ? false : true);
    }
    return callback(null, false);
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  maxAge: 600
}));

// Bound payloads before parsing to reduce exposure to oversized requests.
app.use(express.json({ limit: '16kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

// Per-IP limits: contact form and password attempts are limited separately.
const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { ok: false, error: 'Too many messages were sent from this connection. Please try again in 15 minutes.' }
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { ok: false, error: 'Too many login attempts. Please try again in 15 minutes.' }
});

// Atomically read stored enquiries. An absent file is a normal first-run state.
async function readNotes() {
  try {
    const raw = await fs.readFile(NOTES_FILE, 'utf8');
    const notes = JSON.parse(raw);
    if (!Array.isArray(notes)) throw new Error('Stored inbox data has an invalid format.');
    return notes;
  } catch (error) {
    if (error && error.code === 'ENOENT') return [];
    throw error;
  }
}

async function writeNotes(notes) {
  await fs.mkdir(DATA_DIR, { recursive: true, mode: 0o700 });
  const temporaryFile = `${NOTES_FILE}.${process.pid}.tmp`;
  await fs.writeFile(temporaryFile, JSON.stringify(notes, null, 2), { encoding: 'utf8', mode: 0o600 });
  await fs.rename(temporaryFile, NOTES_FILE);
}

// Serialize file mutations so concurrent contact submissions do not overwrite
// each other's notes in the single Node.js process.
function mutateNotes(mutator) {
  const operation = notesMutationQueue.then(async () => {
    const notes = await readNotes();
    const result = await mutator(notes);
    await writeNotes(notes);
    return result;
  });
  notesMutationQueue = operation.catch(() => undefined);
  return operation;
}

// GET /api/health — service monitor endpoint.
app.get('/api/health', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ ok: true, service: 'eclipsemc-lifesteal', status: 'healthy' });
});

// Small cookie parser avoids an extra dependency; session IDs are opaque,
// random, HttpOnly, SameSite=Strict and stored only on the server.
function parseCookies(header) {
  const result = Object.create(null);
  for (const item of String(header || '').split(';')) {
    const separator = item.indexOf('=');
    if (separator < 1) continue;
    const key = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();
    try { result[key] = decodeURIComponent(value); } catch (_error) { result[key] = value; }
  }
  return result;
}

function getAdminSession(req) {
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (!token) return false;
  const expiresAt = adminSessions.get(token);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}

function requireAdmin(req, res, next) {
  if (!getAdminSession(req)) {
    return res.status(401).json({ ok: false, error: 'Please log in to view the admin inbox.' });
  }
  next();
}

function adminCookie(token, maxAgeSeconds) {
  const secure = process.env.NODE_ENV === 'production' || Boolean(process.env.RAILWAY_ENVIRONMENT);
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}${secure ? '; Secure' : ''}`;
}

// GET /api/admin/session — lets the frontend decide whether to show Login or Inbox.
app.get('/api/admin/session', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ ok: true, authenticated: Boolean(ADMIN_PASSWORD) && getAdminSession(req) });
});

// POST /api/admin/login — password is read only from the server environment.
// It is never included in the public HTML or returned from any endpoint.
app.post('/api/admin/login', loginLimiter, (req, res) => {
  if (!ADMIN_PASSWORD) {
    return res.status(503).json({ ok: false, error: 'Admin login is disabled until ADMIN_PASSWORD is set in the server environment.' });
  }

  const supplied = req.body && typeof req.body.password === 'string' ? req.body.password : '';
  const expectedHash = crypto.createHash('sha256').update(ADMIN_PASSWORD, 'utf8').digest();
  const suppliedHash = crypto.createHash('sha256').update(supplied, 'utf8').digest();
  if (!crypto.timingSafeEqual(expectedHash, suppliedHash)) {
    return res.status(401).json({ ok: false, error: 'The password is incorrect.' });
  }

  // Remove expired entries whenever an admin signs in, limiting session map growth.
  const now = Date.now();
  for (const [token, expiresAt] of adminSessions.entries()) {
    if (expiresAt <= now) adminSessions.delete(token);
  }

  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, now + SESSION_TTL_MS);
  res.set('Cache-Control', 'no-store');
  res.setHeader('Set-Cookie', adminCookie(token, Math.floor(SESSION_TTL_MS / 1000)));
  return res.json({ ok: true, authenticated: true });
});

// POST /api/admin/logout — revoke the current token and clear its cookie.
app.post('/api/admin/logout', (req, res) => {
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (token) adminSessions.delete(token);
  res.set('Cache-Control', 'no-store');
  res.setHeader('Set-Cookie', adminCookie('', 0));
  return res.json({ ok: true });
});

// Strip markup and control characters, then cap every user-controlled field.
function cleanText(value, maxLength) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/<[^>]*>/g, ' ')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);
}

function validEmail(email) {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

// POST /api/contact — validate, save into the admin inbox, and optionally forward.
app.post('/api/contact', contactLimiter, async (req, res, next) => {
  try {
    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body)
      ? req.body
      : {};

    // Honeypot: silently ignore likely automated form submissions.
    if (typeof body.website === 'string' && body.website.trim() !== '') {
      return res.status(202).json({ ok: true, stored: false, deliveryConfigured: Boolean(CONTACT_WEBHOOK_URL) });
    }

    const name = cleanText(body.name, 80);
    const email = cleanText(body.email, 254).toLowerCase();
    const subject = cleanText(body.subject, 120);
    const message = cleanText(body.message, 2000);
    const errors = {};

    if (name.length < 2) errors.name = 'Please enter a name with at least 2 characters.';
    if (!validEmail(email)) errors.email = 'Please enter a valid email address.';
    if (subject.length < 3) errors.subject = 'Please choose a topic or enter a longer subject.';
    if (message.length < 20) errors.message = 'Please enter a message with at least 20 characters.';

    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ ok: false, error: 'Please check the highlighted fields.', fields: errors });
    }

    const submission = {
      id: crypto.randomUUID(),
      name,
      email,
      subject,
      message,
      receivedAt: new Date().toISOString(),
      read: false
    };

    // Contact records are persisted before any external delivery attempt.
    await mutateNotes((notes) => { notes.push(submission); });

    if (!CONTACT_WEBHOOK_URL) {
      return res.status(201).json({
        ok: true,
        stored: true,
        deliveryConfigured: false,
        message: 'Your note has been saved to the EclipseMC admin inbox.'
      });
    }

    // The destination is operator-configured only; clients cannot provide a URL.
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    let upstream;
    try {
      upstream = await fetch(CONTACT_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, subject, message, receivedAt: submission.receivedAt }),
        signal: controller.signal
      });
    } catch (_error) {
      // It is still safely stored in the inbox if external forwarding fails.
      return res.status(201).json({
        ok: true,
        stored: true,
        deliveryConfigured: false,
        message: 'Your note was saved to the admin inbox, but the external notification could not be delivered.'
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!upstream.ok) {
      return res.status(201).json({
        ok: true,
        stored: true,
        deliveryConfigured: false,
        message: 'Your note was saved to the admin inbox, but the external notification was rejected.'
      });
    }

    return res.status(201).json({
      ok: true,
      stored: true,
      deliveryConfigured: true,
      message: 'Your note was saved to the admin inbox and the external notification was delivered.'
    });
  } catch (error) {
    return next(error);
  }
});

// Protected inbox API: newest first, with read/unread state and deletion.
app.get('/api/admin/notes', requireAdmin, async (_req, res, next) => {
  try {
    const notes = await readNotes();
    notes.sort((a, b) => Date.parse(b.receivedAt) - Date.parse(a.receivedAt));
    res.set('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      total: notes.length,
      unread: notes.filter((note) => !note.read).length,
      notes
    });
  } catch (error) {
    return next(error);
  }
});

app.patch('/api/admin/notes/:id', requireAdmin, async (req, res, next) => {
  try {
    if (!req.body || typeof req.body.read !== 'boolean') {
      return res.status(400).json({ ok: false, error: 'Provide read: true or read: false.' });
    }
    let found = false;
    await mutateNotes((notes) => {
      const note = notes.find((item) => item.id === req.params.id);
      if (note) {
        note.read = req.body.read;
        found = true;
      }
    });
    if (!found) return res.status(404).json({ ok: false, error: 'Note not found.' });
    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
});

app.delete('/api/admin/notes/:id', requireAdmin, async (req, res, next) => {
  try {
    let deleted = false;
    await mutateNotes((notes) => {
      const index = notes.findIndex((item) => item.id === req.params.id);
      if (index !== -1) {
        notes.splice(index, 1);
        deleted = true;
      }
    });
    if (!deleted) return res.status(404).json({ ok: false, error: 'Note not found.' });
    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
});

// Static assets first, followed by clean path routes mapped to the same page.
app.use(express.static(PUBLIC_DIR, {
  extensions: ['html'],
  etag: true,
  maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0,
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));

const cleanPageRoutes = [
  '/home', '/store', '/about', '/community', '/faq', '/contact', '/login', '/notes'
];
app.get(cleanPageRoutes, (_req, res) => {
  res.set('Cache-Control', 'no-cache');
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// JSON for unknown API paths; the same frontend can handle unknown web paths gracefully.
app.use('/api', (_req, res) => res.status(404).json({ ok: false, error: 'API route not found.' }));
app.use((_req, res) => res.status(404).sendFile(path.join(PUBLIC_DIR, 'index.html')));

// Central errors avoid leaking stack traces or private submission details.
app.use((error, _req, res, _next) => {
  if (error && (error.type === 'entity.too.large' || error.status === 413)) {
    return res.status(413).json({ ok: false, error: 'Request body is too large.' });
  }
  if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
    return res.status(400).json({ ok: false, error: 'Request body must be valid JSON.' });
  }
  console.error('[eclipsemc] Request failed:', error && error.message ? error.message : 'Unknown error');
  return res.status(500).json({ ok: false, error: 'An unexpected server error occurred.' });
});

// Start HTTP service and drain active connections on shutdown.
const server = app.listen(PORT, () => {
  console.log(`EclipseMC Lifesteal is available on port ${PORT}`);
  console.log(`Contact inbox data directory: ${DATA_DIR}`);
});

let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[eclipsemc] ${signal} received; shutting down gracefully.`);
  server.close((error) => {
    if (error) {
      console.error('[eclipsemc] Shutdown error:', error.message);
      process.exitCode = 1;
    }
    process.exit();
  });
  setTimeout(() => {
    console.error('[eclipsemc] Graceful shutdown timed out; forcing exit.');
    process.exit(1);
  }, 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
