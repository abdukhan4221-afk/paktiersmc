import { randomUUID } from 'node:crypto';
import { dataStore, json, methodNotAllowed, parseBody, cleanText, validEmail, checkRateLimit, serverError } from '../lib/common.mjs';

const CONTACT_WEBHOOK_URL = process.env.CONTACT_WEBHOOK_URL || '';

export const handler = async (event) => {
  if (event.httpMethod !== 'POST') return methodNotAllowed('POST');
  try {
    const rate = await checkRateLimit(event, 'contact', 5, 15 * 60 * 1000);
    if (!rate.allowed) return json(429, { ok: false, error: 'Too many messages were sent. Please try again in 15 minutes.' }, { 'Retry-After': String(rate.retryAfter) });

    const body = parseBody(event);
    // Honeypot field: quietly accept automated submissions without saving them.
    if (typeof body.website === 'string' && body.website.trim() !== '') {
      return json(202, { ok: true, stored: false, deliveryConfigured: Boolean(CONTACT_WEBHOOK_URL) });
    }

    const name = cleanText(body.name, 80);
    const email = cleanText(body.email, 254).toLowerCase();
    const subject = cleanText(body.subject, 120);
    const message = cleanText(body.message, 2000);
    const fields = {};
    if (name.length < 2) fields.name = 'Please enter a name with at least 2 characters.';
    if (!validEmail(email)) fields.email = 'Please enter a valid email address.';
    if (subject.length < 3) fields.subject = 'Please choose a topic or enter a longer subject.';
    if (message.length < 20) fields.message = 'Please enter a message with at least 20 characters.';
    if (Object.keys(fields).length) return json(400, { ok: false, error: 'Please check the highlighted fields.', fields });

    const receivedAt = new Date().toISOString();
    const submission = { id: randomUUID(), name, email, subject, message, receivedAt, read: false };
    await dataStore().setJSON(`note:${submission.id}`, submission);

    if (!CONTACT_WEBHOOK_URL) {
      return json(201, { ok: true, stored: true, deliveryConfigured: false, message: 'Your note has been saved to the EclipseMC admin inbox.' });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    let upstream;
    try {
      upstream = await fetch(CONTACT_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, subject, message, receivedAt }),
        signal: controller.signal
      });
    } catch (_error) {
      return json(201, { ok: true, stored: true, deliveryConfigured: false, message: 'Your note was saved to the admin inbox, but the external notification could not be delivered.' });
    } finally {
      clearTimeout(timeout);
    }

    if (!upstream.ok) {
      return json(201, { ok: true, stored: true, deliveryConfigured: false, message: 'Your note was saved to the admin inbox, but the external notification was rejected.' });
    }
    return json(201, { ok: true, stored: true, deliveryConfigured: true, message: 'Your note was saved to the admin inbox and the external notification was delivered.' });
  } catch (error) {
    return serverError(error);
  }
};
