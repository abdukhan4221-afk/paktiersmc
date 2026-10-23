import { createHash, timingSafeEqual } from 'node:crypto';
import { checkRateLimit, createAdminSession, json, methodNotAllowed, parseBody, serverError } from '../lib/common.mjs';

export const handler = async (event) => {
  if (event.httpMethod !== 'POST') return methodNotAllowed('POST');
  try {
    const expectedPassword = process.env.ADMIN_PASSWORD || '';
    if (!expectedPassword) return json(503, { ok: false, error: 'Admin login is disabled. Set ADMIN_PASSWORD in Netlify environment variables.' });

    const rate = await checkRateLimit(event, 'admin-login', 5, 15 * 60 * 1000);
    if (!rate.allowed) return json(429, { ok: false, error: 'Too many login attempts. Please try again in 15 minutes.' }, { 'Retry-After': String(rate.retryAfter) });

    const body = parseBody(event);
    const password = typeof body.password === 'string' ? body.password : '';
    const expected = createHash('sha256').update(expectedPassword, 'utf8').digest();
    const supplied = createHash('sha256').update(password, 'utf8').digest();
    if (!timingSafeEqual(expected, supplied)) return json(401, { ok: false, error: 'The password is incorrect.' });

    const session = await createAdminSession(event);
    return json(200, { ok: true, authenticated: true }, { 'Set-Cookie': session.cookie });
  } catch (error) {
    return serverError(error);
  }
};
