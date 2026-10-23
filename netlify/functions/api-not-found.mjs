import { json } from '../lib/common.mjs';

export const handler = async () => json(404, { ok: false, error: 'API route not found.' });
