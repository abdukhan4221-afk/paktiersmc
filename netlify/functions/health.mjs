import { json, methodNotAllowed } from '../lib/common.mjs';

export const handler = async (event) => {
  if (event.httpMethod !== 'GET') return methodNotAllowed('GET');
  return json(200, { ok: true, service: 'eclipsemc-lifesteal', status: 'healthy', platform: 'netlify-functions' });
};
