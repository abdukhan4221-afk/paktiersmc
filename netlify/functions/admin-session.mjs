import { getAdminSession, json, methodNotAllowed, serverError } from '../lib/common.mjs';

export const handler = async (event) => {
  if (event.httpMethod !== 'GET') return methodNotAllowed('GET');
  try {
    const session = await getAdminSession(event);
    return json(200, { ok: true, authenticated: Boolean(session) });
  } catch (error) {
    return serverError(error);
  }
};
