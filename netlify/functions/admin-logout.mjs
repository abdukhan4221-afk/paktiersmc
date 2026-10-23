import { dataStore, expiredSessionCookie, getAdminSession, json, methodNotAllowed, serverError } from '../lib/common.mjs';

export const handler = async (event) => {
  if (event.httpMethod !== 'POST') return methodNotAllowed('POST');
  try {
    const session = await getAdminSession(event);
    if (session) await dataStore().delete(`session:${session.id}`);
    return json(200, { ok: true }, { 'Set-Cookie': expiredSessionCookie(event) });
  } catch (error) {
    // Clear the browser cookie even if the storage service has a transient issue.
    const result = serverError(error);
    result.headers['Set-Cookie'] = expiredSessionCookie(event);
    return result;
  }
};
