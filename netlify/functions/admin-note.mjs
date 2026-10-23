import { dataStore, getAdminSession, json, methodNotAllowed, parseBody, serverError } from '../lib/common.mjs';

export const handler = async (event) => {
  if (!['PATCH', 'DELETE'].includes(event.httpMethod)) return methodNotAllowed('PATCH, DELETE');
  try {
    const session = await getAdminSession(event);
    if (!session) return json(401, { ok: false, error: 'Please log in to manage inbox notes.' });

    const id = String((event.queryStringParameters && event.queryStringParameters.id) || '').trim();
    if (!/^[a-f0-9-]{36}$/i.test(id)) return json(400, { ok: false, error: 'A valid note ID is required.' });
    const key = `note:${id}`;
    const store = dataStore();
    const note = await store.get(key, { type: 'json' });
    if (!note) return json(404, { ok: false, error: 'Note not found.' });

    if (event.httpMethod === 'PATCH') {
      const body = parseBody(event);
      if (typeof body.read !== 'boolean') return json(400, { ok: false, error: 'Provide read: true or read: false.' });
      note.read = body.read;
      await store.setJSON(key, note);
      return json(200, { ok: true });
    }

    await store.delete(key);
    return json(200, { ok: true });
  } catch (error) {
    return serverError(error);
  }
};
