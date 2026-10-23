import { getAdminSession, json, listNotes, methodNotAllowed, serverError } from '../lib/common.mjs';

export const handler = async (event) => {
  if (event.httpMethod !== 'GET') return methodNotAllowed('GET');
  try {
    const session = await getAdminSession(event);
    if (!session) return json(401, { ok: false, error: 'Please log in to view the admin inbox.' });
    const notes = await listNotes();
    return json(200, { ok: true, total: notes.length, unread: notes.filter((note) => !note.read).length, notes });
  } catch (error) {
    return serverError(error);
  }
};
