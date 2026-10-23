# EclipseMC Lifesteal — Netlify build

This package can be deployed as a Netlify static site plus Netlify Functions. `api_server.js` remains available for local/regular Node.js hosting, but Netlify runs the files in `netlify/functions/` instead.

## Deploy on Netlify

1. Put the contents of this project at the **repository root** and push them to GitHub. Do not deploy only the `public/` folder: Functions must be included in the build.
2. In Netlify, import the GitHub repository. `netlify.toml` configures `npm run build`, publishes `public/`, and deploys the functions in `netlify/functions/`.
3. In **Site configuration → Environment variables**, add:
   - `ADMIN_PASSWORD` — your private inbox login password.
   - `ADMIN_SESSION_SECRET` — a random secret at least 32 characters long. Generate one locally with `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`.
   - `CONTACT_WEBHOOK_URL` — optional trusted webhook if you want contact notes forwarded elsewhere.
4. Redeploy after setting the variables.

Contact notes, revocable admin sessions, and rate-limit records use Netlify Blobs via `@netlify/blobs`; they are not written to the deployed filesystem. Netlify Blobs is accessed directly by the functions and needs no `DATA_DIR` or attached disk.

## Verify after deployment

- `/home` — homepage
- `/store` — rank store
- `/login` — admin login
- `/notes` — protected contact inbox
- `/api/health` — JSON health check

Submitting the contact form saves a note to the Netlify Blobs inbox. If `CONTACT_WEBHOOK_URL` is not configured, no email or external notification is sent; the note remains in the admin inbox.

## Local development

For the original Express server and local JSON-file storage, use `npm install` then `npm start`. To exercise Netlify Functions locally, use `npm run netlify:dev` after connecting the project with the Netlify CLI. Netlify's local Blobs sandbox is separate from production data.
