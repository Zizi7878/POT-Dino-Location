# POT Dino Location

The map is a static site and can be hosted on GitHub Pages. Account creation, login sessions, and map entries are handled by the Node.js API in `server.js`; the API uses SQLite and must run on a host with persistent disk storage.

## Run the API locally

Requires Node.js 20 or newer.

```sh
npm install
ALLOWED_ORIGINS=http://localhost:8000 npm start
```

In another terminal, serve this directory on port 8000, for example with `npx serve -l 8000`. Open the served site and use its account form. The API creates `data/accounts.sqlite` automatically. Keep this database file on persistent storage and back it up; do not commit it.

## Deploy

1. Deploy this repository's `server.js` as a Node.js web service with persistent disk storage. Set its start command to `npm start` and its `PORT` environment variable if required by the host.
2. Set `DB_PATH` to a file on the host's persistent disk.
3. Set `ALLOWED_ORIGINS` to the exact GitHub Pages origin, such as `https://zizi7878.github.io` (no trailing slash). Include additional comma-separated origins only when needed.
4. Update the `pot-api-url` meta tag in `index.html` to the HTTPS base URL for the API, such as `https://your-api.example.com`. Do not include `/api` at the end.
5. Deploy the changed site to GitHub Pages. Verify the API health endpoint at `https://your-api.example.com/api/health`.

The API requires CORS origins to match exactly. Use HTTPS for the deployed API and site. Do not use an ephemeral filesystem for the SQLite database: accounts and entries will be lost when that filesystem is reset.

## Accounts and saved entries

Usernames are case-insensitive and accept 3–32 lowercase letters, digits, underscores, or hyphens. Passwords must be at least 12 characters. Passwords are stored as salted scrypt hashes. Session tokens are random, expire after 30 days, and are revoked when the user logs out. Entries are stored separately per account. When a user creates a server account in a browser with existing account-specific local entries for that username, those entries are copied into the new account; the old browser copy is not deleted. Old browser-only accounts are not server accounts and must be created again.
