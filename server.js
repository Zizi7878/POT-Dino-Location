const crypto = require('node:crypto');
const path = require('node:path');
const { promisify } = require('node:util');
const express = require('express');
const Database = require('better-sqlite3');
const { rateLimit } = require('express-rate-limit');

const scrypt = promisify(crypto.scrypt);
const app = express();
const port = Number(process.env.PORT || 3000);
const databasePath = path.resolve(process.env.DB_PATH || path.join(__dirname, 'data', 'accounts.sqlite'));
const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000,http://localhost:5500,http://127.0.0.1:5500')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean)
);
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_ENTRIES = 1000;
const MAX_NOTES_LENGTH = 500;

const fs = require('node:fs');
fs.mkdirSync(path.dirname(databasePath), { recursive: true });

const db = new Database(databasePath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS entries (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
`);

app.disable('x-powered-by');
app.use((req, res, next) => {
  const origin = req.get('origin');
  if (origin && !allowedOrigins.has(origin)) {
    return res.status(403).json({ error: 'This site is not allowed to use the API.' });
  }
  if (origin) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
    res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '1mb' }));

const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many account attempts. Try again later.' }
});

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function hashPassword(password, salt) {
  return scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 });
}

async function createSession(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + SESSION_DURATION_MS;
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .run(hashToken(token), user.id, expiresAt);
  return {
    token,
    account: { id: String(user.id), username: user.username }
  };
}

function requireSession(req, res, next) {
  const authorization = req.get('authorization') || '';
  const match = authorization.match(/^Bearer ([A-Za-z0-9_-]{40,})$/);
  if (!match) return res.status(401).json({ error: 'Please log in to continue.' });

  const session = db.prepare(`
    SELECT users.id, users.username, sessions.expires_at
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
  `).get(hashToken(match[1]));
  if (!session || session.expires_at <= Date.now()) {
    if (session) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(match[1]));
    return res.status(401).json({ error: 'Your session has expired. Please log in again.' });
  }

  req.account = { id: session.id, username: session.username };
  req.sessionTokenHash = hashToken(match[1]);
  next();
}

function validateEntries(value) {
  if (!Array.isArray(value) || value.length > MAX_ENTRIES) return null;
  const entries = [];
  for (const entry of value) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
    if (typeof entry.dino !== 'string' || entry.dino.length < 1 || entry.dino.length > 80) return null;
    const notes = entry.notes === undefined ? '' : entry.notes;
    if (typeof notes !== 'string' || notes.length > MAX_NOTES_LENGTH) return null;
    if (!Number.isFinite(entry.x) || entry.x < 0 || entry.x > 100) return null;
    if (!Number.isFinite(entry.y) || entry.y < 0 || entry.y > 100) return null;
    if (entry.color !== undefined && (typeof entry.color !== 'string' || !/^#[0-9a-f]{6}$/i.test(entry.color))) return null;
    entries.push({
      dino: entry.dino,
      notes,
      x: entry.x,
      y: entry.y,
      color: entry.color || '#7c9cff'
    });
  }
  return entries;
}

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/auth/register', authRateLimit, async (req, res, next) => {
  try {
    const username = typeof req.body.username === 'string' ? req.body.username.trim().toLowerCase() : '';
    const password = req.body.password;
    if (!/^[a-z0-9_-]{3,32}$/.test(username)) {
      return res.status(400).json({ error: 'Username must be 3–32 characters: letters, numbers, _ or -.' });
    }
    if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
      return res.status(400).json({ error: 'Password must be at least 12 characters and no more than 128.' });
    }
    const initialEntries = validateEntries(req.body.initialEntries ?? []);
    if (!initialEntries) {
      return res.status(400).json({ error: 'Previous entries are invalid or exceed the save limit.' });
    }

    const salt = crypto.randomBytes(16);
    const passwordHash = await hashPassword(password, salt);
    let result;
    try {
      result = db.transaction(() => {
        const newUser = db.prepare(`
          INSERT INTO users (username, password_salt, password_hash, created_at)
          VALUES (?, ?, ?, ?)
        `).run(username, salt.toString('hex'), passwordHash.toString('hex'), Date.now());
        if (initialEntries.length) {
          db.prepare('INSERT INTO entries (user_id, data, updated_at) VALUES (?, ?, ?)')
            .run(newUser.lastInsertRowid, JSON.stringify(initialEntries), Date.now());
        }
        return newUser;
      })();
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({ error: 'That username is already registered.' });
      }
      throw error;
    }

    res.status(201).json(await createSession({ id: result.lastInsertRowid, username }));
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login', authRateLimit, async (req, res, next) => {
  try {
    const username = typeof req.body.username === 'string' ? req.body.username.trim().toLowerCase() : '';
    const password = req.body.password;
    if (typeof password !== 'string' || password.length > 128) {
      return res.status(400).json({ error: 'Invalid username or password.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username);
    if (!user) return res.status(401).json({ error: 'Invalid username or password.' });
    const salt = Buffer.from(user.password_salt, 'hex');
    const expectedHash = Buffer.from(user.password_hash, 'hex');
    const actualHash = await hashPassword(password, salt);
    if (!crypto.timingSafeEqual(expectedHash, actualHash)) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    res.json(await createSession(user));
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/me', requireSession, (req, res) => res.json({ account: req.account }));

app.post('/api/auth/logout', requireSession, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.sessionTokenHash);
  res.sendStatus(204);
});

app.get('/api/entries', requireSession, (req, res) => {
  const row = db.prepare('SELECT data FROM entries WHERE user_id = ?').get(req.account.id);
  if (!row) return res.json({ entries: [] });
  try {
    const entries = JSON.parse(row.data);
    return res.json({ entries });
  } catch (error) {
    return res.status(500).json({ error: 'Saved entries could not be read.' });
  }
});

app.put('/api/entries', requireSession, (req, res) => {
  const entries = validateEntries(req.body.entries);
  if (!entries) return res.status(400).json({ error: 'Entries are invalid or exceed the save limit.' });

  db.prepare(`
    INSERT INTO entries (user_id, data, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
  `).run(req.account.id, JSON.stringify(entries), Date.now());
  res.json({ entries });
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof SyntaxError && 'body' in error) {
    return res.status(400).json({ error: 'Request body must be valid JSON.' });
  }
  if (error.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body is too large.' });
  }
  if (Number.isInteger(error.status) && error.status >= 400 && error.status < 500) {
    return res.status(error.status).json({ error: 'The request could not be processed.' });
  }
  console.error(error);
  return res.status(500).json({ error: 'The server could not complete the request.' });
});

const server = app.listen(port, '0.0.0.0', () => {
  console.log(`POT Dino Location API listening on port ${port}`);
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
