const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();

// ── Zmień ten string na coś losowego! ──────────────────────────
const SECRET = 'ironlog-super-secret-zmien-to-teraz-2024';
// ───────────────────────────────────────────────────────────────

const db = new Database(path.join(__dirname, 'data', 'ironlog.db'));

app.use(cors());
app.use(express.json({ limit: '5mb' }));

// Serwuj pliki statyczne (index.html apki)
app.use(express.static(path.join(__dirname, 'public')));

// ── Tworzenie tabel ──────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sync_data (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER UNIQUE NOT NULL,
    data       TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// ── Middleware: weryfikacja JWT ───────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Brak tokenu autoryzacji' });
  }
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token wygasł lub jest nieprawidłowy' });
  }
}

// ════════════════════════════════════════════════════════════
// AUTH ENDPOINTS
// ════════════════════════════════════════════════════════════

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Podaj nazwę użytkownika i hasło' });
  }
  if (username.length < 3) {
    return res.status(400).json({ error: 'Nazwa użytkownika musi mieć co najmniej 3 znaki' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Hasło musi mieć co najmniej 6 znaków' });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username.trim(), hash);
    res.json({ ok: true, message: 'Konto utworzone pomyślnie' });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      res.status(409).json({ error: 'Użytkownik o tej nazwie już istnieje' });
    } else {
      res.status(500).json({ error: 'Błąd serwera' });
    }
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Podaj nazwę użytkownika i hasło' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Nieprawidłowa nazwa użytkownika lub hasło' });
  }
  const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '30d' });
  res.json({ ok: true, token, username: user.username });
});

// ════════════════════════════════════════════════════════════
// SYNC ENDPOINTS
// ════════════════════════════════════════════════════════════

// GET /api/sync – pobierz dane z serwera
app.get('/api/sync', requireAuth, (req, res) => {
  const row = db.prepare('SELECT data, updated_at FROM sync_data WHERE user_id = ?').get(req.user.id);
  if (!row) {
    return res.json({ data: null, updated_at: null });
  }
  res.json({ data: JSON.parse(row.data), updated_at: row.updated_at });
});

// POST /api/sync – zapisz dane na serwer
app.post('/api/sync', requireAuth, (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'Brak danych do synchronizacji' });

  const existing = db.prepare('SELECT id FROM sync_data WHERE user_id = ?').get(req.user.id);
  if (existing) {
    db.prepare('UPDATE sync_data SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?')
      .run(JSON.stringify(data), req.user.id);
  } else {
    db.prepare('INSERT INTO sync_data (user_id, data) VALUES (?, ?)')
      .run(req.user.id, JSON.stringify(data));
  }
  res.json({ ok: true, updated_at: new Date().toISOString() });
});

// ── Start serwera ─────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ IronLog backend działa na porcie ${PORT}`);
  console.log(`   Otwórz: http://localhost:${PORT}`);
});
