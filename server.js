const express = require('express'), multer = require('multer'), Database = require('better-sqlite3');
const bcrypt = require('bcryptjs'), cookieSession = require('cookie-session');
const path = require('path'), fs = require('fs'), crypto = require('crypto');

const app = express(), PORT = process.env.PORT || 3000;
const UP = path.join(__dirname, 'uploads');
fs.mkdirSync(path.join(UP, 'books'), { recursive: true });
fs.mkdirSync(path.join(UP, 'covers'), { recursive: true });

const db = new Database(path.join(__dirname, 'abooks.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, hash TEXT, is_admin INT DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS books(id INTEGER PRIMARY KEY, user_id INT, title TEXT, author TEXT, genre TEXT, year INT, language TEXT,
  description TEXT, tags TEXT, format TEXT, file TEXT, cover TEXT, size INT, downloads INT DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);`);

// Session secret: set SECRET env var in production, otherwise one is generated and saved locally.
const sf = path.join(__dirname, '.secret');
if (!fs.existsSync(sf)) fs.writeFileSync(sf, crypto.randomBytes(32).toString('hex'));
app.use(cookieSession({ name: 'abooks', secret: process.env.SECRET || fs.readFileSync(sf, 'utf8'), maxAge: 30 * 864e5, httpOnly: true, sameSite: 'lax' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/covers', express.static(path.join(UP, 'covers')));

const getUser = q => q.session.uid && db.prepare('SELECT id,username,is_admin FROM users WHERE id=?').get(q.session.uid);
const need = (q, s, n) => getUser(q) ? n() : s.status(401).json({ error: 'Please sign in first.' });

// ---------- auth ----------
app.post('/api/register', (req, res) => {
  const { username = '', password = '' } = req.body;
  if (!/^[\w.-]{3,24}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–24 letters, numbers, dots, dashes or underscores.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) return res.status(400).json({ error: 'That username is taken.' });
  const first = !db.prepare('SELECT 1 FROM users').get(); // first account = site owner/admin
  const id = db.prepare('INSERT INTO users(username,hash,is_admin) VALUES(?,?,?)').run(username, bcrypt.hashSync(password, 10), first ? 1 : 0).lastInsertRowid;
  req.session.uid = id;
  res.json(getUser(req));
});
app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(req.body.username || '');
  if (!u || !bcrypt.compareSync(req.body.password || '', u.hash)) return res.status(400).json({ error: 'Wrong username or password.' });
  req.session.uid = u.id;
  res.json(getUser(req));
});
app.post('/api/logout', (req, res) => { req.session = null; res.json({ ok: true }); });
app.get('/api/me', (req, res) => res.json({ user: getUser(req) || null }));

// ---------- books ----------
const COLS = 'b.id,b.user_id,b.title,b.author,b.genre,b.year,b.language,b.description,b.tags,b.format,b.cover,b.size,b.downloads,b.created,u.username uploader';

app.get('/api/books', (req, res) => {
  const { q = '', genre = '', sort = 'new' } = req.query, page = Math.max(1, +req.query.page || 1), per = 24;
  const w = [], a = [];
  for (const t of q.trim().split(/\s+/).filter(Boolean).slice(0, 8)) {
    const l = `%${t.replace(/[\\%_]/g, '\\$&')}%`;
    w.push(`(b.title LIKE ? ESCAPE '\\' OR b.author LIKE ? ESCAPE '\\' OR b.genre LIKE ? ESCAPE '\\' OR b.tags LIKE ? ESCAPE '\\' OR b.description LIKE ? ESCAPE '\\')`);
    a.push(l, l, l, l, l);
  }
  if (genre) { w.push('b.genre=?'); a.push(genre); }
  const W = w.length ? 'WHERE ' + w.join(' AND ') : '';
  const order = { new: 'b.id DESC', popular: 'b.downloads DESC,b.id DESC', title: 'b.title COLLATE NOCASE' }[sort] || 'b.id DESC';
  const total = db.prepare(`SELECT COUNT(*) n FROM books b ${W}`).get(...a).n;
  const books = db.prepare(`SELECT ${COLS} FROM books b JOIN users u ON u.id=b.user_id ${W} ORDER BY ${order} LIMIT ? OFFSET ?`).all(...a, per, (page - 1) * per);
  res.json({ books, total, pages: Math.max(1, Math.ceil(total / per)) });
});

app.get('/api/books/:id', (req, res) => {
  const b = db.prepare(`SELECT ${COLS} FROM books b JOIN users u ON u.id=b.user_id WHERE b.id=?`).get(req.params.id);
  b ? res.json(b) : res.status(404).json({ error: 'Book not found.' });
});

app.get('/api/books/:id/download', (req, res) => {
  const b = db.prepare('SELECT * FROM books WHERE id=?').get(req.params.id);
  if (!b) return res.status(404).send('Not found');
  db.prepare('UPDATE books SET downloads=downloads+1 WHERE id=?').run(b.id);
  const name = `${b.title} - ${b.author}`.replace(/[^\w .,'()-]/g, '_').slice(0, 120) + '.' + b.format;
  res.download(path.join(UP, 'books', b.file), name);
});

const BOOK_EXT = ['.pdf', '.epub', '.djvu', '.djv'], IMG_EXT = ['.jpg', '.jpeg', '.png', '.webp'];
const up = multer({
  storage: multer.diskStorage({
    destination: (q, f, cb) => cb(null, path.join(UP, f.fieldname === 'cover' ? 'covers' : 'books')),
    filename: (q, f, cb) => cb(null, crypto.randomBytes(12).toString('hex') + path.extname(f.originalname).toLowerCase())
  }),
  limits: { fileSize: 300 * 1024 * 1024 },
  fileFilter: (q, f, cb) => {
    const ok = (f.fieldname === 'cover' ? IMG_EXT : BOOK_EXT).includes(path.extname(f.originalname).toLowerCase());
    cb(ok ? null : new Error(f.fieldname === 'cover' ? 'Cover must be a JPG, PNG or WEBP image.' : 'Book must be a PDF, EPUB or DJVU file.'), ok);
  }
}).fields([{ name: 'book', maxCount: 1 }, { name: 'cover', maxCount: 1 }]);

app.post('/api/books', need, (req, res) => up(req, res, err => {
  const F = req.files || {}, bf = F.book && F.book[0], cf = F.cover && F.cover[0];
  const fail = m => { [bf, cf].forEach(f => f && fs.unlink(f.path, () => {})); res.status(400).json({ error: m }); };
  if (err) return fail(err.message);
  const b = req.body;
  if (!bf) return fail('Please attach a PDF, EPUB or DJVU file.');
  if (!(b.title || '').trim() || !(b.author || '').trim()) return fail('Title and author are required.');
  if (!b.rights) return fail('Please confirm you have the right to share this book.');
  let fmt = path.extname(bf.filename).slice(1); if (fmt === 'djv') fmt = 'djvu';
  const id = db.prepare(`INSERT INTO books(user_id,title,author,genre,year,language,description,tags,format,file,cover,size) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(getUser(req).id, b.title.trim().slice(0, 200), b.author.trim().slice(0, 200), (b.genre || '').slice(0, 60), +b.year || null,
      (b.language || '').slice(0, 40), (b.description || '').slice(0, 5000), (b.tags || '').slice(0, 200), fmt, bf.filename, cf ? cf.filename : null, bf.size).lastInsertRowid;
  res.json({ id });
}));

app.delete('/api/books/:id', need, (req, res) => {
  const u = getUser(req), b = db.prepare('SELECT * FROM books WHERE id=?').get(req.params.id);
  if (!b) return res.status(404).json({ error: 'Book not found.' });
  if (b.user_id !== u.id && !u.is_admin) return res.status(403).json({ error: 'You can only delete your own books.' });
  db.prepare('DELETE FROM books WHERE id=?').run(b.id);
  fs.unlink(path.join(UP, 'books', b.file), () => {});
  if (b.cover) fs.unlink(path.join(UP, 'covers', b.cover), () => {});
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`A-Books running at http://localhost:${PORT}`));
