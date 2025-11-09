// index.js (updated with admin management endpoints)
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const ExcelJS = require('exceljs');
const fs = require('fs');
const path = require('path');

const DB_FILE = process.env.DB_FILE || path.join(process.env.PERSISTENT_DIR || __dirname, 'ukt.sqlite');
const JWT_SECRET = process.env.JWT_SECRET || 'ubah_rahasia_ini';
const PORT = process.env.PORT || 3000;

const db = new sqlite3.Database(DB_FILE);

// Utility: wrap sqlite3 in promises (simple)
function run(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ id: this.lastID, changes: this.changes });
    });
  });
}
function get(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}
function all(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

const app = express();
app.use(cors());
app.use(express.json());

// --- Auth helpers ---
function generateToken(user) {
  return jwt.sign({ username: user.username, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  const token = h.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// --- Routes ---

// Health
app.get('/api/ping', (req, res) => res.json({ ok: true }));

// Register with admin limit
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, name, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });

    // Check existing username
    const exists = await get(db, 'SELECT id FROM users WHERE username = ?', [username]).catch(() => null);
    if (exists) return res.status(400).json({ error: 'username sudah ada' });

    // If requested role is admin, enforce limit: max 2 admins
    const requestedRole = role === 'admin' ? 'admin' : 'member';
    if (requestedRole === 'admin') {
      const row = await get(db, "SELECT COUNT(*) as count FROM users WHERE role = 'admin'").catch(() => ({ count: 0 }));
      const adminCount = row ? Number(row.count || 0) : 0;
      if (adminCount >= 2) {
        return res.status(403).json({ error: 'Batas akun admin tercapai (maksimal 2 admin)' });
      }
    }

    const hash = await bcrypt.hash(password, 10);
    await run(db, 'INSERT INTO users (username,password,name,role) VALUES (?,?,?,?)', [username, hash, name || username, requestedRole]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });
    const row = await get(db, 'SELECT * FROM users WHERE username = ?', [username]).catch(() => null);
    if (!row) return res.status(400).json({ error: 'username/password salah' });
    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.status(400).json({ error: 'username/password salah' });
    const token = generateToken(row);
    res.json({ ok: true, token, user: { username: row.username, name: row.name, role: row.role } });
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Get current user (requires token)
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// Change password endpoint
app.post('/api/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'currentPassword & newPassword required' });

    // Load user from DB to get hashed password
    const row = await get(db, 'SELECT * FROM users WHERE username = ?', [req.user.username]).catch(() => null);
    if (!row) return res.status(404).json({ error: 'User tidak ditemukan' });

    const match = await bcrypt.compare(currentPassword, row.password);
    if (!match) return res.status(403).json({ error: 'Password saat ini salah' });

    // Optionally prevent reuse of same password
    const same = await bcrypt.compare(newPassword, row.password);
    if (same) return res.status(400).json({ error: 'Password baru tidak boleh sama dengan password lama' });

    const newHash = await bcrypt.hash(newPassword, 10);
    await run(db, 'UPDATE users SET password = ? WHERE username = ?', [newHash, req.user.username]);
    res.json({ ok: true, message: 'Password berhasil diubah' });
  } catch (err) {
    console.error('Change-password error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Create transaction (member or admin; member only pemasukan enforced server-side)
app.post('/api/transactions', authMiddleware, async (req, res) => {
  try {
    const { jenis, tipe, jumlah, date, desc } = req.body;
    if (!jenis || !tipe || !jumlah) return res.status(400).json({ error: 'jenis, tipe, jumlah required' });
    if (req.user.role === 'member' && tipe !== 'pemasukan') return res.status(403).json({ error: 'Member hanya boleh input pemasukan' });
    const j = Math.round(Number(jumlah));
    const d = date || new Date().toISOString().slice(0,10);
    await run(db, 'INSERT INTO transactions (jenis,tipe,jumlah,date,desc,by_user) VALUES (?,?,?,?,?,?)', [jenis, tipe, j, d, desc || '', req.user.username]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Create tx error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// List transactions (with optional filters)
app.get('/api/transactions', authMiddleware, async (req, res) => {
  try {
    const tipe = req.query.tipe || 'all';
    const from = req.query.from;
    const to = req.query.to;

    let sql = 'SELECT id, jenis, tipe, jumlah, date, desc, by_user, created_at FROM transactions';
    const conditions = [];
    const params = [];
    if (tipe && tipe !== 'all') { conditions.push('tipe = ?'); params.push(tipe); }
    if (from) { conditions.push('date >= ?'); params.push(from); }
    if (to) { conditions.push('date <= ?'); params.push(to); }
    if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
    sql += ' ORDER BY date DESC, id DESC';
    const rows = await all(db, sql, params);
    res.json({ ok: true, rows });
  } catch (err) {
    console.error('List tx error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Delete single transaction (admin only)
app.delete('/api/transactions/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const id = req.params.id;
    await run(db, 'DELETE FROM transactions WHERE id = ?', [id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete tx error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Delete all transactions (admin only)
app.delete('/api/transactions', authMiddleware, adminOnly, async (req, res) => {
  try {
    await run(db, 'DELETE FROM transactions', []);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete all tx error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Export XLSX (admin only) - returns downloadable file
app.get('/api/export', authMiddleware, adminOnly, async (req, res) => {
  try {
    const rows = await all(db, 'SELECT date, jenis, tipe, jumlah, by_user as by, desc FROM transactions ORDER BY date DESC, id DESC');
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Riwayat');
    sheet.columns = [
      { header: 'Tanggal', key: 'date', width: 15 },
      { header: 'Jenis', key: 'jenis', width: 25 },
      { header: 'Tipe', key: 'tipe', width: 15 },
      { header: 'Jumlah', key: 'jumlah', width: 15 },
      { header: 'Oleh', key: 'by', width: 20 },
      { header: 'Keterangan', key: 'desc', width: 30 }
    ];
    rows.forEach(r => sheet.addRow(r));
    const fname = `ukt_riwayat_${new Date().toISOString().slice(0,10)}.xlsx`;

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error('Export error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// --- Admin management endpoints ---
// List users (admin)
app.get('/api/admin/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const rows = await all(db, 'SELECT id, username, name, role, created_at FROM users ORDER BY id ASC');
    res.json({ ok: true, rows });
  } catch (err) {
    console.error('Admin list users error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Reset password for a user (admin) - set to newPassword
app.post('/api/admin/reset-password', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) return res.status(400).json({ error: 'username & newPassword required' });
    const row = await get(db, 'SELECT id FROM users WHERE username = ?', [username]).catch(() => null);
    if (!row) return res.status(404).json({ error: 'User tidak ditemukan' });
    const hash = await bcrypt.hash(newPassword, 10);
    await run(db, 'UPDATE users SET password = ? WHERE username = ?', [hash, username]);
    res.json({ ok: true, message: 'Password user di-reset' });
  } catch (err) {
    console.error('Admin reset-password error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Promote a user to admin (admin) - respects admin limit 2
app.post('/api/admin/promote', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'username required' });
    const userRow = await get(db, 'SELECT id, role FROM users WHERE username = ?', [username]).catch(() => null);
    if (!userRow) return res.status(404).json({ error: 'User tidak ditemukan' });
    if (userRow.role === 'admin') return res.status(400).json({ error: 'User sudah admin' });
    const row = await get(db, "SELECT COUNT(*) as count FROM users WHERE role = 'admin'").catch(() => ({ count: 0 }));
    const adminCount = row ? Number(row.count || 0) : 0;
    if (adminCount >= 2) return res.status(403).json({ error: 'Batas akun admin tercapai (maksimal 2 admin)' });
    await run(db, 'UPDATE users SET role = ? WHERE username = ?', ['admin', username]);
    res.json({ ok: true, message: 'User dipromosikan menjadi admin' });
  } catch (err) {
    console.error('Admin promote error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Demote an admin to member (admin)
app.post('/api/admin/demote', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'username required' });
    if (username === req.user.username) return res.status(400).json({ error: 'Tidak bisa mendemote diri sendiri' });
    const userRow = await get(db, 'SELECT id, role FROM users WHERE username = ?', [username]).catch(() => null);
    if (!userRow) return res.status(404).json({ error: 'User tidak ditemukan' });
    if (userRow.role !== 'admin') return res.status(400).json({ error: 'User bukan admin' });
    await run(db, 'UPDATE users SET role = ? WHERE username = ?', ['member', username]);
    res.json({ ok: true, message: 'Admin didemote menjadi member' });
  } catch (err) {
    console.error('Admin demote error', err);
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`UKT server listening on http://localhost:${PORT}`);
  console.log('Run "node migrations.js" first if database not initialized.');
});
