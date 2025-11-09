CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  name TEXT,
  role TEXT NOT NULL CHECK (role IN ('admin','member')),
  created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  jenis TEXT NOT NULL,
  tipe TEXT NOT NULL CHECK (tipe IN ('pemasukan','pengeluaran')),
  jumlah INTEGER NOT NULL,
  date TEXT NOT NULL,
  desc TEXT,
  by_user TEXT,
  created_at TEXT DEFAULT (datetime('now','localtime'))
);
