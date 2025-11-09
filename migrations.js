// migrations.js
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const DB_FILE = './ukt.sqlite';

async function run() {
  const db = new sqlite3.Database(DB_FILE);

  const sql = fs.readFileSync('./migrations.sql', 'utf8');
  db.exec(sql, async (err) => {
    if (err) {
      console.error('Gagal migrasi:', err);
      process.exit(1);
    }

    // Pastikan admin default ada
    db.get("SELECT id FROM users WHERE username = ?", ['admin'], async (err, row) => {
      if (err) { console.error(err); process.exit(1); }
      if (!row) {
        const hash = await bcrypt.hash('Admin@123', 10);
        db.run("INSERT INTO users (username,password,name,role) VALUES (?,?,?,?)",
          ['admin', hash, 'Admin Team D', 'admin'], function(err){
            if (err) console.error('Gagal buat admin:', err);
            else console.log('Admin default dibuat -> username: admin | password: Admin@123');
            db.close();
          });
      } else {
        console.log('Admin sudah ada, tidak membuat akun baru.');
        db.close();
      }
    });
  });
}

run();
