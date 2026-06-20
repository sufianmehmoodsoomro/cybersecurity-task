const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, '../database.db'), (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
  } else {
    console.log('✅ Database connected');
  }
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT
  )`, (err) => {
    if (err) {
      console.error('Table error:', err.message);
    } else {
      console.log('✅ Users table ready');
    }
  });
});

function getUserVulnerable(username, callback) {
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  console.log('⚠️  Vulnerable Query:', query);
  db.all(query, callback);
}

function getUserSafe(username, callback) {
  const query = `SELECT * FROM users WHERE username = ?`;
  console.log('✅ Safe Query:', query);
  db.all(query, [username], callback);
}

function insertUser(username, password, email) {
  const query = `INSERT OR IGNORE INTO users (username, password, email) VALUES (?, ?, ?)`;
  db.run(query, [username, password, email]);
}

module.exports = { getUserVulnerable, getUserSafe, insertUser, db };