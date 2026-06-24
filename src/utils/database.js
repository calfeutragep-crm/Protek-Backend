const path = require('path');
const fs = require('fs');

let db = null;
let SQL = null;

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../../data/protek.db');

async function initDb() {
  if (!SQL) {
    SQL = await require('sql.js')();
  }

  // Ensure data dir exists
  const dataDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

  // Load or create DB
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  createSchema();
  seedRoles();
  return db;
}

function saveDb() {
  if (!db) return;
  const dataDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function createSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      password_hash TEXT NOT NULL,
      role_id INTEGER,
      requested_role_id INTEGER,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(role_id) REFERENCES roles(id)
    );

    CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      label TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      message TEXT,
      read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor_id TEXT,
      action TEXT,
      target_id TEXT,
      details TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);
  saveDb();
}

function seedRoles() {
  const roles = [
    [1, 'owner', 'Owner'],
    [2, 'setter', 'Setter'],
    [3, 'closer', 'Closer'],
    [4, 'manager', 'Installation Manager'],
    [5, 'tech', 'Technician'],
  ];
  const stmt = db.prepare('INSERT OR IGNORE INTO roles (id, name, label) VALUES (?, ?, ?)');
  roles.forEach(r => { stmt.run(r); });
  stmt.free();
  saveDb();
}

function getDb() {
  return db;
}

function query(sql, params = []) {
  if (!db) throw new Error('DB not initialized');
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function run(sql, params = []) {
  if (!db) throw new Error('DB not initialized');
  db.run(sql, params);
  saveDb();
}

function get(sql, params = []) {
  const rows = query(sql, params);
  return rows[0] || null;
}

module.exports = { initDb, getDb, query, run, get, saveDb };
