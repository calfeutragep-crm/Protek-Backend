const path = require('path');
const fs = require('fs');
const { v4: uuid } = require('uuid');

let db = null;
let SQL = null;

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../../data/protek.db');

async function initDb() {
  if (!SQL) SQL = await require('sql.js')();
  const dataDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  createSchema();
  migrateNewColumns();
  seedChatChannels();
  backfillChatChannels();
  seedRoles();
  return db;
}

// db.export() serialise TOUTE la base sql.js en memoire a chaque appel, puis on l'ecrit sur
// disque — un cout proportionnel a la taille totale de la base (photos, notes, historique de
// TOUS les clients). Avant ce correctif, saveDb() s'executait de facon SYNCHRONE et IMMEDIATE
// apres CHAQUE run() — souvent plusieurs fois par requete (ex: creer un ticket + notifier N
// gestionnaires = N+1 exports d'affilee) — ce qui bloquait tout le event loop Node pendant
// plusieurs secondes des que la base a grossi. C'etait la cause du delai de 20-30s en cliquant
// sur un bouton/icone. On regroupe maintenant les sauvegardes (debounce) : plusieurs run()
// rapproches ne declenchent qu'un seul export+ecriture, avec un delai maximum de securite pour
// ne jamais retarder la persistance de plus de ~1.5s (utile en cas de crash/redeploiement).
let saveTimer = null;
let maxWaitTimer = null;
let saveDirty = false;
const SAVE_DEBOUNCE_MS = 300;
const SAVE_MAX_WAIT_MS = 1500;

function flushDbSync() {
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  if (maxWaitTimer) { clearTimeout(maxWaitTimer); maxWaitTimer = null; }
  if (!db || !saveDirty) return;
  const dataDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
  saveDirty = false;
}

function saveDb() {
  if (!db) return;
  saveDirty = true;
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(flushDbSync, SAVE_DEBOUNCE_MS);
  if (!maxWaitTimer) maxWaitTimer = setTimeout(flushDbSync, SAVE_MAX_WAIT_MS);
}

// Toujours persister avant que le process ne s'arrete (redeploiement Railway, crash gracieux, etc.)
process.on('SIGTERM', flushDbSync);
process.on('SIGINT', flushDbSync);
process.on('beforeExit', flushDbSync);

function createSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      label TEXT NOT NULL
    );
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
      notify_email TEXT,
      notify_phone TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(role_id) REFERENCES roles(id)
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
    CREATE TABLE IF NOT EXISTS assignments (
      setter_id TEXT PRIMARY KEY,
      closer_id TEXT,
      FOREIGN KEY(setter_id) REFERENCES users(id),
      FOREIGN KEY(closer_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS leads (
      id TEXT PRIMARY KEY,
      first_name TEXT,
      last_name TEXT,
      phone TEXT,
      email TEXT,
      address TEXT,
      city TEXT,
      postal TEXT,
      notes TEXT,
      status TEXT DEFAULT 'Scheduled',
      setter_id TEXT,
      closer_id TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(setter_id) REFERENCES users(id),
      FOREIGN KEY(closer_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS appointments (
      id TEXT PRIMARY KEY,
      lead_id TEXT,
      setter_id TEXT,
      closer_id TEXT,
      appt_date TEXT,
      appt_hour INTEGER DEFAULT 14,
      status TEXT DEFAULT 'Scheduled',
      notes TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(lead_id) REFERENCES leads(id),
      FOREIGN KEY(setter_id) REFERENCES users(id),
      FOREIGN KEY(closer_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS deals (
      id TEXT PRIMARY KEY,
      appointment_id TEXT,
      closer_id TEXT,
      setter_id TEXT,
      client_name TEXT,
      address TEXT,
      city TEXT,
      postal TEXT,
      phone TEXT,
      email TEXT,
      price REAL,
      payment_method TEXT,
      footage_total REAL,
      footage_white REAL,
      footage_black REAL,
      footage_wheat REAL,
      footage_other TEXT,
      ladder_height TEXT,
      install_date TEXT,
      work_front TEXT,
      work_right TEXT,
      work_left TEXT,
      work_rear TEXT,
      color_white TEXT,
      color_black TEXT,
      color_wheat TEXT,
      color_other TEXT,
      notes TEXT,
      photo_urls TEXT DEFAULT '[]',
      status TEXT DEFAULT 'Pending Installation',
      tech_id TEXT,
      obstacles_to_remove TEXT,
      tools_needed TEXT,
      tools_notes TEXT,
      ad_lead_id TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(appointment_id) REFERENCES appointments(id),
      FOREIGN KEY(closer_id) REFERENCES users(id),
      FOREIGN KEY(setter_id) REFERENCES users(id),
      FOREIGN KEY(tech_id) REFERENCES users(id),
      FOREIGN KEY(ad_lead_id) REFERENCES ad_leads(id)
    );
    CREATE TABLE IF NOT EXISTS ad_leads (
      id TEXT PRIMARY KEY,
      source TEXT,
      first_name TEXT,
      last_name TEXT,
      phone TEXT,
      email TEXT,
      notes TEXT,
      status TEXT NOT NULL DEFAULT 'New',
      closer_id TEXT,
      contacted_at TEXT,
      appt_date TEXT,
      appt_hour INTEGER,
      created_by TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(closer_id) REFERENCES users(id),
      FOREIGN KEY(created_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS ad_lead_cost_requests (
      id TEXT PRIMARY KEY,
      ad_lead_id TEXT,
      closer_id TEXT,
      client_name TEXT,
      footage_total TEXT,
      ladder_type TEXT,
      tools_needed TEXT,
      obstacles_to_remove TEXT,
      photo_urls TEXT DEFAULT '[]',
      cost REAL,
      cost_status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(ad_lead_id) REFERENCES ad_leads(id),
      FOREIGN KEY(closer_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS chat_channels (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS chat_messages (
      id TEXT PRIMARY KEY,
      sender_id TEXT,
      channel_id TEXT,
      type TEXT NOT NULL DEFAULT 'user',
      body TEXT NOT NULL,
      image_url TEXT,
      appointment_id TEXT,
      client_name TEXT,
      footage_total TEXT,
      ladder_type TEXT,
      tools_needed TEXT,
      obstacles_to_remove TEXT,
      photo_urls TEXT DEFAULT '[]',
      cost REAL,
      cost_status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(sender_id) REFERENCES users(id),
      FOREIGN KEY(channel_id) REFERENCES chat_channels(id)
    );
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      endpoint TEXT NOT NULL UNIQUE,
      p256dh TEXT NOT NULL,
      auth TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS installation_tickets (
      id TEXT PRIMARY KEY,
      deal_id TEXT,
      appointment_id TEXT,
      closer_id TEXT,
      setter_id TEXT,
      client_name TEXT NOT NULL,
      address TEXT,
      city TEXT,
      postal TEXT,
      phone TEXT,
      email TEXT,
      footage_total REAL,
      footage_white REAL,
      footage_black REAL,
      footage_wheat REAL,
      footage_other TEXT,
      ladder_height TEXT,
      work_front TEXT,
      work_right TEXT,
      work_left TEXT,
      work_rear TEXT,
      color_white TEXT,
      color_black TEXT,
      color_wheat TEXT,
      color_other TEXT,
      notes TEXT,
      photo_urls TEXT DEFAULT '[]',
      preferred_install_date TEXT,
      scheduled_install_date TEXT,
      tech_id TEXT,
      status TEXT DEFAULT 'New',
      obstacles_to_remove TEXT,
      tools_needed TEXT,
      tools_notes TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(deal_id) REFERENCES deals(id),
      FOREIGN KEY(appointment_id) REFERENCES appointments(id),
      FOREIGN KEY(closer_id) REFERENCES users(id),
      FOREIGN KEY(setter_id) REFERENCES users(id),
      FOREIGN KEY(tech_id) REFERENCES users(id)
    );
  `);
  saveDb();
}

// --- Migration : ajoute les colonnes manquantes sur une base déjà existante ---
// "CREATE TABLE IF NOT EXISTS" ne modifie pas une table qui existe déjà en prod,
// donc on vérifie/ajoute les nouvelles colonnes ici à chaque démarrage (idempotent).
function columnExists(table, column) {
  const res = db.exec(`PRAGMA table_info(${table})`);
  if (!res[0]) return false;
  return res[0].values.some(row => row[1] === column);
}

function migrateNewColumns() {
  const migrations = [
    { table: 'deals',                column: 'obstacles_to_remove', def: 'TEXT' },
    { table: 'deals',                column: 'tools_needed',        def: 'TEXT' },
    { table: 'deals',                column: 'tools_notes',         def: 'TEXT' },
    { table: 'installation_tickets', column: 'obstacles_to_remove', def: 'TEXT' },
    { table: 'installation_tickets', column: 'tools_needed',        def: 'TEXT' },
    { table: 'installation_tickets', column: 'tools_notes',         def: 'TEXT' },
    { table: 'chat_messages',        column: 'image_url',           def: 'TEXT' },
    { table: 'chat_messages',        column: 'channel_id',          def: 'TEXT' },
    { table: 'chat_messages',        column: 'appointment_id',      def: 'TEXT' },
    { table: 'chat_messages',        column: 'client_name',         def: 'TEXT' },
    { table: 'chat_messages',        column: 'footage_total',       def: 'TEXT' },
    { table: 'chat_messages',        column: 'ladder_type',         def: 'TEXT' },
    { table: 'chat_messages',        column: 'tools_needed',        def: 'TEXT' },
    { table: 'chat_messages',        column: 'obstacles_to_remove', def: 'TEXT' },
    { table: 'chat_messages',        column: 'photo_urls',          def: "TEXT DEFAULT '[]'" },
    { table: 'chat_messages',        column: 'cost',                def: 'REAL' },
    { table: 'chat_messages',        column: 'cost_status',         def: "TEXT DEFAULT 'pending'" },
    { table: 'users',                column: 'notify_email',        def: 'TEXT' },
    { table: 'users',                column: 'notify_phone',        def: 'TEXT' },
    { table: 'deals',                column: 'ad_lead_id',          def: 'TEXT' },
    { table: 'deals',                column: 'city',                def: 'TEXT' },
    { table: 'deals',                column: 'postal',              def: 'TEXT' },
    { table: 'installation_tickets', column: 'city',                def: 'TEXT' },
    { table: 'installation_tickets', column: 'postal',              def: 'TEXT' },
    // Acces CRM secondaire — permet a un membre (ex: closer porte-a-porte) d'avoir AUSSI un
    // role dans l'autre CRM (ex: lead_closer). Un seul role est "actif" (role_id, celui qui
    // determine les permissions serveur) a la fois ; l'autre reste "en reserve" ici. Voir
    // POST /auth/swap-crm-role : quand l'utilisateur choisit au login le CRM correspondant a
    // sa reserve, le serveur echange role_id <-> secondary_role_id.
    { table: 'users',                column: 'secondary_role_id',   def: 'INTEGER REFERENCES roles(id)' },
    // chat_messages n'avait pas de colonne updated_at — le /poll d'un closer ne detectait donc
    // jamais qu'un cost_request existant venait de recevoir son prix (setCostRequestPrice ne
    // faisait qu'un UPDATE, invisible pour une requete filtrant sur created_at). Voir aussi le
    // WHERE du poll de chat_messages plus bas et setCostRequestPrice() dans chat.controller.js.
    { table: 'chat_messages',        column: 'updated_at',          def: 'TEXT' },
    // Id du contact GoHighLevel a l'origine du lead (rempli par le webhook /webhooks/ad-leads
    // quand la source est GHL) — permet de retrouver l'opportunite correspondante cote GHL et
    // d'y repousser les changements de statut (RDV booke -> stage CONFIRMATION, deal signe ->
    // won). Voir src/utils/ghlClient.js.
    { table: 'ad_leads',              column: 'ghl_contact_id',      def: 'TEXT' },
  ];
  let changed = false;
  migrations.forEach(({ table, column, def }) => {
    if (!columnExists(table, column)) {
      db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${def}`);
      console.log(`✓ Migration: colonne ajoutée ${table}.${column}`);
      changed = true;
    }
  });
  if (changed) saveDb();
}

// --- Sous-chats par defaut : Team Rive-Sud, Cost, Liste de streets ---
// Idempotent grace a UNIQUE(name) + INSERT OR IGNORE : ne recree rien si deja present.
function seedChatChannels() {
  const defaults = ['Team Rive-Sud', 'Cost', 'Liste de streets'];
  const stmt = db.prepare('INSERT OR IGNORE INTO chat_channels (id, name) VALUES (?, ?)');
  defaults.forEach(name => stmt.run([uuid(), name]));
  stmt.free();
  saveDb();
}

// Les messages envoyes avant l'ajout des canaux n'ont pas de channel_id — on les rattache
// au canal "Team Rive-Sud" par defaut pour ne rien perdre.
function backfillChatChannels() {
  const defaultChannel = get('SELECT id FROM chat_channels WHERE name = ?', ['Team Rive-Sud']);
  if (!defaultChannel) return;
  db.run('UPDATE chat_messages SET channel_id = ? WHERE channel_id IS NULL', [defaultChannel.id]);
  saveDb();
}

function seedRoles() {
  const roles = [
    [1, 'owner', 'Owner'],
    [2, 'setter', 'Setter'],
    [3, 'closer', 'Closer'],
    [4, 'manager', 'Installation Manager'],
    [5, 'tech', 'Technician'],
    [6, 'lead_marketing', 'Marketing (Leads)'],
    [7, 'lead_closer', 'Lead Closer'],
  ];
  const stmt = db.prepare('INSERT OR IGNORE INTO roles (id, name, label) VALUES (?, ?, ?)');
  roles.forEach(r => stmt.run(r));
  stmt.free();
  saveDb();
}

function getDb() { return db; }

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
  return query(sql, params)[0] || null;
}

module.exports = { initDb, getDb, query, run, get, saveDb };
