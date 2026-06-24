// Called at server startup to ensure DB is ready
const { initDb } = require('./database');
const bcrypt = require('bcryptjs');
const { v4: uuid } = require('uuid');
const { get, run } = require('./database');

async function ensureOwner() {
  const existing = get(`SELECT u.id FROM users u JOIN roles r ON u.role_id = r.id WHERE r.name = 'owner'`);
  if (!existing) {
    const ownerRole = get('SELECT id FROM roles WHERE name = ?', ['owner']);
    if (ownerRole) {
      const hash = await bcrypt.hash('Admin@Protek2024!', 12);
      run(
        `INSERT INTO users (id, first_name, last_name, email, password_hash, role_id, status)
         VALUES (?, 'Admin', 'PROTEK', 'admin@protek.ca', ?, ?, 'active')`,
        [uuid(), hash, ownerRole.id]
      );
      console.log('✓ Owner account created: admin@protek.ca / Admin@Protek2024!');
    }
  }
}

async function startup() {
  await initDb();
  await ensureOwner();
}

module.exports = { startup };
