const { initDb, get, run } = require('./database');
const bcrypt = require('bcryptjs');
const { v4: uuid } = require('uuid');

async function seed() {
  await initDb();
  // Check if owner already exists
  const existing = get(`SELECT u.id FROM users u JOIN roles r ON u.role_id = r.id WHERE r.name = 'owner'`);
  if (existing) {
    console.log('✓ Owner account already exists.');
    process.exit(0);
  }
  const ownerRole = get('SELECT id FROM roles WHERE name = ?', ['owner']);
  if (!ownerRole) { console.error('Roles not seeded.'); process.exit(1); }
  const hash = await bcrypt.hash('Admin@Protek2024!', 12);
  run(
    `INSERT INTO users (id, first_name, last_name, email, password_hash, role_id, status)
     VALUES (?, 'Admin', 'PROTEK', 'admin@protek.ca', ?, ?, 'active')`,
    [uuid(), hash, ownerRole.id]
  );
  console.log('✓ Owner seeded: admin@protek.ca / Admin@Protek2024!');
  process.exit(0);
}

seed().catch(e => { console.error(e); process.exit(1); });
