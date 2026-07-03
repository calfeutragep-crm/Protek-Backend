const bcrypt = require('bcryptjs');
const { v4: uuid } = require('uuid');
const { get, run, query } = require('../utils/database');
const { signToken } = require('../middleware/auth');

async function register(req, res) {
  try {
    const { firstName, lastName, email, phone, password, requestedRole } = req.body;
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ error: 'First name, last name, email, and password are required.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    const existing = get('SELECT id FROM users WHERE LOWER(email) = LOWER(?)', [email]);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    // Le role n'est plus choisi par l'utilisateur a l'inscription: l'admin l'assigne
    // lui-meme au moment de l'approbation (voir approveUser dans users.controller.js).
    // Le frontend n'envoie plus requestedRole; on garde le support ici en compatibilite
    // au cas ou un appel externe le fournirait encore, mais on ne defaute plus a 'setter'.
    const roleRow = requestedRole ? get('SELECT id FROM roles WHERE name = ?', [requestedRole]) : null;
    const roleId = roleRow ? roleRow.id : null;

    const hash = await bcrypt.hash(password, 12);
    const id = uuid();
    run(
      `INSERT INTO users (id, first_name, last_name, email, phone, password_hash, role_id, requested_role_id, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
      [id, firstName, lastName, email.toLowerCase(), phone || null, hash, null, roleId]
    );

    // Notify owner
    const owner = get(`SELECT u.id FROM users u JOIN roles r ON u.role_id = r.id WHERE r.name = 'owner' LIMIT 1`);
    if (owner) {
      run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)',
        [uuid(), owner.id, `New registration: ${firstName} ${lastName} (${email}) — pending approval`]);
    }

    return res.status(201).json({ message: 'Registration successful. Awaiting owner approval.', status: 'pending' });
  } catch (e) {
    console.error('register error', e);
    return res.status(500).json({ error: 'Registration failed.' });
  }
}

async function login(req, res) {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    const user = get(
      `SELECT u.*, r.name as role FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE LOWER(u.email) = LOWER(?)`,
      [email]
    );
    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password.' });

    if (user.status === 'pending') {
      return res.status(403).json({ error: 'pending', message: 'Your account is awaiting approval.' });
    }
    if (user.status === 'rejected') {
      return res.status(403).json({ error: 'Your account has been rejected. Contact the owner.' });
    }
    if (user.status === 'suspended') {
      return res.status(403).json({ error: 'Your account has been suspended. Contact the owner.' });
    }

    const token = signToken(user);
    return res.json({
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        status: user.status,
      }
    });
  } catch (e) {
    console.error('login error', e);
    return res.status(500).json({ error: 'Login failed.' });
  }
}

function me(req, res) {
  const u = req.user;
  return res.json({
    id: u.id,
    firstName: u.first_name,
    lastName: u.last_name,
    email: u.email,
    phone: u.phone,
    role: u.role,
    status: u.status,
  });
}

module.exports = { register, login, me };
