const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { v4: uuid } = require('uuid');
const { get, run, query } = require('../utils/database');
const { signToken } = require('../middleware/auth');
const { sendEmail } = require('../utils/email');

const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // 60 minutes (exigence utilisateur)

function hashResetToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}


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
    secondaryRole: u.secondary_role || null,
    status: u.status,
  });
}

// Echange le role actif <-> le role "en reserve" pour l'utilisateur courant. Appele par le
// frontend quand quelqu'un ayant un acces double CRM choisit au login le CRM qui NE correspond
// PAS a son role actuellement actif (voir roleCrmMode() cote frontend) : ca lui permet de
// "changer de CRM" sans creer une deuxieme session/token — requireAuth relit toujours role_id
// depuis la DB a chaque requete, donc l'echange prend effet immediatement partout.
function swapCrmRole(req, res) {
  const u = req.user;
  if (!u.secondary_role_id) {
    return res.status(400).json({ error: 'No secondary CRM access assigned.' });
  }
  const current = get('SELECT role_id, secondary_role_id FROM users WHERE id = ?', [u.id]);
  if (!current || !current.secondary_role_id) {
    return res.status(400).json({ error: 'No secondary CRM access assigned.' });
  }
  run('UPDATE users SET role_id = ?, secondary_role_id = ?, updated_at = datetime(\'now\') WHERE id = ?',
    [current.secondary_role_id, current.role_id, u.id]);
  const updated = get(
    `SELECT r.name as role, sr.name as secondary_role
     FROM users u
     LEFT JOIN roles r  ON u.role_id = r.id
     LEFT JOIN roles sr ON u.secondary_role_id = sr.id
     WHERE u.id = ?`,
    [u.id]
  );
  return res.json({ role: updated.role, secondaryRole: updated.secondary_role || null });
}

// POST /auth/forgot-password — etape 1/2 du flow "mot de passe oublie" (les deux CRM partagent
// le meme ecran de connexion/le meme backend, voir renderLogin() cote frontend). Reponse
// TOUJOURS identique que le compte existe ou non, pour ne jamais reveler par timing/contenu
// quels emails sont enregistres — seul l'envoi (ou non) de l'email differe en interne.
async function forgotPassword(req, res) {
  try {
    const { email } = req.body || {};
    if (!email || !String(email).trim()) {
      return res.status(400).json({ error: 'Email is required.' });
    }
    const user = get('SELECT id, first_name, email FROM users WHERE LOWER(email) = LOWER(?)', [String(email).trim()]);
    if (user) {
      // Un seul lien actif a la fois : toute demande d'un NOUVEAU lien invalide immediatement
      // les precedents encore non utilises pour ce compte (pas seulement au moment du reset —
      // voir aussi resetPassword ci-dessous pour l'invalidation post-usage).
      run(`UPDATE password_reset_tokens SET used_at = datetime('now') WHERE user_id = ? AND used_at IS NULL`, [user.id]);
      const rawToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString();
      run(
        `INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
        [uuid(), user.id, hashResetToken(rawToken), expiresAt]
      );
      const base = (process.env.FRONTEND_URL || 'https://eclectic-sorbet-d63488.netlify.app').split(',')[0].trim();
      const resetUrl = `${base}${base.includes('?') ? '&' : '?'}resetToken=${rawToken}`;
      sendEmail({
        to: user.email,
        subject: 'Protek CRM — Réinitialisation de mot de passe',
        text: `Bonjour ${user.first_name || ''},

`
          + `Une demande de réinitialisation de mot de passe a été faite pour ce compte.

`
          + `Cliquez sur le lien ci-dessous pour choisir un nouveau mot de passe (valide 60 minutes, usage unique) :
${resetUrl}

`
          + `Si vous n'êtes pas à l'origine de cette demande, ignorez cet email — votre mot de passe actuel reste inchangé.

`
          + `— Protek CRM`,
      }).catch(() => {});
    }
    return res.json({ message: "Si un compte existe avec cet email, un lien de réinitialisation vient d'être envoyé." });
  } catch (e) {
    console.error('forgotPassword error', e);
    return res.status(500).json({ error: 'Une erreur est survenue.' });
  }
}

// POST /auth/reset-password — etape 2/2. Le jeton brut recu par email est hashe puis compare au
// hash stocke (jamais l'inverse) ; verifie usage unique (used_at) et expiration (expires_at)
// avant d'ecrire le nouveau mot de passe.
async function resetPassword(req, res) {
  try {
    const { token, password } = req.body || {};
    if (!token || !password) {
      return res.status(400).json({ error: 'Token and new password are required.' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    const row = get('SELECT * FROM password_reset_tokens WHERE token_hash = ?', [hashResetToken(String(token))]);
    if (!row || row.used_at) {
      return res.status(400).json({ error: 'Ce lien de réinitialisation est invalide ou a déjà été utilisé.' });
    }
    if (new Date(row.expires_at).getTime() < Date.now()) {
      return res.status(400).json({ error: 'Ce lien de réinitialisation a expiré. Demandez-en un nouveau.' });
    }
    const hash = await bcrypt.hash(String(password), 12);
    run(`UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?`, [hash, row.user_id]);
    // Usage unique + invalide tous les AUTRES liens actifs du meme compte (exigence: apres
    // reinitialisation, tous les anciens liens deviennent invalides).
    run(`UPDATE password_reset_tokens SET used_at = datetime('now') WHERE user_id = ? AND used_at IS NULL`, [row.user_id]);
    return res.json({ message: 'Mot de passe réinitialisé. Vous pouvez maintenant vous connecter.' });
  } catch (e) {
    console.error('resetPassword error', e);
    return res.status(500).json({ error: 'Une erreur est survenue.' });
  }
}

module.exports = { register, login, me, swapCrmRole, forgotPassword, resetPassword };
