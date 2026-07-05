const jwt = require('jsonwebtoken');
const { get } = require('../utils/database');

const JWT_SECRET = process.env.JWT_SECRET || 'protek-dev-secret-change-in-production';

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  const token = auth.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Refresh user from DB to catch role/status changes
    const user = get(
      `SELECT u.id, u.first_name, u.last_name, u.email, u.phone, u.status, u.secondary_role_id,
              r.name as role, sr.name as secondary_role
       FROM users u
       LEFT JOIN roles r  ON u.role_id = r.id
       LEFT JOIN roles sr ON u.secondary_role_id = sr.id
       WHERE u.id = ?`,
      [decoded.id]
    );
    if (!user) return res.status(401).json({ error: 'User not found.' });
    if (user.status !== 'active') return res.status(403).json({ error: 'Account not active.' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

function requireOwner(req, res, next) {
  if (!req.user || req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Owner access required.' });
  }
  next();
}

module.exports = { signToken, requireAuth, requireOwner };
