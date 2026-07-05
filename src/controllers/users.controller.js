const { v4: uuid } = require('uuid');
const { query, get, run } = require('../utils/database');

function getUsers(req, res) {
  const { status } = req.query;
  let sql = `SELECT u.id, u.first_name, u.last_name, u.email, u.phone, u.status, u.created_at,
              u.secondary_role_id,
              r.name as role, r.label as role_label,
              rr.name as requested_role, rr.label as requested_role_label,
              sr.name as secondary_role, sr.label as secondary_role_label
             FROM users u
             LEFT JOIN roles r ON u.role_id = r.id
             LEFT JOIN roles rr ON u.requested_role_id = rr.id
             LEFT JOIN roles sr ON u.secondary_role_id = sr.id
             WHERE r.name != 'owner' OR r.name IS NULL`;
  const params = [];
  if (status) { sql += ' AND u.status = ?'; params.push(status); }
  sql += ' ORDER BY u.created_at DESC';
  const users = query(sql, params);
  return res.json(users);
}

function getUser(req, res) {
  const u = get(
    `SELECT u.*, r.name as role FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE u.id = ?`,
    [req.params.id]
  );
  if (!u) return res.status(404).json({ error: 'User not found.' });
  return res.json(u);
}

function approveUser(req, res) {
  const { id } = req.params;
  const { roleId, secondaryRoleId } = req.body;
  const u = get('SELECT * FROM users WHERE id = ?', [id]);
  if (!u) return res.status(404).json({ error: 'User not found.' });
  const targetRoleId = roleId || u.requested_role_id || 2;
  run('UPDATE users SET status = ?, role_id = ?, secondary_role_id = ?, updated_at = datetime(\'now\') WHERE id = ?',
    ['active', targetRoleId, secondaryRoleId || null, id]);
  run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)',
    [uuid(), id, 'Your account has been approved! You can now log in.']);
  run('INSERT INTO audit_logs (id, actor_id, action, target_id, details) VALUES (?, ?, ?, ?, ?)',
    [uuid(), req.user.id, 'approve_user', id, JSON.stringify({ roleId: targetRoleId, secondaryRoleId: secondaryRoleId || null })]);
  return res.json({ message: 'User approved.' });
}

function rejectUser(req, res) {
  const { id } = req.params;
  run('UPDATE users SET status = ?, updated_at = datetime(\'now\') WHERE id = ?', ['rejected', id]);
  run('INSERT INTO audit_logs (id, actor_id, action, target_id, details) VALUES (?, ?, ?, ?, ?)',
    [uuid(), req.user.id, 'reject_user', id, '{}']);
  run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)',
    [uuid(), id, 'Your registration has been declined. Contact the owner for more information.']);
  return res.json({ message: 'User rejected.' });
}

function suspendUser(req, res) {
  const { id } = req.params;
  run('UPDATE users SET status = ?, updated_at = datetime(\'now\') WHERE id = ?', ['suspended', id]);
  run('INSERT INTO audit_logs (id, actor_id, action, target_id, details) VALUES (?, ?, ?, ?, ?)',
    [uuid(), req.user.id, 'suspend_user', id, '{}']);
  return res.json({ message: 'User suspended.' });
}

function reactivateUser(req, res) {
  const { id } = req.params;
  run('UPDATE users SET status = ?, updated_at = datetime(\'now\') WHERE id = ?', ['active', id]);
  run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)',
    [uuid(), id, 'Your account has been reactivated.']);
  run('INSERT INTO audit_logs (id, actor_id, action, target_id, details) VALUES (?, ?, ?, ?, ?)',
    [uuid(), req.user.id, 'reactivate_user', id, '{}']);
  return res.json({ message: 'User reactivated.' });
}

function updateUser(req, res) {
  const { id } = req.params;
  const { roleId, status, secondaryRoleId } = req.body;
  const sets = []; const params = [];
  if (roleId !== undefined) { sets.push('role_id = ?'); params.push(roleId); }
  if (status !== undefined) { sets.push('status = ?'); params.push(status); }
  // secondaryRoleId: null/'' efface l'acces CRM secondaire (retire la reserve), sinon l'assigne.
  if (secondaryRoleId !== undefined) { sets.push('secondary_role_id = ?'); params.push(secondaryRoleId || null); }
  if (!sets.length) return res.status(400).json({ error: 'Nothing to update.' });
  sets.push("updated_at = datetime('now')");
  params.push(id);
  run('UPDATE users SET ' + sets.join(', ') + ' WHERE id = ?', params);
  run('INSERT INTO audit_logs (id, actor_id, action, target_id, details) VALUES (?, ?, ?, ?, ?)',
    [uuid(), req.user.id, 'update_user', id, JSON.stringify(req.body)]);
  return res.json({ message: 'User updated.' });
}

function getRoles(req, res) {
  return res.json(query('SELECT * FROM roles ORDER BY id'));
}

function getPermissions(req, res) { return res.json([]); }
function getRolePermissions(req, res) { return res.json([]); }
function updateRolePermissions(req, res) { return res.json({ message: 'Updated.' }); }

function getNotifications(req, res) {
  const notes = query(
    'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
    [req.user.id]
  );
  return res.json(notes);
}

function markNotificationRead(req, res) {
  run('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  return res.json({ message: 'Marked read.' });
}

function markAllNotificationsRead(req, res) {
  run('UPDATE notifications SET read = 1 WHERE user_id = ?', [req.user.id]);
  return res.json({ message: 'All marked read.' });
}

function getAuditLogs(req, res) {
  const logs = query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100');
  return res.json(logs);
}

function getTeam(req, res) {
  const users = query(
    `SELECT u.id, u.first_name, u.last_name, u.email, u.phone, u.status,
      r.name as role
     FROM users u
     LEFT JOIN roles r ON u.role_id = r.id
     WHERE u.status = 'active'
     ORDER BY r.name, u.first_name`
  );
  return res.json(users);
}

module.exports = {
  getUsers, getUser, approveUser, rejectUser, suspendUser, reactivateUser, updateUser,
  getRoles, getPermissions, getRolePermissions, updateRolePermissions,
  getNotifications, markNotificationRead, markAllNotificationsRead, getAuditLogs, getTeam,
};
