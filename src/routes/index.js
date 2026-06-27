const express = require('express');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { v4: uuid } = require('uuid');
const cloudinary = require('cloudinary').v2;

const { register, login, me } = require('../controllers/auth.controller');
const {
  getUsers, getUser, approveUser, rejectUser, suspendUser, reactivateUser, updateUser,
  getRoles, getPermissions, getRolePermissions, updateRolePermissions,
  getNotifications, markNotificationRead, markAllNotificationsRead, getAuditLogs,
} = require('../controllers/users.controller');
const { getTickets, getTicket, updateTicket, createTicketFromDeal, syncTicketFromDeal } = require('../controllers/tickets.controller');
const { requireAuth, requireOwner } = require('../middleware/auth');
const { query, get, run } = require('../utils/database');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDFs allowed'));
    }
  },
});

const router = express.Router();
const loginLimiter    = rateLimit({ windowMs: 15*60*1000, max: 10 });
const registerLimiter = rateLimit({ windowMs: 60*60*1000, max: 5  });

function uploadToCloudinary(buffer, originalname, folder) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: `protek/${folder}`, resource_type: 'auto', use_filename: true },
      (error, result) => { if (error) reject(error); else resolve(result); }
    );
    stream.end(buffer);
  });
}

function requireManagerOrOwner(req, res, next) {
  if (req.user.role !== 'manager' && req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Manager or owner access required.' });
  }
  next();
}
function requireTicketAccess(req, res, next) {
  const r = req.user.role;
  if (r !== 'owner' && r !== 'manager' && r !== 'tech') {
    return res.status(403).json({ error: 'Access denied.' });
  }
  next();
}

router.post('/auth/register', registerLimiter, register);
router.post('/auth/login',    loginLimiter,    login);
router.get ('/auth/me',       requireAuth,     me);

router.post('/upload', requireAuth, upload.array('photos', 10), async (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded.' });
  }
  try {
    const uploads = await Promise.all(
      req.files.map(f => uploadToCloudinary(f.buffer, f.originalname, 'deals'))
    );
    const urls = uploads.map(u => ({ url: u.secure_url, public_id: u.public_id, type: u.resource_type }));
    return res.json({ urls });
  } catch (e) {
    console.error('Cloudinary upload error:', e);
    return res.status(500).json({ error: 'Upload failed: ' + e.message });
  }
});

router.get   ('/notifications',          requireAuth, getNotifications);
router.patch ('/notifications/:id/read', requireAuth, markNotificationRead);
router.patch ('/notifications/read-all', requireAuth, markAllNotificationsRead);

router.get  ('/users',                requireAuth, requireOwner, getUsers);
router.get  ('/users/:id',            requireAuth, requireOwner, getUser);
router.patch('/users/:id',            requireAuth, requireOwner, updateUser);
router.post ('/users/:id/approve',    requireAuth, requireOwner, approveUser);
router.post ('/users/:id/reject',     requireAuth, requireOwner, rejectUser);
router.post ('/users/:id/suspend',    requireAuth, requireOwner, suspendUser);
router.post ('/users/:id/reactivate', requireAuth, requireOwner, reactivateUser);

router.get('/users/team', requireAuth, (req, res) => {
  const rows = query(
    `SELECT u.id, u.first_name, u.last_name, u.email, u.phone, u.status,
            r.name as role, r.label as role_label
     FROM users u LEFT JOIN roles r ON u.role_id = r.id
     WHERE u.status = 'active' ORDER BY r.id, u.first_name`
  );
  return res.json(rows);
});

router.get('/roles',                      requireAuth, getRoles);
router.get('/permissions',                requireAuth, requireOwner, getPermissions);
router.get('/roles/:roleId/permissions',  requireAuth, requireOwner, getRolePermissions);
router.put('/roles/:roleId/permissions',  requireAuth, requireOwner, updateRolePermissions);
router.get('/audit-logs',                 requireAuth, requireOwner, getAuditLogs);

router.get('/assignments', requireAuth, (req, res) => {
  const rows = query('SELECT setter_id, closer_id FROM assignments');
  const map = {};
  rows.forEach(r => { map[r.setter_id] = r.closer_id; });
  return res.json(map);
});

router.put('/assignments', requireAuth, (req, res) => {
  const { setterId, closerId } = req.body;
  if (!setterId) return res.status(400).json({ error: 'setterId required.' });
  run(
    'INSERT INTO assignments (setter_id, closer_id) VALUES (?, ?) ON CONFLICT(setter_id) DO UPDATE SET closer_id = excluded.closer_id',
    [setterId, closerId || null]
  );
  return res.json({ message: 'Assignment saved.' });
});

router.get('/leads', requireAuth, (req, res) => {
  const rows = query(
    `SELECT l.*,
       s.first_name || ' ' || s.last_name AS setter_name_full,
       c.first_name || ' ' || c.last_name AS closer_name
     FROM leads l
     LEFT JOIN users s ON l.setter_id = s.id
     LEFT JOIN users c ON l.closer_id = c.id
     ORDER BY l.created_at DESC`
  );
  return res.json(rows);
});

router.post('/leads', requireAuth, (req, res) => {
  const { firstName, lastName, phone, email, address, city, postal, notes, closerId, apptDate, apptHour } = req.body;
  if (!firstName || !lastName || !phone) {
    return res.status(400).json({ error: 'firstName, lastName, phone required.' });
  }
  const leadId = uuid();
  const setterId = req.user.id;
  run(
    `INSERT INTO leads (id, first_name, last_name, phone, email, address, city, postal, notes, setter_id, closer_id, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Scheduled')`,
    [leadId, firstName, lastName, phone, email || null, address || null, city || null, postal || null, notes || null, setterId, closerId || null]
  );
  if (apptDate) {
    const apptId = uuid();
    run(
      `INSERT INTO appointments (id, lead_id, setter_id, closer_id, appt_date, appt_hour, status, notes)
       VALUES (?, ?, ?, ?, ?, ?, 'Scheduled', ?)`,
      [apptId, leadId, setterId, closerId || null, apptDate, parseInt(apptHour) || 14, notes || null]
    );
    if (closerId) {
      const setter = get('SELECT first_name, last_name FROM users WHERE id = ?', [setterId]);
      const setterName = setter ? `${setter.first_name} ${setter.last_name}` : 'Un setter';
      run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)', [
        uuid(), closerId,
        `Nouveau RDV: ${firstName} ${lastName} le ${apptDate} — posé par ${setterName}`,
      ]);
    }
  }
  return res.status(201).json({ message: 'Lead created.', id: leadId });
});

router.get('/appointments', requireAuth, (req, res) => {
  const rows = query(
    `SELECT a.*,
       l.first_name || ' ' || l.last_name AS name,
       l.phone, l.address, l.city,
       s.first_name || ' ' || s.last_name AS setter_name,
       c.first_name || ' ' || c.last_name AS closer_name
     FROM appointments a
     LEFT JOIN leads l ON a.lead_id   = l.id
     LEFT JOIN users s ON a.setter_id = s.id
     LEFT JOIN users c ON a.closer_id = c.id
     ORDER BY a.appt_date DESC, a.appt_hour DESC`
  );
  return res.json(rows);
});

router.patch('/appointments/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { status, apptDate, apptHour } = req.body;
  const appt = get('SELECT * FROM appointments WHERE id = ?', [id]);
  if (!appt) return res.status(404).json({ error: 'Appointment not found.' });
  const sets = [];
  const params = [];
  if (status !== undefined)   { sets.push('status = ?');    params.push(status); }
  if (apptDate !== undefined) { sets.push('appt_date = ?'); params.push(apptDate); }
  if (apptHour !== undefined) { sets.push('appt_hour = ?'); params.push(parseInt(apptHour)); }
  if (sets.length) {
    sets.push("updated_at = datetime('now')");
    params.push(id);
    run(`UPDATE appointments SET ${sets.join(', ')} WHERE id = ?`, params);
  }
  if (status === 'Closed Won') {
    if (appt.lead_id) {
      run("UPDATE leads SET status = 'Closed Won', updated_at = datetime('now') WHERE id = ?", [appt.lead_id]);
    }
    const deal = get('SELECT * FROM deals WHERE appointment_id = ?', [id]);
    if (deal) createTicketFromDeal(deal);
  }
  return res.json({ message: 'Appointment updated.' });
});

router.get('/deals', requireAuth, (req, res) => {
  const rows = query(
    `SELECT d.*,
       c.first_name  || ' ' || c.last_name  AS closer_name,
       s.first_name  || ' ' || s.last_name  AS setter_name,
       te.first_name || ' ' || te.last_name AS tech_name
     FROM deals d
     LEFT JOIN users c  ON d.closer_id = c.id
     LEFT JOIN users s  ON d.setter_id = s.id
     LEFT JOIN users te ON d.tech_id   = te.id
     ORDER BY d.created_at DESC`
  );
  rows.forEach(d => {
    try { d.photo_urls = JSON.parse(d.photo_urls || '[]'); } catch { d.photo_urls = []; }
  });
  return res.json(rows);
});

router.post('/deals', requireAuth, (req, res) => {
  const {
    appointmentId, clientName, address, phone, email,
    price, paymentMethod,
    footageTotal, footageOther,
    ladderHeight, installDate,
    workFront, workRight, workLeft, workRear,
    notes, photoUrls,
    closerIdOverride, setterIdOverride,
  } = req.body;
  if (!clientName) return res.status(400).json({ error: 'clientName required.' });
  const dealId = uuid();
  const closerId = closerIdOverride || (req.user.role === 'closer' ? req.user.id : null);
  let setterId = setterIdOverride || null;
  if (!setterId && appointmentId) {
    const appt = get('SELECT setter_id FROM appointments WHERE id = ?', [appointmentId]);
    if (appt) setterId = appt.setter_id;
  }
  const photoUrlsJson = JSON.stringify(Array.isArray(photoUrls) ? photoUrls : []);
  run(
    `INSERT INTO deals (
       id, appointment_id, closer_id, setter_id,
       client_name, address, phone, email,
       price, payment_method,
       footage_total, footage_other,
       ladder_height, install_date,
       work_front, work_right, work_left, work_rear,
       notes, photo_urls, status
     ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      dealId, appointmentId || null, closerId, setterId,
      clientName, address || null, phone || null, email || null,
      parseFloat(price) || 0, paymentMethod || null,
      parseFloat(footageTotal) || 0,
      footageOther || null,
      ladderHeight || null, installDate || null,
      workFront || null, workRight || null, workLeft || null, workRear || null,
      notes || null, photoUrlsJson, 'Pending Installation',
    ]
  );
  const newDeal = get('SELECT * FROM deals WHERE id = ?', [dealId]);
  if (newDeal) createTicketFromDeal(newDeal);
  return res.status(201).json({ message: 'Deal created.', id: dealId });
});

router.patch('/deals/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { status, techId, installDate, photoUrls } = req.body;
  const deal = get('SELECT * FROM deals WHERE id = ?', [id]);
  if (!deal) return res.status(404).json({ error: 'Deal not found.' });
  const sets = [];
  const params = [];
  if (status !== undefined)      { sets.push('status = ?');       params.push(status); }
  if (techId !== undefined)      { sets.push('tech_id = ?');      params.push(techId || null); }
  if (installDate !== undefined) { sets.push('install_date = ?'); params.push(installDate || null); }
  if (photoUrls !== undefined)   { sets.push('photo_urls = ?');   params.push(JSON.stringify(photoUrls)); }
  if (!sets.length) return res.status(400).json({ error: 'Nothing to update.' });
  sets.push("updated_at = datetime('now')");
  params.push(id);
  run(`UPDATE deals SET ${sets.join(', ')} WHERE id = ?`, params);
  const updatedDeal = get('SELECT * FROM deals WHERE id = ?', [id]);
  if (updatedDeal) syncTicketFromDeal(updatedDeal);
  const ticket = get('SELECT id FROM installation_tickets WHERE deal_id = ?', [id]);
  if (ticket) {
    const tSets = [];
    const tParams = [];
    if (techId !== undefined)      { tSets.push('tech_id = ?');                tParams.push(techId || null); }
    if (installDate !== undefined) { tSets.push('scheduled_install_date = ?'); tParams.push(installDate || null); }
    if (status === 'Completed')    { tSets.push('status = ?');                 tParams.push('Completed'); }
    if (tSets.length) {
      tSets.push("updated_at = datetime('now')");
      tParams.push(ticket.id);
      run(`UPDATE installation_tickets SET ${tSets.join(', ')} WHERE id = ?`, tParams);
    }
  }
  return res.json({ message: 'Deal updated.' });
});

router.get  ('/tickets',     requireAuth, requireTicketAccess,   getTickets);
router.get  ('/tickets/:id', requireAuth, requireTicketAccess,   getTicket);
router.patch('/tickets/:id', requireAuth, requireManagerOrOwner, updateTicket);

router.get('/poll', requireAuth, (req, res) => {
  const since = req.query.since || new Date(Date.now() - 30000).toISOString();
  const role = req.user.role;
  let newTickets = [];
  if (role === 'manager' || role === 'owner') {
    newTickets = query(
      `SELECT t.*,
         tech.first_name || ' ' || tech.last_name AS tech_name,
         cl.first_name   || ' ' || cl.last_name   AS closer_name,
         st.first_name   || ' ' || st.last_name   AS setter_name
       FROM installation_tickets t
       LEFT JOIN users tech ON t.tech_id   = tech.id
       LEFT JOIN users cl   ON t.closer_id = cl.id
       LEFT JOIN users st   ON t.setter_id = st.id
       WHERE t.updated_at > ?
       ORDER BY t.created_at DESC`,
      [since]
    );
    newTickets.forEach(t => {
      try { t.photo_urls = JSON.parse(t.photo_urls || '[]'); } catch { t.photo_urls = []; }
    });
  }
  let updatedJobs = [];
  if (role === 'tech') {
    updatedJobs = query(
      `SELECT t.*,
         cl.first_name || ' ' || cl.last_name AS closer_name,
         st.first_name || ' ' || st.last_name AS setter_name
       FROM installation_tickets t
       LEFT JOIN users cl ON t.closer_id = cl.id
       LEFT JOIN users st ON t.setter_id = st.id
       WHERE t.tech_id = ? AND t.updated_at > ?
       ORDER BY t.scheduled_install_date ASC`,
      [req.user.id, since]
    );
    updatedJobs.forEach(t => {
      try { t.photo_urls = JSON.parse(t.photo_urls || '[]'); } catch { t.photo_urls = []; }
    });
  }
  const unreadCount = get(
    'SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND read = 0',
    [req.user.id]
  );
  return res.json({
    newTickets,
    updatedJobs,
    unreadNotifications: unreadCount ? unreadCount.c : 0,
    serverTime: new Date().toISOString(),
  });
});

module.exports = router;
