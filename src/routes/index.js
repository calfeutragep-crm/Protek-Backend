const express = require('express');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { v4: uuid } = require('uuid');
const cloudinary = require('cloudinary').v2;

const { register, login, me, swapCrmRole } = require('../controllers/auth.controller');
const {
  getUsers, getUser, approveUser, rejectUser, suspendUser, reactivateUser, updateUser,
  getRoles, getPermissions, getRolePermissions, updateRolePermissions,
  getNotifications, markNotificationRead, markAllNotificationsRead, getAuditLogs,
} = require('../controllers/users.controller');
const { getTickets, getTicket, updateTicket, createTicketFromDeal, syncTicketFromDeal } = require('../controllers/tickets.controller');
const {
  getChatChannels, createChatChannel,
  getChatMessages, postChatMessage, postSystemMessage, setCostRequestPrice,
} = require('../controllers/chat.controller');
const { requireAuth, requireOwner } = require('../middleware/auth');
const { query, get, run } = require('../utils/database');
const { sendEmail } = require('../utils/email');

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
// Le "Leads CRM" (Facebook/Instagram/Google Ads) est une section entierement separee du CRM
// porte-a-porte : seuls owner, lead_marketing et lead_closer y ont acces. Les roles porte-a-porte
// (setter/closer/manager/tech) sont explicitement bloques par requireD2DOnly ci-dessous, et
// symetriquement les roles leads-CRM sont bloques des routes porte-a-porte qui n'avaient pas
// deja de restriction de role.
function requireLeadsCrmAccess(req, res, next) {
  const r = req.user.role;
  if (r !== 'owner' && r !== 'lead_marketing' && r !== 'lead_closer') {
    return res.status(403).json({ error: 'Access restricted to the Leads CRM team.' });
  }
  next();
}
function requireLeadsCrmCloser(req, res, next) {
  const r = req.user.role;
  if (r !== 'owner' && r !== 'lead_closer') {
    return res.status(403).json({ error: 'Lead closer or owner access required.' });
  }
  next();
}
function requireD2DOnly(req, res, next) {
  const r = req.user.role;
  if (r === 'lead_marketing' || r === 'lead_closer') {
    return res.status(403).json({ error: 'This section is not part of the Leads CRM.' });
  }
  next();
}
function requireChatAccess(req, res, next) {
  const r = req.user.role;
  if (r !== 'owner' && r !== 'setter' && r !== 'closer') {
    return res.status(403).json({ error: 'Chat access restricted to setters, closers, and owner.' });
  }
  next();
}

// ── Leaderboard hebdomadaire (setters: RDV pris, closers: deals fermes) ──
// Semaine du lundi 00h00 au dimanche 23h59:59, heure de l'Est (America/Toronto — gere EST/EDT
// automatiquement). Le classement est calcule A LA VOLEE depuis les tables appointments/deals
// existantes (aucun compteur stocke separement) : c'est toujours exact, ca "se reinitialise" tout
// seul des que la semaine change (aucun job de reset a maintenir), et ca reste coherent meme si un
// RDV/deal est modifie ou re-ouvert. Les deals issus du Leads CRM (ad_lead_id non NULL) ne comptent
// pas ici — le leaderboard est scope au CRM porte-a-porte, comme le canal Team Rive-Sud lui-meme.
const LEADERBOARD_TZ = 'America/Toronto';

function tzWallTimeToUTC(y, m, d, h, mi, s, timeZone) {
  // Convertit une heure "murale" locale (ex: lundi 00:00 heure de l'Est) en instant UTC, sans
  // dependance externe. On part d'une estimation naive puis on corrige par l'ecart observe —
  // 2 iterations suffisent car le decalage horaire (EST -05:00 / EDT -04:00) est un nombre
  // entier d'heures constant sur la journee visee.
  let guess = Date.UTC(y, m - 1, d, h, mi, s);
  for (let i = 0; i < 2; i++) {
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone, year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    }).formatToParts(new Date(guess)).reduce((a, p) => { a[p.type] = p.value; return a; }, {});
    const hh = parts.hour === '24' ? 0 : parseInt(parts.hour, 10);
    const guessedLocalAsUTC = Date.UTC(+parts.year, +parts.month - 1, +parts.day, hh, +parts.minute, +parts.second);
    guess += Date.UTC(y, m - 1, d, h, mi, s) - guessedLocalAsUTC;
  }
  return new Date(guess);
}

function getWeekBoundsUTC(now) {
  now = now || new Date();
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: LEADERBOARD_TZ, year: 'numeric', month: '2-digit', day: '2-digit', weekday: 'short',
  }).formatToParts(now).reduce((a, p) => { a[p.type] = p.value; return a; }, {});
  const WD = { Mon: 0, Tue: 1, Wed: 2, Thu: 3, Fri: 4, Sat: 5, Sun: 6 };
  const daysSinceMonday = WD[parts.weekday] != null ? WD[parts.weekday] : 0;
  // Arithmetique de calendrier (jours entiers) faite a midi UTC pour eviter tout risque de
  // deborder sur le jour precedent/suivant a cause d'un decalage horaire — insensible au fuseau.
  const localNoon = new Date(Date.UTC(+parts.year, +parts.month - 1, +parts.day, 12, 0, 0));
  const monday = new Date(localNoon.getTime() - daysSinceMonday * 86400000);
  const nextMonday = new Date(monday.getTime() + 7 * 86400000);
  const weekStart = tzWallTimeToUTC(monday.getUTCFullYear(), monday.getUTCMonth() + 1, monday.getUTCDate(), 0, 0, 0, LEADERBOARD_TZ);
  const weekEnd = tzWallTimeToUTC(nextMonday.getUTCFullYear(), nextMonday.getUTCMonth() + 1, nextMonday.getUTCDate(), 0, 0, 0, LEADERBOARD_TZ);
  return { weekStart, weekEnd };
}

function sqlDateTime(d) { return d.toISOString().slice(0, 19).replace('T', ' '); }

function computeLeaderboard() {
  const { weekStart, weekEnd } = getWeekBoundsUTC();
  const startStr = sqlDateTime(weekStart), endStr = sqlDateTime(weekEnd);

  const setterCounts = query(
    `SELECT setter_id, COUNT(*) AS cnt FROM appointments
     WHERE setter_id IS NOT NULL AND created_at >= ? AND created_at < ?
     GROUP BY setter_id`,
    [startStr, endStr]
  );
  const setterCountMap = {};
  setterCounts.forEach(r => { setterCountMap[r.setter_id] = r.cnt; });
  const setterUsers = query(
    `SELECT u.id, u.first_name, u.last_name FROM users u JOIN roles r ON u.role_id = r.id
     WHERE r.name = 'setter' AND u.status = 'active'`
  );
  const setters = setterUsers
    .map(u => ({ id: u.id, name: `${u.first_name} ${u.last_name}`, count: setterCountMap[u.id] || 0 }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  const closerCounts = query(
    `SELECT closer_id, COUNT(*) AS cnt FROM deals
     WHERE closer_id IS NOT NULL AND ad_lead_id IS NULL AND created_at >= ? AND created_at < ?
     GROUP BY closer_id`,
    [startStr, endStr]
  );
  const closerCountMap = {};
  closerCounts.forEach(r => { closerCountMap[r.closer_id] = r.cnt; });
  const closerUsers = query(
    `SELECT u.id, u.first_name, u.last_name FROM users u JOIN roles r ON u.role_id = r.id
     WHERE r.name = 'closer' AND u.status = 'active'`
  );
  const closers = closerUsers
    .map(u => ({ id: u.id, name: `${u.first_name} ${u.last_name}`, count: closerCountMap[u.id] || 0 }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  return { weekStart: weekStart.toISOString(), weekEnd: weekEnd.toISOString(), setters, closers };
}

router.post('/auth/register', registerLimiter, register);
router.post('/auth/login',    loginLimiter,    login);
router.get ('/auth/me',       requireAuth,     me);
// Echange le role actif <-> le role "en reserve" (acces CRM secondaire) — voir
// swapCrmRole() dans auth.controller.js pour le detail du mecanisme.
router.post('/auth/swap-crm-role', requireAuth, swapCrmRole);

// Plafond par requete relativement genereux (le frontend envoie desormais les photos par lots —
// voir uploadPhotosBatched() cote client — donc un closer qui selectionne un nombre illimite de
// photos n'est jamais bloque : il envoie simplement plusieurs requetes successives de 15 photos
// max chacune). Ce plafond protege uniquement la memoire du serveur pour UNE requete individuelle.
router.post('/upload', requireAuth, upload.array('photos', 20), async (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded.' });
  }
  try {
    const folder = (req.body && req.body.folder) || 'deals';
    const uploads = await Promise.all(
      req.files.map(f => uploadToCloudinary(f.buffer, f.originalname, folder))
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

router.get  ('/users',   requireAuth, requireOwner, getUsers);

router.get('/users/team', requireAuth, (req, res) => {
  const rows = query(
    `SELECT u.id, u.first_name, u.last_name, u.email, u.phone, u.status,
            r.name as role, r.label as role_label
     FROM users u LEFT JOIN roles r ON u.role_id = r.id
     WHERE u.status = 'active' ORDER BY r.id, u.first_name`
  );
  return res.json(rows);
});

router.get  ('/users/:id',            requireAuth, requireOwner, getUser);
router.patch('/users/:id',            requireAuth, requireOwner, updateUser);
router.post ('/users/:id/approve',    requireAuth, requireOwner, approveUser);
router.post ('/users/:id/reject',     requireAuth, requireOwner, rejectUser);
router.post ('/users/:id/suspend',    requireAuth, requireOwner, suspendUser);
router.post ('/users/:id/reactivate', requireAuth, requireOwner, reactivateUser);

router.get('/roles',                      requireAuth, getRoles);
router.get('/permissions',                requireAuth, requireOwner, getPermissions);
router.get('/roles/:roleId/permissions',  requireAuth, requireOwner, getRolePermissions);
router.put('/roles/:roleId/permissions',  requireAuth, requireOwner, updateRolePermissions);
router.get('/audit-logs',                 requireAuth, requireOwner, getAuditLogs);

router.get('/assignments', requireAuth, requireD2DOnly, (req, res) => {
  const rows = query('SELECT setter_id, closer_id FROM assignments');
  const map = {};
  rows.forEach(r => { map[r.setter_id] = r.closer_id; });
  return res.json(map);
});

router.put('/assignments', requireAuth, requireD2DOnly, (req, res) => {
  const { setterId, closerId } = req.body;
  if (!setterId) return res.status(400).json({ error: 'setterId required.' });
  run(
    'INSERT INTO assignments (setter_id, closer_id) VALUES (?, ?) ON CONFLICT(setter_id) DO UPDATE SET closer_id = excluded.closer_id',
    [setterId, closerId || null]
  );
  return res.json({ message: 'Assignment saved.' });
});

router.get('/leads', requireAuth, requireD2DOnly, (req, res) => {
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

router.post('/leads', requireAuth, requireD2DOnly, (req, res) => {
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
    // Notification chat — aucune donnee client, juste le compteur attribue au setter.
    // Ton "hype" volontaire (gras/couleur cote frontend + emojis) pour motiver l'equipe en temps
    // reel ; voir aussi computeLeaderboard() pour le classement hebdomadaire correspondant.
    postSystemMessage(`🔥📅 NOUVEAU RDV BOOKÉ !\n${req.user.first_name} ${req.user.last_name} vient de décrocher un rendez-vous — ON CONTINUE COMME ÇA! 💪🚀`);
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

router.get('/appointments', requireAuth, requireD2DOnly, (req, res) => {
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

router.patch('/appointments/:id', requireAuth, requireD2DOnly, (req, res) => {
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
    appointmentId, clientName, address, city, postal, phone, email,
    price, paymentMethod,
    footageTotal, footageOther,
    ladderHeight, installDate,
    workFront, workRight, workLeft, workRear,
    notes, photoUrls,
    closerIdOverride, setterIdOverride,
    obstaclesToRemove, toolsNeeded, toolsNotes,
    adLeadId,
  } = req.body;
  if (!clientName) return res.status(400).json({ error: 'clientName required.' });
  const dealId = uuid();
  const closerId = closerIdOverride || (['closer', 'lead_closer'].includes(req.user.role) ? req.user.id : null);
  let setterId = setterIdOverride || null;
  if (!setterId && appointmentId) {
    const appt = get('SELECT setter_id FROM appointments WHERE id = ?', [appointmentId]);
    if (appt) setterId = appt.setter_id;
  }
  const photoUrlsJson = JSON.stringify(Array.isArray(photoUrls) ? photoUrls : []);
  run(
    `INSERT INTO deals (
       id, appointment_id, closer_id, setter_id,
       client_name, address, city, postal, phone, email,
       price, payment_method,
       footage_total, footage_other,
       ladder_height, install_date,
       work_front, work_right, work_left, work_rear,
       notes, photo_urls, status,
       obstacles_to_remove, tools_needed, tools_notes, ad_lead_id
     ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      dealId, appointmentId || null, closerId, setterId,
      clientName, address || null, city || null, postal || null, phone || null, email || null,
      parseFloat(price) || 0, paymentMethod || null,
      parseFloat(footageTotal) || 0,
      footageOther || null,
      ladderHeight || null, installDate || null,
      workFront || null, workRight || null, workLeft || null, workRear || null,
      notes || null, photoUrlsJson, 'Pending Installation',
      obstaclesToRemove || null, toolsNeeded || null, toolsNotes || null,
      adLeadId || null,
    ]
  );
  const newDeal = get('SELECT * FROM deals WHERE id = ?', [dealId]);
  if (newDeal) createTicketFromDeal(newDeal);
  if (adLeadId) {
    run(`UPDATE ad_leads SET status = 'Closed Won', updated_at = datetime('now') WHERE id = ?`, [adLeadId]);
  }
  // Notification chat — aucune donnee client (pas de nom, prix, ou photo), juste
  // le compteur attribue au closer, avec le setter qui a pris le rendez-vous d'origine.
  // (Les deals issus du Leads CRM ne postent pas dans le chat porte-a-porte — sections isolees.)
  if (!adLeadId) {
    const closerUser = closerId ? get('SELECT first_name, last_name FROM users WHERE id = ?', [closerId]) : null;
    const setterUser = setterId ? get('SELECT first_name, last_name FROM users WHERE id = ?', [setterId]) : null;
    const closerName = closerUser ? `${closerUser.first_name} ${closerUser.last_name}` : 'Closer inconnu';
    const setterName = setterUser ? `${setterUser.first_name} ${setterUser.last_name}` : null;
    postSystemMessage(
      `🎉💰 DEAL CLOSÉ !\n${closerName} vient de fermer une vente!`
      + (setterName ? `\n${setterName} +$300 🙌` : '')
      + `\nON EST EN FEU! 🔥`
    );
  }
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

router.get ('/chat/channels', requireAuth, requireChatAccess, getChatChannels);
router.post('/chat/channels', requireAuth, requireOwner,      createChatChannel);

router.get  ('/chat/messages',        requireAuth, requireChatAccess, getChatMessages);
router.post ('/chat/messages',        requireAuth, requireChatAccess, postChatMessage);
router.patch('/chat/messages/:id/cost', requireAuth, requireOwner,    setCostRequestPrice);

// Classement hebdomadaire (setters: RDV pris, closers: deals fermes) — voir computeLeaderboard()
// plus haut. Meme acces que le chat (setter/closer/owner), puisqu'il vit dans Team Rive-Sud.
router.get('/leaderboard', requireAuth, requireChatAccess, (req, res) => {
  return res.json(computeLeaderboard());
});

// ═══════════════════════════════════════════
// LEADS CRM — section isolee pour les leads Facebook / Instagram / Google Ads.
// Acces strictement limite a owner, lead_marketing et lead_closer (requireLeadsCrmAccess).
// ═══════════════════════════════════════════

// Le lead closer (ou owner) choisit ou l'email de notification "nouveau lead" doit etre envoye.
router.patch('/auth/notify-prefs', requireAuth, (req, res) => {
  const { notifyEmail, notifyPhone } = req.body;
  const sets = []; const params = [];
  if (notifyEmail !== undefined) { sets.push('notify_email = ?'); params.push(notifyEmail || null); }
  if (notifyPhone !== undefined) { sets.push('notify_phone = ?'); params.push(notifyPhone || null); }
  if (!sets.length) return res.status(400).json({ error: 'Nothing to update.' });
  params.push(req.user.id);
  run(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, params);
  return res.json({ message: 'Preferences updated.' });
});

router.get('/leads-crm/leads', requireAuth, requireLeadsCrmAccess, (req, res) => {
  const rows = query(
    `SELECT l.*, c.first_name || ' ' || c.last_name AS closer_name
     FROM ad_leads l
     LEFT JOIN users c ON l.closer_id = c.id
     ORDER BY l.created_at DESC`
  );
  return res.json(rows);
});

router.post('/leads-crm/leads', requireAuth, requireLeadsCrmAccess, async (req, res) => {
  const { source, firstName, lastName, phone, email, notes } = req.body;
  if (!firstName || !lastName || !phone) {
    return res.status(400).json({ error: 'firstName, lastName, phone required.' });
  }
  const id = uuid();
  run(
    `INSERT INTO ad_leads (id, source, first_name, last_name, phone, email, notes, status, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'New', ?)`,
    [id, source || 'Autre', firstName, lastName, phone, email || null, notes || null, req.user.id]
  );
  // Notifie tous les lead closers actifs (best-effort — n'echoue jamais la creation du lead).
  const closers = query(
    `SELECT u.id, u.first_name, u.email, u.notify_email FROM users u
     JOIN roles r ON u.role_id = r.id
     WHERE r.name = 'lead_closer' AND u.status = 'active'`
  );
  closers.forEach(c => {
    run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)', [
      uuid(), c.id, `🆕 Nouveau lead (${source || 'Autre'}): ${firstName} ${lastName} — ${phone}`,
    ]);
    const to = c.notify_email || c.email;
    sendEmail({
      to,
      subject: `Nouveau lead ${source || ''} — ${firstName} ${lastName}`,
      text: `Un nouveau lead vient d'arriver dans la queue.\n\nSource: ${source || 'Autre'}\nNom: ${firstName} ${lastName}\nTelephone: ${phone}\nEmail: ${email || '—'}\nNotes: ${notes || '—'}\n\nConnectez-vous au Leads CRM pour le prendre en charge.`,
    }).catch(() => {});
  });
  return res.status(201).json({ message: 'Lead created.', id });
});

router.patch('/leads-crm/leads/:id', requireAuth, requireLeadsCrmAccess, (req, res) => {
  const { id } = req.params;
  const { status, claim, apptDate, apptHour, notes } = req.body;
  const lead = get('SELECT * FROM ad_leads WHERE id = ?', [id]);
  if (!lead) return res.status(404).json({ error: 'Lead not found.' });

  const sets = ["updated_at = datetime('now')"];
  const params = [];

  if (claim) { sets.push('closer_id = ?'); params.push(req.user.role === 'owner' ? (req.body.closerId || req.user.id) : req.user.id); }
  if (!lead.contacted_at && (status === 'Contacted' || apptDate)) {
    sets.push('contacted_at = ?'); params.push(new Date().toISOString());
  }
  if (apptDate !== undefined) { sets.push('appt_date = ?'); params.push(apptDate || null); }
  if (apptHour !== undefined) { sets.push('appt_hour = ?'); params.push(apptHour != null ? parseInt(apptHour) : null); }
  if (notes !== undefined) { sets.push('notes = ?'); params.push(notes || null); }
  const TERMINAL_STATUSES = ['Closed Won', 'Closed Lost', 'No Show'];
  if (status) {
    sets.push('status = ?'); params.push(status);
  } else if (apptDate && !TERMINAL_STATUSES.includes(lead.status)) {
    // Fixer une date de rendez-vous fait toujours progresser le lead vers "Appointment Set",
    // qu'il vienne de "New" ou de "Contacted" — sauf s'il est deja dans un etat final.
    sets.push('status = ?'); params.push('Appointment Set');
  }

  params.push(id);
  run(`UPDATE ad_leads SET ${sets.join(', ')} WHERE id = ?`, params);
  return res.json({ message: 'Lead updated.' });
});

router.get('/leads-crm/cost-requests', requireAuth, requireLeadsCrmAccess, (req, res) => {
  const rows = query(
    `SELECT cr.*, c.first_name || ' ' || c.last_name AS closer_name
     FROM ad_lead_cost_requests cr
     LEFT JOIN users c ON cr.closer_id = c.id
     ORDER BY cr.created_at DESC`
  );
  rows.forEach(r => { try { r.photo_urls = JSON.parse(r.photo_urls || '[]'); } catch { r.photo_urls = []; } });
  return res.json(rows);
});

router.post('/leads-crm/cost-requests', requireAuth, requireLeadsCrmCloser, (req, res) => {
  const { adLeadId, clientName, footageTotal, ladderType, toolsNeeded, obstaclesToRemove, photoUrls } = req.body;
  if (!clientName) return res.status(400).json({ error: 'clientName required.' });
  const id = uuid();
  const urls = Array.isArray(photoUrls) ? photoUrls : [];
  run(
    `INSERT INTO ad_lead_cost_requests (
      id, ad_lead_id, closer_id, client_name, footage_total, ladder_type,
      tools_needed, obstacles_to_remove, photo_urls, cost_status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
    [
      id, adLeadId || null, req.user.id, clientName,
      footageTotal ? String(footageTotal) : null, ladderType || null,
      toolsNeeded || null, obstaclesToRemove || null, JSON.stringify(urls),
    ]
  );
  return res.status(201).json({ message: 'Cost request sent.', id });
});

router.patch('/leads-crm/cost-requests/:id/cost', requireAuth, requireOwner, (req, res) => {
  const { id } = req.params;
  const { cost } = req.body;
  const parsed = parseFloat(cost);
  if (!parsed || parsed <= 0) return res.status(400).json({ error: 'Valid cost required.' });
  const cr = get('SELECT id FROM ad_lead_cost_requests WHERE id = ?', [id]);
  if (!cr) return res.status(404).json({ error: 'Cost request not found.' });
  run(`UPDATE ad_lead_cost_requests SET cost = ?, cost_status = 'priced', updated_at = datetime('now') WHERE id = ?`, [parsed, id]);
  return res.json({ message: 'Cost updated.' });
});

// ═══════════════════════════════════════════
// MASTER DATABASE — vue unifiee (owner uniquement). Fusionne tout ce qui est jamais entre dans
// l'entreprise, peu importe l'origine (porte-a-porte ou leads Facebook/Instagram/Google Ads) :
// lead -> rendez-vous -> deal -> ticket d'installation, de la creation a la fin du job.
//
// La table `deals` est le pivot commun aux deux CRM (deals.appointment_id pour le porte-a-porte,
// deals.ad_lead_id pour les leads marketing) — on rattache donc chaque deal a son lead d'origine
// plutot que de dupliquer les lignes. Une fois qu'un deal existe, le meme installation_ticket est
// cree par createTicketFromDeal() peu importe l'origine (voir POST /deals) : le pipeline
// d'installation est deja unifie, cette route ne fait qu'exposer le tout regroupe et etiquete.
router.get('/database', requireAuth, requireOwner, (req, res) => {
  function parseUrls(raw) {
    try { const a = JSON.parse(raw || '[]'); return Array.isArray(a) ? a : []; } catch { return []; }
  }
  function mergePhotos() {
    const seen = new Set(); const out = [];
    Array.prototype.forEach.call(arguments, function (list) {
      (list || []).forEach(function (u) { if (u && !seen.has(u)) { seen.add(u); out.push(u); } });
    });
    return out;
  }

  // --- Porte-a-porte : leads + leurs rendez-vous ---
  const leads = query(
    `SELECT l.*,
       s.first_name || ' ' || s.last_name AS setter_name,
       c.first_name || ' ' || c.last_name AS closer_name
     FROM leads l
     LEFT JOIN users s ON l.setter_id = s.id
     LEFT JOIN users c ON l.closer_id = c.id`
  );
  const appts = query(`SELECT * FROM appointments`);
  const apptsByLeadId = {};
  appts.forEach(a => {
    if (!apptsByLeadId[a.lead_id]) apptsByLeadId[a.lead_id] = [];
    apptsByLeadId[a.lead_id].push(a);
  });

  // --- Deals : table pivot commune aux deux CRM ---
  const deals = query(
    `SELECT d.*,
       c.first_name  || ' ' || c.last_name  AS closer_name,
       s.first_name  || ' ' || s.last_name  AS setter_name,
       te.first_name || ' ' || te.last_name AS tech_name
     FROM deals d
     LEFT JOIN users c  ON d.closer_id = c.id
     LEFT JOIN users s  ON d.setter_id = s.id
     LEFT JOIN users te ON d.tech_id   = te.id`
  );
  const dealsByAppointmentId = {};
  const dealsByAdLeadId = {};
  deals.forEach(d => {
    if (d.appointment_id) dealsByAppointmentId[d.appointment_id] = d;
    if (d.ad_lead_id)     dealsByAdLeadId[d.ad_lead_id] = d;
  });

  // --- Tickets d'installation : etape finale, commune aux deux CRM ---
  const tickets = query(
    `SELECT t.*, te.first_name || ' ' || te.last_name AS tech_name
     FROM installation_tickets t
     LEFT JOIN users te ON t.tech_id = te.id`
  );
  const ticketsByDealId = {};
  tickets.forEach(t => { ticketsByDealId[t.deal_id] = t; });

  // --- Demandes de prix porte-a-porte (chat "Ask for Cost", liees a un rendez-vous precis) ---
  const d2dCostRequests = query(
    `SELECT * FROM chat_messages WHERE type = 'cost_request' AND appointment_id IS NOT NULL ORDER BY created_at DESC`
  );
  const d2dCostByApptId = {};
  d2dCostRequests.forEach(cr => { if (!d2dCostByApptId[cr.appointment_id]) d2dCostByApptId[cr.appointment_id] = cr; });

  // --- Leads marketing (Facebook / Google Ads / Instagram / Autre) ---
  const adLeads = query(
    `SELECT l.*, c.first_name || ' ' || c.last_name AS closer_name
     FROM ad_leads l
     LEFT JOIN users c ON l.closer_id = c.id`
  );
  const adLeadCostRequests = query(`SELECT * FROM ad_lead_cost_requests ORDER BY created_at DESC`);
  const adLeadCostByAdLeadId = {};
  adLeadCostRequests.forEach(cr => { if (!adLeadCostByAdLeadId[cr.ad_lead_id]) adLeadCostByAdLeadId[cr.ad_lead_id] = cr; });

  const rows = [];

  // 1) Chaque lead porte-a-porte, avec son rendez-vous / deal / ticket / cout s'ils existent.
  leads.forEach(l => {
    const leadAppts = (apptsByLeadId[l.id] || []).slice().sort((a, b) =>
      (b.appt_date || '').localeCompare(a.appt_date || '') || (b.created_at || '').localeCompare(a.created_at || '')
    );
    // On privilegie le rendez-vous qui a un deal attache ; sinon le plus recent.
    const appt = leadAppts.find(a => dealsByAppointmentId[a.id]) || leadAppts[0] || null;
    const deal = appt ? dealsByAppointmentId[appt.id] : null;
    const ticket = deal ? ticketsByDealId[deal.id] : null;
    const costReq = appt ? d2dCostByApptId[appt.id] : null;
    const status = (ticket && ticket.status) || (deal && deal.status) || (appt && appt.status) || l.status || 'Scheduled';

    rows.push({
      id: 'lead:' + l.id,
      crmType: 'd2d',
      crmLabel: 'Door-to-Door',
      leadSource: 'Door-to-Door',
      customerName: ((l.first_name || '') + ' ' + (l.last_name || '')).trim(),
      phone: l.phone || '', email: l.email || '',
      address: (deal && deal.address) || l.address || '',
      city: (deal && deal.city) || l.city || '', postal: (deal && deal.postal) || l.postal || '',
      notes: l.notes || '',
      status,
      createdAt: l.created_at,
      apptDate: appt ? appt.appt_date : null,
      apptHour: appt ? appt.appt_hour : null,
      setterName: l.setter_name || (deal && deal.setter_name) || '',
      closerName: l.closer_name || (deal && deal.closer_name) || '',
      techName: (deal && deal.tech_name) || (ticket && ticket.tech_name) || '',
      saleAmount: deal ? (parseFloat(deal.price) || 0) : null,
      jobCost: costReq && costReq.cost != null ? parseFloat(costReq.cost) : null,
      jobCostStatus: costReq ? costReq.cost_status : null,
      installDate: (ticket && ticket.scheduled_install_date) || (deal && deal.install_date) || null,
      photos: mergePhotos(parseUrls(deal && deal.photo_urls), parseUrls(ticket && ticket.photo_urls), parseUrls(costReq && costReq.photo_urls)),
      leadId: l.id, apptId: appt ? appt.id : null, dealId: deal ? deal.id : null, ticketId: ticket ? ticket.id : null, adLeadId: null,
    });
  });

  // 2) Chaque lead marketing, avec son deal / ticket / cout s'ils existent.
  adLeads.forEach(al => {
    const deal = dealsByAdLeadId[al.id] || null;
    const ticket = deal ? ticketsByDealId[deal.id] : null;
    const costReq = adLeadCostByAdLeadId[al.id] || null;
    const status = (ticket && ticket.status) || (deal && deal.status) || al.status || 'New';

    rows.push({
      id: 'adlead:' + al.id,
      crmType: 'marketing',
      crmLabel: 'Marketing Lead',
      leadSource: al.source || 'Autre',
      customerName: ((al.first_name || '') + ' ' + (al.last_name || '')).trim(),
      phone: al.phone || '', email: al.email || '',
      address: (deal && deal.address) || '',
      // ad_leads n'a pas de champs ville/code postal distincts — collectes uniquement une fois
      // le deal ferme (formulaire du closer), donc vides tant qu'aucun deal n'existe.
      city: (deal && deal.city) || '', postal: (deal && deal.postal) || '',
      notes: al.notes || '',
      status,
      createdAt: al.created_at,
      apptDate: al.appt_date || null,
      apptHour: al.appt_hour || null,
      setterName: '',
      closerName: al.closer_name || (deal && deal.closer_name) || '',
      techName: (deal && deal.tech_name) || (ticket && ticket.tech_name) || '',
      saleAmount: deal ? (parseFloat(deal.price) || 0) : null,
      jobCost: costReq && costReq.cost != null ? parseFloat(costReq.cost) : null,
      jobCostStatus: costReq ? costReq.cost_status : null,
      installDate: (ticket && ticket.scheduled_install_date) || (deal && deal.install_date) || null,
      photos: mergePhotos(parseUrls(deal && deal.photo_urls), parseUrls(ticket && ticket.photo_urls), parseUrls(costReq && costReq.photo_urls)),
      leadId: null, apptId: null, dealId: deal ? deal.id : null, ticketId: ticket ? ticket.id : null, adLeadId: al.id,
    });
  });

  // 3) Filet de securite : deals sans lead ni ad_lead rattache (ne devrait pas arriver en usage
  // normal, mais un deal ferme ne doit jamais disparaitre de la base juste parce qu'il est orphelin).
  deals.forEach(d => {
    if (d.appointment_id || d.ad_lead_id) return; // deja couvert plus haut
    const ticket = ticketsByDealId[d.id] || null;
    const status = (ticket && ticket.status) || d.status || 'Pending Installation';
    rows.push({
      id: 'deal:' + d.id,
      crmType: 'other',
      crmLabel: 'Autre',
      leadSource: 'Direct',
      customerName: d.client_name || '',
      phone: d.phone || '', email: d.email || '',
      address: d.address || '', city: d.city || '', postal: d.postal || '',
      notes: d.notes || '',
      status,
      createdAt: d.created_at,
      apptDate: null, apptHour: null,
      setterName: d.setter_name || '',
      closerName: d.closer_name || '',
      techName: d.tech_name || (ticket && ticket.tech_name) || '',
      saleAmount: parseFloat(d.price) || 0,
      jobCost: null, jobCostStatus: null,
      installDate: (ticket && ticket.scheduled_install_date) || d.install_date || null,
      photos: mergePhotos(parseUrls(d.photo_urls), parseUrls(ticket && ticket.photo_urls)),
      leadId: null, apptId: null, dealId: d.id, ticketId: ticket ? ticket.id : null, adLeadId: null,
    });
  });

  rows.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  return res.json(rows);
});

router.get('/poll', requireAuth, (req, res) => {
  const since = req.query.since || new Date(Date.now() - 30000).toISOString();
  const role = req.user.role;
  let newTickets = [];
  if (role === 'manager' || role === 'owner') {
    newTickets = query(
      `SELECT t.*,
         tech.first_name || ' ' || tech.last_name AS tech_name,
         cl.first_name   || ' ' || cl.last_name   AS closer_name,
         st.first_name   || ' ' || st.last_name   AS setter_name,
         CASE WHEN d.ad_lead_id IS NOT NULL THEN 'marketing' ELSE 'd2d' END AS origin
       FROM installation_tickets t
       LEFT JOIN users tech ON t.tech_id   = tech.id
       LEFT JOIN users cl   ON t.closer_id = cl.id
       LEFT JOIN users st   ON t.setter_id = st.id
       LEFT JOIN deals d    ON t.deal_id   = d.id
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
         st.first_name || ' ' || st.last_name AS setter_name,
         CASE WHEN d.ad_lead_id IS NOT NULL THEN 'marketing' ELSE 'd2d' END AS origin
       FROM installation_tickets t
       LEFT JOIN users cl ON t.closer_id = cl.id
       LEFT JOIN users st ON t.setter_id = st.id
       LEFT JOIN deals d  ON t.deal_id   = d.id
       WHERE t.tech_id = ? AND t.updated_at > ?
       ORDER BY t.scheduled_install_date ASC`,
      [req.user.id, since]
    );
    updatedJobs.forEach(t => {
      try { t.photo_urls = JSON.parse(t.photo_urls || '[]'); } catch { t.photo_urls = []; }
    });
  }
  let newChatMessages = [];
  if (role === 'owner' || role === 'setter' || role === 'closer') {
    newChatMessages = query(
      `SELECT m.*,
         u.first_name AS sender_first_name, u.last_name AS sender_last_name,
         r.name AS sender_role
       FROM chat_messages m
       LEFT JOIN users u ON m.sender_id = u.id
       LEFT JOIN roles r ON u.role_id = r.id
       WHERE m.created_at > ?
       ORDER BY m.created_at ASC`,
      [since]
    );
    newChatMessages.forEach(m => {
      try { m.photo_urls = JSON.parse(m.photo_urls || '[]'); } catch { m.photo_urls = []; }
    });
  }
  // Leaderboard recalcule a chaque poll (toutes les 15s cote frontend) pour que le classement
  // reste toujours a jour sans action manuelle — voir computeLeaderboard() plus haut.
  let leaderboard = null;
  if (role === 'owner' || role === 'setter' || role === 'closer') {
    leaderboard = computeLeaderboard();
  }
  let newAdLeads = [];
  let newAdLeadCostRequests = [];
  if (role === 'owner' || role === 'lead_marketing' || role === 'lead_closer') {
    newAdLeads = query(
      `SELECT l.*, c.first_name || ' ' || c.last_name AS closer_name
       FROM ad_leads l
       LEFT JOIN users c ON l.closer_id = c.id
       WHERE l.updated_at > ?
       ORDER BY l.created_at DESC`,
      [since]
    );
    newAdLeadCostRequests = query(
      `SELECT cr.*, c.first_name || ' ' || c.last_name AS closer_name
       FROM ad_lead_cost_requests cr
       LEFT JOIN users c ON cr.closer_id = c.id
       WHERE cr.updated_at > ?
       ORDER BY cr.created_at DESC`,
      [since]
    );
    newAdLeadCostRequests.forEach(r => {
      try { r.photo_urls = JSON.parse(r.photo_urls || '[]'); } catch { r.photo_urls = []; }
    });
  }
  const unreadCount = get(
    'SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND read = 0',
    [req.user.id]
  );
  return res.json({
    newTickets,
    updatedJobs,
    newChatMessages,
    leaderboard,
    newAdLeads,
    newAdLeadCostRequests,
    unreadNotifications: unreadCount ? unreadCount.c : 0,
    serverTime: new Date().toISOString(),
  });
});

module.exports = router;
