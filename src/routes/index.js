const express = require('express');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');
const { v4: uuid } = require('uuid');
const cloudinary = require('cloudinary').v2;

// Audit 2026-09-05 : POST /webhooks/ad-leads et /webhooks/after-sales comparaient la cle
// partagee avec `!==` (comparaison a temps variable — le temps de reponse peut, en theorie,
// fuiter la cle caractere par caractere a un attaquant qui mesure la latence sur beaucoup de
// tentatives). crypto.timingSafeEqual() compare en temps constant. Il exige deux buffers de
// MEME longueur (sinon il leve une exception) — on compare donc d'abord les longueurs, ce qui
// est sans risque a reveler (la longueur d'une cle secrete n'aide pas a la deviner).
function secretsMatch(provided, configured) {
  if (typeof provided !== 'string' || typeof configured !== 'string') return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(configured);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

const { register, login, me, swapCrmRole, forgotPassword, resetPassword } = require('../controllers/auth.controller');
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
const { sendPushToUser, VAPID_PUBLIC_KEY } = require('../utils/push');
const { notifyUser, notifyRole } = require('../utils/notify');
const { sendSms } = require('../utils/sms');
const { sendEmail } = require('../utils/email');
const { buildClosedWonMessage } = require('../utils/dealClosedMessage');
const { buildNewLeadSms } = require('../utils/newLeadSms');
const { moveOpportunityToConfirmation, markOpportunityWon } = require('../utils/ghlClient');

// Etiquettes utilisees dans TOUS les messages de notification pour que chacun sache d'un coup
// d'oeil de quel CRM vient le lead/rendez-vous/deal — jamais d'ambiguite entre porte-a-porte et
// Facebook/Instagram/Google (Lead CRM).
const LABEL_D2D = '[Porte-à-porte]';
const LABEL_LEADS = '[Lead CRM]';

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
// Webhook public (pas de session/JWT possible depuis Zapier/Meta/Google) — proteger par cle
// partagee (voir POST /webhooks/ad-leads) plutot que par volume seul, mais on garde un plafond
// large au cas ou une source enverrait des doublons/retries en rafale.
const webhookLimiter  = rateLimit({ windowMs: 60*1000, max: 60 });

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
// Audit 2026-09-07 (test end-to-end du workflow complet setter -> technicien) : PATCH
// /tickets/:id etait restreint a requireManagerOrOwner depuis la toute premiere version du
// code, alors que le frontend donne au technicien des boutons "Scheduled / In Progress /
// Completed" qui appellent CE MEME endpoint (voir buildTicketDetailSheet cote frontend) — un
// technicien recevait donc systematiquement un 403 en tentant de faire progresser son propre
// job, confirme par un test HTTP reel. On autorise maintenant owner/manager (sur n'importe quel
// ticket, comme avant) ET tech, mais UNIQUEMENT sur un ticket qui lui est deja assigne — jamais
// sur le ticket d'un collegue. La restriction des CHAMPS modifiables par un tech (statut
// seulement, jamais reassignation/date) est faite dans updateTicket() (voir tickets.controller.js).
function requireTicketUpdateAccess(req, res, next) {
  const r = req.user.role;
  if (r === 'owner' || r === 'manager') return next();
  if (r === 'tech') {
    const ticket = get('SELECT tech_id FROM installation_tickets WHERE id = ?', [req.params.id]);
    if (ticket && ticket.tech_id === req.user.id) return next();
    return res.status(403).json({ error: 'You can only update your own assigned tickets.' });
  }
  return res.status(403).json({ error: 'Manager, owner, or assigned technician access required.' });
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
// Demande utilisateur 2026-09-15 : la section "Queue" du Leads CRM (pipeline des leads
// marketing — statut, fiche de qualification, prise de RDV) devient owner-only. lead_marketing
// et lead_closer gardent leur acces au reste (GET /leads-crm/leads en lecture pour leur
// Calendrier, Cost, Base) — voir requireLeadsCrmAccess ci-dessus, inchange — mais perdent les
// actions ci-dessous, qui deplacaient un lead dans le pipeline. Applique UNIQUEMENT aux routes
// qui modifient un ad_lead (statut/qualification/booking), jamais a la lecture seule.
function requireQueueOwner(req, res, next) {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Section Queue réservée au owner.' });
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
// Audit 2026-09-05 : POST/PATCH /deals n'avaient aucune restriction de role au-dela de
// requireAuth — un tech ou un lead_marketing authentifie pouvait appeler l'API directement
// (hors UI, qui cache simplement le bouton) pour creer un deal ou modifier le statut/technicien/
// photos de N'IMPORTE QUEL deal. Cree un deal (porte-a-porte OU issu d'un lead marketing via
// adLeadId, voir POST /deals) : uniquement closer/team_leader_vente/lead_closer/owner — memes
// roles que ceux deja consideres comme "createur automatique" (closerId = req.user.id) dans la
// logique existante de POST /deals.
function requireDealCreateAccess(req, res, next) {
  const r = req.user.role;
  if (!['owner', 'closer', 'team_leader_vente', 'lead_closer'].includes(r)) {
    return res.status(403).json({ error: 'Deal creation is restricted to closers, team leads, lead closers, and the owner.' });
  }
  next();
}
function requireChatAccess(req, res, next) {
  const r = req.user.role;
  // team_leader_vente voit tout ce que les setters/closers voient (voir seedRoles) — inclut donc
  // le chat d'equipe et le leaderboard, memes routes qu'eux. Reste exclu de /tickets et /database
  // (non touchees ici, allowlist separee).
  if (r !== 'owner' && r !== 'setter' && r !== 'closer' && r !== 'team_leader_vente') {
    return res.status(403).json({ error: 'Chat access restricted to setters, closers, team leads, and owner.' });
  }
  next();
}

// ── Commissions (deals porte-a-porte fermes uniquement — voir demande utilisateur "la commission
// est seulement pour les deals closes, ca n'a rien a voir avec les rendez-vous") ──
// Regle: setter = 300$ fixe par deal ; closer = prix du deal - cost - 300$ setter, SAUF si
// self_lead (le closer a ferme sur SON PROPRE lead, aucun setter implique) auquel cas la part
// setter de 300$ ne s'applique pas et le closer la touche en plus. Recalculee a chaque creation
// de deal et a chaque PATCH qui touche price/cost/self_lead (voir POST/PATCH /deals ci-dessous).
// Une commission deja marquee 'paid' n'est JAMAIS recalculee automatiquement (montant historique
// fige) — seules les lignes encore 'pending' sont mises a jour.
const SETTER_COMMISSION = 300;
function upsertCommission(dealId, userId, role, amount) {
  if (!userId) return;
  const existing = get('SELECT id, status FROM commissions WHERE deal_id = ? AND role = ?', [dealId, role]);
  if (!existing) {
    run(
      `INSERT INTO commissions (id, deal_id, user_id, role, amount, status) VALUES (?, ?, ?, ?, ?, 'pending')`,
      [uuid(), dealId, userId, role, amount]
    );
  } else if (existing.status === 'pending') {
    run(`UPDATE commissions SET user_id = ?, amount = ?, updated_at = datetime('now') WHERE id = ?`,
      [userId, amount, existing.id]);
  }
  // status 'paid' : on ne touche plus au montant, il reste tel quel meme si price/cost changent apres coup.
}
function syncCommissionsForDeal(dealId) {
  const deal = get('SELECT * FROM deals WHERE id = ?', [dealId]);
  if (!deal) return;
  // Uniquement le pipeline porte-a-porte (ad_lead_id NULL) — les deals issus du Leads CRM
  // marketing n'ont pas de setter/closer au meme sens et ne sont pas concernes par ces commissions.
  if (deal.ad_lead_id) return;
  const price = parseFloat(deal.price) || 0;
  const cost = parseFloat(deal.cost) || 0;
  const selfLead = !!deal.self_lead;
  const hasSetter = !!deal.setter_id && !selfLead;
  if (hasSetter) upsertCommission(dealId, deal.setter_id, 'setter', SETTER_COMMISSION);
  if (deal.closer_id) {
    const closerAmount = price - cost - (hasSetter ? SETTER_COMMISSION : 0);
    upsertCommission(dealId, deal.closer_id, 'closer', closerAmount);
  }
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
// "Mot de passe oublie" — limite plus stricte que le login normal (5 demandes / 15 min / IP)
// puisque chaque demande declenche un envoi d'email, pour eviter tout abus/spam d'une boite mail.
const forgotPasswordLimiter = rateLimit({ windowMs: 15*60*1000, max: 5 });
router.post('/auth/forgot-password', forgotPasswordLimiter, forgotPassword);
router.post('/auth/reset-password',  forgotPasswordLimiter, resetPassword);
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

// Audit 2026-09-05 : n'avait que requireD2DOnly, donc un setter ou un tech authentifie pouvait
// reassigner N'IMPORTE QUEL setter a N'IMPORTE QUEL closer via l'API directement (l'UI qui
// appelle ceci vit exclusivement dans les ecrans de gestion d'equipe de l'owner, voir
// saveAssignments() cote frontend). Restreint a l'owner, seul role qui gere ces affectations.
router.put('/assignments', requireAuth, requireOwner, (req, res) => {
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
  // Audit 2026-09-10 (rapporte par l'utilisateur : la ville n'apparaissait "que sur certains
  // rendez-vous") — le formulaire "Nouveau Lead" marque deja "Ville *" comme obligatoire cote
  // frontend (voir openNewLeadSheet), mais rien ne l'imposait cote serveur : un appel direct a
  // cette API (ou un ancien build du frontend) pouvait creer un lead/RDV sans ville, qui
  // n'apparaissait alors jamais dans le calendrier du closer ni dans la fiche du RDV. On aligne
  // maintenant le serveur sur l'exigence deja affichee au setter.
  if (!city) {
    return res.status(400).json({ error: 'city required.' });
  }
  const leadId = uuid();
  const setterId = req.user.id;
  run(
    `INSERT INTO leads (id, first_name, last_name, phone, email, address, city, postal, notes, setter_id, closer_id, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Scheduled')`,
    [leadId, firstName, lastName, phone, email || null, address || null, city || null, postal || null, notes || null, setterId, closerId || null]
  );
  // Un nouveau lead porte-a-porte concerne le closer assigne (s'il y en a un) ET l'owner —
  // meme sans rendez-vous encore pris (voir aussi insertAdLead(), equivalent cote Lead CRM).
  if (closerId) {
    notifyUser(closerId, `🆕 ${LABEL_D2D} Nouveau lead: ${firstName} ${lastName} — ${phone}`,
      { title: `🆕 Nouveau lead ${LABEL_D2D}`, body: `${firstName} ${lastName} — ${phone}`, url: '/' });
  }
  notifyRole('owner', `🆕 ${LABEL_D2D} Nouveau lead: ${firstName} ${lastName} — ${phone}`,
    { title: `🆕 Nouveau lead ${LABEL_D2D}`, body: `${firstName} ${lastName} — ${phone}`, url: '/' });
  if (apptDate) {
    // Le closer a peut-etre bloque ce creneau (vacances, sport...) — voir isSlotBlocked() et
    // POST /closer-blackouts. Bloque pour tout le monde, pas seulement son propre bouton +.
    if (closerId && isSlotBlocked(closerId, apptDate, parseFloat(apptHour) || 14)) {
      return res.status(409).json({ error: 'Ce closer a bloqué ce créneau — RDV impossible à cette date/heure.' });
    }
    const apptId = uuid();
    run(
      `INSERT INTO appointments (id, lead_id, setter_id, closer_id, appt_date, appt_hour, status, notes)
       VALUES (?, ?, ?, ?, ?, ?, 'Scheduled', ?)`,
      [apptId, leadId, setterId, closerId || null, apptDate, parseFloat(apptHour) || 14, notes || null]
    );
    // Notification chat — aucune donnee client, juste le compteur attribue au setter.
    // Ton "hype" volontaire (gras/couleur cote frontend + emojis) pour motiver l'equipe en temps
    // reel ; voir aussi computeLeaderboard() pour le classement hebdomadaire correspondant.
    postSystemMessage(`🔥📅 NOUVEAU RDV BOOKÉ !\n${req.user.first_name} ${req.user.last_name} vient de décrocher un rendez-vous — ON CONTINUE COMME ÇA! 💪🚀`);
    const setter = get('SELECT first_name, last_name FROM users WHERE id = ?', [setterId]);
    const setterName = setter ? `${setter.first_name} ${setter.last_name}` : 'Un setter';
    if (closerId) {
      notifyUser(closerId, `📅 ${LABEL_D2D} Nouveau RDV: ${firstName} ${lastName} le ${apptDate} — posé par ${setterName}`,
        { title: `📅 Nouveau RDV ${LABEL_D2D}`, body: `${firstName} ${lastName} — ${apptDate}`, url: '/' });
    }
    notifyRole('owner', `📅 ${LABEL_D2D} RDV pris: ${firstName} ${lastName} le ${apptDate} — posé par ${setterName}`,
      { title: `📅 RDV pris ${LABEL_D2D}`, body: `${firstName} ${lastName} — ${apptDate}`, url: '/' });
  }
  return res.status(201).json({ message: 'Lead created.', id: leadId });
});

router.get('/appointments', requireAuth, requireD2DOnly, (req, res) => {
  const rows = query(
    `SELECT a.*,
       l.first_name AS lead_first_name, l.last_name AS lead_last_name,
       l.first_name || ' ' || l.last_name AS name,
       l.phone, l.email, l.address, l.city, l.postal,
       s.first_name || ' ' || s.last_name AS setter_name,
       c.first_name || ' ' || c.last_name AS closer_name
     FROM appointments a
     LEFT JOIN leads l ON a.lead_id   = l.id
     LEFT JOIN users s ON a.setter_id = s.id
     LEFT JOIN users c ON a.closer_id = c.id
     ORDER BY a.appt_date DESC, a.appt_hour DESC`
  );
  // photo_urls stocke en JSON (voir deals.photo_urls / ad_leads.quote_image_urls, meme convention)
  // — photos de callback televersees depuis la fiche du RDV.
  rows.forEach(a => {
    try { a.photo_urls = JSON.parse(a.photo_urls || '[]'); } catch { a.photo_urls = []; }
  });
  return res.json(rows);
});

router.patch('/appointments/:id', requireAuth, requireD2DOnly, (req, res) => {
  const { id } = req.params;
  const {
    status, apptDate, apptHour, notes, photoUrls,
    clientFirstName, clientLastName, phone, email, address, city, postal,
  } = req.body;
  const appt = get('SELECT * FROM appointments WHERE id = ?', [id]);
  if (!appt) return res.status(404).json({ error: 'Appointment not found.' });
  // Reprogrammation (nouvelle date/heure) — meme verification de blocage que POST /leads. On ne
  // bloque que si la date OU l'heure change reellement (permet par ex. de juste changer le statut
  // d'un RDV deja pris sur un jour depuis bloque apres coup, sans se retrouver coince).
  if ((apptDate !== undefined && apptDate !== appt.appt_date) || (apptHour !== undefined && parseFloat(apptHour) !== appt.appt_hour)) {
    const checkDate = apptDate !== undefined ? apptDate : appt.appt_date;
    const checkHour = apptHour !== undefined ? parseFloat(apptHour) : appt.appt_hour;
    if (appt.closer_id && isSlotBlocked(appt.closer_id, checkDate, checkHour)) {
      return res.status(409).json({ error: 'Ce closer a bloqué ce créneau — RDV impossible à cette date/heure.' });
    }
  }
  const sets = [];
  const params = [];
  if (status !== undefined)   { sets.push('status = ?');    params.push(status); }
  if (apptDate !== undefined) { sets.push('appt_date = ?'); params.push(apptDate); }
  if (apptHour !== undefined) { sets.push('appt_hour = ?'); params.push(parseFloat(apptHour)); }
  // Notes du RDV — editables a tout moment, y compris apres la prise du RDV (le setter veut
  // pouvoir corriger/completer ses notes une fois sur le terrain, voir demande utilisateur).
  if (notes !== undefined)    { sets.push('notes = ?');     params.push(notes || null); }
  // Photos du RDV (callback) — tableau JSON d'URLs Cloudinary, meme convention que deals/ad_leads.
  if (photoUrls !== undefined) { sets.push('photo_urls = ?'); params.push(JSON.stringify(Array.isArray(photoUrls) ? photoUrls : [])); }
  if (sets.length) {
    sets.push("updated_at = datetime('now')");
    params.push(id);
    run(`UPDATE appointments SET ${sets.join(', ')} WHERE id = ?`, params);
  }
  // Infos client (nom, tel, email, adresse) vivent sur la fiche `leads`, pas `appointments` —
  // meme regle que ci-dessus : editables en tout temps, meme RDV deja pris/ferme, pour corriger
  // une adresse ou un numero errone sans devoir tout re-creer.
  if (appt.lead_id) {
    const leadSets = [];
    const leadParams = [];
    if (clientFirstName !== undefined) { leadSets.push('first_name = ?'); leadParams.push(clientFirstName); }
    if (clientLastName  !== undefined) { leadSets.push('last_name = ?');  leadParams.push(clientLastName); }
    if (phone   !== undefined) { leadSets.push('phone = ?');   leadParams.push(phone); }
    if (email   !== undefined) { leadSets.push('email = ?');   leadParams.push(email || null); }
    if (address !== undefined) { leadSets.push('address = ?'); leadParams.push(address); }
    if (city    !== undefined) { leadSets.push('city = ?');    leadParams.push(city || null); }
    if (postal  !== undefined) { leadSets.push('postal = ?');  leadParams.push(postal || null); }
    if (leadSets.length) {
      leadSets.push("updated_at = datetime('now')");
      leadParams.push(appt.lead_id);
      run(`UPDATE leads SET ${leadSets.join(', ')} WHERE id = ?`, leadParams);
    }
  }
  if (status === 'Closed Won') {
    if (appt.lead_id) {
      run("UPDATE leads SET status = 'Closed Won', updated_at = datetime('now') WHERE id = ?", [appt.lead_id]);
    }
    const deal = get('SELECT * FROM deals WHERE appointment_id = ?', [id]);
    if (deal) createTicketFromDeal(deal);
  }
  // Sync retour vers le Leads CRM (Queue, owner-only) — demande utilisateur 2026-09-15 : quand
  // le closer/team_leader_vente ferme (won OU perdu) un RDV qui a ete booke depuis un lead
  // marketing (voir POST /leads-crm/leads/:id/book, qui relie ad_leads.appointment_id a CE
  // rendez-vous), le statut doit se repercuter automatiquement dans la Queue, sans action
  // manuelle de l'owner. "Closed Won" est deja gere plus haut par POST /deals quand adLeadId est
  // fourni (voir plus bas) — ce bloc-ci couvre en plus le cas ou le statut est change ICI, sur le
  // RDV directement (bouton statut de la fiche RDV), qui est le chemin le plus frequent pour
  // "Closed Lost" (aucun deal n'est jamais cree pour un RDV perdu).
  if (status === 'Closed Won' || status === 'Closed Lost') {
    const linkedAdLead = get('SELECT id, first_name, last_name, ghl_contact_id FROM ad_leads WHERE appointment_id = ?', [id]);
    if (linkedAdLead) {
      run('UPDATE ad_leads SET status = ?, updated_at = datetime(\'now\') WHERE id = ?', [status, linkedAdLead.id]);
      const adLeadName = `${linkedAdLead.first_name || ''} ${linkedAdLead.last_name || ''}`.trim() || 'Client';
      notifyRole('owner', `💰 ${LABEL_LEADS} Lead ${status === 'Closed Won' ? 'fermé' : 'perdu'} (Queue): ${adLeadName}`,
        { title: `💰 Queue mise à jour ${LABEL_LEADS}`, body: `${adLeadName} — ${status}`, url: '/' });
      if (status === 'Closed Won' && linkedAdLead.ghl_contact_id) markOpportunityWon(linkedAdLead.ghl_contact_id);
    }
  }
  // Le setter qui a pose ce rendez-vous veut savoir ce qu'il est devenu (ferme, perdu, no-show,
  // etc.) — c'est son travail de prospection qui est en jeu. Notifie a CHAQUE changement de
  // statut, quel qu'il soit (pas seulement Closed Won), voir demande utilisateur.
  if (status !== undefined && appt.setter_id) {
    const lead = appt.lead_id ? get('SELECT first_name, last_name FROM leads WHERE id = ?', [appt.lead_id]) : null;
    const name = lead ? `${lead.first_name} ${lead.last_name}` : 'Client';
    notifyUser(appt.setter_id, `📊 ${LABEL_D2D} Statut mis à jour — ${name}: ${status}`,
      { title: `📊 Statut mis à jour ${LABEL_D2D}`, body: `${name}: ${status}`, url: '/' });
    // L'owner veut TOUTE notification importante, meme deconnecte/app fermee (voir demande
    // utilisateur "notifications owner") — jusqu'ici seul le setter etait prevenu d'un changement
    // de statut de RDV porte-a-porte.
    notifyRole('owner', `📊 ${LABEL_D2D} Statut mis à jour — ${name}: ${status}`,
      { title: `📊 Statut mis à jour ${LABEL_D2D}`, body: `${name}: ${status}`, url: '/' });
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

router.post('/deals', requireAuth, requireDealCreateAccess, (req, res) => {
  const {
    appointmentId, clientName, address, city, postal, phone, email,
    price, paymentMethod,
    footageTotal, footageOther,
    ladderHeight, installDate,
    workFront, workRight, workLeft, workRear,
    notes, photoUrls,
    closerIdOverride, setterIdOverride,
    obstaclesToRemove, toolsNeeded, toolsNotes,
    adLeadId, selfLead,
  } = req.body;
  if (!clientName) return res.status(400).json({ error: 'clientName required.' });
  // Auto-resolution de adLeadId depuis appointmentId — le front (formulaire de deal D2D
  // classique, openDealSheet) n'envoie jamais adLeadId : il n'a aucune notion des leads
  // marketing. Si ce rendez-vous a ete booke depuis la Queue (voir POST
  // /leads-crm/leads/:id/book, qui relie ad_leads.appointment_id), on retrouve le lead ici pour
  // que deals.ad_lead_id et la synchro "Closed Won" ci-dessous fonctionnent meme quand adLeadId
  // n'est pas explicitement fourni — demande utilisateur 2026-09-15 "Queue admin-only".
  let resolvedAdLeadId = adLeadId || null;
  if (!resolvedAdLeadId && appointmentId) {
    const linkedAdLead = get('SELECT id FROM ad_leads WHERE appointment_id = ?', [appointmentId]);
    if (linkedAdLead) resolvedAdLeadId = linkedAdLead.id;
  }
  // Audit 2026-09-07 (test end-to-end) : rien n'empechait un prix negatif d'etre envoye ici — un
  // deal se referme forcement sur une VENTE, jamais un montant negatif (un remboursement/
  // ajustement est une operation distincte, pas encore definie cote produit — voir cartographie
  // initiale). On rejette donc simplement un prix negatif a la creation.
  if (price !== undefined && price !== null && price !== '' && parseFloat(price) < 0) {
    return res.status(400).json({ error: 'Price cannot be negative.' });
  }
  const dealId = uuid();
  const closerId = closerIdOverride || (['closer', 'lead_closer', 'team_leader_vente'].includes(req.user.role) ? req.user.id : null);
  // "Lead moi" — le closer ferme sur son propre lead, jamais de setter associe meme si un
  // setterIdOverride ou un appointment.setter_id existait (voir syncCommissionsForDeal).
  const isSelfLead = !!selfLead;
  let setterId = isSelfLead ? null : (setterIdOverride || null);
  if (!isSelfLead && !setterId && appointmentId) {
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
       obstacles_to_remove, tools_needed, tools_notes, ad_lead_id, self_lead
     ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
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
      resolvedAdLeadId || null, isSelfLead ? 1 : 0,
    ]
  );
  const newDeal = get('SELECT * FROM deals WHERE id = ?', [dealId]);
  if (newDeal) createTicketFromDeal(newDeal);
  syncCommissionsForDeal(dealId);
  if (resolvedAdLeadId) {
    run(`UPDATE ad_leads SET status = 'Closed Won', updated_at = datetime('now') WHERE id = ?`, [resolvedAdLeadId]);
    // Repousse vers GoHighLevel : marque l'opportunite correspondante "won". Fire-and-forget
    // (voir ghlClient.js) — un souci cote GHL ne doit jamais retarder ou faire echouer la
    // creation du deal cote Protek.
    const closedAdLead = get('SELECT ghl_contact_id FROM ad_leads WHERE id = ?', [resolvedAdLeadId]);
    if (closedAdLead && closedAdLead.ghl_contact_id) markOpportunityWon(closedAdLead.ghl_contact_id);
  }
  const dealPrice = parseFloat(price) || 0;
  // Notification chat — aucune donnee client (pas de nom, prix, ou photo), juste
  // le compteur attribue au closer, avec le setter qui a pris le rendez-vous d'origine.
  // (Les deals issus du Leads CRM ne postent pas dans le chat porte-a-porte — sections isolees.)
  if (!resolvedAdLeadId) {
    const closerUser = closerId ? get('SELECT first_name, last_name FROM users WHERE id = ?', [closerId]) : null;
    const setterUser = setterId ? get('SELECT first_name, last_name FROM users WHERE id = ?', [setterId]) : null;
    const closerName = closerUser ? `${closerUser.first_name} ${closerUser.last_name}` : 'Closer inconnu';
    const setterName = setterUser ? `${setterUser.first_name} ${setterUser.last_name}` : null;
    postSystemMessage(
      `🎉💰 DEAL CLOSÉ !\n${closerName} vient de fermer une vente!`
      + (setterName ? `\n${setterName} +$300 🙌` : '')
      + `\nON EST EN FEU! 🔥`
    );
    // Le setter qui a pose le rendez-vous d'origine, et l'owner, veulent savoir des qu'un deal
    // porte-a-porte ferme (voir demande utilisateur : setter + admin notifies sur "deal ferme").
    if (setterId) {
      notifyUser(setterId, `💰 ${LABEL_D2D} Deal fermé: ${clientName} — $${dealPrice}`,
        { title: `💰 Deal fermé ${LABEL_D2D}`, body: `${clientName} — $${dealPrice}`, url: '/' });
    }
    notifyRole('owner', `💰 ${LABEL_D2D} Deal fermé: ${clientName} — $${dealPrice}`,
      { title: `💰 Deal fermé ${LABEL_D2D}`, body: `${clientName} — $${dealPrice}`, url: '/' });
  } else {
    // Deal issu du Lead CRM (marketing) — le role marketing et l'owner veulent savoir que ce
    // lead publicitaire vient de se transformer en vente.
    notifyRole(['lead_marketing', 'owner'], `💰 ${LABEL_LEADS} Lead fermé: ${clientName} — $${dealPrice}`,
      { title: `💰 Lead fermé ${LABEL_LEADS}`, body: `${clientName} — $${dealPrice}`, url: '/' });
  }
  // Automatisation SMS + courriel client — declenchee a la creation du deal (le moment ou
  // la vente est "closed won" dans le CRM, D2D comme lead marketing), voir demande
  // utilisateur "automatisation sms/courriel quand un deal est closed won". Fire-and-forget
  // (pas de await) — un souci Twilio/Resend ne doit jamais retarder ou faire echouer la
  // creation du deal cote closer ; chaque util est deja best-effort de son cote (no-op si
  // les cles TWILIO_*/RESEND_API_KEY ne sont pas configurees sur Railway).
  const { subject: closedWonSubject, body: closedWonBody } = buildClosedWonMessage(clientName);
  if (phone) sendSms({ to: phone, body: closedWonBody });
  if (email) sendEmail({ to: email, subject: closedWonSubject, text: closedWonBody });

  return res.status(201).json({ message: 'Deal created.', id: dealId });
});

// Audit 2026-09-05 : n'avait que requireAuth — en pratique, seul l'ecran manager/owner
// (openDealDetailSheet cote frontend) appelle ce PATCH (changement de statut, assignation d'un
// technicien) ; rien ne l'empechait cote serveur d'etre appele par n'importe quel role
// authentifie. Restreint a requireManagerOrOwner, deja utilise pour les routes /tickets
// equivalentes.
router.patch('/deals/:id', requireAuth, requireManagerOrOwner, (req, res) => {
  const { id } = req.params;
  const { status, techId, installDate, photoUrls, price, cost, selfLead } = req.body;
  const deal = get('SELECT * FROM deals WHERE id = ?', [id]);
  if (!deal) return res.status(404).json({ error: 'Deal not found.' });
  // Audit 2026-09-07 (test end-to-end) : meme raisonnement que POST /deals ci-dessus — ni le prix
  // ni le cout d'installation ne devraient jamais etre negatifs (un cout plus eleve que le prix
  // reduit deja la commission du closer jusqu'a zero/negatif, voir syncCommissionsForDeal ; ca
  // reste une decision produit distincte de "un montant negatif saisi par erreur").
  if (price !== undefined && price !== null && price !== '' && parseFloat(price) < 0) {
    return res.status(400).json({ error: 'Price cannot be negative.' });
  }
  if (cost !== undefined && cost !== null && cost !== '' && parseFloat(cost) < 0) {
    return res.status(400).json({ error: 'Cost cannot be negative.' });
  }
  // price/cost/selfLead : reserves a l'owner (calcul des commissions, voir requireOwner ci-dessous
  // sur PATCH /commissions et syncCommissionsForDeal) — un closer ne doit pas pouvoir gonfler sa
  // propre commission en modifiant son prix ou son cout apres coup.
  const canEditMoney = req.user.role === 'owner';
  const sets = [];
  const params = [];
  if (status !== undefined)      { sets.push('status = ?');       params.push(status); }
  if (techId !== undefined)      { sets.push('tech_id = ?');      params.push(techId || null); }
  if (installDate !== undefined) { sets.push('install_date = ?'); params.push(installDate || null); }
  if (photoUrls !== undefined)   { sets.push('photo_urls = ?');   params.push(JSON.stringify(photoUrls)); }
  if (canEditMoney && price !== undefined)    { sets.push('price = ?');     params.push(parseFloat(price) || 0); }
  if (canEditMoney && cost !== undefined)     { sets.push('cost = ?');      params.push(parseFloat(cost) || 0); }
  if (canEditMoney && selfLead !== undefined) { sets.push('self_lead = ?'); params.push(selfLead ? 1 : 0); }
  if (!sets.length) return res.status(400).json({ error: 'Nothing to update.' });
  sets.push("updated_at = datetime('now')");
  params.push(id);
  run(`UPDATE deals SET ${sets.join(', ')} WHERE id = ?`, params);
  if (canEditMoney && (price !== undefined || cost !== undefined || selfLead !== undefined)) {
    syncCommissionsForDeal(id);
  }
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

// ── Commissions — voir syncCommissionsForDeal() plus haut pour le calcul. Setter/closer voient
// uniquement les leurs (/commissions/mine) ; l'owner voit tout et peut basculer le statut
// pending <-> paid ("a verser" / "verse", voir demande utilisateur).
router.get('/commissions/mine', requireAuth, requireD2DOnly, (req, res) => {
  const rows = query(
    `SELECT c.*, d.client_name, d.price, d.install_date, d.status AS deal_status
     FROM commissions c
     JOIN deals d ON c.deal_id = d.id
     WHERE c.user_id = ?
     ORDER BY c.created_at DESC`,
    [req.user.id]
  );
  return res.json(rows);
});

router.get('/commissions', requireAuth, requireOwner, (req, res) => {
  const rows = query(
    `SELECT c.*, d.client_name, d.price, d.install_date, d.status AS deal_status,
       u.first_name || ' ' || u.last_name AS user_name
     FROM commissions c
     JOIN deals d ON c.deal_id = d.id
     LEFT JOIN users u ON c.user_id = u.id
     ORDER BY c.created_at DESC`
  );
  return res.json(rows);
});

router.patch('/commissions/:id', requireAuth, requireOwner, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!['pending', 'paid'].includes(status)) {
    return res.status(400).json({ error: "status must be 'pending' or 'paid'." });
  }
  const commission = get('SELECT id FROM commissions WHERE id = ?', [id]);
  if (!commission) return res.status(404).json({ error: 'Commission not found.' });
  run(`UPDATE commissions SET status = ?, updated_at = datetime('now') WHERE id = ?`, [status, id]);
  return res.json({ message: 'Commission updated.' });
});

// ── Blocages d'horaire closer (vacances, sport, indisponibilite) — voir demande utilisateur
// "mettre des endpoints dans l'horaire ou tu peux pas mettre de rdv". Le closer gere les siens ;
// l'owner peut en gerer pour n'importe quel closer (utile s'il bloque une journee ferie pour
// toute l'equipe, par exemple). Bloque la prise de RDV pour tout le monde — voir la verification
// dans POST /leads et PATCH /appointments/:id plus bas (isSlotBlocked()).
router.get('/closer-blackouts', requireAuth, requireD2DOnly, (req, res) => {
  return res.json(query('SELECT * FROM closer_blackouts ORDER BY date ASC'));
});

router.post('/closer-blackouts', requireAuth, requireD2DOnly, (req, res) => {
  const { closerId, date, allDay, startHour, endHour, reason } = req.body;
  const r = req.user.role;
  if (r !== 'closer' && r !== 'team_leader_vente' && r !== 'owner') {
    return res.status(403).json({ error: 'Closer or owner access required.' });
  }
  const targetCloserId = (r === 'owner' && closerId) ? closerId : req.user.id;
  if (!date) return res.status(400).json({ error: 'date required.' });
  const isAllDay = allDay === undefined ? true : !!allDay;
  const id = uuid();
  run(
    `INSERT INTO closer_blackouts (id, closer_id, date, all_day, start_hour, end_hour, reason)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [id, targetCloserId, date, isAllDay ? 1 : 0,
     isAllDay ? null : (parseFloat(startHour) || null),
     isAllDay ? null : (parseFloat(endHour) || null),
     reason || null]
  );
  return res.status(201).json({ message: 'Blackout created.', id });
});

router.delete('/closer-blackouts/:id', requireAuth, requireD2DOnly, (req, res) => {
  const { id } = req.params;
  const b = get('SELECT * FROM closer_blackouts WHERE id = ?', [id]);
  if (!b) return res.status(404).json({ error: 'Blackout not found.' });
  if (req.user.role !== 'owner' && b.closer_id !== req.user.id) {
    return res.status(403).json({ error: 'Access denied.' });
  }
  run('DELETE FROM closer_blackouts WHERE id = ?', [id]);
  return res.json({ message: 'Blackout deleted.' });
});

// Verifie si un creneau (closerId/date/hour) tombe dans un blocage — utilisee avant de creer ou
// reprogrammer un rendez-vous (voir POST /leads et PATCH /appointments/:id).
function isSlotBlocked(closerId, date, hour) {
  if (!closerId || !date) return false;
  const blocks = query('SELECT * FROM closer_blackouts WHERE closer_id = ? AND date = ?', [closerId, date]);
  return blocks.some(b => {
    if (b.all_day) return true;
    if (hour == null || b.start_hour == null || b.end_hour == null) return false;
    return hour >= b.start_hour && hour < b.end_hour;
  });
}

router.get  ('/tickets',     requireAuth, requireTicketAccess,   getTickets);
router.get  ('/tickets/:id', requireAuth, requireTicketAccess,   getTicket);
router.patch('/tickets/:id', requireAuth, requireTicketUpdateAccess, updateTicket);

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

// ── Notifications push (telephone) ──
// Cle publique VAPID necessaire cote front pour pushManager.subscribe() — publique par design,
// aucune authentification requise (elle ne sert a rien sans la cle privee cote serveur).
router.get('/push/vapid-public-key', (req, res) => {
  if (!VAPID_PUBLIC_KEY) return res.status(503).json({ error: 'Push not configured.' });
  return res.json({ publicKey: VAPID_PUBLIC_KEY });
});

// Enregistre (ou met a jour) l'abonnement push de l'appareil courant pour l'utilisateur connecte.
// Un utilisateur peut avoir plusieurs abonnements actifs (telephone + ordinateur) — on upsert sur
// endpoint (unique par appareil/navigateur) plutot que de remplacer l'abonnement precedent.
router.post('/push/subscribe', requireAuth, (req, res) => {
  const { endpoint, keys } = req.body || {};
  if (!endpoint || !keys || !keys.p256dh || !keys.auth) {
    return res.status(400).json({ error: 'endpoint and keys.p256dh/keys.auth required.' });
  }
  run(
    `INSERT INTO push_subscriptions (id, user_id, endpoint, p256dh, auth) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth`,
    [uuid(), req.user.id, endpoint, keys.p256dh, keys.auth]
  );
  return res.status(201).json({ message: 'Subscribed.' });
});

router.delete('/push/subscribe', requireAuth, (req, res) => {
  const { endpoint } = req.body || {};
  if (!endpoint) return res.status(400).json({ error: 'endpoint required.' });
  run('DELETE FROM push_subscriptions WHERE endpoint = ? AND user_id = ?', [endpoint, req.user.id]);
  return res.json({ message: 'Unsubscribed.' });
});

router.get('/leads-crm/leads', requireAuth, requireLeadsCrmAccess, (req, res) => {
  const rows = query(
    `SELECT l.*, c.first_name || ' ' || c.last_name AS closer_name
     FROM ad_leads l
     LEFT JOIN users c ON l.closer_id = c.id
     ORDER BY l.created_at DESC`
  );
  rows.forEach(r => { try { r.quote_image_urls = JSON.parse(r.quote_image_urls || '[]'); } catch { r.quote_image_urls = []; } });
  return res.json(rows);
});

// Coeur partage entre la creation manuelle (POST /leads-crm/leads, un membre de l'equipe connecte)
// et l'ingestion automatique (POST /webhooks/ad-leads, une source externe comme Zapier relayant
// Facebook/Instagram/Google) : insere le lead marketing et notifie l'equipe Leads CRM.
// createdBy est null pour un lead venu d'un webhook (pas d'utilisateur CRM a l'origine).
//
// Notifie les lead closers (qui doivent contacter le lead au plus vite), le role marketing (qui a
// paye pour le lead et veut voir en temps reel que la pub convertit), ET l'owner (visibilite
// complete sur les deux CRM) — tous via notifyRole (in-app + push, voir utils/notify.js).
function insertAdLead({
  source, firstName, lastName, phone, email, notes, createdBy, ghlContactId,
  city, buildingType, calfeutrageCondition, zonesToSeal, projectDetails, formSource,
}) {
  const id = uuid();
  run(
    `INSERT INTO ad_leads (
       id, source, first_name, last_name, phone, email, notes, status, created_by, ghl_contact_id,
       city, building_type, calfeutrage_condition, zones_to_seal, project_details, form_source,
       qualification_exempt
     ) VALUES (?, ?, ?, ?, ?, ?, ?, 'New', ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
    [
      id, source || 'Autre', firstName, lastName, phone, email || null, notes || null, createdBy || null, ghlContactId || null,
      city || null, buildingType || null, calfeutrageCondition || null, zonesToSeal || null, projectDetails || null, formSource || null,
    ]
  );
  notifyRole(['lead_closer', 'lead_marketing', 'owner'],
    `🆕 ${LABEL_LEADS} Nouveau lead (${source || 'Autre'}): ${firstName} ${lastName} — ${phone}`,
    { title: `🆕 Nouveau lead ${LABEL_LEADS}`, body: `${firstName} ${lastName} — ${phone}`, url: '/' });
  // SMS automatise au client des la reception d'un nouveau lead (toutes sources), demande
      // utilisateur 2026-09-15 — voir utils/newLeadSms.js. Fire-and-forget comme le message
      // closed-won : un souci Twilio ne doit jamais faire echouer la creation du lead.
      if (phone) sendSms({ to: phone, body: buildNewLeadSms() });
      return id;
}

router.post('/leads-crm/leads', requireAuth, requireLeadsCrmAccess, async (req, res) => {
  const { source, firstName, lastName, phone, email, notes } = req.body;
  if (!firstName || !lastName || !phone) {
    return res.status(400).json({ error: 'firstName, lastName, phone required.' });
  }
  const id = insertAdLead({ source, firstName, lastName, phone, email, notes, createdBy: req.user.id });
  return res.status(201).json({ message: 'Lead created.', id });
});

// POST /webhooks/ad-leads — point d'entree PUBLIC (aucune session CRM possible depuis Zapier/Meta/
// Google) pour l'ingestion automatique des leads publicitaires. Protege par une cle partagee
// (LEADS_WEBHOOK_SECRET, voir variables Railway) passee en query (?key=...) ou header
// x-webhook-secret — jamais par un compte utilisateur. Accepte plusieurs alias de champs car
// chaque plateforme (Facebook Lead Ads, Google Ads, Zapier) nomme ses champs differemment ; on
// tente aussi de scinder un nom complet ("fullName"/"name") si prenom/nom ne sont pas fournis
// separement.
router.post('/webhooks/ad-leads', webhookLimiter, (req, res) => {
  const configuredSecret = process.env.LEADS_WEBHOOK_SECRET;
  if (!configuredSecret) {
    return res.status(503).json({ error: 'Webhook non configure (LEADS_WEBHOOK_SECRET manquant).' });
  }
  const providedSecret = req.query.key || req.headers['x-webhook-secret'];
  if (!secretsMatch(providedSecret, configuredSecret)) {
    return res.status(401).json({ error: 'Cle webhook invalide.' });
  }

  const b = req.body || {};
  let firstName = b.firstName || b.first_name || '';
  let lastName  = b.lastName  || b.last_name  || '';
  if (!firstName && !lastName) {
    const full = (b.fullName || b.full_name || b.name || '').trim();
    if (full) {
      const parts = full.split(/\s+/);
      firstName = parts.shift() || '';
      lastName = parts.join(' ') || '';
    }
  }
  const phone = b.phone || b.phone_number || b.phoneNumber || '';
  const email = b.email || b.email_address || b.emailAddress || null;
  const source = b.source || b.platform || 'Facebook';
  const notes  = b.notes || b.message || null;
  // Id du contact GoHighLevel (merge tag {{contact.id}} cote workflow) — necessaire pour
  // repousser plus tard les changements de statut vers GHL (voir ghlClient.js). Optionnel :
  // les sources qui ne le fournissent pas (Meta/Google directs) continuent de fonctionner,
  // simplement sans synchronisation retour.
  const ghlContactId = b.contactId || b.contact_id || null;
  // Champs du formulaire de qualification GHL (Custom Fields > Additional Info) — merge tags
  // {{contact.ville}}, {{contact.type_de_btiment}}, {{contact.tat_du_calfeutrage}},
  // {{contact.zones__calfeutrer}}, {{contact.dtails_du_projet}}, {{contact.source_du_formulaire}}.
  // On accepte plusieurs alias par champ : le workflow GHL qui poste ici peut nommer ses clefs
  // JSON soit comme le merge tag brut, soit en camelCase, soit avec le libelle exact du champ —
  // meme logique defensive que firstName/phone/email ci-dessus.
  const city = b.city || b.ville || b.Ville || null;
  const buildingType = b.buildingType || b.building_type
    || b.type_de_btiment || b.type_de_batiment || b['Type de bâtiment'] || null;
  const calfeutrageCondition = b.calfeutrageCondition || b.calfeutrage_condition
    || b.tat_du_calfeutrage || b.etat_du_calfeutrage || b['État du calfeutrage'] || null;
  const zonesToSeal = b.zonesToSeal || b.zones_to_seal
    || b.zones__calfeutrer || b.zones_a_calfeutrer || b['Zones à calfeutrer'] || null;
  const projectDetails = b.projectDetails || b.project_details
    || b.dtails_du_projet || b.details_du_projet || b['Détails du projet'] || null;
  const formSource = b.formSource || b.form_source
    || b.source_du_formulaire || b['Source du formulaire'] || null;

  if (!firstName || !phone) {
    return res.status(400).json({ error: 'firstName (ou fullName) et phone requis.' });
  }

  // Anti-doublon : depuis que notre site web (calfeutrageprotek.com) relaye lui-meme les leads
  // vers ce webhook EN PLUS d'une automatisation GHL qui relaye parfois le meme contact, une seule
  // soumission de formulaire peut declencher deux appels quasi simultanes pour la meme personne.
  // On ignore une nouvelle insertion si un lead avec le meme telephone (normalise, sans espaces/
  // tirets/parentheses) a deja ete cree dans les 5 dernieres minutes — assez court pour ne jamais
  // bloquer une resoumission volontaire plus tard, assez long pour absorber la course entre les
  // deux chemins d'ingestion. Voir memoire "protek-website-lead-pipeline" pour le contexte complet.
  const normalizedPhone = phone.replace(/\D/g, '');
  if (normalizedPhone) {
    const recentDup = get(
      `SELECT id FROM ad_leads
       WHERE REPLACE(REPLACE(REPLACE(REPLACE(phone,'-',''),' ',''),'(',''),')','') = ?
         AND created_at >= datetime('now', '-5 minutes')
       ORDER BY created_at DESC LIMIT 1`,
      [normalizedPhone]
    );
    if (recentDup) {
      return res.status(200).json({ message: 'Lead deja recu (doublon evite).', id: recentDup.id });
    }
  }

  try {
    const id = insertAdLead({
      source, firstName, lastName: lastName || '—', phone, email, notes, createdBy: null, ghlContactId,
      city, buildingType, calfeutrageCondition, zonesToSeal, projectDetails, formSource,
    });
    return res.status(201).json({ message: 'Lead created.', id });
  } catch (e) {
    console.error('webhook ad-leads error', e);
    return res.status(500).json({ error: 'Insertion echouee.' });
  }
});

// ═══════════════════════════════════════════
// APRES-VENTE — file de demandes admin-only (owner uniquement), separee du pipeline de vente.
// Ingeree via le formulaire calfeutrageprotek.com/apres-vente -> fonction Supabase notify-lead
// (isAfterSales:true) -> ce webhook, jamais melangee a ad_leads/appointments. Voir memoire
// "protek-closer-calendar-features" / "protek-website-lead-pipeline" pour le contexte du pipeline
// existant qu'on reutilise cote transport (meme cle partagee) sans reutiliser la table.
// ═══════════════════════════════════════════
function insertAfterSalesRequest({ firstName, lastName, phone, email, address, city, installDate, invoiceNumber, description }) {
  const id = uuid();
  run(
    `INSERT INTO after_sales_requests (
       id, first_name, last_name, phone, email, address, city, install_date, invoice_number, description, status
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'New')`,
    [id, firstName, lastName || null, phone, email || null, address || null, city || null, installDate || null, invoiceNumber || null, description || null]
  );
  // Owner uniquement — jamais les roles de vente (setter/closer/lead_closer/lead_marketing),
  // c'est une demande de service, pas un prospect.
  notifyRole('owner', `🛠️ Nouvelle demande apres-vente: ${firstName} ${lastName || ''} — ${phone}`,
    { title: '🛠️ Nouvelle demande apres-vente', body: `${firstName} ${lastName || ''} — ${phone}`, url: '/' });
  return id;
}

// POST /webhooks/after-sales — point d'entree PUBLIC (meme cle partagee LEADS_WEBHOOK_SECRET que
// /webhooks/ad-leads, deja provisionnee sur Railway ET dans le projet Supabase du site — voir
// PROTEK_CRM_WEBHOOK_SECRET, meme valeur). Accepte les memes alias de champs que /webhooks/ad-leads
// par coherence, meme si aujourd'hui seule notify-lead (isAfterSales) l'appelle.
router.post('/webhooks/after-sales', webhookLimiter, (req, res) => {
  const configuredSecret = process.env.LEADS_WEBHOOK_SECRET;
  if (!configuredSecret) {
    return res.status(503).json({ error: 'Webhook non configure (LEADS_WEBHOOK_SECRET manquant).' });
  }
  const providedSecret = req.query.key || req.headers['x-webhook-secret'];
  if (!secretsMatch(providedSecret, configuredSecret)) {
    return res.status(401).json({ error: 'Cle webhook invalide.' });
  }

  const b = req.body || {};
  let firstName = b.firstName || b.first_name || '';
  let lastName  = b.lastName  || b.last_name  || '';
  if (!firstName && !lastName) {
    const full = (b.name || b.fullName || b.full_name || '').trim();
    if (full) {
      const parts = full.split(/\s+/);
      firstName = parts.shift() || '';
      lastName = parts.join(' ') || '';
    }
  }
  const phone = b.phone || b.phone_number || b.phoneNumber || '';
  const email = b.email || b.email_address || b.emailAddress || null;
  const address = b.address || null;
  const city = b.city || b.ville || null;
  const installDate = b.installDate || b.install_date || null;
  const invoiceNumber = b.invoiceNumber || b.invoice_number || null;
  const description = b.description || b.message || b.notes || null;

  if (!firstName || !phone) {
    return res.status(400).json({ error: 'firstName (ou name) et phone requis.' });
  }

  try {
    const id = insertAfterSalesRequest({ firstName, lastName, phone, email, address, city, installDate, invoiceNumber, description });
    return res.status(201).json({ message: 'After-sales request created.', id });
  } catch (e) {
    console.error('webhook after-sales error', e);
    return res.status(500).json({ error: 'Insertion echouee.' });
  }
});

// GET/PATCH/DELETE /after-sales — reserve a l'owner ET au gerant des installations (manager),
// voir requireManagerOrOwner. Demande utilisateur (2026-08-03) : le gerant doit avoir le meme
// acces que l'owner sur cette section (il assigne les jobs aux techniciens). Toujours bloque pour
// setter/closer/tech/lead_marketing/lead_closer/team_leader_vente.
router.get('/after-sales', requireAuth, requireManagerOrOwner, (req, res) => {
  const rows = query('SELECT * FROM after_sales_requests ORDER BY created_at DESC');
  rows.forEach(r => { try { r.photo_urls = JSON.parse(r.photo_urls || '[]'); } catch { r.photo_urls = []; } });
  return res.json(rows);
});

router.patch('/after-sales/:id', requireAuth, requireManagerOrOwner, (req, res) => {
  const { id } = req.params;
  const { status, adminNotes, photoUrls } = req.body;
  const reqRow = get('SELECT * FROM after_sales_requests WHERE id = ?', [id]);
  if (!reqRow) return res.status(404).json({ error: 'Demande introuvable.' });
  const sets = [];
  const params = [];
  if (status !== undefined)     { sets.push('status = ?');       params.push(status); }
  if (adminNotes !== undefined) { sets.push('admin_notes = ?');  params.push(adminNotes || null); }
  // Photos televersees depuis la fiche (ex: photos du degat/probleme signale) — meme convention
  // JSON que partout ailleurs (deals/appointments/ad_leads).
  if (photoUrls !== undefined)  { sets.push('photo_urls = ?');   params.push(JSON.stringify(Array.isArray(photoUrls) ? photoUrls : [])); }
  if (sets.length) {
    sets.push("updated_at = datetime('now')");
    params.push(id);
    run(`UPDATE after_sales_requests SET ${sets.join(', ')} WHERE id = ?`, params);
  }
  return res.json({ message: 'After-sales request updated.' });
});

// Suppression — demande utilisateur explicite. Reserve owner/manager comme le reste de la
// section. Ne touche pas a un eventuel ticket d'installation deja cree (voir assign ci-dessous) :
// une fois assigne a un technicien, le job continue d'exister dans installation_tickets meme si
// la demande apres-vente d'origine est supprimee.
router.delete('/after-sales/:id', requireAuth, requireManagerOrOwner, (req, res) => {
  const { id } = req.params;
  const reqRow = get('SELECT id FROM after_sales_requests WHERE id = ?', [id]);
  if (!reqRow) return res.status(404).json({ error: 'Demande introuvable.' });
  run('DELETE FROM after_sales_requests WHERE id = ?', [id]);
  return res.json({ message: 'After-sales request deleted.' });
});

// Assigner une demande apres-vente a un technicien — cree (ou met a jour, si deja assignee une
// premiere fois) un installation_ticket exactement comme un deal Closed Won le ferait, pour que
// le technicien la voie dans SON PROPRE horaire (GET /tickets scope deja par tech_id) au meme
// titre qu'une installation normale. Voir demande utilisateur "assigner a un technicien qui iras
// directement dans son horaire comme une installation normale".
router.post('/after-sales/:id/assign', requireAuth, requireManagerOrOwner, (req, res) => {
  const { id } = req.params;
  const { techId, scheduledDate } = req.body;
  const asRow = get('SELECT * FROM after_sales_requests WHERE id = ?', [id]);
  if (!asRow) return res.status(404).json({ error: 'Demande introuvable.' });
  if (!techId) return res.status(400).json({ error: 'techId requis.' });

  const clientName = `${asRow.first_name || ''} ${asRow.last_name || ''}`.trim() || 'Client';
  let ticketId = asRow.ticket_id;
  if (ticketId) {
    // Deja assignee une premiere fois — on met simplement a jour le technicien/la date plutot
    // que de creer un second ticket pour la meme demande.
    run(
      `UPDATE installation_tickets SET tech_id = ?, scheduled_install_date = ?, status = 'Scheduled', updated_at = datetime('now') WHERE id = ?`,
      [techId, scheduledDate || null, ticketId]
    );
  } else {
    ticketId = uuid();
    run(
      `INSERT INTO installation_tickets (
         id, after_sales_id, client_name, address, city, phone, email,
         notes, photo_urls, scheduled_install_date, tech_id, status
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        ticketId, asRow.id, clientName, asRow.address || null, asRow.city || null,
        asRow.phone || null, asRow.email || null, asRow.description || null,
        asRow.photo_urls || '[]', scheduledDate || null, techId, 'Scheduled',
      ]
    );
    run("UPDATE after_sales_requests SET ticket_id = ?, status = 'In Progress', updated_at = datetime('now') WHERE id = ?", [ticketId, asRow.id]);
  }
  const tech = get('SELECT first_name FROM users WHERE id = ?', [techId]);
  if (tech) {
    const dateStr = scheduledDate ? ` le ${scheduledDate}` : '';
    notifyUser(techId, `🛠️ Job après-vente assigné: ${clientName}${dateStr} — ${asRow.address || ''}`,
      { title: '🛠️ Job après-vente assigné', body: `${clientName}${dateStr}`, url: '/' });
  }
  return res.json({ message: 'After-sales request assigned.', ticketId });
});


// Verrou de qualification : un lead_closer ne peut pas deplacer un lead NON exempt (voir
// qualification_exempt, migration database.js) vers un autre statut tant que la fiche de
// qualification n'est pas complete (qualification_completed_at NULL). L'owner peut toujours
// forcer un changement de statut en cas d'exception (voir requete utilisateur). Cette fonction
// est aussi appelee par PATCH .../qualification pour re-verifier apres sauvegarde.
function isQualificationBlocking(lead, actorRole, targetStatus) {
  if (actorRole !== 'lead_closer') return false;
  if (lead.qualification_exempt) return false;
  if (lead.qualification_completed_at) return false;
  // "Contacted" indique seulement qu'un premier contact a ete effectue, et "Not Qualified" est
  // une sortie anticipee du pipeline (hors territoire, hors sujet, projet non admissible, etc.) —
  // aucun des deux ne doit jamais etre bloque par la fiche de qualification. Elle ne redevient
  // obligatoire qu'a partir de la prise de rendez-vous / des etapes suivantes. Voir demande
  // utilisateur "permettre de deplacer un lead vers Contacte sans prequalification".
  if (targetStatus === 'Contacted' || targetStatus === 'Not Qualified') return false;
  return true;
}
const QUALIFICATION_LOCK_MESSAGE = 'Veuillez compléter la fiche de qualification avant de pouvoir déplacer ce lead vers un autre statut.';

router.patch('/leads-crm/leads/:id', requireAuth, requireQueueOwner, (req, res) => {
  const { id } = req.params;
  const { status, claim, apptDate, apptHour, notes, quoteImageUrls } = req.body;
  const lead = get('SELECT * FROM ad_leads WHERE id = ?', [id]);
  if (!lead) return res.status(404).json({ error: 'Lead not found.' });

  // Le verrou ne bloque que les VRAIS changements de statut (une valeur differente de l'actuel) —
  // re-cliquer le statut deja actif (no-op) ou faire d'autres actions (claim, notes, RDV, quote)
  // reste toujours permis meme fiche incomplete, sinon on empecherait meme de commencer a
  // qualifier le lead (prendre le RDV fait partie de la fiche elle-meme, voir Q11).
  if (status && status !== lead.status && isQualificationBlocking(lead, req.user.role, status)) {
    return res.status(400).json({ error: QUALIFICATION_LOCK_MESSAGE });
  }

  const sets = ["updated_at = datetime('now')"];
  const params = [];

  if (claim) { sets.push('closer_id = ?'); params.push(req.user.role === 'owner' ? (req.body.closerId || req.user.id) : req.user.id); }
  if (!lead.contacted_at && (status === 'Contacted' || apptDate)) {
    sets.push('contacted_at = ?'); params.push(new Date().toISOString());
  }
  if (apptDate !== undefined) { sets.push('appt_date = ?'); params.push(apptDate || null); }
  if (apptHour !== undefined) { sets.push('appt_hour = ?'); params.push(apptHour != null ? parseFloat(apptHour) : null); }
  if (notes !== undefined) { sets.push('notes = ?'); params.push(notes || null); }
  // Image(s) de soumission/quote (etape "Left Quote") — le front envoie toujours le tableau
  // complet (existant + nouvelles URLs Cloudinary), meme convention que deals.photo_urls : on
  // remplace la colonne entiere plutot que d'append cote serveur.
  if (quoteImageUrls !== undefined) {
    sets.push('quote_image_urls = ?');
    params.push(JSON.stringify(Array.isArray(quoteImageUrls) ? quoteImageUrls : []));
  }
  // "Not Qualified" est traite comme terminal (n'avance jamais automatiquement via apptDate,
  // voir plus bas) mais a sa PROPRE notification (pas "ferme/perdu/no-show") — voir bloc dedie
  // apres la sauvegarde.
  const TERMINAL_STATUSES = ['Closed Won', 'Closed Lost', 'No Show', 'Not Qualified'];
  if (status) {
    sets.push('status = ?'); params.push(status);
  } else if (apptDate && !TERMINAL_STATUSES.includes(lead.status)) {
    // Fixer une date de rendez-vous fait toujours progresser le lead vers "Appointment Set",
    // qu'il vienne de "New" ou de "Contacted" — sauf s'il est deja dans un etat final.
    sets.push('status = ?'); params.push('Appointment Set');
  }

  params.push(id);
  run(`UPDATE ad_leads SET ${sets.join(', ')} WHERE id = ?`, params);

  const leadName = `${lead.first_name || ''} ${lead.last_name || ''}`.trim() || 'Client';
  // RDV pris sur un lead marketing — l'owner veut le savoir, comme cote porte-a-porte (voir
  // POST /leads). Le closer qui vient de le prendre le sait deja (c'est son action), pas besoin
  // de le renotifier lui-meme.
  if (apptDate && !lead.appt_date) {
    notifyRole('owner', `📅 ${LABEL_LEADS} RDV pris: ${leadName} le ${apptDate}`,
      { title: `📅 RDV pris ${LABEL_LEADS}`, body: `${leadName} — ${apptDate}`, url: '/' });
    // Repousse vers GoHighLevel : deplace l'opportunite correspondante vers l'etape
    // CONFIRMATION du pipeline LEADS. Fire-and-forget (pas de await) — un souci cote GHL
    // (token expire, opportunite introuvable) ne doit jamais retarder ou faire echouer la
    // reponse au closer qui vient de booker le RDV. Voir ghlClient.js pour le detail.
    if (lead.ghl_contact_id) moveOpportunityToConfirmation(lead.ghl_contact_id);
  }
  // Lead marketing ferme (gagne ou perdu) — marketing (a paye pour ce lead) + owner veulent savoir.
  const CLOSED_TERMINAL_STATUSES = ['Closed Won', 'Closed Lost', 'No Show'];
  if (status && CLOSED_TERMINAL_STATUSES.includes(status) && lead.status !== status) {
    const verb = status === 'Closed Won' ? 'fermé' : (status === 'No Show' ? 'no-show' : 'perdu');
    notifyRole(['lead_marketing', 'owner'], `💰 ${LABEL_LEADS} Lead ${verb}: ${leadName}`,
      { title: `💰 Lead ${verb} ${LABEL_LEADS}`, body: leadName, url: '/' });
  }
  // Lead marque "Non qualifie" — sortie anticipee du pipeline (hors territoire, hors sujet,
  // projet non admissible, etc.), voir demande utilisateur "ajouter une section Non qualifies".
  if (status === 'Not Qualified' && lead.status !== 'Not Qualified') {
    notifyRole(['lead_marketing', 'owner'], `🚫 ${LABEL_LEADS} Lead non qualifié: ${leadName}`,
      { title: `🚫 Lead non qualifié ${LABEL_LEADS}`, body: leadName, url: '/' });
  }
  return res.json({ message: 'Lead updated.' });
});

// ── Fiche de qualification (Leads CRM, appel initial du lead_closer) ──
// Validee cote serveur (en plus du front) avant de marquer qualification_completed_at : c'est ce
// timestamp, et lui seul, que le verrou de statut ci-dessus consulte. Tant que la validation
// echoue, on sauvegarde quand meme les reponses fournies (permet un remplissage progressif
// pendant l'appel) mais qualification_completed_at reste NULL — le lead reste bloque.
router.patch('/leads-crm/leads/:id/qualification', requireAuth, requireQueueOwner, (req, res) => {
  const { id } = req.params;
  const lead = get('SELECT * FROM ad_leads WHERE id = ?', [id]);
  if (!lead) return res.status(404).json({ error: 'Lead not found.' });

  const b = req.body || {};
  const unitsCount = (b.unitsCount || '').toString().trim();
  const buildingType = (b.buildingType || '').toString().trim();
  const sealantColor = (b.sealantColor || '').toString().trim();
  const sealantColorOther = (b.sealantColorOther || '').toString().trim();
  const language = (b.language || '').toString().trim();
  const reasons = Array.isArray(b.reasons) ? b.reasons.filter(Boolean) : [];
  const reasonsOther = (b.reasonsOther || '').toString().trim();
  const timeline = (b.timeline || '').toString().trim();
  const otherRenovations = (b.otherRenovations || '').toString().trim();
  const otherRenovationsWhich = (b.otherRenovationsWhich || '').toString().trim();
  const renovationPriority = (b.renovationPriority || '').toString().trim();
  const decisionMakerInvolved = (b.decisionMakerInvolved || '').toString().trim();
  const apptNotBookedReason = (b.apptNotBookedReason || '').toString().trim();

  const missing = [];
  if (!unitsCount) missing.push('unitsCount');
  if (!buildingType) missing.push('buildingType');
  if (!sealantColor) missing.push('sealantColor');
  if (sealantColor === 'Autre' && !sealantColorOther) missing.push('sealantColorOther');
  if (!language) missing.push('language');
  if (!reasons.length) missing.push('reasons');
  if (reasons.includes('Autre') && !reasonsOther) missing.push('reasonsOther');
  if (!timeline) missing.push('timeline');
  if (otherRenovations !== 'Oui' && otherRenovations !== 'Non') missing.push('otherRenovations');
  if (otherRenovations === 'Oui' && !otherRenovationsWhich) missing.push('otherRenovationsWhich');
  if (otherRenovations === 'Oui' && !renovationPriority) missing.push('renovationPriority');
  if (decisionMakerInvolved !== 'Oui' && decisionMakerInvolved !== 'Non') missing.push('decisionMakerInvolved');
  // Q11 : soit un RDV est deja booke (lead.appt_date, via PATCH /leads-crm/leads/:id existant),
  // soit la raison de non-booking est fournie ici — l'un des deux est obligatoire.
  const apptResolved = !!lead.appt_date || !!apptNotBookedReason;
  if (!apptResolved) missing.push('apptDateOrNotBookedReason');

  const complete = missing.length === 0;

  run(
    `UPDATE ad_leads SET
       qual_units_count = ?, qual_building_type = ?, qual_sealant_color = ?, qual_sealant_color_other = ?,
       qual_language = ?, qual_reasons = ?, qual_reasons_other = ?, qual_timeline = ?,
       qual_other_renovations = ?, qual_other_renovations_which = ?, qual_renovation_priority = ?,
       qual_decision_maker_involved = ?, qual_appt_not_booked_reason = ?,
       qualification_completed_at = CASE WHEN ? THEN datetime('now') ELSE qualification_completed_at END,
       updated_at = datetime('now')
     WHERE id = ?`,
    [
      unitsCount || null, buildingType || null, sealantColor || null, sealantColorOther || null,
      language || null, reasons.length ? reasons.join(', ') : null, reasonsOther || null, timeline || null,
      otherRenovations || null, otherRenovationsWhich || null, renovationPriority || null,
      decisionMakerInvolved || null, apptNotBookedReason || null,
      complete ? 1 : 0,
      id,
    ]
  );

  return res.json({ message: complete ? 'Qualification complétée.' : 'Qualification enregistrée (incomplète).', complete, missing });
});

// POST /leads-crm/leads/:id/book — owner uniquement (voir requireQueueOwner) : booke le RDV
// d'un lead marketing dans le VRAI horaire d'un closer ou team_leader_vente porte-a-porte (le
// meme calendrier que le CRM D2D et Référencement), au lieu du simple champ appt_date/appt_hour
// autonome utilise jusqu'ici sur ad_leads. Modele directement sur
// POST /referencement/leads/:id/book : cree une vraie ligne leads + appointments (meme check de
// blackout via isSlotBlocked), puis relie le ad_lead a ce RDV (ad_leads.lead_id/appointment_id,
// meme convention que referral_leads.lead_id/appointment_id) pour que PATCH /appointments/:id
// puisse resynchroniser automatiquement le statut du lead marketing quand le closer ferme le
// rendez-vous (Closed Won/Closed Lost — voir plus bas).
router.post('/leads-crm/leads/:id/book', requireAuth, requireQueueOwner, (req, res) => {
  const { id } = req.params;
  const lead = get('SELECT * FROM ad_leads WHERE id = ?', [id]);
  if (!lead) return res.status(404).json({ error: 'Lead not found.' });

  const { closerId, apptDate, apptHour, address, city, postal } = req.body;
  if (!closerId) return res.status(400).json({ error: 'closerId requis.' });
  const closer = get(
    `SELECT u.id, u.first_name, u.last_name FROM users u
     JOIN roles r ON u.role_id = r.id
     WHERE u.id = ? AND r.name IN ('closer', 'team_leader_vente') AND u.status = 'active'`,
    [closerId]
  );
  if (!closer) return res.status(400).json({ error: 'closerId invalide (doit être un closer ou team leader vente actif).' });
  if (!apptDate) return res.status(400).json({ error: 'apptDate requis.' });
  const finalCity = city || lead.city;
  if (!finalCity) return res.status(400).json({ error: 'city requis.' });
  const hour = parseFloat(apptHour);
  const finalHour = isNaN(hour) ? 14 : hour;

  if (isSlotBlocked(closerId, apptDate, finalHour)) {
    return res.status(409).json({ error: 'Ce closer a bloqué ce créneau — RDV impossible à cette date/heure.' });
  }

  const leadName = `${lead.first_name || ''} ${lead.last_name || ''}`.trim() || 'Client';
  const leadId = uuid();
  run(
    `INSERT INTO leads (id, first_name, last_name, phone, email, address, city, postal, notes, setter_id, closer_id, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Scheduled')`,
    [leadId, lead.first_name || '', lead.last_name || '', lead.phone, lead.email, address || null, finalCity, postal || null,
     `${LABEL_LEADS} ${lead.notes || ''}`.trim(), null, closerId]
  );
  const apptId = uuid();
  run(
    `INSERT INTO appointments (id, lead_id, setter_id, closer_id, appt_date, appt_hour, status, notes)
     VALUES (?, ?, ?, ?, ?, ?, 'Scheduled', ?)`,
    [apptId, leadId, null, closerId, apptDate, finalHour, `${LABEL_LEADS} suivi lead marketing`]
  );
  // Meme progression automatique que le PATCH classique (voir plus haut) : booker un RDV fait
  // toujours avancer le lead vers "Appointment Set", sauf s'il est deja dans un etat final.
  const TERMINAL_STATUSES_BOOK = ['Closed Won', 'Closed Lost', 'No Show', 'Not Qualified'];
  const nextStatus = TERMINAL_STATUSES_BOOK.includes(lead.status) ? lead.status : 'Appointment Set';
  run(
    `UPDATE ad_leads SET
       status = ?, closer_id = ?, appt_date = ?, appt_hour = ?, lead_id = ?, appointment_id = ?,
       contacted_at = COALESCE(contacted_at, ?), updated_at = datetime('now')
     WHERE id = ?`,
    [nextStatus, closerId, apptDate, finalHour, leadId, apptId, new Date().toISOString(), id]
  );

  const closerName = `${closer.first_name} ${closer.last_name}`;
  notifyUser(closerId, `📅 ${LABEL_LEADS} Nouveau RDV: ${leadName} le ${apptDate}`,
    { title: `📅 Nouveau RDV ${LABEL_LEADS}`, body: `${leadName} — ${apptDate}`, url: '/' });
  notifyRole('owner', `📅 ${LABEL_LEADS} RDV booké pour ${closerName}: ${leadName} le ${apptDate}`,
    { title: `📅 RDV booké ${LABEL_LEADS}`, body: `${leadName} — ${apptDate}`, url: '/' });
  if (lead.ghl_contact_id) moveOpportunityToConfirmation(lead.ghl_contact_id);

  return res.status(201).json({ message: 'Rendez-vous booké.', leadId, appointmentId: apptId });
});

// ── Notes horodatees (Leads CRM) — historique append-only distinct du champ ad_leads.notes
// (texte libre, ecrase a chaque PATCH ci-dessus). Une entree n'est jamais modifiee ni supprimee
// une fois creee : c'est un journal de suivi (avant/apres RDV, a n'importe quelle etape).
router.get('/leads-crm/leads/:id/notes', requireAuth, requireLeadsCrmAccess, (req, res) => {
  const { id } = req.params;
  const lead = get('SELECT id FROM ad_leads WHERE id = ?', [id]);
  if (!lead) return res.status(404).json({ error: 'Lead not found.' });
  // Tri par created_at DESC puis rowid DESC : created_at n'a qu'une resolution a la seconde
  // (datetime('now') SQLite), donc deux notes ajoutees dans la meme seconde departagent sur
  // l'ordre d'insertion (rowid croissant) pour garantir que la plus recente reste toujours en
  // premier, sans jamais perdre ou reordonner une note existante.
  const rows = query(
    `SELECT n.*, u.first_name || ' ' || u.last_name AS author_name
     FROM ad_lead_notes n
     LEFT JOIN users u ON n.author_id = u.id
     WHERE n.ad_lead_id = ?
     ORDER BY n.created_at DESC, n.rowid DESC`,
    [id]
  );
  return res.json(rows);
});

router.post('/leads-crm/leads/:id/notes', requireAuth, requireLeadsCrmAccess, (req, res) => {
  const { id } = req.params;
  const { body } = req.body || {};
  if (!body || !String(body).trim()) return res.status(400).json({ error: 'body required.' });
  const lead = get('SELECT id FROM ad_leads WHERE id = ?', [id]);
  if (!lead) return res.status(404).json({ error: 'Lead not found.' });
  const noteId = uuid();
  run(
    `INSERT INTO ad_lead_notes (id, ad_lead_id, author_id, body) VALUES (?, ?, ?, ?)`,
    [noteId, id, req.user.id, String(body).trim()]
  );
  return res.status(201).json({ message: 'Note added.', id: noteId });
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
  // L'owner renseigne le prix (voir PATCH .../cost-requests/:id/cost, requireOwner) et n'etait
  // jusqu'ici jamais notifie qu'une demande venait d'arriver — voir demande utilisateur "admins
  // doivent avoir toutes les notifications de tout les leads cost demandes".
  notifyRole('owner', `📋 ${LABEL_LEADS} Nouvelle demande de prix — ${clientName}`,
    { title: '📋 Demande de prix', body: clientName, url: '/' }, req.user.id);
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
// Construit la liste unifiee de "rows" (porte-a-porte + marketing + deals orphelins) partagee par
// GET /database (owner, vue complete) et GET /leads-crm/database (marketing, vue filtree). Extrait
// en fonction a part pour eviter de dupliquer ~200 lignes de logique entre les deux routes.
function buildDatabaseRows() {
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
      // Specificites du job — saisies par le closer au deal (voir openDealSheet), dupliquees sur
      // le ticket d'installation ensuite : on prend le deal en priorite (source la plus tot
      // disponible), le ticket en repli si jamais le deal a ete purge mais pas le ticket.
      apptNotes: appt ? (appt.notes || '') : '',
      paymentMethod: (deal && deal.payment_method) || '',
      footageTotal: (deal && deal.footage_total != null) ? deal.footage_total : ((ticket && ticket.footage_total != null) ? ticket.footage_total : null),
      footageWhite: (deal && deal.footage_white) || (ticket && ticket.footage_white) || null,
      footageBlack: (deal && deal.footage_black) || (ticket && ticket.footage_black) || null,
      footageWheat: (deal && deal.footage_wheat) || (ticket && ticket.footage_wheat) || null,
      footageOther: (deal && deal.footage_other) || (ticket && ticket.footage_other) || '',
      ladderHeight: (deal && deal.ladder_height) || (ticket && ticket.ladder_height) || '',
      workFront: (deal && deal.work_front) || (ticket && ticket.work_front) || '',
      workRight: (deal && deal.work_right) || (ticket && ticket.work_right) || '',
      workLeft: (deal && deal.work_left) || (ticket && ticket.work_left) || '',
      workRear: (deal && deal.work_rear) || (ticket && ticket.work_rear) || '',
      obstaclesToRemove: (deal && deal.obstacles_to_remove) || (ticket && ticket.obstacles_to_remove) || '',
      toolsNeeded: (deal && deal.tools_needed) || (ticket && ticket.tools_needed) || '',
      toolsNotes: (deal && deal.tools_notes) || (ticket && ticket.tools_notes) || '',
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
      // Ville vient du formulaire de qualification GHL (ad_leads.city) des l'ingestion ; le code
      // postal, lui, n'est collecte qu'une fois le deal ferme (formulaire du closer), donc vide
      // tant qu'aucun deal n'existe.
      city: al.city || (deal && deal.city) || '', postal: (deal && deal.postal) || '',
      notes: al.notes || '',
      buildingType: al.building_type || '',
      calfeutrageCondition: al.calfeutrage_condition || '',
      zonesToSeal: al.zones_to_seal || '',
      projectDetails: al.project_details || '',
      formSource: al.form_source || '',
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
      apptNotes: al.notes || '',
      paymentMethod: (deal && deal.payment_method) || '',
      footageTotal: (deal && deal.footage_total != null) ? deal.footage_total : ((ticket && ticket.footage_total != null) ? ticket.footage_total : null),
      footageWhite: (deal && deal.footage_white) || (ticket && ticket.footage_white) || null,
      footageBlack: (deal && deal.footage_black) || (ticket && ticket.footage_black) || null,
      footageWheat: (deal && deal.footage_wheat) || (ticket && ticket.footage_wheat) || null,
      footageOther: (deal && deal.footage_other) || (ticket && ticket.footage_other) || '',
      ladderHeight: (deal && deal.ladder_height) || (ticket && ticket.ladder_height) || '',
      workFront: (deal && deal.work_front) || (ticket && ticket.work_front) || '',
      workRight: (deal && deal.work_right) || (ticket && ticket.work_right) || '',
      workLeft: (deal && deal.work_left) || (ticket && ticket.work_left) || '',
      workRear: (deal && deal.work_rear) || (ticket && ticket.work_rear) || '',
      obstaclesToRemove: (deal && deal.obstacles_to_remove) || (ticket && ticket.obstacles_to_remove) || '',
      toolsNeeded: (deal && deal.tools_needed) || (ticket && ticket.tools_needed) || '',
      toolsNotes: (deal && deal.tools_notes) || (ticket && ticket.tools_notes) || '',
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
      apptNotes: '',
      paymentMethod: d.payment_method || '',
      footageTotal: d.footage_total != null ? d.footage_total : ((ticket && ticket.footage_total != null) ? ticket.footage_total : null),
      footageWhite: d.footage_white || (ticket && ticket.footage_white) || null,
      footageBlack: d.footage_black || (ticket && ticket.footage_black) || null,
      footageWheat: d.footage_wheat || (ticket && ticket.footage_wheat) || null,
      footageOther: d.footage_other || (ticket && ticket.footage_other) || '',
      ladderHeight: d.ladder_height || (ticket && ticket.ladder_height) || '',
      workFront: d.work_front || (ticket && ticket.work_front) || '',
      workRight: d.work_right || (ticket && ticket.work_right) || '',
      workLeft: d.work_left || (ticket && ticket.work_left) || '',
      workRear: d.work_rear || (ticket && ticket.work_rear) || '',
      obstaclesToRemove: d.obstacles_to_remove || (ticket && ticket.obstacles_to_remove) || '',
      toolsNeeded: d.tools_needed || (ticket && ticket.tools_needed) || '',
      toolsNotes: d.tools_notes || (ticket && ticket.tools_notes) || '',
    });
  });

  rows.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  return rows;
}

router.get('/database', requireAuth, requireOwner, (req, res) => {
  return res.json(buildDatabaseRows());
});

// GET /database/d2d — meme format, mais scope au porte-a-porte uniquement (exclut crmType ===
// 'marketing') : c'est la Base que l'owner voit quand il est dans le CRM Porte-a-Porte ("admin
// CRM"), pour que les deux CRM restent des vues completement separees, symetriques avec
// /leads-crm/database ci-dessous.
router.get('/database/d2d', requireAuth, requireOwner, (req, res) => {
  const rows = buildDatabaseRows().filter(r => r.crmType !== 'marketing');
  return res.json(rows);
});

// GET /leads-crm/database — meme format que /database (voir buildDatabaseRows), mais filtre pour
// ne renvoyer QUE les leads marketing (crmType === 'marketing') : le porte-a-porte n'y apparait
// jamais. Ouvert a owner/lead_marketing/lead_closer (voir requireLeadsCrmAccess) — utilise par le
// role marketing ET par l'owner quand il est dans le CRM Leads.
router.get('/leads-crm/database', requireAuth, requireLeadsCrmAccess, (req, res) => {
  const rows = buildDatabaseRows().filter(r => r.crmType === 'marketing');
  return res.json(rows);
});

// DELETE /database/:id — supprime definitivement un client/lead/deal et TOUT ce qui lui est
// rattache (rendez-vous, deal, ticket d'installation, demandes de prix liees). Reserve a l'owner
// (voir requireOwner) — utile pour purger des donnees de test ou corriger une erreur de saisie.
// :id est l'id compose retourne par GET /database ("lead:<id>" / "adlead:<id>" / "deal:<id>").
router.delete('/database/:id', requireAuth, requireOwner, (req, res) => {
  const raw = req.params.id || '';
  const sep = raw.indexOf(':');
  if (sep < 0) return res.status(400).json({ error: 'Invalid id.' });
  const kind = raw.slice(0, sep);
  const realId = raw.slice(sep + 1);
  if (!realId) return res.status(400).json({ error: 'Invalid id.' });

  function deleteDealChain(dealId) {
    if (!dealId) return;
    run('DELETE FROM installation_tickets WHERE deal_id = ?', [dealId]);
    run('DELETE FROM deals WHERE id = ?', [dealId]);
  }

  if (kind === 'lead') {
    const lead = get('SELECT id FROM leads WHERE id = ?', [realId]);
    if (!lead) return res.status(404).json({ error: 'Lead not found.' });
    const appts = query('SELECT id FROM appointments WHERE lead_id = ?', [realId]);
    appts.forEach(a => {
      const deal = get('SELECT id FROM deals WHERE appointment_id = ?', [a.id]);
      if (deal) deleteDealChain(deal.id);
      run(`DELETE FROM chat_messages WHERE type = 'cost_request' AND appointment_id = ?`, [a.id]);
    });
    run('DELETE FROM appointments WHERE lead_id = ?', [realId]);
    run('DELETE FROM leads WHERE id = ?', [realId]);
  } else if (kind === 'adlead') {
    const adLead = get('SELECT id FROM ad_leads WHERE id = ?', [realId]);
    if (!adLead) return res.status(404).json({ error: 'Lead not found.' });
    const deal = get('SELECT id FROM deals WHERE ad_lead_id = ?', [realId]);
    if (deal) deleteDealChain(deal.id);
    run('DELETE FROM ad_lead_cost_requests WHERE ad_lead_id = ?', [realId]);
    run('DELETE FROM ad_leads WHERE id = ?', [realId]);
  } else if (kind === 'deal') {
    const deal = get('SELECT id FROM deals WHERE id = ?', [realId]);
    if (!deal) return res.status(404).json({ error: 'Deal not found.' });
    deleteDealChain(realId);
  } else {
    return res.status(400).json({ error: 'Invalid id.' });
  }

  run('INSERT INTO audit_logs (id, actor_id, action, target_id, details) VALUES (?, ?, ?, ?, ?)',
    [uuid(), req.user.id, 'delete_database_entry', realId, JSON.stringify({ kind })]);
  return res.json({ message: 'Deleted.' });
});

router.get('/poll', requireAuth, (req, res) => {
  const sinceRaw = req.query.since || new Date(Date.now() - 30000).toISOString();
  // Bug racine (touchait TOUS les polls, pas seulement le cout) : les colonnes *_at sont du TEXT
  // rempli via SQLite datetime('now') -> format "YYYY-MM-DD HH:MM:SS", alors que le frontend
  // envoie un ISO string JS -> "YYYY-MM-DDTHH:MM:SS.sssZ". En comparaison texte, le caractere
  // 'T' (0x54) est toujours superieur a l'espace (0x20) a la meme position, donc
  // `col > since` etait quasi TOUJOURS faux pour toute comparaison le meme jour, peu importe
  // l'heure reelle — aucune mise a jour (tickets, ad_leads, chat/cost) n'etait donc jamais
  // detectee par le polling. On normalise ici au meme format que SQLite avant de comparer.
  const since = sqlDateTime(new Date(sinceRaw));
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
  if (role === 'owner' || role === 'setter' || role === 'closer' || role === 'team_leader_vente') {
    // OR updated_at > ? : capte aussi les cost_request existants dont seul le prix a change
    // (setCostRequestPrice ne cree pas un nouveau message, il UPDATE l'existant) — sans ce
    // deuxieme filtre, un closer reste sur le canal Cost ne voyait jamais le prix apparaitre.
    newChatMessages = query(
      `SELECT m.*,
         u.first_name AS sender_first_name, u.last_name AS sender_last_name,
         r.name AS sender_role
       FROM chat_messages m
       LEFT JOIN users u ON m.sender_id = u.id
       LEFT JOIN roles r ON u.role_id = r.id
       WHERE m.created_at > ? OR m.updated_at > ?
       ORDER BY m.created_at ASC`,
      [since, since]
    );
    newChatMessages.forEach(m => {
      try { m.photo_urls = JSON.parse(m.photo_urls || '[]'); } catch { m.photo_urls = []; }
    });
  }
  // Leaderboard recalcule a chaque poll (toutes les 15s cote frontend) pour que le classement
  // reste toujours a jour sans action manuelle — voir computeLeaderboard() plus haut.
  let leaderboard = null;
  if (role === 'owner' || role === 'setter' || role === 'closer' || role === 'team_leader_vente') {
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


// ═══════════════════════════════════════════
// RÉFÉRENCEMENT — leads de recommandation client (calfeutrageprotek.com/referencement).
// Pipeline dédié, distinct du "Leads CRM" (ad_leads, Facebook/Instagram/Google) et du CRM
// porte-à-porte classique : accès restreint à owner, team_leader_vente et closer uniquement
// (voir demande utilisateur — section "referencement" pour admin/team lead ventes/closers). Le
// closer ne voit QUE ses propres leads assignés (filtré côté SERVEUR ci-dessous, jamais
// seulement côté UI, même erreur que l'audit 2026-09-05 sur /leads) ; owner/team_leader_vente
// voient tout et assignent un closer. Une fois assigné, le closer "booke" son RDV — voir POST
// /referencement/leads/:id/book, qui crée une vraie ligne dans leads+appointments (même
// mécanisme que POST /leads) pour que ce RDV apparaisse dans son horaire/calendrier existant
// sans dupliquer cette logique de blackouts/notifications.
const LABEL_REF = '[Référencement]';

function requireReferencementAccess(req, res, next) {
  const r = req.user.role;
  if (r !== 'owner' && r !== 'team_leader_vente' && r !== 'closer') {
    return res.status(403).json({ error: 'Accès restreint au owner, team leader vente et closers.' });
  }
  next();
}
function requireReferencementAdmin(req, res, next) {
  const r = req.user.role;
  if (r !== 'owner' && r !== 'team_leader_vente') {
    return res.status(403).json({ error: 'Owner ou team leader vente requis.' });
  }
  next();
}

function insertReferralLead({ firstName, lastName, phone, email, address, city, postal, notes, referrerName, referrerPhone, referrerEmail, repName }) {
  const id = uuid();
  run(
    `INSERT INTO referral_leads (
       id, first_name, last_name, phone, email, address, city, postal, notes,
       referrer_name, referrer_phone, referrer_email, rep_name, status
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Nouveau')`,
    [id, firstName, lastName || null, phone, email || null, address || null, city || null, postal || null, notes || null,
     referrerName || null, referrerPhone || null, referrerEmail || null, repName || null]
  );
  notifyRole(['owner', 'team_leader_vente'],
    `🆕 ${LABEL_REF} Nouveau lead: ${firstName} ${lastName || ''} — ${phone}`,
    { title: `🆕 Nouveau lead ${LABEL_REF}`, body: `${firstName} ${lastName || ''} — ${phone}`, url: '/' });
  return id;
}

// POST /webhooks/referencement — point d'entrée PUBLIC appelé par le relais serveur de
// calfeutrageprotek.com/referencement (même clé partagée que /webhooks/ad-leads et
// /webhooks/after-sales — LEADS_WEBHOOK_SECRET, déjà provisionnée sur Railway ET côté site).
// Le formulaire public poste vers le backend du site (jamais directement depuis le navigateur du
// visiteur, la clé ne doit jamais être exposée côté client), qui relaie ici. Si ce relais n'existe
// pas encore côté site, il doit poster ici avec ?key=LEADS_WEBHOOK_SECRET (ou header
// x-webhook-secret) — voir POST /webhooks/ad-leads pour un exemple déjà en place.
router.post('/webhooks/referencement', webhookLimiter, (req, res) => {
  const configuredSecret = process.env.LEADS_WEBHOOK_SECRET;
  if (!configuredSecret) {
    return res.status(503).json({ error: 'Webhook non configuré (LEADS_WEBHOOK_SECRET manquant).' });
  }
  const providedSecret = req.query.key || req.headers['x-webhook-secret'];
  if (!secretsMatch(providedSecret, configuredSecret)) {
    return res.status(401).json({ error: 'Clé webhook invalide.' });
  }

  const b = req.body || {};
  let firstName = b.firstName || b.first_name || '';
  let lastName  = b.lastName || b.last_name || '';
  if (!firstName && !lastName) {
    const full = (b.fullName || b.full_name || b.name || '').trim();
    if (full) {
      const parts = full.split(/\s+/);
      firstName = parts.shift() || '';
      lastName = parts.join(' ') || '';
    }
  }
  const phone   = b.phone || b.phone_number || b.phoneNumber || '';
  const email   = b.email || b.email_address || b.emailAddress || null;
  const address = b.address || b.adresse || null;
  const city    = b.city || b.ville || null;
  const postal  = b.postal || b.postalCode || b.codePostal || null;
  const notes   = b.notes || b.message || null;
  // Reponses distinctes du referent (la personne qui refere) — demande utilisateur 2026-09-14 :
  // affichees separement dans la fiche du lead au CRM plutot que noyees dans notes. Voir
  // ReferralPage.tsx / notify-lead cote site (repository Lovable).
  const referrerName  = b.referrerName || b.referrer_name || null;
  const referrerPhone = b.referrerPhone || b.referrer_phone || null;
  const referrerEmail = b.referrerEmail || b.referrer_email || null;
  const repName        = b.repName || b.rep_name || null;

  if (!firstName || !phone) {
    return res.status(400).json({ error: 'firstName (ou fullName) et phone requis.' });
  }

  // Anti-doublon (même fenêtre de 5 min que /webhooks/ad-leads) — une resoumission accidentelle
  // du formulaire ne crée pas deux fois le même lead.
  const normalizedPhone = phone.replace(/\D/g, '');
  if (normalizedPhone) {
    const recentDup = get(
      `SELECT id FROM referral_leads
       WHERE REPLACE(REPLACE(REPLACE(REPLACE(phone,'-',''),' ',''),'(',''),')','') = ?
         AND created_at >= datetime('now', '-5 minutes')
       ORDER BY created_at DESC LIMIT 1`,
      [normalizedPhone]
    );
    if (recentDup) {
      return res.status(200).json({ message: 'Lead déjà reçu (doublon évité).', id: recentDup.id });
    }
  }

  try {
    const id = insertReferralLead({ firstName, lastName, phone, email, address, city, postal, notes, referrerName, referrerPhone, referrerEmail, repName });
    return res.status(201).json({ message: 'Lead crcé.', id });
  } catch (e) {
    console.error('webhook referencement error', e);
    return res.status(500).json({ error: 'Insertion échouée.' });
  }
});

// GET /referencement/leads — owner/team_leader_vente voient tous les leads ; un closer ne voit
// QUE ceux qui lui sont assignés (closer_id = req.user.id). Filtrage fait ICI, côté serveur,
// jamais seulement côté UI — même règle que l'audit 2026-09-05 sur /leads et /assignments.
router.get('/referencement/leads', requireAuth, requireReferencementAccess, (req, res) => {
  const r = req.user.role;
  let rows;
  if (r === 'closer') {
    rows = query(
      `SELECT rl.*, c.first_name || ' ' || c.last_name AS closer_name
       FROM referral_leads rl
       LEFT JOIN users c ON rl.closer_id = c.id
       WHERE rl.closer_id = ?
       ORDER BY rl.created_at DESC`,
      [req.user.id]
    );
  } else {
    rows = query(
      `SELECT rl.*, c.first_name || ' ' || c.last_name AS closer_name
       FROM referral_leads rl
       LEFT JOIN users c ON rl.closer_id = c.id
       ORDER BY rl.created_at DESC`
    );
  }
  return res.json(rows);
});

// PATCH /referencement/leads/:id/assign — owner/team_leader_vente uniquement : assigne (ou
// réassigne) le lead à un closer. Notifie le closer assigné.
router.patch('/referencement/leads/:id/assign', requireAuth, requireReferencementAdmin, (req, res) => {
  const lead = get('SELECT * FROM referral_leads WHERE id = ?', [req.params.id]);
  if (!lead) return res.status(404).json({ error: 'Lead introuvable.' });
  const { closerId } = req.body;
  if (!closerId) return res.status(400).json({ error: 'closerId requis.' });
  const closer = get(`SELECT id FROM users WHERE id = ? AND role_id = (SELECT id FROM roles WHERE name = 'closer')`, [closerId]);
  if (!closer) return res.status(400).json({ error: 'closerId invalide (doit être un closer existant).' });
  run(
    `UPDATE referral_leads SET closer_id = ?, status = 'Assigné', updated_at = datetime('now') WHERE id = ?`,
    [closerId, req.params.id]
  );
  notifyUser(closerId, `🆕 ${LABEL_REF} Lead assigné: ${lead.first_name} ${lead.last_name || ''} — ${lead.phone}`,
    { title: `🆕 Nouveau lead ${LABEL_REF}`, body: `${lead.first_name} ${lead.last_name || ''} — ${lead.phone}`, url: '/' });
  return res.json({ message: 'Lead assigné.' });
});

// PATCH /referencement/leads/:id — mise à jour notes/statut de suivi (Ferme/Perdu/etc.) —
// owner/team_leader_vente, ou le closer assigné à CE lead précisément (jamais un autre closer).
router.patch('/referencement/leads/:id', requireAuth, requireReferencementAccess, (req, res) => {
  const lead = get('SELECT * FROM referral_leads WHERE id = ?', [req.params.id]);
  if (!lead) return res.status(404).json({ error: 'Lead introuvable.' });
  const r = req.user.role;
  if (r === 'closer' && lead.closer_id !== req.user.id) {
    return res.status(403).json({ error: 'Ce lead ne vous est pas assigné.' });
  }
  const { status, notes } = req.body;
  const fields = [];
  const vals = [];
  if (status !== undefined) { fields.push('status = ?'); vals.push(status); }
  if (notes !== undefined)  { fields.push('notes = ?');  vals.push(notes); }
  if (!fields.length) return res.status(400).json({ error: 'Rien à mettre à jour.' });
  fields.push(`updated_at = datetime('now')`);
  vals.push(req.params.id);
  run(`UPDATE referral_leads SET ${fields.join(', ')} WHERE id = ?`, vals);
  return res.json({ message: 'Lead mis à jour.' });
});

// POST /referencement/leads/:id/book — le closer assigné (ou owner/team_leader_vente pour lui)
// booke le RDV de suivi dans SON PROPRE horaire. Crée une vraie ligne leads + appointments (même
// mécanisme que POST /leads, y compris le check de blackout) pour que ce RDV apparaisse dans le
// calendrier existant du closer sans dupliquer cette logique — voir isSlotBlocked().
router.post('/referencement/leads/:id/book', requireAuth, requireReferencementAccess, (req, res) => {
  const lead = get('SELECT * FROM referral_leads WHERE id = ?', [req.params.id]);
  if (!lead) return res.status(404).json({ error: 'Lead introuvable.' });
  const r = req.user.role;
  if (r === 'closer' && lead.closer_id !== req.user.id) {
    return res.status(403).json({ error: 'Ce lead ne vous est pas assigné.' });
  }
  if (!lead.closer_id) return res.status(400).json({ error: 'Ce lead doit d\'abord être assigné à un closer.' });
  const { apptDate, apptHour, address, city, postal } = req.body;
  if (!apptDate) return res.status(400).json({ error: 'apptDate requis.' });
  const finalCity = city || lead.city;
  if (!finalCity) return res.status(400).json({ error: 'city requis.' });
  const hour = parseFloat(apptHour);
  const finalHour = isNaN(hour) ? 14 : hour;

  if (isSlotBlocked(lead.closer_id, apptDate, finalHour)) {
    return res.status(409).json({ error: 'Ce closer a bloqué ce créneau — RDV impossible à cette date/heure.' });
  }

  const leadId = uuid();
  run(
    `INSERT INTO leads (id, first_name, last_name, phone, email, address, city, postal, notes, setter_id, closer_id, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Scheduled')`,
    [leadId, lead.first_name, lead.last_name || '', lead.phone, lead.email, address || lead.address, finalCity, postal || lead.postal,
     `${LABEL_REF} ${lead.notes || ''}`.trim(), null, lead.closer_id]
  );
  const apptId = uuid();
  run(
    `INSERT INTO appointments (id, lead_id, setter_id, closer_id, appt_date, appt_hour, status, notes)
     VALUES (?, ?, ?, ?, ?, ?, 'Scheduled', ?)`,
    [apptId, leadId, null, lead.closer_id, apptDate, finalHour, `${LABEL_REF} suivi référencement`]
  );
  run(
    `UPDATE referral_leads SET status = 'Booké', lead_id = ?, appointment_id = ?, updated_at = datetime('now') WHERE id = ?`,
    [leadId, apptId, req.params.id]
  );
  notifyRole(['owner', 'team_leader_vente'],
    `📅 ${LABEL_REF} RDV booké: ${lead.first_name} ${lead.last_name || ''} le ${apptDate}`,
    { title: `📅 RDV booké ${LABEL_REF}`, body: `${lead.first_name} ${lead.last_name || ''} — ${apptDate}`, url: '/' });

  return res.status(201).json({ message: 'Rendez-vous booké.', leadId, appointmentId: apptId });
});

module.exports = router;
