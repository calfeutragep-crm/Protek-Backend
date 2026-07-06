// Notification centrale — un seul point d'entree pour "prevenir quelqu'un" dans tout le CRM,
// que ce soit un utilisateur precis (notifyUser) ou tout un role (notifyRole). Combine TOUJOURS
// deux canaux : la cloche in-app (table notifications, lue par GET /notifications + /poll) ET le
// push telephone (utils/push.js) — best-effort, l'un ne bloque jamais l'autre. Centraliser ici
// evite d'avoir a se souvenir des deux appels a chaque nouvel evenement (lead/RDV/deal/chat).
const { v4: uuid } = require('uuid');
const { query, run } = require('./database');
const { sendPushToUser } = require('./push');

// Utilisateurs actifs pour un ou plusieurs roles (ex: 'owner', ou ['lead_closer','lead_marketing']).
function activeUsersByRole(roleNames) {
  const names = Array.isArray(roleNames) ? roleNames : [roleNames];
  if (!names.length) return [];
  const placeholders = names.map(() => '?').join(',');
  return query(
    `SELECT u.id FROM users u JOIN roles r ON u.role_id = r.id
     WHERE r.name IN (${placeholders}) AND u.status = 'active'`,
    names
  );
}

// pushPayload optionnel : {title, body, url} — si omis, on derive un payload simple depuis message.
function notifyUser(userId, message, pushPayload) {
  if (!userId) return;
  run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)', [uuid(), userId, message]);
  sendPushToUser(userId, pushPayload || { title: 'Protek CRM', body: message, url: '/' }).catch(() => {});
}

function notifyUsers(userIds, message, pushPayload) {
  (userIds || []).forEach(id => notifyUser(id, message, pushPayload));
}

// Notifie tous les utilisateurs actifs d'un/des role(s), en excluant optionnellement l'auteur de
// l'action (ex: ne pas notifier le closer qui vient lui-meme de poster un message de chat).
function notifyRole(roleNames, message, pushPayload, excludeUserId) {
  activeUsersByRole(roleNames).forEach(u => {
    if (excludeUserId && u.id === excludeUserId) return;
    notifyUser(u.id, message, pushPayload);
  });
}

module.exports = { notifyUser, notifyUsers, notifyRole, activeUsersByRole };
