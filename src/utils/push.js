// Notifications push web (protocole Web Push standard — aucun compte tiers requis, contrairement
// a Firebase/OneSignal). Fonctionne sur Android (Chrome) des l'app est ouverte une fois, et sur iOS
// (Safari 16.4+) UNIQUEMENT si le PWA a ete "ajoute a l'ecran d'accueil" au prealable — limite
// d'Apple, pas de ce code. C'est le remplacement de l'email pour notifier les lead closers et le
// role marketing des qu'un nouveau lead publicitaire arrive : voir insertAdLead() dans
// src/routes/index.js.
const webpush = require('web-push');
const { query, run } = require('./database');
const { v4: uuid } = require('uuid');

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:calfeutragep@gmail.com';

let configured = false;
if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
  configured = true;
} else {
  console.warn('[push] VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY not set — push notifications disabled.');
}

// Envoie une notification push a TOUS les appareils abonnes d'un utilisateur (un utilisateur peut
// avoir plusieurs abonnements : telephone + ordinateur, par exemple). Best-effort : un abonnement
// expire/invalide (410/404 de Google/Apple) est supprime silencieusement de la base plutot que de
// faire echouer l'appelant.
async function sendPushToUser(userId, payload) {
  if (!configured) return;
  const subs = query('SELECT id, endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = ?', [userId]);
  const body = JSON.stringify(payload);
  await Promise.all(subs.map(async (s) => {
    try {
      await webpush.sendNotification(
        { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
        body
      );
    } catch (e) {
      if (e && (e.statusCode === 404 || e.statusCode === 410)) {
        run('DELETE FROM push_subscriptions WHERE id = ?', [s.id]);
      } else {
        console.error('[push] send failed:', e && e.message);
      }
    }
  }));
}

module.exports = { sendPushToUser, VAPID_PUBLIC_KEY, isConfigured: () => configured };
