const { v4: uuid } = require('uuid');
const { query, get, run } = require('../utils/database');

// GET /chat/messages — dernier 200 messages (systeme + utilisateur), tries du plus ancien au plus recent.
// Aucune donnee client (nom, prix, photos) n'est jamais stockee ici — seulement les noms de
// l'expediteur (setter/closer/owner) et le texte du message.
function getChatMessages(req, res) {
  const rows = query(
    `SELECT m.*,
       u.first_name AS sender_first_name, u.last_name AS sender_last_name,
       r.name AS sender_role
     FROM chat_messages m
     LEFT JOIN users u ON m.sender_id = u.id
     LEFT JOIN roles r ON u.role_id = r.id
     ORDER BY m.created_at ASC
     LIMIT 200`
  );
  return res.json(rows);
}

// POST /chat/messages — message libre envoye par un setter, closer ou owner.
function postChatMessage(req, res) {
  const { text } = req.body;
  if (!text || !String(text).trim()) return res.status(400).json({ error: 'text required.' });
  const id = uuid();
  run(
    `INSERT INTO chat_messages (id, sender_id, type, body) VALUES (?, ?, 'user', ?)`,
    [id, req.user.id, String(text).trim().slice(0, 1000)]
  );
  const saved = get('SELECT * FROM chat_messages WHERE id = ?', [id]);
  return res.status(201).json({ message: 'Sent.', id, chatMessage: saved });
}

// Fonction interne (pas une route) — appelee depuis les routes deals/leads pour poster
// automatiquement une notification "+1 rendez-vous" / "+1 deal" sans aucune donnee client.
function postSystemMessage(text) {
  const id = uuid();
  run(`INSERT INTO chat_messages (id, sender_id, type, body) VALUES (?, NULL, 'system', ?)`, [id, text]);
  return id;
}

module.exports = { getChatMessages, postChatMessage, postSystemMessage };
