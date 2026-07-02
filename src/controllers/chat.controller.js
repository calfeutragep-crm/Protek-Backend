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

// POST /chat/messages — message libre (texte et/ou photo) envoye par un setter, closer ou owner.
// La photo est deja hebergee sur Cloudinary a ce stade (uploadee via POST /upload) ; on ne
// stocke ici que son URL, jamais de donnee client.
function postChatMessage(req, res) {
  const { text, imageUrl } = req.body;
  const trimmed = text ? String(text).trim() : '';
  if (!trimmed && !imageUrl) return res.status(400).json({ error: 'text or imageUrl required.' });
  const id = uuid();
  run(
    `INSERT INTO chat_messages (id, sender_id, type, body, image_url) VALUES (?, ?, 'user', ?, ?)`,
    [id, req.user.id, trimmed.slice(0, 1000), imageUrl || null]
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
