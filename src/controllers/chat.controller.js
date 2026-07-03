const { v4: uuid } = require('uuid');
const { query, get, run } = require('../utils/database');

const DEFAULT_CHANNEL_NAME = 'Team Rive-Sud';

// GET /chat/channels — liste des sous-chats (Team Rive-Sud, Cost, Liste de streets, + ceux
// ajoutes par l'owner). Visible par setter, closer, owner.
function getChatChannels(req, res) {
  const rows = query('SELECT * FROM chat_channels ORDER BY created_at ASC');
  return res.json(rows);
}

// POST /chat/channels — cree un nouveau sous-chat. Owner uniquement (voir requireOwner sur la route).
function createChatChannel(req, res) {
  const { name } = req.body;
  const trimmed = name ? String(name).trim() : '';
  if (!trimmed) return res.status(400).json({ error: 'name required.' });
  const existing = get('SELECT id FROM chat_channels WHERE name = ?', [trimmed]);
  if (existing) return res.status(409).json({ error: 'Un canal avec ce nom existe deja.' });
  const id = uuid();
  run('INSERT INTO chat_channels (id, name) VALUES (?, ?)', [id, trimmed.slice(0, 60)]);
  return res.status(201).json({ message: 'Channel created.', id });
}

// GET /chat/messages?channelId=... — derniers 300 messages du canal demande, du plus ancien
// au plus recent. Aucune donnee client (nom, prix, photos de deal) n'y transite jamais —
// seulement les noms de l'expediteur (setter/closer/owner) et le texte/photo du message.
function getChatMessages(req, res) {
  const { channelId } = req.query;
  if (!channelId) return res.status(400).json({ error: 'channelId required.' });
  const rows = query(
    `SELECT m.*,
       u.first_name AS sender_first_name, u.last_name AS sender_last_name,
       r.name AS sender_role
     FROM chat_messages m
     LEFT JOIN users u ON m.sender_id = u.id
     LEFT JOIN roles r ON u.role_id = r.id
     WHERE m.channel_id = ?
     ORDER BY m.created_at ASC
     LIMIT 300`,
    [channelId]
  );
  return res.json(rows);
}

// POST /chat/messages — message libre (texte et/ou photo) envoye par un setter, closer ou owner,
// dans un canal precis. La photo est deja hebergee sur Cloudinary a ce stade (uploadee via
// POST /upload) ; on ne stocke ici que son URL, jamais de donnee client.
function postChatMessage(req, res) {
  const { text, imageUrl, channelId } = req.body;
  if (!channelId) return res.status(400).json({ error: 'channelId required.' });
  const trimmed = text ? String(text).trim() : '';
  if (!trimmed && !imageUrl) return res.status(400).json({ error: 'text or imageUrl required.' });
  const id = uuid();
  run(
    `INSERT INTO chat_messages (id, sender_id, channel_id, type, body, image_url) VALUES (?, ?, ?, 'user', ?, ?)`,
    [id, req.user.id, channelId, trimmed.slice(0, 1000), imageUrl || null]
  );
  const saved = get('SELECT * FROM chat_messages WHERE id = ?', [id]);
  return res.status(201).json({ message: 'Sent.', id, chatMessage: saved });
}

// Fonction interne (pas une route) — appelee depuis les routes deals/leads pour poster
// automatiquement une notification "+1 rendez-vous" / "+1 deal" sans aucune donnee client.
// Poste par defaut dans le canal "Team Rive-Sud".
function postSystemMessage(text, channelName) {
  const channel = get('SELECT id FROM chat_channels WHERE name = ?', [channelName || DEFAULT_CHANNEL_NAME]);
  if (!channel) return null;
  const id = uuid();
  run(
    `INSERT INTO chat_messages (id, sender_id, channel_id, type, body) VALUES (?, NULL, ?, 'system', ?)`,
    [id, channel.id, text]
  );
  return id;
}

module.exports = {
  getChatChannels, createChatChannel,
  getChatMessages, postChatMessage, postSystemMessage,
};
