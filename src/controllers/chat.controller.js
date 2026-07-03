const { v4: uuid } = require('uuid');
const { query, get, run } = require('../utils/database');

const DEFAULT_CHANNEL_NAME = 'Team Rive-Sud';

// Le canal "Cost" contient les prix de revient des jobs — reserve au closer et a l'owner.
// Le setter garde acces a tous les autres canaux (Team Rive-Sud, Liste de streets, etc.).
function isCostChannelId(channelId) {
  const ch = get('SELECT name FROM chat_channels WHERE id = ?', [channelId]);
  return !!ch && ch.name === 'Cost';
}

// GET /chat/channels — liste des sous-chats (Team Rive-Sud, Cost, Liste de streets, + ceux
// ajoutes par l'owner). Visible par setter, closer, owner — sauf "Cost", masque au setter.
function getChatChannels(req, res) {
  let rows = query('SELECT * FROM chat_channels ORDER BY created_at ASC');
  if (req.user.role === 'setter') rows = rows.filter(c => c.name !== 'Cost');
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
  if (req.user.role === 'setter' && isCostChannelId(channelId)) {
    return res.status(403).json({ error: 'Le canal Cost est reserve au closer et a l\'owner.' });
  }
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
  rows.forEach(m => {
    try { m.photo_urls = JSON.parse(m.photo_urls || '[]'); } catch { m.photo_urls = []; }
  });
  return res.json(rows);
}

// POST /chat/messages — soit un message libre (texte et/ou photo), soit une "demande de prix"
// structuree (type: 'cost_request') envoyee par un closer depuis un rendez-vous, dans un canal
// precis. La/les photo(s) sont deja hebergees sur Cloudinary a ce stade (uploadees via
// POST /upload) ; on ne stocke ici que leurs URLs.
function postChatMessage(req, res) {
  const {
    text, imageUrl, channelId, type,
    appointmentId, clientName, footageTotal, ladderType, toolsNeeded, obstaclesToRemove, photoUrls,
  } = req.body;
  if (!channelId) return res.status(400).json({ error: 'channelId required.' });
  if (req.user.role === 'setter' && isCostChannelId(channelId)) {
    return res.status(403).json({ error: 'Le canal Cost est reserve au closer et a l\'owner.' });
  }

  if (type === 'cost_request') {
    const id = uuid();
    const urls = Array.isArray(photoUrls) ? photoUrls : [];
    const summary = `📋 Demande de prix — ${clientName || 'Client'}`;
    run(
      `INSERT INTO chat_messages (
        id, sender_id, channel_id, type, body,
        appointment_id, client_name, footage_total, ladder_type,
        tools_needed, obstacles_to_remove, photo_urls, cost_status
      ) VALUES (?, ?, ?, 'cost_request', ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
      [
        id, req.user.id, channelId, summary,
        appointmentId || null, clientName || null,
        footageTotal ? String(footageTotal) : null, ladderType || null,
        toolsNeeded || null, obstaclesToRemove || null, JSON.stringify(urls),
      ]
    );
    const saved = get('SELECT * FROM chat_messages WHERE id = ?', [id]);
    try { saved.photo_urls = JSON.parse(saved.photo_urls || '[]'); } catch { saved.photo_urls = []; }
    return res.status(201).json({ message: 'Cost request sent.', id, chatMessage: saved });
  }

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

// PATCH /chat/messages/:id/cost — l'owner renseigne le prix d'une demande de prix ("ticket cost").
// Le ticket passe alors de cost_status='pending' a 'priced' et le prix est visible dans le canal
// Cost pour tous (setter/closer/owner), utile pour la paie du closer concerne.
function setCostRequestPrice(req, res) {
  const { id } = req.params;
  const { cost } = req.body;
  const parsed = parseFloat(cost);
  if (!parsed || parsed <= 0) return res.status(400).json({ error: 'Valid cost required.' });
  const msg = get('SELECT id FROM chat_messages WHERE id = ? AND type = ?', [id, 'cost_request']);
  if (!msg) return res.status(404).json({ error: 'Cost request not found.' });
  run(`UPDATE chat_messages SET cost = ?, cost_status = 'priced' WHERE id = ?`, [parsed, id]);
  const saved = get('SELECT * FROM chat_messages WHERE id = ?', [id]);
  try { saved.photo_urls = JSON.parse(saved.photo_urls || '[]'); } catch { saved.photo_urls = []; }
  return res.json({ message: 'Cost updated.', chatMessage: saved });
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
  getChatMessages, postChatMessage, postSystemMessage, setCostRequestPrice,
};
