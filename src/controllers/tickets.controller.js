const { v4: uuid } = require('uuid');
const { query, get, run } = require('../utils/database');

function createTicketFromDeal(deal) {
  const existing = get('SELECT id FROM installation_tickets WHERE deal_id = ?', [deal.id]);
  if (existing) return existing;
  const ticketId = uuid();
  run(
    `INSERT INTO installation_tickets (
      id, deal_id, appointment_id, closer_id, setter_id,
      client_name, address, phone, email,
      footage_total, footage_white, footage_black, footage_wheat, footage_other,
      ladder_height,
      work_front, work_right, work_left, work_rear,
      color_white, color_black, color_wheat, color_other,
      notes, photo_urls, preferred_install_date, status
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      ticketId, deal.id, deal.appointment_id || null,
      deal.closer_id || null, deal.setter_id || null,
      deal.client_name, deal.address || null,
      deal.phone || null, deal.email || null,
      deal.footage_total || null, deal.footage_white || null,
      deal.footage_black || null, deal.footage_wheat || null,
      deal.footage_other || null, deal.ladder_height || null,
      deal.work_front || null, deal.work_right || null,
      deal.work_left || null, deal.work_rear || null,
      deal.color_white || null, deal.color_black || null,
      deal.color_wheat || null, deal.color_other || null,
      deal.notes || null,
      deal.photo_urls || '[]',
      deal.install_date || null,
      'New',
    ]
  );
  const managers = query(
    `SELECT u.id FROM users u JOIN roles r ON u.role_id = r.id
     WHERE r.name = 'manager' AND u.status = 'active'`
  );
  managers.forEach(m => {
    run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)', [
      uuid(), m.id,
      `Nouveau ticket d'installation: ${deal.client_name} — ${deal.address || 'adresse non fournie'}`,
    ]);
  });
  return { id: ticketId };
}

function syncTicketFromDeal(deal) {
  const ticket = get('SELECT id FROM installation_tickets WHERE deal_id = ?', [deal.id]);
  if (!ticket) return;
  run(
    `UPDATE installation_tickets SET
      client_name = ?, address = ?, phone = ?, email = ?,
      footage_total = ?, footage_white = ?, footage_black = ?,
      footage_wheat = ?, footage_other = ?, ladder_height = ?,
      work_front = ?, work_right = ?, work_left = ?, work_rear = ?,
      color_white = ?, color_black = ?, color_wheat = ?, color_other = ?,
      notes = ?, photo_urls = ?, preferred_install_date = ?,
      updated_at = datetime('now')
    WHERE deal_id = ?`,
    [
      deal.client_name, deal.address || null,
      deal.phone || null, deal.email || null,
      deal.footage_total || null, deal.footage_white || null,
      deal.footage_black || null, deal.footage_wheat || null,
      deal.footage_other || null, deal.ladder_height || null,
      deal.work_front || null, deal.work_right || null,
      deal.work_left || null, deal.work_rear || null,
      deal.color_white || null, deal.color_black || null,
      deal.color_wheat || null, deal.color_other || null,
      deal.notes || null,
      deal.photo_urls || '[]',
      deal.install_date || null,
      deal.id,
    ]
  );
  const updatedTicket = get('SELECT tech_id, client_name FROM installation_tickets WHERE deal_id = ?', [deal.id]);
  if (updatedTicket && updatedTicket.tech_id) {
    run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)', [
      uuid(), updatedTicket.tech_id,
      `Fiche mise à jour: ${deal.client_name} — nouvelles informations disponibles`,
    ]);
  }
}

function getTickets(req, res) {
  const role = req.user.role;
  let sql = `
    SELECT t.*,
      tech.first_name || ' ' || tech.last_name AS tech_name,
      cl.first_name   || ' ' || cl.last_name   AS closer_name,
      st.first_name   || ' ' || st.last_name   AS setter_name
    FROM installation_tickets t
    LEFT JOIN users tech ON t.tech_id   = tech.id
    LEFT JOIN users cl   ON t.closer_id = cl.id
    LEFT JOIN users st   ON t.setter_id = st.id
  `;
  const params = [];
  if (role === 'tech') { sql += ' WHERE t.tech_id = ?'; params.push(req.user.id); }
  sql += ' ORDER BY t.created_at DESC';
  const tickets = query(sql, params);
  tickets.forEach(t => {
    try { t.photo_urls = JSON.parse(t.photo_urls || '[]'); } catch { t.photo_urls = []; }
  });
  return res.json(tickets);
}

function getTicket(req, res) {
  const t = get(
    `SELECT t.*,
       tech.first_name || ' ' || tech.last_name AS tech_name,
       cl.first_name   || ' ' || cl.last_name   AS closer_name,
       st.first_name   || ' ' || st.last_name   AS setter_name
     FROM installation_tickets t
     LEFT JOIN users tech ON t.tech_id   = tech.id
     LEFT JOIN users cl   ON t.closer_id = cl.id
     LEFT JOIN users st   ON t.setter_id = st.id
     WHERE t.id = ?`,
    [req.params.id]
  );
  if (!t) return res.status(404).json({ error: 'Ticket not found.' });
  try { t.photo_urls = JSON.parse(t.photo_urls || '[]'); } catch { t.photo_urls = []; }
  return res.json(t);
}

function updateTicket(req, res) {
  const { id } = req.params;
  const { techId, scheduledInstallDate, status, notes } = req.body;
  const ticket = get('SELECT * FROM installation_tickets WHERE id = ?', [id]);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found.' });
  const sets = [];
  const params = [];
  if (techId !== undefined)               { sets.push('tech_id = ?');                params.push(techId || null); }
  if (scheduledInstallDate !== undefined) { sets.push('scheduled_install_date = ?'); params.push(scheduledInstallDate || null); }
  if (status !== undefined)               { sets.push('status = ?');                 params.push(status); }
  if (notes !== undefined)                { sets.push('notes = ?');                  params.push(notes); }
  if (!sets.length) return res.status(400).json({ error: 'Nothing to update.' });
  sets.push("updated_at = datetime('now')");
  params.push(id);
  run(`UPDATE installation_tickets SET ${sets.join(', ')} WHERE id = ?`, params);
  const notifyTechId = techId || ticket.tech_id;
  if (notifyTechId) {
    const tech = get('SELECT first_name FROM users WHERE id = ?', [notifyTechId]);
    if (tech) {
      const dateStr = scheduledInstallDate || ticket.scheduled_install_date || '';
      const msg = techId && techId !== ticket.tech_id
        ? `Nouveau job assigné: ${ticket.client_name}${dateStr ? ' le ' + dateStr : ''} — ${ticket.address || ''}`
        : `Job mis à jour: ${ticket.client_name}${dateStr ? ' — ' + dateStr : ''}`;
      run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)', [uuid(), notifyTechId, msg]);
    }
  }
  run('INSERT INTO audit_logs (id, actor_id, action, target_id, details) VALUES (?, ?, ?, ?, ?)', [
    uuid(), req.user.id, 'update_ticket', id, JSON.stringify(req.body),
  ]);
  return res.json({ message: 'Ticket updated.' });
}

module.exports = { getTickets, getTicket, updateTicket, createTicketFromDeal, syncTicketFromDeal };
