const { v4: uuid } = require('uuid');
const { query, get, run } = require('../utils/database');

// POST — closer submits a deal
function createDeal(req, res) {
  const u = req.user;
  const {
    appointmentId, clientName, address, phone, email,
    price, paymentMethod,
    footageTotal, footageWhite, footageBlack, footageWheat, footageOther,
    ladderHeight, installDate, notes,
    workFront, workRight, workLeft, workRear,
    colorWhite, colorBlack, colorWheat, colorOther,
    photos
  } = req.body;

  if (!clientName) return res.status(400).json({ error: 'Client name is required.' });

  const id = uuid();
  run(
    `INSERT INTO deals (
      id, appointment_id, closer_id, client_name, address, phone, email,
      price, payment_method,
      footage_total, footage_white, footage_black, footage_wheat, footage_other,
      ladder_height, install_date, notes,
      work_front, work_right, work_left, work_rear,
      color_white, color_black, color_wheat, color_other,
      photos, status
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      id, appointmentId||null, u.id, clientName, address||null, phone||null, email||null,
      price||null, paymentMethod||null,
      footageTotal||null, footageWhite||0, footageBlack||0, footageWheat||0, footageOther||null,
      ladderHeight||null, installDate||null, notes||null,
      workFront||null, workRight||null, workLeft||null, workRear||null,
      colorWhite||null, colorBlack||null, colorWheat||null, colorOther||null,
      photos ? JSON.stringify(photos) : null,
      'Pending Installation'
    ]
  );

  if (appointmentId) {
    run(`UPDATE appointments SET status = 'Closed Won', updated_at = datetime('now') WHERE id = ?`, [appointmentId]);
    const appt = get('SELECT lead_id FROM appointments WHERE id = ?', [appointmentId]);
    if (appt && appt.lead_id) {
      run(`UPDATE leads SET status = 'Closed Won', updated_at = datetime('now') WHERE id = ?`, [appt.lead_id]);
    }
  }

  const managers = query(`SELECT u.id FROM users u JOIN roles r ON u.role_id = r.id WHERE r.name = 'manager' AND u.status = 'active'`);
  managers.forEach(function(m) {
    run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)',
      [uuid(), m.id, 'Nouveau deal a installer: ' + clientName + (installDate ? ' le ' + installDate : '')]);
  });

  return res.status(201).json({ id, message: 'Deal cree avec succes.' });
}

// GET deals
function getDeals(req, res) {
  const u = req.user;
  let sql, params = [];

  if (u.role === 'owner') {
    sql = `SELECT d.*, c.first_name || ' ' || c.last_name as closer_name
           FROM deals d LEFT JOIN users c ON d.closer_id = c.id
           ORDER BY d.created_at DESC`;
  } else if (u.role === 'closer') {
    sql = `SELECT * FROM deals WHERE closer_id = ? ORDER BY created_at DESC`;
    params = [u.id];
  } else if (u.role === 'manager' || u.role === 'tech') {
    sql = `SELECT d.*, c.first_name || ' ' || c.last_name as closer_name
           FROM deals d LEFT JOIN users c ON d.closer_id = c.id
           ORDER BY d.created_at DESC`;
  } else {
    sql = `SELECT * FROM deals ORDER BY created_at DESC`;
  }

  return res.json(query(sql, params));
}

// PATCH update deal
function updateDeal(req, res) {
  const { id } = req.params;
  const { status, techId, installDate } = req.body;
  const sets = ["updated_at = datetime('now')"];
  const params = [];
  if (status) { sets.push('status = ?'); params.push(status); }
  if (techId !== undefined) { sets.push('tech_id = ?'); params.push(techId); }
  if (installDate) { sets.push('install_date = ?'); params.push(installDate); }
  params.push(id);
  run('UPDATE deals SET ' + sets.join(', ') + ' WHERE id = ?', params);

  if (techId) {
    const deal = get('SELECT client_name, install_date FROM deals WHERE id = ?', [id]);
    if (deal) {
      run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)',
        [uuid(), techId, 'Nouveau job assigne: ' + deal.client_name + (deal.install_date ? ' le ' + deal.install_date : '')]);
    }
  }

  return res.json({ message: 'Deal mis a jour.' });
}

module.exports = { createDeal, getDeals, updateDeal };
