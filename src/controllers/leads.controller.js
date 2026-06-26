const { v4: uuid } = require('uuid');
const { query, get, run } = require('../utils/database');

// GET all leads (owner sees all, closer sees assigned, setter sees their own)
function getLeads(req, res) {
  const u = req.user;
  let sql, params = [];

  if (u.role === 'owner') {
    sql = `SELECT l.*,
      s.first_name || ' ' || s.last_name as setter_name_full,
      c.first_name || ' ' || c.last_name as closer_name_full
      FROM leads l
      LEFT JOIN users s ON l.setter_id = s.id
      LEFT JOIN users c ON l.closer_id = c.id
      ORDER BY l.created_at DESC`;
  } else if (u.role === 'closer') {
    sql = `SELECT l.*,
      s.first_name || ' ' || s.last_name as setter_name_full
      FROM leads l
      LEFT JOIN users s ON l.setter_id = s.id
      WHERE l.closer_id = ?
      ORDER BY l.created_at DESC`;
    params = [u.id];
  } else if (u.role === 'setter') {
    sql = `SELECT l.*,
      c.first_name || ' ' || c.last_name as closer_name_full
      FROM leads l
      LEFT JOIN users c ON l.closer_id = c.id
      WHERE l.setter_id = ?
      ORDER BY l.created_at DESC`;
    params = [u.id];
  } else {
    sql = `SELECT * FROM leads ORDER BY created_at DESC`;
  }

  return res.json(query(sql, params));
}

// POST create lead + appointment
function createLead(req, res) {
  const u = req.user;
  const { firstName, lastName, phone, email, address, city, postal, notes, closerId, apptDate, apptHour } = req.body;
  if (!firstName || !lastName || !phone || !address) {
    return res.status(400).json({ error: 'Prenom, nom, telephone et adresse sont requis.' });
  }

  const leadId = uuid();
  run(
    `INSERT INTO leads (id, first_name, last_name, phone, email, address, city, postal, notes, setter_id, closer_id, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Scheduled')`,
    [leadId, firstName, lastName, phone, email||null, address, city||null, postal||null, notes||null, u.id, closerId||null]
  );

  let apptId = null;
  if (apptDate && apptHour !== undefined) {
    apptId = uuid();
    const setterName = u.first_name + ' ' + u.last_name;
    let closerName = '';
    if (closerId) {
      const closer = get('SELECT first_name, last_name FROM users WHERE id = ?', [closerId]);
      if (closer) closerName = closer.first_name + ' ' + closer.last_name;
    }
    run(
      `INSERT INTO appointments (id, lead_id, name, phone, address, setter_id, setter_name, closer_id, closer_name, appt_date, appt_hour, status, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Scheduled', ?)`,
      [apptId, leadId, firstName+' '+lastName, phone, address+(city?' - '+city:''), u.id, setterName, closerId||null, closerName, apptDate, parseInt(apptHour)||14, notes||null]
    );
    if (closerId) {
      run('INSERT INTO notifications (id, user_id, message) VALUES (?, ?, ?)',
        [uuid(), closerId, 'Nouveau rendez-vous: ' + firstName + ' ' + lastName + ' le ' + apptDate]);
    }
  }

  return res.status(201).json({ leadId, apptId, message: 'Lead cree avec succes.' });
}

// PATCH update lead status
function updateLead(req, res) {
  const { id } = req.params;
  const { status } = req.body;
  run(`UPDATE leads SET status = ?, updated_at = datetime('now') WHERE id = ?`, [status, id]);
  return res.json({ message: 'Lead mis a jour.' });
}

// GET all appointments
function getAppointments(req, res) {
  const u = req.user;
  let sql, params = [];

  if (u.role === 'owner') {
    sql = `SELECT * FROM appointments ORDER BY appt_date ASC, appt_hour ASC`;
  } else if (u.role === 'closer') {
    sql = `SELECT * FROM appointments WHERE closer_id = ? ORDER BY appt_date ASC, appt_hour ASC`;
    params = [u.id];
  } else if (u.role === 'setter') {
    sql = `SELECT * FROM appointments WHERE setter_id = ? ORDER BY appt_date ASC, appt_hour ASC`;
    params = [u.id];
  } else {
    sql = `SELECT * FROM appointments ORDER BY appt_date ASC`;
  }

  return res.json(query(sql, params));
}

// PATCH update appointment (status + reschedule)
function updateAppointment(req, res) {
  const { id } = req.params;
  const { status, apptDate, apptHour } = req.body;
  const sets = ["updated_at = datetime('now')"];
  const params = [];
  if (status) { sets.push('status = ?'); params.push(status); }
  if (apptDate) { sets.push('appt_date = ?'); params.push(apptDate); }
  if (apptHour !== undefined) { sets.push('appt_hour = ?'); params.push(parseInt(apptHour)); }
  params.push(id);
  run('UPDATE appointments SET ' + sets.join(', ') + ' WHERE id = ?', params);
  if (status) {
    const appt = get('SELECT lead_id FROM appointments WHERE id = ?', [id]);
    if (appt && appt.lead_id) {
      run(`UPDATE leads SET status = ?, updated_at = datetime('now') WHERE id = ?`, [status, appt.lead_id]);
    }
  }
  return res.json({ message: 'Rendez-vous mis a jour.' });
}

// GET assignments map { setterId: closerId }
function getAssignments(req, res) {
  const rows = query(
    `SELECT sa.setter_id, sa.closer_id
     FROM setter_assignments sa`
  );
  const map = {};
  rows.forEach(function(r) { map[r.setter_id] = r.closer_id; });
  return res.json(map);
}

// PUT save assignment (owner only)
function setAssignment(req, res) {
  const { setterId, closerId } = req.body;
  if (!setterId || !closerId) return res.status(400).json({ error: 'setterId and closerId required' });
  run(
    `INSERT INTO setter_assignments (setter_id, closer_id) VALUES (?, ?)
     ON CONFLICT(setter_id) DO UPDATE SET closer_id = excluded.closer_id, assigned_at = datetime('now')`,
    [setterId, closerId]
  );
  return res.json({ message: 'Assignment saved.' });
}

module.exports = { getLeads, createLead, updateLead, getAppointments, updateAppointment, getAssignments, setAssignment };
