// Envoi d'email via l'API Resend (https://resend.com). Aucune dependance npm requise —
// simple appel fetch(). Si RESEND_API_KEY n'est pas configure, on log un avertissement et on
// ne fait rien (le reste de l'app continue de fonctionner normalement — SMS/email sont
// "best effort", jamais bloquants).
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const FROM_EMAIL = process.env.RESEND_FROM_EMAIL || 'Protek CRM <onboarding@resend.dev>';

async function sendEmail({ to, subject, text }) {
  if (!to) return { skipped: true, reason: 'no recipient' };
  if (!RESEND_API_KEY) {
    console.warn(`[email] RESEND_API_KEY not set — skipping email to ${to}: "${subject}"`);
    return { skipped: true, reason: 'no api key' };
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${RESEND_API_KEY}`,
      },
      body: JSON.stringify({ from: FROM_EMAIL, to: [to], subject, text }),
    });
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      console.error(`[email] Resend error ${res.status} sending to ${to}:`, errBody);
      return { skipped: false, ok: false };
    }
    return { skipped: false, ok: true };
  } catch (e) {
    console.error('[email] send failed:', e.message);
    return { skipped: false, ok: false, error: e.message };
  }
}

module.exports = { sendEmail };
