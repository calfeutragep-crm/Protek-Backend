// Envoi de SMS via l'API Twilio (https://www.twilio.com). Aucune dependance npm requise — simple
// appel fetch() avec Basic Auth, meme philosophie que utils/email.js (Resend) : si les variables
// d'environnement ne sont pas configurees, on log un avertissement et on ne fait rien (best
// effort, jamais bloquant pour le reste de l'app — un souci Twilio ne doit jamais faire echouer
// la creation d'un deal).
//
// Deux numeros expediteurs distincts (demande utilisateur 2026-09-14) : le message de
// referencement (deal closed won) doit rester sur TWILIO_FROM_NUMBER (le numero Twilio existant,
// +1 450-390-8294) tandis que le message "nouveau lead" doit partir du numero d'affaires du
// closer une fois son Hosted SMS approuve par Twilio (TWILIO_LEADS_FROM_NUMBER). sendSms() accepte
// donc un `from` optionnel qui, s'il est fourni, prend le pas sur TWILIO_FROM_NUMBER — sinon on
// retombe sur le comportement d'origine (un seul numero pour tout).
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_FROM_NUMBER = process.env.TWILIO_FROM_NUMBER;

async function sendSms({ to, body, from }) {
  if (!to) return { skipped: true, reason: 'no recipient' };
  const fromNumber = from || TWILIO_FROM_NUMBER;
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !fromNumber) {
    console.warn(`[sms] TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN/from number not set — skipping SMS to ${to}`);
    return { skipped: true, reason: 'not configured' };
  }
  try {
    const auth = Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString('base64');
    const params = new URLSearchParams({ To: to, From: fromNumber, Body: body });
    const res = await fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`,
      {
        method: 'POST',
        headers: {
          Authorization: `Basic ${auth}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString(),
      }
    );
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      console.error(`[sms] Twilio error ${res.status} sending to ${to}:`, errBody);
      return { skipped: false, ok: false };
    }
    return { skipped: false, ok: true };
  } catch (e) {
    console.error('[sms] send failed:', e.message);
    return { skipped: false, ok: false, error: e.message };
  }
}

module.exports = { sendSms };
