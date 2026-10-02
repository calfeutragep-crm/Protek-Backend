// Message de presentation envoye (SMS + courriel) au client des qu'un lead du Leads CRM passe a
// "Appointment Set" (demande utilisateur 2026-10-02) : confirme le rendez-vous et presente
// l'entreprise, notre facon de travailler, la licence RBQ, le permis OPC et le site web.
// Meme philosophie que utils/dealClosedMessage.js : texte brut (SMS et champ "text" de Resend),
// aucune dependance. TOUT le texte client vit dans ce fichier — pour changer la formulation,
// c'est ici et nulle part ailleurs.
const COMPANY = {
  name: 'Groupe Protek Calfeutrage',
  legalName: 'Groupe Protek Calfeutrage Inc.',
  rbq: '5869-2401-01',
  opc: '122860',
  website: 'https://calfeutrageprotek.com',
  phone: '438-405-4195',
};

const JOURS = ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];
const MOIS = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'];

// '2026-10-09' -> 'vendredi 9 octobre'. Calcule en UTC pour ne jamais glisser d'un jour selon le
// fuseau du serveur Railway. Retourne '' si la date est absente ou dans un format inattendu (le
// message reste alors valide, simplement sans la date).
function formatDateFr(apptDate) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(apptDate || ''));
  if (!m) return '';
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  if (isNaN(d.getTime())) return '';
  const day = d.getUTCDate();
  return `${JOURS[d.getUTCDay()]} ${day === 1 ? '1er' : day} ${MOIS[d.getUTCMonth()]}`;
}

// 14 -> '14 h', 14.5 -> '14 h 30' (appt_hour est stocke en heure decimale).
function formatHourFr(apptHour) {
  const h = parseFloat(apptHour);
  if (isNaN(h) || h < 0 || h >= 24) return '';
  const hh = Math.floor(h);
  const mm = Math.round((h - hh) * 60);
  return mm ? `${hh} h ${String(mm).padStart(2, '0')}` : `${hh} h`;
}

function buildAppointmentSetMessage({ firstName, apptDate, apptHour, closerFirstName } = {}) {
  const name = (firstName || '').trim();
  const hello = name ? `Bonjour ${name},` : 'Bonjour,';
  const dateTxt = formatDateFr(apptDate);
  const hourTxt = formatHourFr(apptHour);
  let when = '';
  if (dateTxt) when = ` pour le ${dateTxt}${hourTxt ? ` à ${hourTxt}` : ''}`;
  const withWho = closerFirstName ? ` avec notre représentant ${String(closerFirstName).trim()}` : '';

  const sms =
`${hello} ici ${COMPANY.name}. Votre rendez-vous est confirmé${when}${withWho}.

Qui nous sommes : une entreprise québécoise spécialisée en calfeutrage extérieur (Montréal, Rive-Sud, Rive-Nord).

Notre façon de travailler : évaluation gratuite sur place, soumission écrite et claire, travaux réalisés par nos techniciens avec des scellants professionnels, puis contrôle de qualité effectué avant même de récolter le paiement. Financement 0 % disponible.

Licence RBQ : ${COMPANY.rbq}
Permis OPC (commerçant itinérant) : ${COMPANY.opc}

Site web : ${COMPANY.website}
Questions ou empêchement? ${COMPANY.phone}`;

  const email =
`${hello}

Merci de votre intérêt! Votre rendez-vous avec ${COMPANY.name} est confirmé${when}${withWho}.

Avant notre visite, voici un petit mot pour vous présenter qui nous sommes et comment nous travaillons.

QUI NOUS SOMMES
${COMPANY.legalName} est une entreprise québécoise spécialisée en calfeutrage extérieur : fenêtres, portes et joints extérieurs. Nous desservons Montréal, la Rive-Sud et la Rive-Nord.

NOTRE FAÇON DE TRAVAILLER
1. Évaluation gratuite sur place — notre représentant inspecte vos joints, prend les mesures et répond à toutes vos questions, sans engagement.
2. Soumission écrite et claire — vous savez exactement ce qui sera fait et à quel prix avant de décider.
3. Travaux réalisés par nos techniciens — avec des scellants de qualité professionnelle, conçus pour notre climat.
4. Contrôle de qualité — nous vérifions les travaux avant même de récolter le paiement.
5. Financement à 0 % d'intérêt disponible.

NOS LICENCES ET PERMIS
- Licence RBQ (Régie du bâtiment du Québec) : ${COMPANY.rbq}
- Permis de commerçant itinérant de l'Office de la protection du consommateur (OPC) : ${COMPANY.opc}
Vous pouvez les vérifier en tout temps sur rbq.gouv.qc.ca et opc.gouv.qc.ca.

POUR EN SAVOIR PLUS
Site web : ${COMPANY.website}
Téléphone : ${COMPANY.phone}

Un empêchement ou une question avant le rendez-vous? Appelez-nous au ${COMPANY.phone}.

Au plaisir de vous rencontrer,
L'équipe Protek`;

  return {
    subject: `Votre rendez-vous avec ${COMPANY.name} — qui nous sommes`,
    sms,
    email,
  };
}

module.exports = { buildAppointmentSetMessage, formatDateFr, formatHourFr };
