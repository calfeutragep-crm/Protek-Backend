// Message envoye (SMS + courriel) des qu'un nouveau lead publicitaire (Facebook/Instagram/
// Google Ads) entre dans le Leads CRM — que ce soit via le webhook automatique
// (POST /webhooks/ad-leads) ou une creation manuelle (POST /leads-crm/leads), voir insertAdLead()
// dans routes/index.js. Objectif : contacter le client en quelques secondes pendant qu'il est
// encore "chaud", avant qu'un lead closer humain n'ait eu le temps de decrocher le telephone.
// Texte fourni par l'utilisateur, signe "Max" — meme convention que dealClosedMessage.js (texte
// brut, pas de markdown, puisque SMS et le "text" Resend sont du texte brut).
function buildNewLeadMessage(firstName) {
  const name = firstName || 'là';
  const body =
`Bonjour ${name} !
Ici Max de chez Groupe Protek Calfeutrage. Nous venons de recevoir votre demande concernant vos travaux de calfeutrage.
Seriez-vous disponible maintenant pour un petit appel afin que je puisse mieux comprendre vos besoins et voir avec vous pour une soumission gratuite?
À bientôt!`;
  return {
    subject: 'Nous avons reçu votre demande — Groupe Protek Calfeutrage',
    body,
  };
}

module.exports = { buildNewLeadMessage };
