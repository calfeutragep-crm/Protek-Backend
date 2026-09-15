// Message SMS automatise envoye au client des qu'un nouveau lead (demande de soumission) est
// recu, toutes sources confondues (site web, Facebook, Instagram, formulaire externe). Demande
// utilisateur 2026-09-15 : reponse du client redirigee vers OWNER_CELL_NUMBER via
// /webhooks/twilio/sms-inbound (voir routes/index.js), deja en place depuis le 2026-09-14.
// Envoye depuis TWILIO_FROM_NUMBER (meme numero que le message closed-won) — voir
// TWILIO_LEADS_FROM_NUMBER dans utils/sms.js pour une version future avec le numero personnel
// du closer, une fois son Hosted SMS approuve par Twilio.
function buildNewLeadSms() {
    return "Bonjour, mon nom est Max de chez Calfeutrage Protek. Je viens de voir votre demande de soumission — avez-vous quelques instants maintenant pour discuter de votre projet, ou preferez-vous que je vous appelle un peu plus tard?";
}

module.exports = { buildNewLeadSms };
