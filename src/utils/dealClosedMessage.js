// Message envoye (SMS + courriel) au client des la creation d'un deal (vente fermee), pour le
// remercier et lui presenter le programme de referencement. Texte fourni par l'utilisateur —
// on retire juste le markdown (**gras**) puisque SMS et le "text" Resend sont du texte brut.
function buildClosedWonMessage(clientName) {
  const name = clientName || 'cher client';
  const body =
`Bonjour ${name} !

Merci encore de nous avoir fait confiance pour vos travaux !

Petit message pour vous dire qu'on a aussi un programme de référencement. Si vous connaissez un ami, un voisin ou un membre de votre famille qui aurait besoin de nos services, vous pouvez nous le référer ici :
https://calfeutrageprotek.com/referencement

Nous offrons des primes de référencement pouvant aller jusqu'à 250$ lorsqu'une référence devient cliente.

Ça nous fait toujours vraiment plaisir quand un client satisfait parle de nous autour de lui !

Merci encore ${name} et au plaisir !
L'équipe Protek`;
  return {
    subject: 'Merci pour votre confiance — Programme de référencement Protek',
    body,
  };
}

module.exports = { buildClosedWonMessage };
