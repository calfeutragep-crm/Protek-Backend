// ═══════════════════════════════════════════
// GHL CLIENT — pousse les mises a jour de Protek CRM VERS GoHighLevel (sens inverse du
// webhook /webhooks/ad-leads qui, lui, fait entrer les leads GHL DANS Protek).
//
// Deux evenements Protek declenchent un appel API GHL :
//   1) RDV booke sur un lead marketing (PATCH /leads-crm/leads/:id, apptDate defini)
//      -> deplace l'opportunite GHL vers l'etape CONFIRMATION du pipeline LEADS.
//   2) Deal signe sur un lead marketing (POST /deals avec adLeadId)
//      -> marque l'opportunite GHL correspondante "won".
//
// Tout est best-effort : si GHL_API_TOKEN n'est pas configure, ou si l'appel echoue (contact
// sans opportunite trouvee, token expire, etc.), on logge et on continue — un probleme cote
// GHL ne doit jamais faire echouer une action Protek (booking RDV, signature deal).
// ═══════════════════════════════════════════

const GHL_API_BASE = 'https://services.leadconnectorhq.com';
const GHL_API_VERSION = '2021-07-28';

function ghlConfigured() {
  return !!(process.env.GHL_API_TOKEN && process.env.GHL_LOCATION_ID);
}

async function ghlRequest(method, path, body) {
  const token = process.env.GHL_API_TOKEN;
  const res = await fetch(`${GHL_API_BASE}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Version: GHL_API_VERSION,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    throw new Error(`GHL API ${method} ${path} -> ${res.status}: ${typeof data === 'string' ? data : JSON.stringify(data)}`);
  }
  return data;
}

// Retrouve l'opportunite GHL rattachee a un contact, dans le pipeline LEADS — on ne stocke
// pas l'opportunityId au moment de l'ingestion (le workflow GHL cree l'opportunite dans une
// etape precedente, son id n'est pas trivial a recuperer via merge tag), donc on la retrouve
// ici a la volee via l'API de recherche officielle.
async function findOpportunityByContact(contactId) {
  const locationId = process.env.GHL_LOCATION_ID;
  const pipelineId = process.env.GHL_PIPELINE_ID;
  const params = new URLSearchParams({ location_id: locationId, contact_id: contactId });
  if (pipelineId) params.set('pipeline_id', pipelineId);
  const data = await ghlRequest('GET', `/opportunities/search?${params.toString()}`);
  const opps = (data && (data.opportunities || data.data)) || [];
  return opps[0] || null;
}

// 1) RDV booke -> deplace l'opportunite vers l'etape CONFIRMATION.
async function moveOpportunityToConfirmation(contactId) {
  if (!contactId) return;
  if (!ghlConfigured()) { console.warn('GHL non configure (GHL_API_TOKEN/GHL_LOCATION_ID) — stage move ignore.'); return; }
  const stageId = process.env.GHL_STAGE_CONFIRMATION_ID;
  if (!stageId) { console.warn('GHL_STAGE_CONFIRMATION_ID manquant — stage move ignore.'); return; }
  try {
    const opp = await findOpportunityByContact(contactId);
    if (!opp) { console.warn(`Aucune opportunite GHL trouvee pour contact ${contactId} — stage move ignore.`); return; }
    await ghlRequest('PUT', `/opportunities/${opp.id}`, { pipelineStageId: stageId });
    console.log(`✓ GHL: opportunite ${opp.id} deplacee vers CONFIRMATION.`);
  } catch (e) {
    console.error('GHL moveOpportunityToConfirmation error:', e.message);
  }
}

// 2) Deal signe -> marque l'opportunite "won".
async function markOpportunityWon(contactId) {
  if (!contactId) return;
  if (!ghlConfigured()) { console.warn('GHL non configure (GHL_API_TOKEN/GHL_LOCATION_ID) — won ignore.'); return; }
  try {
    const opp = await findOpportunityByContact(contactId);
    if (!opp) { console.warn(`Aucune opportunite GHL trouvee pour contact ${contactId} — won ignore.`); return; }
    await ghlRequest('PUT', `/opportunities/${opp.id}`, { status: 'won' });
    console.log(`✓ GHL: opportunite ${opp.id} marquee won.`);
  } catch (e) {
    console.error('GHL markOpportunityWon error:', e.message);
  }
}

module.exports = { moveOpportunityToConfirmation, markOpportunityWon };
