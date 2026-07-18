const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { startup } = require('./utils/initDb');
const routes = require('./routes');

const app = express();
// Railway (comme tout PaaS derriere un proxy inverse) ajoute un en-tete X-Forwarded-For.
// Sans 'trust proxy', express-rate-limit rejette ces requetes (ERR_ERL_UNEXPECTED_X_FORWARDED_FOR)
// vu dans les logs de prod sur POST /webhooks/ad-leads — plus utilise via Zapier, l'ingestion se
// fait desormais directement depuis calfeutrageprotek.com (edge function Supabase) et le workflow
// GHL. 1 = fait confiance au premier hop du proxy uniquement (l'IP Railway), suffisant et plus sur
// qu'un 'true' illimite.
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3001;

const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:3000,http://localhost:5173').split(',').map(s => s.trim());

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: function(origin, cb) {
    if (!origin || allowedOrigins.some(o => o === '*' || o === origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/api', routes);
app.get('/health', (req, res) => res.json({ status: 'ok', app: 'PROTEK CRM' }));
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error.' });
});

startup().then(() => {
  app.listen(PORT, () => console.log(`🚀 PROTEK CRM API — port ${PORT}`));
}).catch(e => { console.error('Startup failed:', e); process.exit(1); });
