const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { startup } = require('./utils/initDb');
const routes = require('./routes');

const app = express();
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
