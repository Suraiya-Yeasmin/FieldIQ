import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pg from 'pg';
import nodemailer from 'nodemailer';
import bcrypt from 'bcryptjs';
import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(__dirname, '..', 'frontend');
const port = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
const origin = process.env.APP_ORIGIN || `http://localhost:${port}`;
const secret = process.env.SESSION_SECRET || '';
if (secret.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters. Set it in backend/.env.');
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required. Configure PostgreSQL in backend/.env.');
if (isProd && !origin.startsWith('https://')) throw new Error('Production APP_ORIGIN must use HTTPS.');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'require' ? { rejectUnauthorized: process.env.PGSSL_REJECT_UNAUTHORIZED !== 'false' } : undefined,
  max: Number(process.env.PGPOOL_MAX || 10),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});
pool.on('error', err => console.error('Unexpected PostgreSQL pool error:', err.message));

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  full_name VARCHAR(80) NOT NULL,
  email VARCHAR(254) NOT NULL,
  password_hash TEXT NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique ON users (LOWER(email));
CREATE TABLE IF NOT EXISTS sessions (
  token_hash CHAR(64) PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  csrf_hash CHAR(64) NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS user_data (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  data_key VARCHAR(40) NOT NULL CHECK (data_key IN ('calendarTasks','savedPrefs','farms','fields','cropRotations','irrigationSchedules','fertilizerReminders','harvestRecords','savedReports','preferences')),
  json_value JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(user_id, data_key)
);
CREATE TABLE IF NOT EXISTS action_tokens (
  token_hash CHAR(64) PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose VARCHAR(10) NOT NULL CHECK (purpose IN ('verify','reset')),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS action_tokens_user_idx ON action_tokens(user_id);
CREATE INDEX IF NOT EXISTS action_tokens_expiry_idx ON action_tokens(expires_at);
`;
await pool.query(schema);

// Keyed hashes ensure a database-only leak does not expose reusable session/action tokens.
const hash = value => createHmac('sha256', secret).update(value).digest('hex');
const token = () => randomBytes(32).toString('base64url');
const cookieName = isProd ? '__Host-fieldiq_session' : 'fieldiq_session';
const ttlHours = Math.min(72, Math.max(1, Number(process.env.SESSION_TTL_HOURS || 12)));
const cookieOpts = { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/', maxAge: ttlHours * 3_600_000 };
const mailConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS && process.env.SMTP_FROM);
const transporter = mailConfigured ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE) === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
}) : null;
const requireEmailVerification = String(process.env.REQUIRE_EMAIL_VERIFICATION || 'true') === 'true';
const authLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 8, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many attempts. Please try again later.' } });
const writeLimiter = rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many save requests. Please wait and try again.' } });
const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '1mb', strict: true }));
app.use('/api', (_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); res.setHeader('Pragma', 'no-cache'); next(); });
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const requestOrigin = req.get('origin');
    if (!requestOrigin || requestOrigin !== origin) return res.status(403).json({ error: 'Request origin rejected.' });
  }
  next();
});

app.use(async (req, res, next) => {
  try {
    const rawCookie = readCookie(req.headers.cookie, cookieName);
    req.session = null;
    if (rawCookie) {
      const result = await pool.query(
        `SELECT s.token_hash, s.csrf_hash, u.id AS user_id, u.full_name, u.email, u.email_verified
         FROM sessions s LEFT JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
        [hash(rawCookie)],
      );
      if (result.rowCount) {
        const row = result.rows[0];
        req.session = {
          tokenHash: row.token_hash,
          csrfHash: row.csrf_hash,
          user: row.user_id ? { id: row.user_id, fullName: row.full_name, email: row.email, emailVerified: row.email_verified } : null,
        };
      }
    }
    next();
  } catch (error) { next(error); }
});
function readCookie(header = '', name) {
  const part = header.split(';').map(v => v.trim()).find(v => v.startsWith(`${name}=`));
  return part ? part.slice(name.length + 1) : null;
}
async function createSession(res, userId = null) {
  const raw = token();
  const csrf = token();
  await pool.query('INSERT INTO sessions(token_hash,user_id,csrf_hash,expires_at) VALUES($1,$2,$3,NOW()+($4 * INTERVAL \'1 hour\'))', [hash(raw), userId, hash(csrf), ttlHours]);
  res.cookie(cookieName, raw, cookieOpts);
  return csrf;
}
async function destroySession(req, res) {
  if (req.session?.tokenHash) await pool.query('DELETE FROM sessions WHERE token_hash=$1', [req.session.tokenHash]);
  res.clearCookie(cookieName, { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/' });
}
function requireCsrf(req, res, next) {
  const supplied = req.get('x-csrf-token') || '';
  if (!req.session || !supplied || !timingSafeEqual(Buffer.from(hash(supplied)), Buffer.from(req.session.csrfHash))) {
    return res.status(403).json({ error: 'Security token expired. Refresh the page and try again.' });
  }
  next();
}
function requireUser(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: 'Please sign in to access this information.' });
  next();
}
function validPassword(password) {
  return password.length >= 12 && Buffer.byteLength(password, 'utf8') <= 72 && /[a-z]/.test(password) && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password);
}
const passwordHash = password => bcrypt.hash(password, 12);
const dummyPasswordHash = await passwordHash(randomBytes(32).toString('hex'));
async function verifyPassword(password, encoded) { try { return await bcrypt.compare(password, encoded); } catch { return false; } }
async function issueAction(userId, purpose) {
  const raw = token();
  await pool.query('DELETE FROM action_tokens WHERE user_id=$1 AND purpose=$2 AND used_at IS NULL', [userId, purpose]);
  await pool.query('INSERT INTO action_tokens(token_hash,user_id,purpose,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL \'30 minutes\')', [hash(raw), userId, purpose]);
  return raw;
}
async function sendActionMail(email, purpose, raw) {
  if (!transporter) throw new Error('Email delivery is not configured. Add SMTP_HOST, SMTP_USER, SMTP_PASS and SMTP_FROM to backend/.env.');
  const url = purpose === 'verify' ? `${origin}/api/auth/verify?token=${encodeURIComponent(raw)}` : `${origin}/?reset=${encodeURIComponent(raw)}`;
  await transporter.sendMail({
    from: process.env.SMTP_FROM, to: email,
    subject: purpose === 'verify' ? 'Verify your FieldIQ email' : 'Reset your FieldIQ password',
    text: `Use this one-time link within 30 minutes: ${url}\nIf you did not request this, ignore this email.`,
  });
}


// NASA POWER daily point data. Read-only proxy with input bounds and a short cache.
const nasaCache = new Map();
const nasaLimiter = rateLimit({ windowMs: 60_000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'NASA data request limit reached. Please wait a minute.' } });
app.get('/api/nasa/power', nasaLimiter, async (req, res) => {
  const lat = Number(req.query.lat), lon = Number(req.query.lon);
  if (!Number.isFinite(lat) || lat < -90 || lat > 90 || !Number.isFinite(lon) || lon < -180 || lon > 180) return res.status(400).json({ error: 'Provide valid latitude (-90 to 90) and longitude (-180 to 180).' });
  const key = `${lat.toFixed(3)},${lon.toFixed(3)}`;
  const cached = nasaCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return res.json(cached.data);
  try {
    const end = new Date(Date.now() - 3 * 86400000);
    const start = new Date(end.getTime() - 44 * 86400000);
    const ymd = d => `${d.getUTCFullYear()}${String(d.getUTCMonth()+1).padStart(2,'0')}${String(d.getUTCDate()).padStart(2,'0')}`;
    const url = new URL('https://power.larc.nasa.gov/api/temporal/daily/point');
    url.search = new URLSearchParams({ parameters: 'T2M,T2M_MAX,T2M_MIN,PRECTOTCORR,RH2M', community: 'AG', longitude: String(lon), latitude: String(lat), start: ymd(start), end: ymd(end), format: 'JSON', 'time-standard': 'UTC' }).toString();
    const response = await fetch(url, { signal: AbortSignal.timeout(20000), headers: { 'Accept': 'application/json', 'User-Agent': 'FieldIQ/1.2 (NASA POWER data client)' } });
    if (!response.ok) return res.status(502).json({ error: `NASA POWER returned HTTP ${response.status}. Try again later.` });
    const payload = await response.json();
    const params = payload?.properties?.parameter || {};
    const metadata = payload?.parameters || {};
    const summarize = (name, kind='mean') => {
      const values = Object.entries(params[name] || {}).filter(([date,value]) => /^\d{8}$/.test(date) && Number.isFinite(Number(value)) && Number(value) > -900).sort(([a],[b]) => a.localeCompare(b));
      if (!values.length) return null;
      const nums = values.map(([,v]) => Number(v));
      const latest = values[values.length-1];
      return { latestDate: latest[0], latestValue: Number(latest[1]), mean: Number((nums.reduce((a,b)=>a+b,0)/nums.length).toFixed(2)), total: kind==='sum' ? Number(nums.reduce((a,b)=>a+b,0).toFixed(2)) : undefined, unit: metadata[name]?.units || metadata[name]?.unit || '' };
    };
    const data = {
      source: 'NASA POWER Daily Point API', sourceUrl: 'https://power.larc.nasa.gov/docs/services/api/temporal/daily/',
      coordinates: { latitude: lat, longitude: lon }, requestedPeriod: { start: ymd(start), end: ymd(end), timeStandard: 'UTC' },
      parameters: { temperature: summarize('T2M'), maxTemperature: summarize('T2M_MAX'), minTemperature: summarize('T2M_MIN'), precipitation: summarize('PRECTOTCORR','sum'), relativeHumidity: summarize('RH2M') },
      note: 'NASA POWER gridded meteorological estimates; latest available date may lag. Not a local rain-gauge reading or weather forecast.'
    };
    nasaCache.set(key, { data, expiresAt: Date.now()+15*60_000 });
    res.json(data);
  } catch (error) {
    res.status(502).json({ error: 'Could not retrieve NASA POWER data right now. Check your internet connection and try again.' });
  }
});

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch { res.status(503).json({ ok: false, database: 'unavailable' }); }
});
app.get('/api/auth/csrf', async (req, res, next) => {
  try {
    if (req.session) {
      const csrf = token();
      await pool.query('UPDATE sessions SET csrf_hash=$1 WHERE token_hash=$2', [hash(csrf), req.session.tokenHash]);
      return res.json({ csrfToken: csrf });
    }
    return res.json({ csrfToken: await createSession(res) });
  } catch (e) { next(e); }
});
app.get('/api/auth/me', (req, res) => res.json({ user: req.session?.user || null }));

app.post('/api/auth/register', authLimiter, requireCsrf, async (req, res, next) => {
  try {
    const fullName = String(req.body?.fullName || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (fullName.length < 2 || fullName.length > 80 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254)
      return res.status(400).json({ error: 'Enter a valid name and email address.' });
    if (!validPassword(password)) return res.status(400).json({ error: 'Use at least 12 characters with uppercase, lowercase, a number and a symbol (maximum 72 UTF-8 bytes).' });
    if (requireEmailVerification && !mailConfigured) return res.status(503).json({ error: 'Email verification is required but SMTP is not configured. Configure SMTP before creating accounts.' });
    const id = randomBytes(16).toString('hex');
    const hashed = await passwordHash(password);
    try { await pool.query('INSERT INTO users(id,full_name,email,password_hash) VALUES($1,$2,$3,$4)', [id, fullName, email, hashed]); }
    catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'An account with this email already exists.' }); throw e; }
    if (requireEmailVerification) {
      const action = await issueAction(id, 'verify');
      try { await sendActionMail(email, 'verify', action); }
      catch (e) { return res.status(503).json({ error: 'Account created, but the verification email could not be sent. Check SMTP settings and resend.' }); }
      return res.status(201).json({ message: 'Account created. Check your email for the verification link. It expires in 30 minutes.' });
    }
    return res.status(201).json({ message: 'Account created. You can now sign in.' });
  } catch (e) { next(e); }
});

app.post('/api/auth/login', authLimiter, requireCsrf, async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const result = await pool.query('SELECT id,full_name,email,password_hash,email_verified FROM users WHERE LOWER(email)=LOWER($1)', [email]);
    const user = result.rows[0];
    // A valid random bcrypt hash reduces account-enumeration timing differences.
    const ok = await verifyPassword(password, user?.password_hash || dummyPasswordHash);
    if (!user || !ok) return res.status(401).json({ error: 'Invalid email or password.' });
    if (requireEmailVerification && !user.email_verified) return res.status(403).json({ error: 'Please verify your email before signing in.' });
    await destroySession(req, res);
    const csrfToken = await createSession(res, user.id);
    return res.json({ user: { id: user.id, fullName: user.full_name, email: user.email, emailVerified: user.email_verified }, csrfToken });
  } catch (e) { next(e); }
});
app.post('/api/auth/logout', requireCsrf, async (req, res, next) => {
  try { await destroySession(req, res); res.json({ ok: true }); } catch (e) { next(e); }
});
app.post('/api/auth/resend-verification', authLimiter, requireCsrf, async (req, res, next) => {
  try {
    if (!mailConfigured) return res.status(503).json({ error: 'Email delivery is not configured. Add SMTP settings first.' });
    const email = String(req.body?.email || '').trim().toLowerCase();
    const result = await pool.query('SELECT id,email_verified FROM users WHERE LOWER(email)=LOWER($1)', [email]);
    if (result.rowCount && !result.rows[0].email_verified) {
      const raw = await issueAction(result.rows[0].id, 'verify');
      await sendActionMail(email, 'verify', raw);
    }
    res.json({ message: 'If this account needs verification, a new email will be sent.' });
  } catch (e) { next(e); }
});
app.get('/api/auth/verify', (req, res) => {
  const raw = String(req.query.token || '');
  if (!raw || raw.length > 200) return res.status(400).send('Invalid or expired verification link.');
  // GET only displays a confirmation page. Mail scanners/prefetchers cannot consume the token.
  res.setHeader('Cache-Control', 'no-store');
  res.type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Verify FieldIQ email</title><body style="font:16px system-ui;max-width:560px;margin:12vh auto;padding:24px"><h2>Verify your FieldIQ email</h2><p>Press the button below to confirm this email address. The link expires after 30 minutes.</p><button id="verify" style="padding:12px 18px;background:#24734d;color:white;border:0;border-radius:8px">Verify email</button><p id="status" role="status"></p><script>const token=${JSON.stringify(raw)};document.getElementById('verify').onclick=async()=>{const s=document.getElementById('status');s.textContent='Verifying…';try{const c=await fetch('/api/auth/csrf',{credentials:'same-origin'}).then(r=>r.json());const r=await fetch('/api/auth/verify',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':c.csrfToken},body:JSON.stringify({token})});const d=await r.json();s.textContent=r.ok?'Email verified. You can return to FieldIQ and sign in.':(d.error||'Verification failed.')}catch(e){s.textContent='Could not verify. Please try again.'}};</script></body></html>`);
});
app.post('/api/auth/verify', authLimiter, requireCsrf, async (req, res, next) => {
  const raw = String(req.body?.token || '');
  if (!raw || raw.length > 200) return res.status(400).json({ error: 'Invalid or expired verification link.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query("SELECT user_id,token_hash FROM action_tokens WHERE token_hash=$1 AND purpose='verify' AND used_at IS NULL AND expires_at>NOW() FOR UPDATE", [hash(raw)]);
    if (!found.rowCount) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'This verification link is invalid or expired.' }); }
    await client.query('UPDATE users SET email_verified=TRUE,updated_at=NOW() WHERE id=$1', [found.rows[0].user_id]);
    await client.query("UPDATE action_tokens SET used_at=NOW() WHERE user_id=$1 AND purpose='verify' AND used_at IS NULL", [found.rows[0].user_id]);
    await client.query('COMMIT');
    res.json({ ok: true, message: 'Email verified. You can return to FieldIQ and sign in.' });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); next(e); } finally { client.release(); }
});
app.post('/api/auth/forgot-password', authLimiter, requireCsrf, async (req, res, next) => {
  try {
    if (!mailConfigured) return res.status(503).json({ error: 'Password reset email is unavailable because SMTP is not configured.' });
    const email = String(req.body?.email || '').trim().toLowerCase();
    const result = await pool.query('SELECT id FROM users WHERE LOWER(email)=LOWER($1)', [email]);
    if (result.rowCount) {
      const raw = await issueAction(result.rows[0].id, 'reset');
      await sendActionMail(email, 'reset', raw);
    }
    res.json({ message: 'If an account exists, a password-reset email will be sent.' });
  } catch (e) { next(e); }
});
app.post('/api/auth/reset-password', authLimiter, requireCsrf, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const raw = String(req.body?.token || '');
    const password = String(req.body?.password || '');
    if (!validPassword(password)) return res.status(400).json({ error: 'Use at least 12 characters with uppercase, lowercase, a number and a symbol (maximum 72 UTF-8 bytes).' });
    await client.query('BEGIN');
    const result = await client.query("SELECT token_hash,user_id FROM action_tokens WHERE token_hash=$1 AND purpose='reset' AND used_at IS NULL AND expires_at>NOW() FOR UPDATE", [hash(raw)]);
    if (!result.rowCount) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'This reset link is invalid or expired.' }); }
    const pw = await passwordHash(password);
    await client.query('UPDATE users SET password_hash=$1,updated_at=NOW() WHERE id=$2', [pw, result.rows[0].user_id]);
    await client.query('UPDATE action_tokens SET used_at=NOW() WHERE token_hash=$1', [result.rows[0].token_hash]);
    await client.query('DELETE FROM sessions WHERE user_id=$1', [result.rows[0].user_id]);
    await client.query('DELETE FROM action_tokens WHERE user_id=$1', [result.rows[0].user_id]);
    await client.query('COMMIT');
    res.json({ message: 'Password updated. Please sign in again.' });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); next(e); }
  finally { client.release(); }
});

const allowedDataKeys = new Set(['calendarTasks','savedPrefs','farms','fields','cropRotations','irrigationSchedules','fertilizerReminders','harvestRecords','savedReports','preferences']);
app.get('/api/user/data', requireUser, async (req, res, next) => {
  try {
    const result = await pool.query('SELECT data_key,json_value FROM user_data WHERE user_id=$1', [req.session.user.id]);
    const data = Object.fromEntries(result.rows.map(row => [row.data_key, row.json_value]));
    res.json({ data });
  } catch (e) { next(e); }
});
app.put('/api/user/data', writeLimiter, requireUser, requireCsrf, async (req, res, next) => {
  try {
    const entries = Object.entries(req.body || {});
    if (!entries.length || entries.length > 10 || entries.some(([key]) => !allowedDataKeys.has(key))) return res.status(400).json({ error: 'Unsupported or empty data payload.' });
    for (const [key, value] of entries) {
      if (key === 'savedPrefs') {
        if (!value || typeof value !== 'object' || Array.isArray(value)) return res.status(400).json({ error: 'Saved preferences must be an object.' });
      } else if (!Array.isArray(value) || value.length > 5000) {
        return res.status(400).json({ error: `${key} must be an array with no more than 5,000 records.` });
      }
      const encoded = JSON.stringify(value);
      if (encoded === undefined || Buffer.byteLength(encoded, 'utf8') > 500_000) return res.status(413).json({ error: 'Each saved data item must be under 500 KB.' });
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const [key, value] of entries) {
        await client.query(`INSERT INTO user_data(user_id,data_key,json_value,updated_at) VALUES($1,$2,$3::jsonb,NOW())
          ON CONFLICT(user_id,data_key) DO UPDATE SET json_value=EXCLUDED.json_value,updated_at=NOW()`, [req.session.user.id, key, JSON.stringify(value)]);
      }
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.use('/backend', (_req, res) => res.sendStatus(404));
app.use(express.static(appRoot, { index: 'FieldIQ.html', dotfiles: 'deny', setHeaders(res, file) { if (file.endsWith('.html')) res.setHeader('Cache-Control', 'no-store'); } }));
app.use((err, _req, res, _next) => {
  console.error('FieldIQ server error:', err.message);
  if (res.headersSent) return;
  res.status(500).json({ error: 'A server error occurred. Please try again.' });
});
const server = app.listen(port, () => console.log(`FieldIQ running at ${origin}`));
const cleanup = setInterval(() => {
  pool.query('DELETE FROM sessions WHERE expires_at < NOW()').catch(() => {});
  pool.query('DELETE FROM action_tokens WHERE expires_at < NOW() OR used_at IS NOT NULL').catch(() => {});
}, 60 * 60_000);
cleanup.unref();
async function shutdown() { clearInterval(cleanup); server.close(); await pool.end(); process.exit(0); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
