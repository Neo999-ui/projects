const http = require('http');
const path = require('path');
const express = require('express');
const cors = require('cors');
const { WebSocketServer, WebSocket } = require('ws');
const BruteForceDetector = require('./detector.js');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Detection Engine
const detector = new BruteForceDetector();

/**
 * Broadcast event and stats to all connected WebSocket clients
 */
function broadcast(type, payload) {
  const message = JSON.stringify({ type, payload, timestamp: Date.now() });
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// Periodically send stats update over WebSockets (every 2 seconds)
setInterval(() => {
  broadcast('STATS_UPDATE', detector.getStats());
}, 2000);

// ==================== API ROUTES ==================== //

/**
 * Login Attempt Endpoint
 */
app.post('/api/login', (req, res) => {
  const ip = req.body.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const username = req.body.username || 'unknown_user';
  const password = req.body.password || '';
  const userAgent = req.headers['user-agent'] || 'Browser';

  // Demo credential validation (admin:password123, user:secret)
  const isCorrect = (username === 'admin' && password === 'password123') ||
                    (username === 'user' && password === 'secret');

  const event = detector.processLogin({
    ip,
    username,
    success: isCorrect,
    userAgent
  });

  // Broadcast event to real-time UI
  broadcast('LOGIN_EVENT', { event, stats: detector.getStats() });

  if (event.status === 'BLOCKED') {
    return res.status(403).json({
      success: false,
      message: 'Access Denied: IP address blocked due to detected security threat.',
      event
    });
  }

  if (event.status === 'SUCCESS') {
    return res.json({
      success: true,
      message: 'Authentication successful',
      token: 'jwt_demo_token_12345',
      event
    });
  }

  return res.status(401).json({
    success: false,
    message: 'Invalid username or password',
    event
  });
});

/**
 * Get Detector Statistics & Telemetry
 */
app.get('/api/stats', (req, res) => {
  res.json(detector.getStats());
});

/**
 * Get Event Logs
 */
app.get('/api/logs', (req, res) => {
  res.json({ logs: detector.logs });
});

/**
 * IP Block / Unblock / Whitelist / Blacklist Actions
 */
app.post('/api/ip/unblock', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  const result = detector.unblockIp(ip);
  broadcast('STATS_UPDATE', detector.getStats());
  res.json({ success: true, unblocked: result, ip });
});

app.post('/api/ip/block', (req, res) => {
  const { ip, durationMs, reason } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  const blockInfo = detector.blockIp(ip, durationMs || 60000, reason || 'MANUAL_DASHBOARD_BLOCK');
  broadcast('STATS_UPDATE', detector.getStats());
  res.json({ success: true, blockInfo });
});

app.post('/api/ip/whitelist', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  detector.whitelistIp(ip);
  broadcast('STATS_UPDATE', detector.getStats());
  res.json({ success: true, whitelisted: ip });
});

app.post('/api/ip/blacklist', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  detector.blacklistIp(ip);
  broadcast('STATS_UPDATE', detector.getStats());
  res.json({ success: true, blacklisted: ip });
});

/**
 * Security Policy Config Update
 */
app.post('/api/config', (req, res) => {
  const newConfig = detector.updateConfig(req.body);
  broadcast('STATS_UPDATE', detector.getStats());
  res.json({ success: true, config: newConfig });
});

/**
 * Clear Logs
 */
app.post('/api/clear-logs', (req, res) => {
  detector.clearLogs();
  broadcast('STATS_UPDATE', detector.getStats());
  res.json({ success: true });
});

/**
 * Attack Simulator API Endpoint
 */
let isSimulating = false;

app.post('/api/simulate-attack', async (req, res) => {
  if (isSimulating) {
    return res.status(429).json({ error: 'Simulation already in progress' });
  }

  const {
    attackType = 'BRUTE_FORCE',
    count = 10,
    targetUser = 'admin',
    attackerIp = '198.51.100.42',
    delayMs = 150
  } = req.body;

  isSimulating = true;
  res.json({ success: true, message: `Started ${attackType} simulation (${count} requests)` });

  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  // Run attack sequence in background
  (async () => {
    try {
      if (attackType === 'BRUTE_FORCE') {
        // High frequency failed logins on single account from single IP
        for (let i = 0; i < count; i++) {
          const event = detector.processLogin({
            ip: attackerIp,
            username: targetUser,
            success: false,
            userAgent: 'Hydra/9.2 BruteForceEngine'
          });
          broadcast('LOGIN_EVENT', { event, stats: detector.getStats() });
          await sleep(delayMs);
        }
      } else if (attackType === 'CREDENTIAL_STUFFING') {
        // Single IP trying list of different usernames
        const sampleUsers = ['root', 'admin', 'supervisor', 'dev', 'test', 'oracle', 'postgres', 'service_acc', 'guest'];
        for (let i = 0; i < count; i++) {
          const user = sampleUsers[i % sampleUsers.length];
          const event = detector.processLogin({
            ip: attackerIp,
            username: user,
            success: false,
            userAgent: 'Python-urllib/3.10 CredStuff'
          });
          broadcast('LOGIN_EVENT', { event, stats: detector.getStats() });
          await sleep(delayMs);
        }
      } else if (attackType === 'DISTRIBUTED_ATTACK') {
        // Multiple botnet IPs targeting single username
        for (let i = 0; i < count; i++) {
          const botIp = `185.${Math.floor(Math.random()*250)}.${Math.floor(Math.random()*250)}.${Math.floor(Math.random()*250)}`;
          const event = detector.processLogin({
            ip: botIp,
            username: targetUser,
            success: false,
            userAgent: 'Mirai-Botnet/2.1'
          });
          broadcast('LOGIN_EVENT', { event, stats: detector.getStats() });
          await sleep(delayMs);
        }
      } else if (attackType === 'LEGITIMATE') {
        // Normal user login flow (1 failure + 1 success)
        const event1 = detector.processLogin({
          ip: attackerIp,
          username: targetUser,
          success: false,
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        });
        broadcast('LOGIN_EVENT', { event: event1, stats: detector.getStats() });
        await sleep(500);

        const event2 = detector.processLogin({
          ip: attackerIp,
          username: targetUser,
          success: true,
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        });
        broadcast('LOGIN_EVENT', { event: event2, stats: detector.getStats() });
      }
    } catch (err) {
      console.error('Simulation error:', err);
    } finally {
      isSimulating = false;
      broadcast('STATS_UPDATE', detector.getStats());
    }
  })();
});

// WebSocket Connection Handler
wss.on('connection', (ws) => {
  // Send initial stats on connect
  ws.send(JSON.stringify({ type: 'INIT', payload: { stats: detector.getStats(), logs: detector.logs } }));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Login Brute-Force Detector Server running at http://localhost:${PORT}`);
});
