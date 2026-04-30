'use strict';

/**
 * Logging proxy that sits in front of Juice Shop.
 * Captures every request/response and asynchronously forwards structured
 * JSON logs to the backend log-receiver service.
 * Never blocks the request path — all log I/O is fire-and-forget.
 */

const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const axios = require('axios');

const LOG_RECEIVER_URL = process.env.LOG_RECEIVER_URL || 'http://localhost:5000/log';
const JUICE_SHOP_INTERNAL = process.env.JUICE_SHOP_INTERNAL || 'http://localhost:3000';
const PROXY_PORT = parseInt(process.env.PROXY_PORT || '8080', 10);

const app = express();

// Batch buffer to reduce HTTP overhead to the log-receiver
const LOG_BATCH_SIZE = parseInt(process.env.LOG_BATCH_SIZE || '20', 10);
const LOG_BATCH_INTERVAL_MS = parseInt(process.env.LOG_BATCH_INTERVAL_MS || '2000', 10);

let logBuffer = [];
let flushTimer = null;

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(flushBuffer, LOG_BATCH_INTERVAL_MS);
}

async function flushBuffer() {
  flushTimer = null;
  if (logBuffer.length === 0) return;

  const batch = logBuffer.splice(0, logBuffer.length);
  try {
    await axios.post(
      LOG_RECEIVER_URL.replace('/log', '/logs/batch'),
      batch,
      { timeout: 3000, headers: { 'Content-Type': 'application/json' } }
    );
  } catch {
    // Fallback: try individual POSTs silently
    for (const entry of batch) {
      axios.post(LOG_RECEIVER_URL, entry, { timeout: 2000 }).catch(() => {});
    }
  }
}

function enqueueLog(entry) {
  logBuffer.push(entry);
  if (logBuffer.length >= LOG_BATCH_SIZE) {
    clearTimeout(flushTimer);
    flushTimer = null;
    flushBuffer();
  } else {
    scheduleFlush();
  }
}

// ── Request logging middleware ──────────────────────────────────────────────
app.use((req, res, next) => {
  const startTime = Date.now();

  // Extract real client IP from proxy chain
  const rawIp =
    req.headers['x-forwarded-for'] ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    'unknown';
  const clientIp = rawIp.split(',')[0].trim();

  res.on('finish', () => {
    enqueueLog({
      timestamp: new Date().toISOString(),
      ip: clientIp,
      method: req.method,
      url: req.originalUrl || req.url,
      status: res.statusCode,
      user_agent: req.headers['user-agent'] || '',
      referer: req.headers['referer'] || '',
      response_time_ms: Date.now() - startTime,
      source: 'juice-shop',
      host: req.headers['host'] || '',
      content_type: req.headers['content-type'] || '',
      accept: req.headers['accept'] || '',
      x_forwarded_for: req.headers['x-forwarded-for'] || '',
      content_length: res.getHeader('content-length') || null,
    });
  });

  next();
});

// ── Proxy to Juice Shop ─────────────────────────────────────────────────────
app.use(
  '/',
  createProxyMiddleware({
    target: JUICE_SHOP_INTERNAL,
    changeOrigin: true,
    ws: true,
    on: {
      error: (err, req, res) => {
        console.error('[proxy] error:', err.message);
        if (res && !res.headersSent) {
          res.status(502).send('Upstream unavailable');
        }
      },
    },
  })
);

app.listen(PROXY_PORT, () => {
  console.log(`[proxy] Logging proxy listening on :${PROXY_PORT}`);
  console.log(`[proxy] Forwarding to ${JUICE_SHOP_INTERNAL}`);
  console.log(`[proxy] Log receiver: ${LOG_RECEIVER_URL}`);
});

// Flush remaining logs on shutdown
process.on('SIGTERM', async () => {
  console.log('[proxy] Flushing log buffer before shutdown...');
  await flushBuffer();
  process.exit(0);
});

// ── Start Native Juice Shop Process ─────────────────────────────────────────
const { spawn } = require('child_process');

console.log('[proxy] Spawning backend Juice Shop process...');
const juiceShop = spawn('node', ['build/app'], { 
  cwd: '/juice-shop', 
  stdio: 'inherit' 
});

juiceShop.on('error', (err) => {
  console.error('[proxy] Failed to start Juice Shop:', err);
});

juiceShop.on('exit', (code) => {
  console.log(`[proxy] Juice Shop exited with code ${code}`);
  process.exit(code);
});

