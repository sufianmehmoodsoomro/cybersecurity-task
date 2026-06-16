/**
 * Security Monitor - Simulates Fail2Ban-style log watching on Windows
 * Run with: node monitor.js
 * 
 * On Windows, Fail2Ban doesn't work natively. This script does the same
 * job by watching log files in real time for suspicious patterns.
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const LOGS_DIR = path.join(__dirname, 'logs');
const SUSPICIOUS_LOG = path.join(LOGS_DIR, 'suspicious.log');
const AUTH_LOG = path.join(LOGS_DIR, 'auth-events.log');

// IPs that triggered alerts
const blockedIPs = new Set();
const ipFailCounts = {};

// Thresholds
const ALERT_THRESHOLD = 3;      // alert after 3 suspicious events from same IP
const BLOCK_THRESHOLD = 5;       // block IP after 5 events

console.log('🔍 Security Monitor Started - Watching logs for threats...\n');
console.log('Press Ctrl+C to stop.\n');

// ─────────────────────────────────────────────
// Watch auth-events.log for failed logins
// ─────────────────────────────────────────────
function watchAuthLog() {
  if (!fs.existsSync(AUTH_LOG)) {
    fs.writeFileSync(AUTH_LOG, '');
  }

  let fileSize = fs.statSync(AUTH_LOG).size;

  fs.watch(AUTH_LOG, (eventType) => {
    if (eventType !== 'change') return;

    const newSize = fs.statSync(AUTH_LOG).size;
    if (newSize <= fileSize) return;

    const stream = fs.createReadStream(AUTH_LOG, {
      start: fileSize,
      end: newSize,
    });
    fileSize = newSize;

    const rl = readline.createInterface({ input: stream });
    rl.on('line', (line) => {
      if (!line.trim()) return;
      try {
        const event = JSON.parse(line);
        handleAuthEvent(event);
      } catch (_) {}
    });
  });

  console.log(`👁️  Watching: ${AUTH_LOG}`);
}

// ─────────────────────────────────────────────
// Watch suspicious.log
// ─────────────────────────────────────────────
function watchSuspiciousLog() {
  if (!fs.existsSync(SUSPICIOUS_LOG)) {
    fs.writeFileSync(SUSPICIOUS_LOG, '');
  }

  let fileSize = fs.statSync(SUSPICIOUS_LOG).size;

  fs.watch(SUSPICIOUS_LOG, (eventType) => {
    if (eventType !== 'change') return;

    const newSize = fs.statSync(SUSPICIOUS_LOG).size;
    if (newSize <= fileSize) return;

    const stream = fs.createReadStream(SUSPICIOUS_LOG, {
      start: fileSize,
      end: newSize,
    });
    fileSize = newSize;

    const rl = readline.createInterface({ input: stream });
    rl.on('line', (line) => {
      if (!line.trim()) return;
      try {
        const event = JSON.parse(line);
        handleSuspiciousEvent(event);
      } catch (_) {}
    });
  });

  console.log(`👁️  Watching: ${SUSPICIOUS_LOG}\n`);
}

// ─────────────────────────────────────────────
// Event Handlers
// ─────────────────────────────────────────────
function handleAuthEvent(event) {
  if (event.event === 'FAILED_LOGIN' || event.event === 'LOCKOUT_BLOCKED') {
    const ip = event.ip;
    ipFailCounts[ip] = (ipFailCounts[ip] || 0) + 1;

    console.log(`⚠️  [${event.timestamp}] FAILED LOGIN`);
    console.log(`   IP: ${ip} | Username: ${event.username}`);
    console.log(`   Fail count: ${ipFailCounts[ip]}\n`);

    if (ipFailCounts[ip] >= ALERT_THRESHOLD && !blockedIPs.has(ip)) {
      triggerAlert(ip, 'MULTIPLE_FAILED_LOGINS');
    }
  } else if (event.event === 'LOGIN_SUCCESS') {
    console.log(`✅ [${event.timestamp}] LOGIN SUCCESS`);
    console.log(`   IP: ${event.ip} | User: ${event.username}\n`);
  }
}

function handleSuspiciousEvent(event) {
  const ip = event.ip;
  console.log(`🚨 [${event.timestamp}] SUSPICIOUS ACTIVITY: ${event.type}`);
  console.log(`   IP: ${ip} | Path: ${event.path}\n`);

  ipFailCounts[ip] = (ipFailCounts[ip] || 0) + 1;

  if (ipFailCounts[ip] >= BLOCK_THRESHOLD && !blockedIPs.has(ip)) {
    triggerAlert(ip, 'REPEATED_VIOLATIONS');
  }
}

function triggerAlert(ip, reason) {
  blockedIPs.add(ip);
  const alert = {
    timestamp: new Date().toISOString(),
    type: 'SECURITY_ALERT',
    ip,
    reason,
    action: 'IP flagged for manual review / blocking',
  };

  console.log(`\n🔴 ======================== SECURITY ALERT ========================`);
  console.log(`   IP ADDRESS : ${ip}`);
  console.log(`   REASON     : ${reason}`);
  console.log(`   ACTION     : This IP should be blocked (add to firewall).`);
  console.log(`   TIME       : ${alert.timestamp}`);
  console.log(`🔴 ================================================================\n`);

  // Log the alert
  fs.appendFileSync(
    path.join(LOGS_DIR, 'alerts.log'),
    JSON.stringify(alert) + '\n'
  );

  // On Windows, print the Windows Firewall command to block the IP
  console.log(`💡 To block this IP using Windows Firewall, run as Administrator:`);
  console.log(`   netsh advfirewall firewall add rule name="Block ${ip}" dir=in action=block remoteip=${ip}\n`);
}

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
watchAuthLog();
watchSuspiciousLog();

// Print summary every 60 seconds
setInterval(() => {
  const total = Object.values(ipFailCounts).reduce((a, b) => a + b, 0);
  if (total > 0) {
    console.log(`📊 [Monitor Summary] Total suspicious events: ${total} | Flagged IPs: ${blockedIPs.size}`);
  }
}, 60000);
