/**
 * EBC Agent Logger v2.3.0 — crash-proof
 * Falls back to plain fs.appendFileSync if winston is unavailable
 */

const path = require('path');
const os   = require('os');
const fs   = require('fs');

// Build log dir path — never crash even if env is weird
let logDir;
try {
  logDir = path.join(os.homedir(), 'AppData', 'Roaming', 'EBC-Agent', 'logs');
} catch (e) {
  logDir = path.join('C:\\', 'EBC-Agent', 'logs');
}

// Ensure directory exists — silently ignore errors
try { fs.mkdirSync(logDir, { recursive: true }); } catch (e) {}

const logFile = path.join(logDir, 'agent.log');

// Timestamp formatter
function ts() {
  try {
    return new Date().toLocaleString('en-GB', {
      timeZone: 'Asia/Colombo', day: '2-digit', month: '2-digit',
      year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    });
  } catch (e) {
    return new Date().toISOString();
  }
}

// Plain file writer — always works, no dependencies
function writeToFile(level, message) {
  try {
    const line = `[${ts()}] [${level.padEnd(5)}] ${message}\n`;
    fs.appendFileSync(logFile, line, 'utf8');
  } catch (e) {
    // Absolute last resort — try alternate path
    try {
      fs.appendFileSync('C:\\EBC-Agent-crash.log', `[${ts()}] ${message}\n`, 'utf8');
    } catch (_) {}
  }
}

// Try to use winston for better rotation, fall back to plain writer
let logger;
try {
  const winston = require('winston');
  const fmt = winston.format.combine(
    winston.format.timestamp({ format: ts }),
    winston.format.printf(({ timestamp, level, message }) =>
      `[${timestamp}] [${level.toUpperCase().padEnd(5)}] ${message}`
    )
  );
  logger = winston.createLogger({
    level: 'info',
    format: fmt,
    transports: [
      new winston.transports.File({
        filename: logFile,
        maxsize:  10 * 1024 * 1024,
        maxFiles: 5,
        tailable: true,
      }),
    ],
  });
  // Add console in dev
  if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({ format: winston.format.simple() }));
  }
} catch (e) {
  // winston not available — use plain writer
  writeToFile('WARN', `Winston not available (${e.message}), using plain file logger`);
  logger = {
    info:  (m) => writeToFile('INFO',  m),
    warn:  (m) => writeToFile('WARN',  m),
    error: (m) => writeToFile('ERROR', m),
    debug: (m) => writeToFile('DEBUG', m),
  };
}

module.exports = logger;
