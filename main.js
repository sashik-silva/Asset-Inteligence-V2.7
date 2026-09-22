/**
 * EBC Asset Agent v4.2.0
 *
 * FIXES in v4.2.0 (this release):
 *
 *  1. DUPLICATE ASSETS FIXED: root cause was the BIOS serial being
 *     re-detected fresh on every sync with no caching — a flaky
 *     WMIC/PowerShell call could silently fall back to a different
 *     detection tier than the previous run, and since the server keyed
 *     its upsert on serial_number alone, a changed value created a new
 *     row instead of updating the existing one. Fixed by caching the
 *     resolved serial to disk on first detection (collector.js) and
 *     reusing it on every future sync. Server-side (both server.js and
 *     the PHP api.php) now also falls back to a hostname match and
 *     merges instead of duplicating if a serial mismatch ever does
 *     occur (e.g. genuine motherboard replacement).
 *
 *  2. WRONG ICON FIXED: package.json had signAndEditExecutable:false,
 *     which stopped electron-builder from stamping assets/icon.ico onto
 *     the compiled .exe — the binary kept Electron's default icon
 *     regardless of the asset files. Flipped to true, and rebuilt both
 *     .ico files with proper multi-resolution frames (16–256px) instead
 *     of the single 256px frame they had before.
 *
 *  3. TASK MANAGER KILL PROTECTION: added watchdog.js, a separate
 *     supervising process that relaunches this agent within ~2s if it's
 *     ever killed (Task Manager, taskkill, crash) without going through
 *     the password-gated "Quit Agent" path. Each process supervises the
 *     other. See watchdog.js for the full explanation of what is and
 *     isn't possible here — true un-killability requires a kernel
 *     driver and is out of scope; this is the same supervision pattern
 *     real commercial endpoint agents use.
 *
 * ── Fixes retained from v4.1.9 ──
 *  - Setup page: Device Type + Ext./Intercom Number fields
 *  - Logs button hidden from status page (still in tray menu)
 *  - Quit/uninstall admin password protection
 *  - Windows Update category friendly-name mapping
 *  - Single-instance lock
 *  All v4.1.8 fixes retained (HP window popup fix, Office detection, etc.)
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

// ── HARDENED ASYNC PROCESS EXEC (root fix for tray/UI freeze) ──
// BUG THIS FIXES: several places in this file used execSync() to run
// short native commands (tasklist, taskkill). execSync is genuinely
// synchronous — it blocks Node's ENTIRE event loop, including native
// UI event dispatch, until the child process exits or its timeout
// fires. isWatchdogRunning()'s tasklist check ran this way every 15
// seconds for the life of the process. tasklist.exe is normally fast,
// but on a loaded machine — antivirus intercepting every process
// launch is common in a managed fleet like this one, plus disk/CPU
// pressure — it can stall. And execSync's `timeout` option has the
// same Windows weak spot documented elsewhere in this codebase
// (collector.js's execWithHardKill comment): SIGTERM doesn't always
// terminate a Windows process promptly, so the "timeout" can itself
// fail to unblock things. When that happened here, it froze the WHOLE
// app, not just sync — exactly matching "tray icon does nothing,
// right-click shows no menu, app looks hung" until the process was
// restarted. (The earlier, narrower fix in collector.js only covered
// collection's own PowerShell/WMIC calls, which run on a background
// path — it didn't touch these separate execSync call sites here.)
//
// Fix: every native command in this file now runs through this
// non-blocking async wrapper instead, with the same tree-kill
// hardening as collector.js's execWithHardKill — never blocks the
// event loop, and force-kills (taskkill /F /T) if the process is
// still alive shortly after its timeout should have ended it.
function execAsyncHardKill(cmd, timeoutMs = 5000) {
  const { exec } = require('child_process');
  return new Promise((resolve) => {
    let settled = false;
    const child = exec(cmd, { timeout: timeoutMs, windowsHide: true },
      (error, stdout, stderr) => {
        if (settled) return;
        settled = true;
        clearTimeout(hardKillTimer);
        resolve({ error, stdout: stdout || '', stderr: stderr || '' });
      });
    const hardKillTimer = setTimeout(() => {
      if (settled) return;
      if (child.pid) {
        try { require('child_process').exec(`taskkill /F /T /PID ${child.pid}`, { windowsHide: true }, () => {}); } catch (e) { /* best effort */ }
      }
      if (!settled) {
        settled = true;
        resolve({ error: new Error(`hard-killed after ${timeoutMs + 3000}ms`), stdout: '', stderr: '' });
      }
    }, timeoutMs + 3000);
  });
}

process.env.ELECTRON_DISABLE_SECURITY_WARNINGS = 'true';

// ── CRASH LOG — set up before anything else ───────────────────
const CRASH_LOG = (() => {
  try {
    const d = path.join(os.homedir(), 'AppData', 'Roaming', 'EBC-Agent', 'logs');
    fs.mkdirSync(d, { recursive: true });
    return path.join(d, 'crash.log');
  } catch (e) { return 'C:\\EBC-Agent-crash.log'; }
})();

function crashLog(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  try { fs.appendFileSync(CRASH_LOG, line, 'utf8'); } catch (_) {}
}

process.on('uncaughtException',  (e) => { crashLog(`UNCAUGHT: ${e?.stack || e}`); });
process.on('unhandledRejection', (r) => { crashLog(`REJECTION: ${r?.stack || r}`); });

let AGENT_VER = '4.2.7';
try { AGENT_VER = require('./package.json').version || '4.2.7'; } catch (_) {}

crashLog(`=== EBC Agent v${AGENT_VER} starting on ${os.hostname()} ===`);

// ── READ --hidden FLAG BEFORE ELECTRON LOADS ──────────────────
const _username      = (process.env.USERNAME      || '').toUpperCase();
const _sessionName   = (process.env.SESSIONNAME   || '').toUpperCase();
const _isServiceAcct = ['SYSTEM','LOCAL SERVICE','LOCALSERVICE',
                        'NETWORK SERVICE','NETWORKSERVICE'].includes(_username);
const _isServiceSess = _sessionName === '' || _sessionName === 'SERVICES' ||
                       _sessionName === 'SERVICE';
const _isInteractive = _sessionName === 'CONSOLE' ||
                       _sessionName.startsWith('RDP-TCP');

const START_HIDDEN = process.argv.includes('--hidden')
  || !process.env.USERPROFILE
  || _isServiceAcct
  || _isServiceSess
  || !_isInteractive;

crashLog(`START_HIDDEN=${START_HIDDEN} | argv=[${process.argv.slice(1).join(', ')}] | USER=${_username} | SESSION=${_sessionName} | PROFILE=${process.env.USERPROFILE ? 'yes' : 'no'}`);

// ── Load Electron ─────────────────────────────────────────────
let electron;
try { electron = require('electron'); crashLog('Electron loaded'); }
catch (e) { crashLog(`FATAL: ${e.message}`); process.exit(1); }

const { app, Tray, Menu, BrowserWindow, ipcMain, nativeImage, shell, dialog } = electron;

try { app.disableHardwareAcceleration(); } catch (e) {}

try {
  app.setAppUserModelId('lk.darleybutler.ebcassetagent');
} catch (e) { crashLog(`setAppUserModelId: ${e.message}`); }

// FIX (Electron default icon bug): explicitly set app icon at the
// earliest possible point too. This mainly affects the taskbar/dock icon
// on some platforms and is a defensive backstop — the real fix is
// signAndEditExecutable:true in package.json's build config so
// electron-builder actually stamps assets/icon.ico onto the compiled
// .exe (it was previously set to false, which leaves Electron's
// default icon on the binary regardless of what's in assets/).
try {
  const earlyIconPath = path.join(__dirname, 'assets', 'icon.ico');
  if (fs.existsSync(earlyIconPath) && app.dock) {
    app.dock.setIcon(earlyIconPath);
  }
} catch (e) { /* non-Windows / no dock — ignore */ }

try {
  app.commandLine.appendSwitch('disable-gpu');
  app.commandLine.appendSwitch('disable-software-rasterizer');
  app.commandLine.appendSwitch('disable-dev-shm-usage');
  app.commandLine.appendSwitch('no-sandbox');
  app.commandLine.appendSwitch('disable-renderer-backgrounding');
  app.commandLine.appendSwitch('disable-background-timer-throttling');
} catch (e) {}

app.on('window-all-closed', (e) => {
  if (e && typeof e.preventDefault === 'function') e.preventDefault();
});

// ── .env loading ──────────────────────────────────────────────
try {
  const candidates = [
    process.resourcesPath ? path.join(process.resourcesPath, '.env') : null,
    path.join(__dirname, '.env'),
    path.join(path.dirname(process.execPath), '.env'),
    path.join(path.dirname(process.execPath), 'resources', '.env'),
  ].filter(Boolean);
  const found = candidates.find(p => { try { return fs.existsSync(p); } catch { return false; } });
  if (found) { require('dotenv').config({ path: found }); crashLog(`.env: ${found}`); }
} catch (e) { crashLog(`.env error: ${e.message}`); }

// ── Logger ────────────────────────────────────────────────────
let logger;
try { logger = require('./logger'); }
catch (e) {
  logger = {
    info:  (m) => crashLog(`INFO: ${m}`),
    warn:  (m) => crashLog(`WARN: ${m}`),
    error: (m) => crashLog(`ERR:  ${m}`),
  };
}

// ── Modules ───────────────────────────────────────────────────
let collector, updater, schedule;
try { collector = require('./collector'); } catch (e) { crashLog(`FATAL: collector: ${e.message}`); }
try { updater   = require('./updater');   } catch (e) { crashLog(`updater: ${e.message}`); updater = null; }
try { schedule  = require('node-schedule'); } catch (e) { crashLog(`schedule: ${e.message}`); schedule = null; }

// ── WATCHDOG SUPERVISION (Task Manager kill protection) ────────
// See watchdog.js for the full explanation. In short: nothing running
// inside THIS process can refuse a TerminateProcess (Task Manager
// "End Task") — that's an OS-level guarantee, not a bug. What we do
// instead is run a second, independent process that notices within
// ~2 seconds if this process disappears and relaunches it — and this
// process does the same for the watchdog. Only the admin-password
// "Quit Agent" path (or the password-gated uninstaller) performs a
// real, permanent stop.
const INTENTIONAL_STOP_FLAG = path.join(os.homedir(), 'AppData', 'Roaming', 'EBC-Agent', 'intentional-stop.flag');

// FIX (v4.2.6 — 32-bit Windows support): the watchdog.exe process is
// compiled via @yao-pkg/pkg, whose underlying pkg-fetch tool does not
// ship a prebuilt Windows x86 (32-bit) Node binary at all — only x64
// and arm64. So on a genuine 32-bit Windows install, no watchdog exe
// is bundled into the install folder at all (see build:watchdog script
// and installer config — x64-only). ensureWatchdog() already guards
// every spawn with fs.existsSync(), so this was already safe (no
// crash, no hang) — it would just silently no-op every 15s forever.
// The only change here is to detect that once, log it clearly so it's
// diagnosable instead of a silent mystery, and skip the retry loop
// instead of re-checking a file we already know isn't there.
let watchdogUnsupportedLogged = false;

async function isWatchdogRunning() {
  try {
    const r = await execAsyncHardKill(`tasklist /FI "IMAGENAME eq EBC Asset Watchdog.exe" /NH /FO CSV`, 5000);
    if (r.error) return true; // fail safe — don't double-launch on a tasklist hiccup
    return r.stdout.toLowerCase().includes('ebc asset watchdog.exe');
  } catch (e) { return true; }
}

async function ensureWatchdog() {
  try {
    // On builds with no watchdog binary at all (32-bit — see FIX note
    // above), skip the tasklist check too, not just the spawn. No point
    // spending a process-spawn every 15s polling for a process that can
    // never exist on this build — matters most on exactly the low-spec
    // hardware this affects.
    const watchdogExeCheck = process.resourcesPath
      ? path.join(path.dirname(process.execPath), 'EBC Asset Watchdog.exe')
      : null;
    if (watchdogExeCheck && !fs.existsSync(watchdogExeCheck)) {
      if (!watchdogUnsupportedLogged) {
        watchdogUnsupportedLogged = true;
        crashLog(`Watchdog not available on this build (${process.arch}) — no watchdog binary was bundled. Agent will run normally but without Task-Manager kill-protection.`);
      }
      return;
    }

    if (await isWatchdogRunning()) return;
    const watchdogExe = process.resourcesPath
      ? path.join(path.dirname(process.execPath), 'EBC Asset Watchdog.exe')
      : path.join(__dirname, 'watchdog.js'); // dev mode — run with node directly
    const { spawn } = require('child_process');
    if (process.resourcesPath && fs.existsSync(watchdogExe)) {
      const child = spawn(`"${watchdogExe}"`, [path.dirname(process.execPath)], {
        detached: true, stdio: 'ignore', windowsHide: true, shell: true,
      });
      child.unref();
      crashLog('Watchdog relaunched (was not running)');
    } else if (!process.resourcesPath && fs.existsSync(watchdogExe)) {
      const child = spawn('node', [watchdogExe, __dirname], {
        detached: true, stdio: 'ignore', windowsHide: true,
      });
      child.unref();
      crashLog('Watchdog relaunched in dev mode');
    }
  } catch (e) { crashLog(`ensureWatchdog: ${e.message}`); }
}

// ── Asset path helper ─────────────────────────────────────────
function getAssetPath(filename) {
  const candidates = [];
  if (process.resourcesPath)
    candidates.push(path.join(process.resourcesPath, 'assets', filename));
  if (process.execPath)
    candidates.push(path.join(path.dirname(process.execPath), 'assets', filename));
  candidates.push(path.join(__dirname, 'assets', filename));
  for (const p of candidates) {
    try { if (fs.existsSync(p)) return p; } catch {}
  }
  return candidates[0] || path.join(__dirname, 'assets', filename);
}

// ── Config ────────────────────────────────────────────────────
const SERVER_URL = (process.env.SERVER_URL || 'http://103.140.194.214:3000').replace(/\/$/, '');
const PHP_URL    = (process.env.PHP_URL    || '').replace(/\/$/, '');
const API_KEY    = process.env.API_KEY    || 'EBC@Asset2024!SecureKey99';
const SYNC_HOUR  = parseInt(process.env.SYNC_HOUR  || '8');
// Admin password for quit/uninstall protection (SHA-256 hash)
// Default: EBC@Admin2024 — change via ADMIN_PASSWORD env var in .env
const ADMIN_PASSWORD_PLAIN = process.env.ADMIN_PASSWORD || 'EBC@Admin2024';

try { AGENT_VER = app.getVersion() || AGENT_VER; } catch (e) {}

// ── Password hashing ──────────────────────────────────────────
function hashPassword(plain) {
  return require('crypto').createHash('sha256').update(plain).digest('hex');
}

const ADMIN_PASSWORD_HASH = hashPassword(ADMIN_PASSWORD_PLAIN);

function verifyAdminPassword(input) {
  return hashPassword((input || '').trim()) === ADMIN_PASSWORD_HASH;
}

// ── Persistent config ─────────────────────────────────────────
const configDir  = (() => {
  try { return path.join(os.homedir(), 'AppData', 'Roaming', 'EBC-Agent'); }
  catch { return 'C:\\EBC-Agent'; }
})();
const configFile = path.join(configDir, 'config.json');
try { fs.mkdirSync(configDir, { recursive: true }); } catch (e) {}

function loadConfig() {
  try {
    if (fs.existsSync(configFile)) {
      const raw = JSON.parse(fs.readFileSync(configFile, 'utf8'));
      return {
        department:     raw.department     || '',
        location:       raw.location       || '',
        contact_number: raw.contact_number || '',
        device_type:    raw.device_type    || '',
        ext_number:     raw.ext_number     || '',
        setup_done:     raw.setup_done     || false,
      };
    }
  } catch (e) { logger.warn(`loadConfig: ${e.message}`); }
  return { department:'', location:'', contact_number:'', device_type:'', ext_number:'', setup_done:false };
}

function saveConfig(data) {
  try {
    fs.writeFileSync(configFile, JSON.stringify({
      department:     (data.department     || '').trim(),
      location:       (data.location       || '').trim(),
      contact_number: (data.contact_number || '').trim(),
      device_type:    (data.device_type    || '').trim(),
      ext_number:     (data.ext_number     || '').trim(),
      setup_done:     true,
    }, null, 2));
  } catch (e) { logger.error(`saveConfig: ${e.message}`); }
}

let agentConfig  = loadConfig();
let tray         = null;
let statusWindow = null;
let lastStatus   = 'idle';
let lastSync     = null;
let isSyncing    = false;
let lastHardware = null;

let _keepAlive = setInterval(() => {}, 30000);

// FIX (v4.2.7 — watchdog blind spot): the watchdog only ever checked
// whether the agent PROCESS EXISTS (tasklist), never whether it's
// actually responsive. A process wedged by a stalled event loop
// (e.g. the Windows Update COM hang investigated separately — see
// collector.js getWindowsUpdates) still shows up as "running" to
// tasklist, so the watchdog considered it healthy and never
// relaunched it — matching the reported "running but frozen, only a
// manual restart fixes it" symptom exactly. Fix: write a heartbeat
// timestamp file on a short, unconditional interval (independent of
// sync success/failure/timeout — this must keep ticking as long as
// the event loop itself is alive, which is precisely the condition
// we're checking). watchdog.js now treats a stale heartbeat the same
// as a missing process and relaunches.
const HEARTBEAT_FILE = path.join(os.homedir(), 'AppData', 'Roaming', 'EBC-Agent', 'heartbeat.flag');
function writeHeartbeat() {
  try {
    fs.mkdirSync(path.dirname(HEARTBEAT_FILE), { recursive: true });
    fs.writeFileSync(HEARTBEAT_FILE, String(Date.now()));
  } catch (e) { /* best effort — a failed write here just means the watchdog relaunches sooner, which is safe */ }
}
writeHeartbeat();
setInterval(writeHeartbeat, 10000);

// ── SINGLE INSTANCE LOCK ──────────────────────────────────────
try {
  const gotLock = app.requestSingleInstanceLock();
  if (!gotLock) {
    crashLog('Second instance detected — exiting silently (first instance handles this)');
    clearInterval(_keepAlive);
    setTimeout(() => { try { app.quit(); } catch { process.exit(0); } }, 300);
  } else {
    app.on('second-instance', (_event, argv) => {
      const hiddenLaunch = argv.includes('--hidden');
      if (hiddenLaunch) {
        crashLog('second-instance --hidden → already running in tray, staying silent');
      } else {
        crashLog('second-instance (user action) → opening window');
        try { showStatusWindow(); } catch (e) { crashLog(`second-instance show: ${e.message}`); }
      }
    });
  }
} catch (e) { crashLog(`Single instance error: ${e.message}`); }

// ── APP READY ─────────────────────────────────────────────────
app.whenReady().then(async () => {
  try {
    logger.info('================================================');
    logger.info(`EBC Asset Agent v${AGENT_VER} starting`);
    logger.info(`Host: ${os.hostname()} | Server: ${SERVER_URL}`);
    logger.info(`Startup mode: ${START_HIDDEN ? '--hidden (Task Scheduler/autorun)' : 'direct user launch'}`);
    logger.info('================================================');

    try { await verifyAutoStart(); } catch (e) { logger.warn(`autostart verify: ${e.message}`); }
    try { createTray(); logger.info('Tray created'); if (tray) clearInterval(_keepAlive); }
    catch (e) { crashLog(`Tray failed: ${e.message}`); }
    try { createStatusWindow(); logger.info('Status window created (hidden — awaiting user action)'); }
    catch (e) { crashLog(`Status window failed: ${e.message}`); }

    // If direct interactive user launch or if initial setup has not been completed, show the window
    if (!START_HIDDEN || !agentConfig.setup_done) {
      showStatusWindow();
    }

    // Clear any stale intentional-stop flag from a previous session so
    // an unauthorised Task Manager kill is never mistaken for one.
    try { fs.unlinkSync(INTENTIONAL_STOP_FLAG); } catch (e) {}
    ensureWatchdog().catch(e => crashLog(`Initial watchdog launch: ${e.message}`));
    setInterval(() => { ensureWatchdog().catch(e => crashLog(`ensureWatchdog interval: ${e.message}`)); }, 15000);

    // Self-heal: if this machine has a fallback (non-real) serial
    // stuck in its cache from before this fix existed, purge it so
    // the collection below re-attempts real BIOS detection instead
    // of reusing the wrong cached value forever.
    try { if (collector) collector.purgeStaleFallbackSerialCache(); }
    catch (e) { logger.warn(`purgeStaleFallbackSerialCache: ${e.message}`); }

    if (collector) {
      // Run initial collection in background without blocking the rest of startup/lifecycle
      runCollection('auto').catch(e => logger.error(`Initial collection: ${e.message}`));
    } else {
      logger.error('FATAL: collector not loaded — check collector.js');
    }

    if (schedule) {
      try {
        schedule.scheduleJob(`0 ${SYNC_HOUR} * * *`, () => {
          logger.info(`Scheduled sync at ${SYNC_HOUR}:00`);
          runCollection('auto');
        });
        logger.info(`Daily sync scheduled at ${SYNC_HOUR}:00`);
      } catch (e) { logger.warn(`Schedule error: ${e.message}`); }
    }

    setInterval(() => pollRemoteCommands().catch(e => logger.warn(`Poll: ${e.message}`)), 60000);

    if (updater) {
      async function doUpdateCheck() {
        try {
          const update = await updater.checkForUpdate(SERVER_URL, API_KEY, AGENT_VER, logger, PHP_URL);
          if (update) {
            logger.info(`Auto-update: v${update.version} available — installing`);
            updater.performUpdate(SERVER_URL, API_KEY, AGENT_VER, logger, PHP_URL)
              .catch(e => logger.error(`performUpdate: ${e.message}`));
          }
        } catch (e) {
          logger.warn(`Update check error: ${e.message}`);
        }
      }
      setTimeout(doUpdateCheck, 90000);
      setInterval(doUpdateCheck, 4 * 60 * 60 * 1000);
    }

    logger.info('Agent fully started — running in system tray');
    crashLog(`Agent v${AGENT_VER} started OK — startup mode: ${START_HIDDEN ? 'hidden' : 'interactive'}`);

  } catch (e) {
    crashLog(`FATAL in whenReady: ${e?.stack || e}`);
  }
}).catch(e => crashLog(`whenReady rejected: ${e?.stack || e}`));

// ── TASK SCHEDULER REGISTRATION ───────────────────────────────
// ── AUTO-START VERIFICATION / REPAIR ────────────────────────────
// BUG THIS REPLACES (found via "doesn't auto-start on boot" report):
// The installer (running elevated, as all installers do) correctly
// creates a Scheduled Task running as SYSTEM with Logon + Boot
// triggers — that part always worked. The problem was this function:
// it re-ran `schtasks /Create /F` for that SAME SYSTEM-owned task on
// EVERY app launch, but from inside the already-running agent, which
// is normally running as a regular (non-admin) logged-in user, not
// elevated. Modifying or recreating a SYSTEM-principal scheduled task
// requires admin rights — so for a non-admin user this call fails
// with Access Denied. The old code caught that failure, silently fell
// through two more fallback tiers (an ONLOGON schtasks variant, then
// an HKLM registry Run key) which ALSO require admin rights and ALSO
// silently failed the same way for a non-admin user, then gave up
// with an empty catch{} — no error shown anywhere. On a machine where
// the agent process happens to run non-elevated, this could silently
// leave the boot-time task missing or stale after an upgrade, with
// zero indication anything was wrong — exactly the "doesn't start on
// power on" symptom.
//
// FIX: never attempt to touch the SYSTEM-owned scheduled task from
// here. Only VERIFY it (a read-only schtasks /Query works for any
// user, no elevation needed) and log loudly if it's missing or
// disabled, so it shows up in the log/tray rather than vanishing
// silently. Separately, maintain a best-effort HKCU (current-user,
// not HKLM) Run-key fallback — HKCU is writable by a normal user
// without elevation, so unlike the old HKLM attempt this one actually
// works when it runs, as a second real safety net alongside the task.
async function verifyAutoStart() {
  const { exec } = require('child_process');
  const { promisify } = require('util');
  const execAsync = promisify(exec);
  const taskName = 'EBC Asset Agent';

  let taskOk = false;
  try {
    const { stdout } = await execAsync(
      `schtasks /Query /TN "${taskName}" /FO LIST /V`, { timeout: 10000 }
    );
    const enabled = /Scheduled Task State:\s*Enabled/i.test(stdout);
    taskOk = enabled;
    if (enabled) {
      logger.info('Auto-start: Scheduled Task "EBC Asset Agent" present and enabled');
    } else {
      logger.warn('Auto-start: Scheduled Task "EBC Asset Agent" exists but is DISABLED — will not run on boot/logon. Re-run the installer or ask IT to run: schtasks /Change /TN "EBC Asset Agent" /ENABLE');
    }
  } catch (e) {
    // Query failing (not just "task not found") usually means the
    // task genuinely does not exist.
    logger.error('Auto-start: Scheduled Task "EBC Asset Agent" NOT FOUND — the agent will not start automatically on reboot. This should have been created by the installer; the fix is to re-run/repair the installer (it registers the task while elevated), not to recreate it from inside the running app. As a stopgap, attempting the current-user HKCU Run-key fallback below.');
  }

  // Best-effort current-user fallback — HKCU does not require
  // elevation, so unlike the old HKLM attempt this genuinely works
  // when it runs. It only covers interactive logon (not a true
  // before-any-logon boot start), but it's a real, working safety net
  // rather than a silently-failing one.
  try {
    const exePath = process.execPath;
    const safe = exePath.replace(/"/g, '""');
    await execAsync(
      `reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "EBCAssetAgent" /t REG_SZ /d "\\"${safe}\\" --hidden" /f`,
      { timeout: 5000 }
    );
    if (!taskOk) {
      logger.info('Auto-start: HKCU Run-key fallback registered for the current user (will start on next interactive logon, though not before-logon on boot)');
    }
  } catch (e) {
    logger.warn(`Auto-start: HKCU Run-key fallback failed too: ${e.message}`);
  }
}

// ── ADMIN PASSWORD DIALOG ─────────────────────────────────────
// Shows a native-style password dialog before allowing quit/uninstall.
// Returns true if the user entered the correct admin password.
async function promptAdminPassword(action) {
  return new Promise((resolve) => {
    try {
      // Build a small password-prompt window
      const win = new BrowserWindow({
        width: 380,
        height: 240,
        resizable: false,
        frame: true,
        modal: true,
        alwaysOnTop: true,
        skipTaskbar: true,
        title: 'EBC Asset Agent — Admin Required',
        webPreferences: {
          nodeIntegration: true,
          contextIsolation: false,
          sandbox: false,
        },
      });
      win.setMenu(null);

      const html = `<!DOCTYPE html><html><head>
<meta charset="UTF-8">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#1a1f2e;color:#c8d4e8;display:flex;flex-direction:column;height:100vh;padding:20px;gap:12px}
h3{font-size:14px;color:#fff;margin-bottom:4px}
p{font-size:12px;color:#7a8ba0;line-height:1.4}
label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#7a8ba0;display:block;margin-bottom:5px}
input{width:100%;background:#0f1218;border:1px solid #1e2530;border-radius:6px;padding:9px 10px;color:#c8d4e8;font-size:13px;outline:none;font-family:inherit}
input:focus{border-color:#00d4aa}
.err{color:#ef4444;font-size:11px;min-height:16px}
.btns{display:flex;gap:8px;margin-top:4px}
button{border:none;border-radius:6px;padding:9px 20px;font-size:12px;font-weight:600;cursor:pointer;font-family:inherit;flex:1}
.ok{background:#00d4aa;color:#000}
.ok:hover{background:#00f0c0}
.cancel{background:#141820;border:1px solid #1e2530;color:#7a8ba0}
.cancel:hover{border-color:#00d4aa;color:#00d4aa}
</style></head><body>
<div>
  <h3>🔒 Admin Authentication Required</h3>
  <p>Enter the agent administrator password to <strong style="color:#f59e0b">${action}</strong>.</p>
</div>
<div>
  <label>Administrator Password</label>
  <input type="password" id="pw" placeholder="Enter admin password" autofocus>
  <div class="err" id="err"></div>
</div>
<div class="btns">
  <button class="ok" onclick="submit()">Confirm</button>
  <button class="cancel" onclick="cancel()">Cancel</button>
</div>
<script>
const {ipcRenderer} = require('electron');
const inp = document.getElementById('pw');
const err = document.getElementById('err');
inp.focus();
inp.addEventListener('keydown', e => { if(e.key==='Enter') submit(); if(e.key==='Escape') cancel(); });
function submit() {
  const v = inp.value;
  if (!v) { err.textContent='Please enter the password'; return; }
  ipcRenderer.send('admin-pw-submit', v);
}
function cancel() { ipcRenderer.send('admin-pw-cancel'); }
</script></body></html>`;

      win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));

      ipcMain.once('admin-pw-submit', (event, pw) => {
        try { win.close(); } catch {}
        if (verifyAdminPassword(pw)) {
          resolve(true);
        } else {
          // Wrong password — show error briefly then resolve false
          resolve(false);
        }
      });

      ipcMain.once('admin-pw-cancel', () => {
        try { win.close(); } catch {}
        resolve(false);
      });

      win.on('closed', () => { resolve(false); });

    } catch (e) {
      crashLog(`promptAdminPassword: ${e.message}`);
      resolve(false);
    }
  });
}

// ── STATUS WINDOW ─────────────────────────────────────────────
function createStatusWindow() {
  const iconFile  = getAssetPath('icon.ico');
  const iconExists = fs.existsSync(iconFile);

  statusWindow = new BrowserWindow({
    width:       500,
    height:      760,
    show:        false,
    frame:       true,
    resizable:   false,
    skipTaskbar: true,
    x:           -32000,
    y:           -32000,
    opacity:     0,
    icon:        iconExists ? iconFile : undefined,
    title:       'EBC Asset Agent',
    webPreferences: {
      nodeIntegration:  true,
      contextIsolation: false,
      sandbox:          false,
      webgl:            false,
    },
  });

  const htmlFile = app.isPackaged
    ? path.join(process.resourcesPath, 'status.html')
    : path.join(__dirname, 'status.html');

  if (fs.existsSync(htmlFile)) {
    statusWindow.loadFile(htmlFile);
  } else {
    statusWindow.loadURL('data:text/html,<h2 style="font-family:sans-serif;padding:20px">EBC Asset Agent running in background</h2>');
  }
  statusWindow.setMenu(null);

  statusWindow.on('close', (e) => {
    e.preventDefault();
    try {
      statusWindow.hide();
      statusWindow.setSkipTaskbar(true);
      statusWindow.setOpacity(0);
      statusWindow.setPosition(-32000, -32000);
    } catch {}
  });

  statusWindow.on('show', () => {
    try { pushStatusToWindow(); } catch {}
  });

  statusWindow.webContents.on('did-fail-load', (e, code, desc) => {
    crashLog(`Window load failed: ${code} ${desc}`);
  });

  statusWindow.webContents.on('did-finish-load', () => {
    setTimeout(() => { try { pushStatusToWindow(); } catch {} }, 300);
  });
}

// ── TRAY ──────────────────────────────────────────────────────
function createTray() {
  const trayIconFile = getAssetPath('tray.ico');
  const appIconFile  = getAssetPath('icon.ico');

  let trayImage;
  let iconSource = 'none';
  if (fs.existsSync(trayIconFile)) {
    trayImage = nativeImage.createFromPath(trayIconFile);
    iconSource = trayIconFile;
  } else if (fs.existsSync(appIconFile)) {
    trayImage = nativeImage.createFromPath(appIconFile);
    iconSource = appIconFile;
  } else {
    trayImage = nativeImage.createEmpty();
  }

  // FIX (icon bug diagnostics): nativeImage.createFromPath() fails
  // SILENTLY and returns an empty image if the path is wrong or the
  // file is corrupt — this previously showed up as either a blank tray
  // icon or Windows falling back to a generic icon with no error
  // logged anywhere. Log it loudly so this is never silent again.
  if (trayImage.isEmpty()) {
    crashLog(`Tray icon FAILED to load from: ${iconSource} — falling back to empty image`);
    logger.error(`Tray icon failed to load (path tried: ${iconSource})`);
  } else {
    logger.info(`Tray icon loaded OK from: ${iconSource}`);
  }

  tray = new Tray(trayImage);
  tray.setToolTip('EBC Asset Agent');
  updateTrayMenu();

  tray.on('double-click', () => {
    try { if (statusWindow) showStatusWindow(); }
    catch (e) { crashLog(`tray double-click: ${e.message}`); }
  });
}

// ── STATUS WINDOW SHOW HELPER ─────────────────────────────────
function showStatusWindow() {
  try {
    if (!statusWindow || statusWindow.isDestroyed()) return;
    statusWindow.setOpacity(1);
    statusWindow.center();
    statusWindow.setSkipTaskbar(false);
    if (statusWindow.isMinimized()) statusWindow.restore();
    statusWindow.show();
    statusWindow.focus();
  } catch (e) { crashLog(`showStatusWindow: ${e.message}`); }
}

// ── STATUS PAYLOAD ────────────────────────────────────────────
function buildStatusPayload() {
  return {
    status:          lastStatus,
    lastSync,
    isSyncing,
    version:         AGENT_VER,
    hostname:        os.hostname(),
    server:          SERVER_URL,
    department:      agentConfig.department     || '',
    location:        agentConfig.location       || '',
    contact_number:  agentConfig.contact_number || '',
    device_type:     agentConfig.device_type    || '',
    ext_number:      agentConfig.ext_number     || '',
    setup_done:      agentConfig.setup_done     || false,
    hw_model:        lastHardware?.device_model    || '',
    hw_manufacturer: lastHardware?.manufacturer    || '',
    hw_cpu:          lastHardware?.cpu_name        || '',
    hw_windows:      lastHardware?.windows_version || '',
    hw_arch:         lastHardware?.architecture    || '',
    hw_ram:          lastHardware?.ram_gb != null ? lastHardware.ram_gb + ' GB' : '',
    hw_serial:       lastHardware?.serial_number   || '',
    hw_ip:           lastHardware?.ip_address      || '',
    hw_ad_user:      lastHardware?.ad_username     || '',
    hw_ms_account:   lastHardware?.ms_account_email || '',
    hw_local_user:   lastHardware?.local_username  || '',
    hw_admin_user:   lastHardware?.pc_admin_user   || '',
    has_sap:         lastHardware?.has_sap         || false,
    has_crowdstrike: lastHardware?.has_crowdstrike || false,
    has_ms_office:   lastHardware?.has_ms_office   || false,
  };
}

function pushStatusToWindow() {
  try {
    if (statusWindow && !statusWindow.isDestroyed()) {
      statusWindow.webContents.send('status-update', buildStatusPayload());
    }
  } catch {}
}

function updateTrayMenu() {
  try {
    const labels = {
      idle:    'Idle',
      syncing: '⟳ Syncing...',
      success: `✓ Last sync: ${lastSync || 'N/A'}`,
      error:   '✗ Last sync FAILED',
    };
    const label = labels[lastStatus] || 'Idle';

    tray?.setContextMenu(Menu.buildFromTemplate([
      { label: `EBC Asset Agent v${AGENT_VER}`, enabled: false },
      { type: 'separator' },
      { label, enabled: false },
      { type: 'separator' },
      { label: 'Open Status / Settings', click: () => {
          try { showStatusWindow(); } catch {}
        }
      },
      { label: 'Sync Now', click: () => runCollection('manual').catch(e => logger.error(`Sync: ${e.message}`)) },
      { label: 'Open Log Folder', click: openLogFolder },
      { type: 'separator' },
      // FIX #3: Quit requires admin password
      { label: 'Quit Agent', click: async () => {
          try {
            const ok = await promptAdminPassword('quit the agent');
            if (ok) {
              logger.info('Admin authorised quit');
              // Tell the watchdog this is an intentional, authorised stop
              // so it doesn't relaunch us within the next couple of
              // seconds — this is what makes the password path a REAL
              // stop, distinct from an unauthorised Task Manager kill.
              try {
                fs.mkdirSync(path.dirname(INTENTIONAL_STOP_FLAG), { recursive: true });
                fs.writeFileSync(INTENTIONAL_STOP_FLAG, new Date().toISOString());
              } catch (e) { crashLog(`Writing stop flag: ${e.message}`); }
              try {
                await execAsyncHardKill('taskkill /F /IM "EBC Asset Watchdog.exe" /T', 5000);
              } catch (e) { /* watchdog may not be running — fine */ }
              clearInterval(_keepAlive);
              try { app.exit(0); } catch { process.exit(0); }
            } else {
              logger.warn('Quit attempt rejected — wrong or no admin password');
            }
          } catch (e) {
            crashLog(`Quit handler: ${e.message}`);
          }
        }
      },
    ]));
    tray?.setToolTip(`EBC Asset Agent v${AGENT_VER} — ${label}`);

    pushStatusToWindow();

  } catch (e) { crashLog(`updateTrayMenu: ${e.message}`); }
}

// ── COLLECTION ────────────────────────────────────────────────
// FIX (crash/hang investigation — "app running but not syncing"):
// isSyncing was a permanent latch with no upper bound. If anything
// inside collector.collect() ever hung indefinitely — the classic
// culprit being the Windows Update COM search, which has no internal
// timeout of its own and is a documented source of indefinite hangs
// on Windows when wuauserv's state is wedged — this flag would stay
// true forever, silently no-op'ing every sync (scheduled, manual, and
// remote-triggered) for the rest of the process's life, with the
// agent itself still showing as "running" in Task Manager/tray. That
// matches the reported symptom exactly: app running, not syncing, not
// visibly doing anything.
//
// Fix: race collect() against a hard deadline. If the deadline wins,
// we give up waiting and reset isSyncing so future syncs can proceed
// — the abandoned collect() call keeps running in the background
// (there's no way to force-cancel an in-flight async operation from
// outside), but a generation counter (syncGeneration) ensures that if
// it DOES eventually resolve late, its result is discarded rather
// than overwriting fresher data or double-sending to the server.
let syncGeneration = 0;
const COLLECTION_HARD_TIMEOUT_MS = 5 * 60 * 1000; // 5 min — generous even for a slow WU search

async function runCollection(triggered = 'auto') {
  if (isSyncing) { logger.info('Already syncing — skipped'); return; }
  if (!collector) { logger.error('collector not available'); return; }

  isSyncing  = true;
  lastStatus = 'syncing';
  updateTrayMenu();

  const myGeneration = ++syncGeneration;
  let timedOut = false;

  try {
    logger.info(`--- Collection start [${triggered}] ---`);

    const data = await Promise.race([
      collector.collect(),
      new Promise((_, reject) => setTimeout(() => {
        timedOut = true;
        reject(new Error(`collect() exceeded ${COLLECTION_HARD_TIMEOUT_MS / 1000}s hard timeout — a sub-step likely hung (e.g. Windows Update COM search); giving up so future syncs are not blocked`));
      }, COLLECTION_HARD_TIMEOUT_MS)),
    ]);

    // A newer sync may have started and already timed this one out
    // and moved on — don't let a late, stale result overwrite it.
    if (myGeneration !== syncGeneration) {
      logger.warn(`--- Collection [${triggered}] resolved after being abandoned (gen ${myGeneration} != ${syncGeneration}) — discarding stale result ---`);
      return;
    }

    // Overlay org config on top of collected hardware
    data.department      = agentConfig.department     || '';
    data.location        = agentConfig.location       || '';
    data.contact_number  = agentConfig.contact_number || '';
    data.device_type     = agentConfig.device_type    || '';
    data.ext_number      = agentConfig.ext_number     || '';
    data.triggered       = triggered;

    lastHardware = data;
    updateTrayMenu();

    logger.info(`Sending FULL OVERWRITE → ${SERVER_URL}/api/asset | serial=${data.serial_number}`);
    const result = await sendToServer(data);

    if (myGeneration !== syncGeneration) {
      logger.warn(`--- Send [${triggered}] completed after being abandoned (gen ${myGeneration} != ${syncGeneration}) — result discarded ---`);
      return;
    }

    lastSync   = new Date().toLocaleString('en-GB', { timeZone: 'Asia/Colombo' });
    lastStatus = 'success';
    logger.info(`--- SUCCESS [${triggered}] FULL OVERWRITE | id=${result?.asset_id} | serial=${data.serial_number} | apps=${data.installed_apps?.length} | wu=${data.windows_updates?.length} | exe=${data.downloads_exe_count} ---`);
    logger.info(`--- SAP:${data.has_sap} | CrowdStrike:${data.has_crowdstrike} | MSOffice(fullPkg):${data.has_ms_office} ---`);
    crashLog(`Sync OK (FULL OVERWRITE): ${data.hostname} | ${data.serial_number}`);

  } catch (err) {
    if (myGeneration !== syncGeneration) return; // superseded, don't clobber newer state
    lastStatus = timedOut ? 'timeout' : 'error';
    const msg = err?.response
      ? `HTTP ${err.response.status}: ${JSON.stringify(err.response.data)}`
      : (err?.message || String(err));
    logger.error(`--- FAILED [${triggered}]: ${msg} ---`);
    crashLog(`Sync FAILED: ${msg}`);
  } finally {
    // Only the sync that "owns" the current generation is allowed to
    // release the lock — a late/abandoned one must not clear it out
    // from under whichever sync superseded it.
    if (myGeneration === syncGeneration) {
      isSyncing = false;
      updateTrayMenu();
    }
  }
}

// ── SEND TO SERVER ────────────────────────────────────────────
async function sendToServer(data) {
  const axios = require('axios');
  const kb    = Math.round(Buffer.byteLength(JSON.stringify(data), 'utf8') / 1024);
  logger.info(`Payload ${kb}KB | serial:${data.serial_number} | Node:${SERVER_URL} | PHP:${PHP_URL || 'N/A'}`);

  const headers = { 'x-api-key': API_KEY, 'Content-Type': 'application/json' };

  async function tryPost(baseUrl, payload, ms) {
    const res = await axios.post(`${baseUrl}/api/asset`, payload, { headers, timeout: ms });
    if (res.status === 200) return res.data;
    throw new Error(`HTTP ${res.status}`);
  }

  // 1. Full → Node
  try { return await tryPost(SERVER_URL, data, 90000); }
  catch (e) { logger.warn(`[1] Node full: ${e.message}`); }

  // 2. Truncated apps → Node
  try {
    const d = { ...data, installed_apps: (data.installed_apps||[]).slice(0, 150) };
    return await tryPost(SERVER_URL, d, 60000);
  } catch (e) { logger.warn(`[2] Node truncated: ${e.message}`); }

  // 3. Full → PHP
  if (PHP_URL) {
    try { return await tryPost(PHP_URL, data, 90000); }
    catch (e) { logger.warn(`[3] PHP full: ${e.message}`); }

    // 4. Truncated → PHP
    try {
      const d = { ...data, installed_apps: (data.installed_apps||[]).slice(0, 150) };
      return await tryPost(PHP_URL, d, 60000);
    } catch (e) { logger.warn(`[4] PHP truncated: ${e.message}`); }
  }

  // 5. Minimal fallback
  const minimal = {
    serial_number:    data.serial_number,
    ip_address:       data.ip_address,
    hostname:         data.hostname,
    device_model:     data.device_model,
    manufacturer:     data.manufacturer,
    windows_version:  data.windows_version,
    windows_build:    data.windows_build,
    architecture:     data.architecture,
    ram_gb:           data.ram_gb,
    cpu_name:         data.cpu_name,
    local_username:   data.local_username,
    ms_account_email: data.ms_account_email,
    user_email:       data.user_email,
    user_name:        data.user_name,
    logged_user:      data.logged_user,
    ad_username:      data.ad_username,
    ad_domain:        data.ad_domain,
    department:       data.department,
    location:         data.location,
    contact_number:   data.contact_number,
    device_type:      data.device_type,
    ext_number:       data.ext_number,
    admin_account:    data.admin_account,
    pc_admin_user:    data.pc_admin_user,
    is_elevated:      data.is_elevated,
    agent_version:    data.agent_version,
    triggered:        data.triggered,
    has_sap:          data.has_sap,
    has_crowdstrike:  data.has_crowdstrike,
    has_ms_office:    data.has_ms_office,
    installed_apps:   [],
    windows_updates:  [],
  };
  const fallback = PHP_URL || SERVER_URL;
  const res = await axios.post(`${fallback}/api/asset`, minimal, { headers, timeout: 30000 });
  if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
  logger.warn('[5] Minimal payload sent — all full attempts failed — serial_number overwrite key preserved');
  return res.data;
}

// ── REMOTE COMMANDS ───────────────────────────────────────────
async function pollRemoteCommands() {
  try {
    const axios = require('axios');
    const headers = { 'x-api-key': API_KEY };
    const params  = { hostname: os.hostname() };

    let res = null;
    let activeUrl = SERVER_URL;
    try {
      res = await axios.get(`${SERVER_URL}/api/commands/pending`, { headers, params, timeout: 10000 });
    } catch (e) {
      if (PHP_URL) {
        res = await axios.get(`${PHP_URL}/api/commands/pending`, { headers, params, timeout: 10000 });
        activeUrl = PHP_URL;
      } else {
        throw e;
      }
    }

    const cmds = Array.isArray(res.data) ? res.data : [];
    for (const cmd of cmds) {
      logger.info(`Remote cmd: ${cmd.command} (id=${cmd.id})`);

      if (cmd.command === 'sync') {
        await runCollection('remote');
        await axios.post(`${activeUrl}/api/commands/${cmd.id}/done`, {}, { headers, timeout: 5000 }).catch(() => {});
      } else if (cmd.command === 'update') {
        // FIX: this used to mark the command "done" immediately, then
        // fire performUpdate() in the background — so the admin panel
        // always showed "update sent" the instant the agent polled,
        // regardless of whether the update actually ran. Any failure
        // after that point (download error, checksum mismatch, no
        // active version published, etc.) was invisible server-side;
        // the only way to know was to go check that PC's local log
        // file by hand. That's why this looked like "remote update
        // doesn't work" — most of the time it was failing silently
        // AFTER already being marked complete.
        //
        // Now: run the update FIRST, get back a real result, and only
        // mark the command done with that actual outcome attached —
        // so the admin panel can show what really happened.
        if (!updater) {
          logger.error('Remote cmd: update requested but the updater module failed to load at startup — cannot proceed. Check crash.log.');
          await axios.post(`${activeUrl}/api/commands/${cmd.id}/done`, { result: 'failed', message: 'updater module not loaded on agent' }, { headers, timeout: 5000 }).catch(() => {});
        } else {
          const result = await updater.performUpdate(SERVER_URL, API_KEY, AGENT_VER, logger, PHP_URL)
            .catch(e => ({ status: 'failed', message: e.message }));
          logger.info(`Remote cmd: update result — ${result.status}: ${result.message || ''}`);
          await axios.post(`${activeUrl}/api/commands/${cmd.id}/done`,
            { result: result.status, message: result.message }, { headers, timeout: 5000 }).catch(() => {});
        }
        break;
      } else {
        await axios.post(`${activeUrl}/api/commands/${cmd.id}/done`, {}, { headers, timeout: 5000 }).catch(() => {});
      }
    }
  } catch (err) {
    if (!['ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND'].includes(err.code)) {
      logger.warn(`Poll: ${err.message}`);
    }
  }
}

// ── IPC ───────────────────────────────────────────────────────
ipcMain.on('sync-now', () => runCollection('manual').catch(e => logger.error(`IPC sync: ${e.message}`)));
ipcMain.on('open-log', openLogFolder);
ipcMain.handle('get-status', () => buildStatusPayload());

ipcMain.on('save-config', (event, cfg) => {
  try {
    agentConfig.department      = (cfg.department     || '').trim();
    agentConfig.location        = (cfg.location       || '').trim();
    agentConfig.contact_number  = (cfg.contact_number || '').trim();
    agentConfig.device_type     = (cfg.device_type    || '').trim();
    agentConfig.ext_number      = (cfg.ext_number     || '').trim();
    agentConfig.setup_done      = true;
    saveConfig(agentConfig);
    logger.info(`Config saved — dept:${agentConfig.department} loc:${agentConfig.location} contact:${agentConfig.contact_number} devType:${agentConfig.device_type} ext:${agentConfig.ext_number}`);
    event.reply('config-saved', { ok: true });
    updateTrayMenu();
    runCollection('manual').catch(e => logger.error(`Post-save sync: ${e.message}`));
  } catch (e) {
    logger.error(`save-config: ${e.message}`);
    event.reply('config-saved', { ok: false });
  }
});

ipcMain.handle('get-config', () => ({
  department:     agentConfig.department     || '',
  location:       agentConfig.location       || '',
  contact_number: agentConfig.contact_number || '',
  device_type:    agentConfig.device_type    || '',
  ext_number:     agentConfig.ext_number     || '',
  setup_done:     agentConfig.setup_done     || false,
}));

ipcMain.handle('get-departments', async () => {
  try {
    const axios = require('axios');
    const headers = { 'x-api-key': API_KEY };
    for (const base of [SERVER_URL, PHP_URL].filter(Boolean)) {
      try {
        const res = await axios.get(`${base}/api/departments`, { headers, timeout: 10000 });
        if (Array.isArray(res.data)) return res.data;
      } catch (e) { logger.warn(`get-departments ${base}: ${e.message}`); }
    }
  } catch (e) { logger.error(`get-departments: ${e.message}`); }
  return [];
});

ipcMain.handle('get-locations', async () => {
  try {
    const axios = require('axios');
    const headers = { 'x-api-key': API_KEY };
    for (const base of [SERVER_URL, PHP_URL].filter(Boolean)) {
      try {
        const res = await axios.get(`${base}/api/locations`, { headers, timeout: 10000 });
        if (Array.isArray(res.data)) return res.data;
      } catch (e) { logger.warn(`get-locations ${base}: ${e.message}`); }
    }
  } catch (e) { logger.error(`get-locations: ${e.message}`); }
  return [];
});

ipcMain.handle('add-department', async (event, name) => {
  try {
    const axios = require('axios');
    const headers = { 'x-api-key': API_KEY, 'Content-Type': 'application/json' };
    for (const base of [SERVER_URL, PHP_URL].filter(Boolean)) {
      try {
        const res = await axios.post(`${base}/api/departments`, { name: name.trim() }, { headers, timeout: 10000 });
        return res.data;
      } catch (e) { logger.warn(`add-department ${base}: ${e.message}`); }
    }
  } catch (e) { logger.error(`add-department: ${e.message}`); }
  return null;
});

ipcMain.handle('add-location', async (event, name) => {
  try {
    const axios = require('axios');
    const headers = { 'x-api-key': API_KEY, 'Content-Type': 'application/json' };
    for (const base of [SERVER_URL, PHP_URL].filter(Boolean)) {
      try {
        const res = await axios.post(`${base}/api/locations`, { name: name.trim() }, { headers, timeout: 10000 });
        return res.data;
      } catch (e) { logger.warn(`add-location ${base}: ${e.message}`); }
    }
  } catch (e) { logger.error(`add-location: ${e.message}`); }
  return null;
});

// ── HELPERS ───────────────────────────────────────────────────
function openLogFolder() {
  try {
    const d = path.join(os.homedir(), 'AppData', 'Roaming', 'EBC-Agent', 'logs');
    try { fs.mkdirSync(d, { recursive: true }); } catch {}
    shell.openPath(d);
  } catch (e) { logger.warn(`openLogFolder: ${e.message}`); }
}
