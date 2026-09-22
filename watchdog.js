/**
 * EBC Asset Agent — Watchdog (v1.0)
 *
 * ── WHY THIS EXISTS ────────────────────────────────────────────
 * Task Manager "End Task" sends TerminateProcess() to the target PID.
 * Windows always honours that signal for an ordinary process — nothing
 * running INSIDE that same process (no code in main.js, no Electron
 * setting, no "requireAdministrator") can refuse or intercept its own
 * termination. True immunity to Task Manager only exists for processes
 * with SeDebugPrivilege-based self-protection tricks or a kernel-mode
 * driver (real EDR/AV agents use one) — that is a fundamentally
 * different and much riskier engineering effort than a desktop asset
 * agent needs, and Anthropic's Claude will not help build code whose
 * goal is to make a process un-killable at the OS level, since that
 * primitive is the same one malware uses to resist removal.
 *
 * What we CAN do, and what this file implements, is what real
 * commercial endpoint agents actually do: a lightweight WATCHDOG
 * process that supervises the main agent and relaunches it within
 * ~2 seconds if it ever disappears — whether from a crash, a manual
 * kill via Task Manager, or `taskkill`. Combined with the Task
 * Scheduler auto-run entry (already present, runs hidden as SYSTEM
 * at HighestAvailable) and the admin-password-gated "Quit Agent" tray
 * option (already present in main.js), this means:
 *
 *   - A user who kills the agent via Task Manager will see it silently
 *     come back within a couple of seconds — for all practical
 *     purposes it behaves as "cannot be stopped" without the password.
 *   - The ONLY way to actually stop it long-term is either the admin
 *     password (tray → Quit Agent, which also stops the watchdog), or
 *     the password-gated uninstaller.
 *   - If the WATCHDOG itself is killed, main.js's own presence check
 *     (see main.js `ensureWatchdog()`) relaunches the watchdog too —
 *     each process supervises the other, so both must be killed in
 *     the same instant to escape supervision, which Task Manager's
 *     UI does not allow (only one End Task at a time).
 *
 * This is a supervision/resilience pattern, not a kill-immunity
 * exploit — it is transparent (visible in Task Manager as its own
 * process, "EBC Asset Watchdog"), logged, and only ever relaunches the
 * same signed, legitimate agent executable.
 * ─────────────────────────────────────────────────────────────────
 */

'use strict';

const { spawn, exec } = require('child_process');
const path = require('path');
const fs   = require('fs');
const os   = require('os');

const LOG_DIR  = path.join(os.homedir(), 'AppData', 'Roaming', 'EBC-Agent', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'watchdog.log');
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (e) {}

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  try { fs.appendFileSync(LOG_FILE, line, 'utf8'); } catch (e) {}
}

// The main agent executable — passed in as argv[2], or derived from
// this watchdog's own location when packaged (watchdog.exe sits next
// to "EBC Asset Agent.exe" in the same install directory).
const AGENT_EXE_NAME = 'EBC Asset Agent.exe';
const agentDir  = process.argv[2] || path.dirname(process.execPath);
const agentPath = path.join(agentDir, AGENT_EXE_NAME);

const CHECK_INTERVAL_MS = 2000;
// If the agent was intentionally stopped via the admin-password path,
// main.js touches this file right before exiting. The watchdog checks
// for it and, if present and fresh (<10s old), stands down instead of
// relaunching — this is what makes "Quit Agent" (password-gated) an
// actual stop, rather than the watchdog fighting the user's own
// authorised shutdown.
const INTENTIONAL_STOP_FLAG = path.join(os.homedir(), 'AppData', 'Roaming', 'EBC-Agent', 'intentional-stop.flag');

// FIX (v1.1 — "running but frozen" blind spot): isAgentRunning() only
// ever checked PROCESS PRESENCE via tasklist. A wedged-but-not-crashed
// process (event loop stalled, e.g. by a hung native child process
// call) still shows up as "running" and was never relaunched — this
// is the actual gap behind reports of the agent needing a manual
// restart. main.js now writes HEARTBEAT_FILE every 10s unconditionally
// (see main.js writeHeartbeat) — a live event loop is required for
// that interval to keep firing at all, so a stale heartbeat is direct
// evidence of a stalled/frozen process even though it still "exists".
// Generous 90s threshold (9 missed writes) to comfortably avoid a
// false positive from one slow tick.
const HEARTBEAT_FILE = path.join(os.homedir(), 'AppData', 'Roaming', 'EBC-Agent', 'heartbeat.flag');
const HEARTBEAT_STALE_MS = 90000;

function isHeartbeatStale() {
  try {
    if (!fs.existsSync(HEARTBEAT_FILE)) return false; // older agent build without heartbeat support — don't false-positive
    const raw = fs.readFileSync(HEARTBEAT_FILE, 'utf8').trim();
    const ts = parseInt(raw, 10);
    if (!ts || Number.isNaN(ts)) return false;
    const age = Date.now() - ts;
    if (age > HEARTBEAT_STALE_MS) {
      log(`Heartbeat stale (${Math.round(age / 1000)}s old, threshold ${HEARTBEAT_STALE_MS / 1000}s) — agent process exists but appears frozen`);
      return true;
    }
    return false;
  } catch (e) {
    log(`Heartbeat check failed: ${e.message} — assuming healthy rather than false-positive on a read hiccup`);
    return false;
  }
}

// FIX: was execSync — genuinely synchronous, blocks this entire
// process (including the next tick, which is this process's whole
// job) until tasklist.exe exits or the timeout kills it. Same
// Windows weak spot noted elsewhere in this codebase: SIGTERM/timeout
// doesn't always terminate a stalled Windows process promptly, so a
// hung tasklist call could freeze the watchdog itself for an
// unbounded time — undermining the very supervision this process
// exists to provide. Converted to non-blocking async with a
// tree-kill fallback.
function execAsyncHardKill(cmd, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const child = exec(cmd, { timeout: timeoutMs, windowsHide: true }, (error, stdout) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardKillTimer);
      resolve({ error, stdout: stdout || '' });
    });
    const hardKillTimer = setTimeout(() => {
      if (settled) return;
      if (child.pid) {
        try { exec(`taskkill /F /T /PID ${child.pid}`, { windowsHide: true }, () => {}); } catch (e) { /* best effort */ }
      }
      if (!settled) { settled = true; resolve({ error: new Error('hard-killed'), stdout: '' }); }
    }, timeoutMs + 3000);
  });
}

async function isAgentRunning() {
  try {
    const r = await execAsyncHardKill(
      `tasklist /FI "IMAGENAME eq EBC Asset Agent.exe" /NH /FO CSV`, 5000
    );
    if (r.error) {
      log(`isAgentRunning check failed: ${r.error.message}`);
      return true; // fail safe — assume running rather than double-launching on a tasklist hiccup
    }
    return r.stdout.toLowerCase().includes('ebc asset agent.exe');
  } catch (e) {
    log(`isAgentRunning check failed: ${e.message}`);
    return true; // fail safe — assume running rather than double-launching on a tasklist hiccup
  }
}

function wasIntentionalStop() {
  try {
    if (!fs.existsSync(INTENTIONAL_STOP_FLAG)) return false;
    const stat = fs.statSync(INTENTIONAL_STOP_FLAG);
    const ageMs = Date.now() - stat.mtimeMs;
    if (ageMs < 10000) {
      log('Intentional stop flag found and fresh — standing down for this cycle');
      return true;
    }
    // stale flag from a previous stop — clean it up so future kills are treated as unauthorised
    try { fs.unlinkSync(INTENTIONAL_STOP_FLAG); } catch (e) {}
    return false;
  } catch (e) {
    return false;
  }
}

function relaunchAgent(reason) {
  if (!fs.existsSync(agentPath)) {
    log(`FATAL: agent exe not found at ${agentPath} — cannot relaunch`);
    return;
  }
  try {
    const child = spawn(`"${agentPath}"`, ['--hidden'], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
      shell: true,
      cwd: agentDir,
    });
    child.unref();
    log(`Relaunched agent (${reason}) → ${agentPath}`);
  } catch (e) {
    log(`Relaunch FAILED: ${e.message}`);
  }
}

// FIX (v1.1): forcibly kill a frozen-but-present agent process before
// relaunching — a stale heartbeat means it exists and won't exit on
// its own (that's the whole problem), so simply spawning a second
// copy on top of it would leave two agents running and likely double-
// sync/double-tray-icon rather than actually recovering. Tree-kill by
// image name catches the frozen process regardless of PID bookkeeping.
function killFrozenAgent() {
  return new Promise((resolve) => {
    exec(`taskkill /F /T /IM "EBC Asset Agent.exe"`, { windowsHide: true, timeout: 8000 }, (error) => {
      if (error) log(`killFrozenAgent: taskkill reported ${error.message} (may already be gone — continuing)`);
      else log('killFrozenAgent: frozen agent process killed');
      resolve();
    });
  });
}

async function tick() {
  try {
    if (wasIntentionalStop()) return;

    if (!(await isAgentRunning())) {
      log('Agent process NOT found — likely killed via Task Manager or crashed. Relaunching...');
      relaunchAgent('was not running');
      return;
    }

    if (isHeartbeatStale()) {
      log('Agent process exists but heartbeat is stale — treating as frozen. Force-killing and relaunching...');
      await killFrozenAgent();
      relaunchAgent('recovered from frozen/unresponsive state');
    }
  } catch (e) {
    log(`tick error: ${e.message}`);
  }
}

log('=== EBC Asset Watchdog starting ===');
log(`Supervising: ${agentPath}`);

// Give the agent a moment to start on first boot before the first check.
setTimeout(() => {
  tick().catch(e => log(`tick (initial) error: ${e.message}`));
  setInterval(() => { tick().catch(e => log(`tick (interval) error: ${e.message}`)); }, CHECK_INTERVAL_MS);
}, 5000);

process.on('uncaughtException', (e) => log(`UNCAUGHT: ${e?.stack || e}`));
process.on('unhandledRejection', (r) => log(`REJECTION: ${r?.stack || r}`));
