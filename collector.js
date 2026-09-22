/**
 * EBC Asset Collector v3.4.0
 *
 * FIXES in v4.1.9 / collector v3.4.0:
 *
 *  5. WINDOWS UPDATE CATEGORIES: Raw MS severity names ("Critical Updates")
 *     are now mapped to friendly labels (Security Update, Cumulative Update,
 *     Feature Update, Driver Update, Definition Update, etc.).
 *
 *  6. SERIAL NUMBER DEDUPLICATION: Extended BAD_SERIALS list + new
 *     isLikelyDuplicateSerial() check catches batch-cloned serials,
 *     single-digit repeating patterns, and short numeric placeholders.
 *     Falls back to hardware fingerprint (CPU+MAC SHA1) automatically.
 *
 * Previous fixes from v3.3.0:
 *
 *  MICROSOFT OFFICE — FULL PACKAGE DETECTION ONLY
 *  ─────────────────────────────────────────────
 *  has_ms_office = true ONLY when the computer has the FULL Microsoft Office
 *  suite installed (Word + Excel + PowerPoint as a minimum, installed together
 *  as a suite product).
 *
 *  A standalone single-app install is NOT counted:
 *    ✗ Just Microsoft Word (standalone)
 *    ✗ Just Microsoft Excel (standalone)
 *    ✗ Just Microsoft Access (standalone)
 *    ✗ Just Microsoft Outlook (standalone)
 *    ✗ Just Microsoft OneNote (standalone Store version)
 *
 *  What IS counted (true full package):
 *    ✓ Microsoft 365 / Office 365 (any plan — Home, Personal, Business, ProPlus)
 *    ✓ Office 2024 Home & Business, Professional, LTSC
 *    ✓ Office 2021 Home & Business, Professional, Professional Plus
 *    ✓ Office 2019 Home & Business, Professional, Professional Plus
 *    ✓ Office 2016 Home & Business, Professional, Professional Plus
 *    ✓ Office 2013 Professional Plus / Standard
 *    ✓ Office 2010 Professional Plus / Standard
 *    ✓ Any Click-to-Run install whose ProductReleaseIds contains a SUITE token
 *      (NOT a single-app token like WordRetail, ExcelRetail alone)
 *    ✓ Any install where at least 3 of the 5 core executables exist on disk:
 *      WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, OUTLOOK.EXE, ONENOTE.EXE
 *
 *  Detection layers (in order, stops at first positive match):
 *    1. Installed-apps registry — looks for suite-level entries only.
 *       Individual app entries (e.g. "Microsoft Word" alone) are filtered out.
 *    2. ClickToRun registry — checks ProductReleaseIds for suite tokens.
 *       Single-app C2R tokens (WordRetail, ExcelRetail) are explicitly excluded
 *       unless accompanied by other suite tokens.
 *    3. MSI InstallRoot registry — checks for WINWORD.EXE in the install path
 *       AND counts how many other core exes are present. Requires >= 3.
 *    4. Filesystem scan — counts core Office executables across all known paths.
 *       Requires >= 3 executables to confirm a suite install.
 *    5. Microsoft Store / UWP — counts Store Office app packages.
 *       Requires >= 3 distinct Office app packages (Word + Excel + PowerPoint).
 *
 * All fixes from v3.2.4 retained (user info, serial, etc.)
 */

'use strict';

const os   = require('os');
const fs   = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const logger = require('./logger');

// ── SAFE POWERSHELL ───────────────────────────────────────────
// FIX (crash/hang investigation): Node's child_process exec `timeout`
// option sends SIGTERM to the immediate child on Windows, but this is
// a well-documented weak spot — PowerShell can fail to exit promptly
// on SIGTERM, especially when it's blocked inside a COM/RPC call (the
// Windows Update Agent's Search() method is a known offender: it has
// no internal timeout of its own and can hang indefinitely if
// wuauserv's state is wedged). When that happens, Node's timeout does
// fire, but the underlying powershell.exe process can be left running
// and never actually releases the awaited promise in a timely way on
// some Windows configurations — which was letting a single stuck sync
// wedge the collector open indefinitely (see isSyncing latch in
// main.js, and the hard outer deadline added there as a second,
// independent safety net).
//
// Fix here: track the child's PID and, if our own timer fires before
// Node's child_process timeout has cleaned it up, force a tree-kill
// via `taskkill /F /T /PID <pid>` — this reliably kills the process
// AND any child processes it spawned, unlike a bare SIGTERM.
function execWithHardKill(cmd, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const child = exec(cmd, { timeout: timeoutMs, maxBuffer: 30 * 1024 * 1024, windowsHide: true },
      (error, stdout, stderr) => {
        if (settled) return;
        settled = true;
        clearTimeout(hardKillTimer);
        if (error) resolve({ error, stdout: stdout || '', stderr: stderr || '' });
        else resolve({ error: null, stdout: stdout || '', stderr: stderr || '' });
      });

    // Belt-and-braces: fire a bit after Node's own timeout should have
    // already killed it. If the process is somehow still alive at
    // that point, force it (and any children) down directly.
    const hardKillTimer = setTimeout(() => {
      if (settled) return;
      if (child.pid) {
        try { execAsyncFireAndForget(`taskkill /F /T /PID ${child.pid}`); } catch (e) { /* best effort */ }
      }
      if (!settled) {
        settled = true;
        resolve({ error: new Error(`hard-killed after ${timeoutMs + 3000}ms (no response from timeout signal)`), stdout: '', stderr: '' });
      }
    }, timeoutMs + 3000);
  });
}

// Fire-and-forget async kill — NOT execSync. This runs inside a
// timeout-handler whose entire purpose is unblocking a hung
// operation; using a synchronous call here would defeat that purpose
// if taskkill.exe itself ever stalls (same class of risk as the bug
// this file's execWithHardKill was built to prevent in the first
// place). We don't need to wait for the result — the caller has
// already decided to give up on the original process either way.
function execAsyncFireAndForget(cmd) {
  try { exec(cmd, { timeout: 5000, windowsHide: true }, () => {}); } catch (e) { /* best effort */ }
}

// FIX (v4.2.7): added `retryOnFail` option (default true, unchanged
// behaviour everywhere else). When false, a failed/timed-out first
// attempt is NOT retried — it returns immediately instead of stacking
// a second full-length timeout on top of the first. Introduced for
// getWindowsUpdates(), where retrying a COM call into an already-
// wedged service just doubles the wait with no real chance of a
// different outcome; other callers keep the original retry-once
// behaviour since their commands don't share that specific risk.
async function ps(cmd, timeoutMs = 15000, { retryOnFail = true } = {}) {
  const tmpFile = path.join(os.tmpdir(), `ebc_ps_${Date.now()}_${Math.random().toString(36).slice(2)}.ps1`);
  try {
    fs.writeFileSync(tmpFile, cmd, 'utf8');
    const r1 = await execWithHardKill(
      `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "${tmpFile}"`,
      timeoutMs
    );
    if (!r1.error) return r1.stdout.trim();
    if (!retryOnFail) return '';

    const safe = cmd.replace(/\r?\n/g, ' ').replace(/"/g, '\\"');
    const r2 = await execWithHardKill(
      `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command "${safe}"`,
      timeoutMs
    );
    return r2.error ? '' : r2.stdout.trim();
  } finally {
    try { fs.unlinkSync(tmpFile); } catch { }
  }
}

// FIX (v4.2.6 — WMIC removal on newer Windows 11 builds): Microsoft has
// been removing wmic.exe from Windows entirely (already gone on recent
// Windows 11 24H2/25H2 updates as of 2026, after being deprecated for
// years). On a machine without it, spawning `wmic ...` fails immediately
// (command not found) — execWithHardKill correctly catches that as an
// error and wmic() returns '', so nothing crashes or hangs, but every
// caller silently gets no data instead of falling back to an equivalent
// query. Since WMI itself (the underlying service) is NOT going away —
// only the wmic.exe command-line wrapper is — the fix is to retry via
// PowerShell's Get-CimInstance (the modern, still-supported way to query
// the same WMI classes) whenever the wmic.exe call fails outright. This
// keeps wmic() as a drop-in replacement everywhere it's already called —
// no call sites need to change — and costs nothing extra on machines
// that still have wmic.exe, since the fallback only triggers on failure.
const WMIC_TO_CIM = {
  'bios get serialnumber':                 "(Get-CimInstance Win32_BIOS).SerialNumber",
  'computersystem get name':                "(Get-CimInstance Win32_ComputerSystem).Name",
  'computersystem get username':            "(Get-CimInstance Win32_ComputerSystem).UserName",
};

async function wmicToCimFallback(query) {
  // Pull out the "<class> get <prop>[,<prop>...]" shape from a wmic
  // command string and translate it to the matching CIM query above.
  const norm = query.replace(/^wmic\s+/i, '').replace(/\s*\/(value|format:\w+)\s*$/i, '').trim().toLowerCase();
  const psExpr = WMIC_TO_CIM[norm];
  if (!psExpr) return ''; // no mapping for this specific query — caller's other fallbacks (getSerial's own PS chain, etc.) still apply
  try {
    const out = await ps(psExpr, 10000);
    return out ? out.trim() : '';
  } catch (e) {
    return '';
  }
}

async function wmic(query, timeoutMs = 10000) {
  const r = await execWithHardKill(query, timeoutMs);
  if (!r.error) return r.stdout.trim();

  // wmic.exe missing or failing outright — try the CIM equivalent so
  // callers still get data on machines where wmic.exe has been removed.
  const cimResult = await wmicToCimFallback(query);
  if (cimResult) {
    // Re-shape into the same "Key=Value" text format wmic's /value
    // output uses, so existing regex parsing at call sites (e.g.
    // /SerialNumber=(.+)/i) keeps working unchanged.
    if (/serialnumber/i.test(query)) return `SerialNumber=${cimResult}`;
    if (/get\s+name\b/i.test(query)) return `Name=${cimResult}`;
    if (/get\s+username\b/i.test(query)) return `UserName=${cimResult}`;
    return cimResult;
  }
  return '';
}

async function reg(key, value, timeoutMs = 5000) {
  try {
    const { stdout } = await execAsync(`reg query "${key}" /v "${value}" 2>nul`, { timeout: timeoutMs });
    const m = stdout.match(/REG_\w+\s+(.+)/);
    return m ? m[1].trim() : '';
  } catch {
    return '';
  }
}

// ─────────────────────────────────────────────────────────────
// MAIN COLLECT
// ─────────────────────────────────────────────────────────────
async function collect() {
  logger.info('=== Collection started ===');

  const serial    = await getSerialCached();
  const ipAddr    = await getIP();
  const hostname  = await getHostname();
  const osInfo    = await getOSInfo();
  const hw        = await getHardware();
  const userInfo  = await getUserInfo();
  const adminInfo = await getAdminInfo();
  const apps      = await getInstalledApps();
  const updates   = await getWindowsUpdates();
  const localMgmt = await getLocalUsersAndGroups();
  const exeScan   = await scanExeFiles(userInfo);

  const hasSap         = apps.some(a => isSAP(a.name, a.publisher));
  const hasCrowdStrike = apps.some(a => isCrowdStrike(a.name, a.publisher));

  // ── OFFICE: full suite detection ──────────────────────────
  // Step 1: check the installed-apps list for a SUITE-level entry.
  // Step 2: if not found, run the deep registry + filesystem check.
  // Result is only true when a FULL SUITE is confirmed — not single apps.
  let hasMsOffice = appsListHasOfficeSuite(apps);
  if (!hasMsOffice) {
    logger.info('Office suite not found in app list — running deep check...');
    hasMsOffice = await detectOfficeSuiteDeep();
  }
  logger.info(`Microsoft Office full suite: ${hasMsOffice}`);

  const data = {
    serial_number:        serial,
    ip_address:           ipAddr,
    hostname:             hostname,
    computer_name:        hostname,
    device_model:         hw.model,
    manufacturer:         hw.mfr,
    windows_version:      osInfo.version,
    windows_build:        osInfo.build,
    architecture:         osInfo.arch,
    ram_gb:               hw.ramGb,
    cpu_name:             hw.cpu,

    logged_user:          userInfo.logged,
    local_username:       userInfo.localUser,
    ms_account_email:     userInfo.msEmail,
    user_email:           userInfo.email,
    user_name:            userInfo.name,
    ad_username:          userInfo.adUser,
    ad_domain:            userInfo.domain,

    admin_account:        adminInfo.isAdmin,
    admin_username:       adminInfo.adminUser,
    pc_admin_user:        adminInfo.pcAdminUser,
    is_elevated:          adminInfo.isElevated,

    local_users_json:     JSON.stringify(localMgmt.users),
    local_groups_json:    JSON.stringify(localMgmt.groups),

    department:           '',
    location:             '',
    contact_number:       '',
    installed_apps:       apps,
    windows_updates:      updates.list,
    pending_update_count: updates.count,
    downloads_exe_files:  exeScan.files,
    downloads_exe_count:  exeScan.count,
    downloads_exe_folder: exeScan.folder,
    agent_version:        require('./package.json').version,

    has_sap:              hasSap,
    has_crowdstrike:      hasCrowdStrike,
    has_ms_office:        hasMsOffice,
  };

  logger.info(`Serial: ${data.serial_number} | IP: ${data.ip_address} | Host: ${data.hostname}`);
  logger.info(`OS: ${data.windows_version} (${data.architecture}) | RAM: ${data.ram_gb}GB | CPU: ${data.cpu_name}`);
  logger.info(`LocalUser: ${data.local_username} | MS: ${data.ms_account_email || 'none'} | AD: ${data.ad_username || 'none'}`);
  logger.info(`PCAdmin: ${data.pc_admin_user} | LocalUsers: ${localMgmt.users.length}`);
  logger.info(`Apps: ${apps.length} | Updates: ${updates.count}`);
  logger.info(`SAP: ${hasSap} | CrowdStrike: ${hasCrowdStrike} | MSOffice(fullSuite): ${hasMsOffice}`);

  const appTypes = {};
  for (const a of apps) appTypes[a.app_type] = (appTypes[a.app_type] || 0) + 1;
  logger.info(`App types: ${JSON.stringify(appTypes)}`);

  return data;
}

// ─────────────────────────────────────────────────────────────
// SERIAL NUMBER
// ─────────────────────────────────────────────────────────────
const BAD_SERIALS = [
  '', 'n/a', 'none', 'to be filled by o.e.m.', 'default string',
  'not applicable', 'system serial number', '0', '00000000', 'none1',
  'chassis serial number', 'base board serial number', 'invalid',
  'empty', 'fill by oem', 'oemid', '123456789', '1234567890',
  'no serial number', 'serial number', 'type2 - board serial number',
  'mb-1234567890', 'to be filled', 'unknown',
  // FIX v4.1.9: additional generic/duplicate-prone serials
  '00000000000', '11111111111', 'aaaaaaaaaaa',
  'default_string', 'Not Specified', 'Not Available',
  'Chassis Serial Number', 'System Serial Number',
  'INVALID', 'OEM', 'OEM_Serial',
];

// FIX v4.1.9: Additional serial quality checks beyond the exact-match list
function isLikelyDuplicateSerial(s) {
  if (!s) return true;
  const t = s.trim();
  // All same character (00000, FFFFF, etc.)
  if (/^(.)\1{4,}$/.test(t)) return true;
  // Pure numeric AND very short (under 5 digits) — likely placeholder
  if (/^\d{1,4}$/.test(t)) return true;
  // Looks like a generic OEM placeholder pattern
  if (/^(PC|SN|SER|SERIAL)[\-_]?\d{0,6}$/i.test(t)) return true;
  return false;
}

// ─────────────────────────────────────────────────────────────
// FIX v4.1.9: Windows Update category normalisation
// Map raw Microsoft severity/category names to friendly labels
// ─────────────────────────────────────────────────────────────
function normaliseUpdateCategory(category, severity, title) {
  const cat = (category || '').trim();
  const sev = (severity || '').toLowerCase().trim();
  const ttl = (title    || '').toLowerCase();

  // Severity-based mapping first (most reliable)
  if (sev === 'critical') return 'Security Update';
  if (sev === 'important') return 'Security Update';
  if (sev === 'moderate')  return 'Security Update';
  if (sev === 'low')       return 'Optional Update';

  // Category string mapping
  const catLower = cat.toLowerCase();
  if (catLower.includes('security')) return 'Security Update';
  if (catLower.includes('critical')) return 'Security Update';
  if (catLower.includes('definition') || catLower.includes('antivirus') || catLower.includes('defender'))
    return 'Definition Update';
  if (catLower.includes('cumulative') || ttl.includes('cumulative'))
    return 'Cumulative Update';
  if (catLower.includes('feature') || ttl.includes('feature update to windows'))
    return 'Feature Update';
  if (catLower.includes('driver'))         return 'Driver Update';
  if (catLower.includes('service pack'))   return 'Service Pack';
  if (catLower.includes('office') || ttl.includes('microsoft 365') || ttl.includes('office'))
    return 'Office Update';
  if (catLower.includes('net framework') || ttl.includes('.net'))
    return '.NET Update';
  if (catLower.includes('update rollup')) return 'Update Rollup';
  if (catLower.includes('windows update') || catLower === 'updates')
    return 'Windows Update';

  // Title-based fallback
  if (ttl.includes('security'))    return 'Security Update';
  if (ttl.includes('cumulative'))  return 'Cumulative Update';
  if (ttl.includes('defender'))    return 'Definition Update';

  return cat || 'Windows Update';
}

function isGoodSerial(s) {
  if (!s) return false;
  const t = s.toLowerCase().trim();
  if (BAD_SERIALS.map(b => b.toLowerCase()).includes(t)) return false;
  if (t.length < 3) return false;
  if (/^(.)\1+$/.test(t)) return false;
  if (isLikelyDuplicateSerial(s)) return false;
  return true;
}

// ─────────────────────────────────────────────────────────────
// FIX: SERIAL NUMBER CACHING (root cause of duplicate assets)
//
// getSerial() re-derives the serial from BIOS/WMIC/PowerShell on every
// single sync. If any one of those calls is flaky (timeout, transient
// WMI hiccup, HP BIOS quirk under load) it silently falls through to a
// DIFFERENT fallback tier than the previous run (e.g. BIOS serial one
// day, UUID-based or HW-fingerprint the next). Since the server keys
// its upsert strictly on serial_number, a changed value creates a
// brand-new asset row for the same physical PC instead of updating the
// existing one — this is exactly the duplicate-row symptom reported.
//
// Fix: resolve the serial ONCE, cache it to config.json, and reuse the
// cached value on every subsequent sync for the lifetime of the
// install. Only re-detect if there is no cache yet. This makes the
// per-machine serial 100% stable across syncs, reboots, and network
// hiccups, regardless of which detection tier originally produced it.
//
// FOLLOW-UP FIX (after real deployment feedback): the above caching,
// as first written, cached WHATEVER getSerial() returned on the very
// first sync — including a HW-/UUID-/PC- fallback value, if the real
// BIOS serial happened to fail to read on that first run (slow WMI on
// first boot after install is common). Once cached, that fake value
// was locked in forever, even on machines where the real BIOS serial
// reads successfully on every later sync. That's why some assets
// ended up permanently stuck on a "HW-xxxxxxxxxxxx" fingerprint
// instead of their real serial (e.g. "5CD0314YSF").
//
// Only a REAL serial (BIOS or baseboard — detection tiers b1/b2/b3
// below) is now considered cache-worthy and locked in. A fallback
// value (UUID-/HW-/PC-) is used for that sync but deliberately NOT
// cached, so the agent keeps retrying real-serial detection on every
// subsequent sync until it succeeds — at which point the real serial
// gets cached and takes over permanently. This keeps the original
// fix's guarantee (a REAL serial never flaps between runs) while no
// longer permanently freezing in a bad first read.
// ─────────────────────────────────────────────────────────────
const SERIAL_CACHE_FILE = path.join(
  os.homedir(), 'AppData', 'Roaming', 'EBC-Agent', 'serial.json'
);

// A cached serial is only trusted if it came from a real hardware
// read, not a synthetic fallback — those tiers are tagged below.
function isRealSerialSource(source) {
  return source === 'bios-wmic' || source === 'bios-ps' || source === 'baseboard-ps';
}

function readSerialCache() {
  try {
    if (fs.existsSync(SERIAL_CACHE_FILE)) {
      const raw = JSON.parse(fs.readFileSync(SERIAL_CACHE_FILE, 'utf8'));
      if (raw && raw.serial_number && isGoodSerial(raw.serial_number) &&
          isRealSerialSource(raw.source)) {
        return raw.serial_number;
      }
    }
  } catch (e) { logger.warn(`readSerialCache: ${e.message}`); }
  return null;
}

function writeSerialCache(serial, source) {
  try {
    fs.mkdirSync(path.dirname(SERIAL_CACHE_FILE), { recursive: true });
    fs.writeFileSync(SERIAL_CACHE_FILE, JSON.stringify({
      serial_number: serial,
      source,
      cached_at: new Date().toISOString(),
    }, null, 2));
  } catch (e) { logger.warn(`writeSerialCache: ${e.message}`); }
}

async function getSerialCached() {
  const cached = readSerialCache();
  if (cached) {
    logger.info(`Serial: using cached value ${cached} (stable across syncs)`);
    return cached;
  }
  const { serial, source } = await getSerial();
  if (isRealSerialSource(source)) {
    writeSerialCache(serial, source);
    logger.info(`Serial: first real-hardware detection, cached ${serial} (${source}) for all future syncs`);
  } else {
    logger.warn(`Serial: only a fallback value available this sync (${serial}, source=${source}) — NOT caching, will retry real-serial detection next sync`);
  }
  return serial;
}

// ─────────────────────────────────────────────────────────────
// SELF-HEAL: machines that ran an earlier build of this agent may
// already have a fallback serial (HW-/UUID-/PC-) permanently cached
// to disk from before this fix existed. Call this once at startup —
// if the on-disk cache is a fallback value, delete it so the very
// next collection re-attempts real BIOS detection instead of reusing
// the stale fake serial forever. Safe to call every startup: once a
// real serial is cached under this build (source is properly tagged
// bios-wmic/bios-ps/baseboard-ps), this is a no-op forever after.
//
// NOTE: older agent builds (pre-fix) tagged every cached serial —
// real ones included — as source:"auto-detect", since they made no
// distinction. This function can't tell a legacy REAL serial apart
// from a legacy FAKE one just from that tag, so on a machine's first
// startup after upgrading to this build it purges either kind and
// lets the very next sync re-detect from scratch. For a machine that
// really does have a real BIOS serial, that's a harmless one-time
// re-read that ends up caching the same correct value, now properly
// tagged. For a machine stuck on a fake one, this is exactly the
// repair needed.
// ─────────────────────────────────────────────────────────────
function purgeStaleFallbackSerialCache() {
  try {
    if (!fs.existsSync(SERIAL_CACHE_FILE)) return;
    const raw = JSON.parse(fs.readFileSync(SERIAL_CACHE_FILE, 'utf8'));
    if (raw && raw.serial_number && !isRealSerialSource(raw.source)) {
      fs.unlinkSync(SERIAL_CACHE_FILE);
      logger.warn(`Serial: purged stale fallback cache (was ${raw.serial_number}, source=${raw.source || 'unknown/legacy'}) — will re-attempt real serial detection on next sync`);
    }
  } catch (e) {
    logger.warn(`purgeStaleFallbackSerialCache: ${e.message}`);
  }
}

async function getSerial() {
  const b1 = await wmic('wmic bios get serialnumber /value');
  const m1 = b1.match(/SerialNumber=(.+)/i);
  if (m1 && isGoodSerial(m1[1])) return { serial: m1[1].trim(), source: 'bios-wmic' };

  const b2 = await ps('(Get-WmiObject -Class Win32_BIOS).SerialNumber');
  if (isGoodSerial(b2)) return { serial: b2, source: 'bios-ps' };

  const b3 = await ps('(Get-WmiObject Win32_BaseBoard).SerialNumber');
  if (isGoodSerial(b3)) return { serial: b3, source: 'baseboard-ps' };

  const b4 = await ps('(Get-WmiObject Win32_ComputerSystemProduct).UUID');
  if (b4 && isGoodSerial(b4) &&
      !b4.toLowerCase().includes('ffffffffffff') &&
      !b4.toLowerCase().includes('00000000-0000')) {
    return { serial: `UUID-${b4.trim()}`, source: 'uuid' };
  }

  logger.warn('Serial: no BIOS serial — building hardware fingerprint');
  try {
    const cpuId = await ps('(Get-WmiObject Win32_Processor | Select-Object -First 1).ProcessorId');
    const mac   = await ps(`
try {
  $nic = Get-WmiObject Win32_NetworkAdapter |
    Where-Object { $_.MACAddress -and $_.PhysicalAdapter -eq $true -and
                   $_.MACAddress -notmatch '^00:00' } |
    Sort-Object Index | Select-Object -First 1
  Write-Output $nic.MACAddress
} catch { Write-Output '' }
`);
    const parts = [cpuId, mac].map(s => (s || '').trim().replace(/[^a-zA-Z0-9]/g, '')).filter(Boolean);
    if (parts.length > 0) {
      const hash = require('crypto').createHash('sha1').update(parts.join('')).digest('hex').substring(0, 12).toUpperCase();
      const fp   = `HW-${hash}`;
      logger.warn(`Serial fingerprint: ${fp}`);
      return { serial: fp, source: 'hw-fingerprint' };
    }
  } catch (e) {
    logger.warn(`Serial fingerprint failed: ${e.message}`);
  }

  const hostname = process.env.COMPUTERNAME || os.hostname() || 'PC';
  const fallback = `PC-${hostname.replace(/[^a-zA-Z0-9]/g, '').substring(0, 12).toUpperCase()}`;
  logger.warn(`Serial fallback: ${fallback}`);
  return { serial: fallback, source: 'hostname-fallback' };
}

// ─────────────────────────────────────────────────────────────
// IP, HOSTNAME
// ─────────────────────────────────────────────────────────────
async function getIP() {
  const ifaces   = os.networkInterfaces();
  const priority = ['ethernet', 'eth', 'lan', 'local area connection', 'wi-fi', 'wireless', 'wlan'];
  const all = [];
  for (const [name, list] of Object.entries(ifaces)) {
    for (const i of list) {
      if (i.family === 'IPv4' && !i.internal && i.address !== '127.0.0.1') {
        const score = priority.findIndex(p => name.toLowerCase().includes(p));
        all.push({ ip: i.address, score: score === -1 ? 99 : score });
      }
    }
  }
  all.sort((a, b) => a.score - b.score);
  return all[0]?.ip || '0.0.0.0';
}

async function getHostname() {
  const out = await wmic('wmic computersystem get name /value');
  const m = out.match(/Name=(.+)/i);
  if (m && m[1].trim()) return m[1].trim();
  return process.env.COMPUTERNAME || os.hostname();
}

// ─────────────────────────────────────────────────────────────
// OS INFO
// ─────────────────────────────────────────────────────────────
async function getOSInfo() {
  try {
    const productName = await reg('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName');
    const displayVer  = await reg('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'DisplayVersion');
    const buildNumber = await reg('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'CurrentBuildNumber');
    const editionId   = await reg('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'EditionID');

    const build = parseInt(buildNumber || '0', 10);
    let winVersion = '';

    if (build >= 22000) {
      const edMap = {
        'professional':            'Pro',
        'professionalworkstation': 'Pro for Workstations',
        'enterprise':              'Enterprise',
        'education':               'Education',
        'home':                    'Home',
        'homesinglelanguage':      'Home Single Language',
        'serverstandard':          'Server Standard',
        'serverdatacenter':        'Server Datacenter',
      };
      const edition = editionId ? (edMap[editionId.toLowerCase()] || editionId)
                                : (productName?.replace(/^Microsoft\s+/i, '').replace(/^Windows\s+10\s*/i, '').trim() || 'Pro');
      winVersion = `Windows 11 ${edition}`.trim();
    } else if (productName) {
      winVersion = productName.replace(/^Microsoft /, '').trim();
    }

    if (displayVer && winVersion) winVersion += ` ${displayVer}`;

    let arch = 'x64';
    try {
      const archOut = await ps(`
try {
  $env  = [System.Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE')
  $arch = [System.Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
  if ($arch) { Write-Output $arch } else { Write-Output $env }
} catch { Write-Output 'x64' }
`, 5000);
      if (archOut) {
        const a = archOut.trim().toUpperCase();
        if (a === 'ARM64')      arch = 'ARM64';
        else if (a === 'X86')   arch = 'x86 (32-bit)';
        else if (a === 'AMD64') arch = 'x64';
        else                    arch = archOut.trim();
      }
    } catch { }

    if (winVersion) return { version: winVersion, build: buildNumber || '', arch };
  } catch { }

  return { version: os.version() || 'Windows', build: os.release() || '', arch: process.arch === 'x64' ? 'x64' : process.arch };
}

// ─────────────────────────────────────────────────────────────
// HARDWARE
// ─────────────────────────────────────────────────────────────
async function getHardware() {
  try {
    const model  = await ps('(Get-WmiObject Win32_ComputerSystem).Model');
    const mfr    = await ps('(Get-WmiObject Win32_ComputerSystem).Manufacturer');
    const cpu    = await ps('(Get-WmiObject Win32_Processor | Select-Object -First 1).Name');
    const ramOut = await ps('(Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory');
    const ramGb  = ramOut ? Math.round(parseFloat(ramOut) / (1024 ** 3) * 10) / 10 : 0;
    return { model: model || '', mfr: mfr || '', cpu: cpu || '', ramGb };
  } catch {
    return { model: '', mfr: '', cpu: '', ramGb: 0 };
  }
}

// ─────────────────────────────────────────────────────────────
// USER INFO
// ─────────────────────────────────────────────────────────────
function isDeviceAccount(email) {
  if (!email || !email.includes('@')) return true;
  return email.split('@')[0].endsWith('$');
}

async function getUserInfo() {
  const result = {
    logged:    os.userInfo().username || '',
    localUser: os.userInfo().username || '',
    msEmail:   '',
    email:     '',
    name:      '',
    adUser:    '',
    domain:    '',
  };
  result.localUser = result.logged;

  // STEP 1: whoami /upn — current session only, most trusted
  try {
    const { stdout } = await execAsync('whoami /upn 2>nul', { timeout: 5000 });
    const upn = stdout.trim();
    if (upn && upn.includes('@') && !upn.includes('ERROR') && !upn.includes('\\') && !isDeviceAccount(upn)) {
      result.adUser  = upn;
      result.email   = upn;
      result.msEmail = upn;
      result.name    = upn.split('@')[0];
      result.domain  = upn.split('@')[1] || '';
      logger.info(`UPN (whoami): ${upn}`);
      await _fillOnPremFallback(result);
      logger.info(`FINAL → local=${result.localUser} | msEmail=${result.msEmail} | adUser=${result.adUser}`);
      return result;
    }
  } catch { }

  logger.info('whoami /upn gave nothing — trying Outlook profile');

  const currentUser = result.logged.toLowerCase().replace(/[^a-z0-9._-]/g, '');

  const outlookEmail = await ps(`
try {
  $currentUser = '${currentUser}'
  $found = ''

  $outlookKey = 'HKCU:\\SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Profiles'
  if (Test-Path $outlookKey) {
    Get-ChildItem $outlookKey -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
      if ($found) { return }
      $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
      foreach ($pname in ($props.PSObject.Properties.Name)) {
        $val = $props.$pname
        if ($val -is [string] -and
            $val -match '^[\\w._%+\\-]+@[\\w.\\-]+\\.[A-Za-z]{2,}$' -and
            $val -notmatch '\\$@') {
          $localPart = ($val -split '@')[0].ToLower()
          if ($localPart -like "*$currentUser*" -or $currentUser -like "*$($localPart.Split('.')[0])*") {
            $found = $val.Trim()
            return
          }
        }
      }
    }
  }

  if (-not $found) {
    $officeKey = 'HKCU:\\SOFTWARE\\Microsoft\\Office\\16.0\\Common\\Identity\\Identities'
    if (Test-Path $officeKey) {
      Get-ChildItem $officeKey -ErrorAction SilentlyContinue | ForEach-Object {
        if ($found) { return }
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        foreach ($pname in @('EmailAddress','FriendlyName')) {
          $val = $props.$pname
          if ($val -and $val -match '@' -and $val -notmatch '\\$@') {
            $localPart = ($val -split '@')[0].ToLower()
            if ($localPart -like "*$currentUser*" -or $currentUser -like "*$($localPart.Split('.')[0])*") {
              $found = $val.Trim()
              return
            }
          }
        }
      }
    }
  }

  if ($found) { Write-Output "OUT|$found" } else { Write-Output "" }
} catch { Write-Output "" }
`, 12000);

  if (outlookEmail?.startsWith('OUT|')) {
    const email = outlookEmail.replace('OUT|', '').trim();
    if (email.includes('@') && !isDeviceAccount(email)) {
      result.msEmail = email;
      result.email   = email;
      result.adUser  = email;
      result.name    = email.split('@')[0];
      result.domain  = email.split('@')[1] || '';
      logger.info(`Outlook profile (user-anchored): ${email}`);
    }
  }

  await _fillOnPremFallback(result);

  if (!result.email && result.domain && result.domain !== 'WORKGROUP' &&
      result.domain !== os.hostname() && result.domain.includes('.')) {
    result.email = `${result.logged}@${result.domain.toLowerCase()}`;
  }

  logger.info(`FINAL → local=${result.localUser} | msEmail=${result.msEmail || 'EMPTY'} | adUser=${result.adUser || 'none'} | email=${result.email || 'none'}`);
  return result;
}

async function _fillOnPremFallback(result) {
  try {
    const domainUser = await wmic('wmic computersystem get username /value');
    const dmatch = domainUser.match(/UserName=(.+)/i);
    if (dmatch && dmatch[1].trim() && dmatch[1].includes('\\')) {
      const parts  = dmatch[1].trim().split('\\');
      const domain = parts[0] || '';
      const user   = parts[1] || result.logged;
      if (domain !== 'WORKGROUP' && domain.toUpperCase() !== (os.hostname() || '').toUpperCase()) {
        if (!result.domain) result.domain = domain;
        result.logged = user;
        if (!result.adUser) result.adUser = `${domain}\\${user}`;
        if (!result.name)   result.name   = user;
      }
    }
  } catch { }
}

// ─────────────────────────────────────────────────────────────
// ADMIN INFO
// ─────────────────────────────────────────────────────────────
async function getAdminInfo() {
  const result = { isAdmin: 0, adminUser: '', pcAdminUser: '', isElevated: false };

  const elevated = await ps('([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)', 3000);
  result.isElevated = elevated.toLowerCase() === 'true';
  if (result.isElevated) result.isAdmin = 1;

  const adminAccounts = await ps(`
try {
  $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
    Where-Object { $_.ObjectClass -eq 'User' } |
    Select-Object -ExpandProperty Name
  if ($admins) {
    $names = $admins | ForEach-Object { ($_ -split '\\\\')[-1] }
    Write-Output ($names -join ',')
  }
} catch {
  try {
    $out = net localgroup Administrators 2>$null
    $members = $out | Select-String '^[A-Za-z]' | Where-Object { $_ -notmatch 'Alias|Comment|Members|command|------' }
    Write-Output ($members -join ',')
  } catch {}
}
`, 10000);

  if (adminAccounts) {
    const accounts = adminAccounts.split(',').map(a => a.trim()).filter(Boolean);
    const filtered = accounts.filter(a => !['guest', 'wdagutilityaccount', 'defaultaccount'].includes(a.toLowerCase()));
    if (filtered.length > 0) {
      result.pcAdminUser = filtered.join(', ');
      result.isAdmin = 1;
      logger.info(`Admin accounts: ${result.pcAdminUser}`);
    }
  }

  if (fs.existsSync('C:\\Users\\Administrator')) {
    result.isAdmin = 1;
    if (!result.pcAdminUser) result.pcAdminUser = 'Administrator';
  }

  return result;
}

// ─────────────────────────────────────────────────────────────
// LOCAL USERS AND GROUPS
// ─────────────────────────────────────────────────────────────
async function getLocalUsersAndGroups() {
  const result = { users: [], groups: [] };

  const usersOut = await ps(`
try {
  $users = Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,FullName,Enabled,Description,PrincipalSource
  $users | ForEach-Object {
    Write-Output "$($_.Name)|$($_.FullName)|$($_.Enabled)|$($_.PrincipalSource)"
  }
} catch {
  try {
    $out = net user 2>$null
    $out | Select-String '^\\s*\\S' | Select-Object -Skip 3 | ForEach-Object {
      $names = $_.ToString().Trim() -split '\\s+'
      foreach ($n in $names) { if ($n -and $n -notmatch '^-') { Write-Output "$n||True|Local" } }
    }
  } catch {}
}
`, 15000);

  if (usersOut) {
    for (const line of usersOut.split('\n').filter(l => l.trim())) {
      const parts = line.trim().split('|');
      const name  = (parts[0] || '').trim();
      if (name && name.length > 0 && name !== 'The command' && name !== 'User accounts') {
        result.users.push({
          name,
          fullname: (parts[1] || '').trim(),
          enabled:  (parts[2] || 'True').trim().toLowerCase() !== 'false',
          source:   (parts[3] || 'Local').trim(),
          is_admin: name.toLowerCase() === 'administrator',
        });
      }
    }
  }

  const groupsOut = await ps(`
try {
  $groups = Get-LocalGroup -ErrorAction SilentlyContinue
  foreach ($g in $groups) {
    $members = @()
    try { $members = Get-LocalGroupMember $g.Name -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split '\\\\')[-1] } } catch {}
    Write-Output "$($g.Name)|||$(($members -join ','))"
  }
} catch {}
`, 15000);

  if (groupsOut) {
    for (const line of groupsOut.split('\n').filter(l => l.trim())) {
      const idx = line.indexOf('|||');
      if (idx === -1) continue;
      const gname   = line.substring(0, idx).trim();
      const members = line.substring(idx + 3).split(',').map(m => m.trim()).filter(Boolean);
      if (gname) result.groups.push({ name: gname, members });
    }
  }

  logger.info(`Local users: ${result.users.length} | groups: ${result.groups.length}`);
  return result;
}

// ─────────────────────────────────────────────────────────────
// SOFTWARE DETECTION HELPERS
// ─────────────────────────────────────────────────────────────
function isSAP(name, pub) {
  const n = (name || '').toLowerCase();
  const p = (pub  || '').toLowerCase();
  return (
    n.includes('sap gui') || n.includes('sap business one') ||
    n.includes('sap logon') || n.includes('sap netweaver') || n.includes('sap fiori') ||
    (n.includes('sap') && (p.includes('sap se') || p.includes('sap ag')))
  );
}

function isCrowdStrike(name, pub) {
  const n = (name || '').toLowerCase();
  const p = (pub  || '').toLowerCase();
  return n.includes('crowdstrike') || n.includes('falcon') || p.includes('crowdstrike');
}

// ─────────────────────────────────────────────────────────────
// MICROSOFT OFFICE — FULL SUITE DETECTION
// ─────────────────────────────────────────────────────────────

// Suite-level product names found in Add/Remove Programs.
// These appear ONLY when a suite (not a single standalone app) is installed.
// We explicitly exclude entries that are single-app-only (e.g. "Microsoft Word" alone).
const OFFICE_SUITE_PATTERNS = [
  // Microsoft 365 / Office 365
  /microsoft 365/i,
  /office 365/i,
  // Office 20xx suites — must say "Office" + year, not just the app name
  /microsoft office\s+(home|professional|standard|business|ltsc|pro\b)/i,
  /microsoft office\s+20(10|13|16|19|21|24)/i,
  /office\s+20(10|13|16|19|21|24)\s+(home|professional|standard|business|ltsc|pro\b)/i,
  // Catch "Microsoft Office" with no year as a suite entry
  /^microsoft office$/i,
  /^microsoft office\s+\(.*\)$/i,
];

// Single-app standalone patterns — these are NOT a full suite.
// If ONLY these are found (without a suite-level entry), has_ms_office = false.
const OFFICE_SINGLE_APP_ONLY_PATTERNS = [
  /^microsoft word$/i,
  /^microsoft excel$/i,
  /^microsoft powerpoint$/i,
  /^microsoft outlook$/i,
  /^microsoft onenote$/i,
  /^microsoft access$/i,
  /^microsoft publisher$/i,
  /^microsoft visio$/i,
  /^microsoft project$/i,
];

function isSuiteEntry(name) {
  const n = (name || '').trim();
  return OFFICE_SUITE_PATTERNS.some(p => p.test(n));
}

function isSingleAppOnlyEntry(name) {
  const n = (name || '').trim();
  return OFFICE_SINGLE_APP_ONLY_PATTERNS.some(p => p.test(n));
}

/**
 * Check the installed-apps list from the registry for a SUITE-level Office entry.
 * Returns true only if a suite product is found — not individual standalone apps.
 */
function appsListHasOfficeSuite(apps) {
  for (const a of apps) {
    if (isSuiteEntry(a.name)) {
      logger.info(`Office suite found in app list: "${a.name}" (${a.version || 'no version'})`);
      return true;
    }
  }

  // If no suite entry, check if there are multiple Office apps together.
  // A machine with Word + Excel + PowerPoint all installed = suite.
  const officeApps = apps.filter(a => {
    const n = (a.name || '').toLowerCase();
    const p = (a.publisher || '').toLowerCase();
    return p.includes('microsoft') && (
      n.includes('word') || n.includes('excel') || n.includes('powerpoint') ||
      n.includes('outlook') || n.includes('onenote') || n.includes('access') ||
      n.includes('publisher') || n.includes('office')
    );
  });

  // Count distinct core Office apps
  const hasWord        = officeApps.some(a => a.name.toLowerCase().includes('word'));
  const hasExcel       = officeApps.some(a => a.name.toLowerCase().includes('excel'));
  const hasPowerPoint  = officeApps.some(a => a.name.toLowerCase().includes('powerpoint'));

  if (hasWord && hasExcel && hasPowerPoint) {
    logger.info(`Office suite inferred from app list: Word + Excel + PowerPoint all present`);
    return true;
  }

  return false;
}

/**
 * Deep Office FULL SUITE detection using registry and filesystem.
 * Only returns true if a FULL SUITE is confirmed — not a single standalone app.
 *
 * Layers:
 *   1. ClickToRun — ProductReleaseIds must contain a suite token
 *   2. MSI registry InstallRoot + count of core exe files (requires >= 3)
 *   3. Filesystem scan — count core exe files across all known paths (requires >= 3)
 *   4. Microsoft Store — count distinct Office suite app packages (requires >= 3)
 */
async function detectOfficeSuiteDeep() {
  const psScript = `
$result = 'NOT_FOUND'

# ── 1. Click-to-Run registry ──────────────────────────────────────────────────
# ProductReleaseIds for SUITE installs contains tokens like:
#   O365ProPlusRetail, O365BusinessRetail, Standard2019Volume,
#   ProPlus2021Volume, HomeStudent2021Retail, HomeBusiness2024Retail, etc.
# SINGLE-APP installs contain only: WordRetail, ExcelRetail, etc.
# We require at least ONE suite-level token to confirm a full package.
$c2rKey = 'HKLM:\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration'
if (Test-Path $c2rKey) {
  $ids = (Get-ItemProperty $c2rKey -ErrorAction SilentlyContinue).ProductReleaseIds
  if ($ids) {
    # Suite tokens — any of these means a full package is installed
    $suiteTokens = @(
      'O365ProPlus','O365Business','O365HomePrem','O365SmallBusiness',
      'ProPlus','Standard','HomeBusiness','HomeStudent','Personal',
      'Professional','Academic','Government',
      'ProPlus2019','Standard2019','HomeBusiness2019','HomeStudent2019',
      'ProPlus2021','Standard2021','HomeBusiness2021','HomeStudent2021',
      'ProPlus2024','Standard2024','HomeBusiness2024','HomeStudent2024',
      'ProPlusMSI','StandardMSI'
    )
    $idList = $ids -split ','
    $foundSuiteToken = $false
    foreach ($token in $suiteTokens) {
      if ($idList | Where-Object { $_ -like "*$token*" }) {
        $foundSuiteToken = $true
        break
      }
    }
    if ($foundSuiteToken) {
      $result = "FOUND:C2R suite ($ids)"
    } else {
      # Single-app C2R — check if multiple individual apps are present
      $coreApps = @('Word','Excel','PowerPoint','Outlook','OneNote')
      $count = 0
      foreach ($app in $coreApps) {
        if ($idList | Where-Object { $_ -like "*$app*" }) { $count++ }
      }
      if ($count -ge 3) {
        $result = "FOUND:C2R multi-app ($ids count=$count)"
      }
    }
  }
}

# ── 2. MSI InstallRoot registry + core exe count ──────────────────────────────
if ($result -eq 'NOT_FOUND') {
  $coreExes = @('WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE','OUTLOOK.EXE','ONENOTE.EXE')
  foreach ($v in @('16.0','15.0','14.0','12.0')) {
    $keys = @(
      "HKLM:\\SOFTWARE\\Microsoft\\Office\\$v\\Common\\InstallRoot",
      "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Office\\$v\\Common\\InstallRoot"
    )
    foreach ($key in $keys) {
      if (Test-Path $key) {
        $root = (Get-ItemProperty $key -ErrorAction SilentlyContinue).Path
        if ($root -and (Test-Path $root)) {
          $count = 0
          foreach ($exe in $coreExes) {
            if (Test-Path (Join-Path $root $exe)) { $count++ }
          }
          if ($count -ge 3) {
            $result = "FOUND:MSI Office $v ($count core exes in $root)"
            break
          }
        }
      }
    }
    if ($result -ne 'NOT_FOUND') { break }
  }
}

# ── 3. Filesystem scan — count core Office executables ────────────────────────
if ($result -eq 'NOT_FOUND') {
  $dirs = @(
    'C:\\Program Files\\Microsoft Office\\root\\Office16',
    'C:\\Program Files\\Microsoft Office\\root\\Office15',
    'C:\\Program Files (x86)\\Microsoft Office\\root\\Office16',
    'C:\\Program Files (x86)\\Microsoft Office\\root\\Office15',
    'C:\\Program Files\\Microsoft Office\\Office16',
    'C:\\Program Files\\Microsoft Office\\Office15',
    'C:\\Program Files\\Microsoft Office\\Office14',
    'C:\\Program Files (x86)\\Microsoft Office\\Office16',
    'C:\\Program Files (x86)\\Microsoft Office\\Office15',
    'C:\\Program Files (x86)\\Microsoft Office\\Office14'
  )
  $coreExes = @('WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE','OUTLOOK.EXE','ONENOTE.EXE')
  foreach ($dir in $dirs) {
    if (Test-Path $dir) {
      $count = 0
      foreach ($exe in $coreExes) {
        if (Test-Path (Join-Path $dir $exe)) { $count++ }
      }
      if ($count -ge 3) {
        $result = "FOUND:Filesystem $dir ($count core exes)"
        break
      }
    }
  }
}

# ── 4. Microsoft Store / UWP Office packages ──────────────────────────────────
# Only count as a suite if Word + Excel + PowerPoint are all present as Store apps.
# A single Store app (e.g. just OneNote) is NOT a full suite.
if ($result -eq 'NOT_FOUND') {
  try {
    $storeApps = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {
      $_.Name -match 'Microsoft\\.(MicrosoftWord|MicrosoftExcel|MicrosoftPowerPoint|Office\\.)'
    }
    $storeNames = $storeApps | ForEach-Object { $_.Name }
    $hasWord  = $storeNames | Where-Object { $_ -match 'Word' }
    $hasExcel = $storeNames | Where-Object { $_ -match 'Excel' }
    $hasPPT   = $storeNames | Where-Object { $_ -match 'PowerPoint' }
    if ($hasWord -and $hasExcel -and $hasPPT) {
      $result = "FOUND:Store Word+Excel+PowerPoint"
    }
  } catch {}
}

Write-Output $result
`;

  try {
    const out = (await ps(psScript, 30000)).trim();
    if (out.startsWith('FOUND:')) {
      logger.info(`Office deep suite check: ${out}`);
      return true;
    }
    logger.info(`Office deep suite check: ${out} (not a full suite)`);
  } catch (e) {
    logger.warn(`Office deep suite check error: ${e.message}`);
  }
  return false;
}

// ─────────────────────────────────────────────────────────────
// INSTALLED APPS
// ─────────────────────────────────────────────────────────────
const MS_KEYS = [
  'microsoft', 'ms office', 'office 365', 'office 2', 'word', 'excel', 'powerpoint',
  'outlook', 'onenote', 'teams', 'visio', 'project', 'access', 'publisher', 'skype',
  'onedrive', 'sharepoint', 'edge', 'windows defender', 'sql server', 'visual studio',
  'power bi', '.net framework', 'vc redist', 'c++ redist', 'silverlight', 'xbox',
];
const ADOBE_KEYS = [
  'adobe', 'acrobat', 'illustrator', 'indesign', 'premiere', 'after effects', 'audition',
  'dreamweaver', 'reader', 'creative cloud', 'lightroom', 'xd', 'animate', 'bridge',
  'substance', 'fresco', 'dimension',
];
const PHOTOSHOP_KEYS = ['photoshop'];
const AUTOCAD_KEYS   = [
  'autocad', 'autodesk', 'navisworks', 'revit', '3ds max', 'maya', 'civil 3d',
  'inventor', 'infraworks', 'fusion 360', 'robot structural',
];

function classifyApp(name, pub) {
  const n = (name || '').toLowerCase();
  const p = (pub  || '').toLowerCase();
  if (PHOTOSHOP_KEYS.some(k => n.includes(k))) return 'photoshop';
  if (AUTOCAD_KEYS.some(k => n.includes(k)) || p.includes('autodesk')) return 'autocad';
  if (MS_KEYS.some(k => n.includes(k)) || p.includes('microsoft')) return 'microsoft';
  if (ADOBE_KEYS.some(k => n.includes(k)) || p.includes('adobe')) return 'adobe';
  return 'other';
}

async function getInstalledApps() {
  const apps    = [];
  const seen    = new Set();
  const outFile = path.join(os.tmpdir(), `ebc_apps_${Date.now()}.json`);

  const psScript = `
$hives = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
)
$apps = Get-ItemProperty -Path $hives -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' } |
  Select-Object @{N='n';E={$_.DisplayName.Trim()}},
                @{N='v';E={if($_.DisplayVersion){$_.DisplayVersion.Trim()}else{''}}},
                @{N='p';E={if($_.Publisher){$_.Publisher.Trim()}else{''}}}
$apps | ConvertTo-Json -Compress -Depth 2 | Out-File -FilePath '${outFile.replace(/\\/g, '\\\\')}' -Encoding UTF8
`;

  await ps(psScript, 90000);

  if (fs.existsSync(outFile)) {
    try {
      const raw = fs.readFileSync(outFile, 'utf8').trim().replace(/^\uFEFF/, '');
      if (raw) {
        const arr = JSON.parse(raw);
        for (const item of (Array.isArray(arr) ? arr : [arr])) {
          const name = (item.n || '').trim();
          if (!name || seen.has(name.toLowerCase())) continue;
          seen.add(name.toLowerCase());
          const pub  = (item.p || '').trim();
          const type = classifyApp(name, pub);
          apps.push({ name, version: (item.v || '').trim(), publisher: pub, app_type: type });
        }
      }
    } catch (e) {
      logger.warn(`App parse: ${e.message}`);
    } finally {
      try { fs.unlinkSync(outFile); } catch { }
    }
  }

  if (apps.length === 0) {
    const wmicOut = await wmic('wmic product get name,version,vendor /format:csv', 120000);
    for (const line of wmicOut.split('\n').slice(2)) {
      const parts = line.split(',');
      if (parts.length < 3) continue;
      const name = (parts[2] || parts[1] || '').trim();
      const ver  = (parts[3] || '').trim();
      const pub  = (parts[1] || '').trim();
      if (!name || seen.has(name.toLowerCase())) continue;
      seen.add(name.toLowerCase());
      apps.push({ name, version: ver, publisher: pub, app_type: classifyApp(name, pub) });
    }
  }

  logger.info(`Apps collected: ${apps.length}`);
  return apps.sort((a, b) => a.name.localeCompare(b.name));
}

// ─────────────────────────────────────────────────────────────
// WINDOWS UPDATES
// ─────────────────────────────────────────────────────────────
//
// FIX (v4.2.7 — silent multi-minute freeze traced to this function):
// Logs showed the agent stop dead right before "Windows Updates: N
// pending" ever printed — no timeout error, no next scheduled sync,
// nothing. Two compounding bugs were found here:
//
//  1. ps() retries a failed call with the SAME long timeout on
//     failure — so a genuine COM hang didn't fail after `timeoutMs`,
//     it failed after roughly 2x that (plus two 3s hard-kill grace
//     periods) before even reaching the outer 5-minute collect()
//     deadline in main.js. That outer deadline exists specifically
//     to catch this and unstick future syncs, but on the affected
//     machine even it never fired — meaning the Node event loop
//     itself stalled, not just this one await. That points at
//     wuauserv (Windows Update service) being wedged at the OS
//     level: a COM/RPC call into a truly deadlocked service isn't
//     reliably bounded by killing the PowerShell client process,
//     and stacking two such attempts back-to-back materially raises
//     the odds of hitting that state.
//
//  2. Zero log visibility between "Apps collected" and "Windows
//     Updates: N pending" — a hang here was indistinguishable from
//     a hang anywhere else in collect() from the log alone.
//
// Fix: (a) pre-flight check wuauserv's service state before ever
// touching the COM API — skip the search entirely this cycle if the
// service isn't in a normal Running/Stopped state, rather than
// gamble on a COM call into a service we already know is unhealthy;
// (b) call ps() with retryOnFail:false here — one attempt only, no
// doubled timeout; (c) explicit start/skip/timeout log lines so a
// future hang is immediately visible and locatable from the log
// instead of a silent gap.
async function getWindowsUpdates() {
  const result = { list: [], count: 0 };

  logger.info('Windows Updates: checking wuauserv service state...');
  let serviceHealthy = true;
  try {
    const svc = await execWithHardKill(
      'powershell.exe -NoProfile -NonInteractive -Command "(Get-Service -Name wuauserv).Status"',
      8000
    );
    const status = (svc.stdout || '').trim();
    if (svc.error || !status) {
      logger.warn(`Windows Updates: could not read wuauserv status (${svc.error ? svc.error.message : 'empty result'}) — skipping WU check this cycle`);
      serviceHealthy = false;
    } else if (status !== 'Running' && status !== 'Stopped') {
      logger.warn(`Windows Updates: wuauserv in unexpected state "${status}" — skipping COM search this cycle to avoid a hang`);
      serviceHealthy = false;
    } else {
      logger.info(`Windows Updates: wuauserv status OK (${status}) — proceeding with search`);
    }
  } catch (e) {
    logger.warn(`Windows Updates: service check threw (${e.message}) — skipping WU check this cycle`);
    serviceHealthy = false;
  }

  if (!serviceHealthy) {
    result.count = 0;
    logger.info('Windows Updates: 0 pending (skipped — service unhealthy, will retry next cycle)');
    return result;
  }

  logger.info('Windows Updates: starting COM search (single attempt, 45s cap)...');
  const psOut = await ps(`
try {
  $updateSession  = New-Object -ComObject Microsoft.Update.Session
  $updateSearcher = $updateSession.CreateUpdateSearcher()
  $searchResult   = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
  $updates = @()
  foreach ($update in $searchResult.Updates) {
    $kb = ''
    foreach ($id in $update.KBArticleIDs) { $kb = "KB$id"; break }
    $updates += [PSCustomObject]@{
      title        = $update.Title
      kb           = $kb
      severity     = if($update.MsrcSeverity){$update.MsrcSeverity}else{''}
      size_mb      = [math]::Round($update.MaxDownloadSize / 1MB, 1)
      category     = if($update.Categories.Count -gt 0){$update.Categories.Item(0).Name}else{''}
      is_important = ($update.AutoSelectOnWebSites -eq $true -or $update.MsrcSeverity -match 'Critical|Important')
    }
  }
  $updates | ConvertTo-Json -Compress -Depth 2
} catch {
  Write-Output "[]"
}
`, 45000, { retryOnFail: false });
  logger.info('Windows Updates: COM search finished (or timed out and was killed)');

  if (psOut && psOut.trim() !== '[]') {
    try {
      const raw = psOut.replace(/^\uFEFF/, '').trim();
      if (raw && raw !== '[]') {
        const arr = JSON.parse(raw);
        for (const u of (Array.isArray(arr) ? arr : [arr])) {
          const title = (u.title || u.Title || '').trim();
          if (!title) continue;
          const rawCat = (u.category || u.Category || '').trim();
          const rawSev = (u.severity || u.Severity || '').trim();
          result.list.push({
            title,
            kb:           (u.kb || u.KB || '').trim(),
            severity:     rawSev,
            size_mb:      parseFloat(u.size_mb || 0) || 0,
            // FIX v4.1.9: normalise category to friendly name (no "Critical Updates" etc.)
            category:     normaliseUpdateCategory(rawCat, rawSev, title),
            is_important: !!(u.is_important || u.IsImportant),
          });
        }
        result.count = result.list.length;
      }
    } catch (e) {
      logger.warn(`WU parse: ${e.message}`);
    }
  }

  if (result.count === 0) {
    try {
      const r = await execAsync(
        'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired" 2>nul',
        { timeout: 5000 }
      );
      if (r.stdout && !r.stdout.includes('ERROR')) {
        result.count = 1;
        result.list.push({ title: 'Pending updates (reboot required)', kb: '', severity: '', size_mb: 0, category: 'Windows Update', is_important: true });
      }
    } catch { }
  }

  logger.info(`Windows Updates: ${result.count} pending`);
  return result;
}

// ─────────────────────────────────────────────────────────────
// DOWNLOADS FOLDER .EXE SCAN
// ─────────────────────────────────────────────────────────────
// Scans the user's Downloads folder(s) for .exe files, recursively,
// and reports the list with the regular sync payload.
//
// DOMAIN ACCOUNT & SYSTEM SUPPORT:
// 1. When running as SYSTEM (Scheduled Task / CrowdStrike deployment),
//    os.homedir() points to C:\Windows\system32\config\systemprofile,
//    which has no user downloads. We resolve the actual logged-in
//    user's profile via registry ProfileList (S-1-5-21-*) and HKU
//    mounted hives.
// 2. On domain accounts, user profiles in C:\Users are often named
//    username or username.DOMAIN, and Group Policy / OneDrive KFM
//    frequently redirects Downloads. We query the authoritative
//    User Shell Folders GUID ({374DE290-123F-4565-9164-39C4925E467B})
//    and check OneDrive subfolders.
// 3. Fallback to scanning all interactive user profiles in C:\Users.
// 4. File-path de-duplication, capped depth, max file count, and wall-clock
//    budget ensure fast, non-blocking execution.
const EXE_SCAN_MAX_FILES = 2000;
const EXE_SCAN_MAX_DEPTH = 6;
const EXE_SCAN_TIME_BUDGET_MS = 15000;

async function getDownloadsFolders(userInfo = null) {
  const folders = [];
  const seen = new Set();

  function addFolder(folderPath) {
    if (!folderPath || typeof folderPath !== 'string') return;
    try {
      // Expand %USERPROFILE%, %SystemDrive%, etc.
      let expanded = folderPath.replace(/%([^%]+)%/g, (_, n) => process.env[n] || `%${n}%`);
      const resolved = path.resolve(expanded).trim();
      const norm = resolved.toLowerCase();
      if (!seen.has(norm) && fs.existsSync(resolved)) {
        try {
          if (fs.statSync(resolved).isDirectory()) {
            seen.add(norm);
            folders.push(resolved);
          }
        } catch (_) {}
      }
    } catch (_) {}
  }

  // 1. Check HKCU User Shell Folders (active interactive user registry)
  try {
    const hkcuKey = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders';
    const guid1 = await reg(hkcuKey, '{374DE290-123F-4565-9164-39C4925E467B}'); // Downloads Known Folder GUID
    const guid2 = await reg(hkcuKey, '{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}');
    if (guid1) addFolder(guid1);
    if (guid2) addFolder(guid2);
  } catch (_) {}

  // 2. Check current process user profile (if not a system/service account)
  const home = os.homedir();
  const up = process.env.USERPROFILE || home;
  const isService = (up || '').toLowerCase().includes('systemprofile') ||
                    (up || '').toLowerCase().includes('serviceprofiles') ||
                    (home || '').toLowerCase().includes('systemprofile');
  if (!isService) {
    addFolder(path.join(up, 'Downloads'));
    if (home && home !== up) addFolder(path.join(home, 'Downloads'));
    // Check OneDrive subfolders in current profile
    try {
      if (fs.existsSync(up)) {
        const sub = fs.readdirSync(up, { withFileTypes: true });
        for (const s of sub) {
          if (s.isDirectory() && s.name.toLowerCase().startsWith('onedrive')) {
            addFolder(path.join(up, s.name, 'Downloads'));
          }
        }
      }
    } catch (_) {}
  }

  // 3. Check HKLM ProfileList & HKEY_USERS (critical when running as SYSTEM or on domain accounts)
  try {
    const { stdout: plistOut } = await execAsync(
      'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList" 2>nul',
      { timeout: 5000, windowsHide: true }
    );
    const sids = (plistOut || '').split(/\r?\n/)
      .map(line => line.trim().split('\\').pop())
      .filter(sid => sid && sid.startsWith('S-1-5-21-'));

    for (const sid of sids) {
      try {
        const pPath = await reg(`HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\${sid}`, 'ProfileImagePath');
        if (pPath && !pPath.toLowerCase().includes('systemprofile')) {
          addFolder(path.join(pPath, 'Downloads'));

          // Check OneDrive folders inside this profile
          try {
            if (fs.existsSync(pPath)) {
              const sub = fs.readdirSync(pPath, { withFileTypes: true });
              for (const s of sub) {
                if (s.isDirectory() && s.name.toLowerCase().startsWith('onedrive')) {
                  addFolder(path.join(pPath, s.name, 'Downloads'));
                }
              }
            }
          } catch (_) {}

          // If this user is currently loaded, check their mounted HKU hive for redirected Downloads GUID
          try {
            const hkuKey = `HKU\\${sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders`;
            const hkuDl = await reg(hkuKey, '{374DE290-123F-4565-9164-39C4925E467B}');
            if (hkuDl) {
              const expanded = hkuDl.replace(/%USERPROFILE%/gi, pPath);
              addFolder(expanded);
            }
          } catch (_) {}
        }
      } catch (_) {}
    }
  } catch (_) {}

  // 4. Target User Profile Matching (from userInfo)
  if (userInfo) {
    const targetNames = new Set();
    for (const k of ['logged', 'localUser', 'adUser', 'name']) {
      const val = (userInfo[k] || '').trim();
      if (val) {
        const clean = val.replace(/^[^\\]+\\/, '').replace(/@.*$/, '').toLowerCase();
        if (clean && !['system', 'localservice', 'networkservice'].includes(clean)) {
          targetNames.add(clean);
        }
      }
    }

    if (fs.existsSync('C:\\Users')) {
      try {
        const entries = fs.readdirSync('C:\\Users', { withFileTypes: true });
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          const nameLower = entry.name.toLowerCase();
          for (const target of targetNames) {
            if (nameLower === target || nameLower.startsWith(target + '.')) {
              const uDir = path.join('C:\\Users', entry.name);
              addFolder(path.join(uDir, 'Downloads'));
              try {
                const sub = fs.readdirSync(uDir, { withFileTypes: true });
                for (const s of sub) {
                  if (s.isDirectory() && s.name.toLowerCase().startsWith('onedrive')) {
                    addFolder(path.join(uDir, s.name, 'Downloads'));
                  }
                }
              } catch (_) {}
            }
          }
        }
      } catch (_) {}
    }
  }

  // 5. General C:\Users filesystem scan fallback
  try {
    const usersRoot = 'C:\\Users';
    if (fs.existsSync(usersRoot)) {
      const skip = new Set(['all users', 'default', 'default user', 'public', 'desktop.ini', 'systemprofile', 'localservice', 'networkservice', 'wdigest']);
      const entries = fs.readdirSync(usersRoot, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const nameLower = entry.name.toLowerCase();
        if (skip.has(nameLower)) continue;

        const userDir = path.join(usersRoot, entry.name);
        addFolder(path.join(userDir, 'Downloads'));

        try {
          const sub = fs.readdirSync(userDir, { withFileTypes: true });
          for (const s of sub) {
            if (s.isDirectory() && s.name.toLowerCase().startsWith('onedrive')) {
              addFolder(path.join(userDir, s.name, 'Downloads'));
            }
          }
        } catch (_) {}
      }
    }
  } catch (_) {}

  return folders;
}

function getDownloadsFolder() {
  return path.join(os.homedir(), 'Downloads');
}

async function scanExeFiles(userInfo = null) {
  const downloadFolders = await getDownloadsFolders(userInfo);
  const folderDisplay = downloadFolders.join('; ') || path.join(os.homedir(), 'Downloads');
  const result = {
    folder: folderDisplay,
    folders: downloadFolders,
    count: 0,
    files: [],
    truncated: false,
    scanned: false,
    error: null
  };

  if (downloadFolders.length === 0) {
    logger.info('EXE scan: no user Downloads folder found — skipping');
    return result;
  }

  logger.info(`EXE scan: scanning ${downloadFolders.length} Downloads folder(s): ${folderDisplay}`);
  const startedAt = Date.now();
  const seenFiles = new Set();

  try {
    for (const downloadsDir of downloadFolders) {
      if (Date.now() - startedAt > EXE_SCAN_TIME_BUDGET_MS || result.files.length >= EXE_SCAN_MAX_FILES) {
        result.truncated = true;
        break;
      }

      const stack = [{ dir: downloadsDir, depth: 0 }];

      while (stack.length > 0) {
        if (Date.now() - startedAt > EXE_SCAN_TIME_BUDGET_MS) {
          logger.warn(`EXE scan: time budget (${EXE_SCAN_TIME_BUDGET_MS}ms) exceeded — returning partial results`);
          result.truncated = true;
          break;
        }
        if (result.files.length >= EXE_SCAN_MAX_FILES) {
          result.truncated = true;
          break;
        }

        const { dir, depth } = stack.pop();
        let entries;
        try {
          entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch (e) {
          continue; // skip permission errors on individual subfolders
        }

        for (const entry of entries) {
          if (result.files.length >= EXE_SCAN_MAX_FILES) { result.truncated = true; break; }
          const fullPath = path.join(dir, entry.name);
          const pathLower = fullPath.toLowerCase();

          if (entry.isDirectory()) {
            if (depth < EXE_SCAN_MAX_DEPTH) stack.push({ dir: fullPath, depth: depth + 1 });
          } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.exe')) {
            if (seenFiles.has(pathLower)) continue;
            seenFiles.add(pathLower);

            let size = 0, mtime = null;
            try {
              const st = fs.statSync(fullPath);
              size = st.size;
              mtime = st.mtime.toISOString();
            } catch (e) { /* best effort */ }

            result.files.push({ name: entry.name, path: fullPath, size_bytes: size, modified: mtime });
          }
        }
      }
    }

    result.scanned = true;
    result.count = result.files.length;
    logger.info(`EXE scan: found ${result.count} .exe file(s) across ${downloadFolders.length} Downloads folder(s)${result.truncated ? ' (truncated)' : ''}`);
  } catch (e) {
    result.error = e.message;
    logger.warn(`EXE scan failed: ${e.message}`);
  }

  return result;
}

module.exports = {
  collect,
  readSerialCache,
  writeSerialCache,
  purgeStaleFallbackSerialCache,
  SERIAL_CACHE_FILE,
  scanExeFiles,
  getDownloadsFolder,
  getDownloadsFolders,
};
