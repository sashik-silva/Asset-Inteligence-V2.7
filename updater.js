/**
 * EBC Agent Auto-Updater v4.1.7
 *
 * BUGS FIXED:
 *
 *  FIX 1: EPERM when writing installer — two root causes addressed:
 *
 *    1a. When the agent runs as SYSTEM (Task Scheduler), os.tmpdir()
 *        returns the USER temp folder which SYSTEM cannot write to.
 *        Now tries multiple locations in order of reliability:
 *          1. C:\Windows\Temp           (always writable by SYSTEM)
 *          2. C:\EBC-Agent\downloads    (our own install folder)
 *          3. %PROGRAMDATA%\EBC-Agent   (C:\ProgramData\EBC-Agent)
 *          4. Alongside the .exe        (process.execPath directory)
 *          5. os.tmpdir()               (last resort)
 *
 *    1b. The installer file from a PREVIOUS update attempt may still
 *        exist and be LOCKED by Windows/AV (even in C:\Windows\Temp).
 *        fs.unlinkSync() silently fails on a locked file, then
 *        createWriteStream() on that same locked path throws EPERM.
 *        Fix: use a unique filename per download attempt (timestamp
 *        suffix) so we never try to overwrite a locked file.
 *        Old temp files are cleaned up after a successful install.
 *
 *  FIX 2: shell:true on installer spawn was causing "operation not
 *       permitted" on some locked-down systems. Using shell:false with a
 *       quoted path is more reliable for silent NSIS installs.
 *
 *  FIX 3: "unable to verify the first certificate" when downloading from
 *       PHP fallback URL (https://darleybutler.lk/assetAgent).
 *       When PHP_SSL_IGNORE=true in .env, HTTPS requests to phpUrl use an
 *       https.Agent with rejectUnauthorized:false so the update download
 *       does not abort on self-signed / chain-incomplete certificates.
 *       This only applies to the PHP URL — the primary Node.js server uses
 *       plain HTTP and is unaffected.
 */

const axios  = require('axios');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');
const https  = require('https');

// ─────────────────────────────────────────────────────────────────────────────
// SSL bypass agent — used ONLY when PHP_SSL_IGNORE=true in .env
// ─────────────────────────────────────────────────────────────────────────────
const INSECURE_AGENT = new https.Agent({ rejectUnauthorized: false });

function axiosOptionsFor(url) {
  const ignore = (process.env.PHP_SSL_IGNORE || '').toLowerCase() === 'true';
  if (ignore && /^https:\/\//i.test(url)) {
    return { httpsAgent: INSECURE_AGENT };
  }
  return {};
}

// ─────────────────────────────────────────────────────────────────────────────
// Find a writable path for the installer — unique filename per attempt.
//
// WHY UNIQUE FILENAME:
//   A previous update attempt may have left EBC-Agent-X.Y.Z-Setup.exe on
//   disk. Windows/AV can lock that file even days later. fs.unlinkSync()
//   silently fails on a locked file, then createWriteStream() on the SAME
//   path throws EPERM. Using a timestamp suffix guarantees a fresh filename
//   that cannot be locked by a previous run.
//
// DIRECTORY SEARCH ORDER (most reliable first for SYSTEM account):
//   1. C:\Windows\Temp           — always writable by SYSTEM
//   2. C:\EBC-Agent\downloads    — our own install folder
//   3. %PROGRAMDATA%\EBC-Agent   — C:\ProgramData\EBC-Agent
//   4. Alongside the .exe        — process.execPath directory
//   5. os.tmpdir()               — last resort (fails as SYSTEM)
// ─────────────────────────────────────────────────────────────────────────────
function getWritableInstallerPath(version) {
  const stamp    = Date.now();
  const filename = `EBC-Agent-${version}-Setup-${stamp}.exe`;

  const dirCandidates = [
    'C:\\Windows\\Temp',
    'C:\\EBC-Agent\\downloads',
    path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'EBC-Agent'),
    process.execPath ? path.dirname(process.execPath) : null,
    os.tmpdir(),
  ].filter(Boolean);

  for (const dir of dirCandidates) {
    try {
      fs.mkdirSync(dir, { recursive: true });
      const testPath = path.join(dir, filename);
      // Probe by actually opening for writing — not just a tiny .txt file
      const fd = fs.openSync(testPath, 'w');
      fs.closeSync(fd);
      fs.unlinkSync(testPath);
      return path.join(dir, filename);
    } catch (e) {
      // Not writable — try next candidate
    }
  }
  // Absolute fallback
  return path.join(os.tmpdir(), filename);
}

// Clean up old EBC-Agent installer temp files left by previous attempts.
// Called after the installer is launched — best-effort, never throws.
function cleanOldInstallers(launchedPath, version) {
  try {
    const dir = path.dirname(launchedPath);
    const launched = path.basename(launchedPath);
    for (const f of fs.readdirSync(dir)) {
      // Match timestamped files for this version: EBC-Agent-4.1.7-Setup-<ts>.exe
      if (f.startsWith(`EBC-Agent-${version}-Setup-`) && f.endsWith('.exe') && f !== launched) {
        try { fs.unlinkSync(path.join(dir, f)); } catch {}
      }
    }
    // Try to remove the launched file itself after 30s (once NSIS has read it)
    setTimeout(() => { try { fs.unlinkSync(launchedPath); } catch {} }, 30000);
  } catch {}
}

// ─────────────────────────────────────────────────────────────────────────────
// INTERNAL: hit one URL and return update record or null
// ─────────────────────────────────────────────────────────────────────────────
async function _fetchLatest(baseUrl, apiKey, currentVersion, logger) {
  try {
    const res = await axios.get(`${baseUrl}/api/updates/latest`, {
      headers: { 'x-api-key': apiKey },
      timeout: 12000,
      ...axiosOptionsFor(baseUrl),
    });
    const update = res.data;
    if (!update || !update.version) return { update: null, reachable: true };
    if (isNewerVersion(update.version, currentVersion)) {
      logger.info(`Auto-update: v${update.version} available via ${baseUrl}`);
      return { update, reachable: true };
    }
    logger.info(`Auto-update: up to date (v${currentVersion}) — server has v${update.version}`);
    return { update: null, reachable: true };
  } catch (e) {
    const ignoredCodes = ['ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'ECONNRESET'];
    if (!ignoredCodes.includes(e.code)) {
      logger.warn(`Auto-update check failed at ${baseUrl}: ${e.message}`);
    }
    // FIX (v4.2.7): report unreachable vs "reached, nothing to do" so
    // the caller can tell a genuine outage apart from a normal
    // up-to-date response — see checkForUpdate below.
    return { update: null, reachable: false };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC: checkForUpdate
// ─────────────────────────────────────────────────────────────────────────────
// FIX (v4.2.7 — permanent 404 spam every 4h on every machine): this
// used to fall through to phpUrl any time the Node check returned
// null, which conflated "no update needed" with "request failed" —
// so a perfectly healthy "up to date" response STILL triggered a
// second request to phpUrl's /api/updates/latest, which 404s because
// that endpoint was never implemented on the PHP side. phpUrl is now
// only tried when the Node server was actually unreachable, i.e. a
// genuine fallback rather than a guaranteed extra request every cycle.
async function checkForUpdate(serverUrl, apiKey, currentVersion, logger, phpUrl) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const nodeResult = await _fetchLatest(serverUrl, apiKey, currentVersion, logger);
    if (nodeResult.update) return nodeResult.update;

    if (!nodeResult.reachable && phpUrl) {
      const phpResult = await _fetchLatest(phpUrl, apiKey, currentVersion, logger);
      if (phpResult.update) return phpResult.update;
    }

    if (nodeResult.reachable) break; // got a real answer ("up to date") — no need to retry
    if (attempt < 3) await new Promise(r => setTimeout(r, 5000));
  }
  logger.info(`Auto-update: no update found (v${currentVersion} is current)`);
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// INTERNAL: resolve relative download_url to absolute
// ─────────────────────────────────────────────────────────────────────────────
function resolveDownloadUrl(downloadUrl, serverUrl, phpUrl) {
  if (!downloadUrl) return null;
  if (/^https?:\/\//i.test(downloadUrl)) return downloadUrl;
  const base = phpUrl || serverUrl;
  return base.replace(/\/$/, '') + (downloadUrl.startsWith('/') ? '' : '/') + downloadUrl;
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC: performUpdate
//   Full pipeline: check → download → verify → silent install
// ─────────────────────────────────────────────────────────────────────────────
async function performUpdate(serverUrl, apiKey, currentVersion, logger, phpUrl) {
  try {
    const update = await checkForUpdate(serverUrl, apiKey, currentVersion, logger, phpUrl);
    if (!update) {
      logger.info('Auto-update: nothing to do.');
      return { status: 'no_update_available', message: 'Already on latest version or no active update published' };
    }

    const rawUrl = update.download_url;
    const downloadUrl = resolveDownloadUrl(rawUrl, serverUrl, phpUrl);

    if (!downloadUrl) {
      logger.warn('Auto-update: update record has no download_url — skipping');
      return { status: 'failed', message: 'Update record has no download_url' };
    }

    logger.info(`Auto-update: downloading v${update.version} from ${downloadUrl}`);

    // ── Get a writable path with a unique filename ────────────────────────────
    // FIX 1b: Use a timestamped filename so we never collide with a locked file
    // left by a previous update attempt (AV/Windows can lock .exe files for
    // hours even after the process exits).
    const tmpPath = getWritableInstallerPath(update.version);
    logger.info(`Auto-update: will write installer to ${tmpPath}`);

    // ── Download with progress logging ────────────────────────────────────────
    let writer;
    try {
      writer = fs.createWriteStream(tmpPath);
    } catch (e) {
      logger.error(`Auto-update: cannot create write stream at ${tmpPath}: ${e.message}`);
      return { status: 'failed', message: `Cannot create write stream: ${e.message}` };
    }

    // FIX 3: Use SSL-bypass agent for HTTPS PHP URL when PHP_SSL_IGNORE=true
    const response = await axios.get(downloadUrl, {
      responseType: 'stream',
      timeout: 600000,
      headers: { 'x-api-key': apiKey },
      maxRedirects: 5,
      ...axiosOptionsFor(downloadUrl),
    });

    const totalBytes = parseInt(response.headers['content-length'] || '0', 10);
    let received = 0;
    let lastLogPct = 0;

    response.data.on('data', chunk => {
      received += chunk.length;
      if (totalBytes > 0) {
        const pct = Math.floor((received / totalBytes) * 100);
        if (pct >= lastLogPct + 20) {
          logger.info(`Auto-update: download ${pct}% (${Math.round(received/1024)}KB / ${Math.round(totalBytes/1024)}KB)`);
          lastLogPct = pct;
        }
      }
    });

    await new Promise((resolve, reject) => {
      response.data.pipe(writer);
      writer.on('finish', resolve);
      writer.on('error', reject);
      response.data.on('error', reject);
    });

    const downloadedSize = fs.statSync(tmpPath).size;
    logger.info(`Auto-update: download complete — ${Math.round(downloadedSize / 1024)}KB saved to ${tmpPath}`);

    // ── File size check ───────────────────────────────────────────────────────
    if (update.file_size && update.file_size > 0) {
      if (Math.abs(downloadedSize - update.file_size) > 4096) {
        logger.error(`Auto-update: size mismatch (expected ${update.file_size}, got ${downloadedSize}) — aborting`);
        try { fs.unlinkSync(tmpPath); } catch {}
        return { status: 'failed', message: `Downloaded file size mismatch (expected ${update.file_size}, got ${downloadedSize})` };
      }
    }

    // ── SHA-256 checksum verification ─────────────────────────────────────────
    if (update.checksum && update.checksum.length === 64) {
      logger.info('Auto-update: verifying SHA-256 checksum...');
      const fileBuffer = fs.readFileSync(tmpPath);
      const actual = crypto.createHash('sha256').update(fileBuffer).digest('hex');
      if (actual.toLowerCase() !== update.checksum.toLowerCase()) {
        logger.error(`Auto-update: CHECKSUM MISMATCH — expected ${update.checksum}, got ${actual} — aborting`);
        try { fs.unlinkSync(tmpPath); } catch {}
        return { status: 'failed', message: `Checksum mismatch — downloaded file did not match expected hash` };
      }
      logger.info('Auto-update: checksum verified ✓');
    } else {
      logger.warn('Auto-update: no checksum in update record — proceeding without verification');
    }

    // ── Silent install via NSIS ───────────────────────────────────────────────
    logger.info(`Auto-update: launching NSIS silent installer: ${tmpPath}`);

    // FIX: signal the watchdog to stand down BEFORE launching the
    // installer. Without this, the installer's taskkill on the old
    // "EBC Asset Agent.exe" would be spotted by the watchdog as an
    // unauthorised kill within ~2s, and it would relaunch the OLD exe
    // right as NSIS is trying to overwrite/replace that same file —
    // producing a file-in-use install failure. The installer itself
    // also stops + re-registers the watchdog once the new files are in
    // place (see installer.nsh customInstall), so this is only needed
    // to cover the short window between now and when NSIS runs.
    try {
      const stopFlag = path.join(os.homedir(), 'AppData', 'Roaming', 'EBC-Agent', 'intentional-stop.flag');
      fs.mkdirSync(path.dirname(stopFlag), { recursive: true });
      fs.writeFileSync(stopFlag, new Date().toISOString());
      logger.info('Auto-update: watchdog signalled to stand down for the update');
    } catch (e) { logger.warn(`Auto-update: could not write stop flag: ${e.message}`); }

    const { spawn } = require('child_process');

    // FIX 2: shell:false + absolute path. shell:true caused EPERM on locked-down systems.
    const installer = spawn(tmpPath, ['/S'], {
      detached:    true,
      stdio:       'ignore',
      windowsHide: true,
      shell:       false,
    });
    installer.unref();

    // Clean up old timestamped installer copies — best effort
    cleanOldInstallers(tmpPath, update.version);

    logger.info('Auto-update: installer launched — exiting in 4s so NSIS can replace the exe...');

    setTimeout(() => {
      logger.info('Auto-update: exiting now for installer to replace executable.');
      try { require('electron').app.exit(0); } catch { process.exit(0); }
    }, 4000);

    return { status: 'installing', message: `Installer for v${update.version} launched — agent will restart shortly` };

  } catch (e) {
    logger.error(`Auto-update: unhandled error — ${e.stack || e.message}`);
    return { status: 'failed', message: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Version comparison: returns true if remote > current
// ─────────────────────────────────────────────────────────────────────────────
function isNewerVersion(remote, current) {
  const parse = v => (v || '0.0.0').replace(/[^0-9.]/g, '').split('.').map(n => parseInt(n, 10) || 0);
  const [rA, rB, rC] = parse(remote);
  const [cA, cB, cC] = parse(current);
  if (rA !== cA) return rA > cA;
  if (rB !== cB) return rB > cB;
  return rC > cC;
}

module.exports = { checkForUpdate, performUpdate, isNewerVersion };
