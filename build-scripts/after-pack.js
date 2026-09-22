// afterPack hook — runs once per architecture electron-builder packages.
//
// WHY THIS EXISTS (v4.2.6, 32-bit Windows support):
// The watchdog process is compiled separately via @yao-pkg/pkg, and
// pkg-fetch (the tool that supplies pkg's prebuilt Node binaries) does
// not ship a Windows x86/ia32 build at all — only x64 and arm64. So
// there is no watchdog exe to bundle into the 32-bit install. Rather
// than fail the ia32 build (electron-builder's static "extraFiles"
// config can't conditionally skip a missing file per-arch), this hook
// copies the watchdog exe in only when packaging x64, and does nothing
// on ia32 — main.js's ensureWatchdog() already checks for the file's
// existence before trying to use it (see the FIX note in main.js), so
// a 32-bit install simply runs without the "relaunch within ~2s if
// Task-Manager-killed" protection, instead of failing to run at all.
//
// If a 32-bit watchdog build ever becomes possible (e.g. a
// custom-compiled win-x86 Node binary supplied via PKG_NODE_PATH), add
// its output as dist-watchdog/EBC-Asset-Watchdog-ia32.exe and this
// hook will pick it up automatically — no further changes needed here.

const fs = require('fs');
const path = require('path');

exports.default = async function afterPack(context) {
  // electron-builder's Arch enum: ia32=0, x64=1, armv7l=2, arm64=3, universal=4
  const archName = ['ia32', 'x64', 'armv7l', 'arm64', 'universal'][context.arch];

  if (archName !== 'x64') {
    console.log(`[after-pack] Skipping watchdog bundling for arch "${archName}" — no 32-bit watchdog binary is buildable (see comment at top of this file).`);
    return;
  }

  const src = path.join(__dirname, '..', 'dist-watchdog', 'EBC-Asset-Watchdog-x64.exe');
  const destDir = context.appOutDir;
  const dest = path.join(destDir, 'EBC Asset Watchdog.exe');

  if (!fs.existsSync(src)) {
    console.warn(`[after-pack] WARNING: expected watchdog binary not found at ${src} — did you run "npm run build:watchdog" first? The x64 build will ship WITHOUT kill-protection.`);
    return;
  }

  fs.copyFileSync(src, dest);
  console.log(`[after-pack] Bundled watchdog exe into x64 build: ${dest}`);
};
