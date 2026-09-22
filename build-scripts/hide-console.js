/**
 * hide-console.js
 *
 * WHY THIS EXISTS
 * ────────────────
 * `pkg` compiles watchdog.js into a Windows executable using Node's
 * default CONSOLE subsystem (PE header field IMAGE_SUBSYSTEM = 3).
 * Every time that exe is launched — by NSIS during install, by
 * Task Scheduler, or by the watchdog/agent relaunching each other —
 * Windows briefly shows a black console window before it's hidden,
 * because a console-subsystem process gets one by default regardless
 * of spawn flags like `windowsHide`. `windowsHide` on the *spawning*
 * side hides the window fast, but on some systems (slow AV scanning,
 * Task Scheduler's own session) there's a visible flash before that
 * takes effect — which is exactly the "cmd opens then closes" symptom
 * being reported.
 *
 * THE FIX
 * ────────
 * A Windows PE executable has a Subsystem field in its Optional
 * Header that tells the OS whether to allocate a console at all.
 * GUI-subsystem processes (value 2) never get a console window in the
 * first place — this is how every ordinary background Windows app
 * (including Electron itself) avoids ever flashing a console. This
 * script patches that single byte in the compiled watchdog exe from
 * 3 (CONSOLE) to 2 (GUI) after `pkg` builds it. No console will be
 * allocated on any future launch, by anyone, ever again — this fixes
 * the problem at its root rather than papering over it with spawn
 * flags.
 *
 * This is a standard, well-documented technique (the same one tools
 * like "editbin /SUBSYSTEM:WINDOWS" perform) — it only changes how
 * Windows treats the executable's console allocation, nothing else
 * about its behavior.
 */

'use strict';
const fs = require('fs');
const path = require('path');

const EXE_PATH = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.join(__dirname, '..', 'dist-watchdog', 'EBC-Asset-Watchdog.exe');

const IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;
const IMAGE_SUBSYSTEM_WINDOWS_CUI = 3; // console — what pkg produces by default

function patchSubsystem(exePath) {
  const buf = fs.readFileSync(exePath);

  // ── Walk the PE header to find the Subsystem field offset ──────
  // DOS header: 'MZ' at offset 0, e_lfanew (offset to PE header) at 0x3C
  if (buf.readUInt16LE(0) !== 0x5a4d) { // 'MZ'
    throw new Error('Not a valid PE/DOS executable (missing MZ signature)');
  }
  const peOffset = buf.readUInt32LE(0x3c);
  if (buf.readUInt32LE(peOffset) !== 0x00004550) { // 'PE\0\0'
    throw new Error('Not a valid PE file (missing PE signature)');
  }

  // COFF File Header is 20 bytes, right after the 4-byte PE signature.
  const coffHeaderOffset = peOffset + 4;
  const sizeOfOptionalHeader = buf.readUInt16LE(coffHeaderOffset + 16);
  if (sizeOfOptionalHeader === 0) {
    throw new Error('No optional header present — cannot patch subsystem');
  }

  const optionalHeaderOffset = coffHeaderOffset + 20;
  const magic = buf.readUInt16LE(optionalHeaderOffset);
  // PE32 = 0x10b, PE32+ (64-bit) = 0x20b — Subsystem field is at the
  // same relative offset (68) in both, per the PE/COFF spec.
  if (magic !== 0x10b && magic !== 0x20b) {
    throw new Error(`Unexpected optional header magic: 0x${magic.toString(16)}`);
  }

  const subsystemOffset = optionalHeaderOffset + 68;
  const currentSubsystem = buf.readUInt16LE(subsystemOffset);

  if (currentSubsystem === IMAGE_SUBSYSTEM_WINDOWS_GUI) {
    console.log(`[hide-console] ${path.basename(exePath)} is already GUI-subsystem — nothing to do.`);
    return;
  }
  if (currentSubsystem !== IMAGE_SUBSYSTEM_WINDOWS_CUI) {
    console.warn(`[hide-console] Unexpected current subsystem value ${currentSubsystem} — patching anyway.`);
  }

  buf.writeUInt16LE(IMAGE_SUBSYSTEM_WINDOWS_GUI, subsystemOffset);
  fs.writeFileSync(exePath, buf);
  console.log(`[hide-console] Patched ${path.basename(exePath)}: subsystem CONSOLE(3) → GUI(2). No console window will ever be shown by this exe again.`);
}

try {
  if (!fs.existsSync(EXE_PATH)) {
    console.error(`[hide-console] ERROR: ${EXE_PATH} not found — run "npm run build:watchdog" (the pkg step) first.`);
    process.exit(1);
  }
  patchSubsystem(EXE_PATH);
} catch (e) {
  console.error(`[hide-console] FAILED: ${e.message}`);
  process.exit(1);
}
