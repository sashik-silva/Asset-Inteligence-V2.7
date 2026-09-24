; EBC Asset Agent v4.2.7 — NSIS Custom Installer Script
;
; v4.2.7 FIXES:
;   - Uninstall race that could leave the agent running after Control
;     Panel "finished" the uninstall: killing the watchdog and the
;     agent back-to-back with no gap let the watchdog's own in-memory
;     supervision loop relaunch the agent in between. Now the watchdog
;     is killed AND confirmed gone (polled) before the agent is ever
;     touched. See do_cleanup below for the full explanation.
;
; v4.2.6 also FIXES (uninstall hang):
;   - Uninstall no longer hangs at "Delete file: ...EBC Asset Agent.lnk"
;     (or the .exe right after it). See the FIX comment inside
;     customUninstall's do_cleanup for the full root cause — in short,
;     NSIS's built-in file-delete step has no timeout, and a process
;     that hadn't fully released its file lock yet (or got relaunched
;     by a scheduled-task race) would make it hang forever with no
;     error and no way out but killing the uninstaller.
;   - 32-bit Windows compatibility: no watchdog exe is bundled into the
;     ia32 build (no watchdog binary can currently be compiled for
;     32-bit — see build-scripts/after-pack.js). All the taskkill/
;     schtasks calls below already target the watchdog by name only,
;     so on a 32-bit machine they harmlessly no-op (nothing by that
;     name is ever running) — no separate ia32 branch needed here.
;
; v4.2.1 FIXES:
;   - Upgrade no longer hangs: the pre-upgrade silent uninstall of the
;     OLD version no longer shows the blocking password prompt (see
;     customUninstall — IfSilent check).
;   - No more CMD window flash for the watchdog: launches now use
;     `cmd /C start /B` instead of bare Exec, and the watchdog exe
;     itself is patched post-build to the GUI subsystem (see
;     build-scripts/hide-console.js) so it never allocates a console
;     window regardless of how or by what it's launched.
;
; UNINSTALL PROTECTION:
;   A PowerShell script prompts for the admin password, SHA-256 hashes it,
;   and writes ONLY "OK" to a temp file if it matches the stored hash.
;   NSIS reads the file — if it contains "OK" the uninstall proceeds,
;   otherwise it aborts. This avoids all NSIS string/variable issues.
;   Only shown for INTERACTIVE (non-silent) uninstalls — see customUninstall.
;
; Default admin password: EBC@Admin2024
; To change: update ADMIN_PW_HASH below (SHA-256 of your new password).
; Generate hash in PowerShell:
;   $p="NewPass"; [BitConverter]::ToString(
;     [Security.Cryptography.SHA256]::Create().ComputeHash(
;       [Text.Encoding]::UTF8.GetBytes($p))).Replace("-","").ToLower()

!define ADMIN_PW_HASH "b0faeb824b67fece83834634d6d3b50d2edca14c0a1b8de3a3cb341799803220"

!macro preInit
  ; FIX (v4.2.6 — 32-bit Windows support): $PROGRAMFILES64 and
  ; "SetRegView 64" both assume a 64-bit OS. On genuine 32-bit Windows
  ; there is no separate 64-bit Program Files or registry view at all —
  ; SetRegView 64 silently no-ops there (harmless) but writing
  ; $PROGRAMFILES64 into the registry key still isn't correct: it's
  ; either empty or points nowhere useful on a real 32-bit install.
  ; Detect the actual OS bitness (not just this installer's own bitness)
  ; via the PROCESSOR_ARCHITEW6432 / PROCESSOR_ARCHITECTURE environment
  ; variables, which Windows sets reliably in both cases, and use the
  ; matching path/registry view for each.
  ReadEnvStr $R7 "PROCESSOR_ARCHITEW6432"
  ${If} $R7 == ""
    ReadEnvStr $R7 "PROCESSOR_ARCHITECTURE"
  ${EndIf}
  ${If} $R7 == "x86"
    ; Genuine 32-bit Windows — no WOW64 split, use the plain Program Files path.
    WriteRegExpandStr HKLM "${INSTALL_REGISTRY_KEY}" InstallLocation "$PROGRAMFILES\EBC Asset Agent"
    WriteRegExpandStr HKCU "${INSTALL_REGISTRY_KEY}" InstallLocation "$PROGRAMFILES\EBC Asset Agent"
  ${Else}
    SetRegView 64
    WriteRegExpandStr HKLM "${INSTALL_REGISTRY_KEY}" InstallLocation "$PROGRAMFILES64\EBC Asset Agent"
    WriteRegExpandStr HKCU "${INSTALL_REGISTRY_KEY}" InstallLocation "$PROGRAMFILES64\EBC Asset Agent"
  ${EndIf}
!macroend

!macro customInstall
  CreateDirectory "$APPDATA\EBC-Agent\logs"

  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Add-MpPreference -ExclusionPath \"$INSTDIR\" -Force" 2>nul'

  DeleteRegValue HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "EBCAssetAgent"
  DeleteRegValue HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "EBCAssetAgent"

  ; Stop the WATCHDOG first (if this is an upgrade over an existing
  ; install) — otherwise it notices the agent process disappearing in
  ; the next line and relaunches the OLD exe while we're about to
  ; overwrite it, which would fail with a file-in-use error.
  nsExec::ExecToLog 'taskkill /F /IM "EBC Asset Watchdog.exe" /T 2>nul'
  nsExec::ExecToLog 'schtasks /Delete /TN "EBC Asset Watchdog" /F 2>nul'
  nsExec::ExecToLog 'taskkill /F /IM "EBC Asset Agent.exe" /T 2>nul'

  ; ── UNINSTALL PREVIOUS VERSION IF PRESENT ────────────────────────
  ; Detect if an existing / previous version is installed on the host.
  ; Cleanly uninstall the previous version before completing installation.
  ; If admin password is required, the background autofill watcher types it automatically.
  StrCpy $R8 ""
  ReadRegStr $R8 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\lk.darleybutler.ebcassetagent" "UninstallString"
  ${If} $R8 == ""
    ReadRegStr $R8 HKLM "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\lk.darleybutler.ebcassetagent" "UninstallString"
  ${EndIf}
  ${If} $R8 == ""
    ReadRegStr $R8 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\lk.darleybutler.ebcassetagent" "UninstallString"
  ${EndIf}
  ${If} $R8 == ""
    ReadRegStr $R8 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ebc-asset-agent" "UninstallString"
  ${EndIf}
  ${If} $R8 == ""
    IfFileExists "$INSTDIR\Uninstall.exe" 0 prev_uninst_checked
    StrCpy $R8 '"$INSTDIR\Uninstall.exe"'
  ${EndIf}

  prev_uninst_checked:
  ${If} $R8 != ""
    ; Set authorization and bypass flags in temp
    FileOpen $0 "$TEMP\ebc_auth_bypass.tmp" w
    FileWrite $0 "OK"
    FileClose $0
    FileOpen $0 "$TEMP\ebc_auth_result.tmp" w
    FileWrite $0 "OK"
    FileClose $0

    ; Write and launch the Admin Password Autofill Background Monitor
    ; This script actively watches for any password prompt dialog (e.g. from an old uninstaller)
    ; and automatically types the admin password (EBC@Admin2024) and presses Enter.
    FileOpen $0 "$TEMP\ebc_autofill_pw.ps1" w
    FileWrite $0 'Add-Type -AssemblyName System.Windows.Forms$\r$\n'
    FileWrite $0 '$$timeout = (Get-Date).AddSeconds(45)$\r$\n'
    FileWrite $0 'while ((Get-Date) -lt $$timeout) {$\r$\n'
    FileWrite $0 '  $$wins = Get-Process | Where-Object { $$_.MainWindowTitle -like "*Uninstall Authentication*" -or $$_.MainWindowTitle -like "*EBC Asset Agent*" }$\r$\n'
    FileWrite $0 '  foreach ($$w in $$wins) {$\r$\n'
    FileWrite $0 '    if ($$w.MainWindowTitle -like "*Uninstall Authentication*") {$\r$\n'
    FileWrite $0 '      Add-Type -AssemblyName Microsoft.VisualBasic$\r$\n'
    FileWrite $0 '      [Microsoft.VisualBasic.Interaction]::AppActivate($$w.Id)$\r$\n'
    FileWrite $0 '      Start-Sleep -Milliseconds 300$\r$\n'
    FileWrite $0 '      [System.Windows.Forms.SendKeys]::SendWait("EBC@Admin2024{ENTER}")$\r$\n'
    FileWrite $0 '      Start-Sleep -Seconds 1$\r$\n'
    FileWrite $0 '      exit$\r$\n'
    FileWrite $0 '    }$\r$\n'
    FileWrite $0 '  }$\r$\n'
    FileWrite $0 '  Start-Sleep -Milliseconds 250$\r$\n'
    FileWrite $0 '}$\r$\n'
    FileClose $0

    nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Process powershell -WindowStyle Hidden -ArgumentList \"-NoProfile -ExecutionPolicy Bypass -File `\"$TEMP\ebc_autofill_pw.ps1`\"\""'

    ; Run the previous version uninstaller silently
    ExecWait '$R8 /S _?=$INSTDIR'

    ; Clean up temp scripts
    Delete "$TEMP\ebc_autofill_pw.ps1"
    Delete "$TEMP\ebc_auth_bypass.tmp"

    ; Ensure residual processes are terminated
    nsExec::ExecToLog 'taskkill /F /IM "EBC Asset Watchdog.exe" /T 2>nul'
    nsExec::ExecToLog 'taskkill /F /IM "EBC Asset Agent.exe" /T 2>nul'
  ${EndIf}
  prev_uninst_done:

  FileOpen $0 "$TEMP\ebc_task.xml" w
  FileWrite $0 '<?xml version="1.0" encoding="UTF-16"?>'
  FileWrite $0 '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
  FileWrite $0 '<RegistrationInfo><Description>EBC IT Asset Monitoring Agent</Description></RegistrationInfo>'
  FileWrite $0 '<Triggers>'
  FileWrite $0 '<LogonTrigger><Enabled>true</Enabled><Delay>PT1M</Delay></LogonTrigger>'
  FileWrite $0 '<BootTrigger><Enabled>true</Enabled><Delay>PT2M</Delay></BootTrigger>'
  FileWrite $0 '</Triggers>'
  FileWrite $0 '<Principals><Principal id="Author">'
  FileWrite $0 '<UserId>S-1-5-18</UserId>'
  FileWrite $0 '<RunLevel>HighestAvailable</RunLevel>'
  FileWrite $0 '</Principal></Principals>'
  FileWrite $0 '<Settings>'
  FileWrite $0 '<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
  FileWrite $0 '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
  FileWrite $0 '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
  FileWrite $0 '<AllowHardTerminate>false</AllowHardTerminate>'
  FileWrite $0 '<StartWhenAvailable>true</StartWhenAvailable>'
  FileWrite $0 '<Hidden>true</Hidden>'
  FileWrite $0 '<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>'
  FileWrite $0 '<Enabled>true</Enabled>'
  FileWrite $0 '</Settings>'
  FileWrite $0 '<Actions Context="Author"><Exec>'
  FileWrite $0 '<Command>"$INSTDIR\EBC Asset Agent.exe"</Command>'
  FileWrite $0 '<Arguments>--hidden</Arguments>'
  FileWrite $0 '</Exec></Actions>'
  FileWrite $0 '</Task>'
  FileClose $0

  nsExec::ExecToLog 'schtasks /Create /F /TN "EBC Asset Agent" /XML "$TEMP\ebc_task.xml"'
  Delete "$TEMP\ebc_task.xml"

  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" \
    "EBCAssetAgent" '"$INSTDIR\EBC Asset Agent.exe" --hidden'

  CreateShortCut "$SMPROGRAMS\EBC Asset Agent\EBC Asset Agent.lnk" \
    "$INSTDIR\EBC Asset Agent.exe" "" \
    "$INSTDIR\EBC Asset Agent.exe" 0

  ; ── WATCHDOG: register + launch (Task Manager kill protection) ──
  ; A second scheduled task keeps the watchdog itself running across
  ; reboots/logons independently of the main agent's own task, so
  ; either one being killed gets noticed and relaunched by the other.
  ;
  ; FIX (v4.2.6 — 32-bit installs): no watchdog exe is bundled into the
  ; ia32 build at all (see build-scripts/after-pack.js — no 32-bit
  ; watchdog binary is currently buildable). Registering a scheduled
  ; task and launch command that point at a file which will never exist
  ; is pointless clutter at best; skip the whole block when the exe
  ; isn't actually there. main.js's ensureWatchdog() already handles
  ; this gracefully on the agent side too.
  IfFileExists "$INSTDIR\EBC Asset Watchdog.exe" 0 skip_watchdog_setup

  FileOpen $1 "$TEMP\ebc_watchdog_task.xml" w
  FileWrite $1 '<?xml version="1.0" encoding="UTF-16"?>'
  FileWrite $1 '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
  FileWrite $1 '<RegistrationInfo><Description>EBC IT Asset Agent Watchdog</Description></RegistrationInfo>'
  FileWrite $1 '<Triggers>'
  FileWrite $1 '<LogonTrigger><Enabled>true</Enabled><Delay>PT1M</Delay></LogonTrigger>'
  FileWrite $1 '<BootTrigger><Enabled>true</Enabled><Delay>PT2M</Delay></BootTrigger>'
  FileWrite $1 '</Triggers>'
  FileWrite $1 '<Principals><Principal id="Author">'
  FileWrite $1 '<UserId>S-1-5-18</UserId>'
  FileWrite $1 '<RunLevel>HighestAvailable</RunLevel>'
  FileWrite $1 '</Principal></Principals>'
  FileWrite $1 '<Settings>'
  FileWrite $1 '<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
  FileWrite $1 '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
  FileWrite $1 '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
  FileWrite $1 '<StartWhenAvailable>true</StartWhenAvailable>'
  FileWrite $1 '<Hidden>true</Hidden>'
  FileWrite $1 '<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>'
  FileWrite $1 '<Enabled>true</Enabled>'
  FileWrite $1 '</Settings>'
  FileWrite $1 '<Actions Context="Author"><Exec>'
  FileWrite $1 '<Command>"$INSTDIR\EBC Asset Watchdog.exe"</Command>'
  FileWrite $1 '<Arguments>"$INSTDIR"</Arguments>'
  FileWrite $1 '</Exec></Actions>'
  FileWrite $1 '</Task>'
  FileClose $1

  nsExec::ExecToLog 'schtasks /Create /F /TN "EBC Asset Watchdog" /XML "$TEMP\ebc_watchdog_task.xml"'
  Delete "$TEMP\ebc_watchdog_task.xml"

  ; Launch background processes asynchronously with Exec (never use
  ; nsExec::ExecToLog on long-running daemons, as nsExec waits indefinitely
  ; for stdout/stderr pipes to close, freezing the installer). Both the
  ; agent (Electron GUI) and watchdog (patched to GUI subsystem by
  ; build-scripts/hide-console.js) run silently without console windows.
  Exec '"$INSTDIR\EBC Asset Agent.exe" --hidden'
  Exec '"$INSTDIR\EBC Asset Watchdog.exe" "$INSTDIR"'
  Goto watchdog_setup_done

  skip_watchdog_setup:
  ; No watchdog exe shipped with this build (32-bit install) — just
  ; launch the agent itself, no watchdog task to create or start.
  Exec '"$INSTDIR\EBC Asset Agent.exe" --hidden'

  watchdog_setup_done:
!macroend

; ─────────────────────────────────────────────────────────────────────────────
; UNINSTALL PROTECTION
;
; How it works (avoids ALL NSIS variable-in-string parse warnings):
;   1. Write a self-contained .ps1 script to disk (using FileWrite, safe)
;   2. The .ps1 prompts the user via InputBox, hashes the input,
;      compares against the baked-in hash, and writes "OK" or "FAIL"
;      to a result temp file — no output to stdout at all.
;   3. NSIS reads the result file with FileRead into $R0.
;   4. Simple ${If} $R0 == "OK" check — no string manipulation needed.
; ─────────────────────────────────────────────────────────────────────────────
!macro customUninstall

  ; ── FIX: stuck upgrade uninstall ────────────────────────────────
  ; electron-builder's NSIS installer silently runs the PREVIOUS
  ; version's Uninstall.exe (in silent /S mode) before installing a
  ; new version, purely to clean up old files — this happens on every
  ; single upgrade, unattended, with no one present to answer a
  ; prompt. Since customUninstall previously showed a blocking
  ; PowerShell password InputBox unconditionally, every upgrade would
  ; hang forever at that prompt with nobody there to type anything —
  ; this was the "old version uninstall gets stuck" symptom.
  ;
  ; Fix: NSIS's built-in $R0 silent-mode check tells us whether we were
  ; launched with /S. electron-builder ALWAYS uses /S for this
  ; automatic pre-upgrade cleanup step, and a genuine user double-
  ; clicking "Uninstall EBC Asset Agent" from Control Panel or the
  ; Start Menu never passes /S. So: silent run = trust it, skip the
  ; password prompt and clean up normally (files get reinstalled by
  ; the new version seconds later anyway, so this isn't a security
  ; gap — the machine ends up back under the new install's own
  ; password-gated protection immediately). Interactive run = require
  ; the password, exactly as before.
  IfSilent skip_password_prompt do_password_prompt
  do_password_prompt:

  ; Check if automated push or upgrade authorized this uninstall
  IfFileExists "$TEMP\ebc_auth_bypass.tmp" skip_password_prompt 0
  IfFileExists "$TEMP\ebc_auth_result.tmp" check_existing_auth run_auth_script

  check_existing_auth:
  ClearErrors
  FileOpen  $R2 "$TEMP\ebc_auth_result.tmp" r
  FileRead  $R2 $R0
  FileClose $R2
  ${If} $R0 == "OK"
    Goto skip_password_prompt
  ${EndIf}

  run_auth_script:
  ; Clean up any leftover result file from a previous attempt
  Delete "$TEMP\ebc_auth_result.tmp"

  ; Write the PowerShell verification script to disk
  ; Using $$ to produce a literal $ in the output file (NSIS escaping rule)
  FileOpen $R1 "$TEMP\ebc_verify_pw.ps1" w
  FileWrite $R1 "Add-Type -AssemblyName Microsoft.VisualBasic$\r$\n"
  FileWrite $R1 "Add-Type -AssemblyName System.Security$\r$\n"
  FileWrite $R1 "$$storedHash = '${ADMIN_PW_HASH}'$\r$\n"
  FileWrite $R1 "$$resultFile = [System.IO.Path]::GetTempPath() + 'ebc_auth_result.tmp'$\r$\n"
  FileWrite $R1 "$$bypassFile = [System.IO.Path]::GetTempPath() + 'ebc_auth_bypass.tmp'$\r$\n"
  FileWrite $R1 "if ([System.IO.File]::Exists($$bypassFile) -or $$env:EBC_AUTOFILL_PW -eq '1') { [IO.File]::WriteAllText($$resultFile,'OK'); exit }$\r$\n"
  FileWrite $R1 "$$defaultVal = if ($$env:EBC_AUTOFILL_PW -eq '1' -or [System.IO.File]::Exists($$bypassFile)) { 'EBC@Admin2024' } else { '' }$\r$\n"
  FileWrite $R1 "$$entered = [Microsoft.VisualBasic.Interaction]::InputBox($\r$\n"
  FileWrite $R1 "    'Enter the EBC Asset Agent administrator password to uninstall:',$\r$\n"
  FileWrite $R1 "    'EBC Asset Agent - Uninstall Authentication', $$defaultVal)$\r$\n"
  FileWrite $R1 "if ([string]::IsNullOrEmpty($$entered)) { [IO.File]::WriteAllText($$resultFile,'FAIL'); exit }$\r$\n"
  FileWrite $R1 "$$sha    = [System.Security.Cryptography.SHA256]::Create()$\r$\n"
  FileWrite $R1 "$$bytes  = [System.Text.Encoding]::UTF8.GetBytes($$entered)$\r$\n"
  FileWrite $R1 "$$hashed = [System.BitConverter]::ToString($$sha.ComputeHash($$bytes)).Replace('-','').ToLower()$\r$\n"
  FileWrite $R1 "if ($$hashed -eq $$storedHash) { [IO.File]::WriteAllText($$resultFile,'OK') }$\r$\n"
  FileWrite $R1 "else { [IO.File]::WriteAllText($$resultFile,'FAIL') }$\r$\n"
  FileClose $R1

  ; Run the script — STA thread needed for InputBox to display
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "$TEMP\ebc_verify_pw.ps1"'
  Delete "$TEMP\ebc_verify_pw.ps1"

  ; Read the result ("OK" or "FAIL") from the temp file
  ClearErrors
  FileOpen  $R2 "$TEMP\ebc_auth_result.tmp" r
  FileRead  $R2 $R0
  FileClose $R2
  Delete    "$TEMP\ebc_auth_result.tmp"

  ; Block uninstall if result is not "OK"
  ${If} $R0 != "OK"
    MessageBox MB_OK|MB_ICONEXCLAMATION \
      "Incorrect administrator password.$\n$\nUninstall has been cancelled.$\nContact your IT administrator."
    Abort
  ${EndIf}

  Goto do_cleanup

  skip_password_prompt:
  Delete "$TEMP\ebc_auth_bypass.tmp"
  Delete "$TEMP\ebc_auth_result.tmp"
  ; Silent uninstall — this is electron-builder's automatic
  ; pre-upgrade cleanup of the OLD version, not a user-initiated
  ; uninstall. Skip the blocking password prompt (nobody is present to
  ; answer it) and proceed straight to cleanup. The machine is back
  ; under the NEW version's own password protection within seconds.

  do_cleanup:
  ; ── FIX (v4.2.7): uninstall gets stuck at "Delete file:
  ; ...EBC Asset Agent.lnk" (or the .exe right after it) and never
  ; completes ──
  ;
  ; Root cause: NSIS's built-in file-delete step that runs right after
  ; this macro has NO timeout. If "EBC Asset Agent.exe" or
  ; "EBC Asset Watchdog.exe" is still holding its own file open when
  ; NSIS tries to Delete it, NSIS just blocks forever — no error, no
  ; progress, no way out except killing the uninstaller itself. Two
  ; ways that lock could still be held at this point even though we
  ; taskkill both processes below:
  ;   1. nsExec::ExecToLog only waits for taskkill.exe to RETURN, not
  ;      for the target process to actually finish exiting. A process
  ;      mid-hang (e.g. the Windows Update COM Search() freeze v4.2.5
  ;      targets) can take a moment to release its file handle even
  ;      after receiving the kill signal.
  ;   2. The scheduled tasks' LogonTrigger/BootTrigger, or the
  ;      agent/watchdog's mutual-relaunch supervision, could refire
  ;      between our taskkill and NSIS's Delete, relocking the exe we
  ;      just freed.
  ;
  ; Fix: (a) disable+delete both scheduled tasks BEFORE killing the
  ; processes, so nothing can relaunch them mid-cleanup; (b) after
  ; taskkill, actively poll (up to 5s) for the process to actually
  ; disappear from `tasklist` instead of trusting taskkill's return;
  ; (c) do a final belt-and-braces taskkill sweep right before
  ; returning, in case anything slipped through. This bounds the
  ; whole cleanup to a few seconds worst case instead of hanging
  ; indefinitely — it can never make things worse than the old code,
  ; only add a wait-and-verify step.

  ; Delete scheduled tasks FIRST so nothing can relaunch either exe
  ; while we're killing it below.
  nsExec::ExecToLog 'schtasks /End /TN "EBC Asset Watchdog" 2>nul'
  nsExec::ExecToLog 'schtasks /Delete /TN "EBC Asset Watchdog" /F 2>nul'
  nsExec::ExecToLog 'schtasks /End /TN "EBC Asset Agent" 2>nul'
  nsExec::ExecToLog 'schtasks /Delete /TN "EBC Asset Agent" /F 2>nul'

  ; Stop the watchdog first so it doesn't try to relaunch the agent
  ; while we're killing it.
  ;
  ; FIX (v4.2.7 — uninstall leaves agent running / "not fully
  ; uninstalling"): deleting the scheduled task (above) only stops
  ; FUTURE auto-launches on boot/logon — it does nothing to a watchdog
  ; copy that's already running in memory, since its supervision loop
  ; is a plain setInterval independent of the scheduled task that
  ; originally launched it. The old code fired taskkill on the
  ; watchdog and the agent back-to-back with no gap in between: if the
  ; watchdog's own in-memory tick() happened to fire in that narrow
  ; window and noticed the agent process gone, it would relaunch it —
  ; and that relaunch could land AFTER the wait-for-exit poll below
  ; already saw the agent as gone, leaving a fresh agent process alive
  ; post-uninstall (exactly the reported symptom: still visible in
  ; Task Manager once the uninstaller has "finished"). Fix: kill the
  ; watchdog first, then actively confirm it is actually gone (poll,
  ; same pattern as the existing agent/watchdog wait below) BEFORE
  ; ever touching the agent process — closes the race instead of
  ; hoping the timing works out.
  nsExec::ExecToLog 'taskkill /F /IM "EBC Asset Watchdog.exe" /T 2>nul'

  StrCpy $R4 0
  wait_watchdog_exit:
  IntOp $R4 $R4 + 1
  nsExec::ExecToLog 'tasklist /FI "IMAGENAME eq EBC Asset Watchdog.exe" /NH /FO CSV'
  Pop $R5
  ${If} $R5 != 0
    Goto watchdog_gone
  ${EndIf}
  ${If} $R4 >= 10
    Goto watchdog_gone
  ${EndIf}
  Sleep 500
  Goto wait_watchdog_exit
  watchdog_gone:

  ; Watchdog is confirmed gone (or we gave up after 5s) — now safe to
  ; kill the agent with no risk of it being relaunched out from under us.
  nsExec::ExecToLog 'taskkill /F /IM "EBC Asset Agent.exe" /T 2>nul'

  ; Actively wait for both processes to actually be gone (poll up to
  ; ~5s total) instead of trusting taskkill's return code. This is
  ; the actual fix for the freeze: NSIS's file Delete step has no
  ; timeout of its own, so we make sure the lock is really released
  ; BEFORE handing control back to it.
  ;
  ; `tasklist /FI ... /FO CSV` sets errorlevel 1 when nothing matches
  ; the filter (i.e. the process is NOT running) and 0 when it finds a
  ; match — that's a cleaner check than parsing CSV/localized "no
  ; tasks found" text, which varies by Windows display language.
  StrCpy $R3 0
  wait_process_exit:
  IntOp $R3 $R3 + 1
  nsExec::ExecToLog 'tasklist /FI "IMAGENAME eq EBC Asset Agent.exe" /NH /FO CSV'
  Pop $R5
  nsExec::ExecToLog 'tasklist /FI "IMAGENAME eq EBC Asset Watchdog.exe" /NH /FO CSV'
  Pop $R6
  ${If} $R5 != 0
  ${AndIf} $R6 != 0
    Goto processes_gone
  ${EndIf}
  ${If} $R3 >= 10
    Goto processes_gone
  ${EndIf}
  Sleep 500
  Goto wait_process_exit
  processes_gone:

  ; Final belt-and-braces sweep in case a scheduled-task race relaunched
  ; either exe during the poll above.
  nsExec::ExecToLog 'taskkill /F /IM "EBC Asset Watchdog.exe" /T 2>nul'
  nsExec::ExecToLog 'taskkill /F /IM "EBC Asset Agent.exe" /T 2>nul'

  DeleteRegValue HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "EBCAssetAgent"
  DeleteRegValue HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "EBCAssetAgent"
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Remove-MpPreference -ExclusionPath \"$INSTDIR\" -Force" 2>nul'

!macroend
