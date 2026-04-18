# AEGIS — Windows Auto-Start & Notifications

Two install modes. Pick based on what you need:

| Mode | Starts | Privileges | Toast pop-ups? | Use when |
|---|---|---|---|---|
| **NSSM service** | At boot, before login | LocalSystem | No (Action Center only) | Headless box, server, full process visibility |
| **Task Scheduler at logon** | When *you* log in | Your user | Yes, transient toasts | Workstation where you want visible alerts |

Run **both** for the most coverage: service catches boot-time threats, the user-task hands you live toasts when you're at the keyboard.

---

## 0. Prereqs (do once)

```powershell
cd "C:\Brad\my Projects\aegis"
python -m pip install -r requirements.txt   # installs winotify on Windows
```

---

## 1. NSSM service (boot-time, SYSTEM)

Open PowerShell **as Administrator**:

```powershell
cd "C:\Brad\my Projects\aegis"
powershell -ExecutionPolicy Bypass -File .\scripts\install-service.ps1
```

The script will:
- Auto-download NSSM into `tools\nssm\nssm.exe` if it's missing.
- Register a service named `AEGIS` running `python -m aegis --config config\aegis.yaml`.
- Set it to auto-start, restart on crash (5s delay), and rotate stdout/stderr at 10 MB.

Check it:

```powershell
Get-Service AEGIS
Get-Content .\logs\aegis.log -Tail 30 -Wait
```

Uninstall:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-service.ps1
```

> **Why no toasts from the service?** Windows isolates session 0 — services can't show transient pop-ups to user sessions. Toasts from the service would land silently in the Action Center. Use mode 2 for live alerts.

---

## 2. Task Scheduler at user logon (interactive, toast-capable)

No admin needed (unless you want `RunLevel Highest`):

```powershell
cd "C:\Brad\my Projects\aegis"
powershell -ExecutionPolicy Bypass -File .\scripts\install-task-userlogon.ps1
```

This registers `AEGIS-UserAgent`, runs at every logon as you, hidden (uses `pythonw.exe` if available so no console window appears).

Toast settings live in `config\aegis.yaml`:

```yaml
alerting:
  toast:
    enabled: true
    min_severity: high     # info | low | medium | high | critical
    app_id: AEGIS
    icon_path: ""          # optional .ico for the toast
```

Remove:

```powershell
Unregister-ScheduledTask -TaskName AEGIS-UserAgent -Confirm:$false
```

---

## Tip: smoke-test a toast right now

```powershell
python -c "from winotify import Notification; Notification(app_id='AEGIS', title='Test', msg='Hello from AEGIS').show()"
```

If you see a pop-up, the toast pipeline works. If not: check Windows → Settings → System → Notifications → AEGIS is allowed and "Focus assist" isn't suppressing it.
