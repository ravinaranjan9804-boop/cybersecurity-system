# CyberGuard Security System

## Run on Windows

Set a unique Flask signing key for this terminal session, then start the app:

```powershell
$env:FLASK_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$securePassword = Read-Host "Choose the initial admin password" -AsSecureString
$env:INITIAL_ADMIN_PASSWORD = (New-Object System.Management.Automation.PSCredential("admin", $securePassword)).GetNetworkCredential().Password
.\start_project.bat
```

`INITIAL_ADMIN_PASSWORD` is required only the first time the app creates its admin account. Keep both values private; do not commit them. The local SQLite database is ignored by Git and is created by the app when needed.
