# Centrix Desktop Agent

This is the first desktop-agent scaffold. It starts the local FastAPI backend,
opens the Centrix web console, and gives a packaging target for a later `.exe`.

Run from the project root:

```powershell
py -3 desktop\centrix_desktop.py
```

Future packaging can wrap this with Tauri, Electron, or PyInstaller.
