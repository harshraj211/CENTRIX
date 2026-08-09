$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Start-Process -FilePath "py" -ArgumentList @("-3", "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000") -WorkingDirectory (Join-Path $projectRoot "backend")
Start-Process -FilePath "npm.cmd" -ArgumentList @("run", "dev", "--", "--host", "127.0.0.1", "--port", "8443") -WorkingDirectory (Join-Path $projectRoot "FrontEnd")
