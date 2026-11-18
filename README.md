# API Security & Risk Intelligence Platform

This is a defensive, educational API security testing platform for a controlled local lab. It is not an official OWASP, CVSS, or commercial scanner implementation. Any in-app score is explicitly labeled **project-defined**.

## Native local development

Docker, Docker Compose, PostgreSQL, Redis, and Celery are optional future stretch scope. The required development stack runs entirely as native local processes:

- FastAPI + Uvicorn backend;
- SQLite database at `./api-security.db` by default;
- React + Tailwind frontend started by Vite;
- FastAPI `BackgroundTasks`/`asyncio` for future MVP scan jobs;
- synthetic vulnerable-lab API domains, each bound to a different loopback port.

## Setup on a fresh machine

1. Install Python 3.12+ and Node.js 22+.
2. Copy `.env.example` to `.env`. Replace every `replace-with-*` value with a local, synthetic value; never commit `.env`.
3. Set the variables for the current PowerShell session:

   ```powershell
   Get-Content .env | Where-Object { $_ -match '^[^#].+=' } | ForEach-Object {
     $name, $value = $_ -split '=', 2
     Set-Item -Path "Env:$name" -Value $value
   }
   ```

4. Install backend dependencies and create the SQLite schema:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r backend/requirements-dev.txt
   Set-Location backend
   alembic upgrade head
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

5. In a second terminal, install and run the frontend:

   ```powershell
   Set-Location frontend
   npm ci
   npm run dev
   ```

6. In a third terminal, install lab dependencies and start its separate local processes:

   ```powershell
   python -m pip install -r lab/requirements-dev.txt
   .\scripts\run_lab.ps1 -KeepRunning
   ```

The backend is at `http://127.0.0.1:8000`, the UI at `http://127.0.0.1:5173`, and lab domains at ports 8101–8107. Nothing binds to a public interface.

## Controlled lab

The lab contains synthetic identities only, and paired `/vuln` and `/secure` behavior for object/function/property authorization, JWT handling, payments, orders, inventory, and GraphQL. The public contract intentionally excludes `/internal/diagnostics` (shadow endpoint); `/v1/*` is a deprecated but reachable zombie set. Exact expected outcomes are in [GROUND_TRUTH.md](lab/GROUND_TRUTH.md).

## Verification

```powershell
ruff check backend
pytest backend
pip-audit -r backend/requirements.txt

ruff check lab
pytest lab
pip-audit -r lab/requirements.txt

Set-Location frontend
npm audit
npm run lint
npm run build
```

## Security boundaries

- Secrets come from environment variables only and are never logged.
- Future target-calling features must call `validate_controlled_target` before making a request.
- The default target allowlist contains loopback hosts/ranges only.
- The project does not execute arbitrary user-supplied code or shell commands.
- Future stored evidence and logs must sanitize tokens, credentials, and card-like values.

