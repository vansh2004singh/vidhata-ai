# Vidhata AI — Developer Workflow Agent (prototype)

This is a runnable starter derived from the supplied Vidhata UI and logo. It deliberately reports prototype limits honestly: repository inspection is a heuristic static scan, repository code is not executed, generated patches are drafts only, and no files are applied/committed/pushed.

## What works

- Dark Vidhata UI with the supplied logo.
- FastAPI health endpoint.
- Public GitHub repository/branch validation and shallow clone.
- Heuristic source scan for several potentially risky patterns.
- Findings with path, line, evidence, severity and recommendations.
- Optional patch drafting through an OpenAI-compatible `/chat/completions` API.
- Patch download/copy for manual review.
- No repository code execution during scanning.

## Windows quick start

Requirements: Python 3.11+ (Python 3.12/3.13 recommended), Git installed and on PATH. Node.js is not required for this starter because the UI is static HTML.

1. Extract this folder somewhere like `C:\VidhataAI`.
2. Open PowerShell in the extracted folder.
3. Run `Set-ExecutionPolicy -Scope Process Bypass` if your shell blocks local scripts.
4. Start backend in PowerShell window #1:
   ```powershell
   .\run-backend.ps1
   ```
5. Start frontend in PowerShell window #2:
   ```powershell
   .\run-frontend.ps1
   ```
6. Open `http://127.0.0.1:8000`. Backend health should show connected.
7. Scan a public GitHub repository, for example `https://github.com/psf/requests` on branch `main`.

## Optional model configuration

Edit `backend/.env` and set:

```env
MODEL_BASE_URL=https://YOUR-OPENAI-COMPATIBLE-PROVIDER/v1
MODEL_NAME=YOUR_MODEL_ID
MODEL_API_KEY=YOUR_SECRET_KEY
```

Then restart the backend. The base URL should be the API root ending in `/v1` if the provider supports `/chat/completions`. Never place model credentials in frontend code or commit `.env` to GitHub. An empty configuration means patch drafting is disabled by design.

## API

- `GET /api/health`
- `POST /api/inspect` with `{ "repo_url": "https://github.com/owner/repo", "branch": "main" }`
- `POST /api/patch-draft` with repo URL, branch and one finding from inspection
- Interactive API docs: `http://127.0.0.1:8001/docs`

## Safety and known limitations

- Only public GitHub HTTPS repository URLs are accepted. Private repository auth is not implemented.
- The scanner uses simple regular-expression heuristics. It is not a full SAST engine; false positives and false negatives are expected.
- Scan and patch endpoints clone repository content into a temporary directory, with time/file/size limits. They do not execute repository scripts.
- Patch drafting is optional, uses a configured model endpoint, and validates only the response shape. Review every diff manually.
- No patch is applied, no tests are run, and no Git branch/commit/pull request is created.
- Do not deploy this prototype publicly without authentication, rate limiting, stronger sandboxing, audit logs and production security review. Keep the API bound to localhost during the initial demo.

## Suggested next milestones

1. Add tests for input validation and scanner rules.
2. Add GitHub App/OAuth for private repositories with least-privilege permissions.
3. Integrate Semgrep or language-specific analyzers and normalize results.
4. Add disposable, network-restricted test sandboxes for approved test commands.
5. Add patch application in a temporary worktree, regression tests, and PR creation only after explicit approval.
6. Fine-tune a small model only after baseline evaluation and collecting curated task examples.
