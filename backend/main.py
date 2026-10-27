from __future__ import annotations

import os
import re
import json
import shutil
import subprocess
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

APP_NAME = "Vidhata AI"
MAX_FILES = int(os.getenv("MAX_SCAN_FILES", "2500"))
MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", "500000"))
CLONE_TIMEOUT = int(os.getenv("CLONE_TIMEOUT_SECONDS", "35"))

app = FastAPI(title="Vidhata AI API", version="0.1.0", description="Repository analysis and patch drafting prototype")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

class InspectRequest(BaseModel):
    repo_url: str = Field(min_length=19, max_length=300)
    branch: str = Field(default="main", min_length=1, max_length=100)

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
            raise ValueError("Only public HTTPS GitHub repository URLs are supported in this prototype.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Repository URL must not contain credentials, query parameters, or fragments.")
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) != 2 or any(p in {".", ".."} for p in parts):
            raise ValueError("Use a repository URL like https://github.com/owner/repository")
        if parts[1].endswith(".git"):
            parts[1] = parts[1][:-4]
        if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts):
            raise ValueError("Repository URL contains unsupported characters.")
        return f"https://github.com/{parts[0]}/{parts[1]}"

    @field_validator("branch")
    @classmethod
    def validate_branch(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_./-]+", value) or value.startswith("-") or ".." in value:
            raise ValueError("Branch name contains unsupported characters.")
        return value

class PatchRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    finding: dict[str, Any]

class Finding(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    evidence: str
    recommendation: str
    confidence: str = "medium"

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next", "venv", ".venv", "__pycache__", "target"}
TEXT_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".go", ".java", ".cs", ".env.example", ".yml", ".yaml", ".json", ".sql"}
RULES = [
    ("critical", "Possible hardcoded secret", "secrets", re.compile(r"(?i)(api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{12,}['\"]"), "Move secrets to a secret manager or environment variable; rotate any exposed credential."),
    ("high", "Potential SQL injection", "sql-injection", re.compile(r"(?i)(execute|cursor\.execute|\.query)\s*\(\s*(f['\"]|['\"].*%s|.*\+\s*request\.)"), "Use parameterized queries and avoid concatenating user-controlled values into SQL."),
    ("high", "Use of eval()", "unsafe-eval", re.compile(r"\beval\s*\("), "Avoid eval on untrusted input; use a parser or explicit mapping instead."),
    ("high", "Shell execution may be unsafe", "command-injection", re.compile(r"(?i)(shell\s*=\s*True|os\.system\s*\(|subprocess\.(?:Popen|run|call)\([^\n]*shell\s*=\s*True)"), "Avoid shell=True with untrusted input; pass an argument list and validate inputs."),
    ("medium", "TLS certificate verification disabled", "tls-verification", re.compile(r"(?i)(verify\s*=\s*False|CERT_NONE)"), "Keep TLS certificate verification enabled outside controlled tests."),
    ("medium", "Debug mode may be enabled", "debug-mode", re.compile(r"(?i)(debug\s*=\s*True|DEBUG\s*=\s*True)"), "Ensure debug mode is disabled in production."),
]

def run_git_clone(repo_url: str, branch: str, target: Path) -> None:
    # URL is validated as github.com before reaching this function; no shell is used.
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--branch", branch, "--", repo_url, str(target)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT, check=False)
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Git is not installed on the API host.")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Repository download timed out. Try a smaller public repository.")
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "Git clone failed").strip()[-900:]
        raise HTTPException(status_code=400, detail=f"Could not clone repository/branch: {message}")

def scan_repo(root: Path) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    scanned = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            path = Path(current) / filename
            if path.suffix.lower() not in TEXT_EXTS and filename not in {".env", "Dockerfile"}:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                continue
            scanned += 1
            if scanned > MAX_FILES:
                return findings, scanned - 1
            rel = path.relative_to(root).as_posix()
            for line_no, line in enumerate(content.splitlines(), start=1):
                # Ignore obvious example/placeholder credentials to reduce noise.
                if re.search(r"(?i)(example|placeholder|your[_ -]?(api|secret|token)|changeme|dummy)", line):
                    continue
                for severity, title, category, pattern, recommendation in RULES:
                    if pattern.search(line):
                        findings.append({
                            "id": f"{category}-{len(findings)+1}", "title": title, "severity": severity,
                            "category": category, "file": rel, "line": line_no,
                            "evidence": line.strip()[:280], "recommendation": recommendation,
                            "confidence": "low" if category in {"debug-mode", "unsafe-eval"} else "medium",
                        })
                        if len(findings) >= 100:
                            return findings, scanned
    return findings, scanned

@app.get("/api/health")
def health():
    model_configured = bool(os.getenv("MODEL_BASE_URL") and os.getenv("MODEL_NAME") and os.getenv("MODEL_API_KEY"))
    return {"status": "ok", "service": APP_NAME, "version": "0.1.0", "model_configured": model_configured, "scan_mode": "static-pattern-prototype"}

@app.post("/api/inspect")
def inspect_repo(payload: InspectRequest):
    with tempfile.TemporaryDirectory(prefix="vidhata-scan-") as temp:
        target = Path(temp) / "repo"
        run_git_clone(payload.repo_url, payload.branch, target)
        findings, scanned = scan_repo(target)
        return {
            "status": "completed", "repo_url": payload.repo_url, "branch": payload.branch,
            "scanned_files": scanned, "finding_count": len(findings), "findings": findings,
            "engine": "Vidhata static pattern scanner v0.1",
            "limitations": ["This is a heuristic prototype, not a complete security audit.", "Findings require human review; patterns can produce false positives and miss vulnerabilities.", "Repository code is not executed during scanning."],
        }

@app.post("/api/patch-draft")
def patch_draft(payload: PatchRequest):
    base_url = os.getenv("MODEL_BASE_URL", "").rstrip("/")
    model = os.getenv("MODEL_NAME", "")
    api_key = os.getenv("MODEL_API_KEY", "")
    if not (base_url and model and api_key):
        raise HTTPException(status_code=503, detail="Model endpoint is not configured. Set MODEL_BASE_URL, MODEL_NAME and MODEL_API_KEY in backend/.env. No patch was generated.")
    # Re-read only the selected file from the validated public repo; do not execute repository code.
    repo_url = InspectRequest(repo_url=payload.repo_url, branch=payload.branch).repo_url
    with tempfile.TemporaryDirectory(prefix="vidhata-patch-") as temp:
        target = Path(temp) / "repo"
        run_git_clone(repo_url, payload.branch, target)
        rel = str(payload.finding.get("file", ""))
        rel_path = Path(rel)
        if not rel or rel_path.is_absolute() or ".." in rel_path.parts:
            raise HTTPException(status_code=400, detail="Invalid finding file path.")
        file_path = (target / rel_path).resolve()
        if target.resolve() not in file_path.parents or not file_path.is_file():
            raise HTTPException(status_code=400, detail="Finding file not found in repository.")
        if file_path.stat().st_size > MAX_FILE_BYTES:
            raise HTTPException(status_code=413, detail="File is too large for patch drafting.")
        source = file_path.read_text(encoding="utf-8", errors="replace")
        prompt = (
            "You are a cautious code remediation assistant. Draft a minimal unified diff only; do not claim tests were run. "
            "Preserve behavior except for the security fix. If insufficient context, return a short explanation instead of a diff.\n"
           
f"Finding JSON: {json.dumps(payload.finding)[:2000]}\n"
f"File path: {rel}\n"
f"Source (truncated to 4000 chars):\n{source[:4000]}\n"

            "Return JSON with keys: diff, rationale, risks. Do not include markdown fences."
        )
        
   
    body = json.dumps({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cautious code remediation assistant. "
                    "Return valid JSON only, with keys diff, rationale, risks. "
                    "If no code change is warranted, return an empty diff and explain why."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 1200,
        "stream": False,
    }).encode()


    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            response_data = json.loads(response.read().decode())

        
        message = response_data["choices"][0]["message"]
        content = message.get("content") or ""

        if not content.strip():
            raise HTTPException(
                status_code=502,
                detail=(
                    "Ollama returned an empty message. "
                    "No patch was accepted."
                ),
            )

        content = re.sub(
            r"^```(?:json)?\s*|\s*```$",
            "",
            content.strip(),
            flags=re.I,
        )
        result = json.loads(content)

    except (urllib.error.URLError, TimeoutError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Model endpoint request failed: {exc}",
        )
    except (KeyError, IndexError, json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=502,
            detail="Model returned an invalid response. No patch was accepted.",
        )

    
    diff = str(result.get("diff", "")).strip()
    rationale = str(result.get("rationale", "")).strip()
    risks = result.get("risks", [])

    if not diff:
        return {
            "status": "no_change_recommended",
            "file": rel,
            "diff": "",
            "rationale": rationale or "Model did not recommend a code change.",
            "risks": risks,
            "tests_run": False,
            "requires_human_review": True,
        }

    if (
        "diff --git " not in diff
        or "+++" not in diff
        or "---" not in diff
    ):
        raise HTTPException(
            status_code=502,
            detail="Model output was not a valid-looking unified diff. No patch was accepted.",
        )

    return {
        "status": "drafted",
        "file": rel,
        "diff": diff,
        "rationale": str(result.get("rationale", "")),
        "risks": result.get("risks", []),
        "tests_run": False,
        "requires_human_review": True,
    }

