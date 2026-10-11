"""vibe-shipcheck: pre-publish security config check for vibe-coded apps.

One command that answers a single question before you ship:
"did my AI-generated app leave anything dangerous in the repo?"

Checks (all stdlib, no network, no dependencies):
  - .env files committed or unprotected by .gitignore
  - hardcoded provider secrets (AWS, GitHub, Stripe, OpenAI-style keys, PEM blocks)
  - generic hardcoded credentials (password= / api_key= with literal values)
  - exposed Supabase project URLs and service_role keys outside .env
  - Supabase migrations that CREATE TABLE without ENABLE ROW LEVEL SECURITY
  - wildcard CORS origins
  - DEBUG / development flags left on

Exit codes: 0 = clean (or warnings only), 1 = errors found.
With --strict, warnings also exit 1. Built for CI gates and pre-publish checklists.
"""

import argparse
import base64
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

ERROR = "error"
WARN = "warn"

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".next", ".nuxt", ".turbo", ".parcel-cache", ".svelte-kit",
}
MAX_FILE_BYTES = 1_000_000  # skip anything bigger (bundles, lockfiles, media)

PLACEHOLDER_HINTS = (
    "example", "your_", "xxx", "changeme", "placeholder",
    "fake", "dummy", "todo", "sample",
)


def looks_placeholder(value):
    """True when a secret-looking value is obviously a placeholder, not a leak."""
    v = value.strip().strip("\"'").lower()
    if not v or v in {"undefined", "null", "none", "true", "false"}:
        return True
    if "<" in v or ">" in v:  # <your-key-here>
        return True
    return any(h in v for h in PLACEHOLDER_HINTS)


def looks_like_reference(value):
    """True when the value reads from the environment instead of a literal secret."""
    v = value.lower()
    return any(h in v for h in (
        "process.env", "os.environ", "os.getenv", "getenv(",
        "${", "import.meta.env",
    ))


def make_finding(level, code, relpath, line, message, fix):
    return {
        "level": level,
        "code": code,
        "file": relpath,
        "line": line,
        "message": message,
        "fix": fix,
    }


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def iter_text_files(root):
    """Yield (relative_posix_path, absolute_path) for scannable text files."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for name in filenames:
            if name.endswith((".pyc", ".pyo")):
                continue
            abs_path = Path(dirpath) / name
            try:
                if abs_path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            rel = abs_path.relative_to(root).as_posix()
            yield rel, abs_path


def read_lines(abs_path):
    """Return list of lines, or None for binary/unreadable files."""
    try:
        with open(abs_path, "rb") as f:
            head = f.read(8192)
        if b"\x00" in head:
            return None
        with open(abs_path, "r", encoding="utf-8", errors="strict") as f:
            return f.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# Check 1: .env files
# ---------------------------------------------------------------------------

ENV_SAFE_SUFFIXES = (".example", ".sample", ".template")


def is_env_filename(name):
    return name == ".env" or name.startswith(".env.")


def is_safe_env_example(name):
    return any(name.endswith(s) for s in ENV_SAFE_SUFFIXES)


def _git_tracked_set(root):
    """Set of git-tracked relative posix paths, or None when git is unusable."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode != 0:
            return None
        return {p for p in out.stdout.split("\x00") if p}
    except (OSError, subprocess.SubprocessError):
        return None


def _git_ignored(root, relpath):
    """True when git says the path is ignored; None when git is unusable."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "-q", "--", relpath],
            capture_output=True, timeout=15,
        )
        return out.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return None


def _gitignore_covers(root, relpath):
    """Fallback .gitignore parse (basename + fnmatch) when git is unavailable."""
    gi = Path(root) / ".gitignore"
    if not gi.is_file():
        return False
    name = Path(relpath).name
    try:
        for line in gi.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            line = line.lstrip("/")
            if fnmatch.fnmatch(name, line) or fnmatch.fnmatch(relpath, line):
                return True
    except OSError:
        pass
    return False


def check_env_files(root, findings):
    tracked = _git_tracked_set(root)
    in_git_repo = tracked is not None
    for rel, abs_path in iter_text_files(root):
        name = Path(rel).name
        if not is_env_filename(name) or is_safe_env_example(name):
            continue
        if in_git_repo and rel in tracked:
            findings.append(make_finding(
                ERROR, "env-committed", rel, None,
                ".env file is tracked by git — its secrets ship with the repo",
                "Add it to .gitignore, run `git rm --cached %s`, rotate every key it held." % rel,
            ))
            continue
        ignored = _git_ignored(root, rel)
        if ignored is None:  # git unavailable -> manual .gitignore check
            ignored = _gitignore_covers(root, rel)
        if ignored:
            continue  # properly ignored local .env: fine
        if in_git_repo:
            findings.append(make_finding(
                WARN, "env-untracked", rel, None,
                ".env file is not git-ignored — one `git add .` away from being published",
                "Add `%s` to .gitignore before your next commit." % name,
            ))
        else:
            findings.append(make_finding(
                WARN, "env-unverified", rel, None,
                ".env file found but this is not a git repo — cannot verify it stays unpublished",
                "Keep secrets out of any folder you zip, upload, or deploy as source.",
            ))


# ---------------------------------------------------------------------------
# Check 2: hardcoded secrets
# ---------------------------------------------------------------------------

PROVIDER_PATTERNS = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github-token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}")),
    ("github-pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("stripe-key", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}")),
    ("stripe-webhook-secret", re.compile(r"whsec_[A-Za-z0-9]{20,}")),
    ("openai-key", re.compile(r"sk-proj-[A-Za-z0-9]{20,}")),
    ("openai-key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

GENERIC_CRED = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token)"
    r"\s*[:=]\s*[\"']?([^\"'\s#;,]{8,})"
)

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
SUPABASE_URL_RE = re.compile(r"https://[a-z0-9-]{1,63}\.supabase\.co")


def _jwt_role(token):
    """Return the JWT payload's role claim, or None when undecodable."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
        role = data.get("role")
        return role if isinstance(role, str) else None
    except Exception:
        return None


def check_secrets(root, findings):
    for rel, abs_path in iter_text_files(root):
        name = Path(rel).name
        if is_env_filename(name):
            continue  # .env contents are covered by check_env_files
        lines = read_lines(abs_path)
        if lines is None:
            continue
        for i, line in enumerate(lines, 1):
            for code, pattern in PROVIDER_PATTERNS:
                for m in pattern.finditer(line):
                    if looks_placeholder(m.group(0)):
                        continue
                    findings.append(make_finding(
                        ERROR, "hardcoded-secret", rel, i,
                        "%s looks hardcoded: %s" % (code, m.group(0)[:24] + "..."),
                        "Move it to an environment variable and rotate the key — it is compromised the moment this repo is public.",
                    ))
            for m in GENERIC_CRED.finditer(line):
                value = m.group(2)
                if looks_placeholder(value) or looks_like_reference(value):
                    continue
                findings.append(make_finding(
                    WARN, "hardcoded-credential", rel, i,
                    "literal credential assigned to `%s`" % m.group(1),
                    "Read it from the environment (os.environ / process.env) instead of hardcoding it.",
                ))
            for m in JWT_RE.finditer(line):
                token = m.group(0)
                role = _jwt_role(token)
                low = line.lower()
                if role == "service_role" or ("service_role" in low and "supabase" in low):
                    findings.append(make_finding(
                        ERROR, "supabase-service-key", rel, i,
                        "Supabase service_role key in source — bypasses all row-level security",
                        "service_role belongs only in server-side env vars, never in code. Rotate it in the Supabase dashboard.",
                    ))
                elif "supabase" in low:
                    findings.append(make_finding(
                        WARN, "supabase-token", rel, i,
                        "Supabase JWT in source — verify it is the anon key and RLS is enabled",
                        "Anon keys are public by design, but only safe behind row-level security. Run the RLS check below.",
                    ))


# ---------------------------------------------------------------------------
# Check 3: Supabase URL exposure + RLS
# ---------------------------------------------------------------------------

SUPABASE_USAGE_RE = re.compile(
    r"@supabase/supabase-js|supabase-py|createClient\s*\(|from\s+supabase\s+import",
)


def check_supabase(root, findings):
    url_hits = []
    usage_found = False
    for rel, abs_path in iter_text_files(root):
        lines = read_lines(abs_path)
        if lines is None:
            continue
        for i, line in enumerate(lines, 1):
            for m in SUPABASE_URL_RE.finditer(line):
                url_hits.append((rel, i, m.group(0)))
            if SUPABASE_USAGE_RE.search(line):
                usage_found = True
    for rel, i, url in url_hits:
        findings.append(make_finding(
            WARN, "supabase-url-exposed", rel, i,
            "Supabase project URL in source (%s)" % url,
            "The URL itself is public, but anyone with it + your anon key can query every table whose RLS is off. "
            "Verify RLS is enabled on all tables (see rls-disabled check).",
        ))
    return usage_found or bool(url_hits)


def check_rls(root, findings, supabase_used):
    sql_files = []
    for rel, abs_path in iter_text_files(root):
        if rel.lower().endswith(".sql"):
            sql_files.append((rel, abs_path))
    if not sql_files:
        if supabase_used:
            findings.append(make_finding(
                WARN, "rls-unverified", None, None,
                "Supabase usage detected but no .sql migrations found — RLS status could not be verified",
                "In the Supabase dashboard, open each table and confirm row-level security is ON. "
                "AI-generated migrations create tables with RLS OFF by default.",
            ))
        return
    create_table_re = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:\"?(\w+)\"?\.)?\"?(\w+)\"?",
        re.IGNORECASE,
    )
    for rel, abs_path in sql_files:
        lines = read_lines(abs_path)
        if lines is None:
            continue
        text = "\n".join(lines)
        tables = [t for _, t in create_table_re.findall(text)]
        if tables and "ENABLE ROW LEVEL SECURITY" not in text.upper():
            findings.append(make_finding(
                ERROR, "rls-disabled", rel, None,
                "migration creates table(s) %s without ENABLE ROW LEVEL SECURITY — readable by anyone with the anon key"
                % ", ".join(sorted(set(tables))),
                "Add `ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;` plus policies for every table, or enable RLS in the dashboard.",
            ))


# ---------------------------------------------------------------------------
# Check 4: CORS + DEBUG
# ---------------------------------------------------------------------------

CORS_PATTERNS = [
    ("cors-wildcard", re.compile(r"allow_origins\s*=\s*\[[^\]]*[\"']\*")),
    ("cors-wildcard", re.compile(r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True")),
    ("cors-wildcard", re.compile(r"Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*")),
]

DEBUG_PATTERNS = [
    ("debug-enabled", re.compile(r"(?m)^\s*DEBUG\s*=\s*True\b")),
    ("debug-enabled", re.compile(r"debug\s*=\s*True")),
    ("debug-enabled", re.compile(r"app\.debug\s*=\s*True")),
    ("debug-enabled", re.compile(r"FLASK_ENV\s*=\s*[\"']development[\"']")),
    ("debug-enabled", re.compile(r"NODE_ENV\s*=\s*[\"']development[\"']")),
]

CORS_FIX = ("Restrict origins to your own domains before publishing. "
            "Wildcard CORS lets any website make credentialed requests to your API.")
DEBUG_FIX = ("Turn debug/development mode off for anything public — "
             "it leaks stack traces, enables reloaders/debuggers, and often disables security defaults.")


def check_cors_debug(root, findings):
    for rel, abs_path in iter_text_files(root):
        lines = read_lines(abs_path)
        if lines is None:
            continue
        text = "\n".join(lines)
        for code, pattern in CORS_PATTERNS:
            for m in pattern.finditer(text):
                line_no = text[:m.start()].count("\n") + 1
                findings.append(make_finding(
                    WARN, code, rel, line_no,
                    "wildcard CORS origin — any website can call this API",
                    CORS_FIX,
                ))
        for code, pattern in DEBUG_PATTERNS:
            for m in pattern.finditer(text):
                if is_env_filename(Path(rel).name) and "development" in m.group(0):
                    continue  # dev-only .env is expected
                line_no = text[:m.start()].count("\n") + 1
                findings.append(make_finding(
                    WARN, code, rel, line_no,
                    "debug/development flag left on: `%s`" % m.group(0).strip()[:60],
                    DEBUG_FIX,
                ))


# ---------------------------------------------------------------------------
# Runner / CLI
# ---------------------------------------------------------------------------

def run_checks(root):
    """Run every check against root. Returns (findings, errors, warnings)."""
    root = str(Path(root).resolve())
    findings = []
    check_env_files(root, findings)
    check_secrets(root, findings)
    supabase_used = check_supabase(root, findings)
    check_rls(root, findings, supabase_used)
    check_cors_debug(root, findings)
    # stable order: errors first, then by file/line
    findings.sort(key=lambda f: (
        0 if f["level"] == ERROR else 1,
        f["file"] or "",
        f["line"] or 0,
        f["code"],
    ))
    errors = sum(1 for f in findings if f["level"] == ERROR)
    warnings = sum(1 for f in findings if f["level"] == WARN)
    return findings, errors, warnings


def render_text(root, findings, errors, warnings):
    out = ["vibe-shipcheck %s — pre-publish security check" % __version__,
           "Scanning: %s" % root, ""]
    for level, title in ((ERROR, "ERRORS"), (WARN, "WARNINGS")):
        group = [f for f in findings if f["level"] == level]
        if not group:
            continue
        out.append(title + ":")
        for f in group:
            loc = f["file"] or ""
            if f["line"]:
                loc += ":%d" % f["line"]
            out.append("  [%s] %s — %s" % (f["code"], loc, f["message"]))
            out.append("    fix: %s" % f["fix"])
        out.append("")
    out.append("%d error(s), %d warning(s)" % (errors, warnings))
    if errors:
        out.append("BLOCKED — fix the errors above before publishing.")
    elif warnings:
        out.append("WARN — shippable, but review the warnings above first.")
    else:
        out.append("PASS — nothing dangerous found. Safe to ship.")
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="vibe-shipcheck",
        description="Pre-publish security config check for vibe-coded apps.",
    )
    parser.add_argument("path", nargs="?", default=".",
                        help="repo/folder to scan (default: current directory)")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 on warnings too (for CI)")
    parser.add_argument("--version", action="store_true",
                        help="print version and exit")
    args = parser.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    root = str(Path(args.path).resolve())
    if not Path(root).is_dir():
        print("error: not a directory: %s" % args.path, file=sys.stderr)
        return 2

    findings, errors, warnings = run_checks(root)
    verdict = "blocked" if errors else ("warn" if warnings else "pass")

    if args.json:
        print(json.dumps({
            "tool": "vibe-shipcheck",
            "version": __version__,
            "path": root,
            "verdict": verdict,
            "errors": errors,
            "warnings": warnings,
            "findings": findings,
        }, indent=2))
    else:
        print(render_text(root, findings, errors, warnings))

    if errors:
        return 1
    if warnings and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
