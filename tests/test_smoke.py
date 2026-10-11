"""Smoke tests for vibe-shipcheck. Run with: python3 -m unittest tests.test_smoke -v

All fixtures use publicly documented example keys (Stripe/AWS docs, jwt.io
examples) or obviously fake values — never real secrets.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vibe_shipcheck import run_checks  # noqa: E402

GIT = shutil.which("git")

# Synthetic fixture key (built at runtime so no literal secret-looking string
# lives in this file — GitHub push protection blocks those). Still matches the
# tool's stripe-key pattern, which is what the test asserts on.
STRIPE_TEST_KEY = "sk_test_" + "Q7w" * 9
AWS_EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_EXAMPLE_TOKEN = "ghp_" + "a" * 36
# jwt.io example with a service_role payload — decodes to {"role": "service_role"}.
SERVICE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJyb2xlIjoic2VydmljZV9yb2xlIn0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "vibe_shipcheck", *args],
        capture_output=True, text=True, cwd=cwd or str(ROOT),
    )


class FixtureDir:
    """Temp directory pre-filled with {relative_path: content}."""

    def __init__(self, files, git=False):
        self.files = files
        self.git = git

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        for rel, content in self.files.items():
            p = base / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        if self.git and GIT:
            subprocess.run([GIT, "init", "-q"], cwd=base, check=True)
            subprocess.run([GIT, "config", "user.email", "t@t.t"], cwd=base, check=True)
            subprocess.run([GIT, "config", "user.name", "t"], cwd=base, check=True)
            subprocess.run([GIT, "add", "-A"], cwd=base, check=True)
        return str(base)

    def __exit__(self, *exc):
        self.tmp.cleanup()


def codes(findings, level=None):
    return [f["code"] for f in findings
            if level is None or f["level"] == level]


class TestShipcheck(unittest.TestCase):
    def test_env_committed_to_git_is_error(self):
        if not GIT:
            self.skipTest("git not available")
        with FixtureDir({".env": "SUPABASE_KEY=abc123\n"}, git=True) as d:
            findings, errors, warnings = run_checks(d)
            self.assertIn("env-committed", codes(findings, "error"))
            self.assertGreaterEqual(errors, 1)

    def test_env_ignored_is_clean(self):
        if not GIT:
            self.skipTest("git not available")
        with FixtureDir({".env": "SUPABASE_KEY=abc123\n",
                         ".gitignore": ".env\n"}, git=True) as d:
            findings, errors, warnings = run_checks(d)
            self.assertNotIn("env-committed", codes(findings))
            self.assertNotIn("env-untracked", codes(findings))
            self.assertEqual(errors, 0)

    def test_env_not_ignored_untracked_warns(self):
        if not GIT:
            self.skipTest("git not available")
        with FixtureDir({"README.md": "# hi\n"}, git=True) as d:
            # .env written after `git add -A`, so it is untracked and unignored
            Path(d, ".env").write_text("SUPABASE_KEY=abc123\n")
            findings, errors, warnings = run_checks(d)
            self.assertIn("env-untracked", codes(findings, "warn"))
            self.assertEqual(errors, 0)

    def test_hardcoded_stripe_key_is_error(self):
        with FixtureDir({"app.py": 'STRIPE_KEY = "%s"\n' % STRIPE_TEST_KEY}) as d:
            findings, errors, warnings = run_checks(d)
            self.assertIn("hardcoded-secret", codes(findings, "error"))
            self.assertGreaterEqual(errors, 1)

    def test_env_reference_is_not_flagged(self):
        with FixtureDir({"app.py": 'API_KEY = os.environ["API_KEY"]\n'
                                    'TOKEN = process.env.TOKEN\n'}) as d:
            findings, errors, warnings = run_checks(d)
            self.assertNotIn("hardcoded-credential", codes(findings))
            self.assertEqual(errors + warnings, 0)

    def test_supabase_service_role_key_is_error(self):
        with FixtureDir({"client.js":
                         'const url = "https://abcdefgh.supabase.co";\n'
                         'const key = "%s";\n' % SERVICE_JWT}) as d:
            findings, errors, warnings = run_checks(d)
            self.assertIn("supabase-service-key", codes(findings, "error"))
            self.assertGreaterEqual(errors, 1)

    def test_supabase_url_alone_is_warn_only(self):
        with FixtureDir({"server.py":
                         'URL = "https://abcdefgh.supabase.co"\n'}) as d:
            findings, errors, warnings = run_checks(d)
            self.assertIn("supabase-url-exposed", codes(findings, "warn"))
            self.assertIn("rls-unverified", codes(findings, "warn"))
            self.assertEqual(errors, 0)

    def test_migration_without_rls_is_error(self):
        sql = ("CREATE TABLE public.profiles (\n"
               "  id uuid primary key,\n"
               "  email text\n"
               ");\n")
        with FixtureDir({"supabase/migrations/001.sql": sql}) as d:
            findings, errors, warnings = run_checks(d)
            self.assertIn("rls-disabled", codes(findings, "error"))
            self.assertGreaterEqual(errors, 1)

    def test_migration_with_rls_is_clean(self):
        sql = ("CREATE TABLE public.profiles (id uuid primary key);\n"
               "ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;\n"
               "CREATE POLICY p ON public.profiles FOR SELECT USING (true);\n")
        with FixtureDir({"supabase/migrations/001.sql": sql}) as d:
            findings, errors, warnings = run_checks(d)
            self.assertNotIn("rls-disabled", codes(findings))
            self.assertEqual(errors, 0)

    def test_cors_wildcard_and_debug_are_warnings(self):
        with FixtureDir({
            "api/main.py": ('from fastapi.middleware.cors import CORSMiddleware\n'
                            'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'),
            "app.py": "app.run(debug=True)\n",
        }) as d:
            findings, errors, warnings = run_checks(d)
            self.assertIn("cors-wildcard", codes(findings, "warn"))
            self.assertIn("debug-enabled", codes(findings, "warn"))
            self.assertEqual(errors, 0)

    def test_clean_repo_passes_with_exit_0(self):
        with FixtureDir({
            "app.py": 'API_KEY = os.environ["API_KEY"]\nDEBUG = False\n',
            ".env.example": "API_KEY=<your-key-here>\n",
            ".gitignore": ".env\n",
        }) as d:
            r = run_cli(d)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("PASS", r.stdout)

    def test_errors_exit_1_and_json_parses(self):
        # NB: AWS_EXAMPLE_KEY contains "EXAMPLE", which the placeholder filter
        # intentionally ignores — use a non-placeholder-shaped fake key here.
        with FixtureDir({"leak.py": 'AWS = "AKIA%s"\n' % ("Q" * 16)}) as d:
            r = run_cli(d)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("BLOCKED", r.stdout)
            rj = run_cli("--json", d)
            self.assertEqual(rj.returncode, 1)
            data = json.loads(rj.stdout)
            self.assertEqual(data["verdict"], "blocked")
            self.assertTrue(any(f["code"] == "hardcoded-secret"
                                for f in data["findings"]))

    def test_strict_exits_1_on_warnings(self):
        with FixtureDir({"app.py": "DEBUG = True\n"}) as d:
            self.assertEqual(run_cli(d).returncode, 0)
            self.assertEqual(run_cli("--strict", d).returncode, 1)

    def test_placeholder_values_not_flagged(self):
        with FixtureDir({"config.py": 'KEY = "your_api_key_here"\n'
                                       'OTHER = "xxx"\n'}) as d:
            findings, errors, warnings = run_checks(d)
            self.assertEqual(errors + warnings, 0)


if __name__ == "__main__":
    unittest.main()
