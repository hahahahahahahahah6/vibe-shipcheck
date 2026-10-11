# vibe-shipcheck

Your AI built the app in an afternoon. Did it leave the keys in the repo?

`vibe-shipcheck` is a pre-publish security checklist for vibe-coded apps: one command that scans your project for the exact misconfigurations that keep leaking real user data — committed `.env` files, hardcoded API keys, exposed Supabase URLs, migrations with row-level security off, wildcard CORS, and debug mode left on.

## Why this exists

In September 2026, security firm UpGuard told TechCrunch it had found **around 16,000 Supabase-hosted databases exposing personal data** — names, addresses, phone numbers, even passwords — queryable by anyone on the open web. The mechanism behind almost all of it: AI coding tools write SQL migrations directly, and in that path Postgres row-level security (RLS) defaults to **off**. A founder types a prompt, the AI ships a working app in an afternoon, and nobody ever flips the switch. ([TechCrunch](https://techcrunch.com/2026/09/25/some-supabase-customers-are-publicly-exposing-reams-of-peoples-data-to-the-web/))

This is not a hypothetical risk class. It is the single most common way vibe-coded apps get breached, and it happens **before** publish — the one moment when a 10-second check would have caught it.

## Install

Stdlib only. No dependencies, no network calls. Python 3.9+.

```bash
pip install vibe-shipcheck
```

Or run the single package without installing:

```bash
python -m vibe_shipcheck /path/to/your/app
```

## Usage

```bash
vibe-shipcheck [path] [--json] [--strict]
```

Point it at your project folder (defaults to the current directory):

```bash
$ vibe-shipcheck ./my-lovable-app
vibe-shipcheck 0.1.0 — pre-publish security check
Scanning: /home/hao/my-lovable-app

ERRORS:
  [env-committed] .env — .env file is tracked by git — its secrets ship with the repo
    fix: Add it to .gitignore, run `git rm --cached .env`, rotate every key it held.
  [rls-disabled] supabase/migrations/001_init.sql — migration creates table(s) profiles without ENABLE ROW LEVEL SECURITY — readable by anyone with the anon key
    fix: Add `ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;` plus policies for every table, or enable RLS in the dashboard.

WARNINGS:
  [supabase-url-exposed] src/lib/supabase.ts:3 — Supabase project URL in source (https://<project-ref>.supabase.co)
    fix: The URL itself is public, but anyone with it + your anon key can query every table whose RLS is off. Verify RLS is enabled on all tables (see rls-disabled check).
  [cors-wildcard] api/main.py:12 — wildcard CORS origin — any website can call this API
    fix: Restrict origins to your own domains before publishing. Wildcard CORS lets any website make credentialed requests to your API.

2 error(s), 2 warning(s)
BLOCKED — fix the errors above before publishing.
```

Every finding comes with a **fix line** telling you exactly what to do. Exit codes: **0** clean (or warnings only), **1** errors found — drop it straight into CI or a pre-publish script:

```bash
vibe-shipcheck ./my-app || echo "not shippable yet"
```

`--strict` also exits 1 on warnings (the mode you want in CI). `--json` emits machine-readable findings.

### What it checks

| Level | Code | Meaning |
|-------|------|---------|
| ERROR | `env-committed` | `.env` file is tracked by git — secrets ship with the repo |
| ERROR | `hardcoded-secret` | Provider key hardcoded in source (AWS, GitHub, Stripe, OpenAI-style, PEM blocks) |
| ERROR | `supabase-service-key` | `service_role` key in source — bypasses all row-level security |
| ERROR | `rls-disabled` | SQL migration creates tables without `ENABLE ROW LEVEL SECURITY` |
| WARN | `env-untracked` | `.env` exists but isn't git-ignored — one `git add .` from leaking |
| WARN | `hardcoded-credential` | Literal `password=` / `api_key=` instead of reading from the environment |
| WARN | `supabase-url-exposed` | Supabase project URL in source — reminder to verify RLS |
| WARN | `supabase-token` | Supabase JWT in source — verify it's the anon key, not `service_role` |
| WARN | `rls-unverified` | Supabase used but no migration SQL found to verify RLS against |
| WARN | `cors-wildcard` | Wildcard CORS origin (`allow_origins=["*"]`, `Access-Control-Allow-Origin: *`, …) |
| WARN | `debug-enabled` | `DEBUG=True`, `debug=True`, or dev `NODE_ENV`/`FLASK_ENV` left on |

Placeholder values (`your_key_here`, `xxx`, `<...>`, `AKIA…EXAMPLE`) and proper env references (`os.environ[…]`, `process.env.…`) are never flagged. `.env.example` files are skipped.

## Differentiation

General scanners (Trivy, Gitleaks, Semgrep) scan for **vulnerabilities in code**. `vibe-shipcheck` owns a different moment: the **pre-publish checklist** for apps that were generated, not written.

- **Vibe-coding failure modes, not CVE patterns.** Nobody hand-writing an app forgets RLS on every table; AI tools do it by default because they emit raw `CREATE TABLE` migrations. `vibe-shipcheck` checks the migration files, decodes Supabase JWTs to tell `anon` from `service_role`, and distinguishes a committed `.env` from an ignored one — the exact mistakes UpGuard keeps finding in the wild.
- **Fix lines, not just findings.** Every hit tells a non-security-expert founder what to do in one sentence. The audience is someone who prompted an app into existence, not someone who reads CVE feeds.
- **Ten seconds, zero config.** No rules to write, no baseline to tune, no account. `pip install vibe-shipcheck && vibe-shipcheck .` — it belongs in the same breath as "deploy".

Use both: Gitleaks in CI for deep secret history, `vibe-shipcheck` as the gate right before you hit publish.

## Limitations

- The RLS check is per migration file: a file with `CREATE TABLE` and no `ENABLE ROW LEVEL SECURITY` is flagged. Tables secured via the Supabase dashboard (not migrations) can't be verified from the repo — enable RLS there and the `rls-unverified` warning goes quiet.
- Heuristic secret detection trades recall for precision; it will not catch every exotic key format.

## License

MIT — see [LICENSE](LICENSE).
