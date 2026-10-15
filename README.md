# spillway

[![tests](https://github.com/Kiwi172/spillway/actions/workflows/ci.yml/badge.svg)](https://github.com/Kiwi172/spillway/actions/workflows/ci.yml)

**Find the secrets that spilled onto your machine — not just the ones in
your repos.**

Your CI runs gitleaks, so the repo is clean. But the token you pasted into
a `curl` last Tuesday is still sitting in `~/.bash_history`. The Stripe key
in that abandoned project's `.env` is world-readable. The database password
is baked into a git remote URL. `~/.netrc`, `~/.git-credentials`, the
`.env.example` you copied a real value into — none of that is guarded by
anything.

```
   your workstation                          your CI
   ┌────────────────────────────┐            ┌──────────────────────┐
   │ ~/.bash_history            │            │                      │
   │ .env  .env.production      │   gitleaks │  the repo, on every  │
   │ ~/.netrc  ~/.git-credentials│  doesn't  │  push. ✅ guarded     │
   │ .git/config (remote URLs)  │   look ──▶ │                      │
   │ ~/.aws/credentials         │    here    └──────────────────────┘
   │ ~/.docker/config.json      │
   │ dotfiles, configs, history │
   └────────────────────────────┘
                  │
                  ▼  spillway: one pass, 26 rules, nothing installed
        file:line · rule · masked value · context
        --mask redacts in place, with a backup
```

Everything happens on your machine. No account, no upload, no network calls
at all — spillway never prints a secret in full, so you can paste its
output into a chat or a ticket.

---

## Install

Any machine with Python 3.9 or newer. There is nothing to build and nothing
to install:

```bash
curl -sO https://raw.githubusercontent.com/Kiwi172/spillway/main/spillway.py
chmod +x spillway.py
./spillway.py
```

Or, if you like it:

```bash
pipx install git+https://github.com/Kiwi172/spillway
```

## Use

With no arguments it scans the places secrets actually leak on a
workstation — shell histories, dotfiles in `$HOME`, `.env` files,
`.git/config` remotes, `~/.netrc`, `~/.aws/credentials`,
`~/.docker/config.json`, and friends:

```
$ spillway
spillway 0.1.0  ·  leak sites under /home/you

  HIGH   stripe-key  sk_liv…4xT2
         /home/you/shop/.env:12
         STRIPE_SECRET_KEY=sk_liv…4xT2

  MED    url-credentials  tr0…   (password embedded in a URL)
         /home/you/.git-credentials:1
         https://user:tr0…@github.com

2 secrets in 2 files (2 occurrences)  ·  scanned 61 files / 0.4 MB in 0.3s
```

Point it at anything instead:

```bash
spillway ~/projects                    # a whole tree
spillway --min-confidence low ~/notes  # also show heuristic guesses
spillway --json . | jq .findings       # machine-readable
```

And when you want the leak stopped, not just found:

```bash
$ spillway --mask --dry-run ~/projects   # show what would change
$ spillway --mask ~/projects             # redact in place
redacted /home/you/shop/.env  (backup: .env.spillway-bak)
```

`--mask` replaces every found value with `[redacted:spillway]` and keeps
one `.spillway-bak` copy per file, so it is always undoable.

## What it knows

26 rules in three confidence tiers (`--rules` prints the full list):

| tier | catches | how |
|---|---|---|
| **high** | GitHub, OpenAI, Anthropic, AWS, Google, Slack, Stripe, GitLab, Hugging Face, npm, PyPI, SendGrid, Twilio, DigitalOcean, Telegram, Sentry, JWTs, private-key blocks | unmistakable token prefixes |
| **medium** | passwords embedded in database/service URLs, AWS secret keys by name | structural patterns |
| **low** | `anything_secret = <20 chars>` | name heuristics + Shannon entropy, hidden unless you ask |

Repeated copies of the same token are collapsed into one finding with all
locations listed. Placeholders (`your-api-key-here`, `changeme`,
`postgres:postgres@localhost`) are filtered out. Values are masked
(`ghp_…9f3K`) in every output mode, including JSON.

Exit code is 0 normally, 1 with `--fail-found` when something was found —
so you can wire it into a cron job or a laptop-offboarding checklist.

## How it stays fast

Scanning a home directory means reading a lot of lines that will never
contain a secret. Two cheap gates run before any expensive regex:

1. a line with no token-shaped run, no URL, and no PEM marker is skipped
   outright;
2. each rule declares the literal prefixes it needs (`ghp_`, `sk-`,
   `AKIA`, …) — a line without one never runs that rule's regex.

On a 380 MB tree of recon output that is ~99% of the regex work skipped,
around 8–10 MB/s on one core of an ordinary laptop, in pure Python.

## Non-goals

- **Not a CI secret scanner.** For blocking leaks before they merge, use
  gitleaks or detect-secrets in a pre-commit hook. spillway audits the
  machine those tools never see.
- **Not a vault.** It finds and masks; it does not store or rotate.
- **Not exhaustive.** 26 rules cover the common providers; a random 32-char
  string used as a password with no name near it is invisible to everyone.

## Tests

```bash
python3 -m pytest tests/      # or: python3 tests/test_spillway.py
```

## License

MIT
