"""Tests for spillway. Run with: python3 -m pytest tests/ (or python3 tests/test_spillway.py)"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parent.parent / "spillway.py")

GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"  # 40 chars, valid shape
OPENAI_KEY = "sk-" + "Zk9xQ7wV3uT1sR5pO8nM6kI4gE2cA0bD8fH6jL4nP2qS"
AWS_ID = "AKIA" + "Q7ZR8T3HJKLMNP2W"


def run(*argv, cwd=None):
    return subprocess.run(
        [sys.executable, TOOL, *argv], capture_output=True, text=True, cwd=cwd)


def write(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def make_tree(tmp: Path):
    write(tmp / ".bash_history",
          f"git clone https://user:{GH_TOKEN}@github.com/acme/secret.git\n"
          "ls\n")
    write(tmp / "proj/.env",
          f"OPENAI_API_KEY={OPENAI_KEY}\nDATABASE_URL=postgres://app:s3cr3t@db:5432/app\n")
    write(tmp / "proj/.git/config",
          f"[remote \"origin\"]\n\turl = https://x-access:{GH_TOKEN}@github.com/acme/secret.git\n")
    write(tmp / "clean/notes.txt", "nothing to see here, just prose.\n")
    write(tmp / "bin/blob", "ghp_\x00\x00not text " + GH_TOKEN)
    return tmp


def test_finds_history_and_env(tmp_path):
    make_tree(tmp_path)
    r = run(str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "github-token" in r.stdout
    assert "openai-key" in r.stdout
    assert "url-credentials" in r.stdout
    assert "clean" not in r.stdout


def test_dedupes_same_token_across_files(tmp_path):
    make_tree(tmp_path)
    r = run("--json", str(tmp_path))
    data = json.loads(r.stdout)
    gh = [f for f in data["findings"] if f["rule"] == "github-token"]
    assert len(gh) == 1                      # one finding...
    assert len(gh[0]["occurrences"]) == 2    # ...reported with both copies


def test_value_is_never_printed_in_full(tmp_path):
    make_tree(tmp_path)
    r = run(str(tmp_path))
    assert GH_TOKEN not in r.stdout
    assert OPENAI_KEY not in r.stdout


def test_placeholders_rejected(tmp_path):
    write(tmp_path / ".env",
          "API_KEY=your-api-key-here\nTOKEN=sk-xxxxxxxxxxxxxxxxxxxxxxxxxx\n"
          f"REAL={OPENAI_KEY}\n")
    r = run("--json", str(tmp_path))
    data = json.loads(r.stdout)
    rules = [f["rule"] for f in data["findings"]]
    assert "openai-key" in rules
    assert not any("your-api-key" in json.dumps(f) for f in data["findings"])


def test_binary_and_oversize_skipped(tmp_path):
    make_tree(tmp_path)
    write(tmp_path / "big.txt", ("x" * 100 + GH_TOKEN) * 40000)  # >2MB
    r = run("--json", str(tmp_path))
    data = json.loads(r.stdout)
    files = {o["file"] for f in data["findings"] for o in f["occurrences"]}
    assert not any("blob" in f for f in files)
    assert not any("big.txt" in f for f in files)


def test_mask_rewrites_and_backs_up(tmp_path):
    make_tree(tmp_path)
    hist = tmp_path / ".bash_history"
    before = hist.read_text()
    r = run("--mask", str(tmp_path))
    assert r.returncode == 0, r.stderr
    after = hist.read_text()
    assert GH_TOKEN not in after
    assert "[redacted:spillway]" in after
    assert (tmp_path / ".bash_history.spillway-bak").read_text() == before
    # second run finds nothing new in masked files
    r2 = run("--json", str(tmp_path))
    data = json.loads(r2.stdout)
    assert not [f for f in data["findings"]
                if f["rule"] == "github-token"
                and any(".bash_history" == Path(o["file"]).name
                        for o in f["occurrences"])]


def test_min_confidence_gates_generic_rules(tmp_path):
    write(tmp_path / "cfg", "client_secret = Qw8zX2vN7bM4lK9pJ3hG6fD1sA0cV5tB\n")
    lo = run("--min-confidence", "low", "--json", str(tmp_path))
    med = run("--json", str(tmp_path))
    assert "generic-assignment" in lo.stdout
    assert "generic-assignment" not in med.stdout


def test_fail_found_exit_code(tmp_path):
    make_tree(tmp_path)
    assert run("--fail-found", str(tmp_path)).returncode == 1
    write(tmp_path / "empty", "hello world\n")
    assert run("--fail-found", str(tmp_path / "empty")).returncode == 0


def test_rules_listing():
    r = run("--rules")
    assert r.returncode == 0
    assert "github-token" in r.stdout and "private-key-block" in r.stdout


if __name__ == "__main__":
    import tempfile
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            import inspect
            if inspect.signature(fn).parameters:
                with tempfile.TemporaryDirectory() as d:
                    try:
                        fn(Path(d))
                        print(f"  ok  {name}")
                    except AssertionError as e:
                        failed += 1
                        print(f"FAIL  {name}: {e}")
            else:
                fn()
                print(f"  ok  {name}")
    sys.exit(1 if failed else 0)
