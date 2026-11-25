#!/usr/bin/env python3
"""Automated static and unit-test security check for JellyHA."""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT / "custom_components" / "jellyha"
FRONTEND_DIR = ROOT / "src"

SECURITY_TESTS = [
    "tests/test_security.py",
    "tests/test_api_key_security.py",
    "tests/test_hls_security.py",
    "tests/test_views_auth.py",
    "tests/test_views_security.py",
    "tests/test_services_security.py",
    "tests/test_security_audit_fixes.py",
]


def _scan_files(base: pathlib.Path, glob: str, rules: list[tuple[str, re.Pattern[str], set[str]]]) -> list[str]:
    findings: list[str] = []
    for path in sorted(base.rglob(glob)):
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            for label, pattern, allowlist in rules:
                if rel in allowlist:
                    continue
                if pattern.search(line):
                    findings.append(f"[FAIL] {label} -> {rel}:{lineno}: {stripped[:120]}")
    return findings


def run_static_checks() -> list[str]:
    """Run JellyHA-specific and general static security checks."""
    py_rules: list[tuple[str, re.Pattern[str], set[str]]] = [
        ("Dangerous Python eval/exec", re.compile(r"\b(eval|exec)\s*\("), set()),
        ("Insecure pickle/marshal", re.compile(r"\b(pickle|marshal)\.loads?\s*\("), set()),
        ("Subprocess shell=True", re.compile(r"shell\s*=\s*True"), set()),
        ("TLS verification disabled", re.compile(r"(verify_ssl|ssl|verify)\s*=\s*False"), set()),
        (
            "Public Cache-Control on authenticated proxy view",
            re.compile(r'Cache-Control["\']\s*[:=]\s*["\']public\b', re.IGNORECASE),
            set(),
        ),
        (
            "Raw exception returned in HTTP 500 response",
            re.compile(r"web\.Response\s*\([^)]*status\s*=\s*500[^)]*str\s*\("),
            set(),
        ),
    ]

    ts_rules: list[tuple[str, re.Pattern[str], set[str]]] = [
        ("Dangerous DOM eval/Function", re.compile(r"\b(eval|new\s+Function|document\.write)\s*\("), set()),
        ("unsafeHTML directive usage", re.compile(r"\bunsafeHTML\s*\("), set()),
        (
            "Direct window.open outside safe-url.ts",
            re.compile(r"\bwindow\.open\s*\("),
            {"src/shared/safe-url.ts"},
        ),
        (
            "Raw Jellyfin API key extraction/forwarding in frontend",
            re.compile(r"[?&](?:api_key|ApiKey)="),
            set(),
        ),
    ]

    findings: list[str] = []
    findings.extend(_scan_files(BACKEND_DIR, "*.py", py_rules))
    findings.extend(_scan_files(FRONTEND_DIR, "*.ts", ts_rules))
    return findings


def run_security_tests() -> int:
    """Run all Python security unit test suites."""
    existing = [t for t in SECURITY_TESTS if (ROOT / t).exists()]
    if not existing:
        print("[WARN] No security test files found.")
        return 0
    cmd = [sys.executable, "-m", "unittest", *existing]
    print(f"Running {len(existing)} Python security test suites...")
    proc = subprocess.run(cmd, cwd=ROOT)
    return proc.returncode


def main() -> int:
    print("=== JellyHA Security Check ===")
    static_findings = run_static_checks()
    if static_findings:
        print("\nStatic security check failures:")
        for f in static_findings:
            print(" ", f)
    else:
        print("[OK] Static security checks passed (backend + frontend).")

    test_rc = run_security_tests()
    if test_rc == 0:
        print("[OK] Python security unit tests passed.")
    else:
        print("[FAIL] Python security unit tests failed.")

    if static_findings or test_rc != 0:
        return 1
    print("\nAll JellyHA security checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

