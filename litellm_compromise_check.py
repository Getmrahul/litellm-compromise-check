#!/usr/bin/env python3
"""Offline checker for the reported LiteLLM 1.82.7/1.82.8 compromise."""

from __future__ import annotations

import argparse
import json
import os
import re
import site
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

BAD_VERSIONS = {"1.82.7", "1.82.8"}
SUSPICIOUS_FILENAMES = {
    "litellm_init.pth",
    "sysmon.py",
    "sysmon.service",
}
SUSPICIOUS_PATHS = [
    Path.home() / ".config" / "sysmon" / "sysmon.py",
    Path.home() / ".config" / "systemd" / "user" / "sysmon.service",
]
IOCS = {
    "domains": ["models.litellm.cloud", "checkmarx.zone"],
    "k8s_namespace_hint": "kube-system",
    "k8s_pod_prefix_hint": "node-setup-",
}
MANIFEST_PATTERNS = [
    "requirements*.txt",
    "constraints*.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "uv.lock",
    "pdm.lock",
    "setup.py",
    "setup.cfg",
]
TEXT_BYTES_LIMIT = 2 * 1024 * 1024
VERSION_RE = re.compile(r"^litellm-(?P<version>[0-9][A-Za-z0-9.\-+]*)\.dist-info$")
BAD_REF_RE = re.compile(
    r"(?i)\blitellm\s*(?:==|===|>=|<=|~=|!=|>|<)?\s*(1\.82\.7|1\.82\.8)\b"
)


@dataclass
class Finding:
    kind: str
    severity: str
    path: str
    detail: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check for signs of the reported LiteLLM 1.82.7/1.82.8 compromise."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Repo or directory paths to scan for dependency references. Defaults to the current directory.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print findings as JSON.",
    )
    parser.add_argument(
        "--site-only",
        action="store_true",
        help="Only inspect local Python environments and persistence paths.",
    )
    parser.add_argument(
        "--repo-only",
        action="store_true",
        help="Only scan the supplied paths for dependency references.",
    )
    return parser.parse_args()


def dedupe_paths(paths: Iterable[Path]) -> list[Path]:
    seen: set[str] = set()
    ordered: list[Path] = []
    for path in paths:
        try:
            resolved = str(path.expanduser().resolve())
        except OSError:
            resolved = str(path.expanduser())
        if resolved in seen:
            continue
        seen.add(resolved)
        ordered.append(Path(resolved))
    return ordered


def candidate_python_dirs(extra_roots: Iterable[Path]) -> list[Path]:
    candidates: list[Path] = []
    for getter in (site.getusersitepackages,):
        try:
            value = getter()
        except Exception:
            continue
        if isinstance(value, str):
            candidates.append(Path(value))
    try:
        candidates.extend(Path(p) for p in site.getsitepackages())
    except Exception:
        pass
    for entry in sys.path:
        if "site-packages" in entry or "dist-packages" in entry:
            candidates.append(Path(entry))

    common_roots = [
        Path.home() / ".local",
        Path.home() / ".pyenv",
        Path.home() / ".virtualenvs",
        Path.cwd(),
    ]
    common_roots.extend(extra_roots)
    for root in dedupe_paths(common_roots):
        if not root.exists():
            continue
        try:
            for child in root.rglob("*"):
                if not child.is_dir():
                    continue
                if child.name not in {"site-packages", "dist-packages"}:
                    continue
                rel_parts = child.relative_to(root).parts
                if len(rel_parts) > 8:
                    continue
                candidates.append(child)
        except (OSError, PermissionError):
            continue
    return dedupe_paths(candidates)


def inspect_site_dir(site_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not site_dir.exists():
        return findings

    pth = site_dir / "litellm_init.pth"
    if pth.exists():
        findings.append(
            Finding(
                kind="startup-hook",
                severity="critical",
                path=str(pth),
                detail="Found litellm_init.pth in a Python packages directory.",
            )
        )

    try:
        for entry in site_dir.iterdir():
            match = VERSION_RE.match(entry.name)
            if not match:
                continue
            version = match.group("version")
            if version not in BAD_VERSIONS:
                continue
            findings.append(
                Finding(
                    kind="installed-version",
                    severity="critical",
                    path=str(entry),
                    detail=f"Installed LiteLLM version {version} matches a reported malicious release.",
                )
            )
            record = entry / "RECORD"
            if record.exists():
                try:
                    text = record.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    text = ""
                if "litellm_init.pth" in text:
                    findings.append(
                        Finding(
                            kind="record-indicator",
                            severity="critical",
                            path=str(record),
                            detail="RECORD references litellm_init.pth.",
                        )
                    )
    except (OSError, PermissionError):
        findings.append(
            Finding(
                kind="scan-error",
                severity="info",
                path=str(site_dir),
                detail="Could not fully inspect this Python packages directory.",
            )
        )
    return findings


def inspect_persistence_paths() -> list[Finding]:
    findings: list[Finding] = []
    for path in SUSPICIOUS_PATHS:
        if path.exists():
            findings.append(
                Finding(
                    kind="persistence",
                    severity="critical",
                    path=str(path),
                    detail="Found a file matching a reported persistence path.",
                )
            )
    return findings


def looks_textual(path: Path) -> bool:
    try:
        if path.stat().st_size > TEXT_BYTES_LIMIT:
            return False
        with path.open("rb") as handle:
            chunk = handle.read(4096)
    except (OSError, PermissionError):
        return False
    return b"\x00" not in chunk


def iter_manifest_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    if not root.exists():
        return
    for pattern in MANIFEST_PATTERNS:
        yield from root.rglob(pattern)


def inspect_repo_path(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for path in iter_manifest_files(root):
        resolved = str(path.resolve())
        if resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        if not looks_textual(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            continue
        for index, line in enumerate(text.splitlines(), start=1):
            if BAD_REF_RE.search(line):
                findings.append(
                    Finding(
                        kind="repo-reference",
                        severity="warning",
                        path=f"{path}:{index}",
                        detail=line.strip()[:300],
                    )
                )
            elif "litellm_init.pth" in line or any(domain in line for domain in IOCS["domains"]):
                findings.append(
                    Finding(
                        kind="ioc-reference",
                        severity="critical",
                        path=f"{path}:{index}",
                        detail=line.strip()[:300],
                    )
                )
    return findings


def overall_status(findings: list[Finding]) -> str:
    severities = {finding.severity for finding in findings}
    if "critical" in severities:
        return "CRITICAL"
    if "warning" in severities:
        return "WARNING"
    return "OK"


def print_human(findings: list[Finding], scanned_paths: list[Path], scanned_site_dirs: list[Path]) -> None:
    status = overall_status(findings)
    print(f"LiteLLM compromise check: {status}")
    print()

    if scanned_site_dirs:
        print("Python environment paths checked:")
        for path in scanned_site_dirs:
            print(f"  - {path}")
        print()

    if scanned_paths:
        print("Repo paths checked:")
        for path in scanned_paths:
            print(f"  - {path}")
        print()

    if findings:
        print("Findings:")
        for finding in findings:
            print(f"  - [{finding.severity.upper()}] {finding.kind}: {finding.path}")
            print(f"    {finding.detail}")
    else:
        print("No direct indicators were found.")
        print("This is not a guarantee of safety; it only checks the known public indicators.")

    print()
    print("Recommended next steps:")
    if status == "CRITICAL":
        print("  1. Treat the machine or environment as exposed if the bad package or litellm_init.pth was present.")
        print("  2. Remove the malicious package or environment before reusing it.")
        print("  3. Rotate secrets that may have been present: env vars, SSH keys, cloud credentials, kube tokens, CI tokens.")
        print("  4. Check for persistence files under ~/.config/sysmon and ~/.config/systemd/user.")
        print("  5. Search logs and infra for outbound traffic to the reported domains:")
        for domain in IOCS["domains"]:
            print(f"     - {domain}")
    elif status == "WARNING":
        print("  1. Update manifests and lockfiles to avoid LiteLLM 1.82.7 and 1.82.8.")
        print("  2. Verify no developer or CI environment ever installed those versions.")
        print("  3. Re-run this script inside any virtualenvs, CI runners, or containers that may have used the package.")
    else:
        print("  1. If you used LiteLLM recently, still verify your CI logs, virtualenvs, and ephemeral runners.")
        print("  2. Pin to a known-good version and prefer hash-locked installs for future releases.")


def main() -> int:
    args = parse_args()
    if args.site_only and args.repo_only:
        print("Choose either --site-only or --repo-only, not both.", file=sys.stderr)
        return 2

    repo_paths = dedupe_paths(Path(path) for path in args.paths)
    findings: list[Finding] = []
    site_dirs: list[Path] = []
    visible_repo_paths = [] if args.site_only else repo_paths

    if not args.repo_only:
        site_dirs = candidate_python_dirs(repo_paths)
        for site_dir in site_dirs:
            findings.extend(inspect_site_dir(site_dir))
        findings.extend(inspect_persistence_paths())

    if not args.site_only:
        for repo_path in repo_paths:
            findings.extend(inspect_repo_path(repo_path))

    if args.json:
        payload = {
            "status": overall_status(findings),
            "repo_paths": [str(path) for path in visible_repo_paths],
            "python_paths": [str(path) for path in site_dirs],
            "findings": [asdict(finding) for finding in findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        print_human(findings, visible_repo_paths, site_dirs)
    return 1 if overall_status(findings) == "CRITICAL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
