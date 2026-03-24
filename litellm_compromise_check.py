#!/usr/bin/env python3
"""Offline checker for the reported LiteLLM 1.82.7/1.82.8 compromise."""

from __future__ import annotations

import argparse
import json
import os
import re
import site
import sys
import tarfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

BAD_VERSIONS = {"1.82.7", "1.82.8"}
CONFIRMED_IOCS = {
    "domains": ["models.litellm.cloud"],
    "pth_name": "litellm_init.pth",
}
COMMUNITY_REPORTED_IOCS = {
    "domains": ["checkmarx.zone"],
}
COMMUNITY_REPORTED_PATHS = [
    Path.home() / ".config" / "sysmon" / "sysmon.py",
    Path.home() / ".config" / "systemd" / "user" / "sysmon.service",
]
COMMON_ENV_ROOTS = [
    Path.home() / ".local",
    Path.home() / ".pyenv",
    Path.home() / ".virtualenvs",
    Path.home() / ".venvs",
    Path.home() / "venvs",
    Path.home() / ".cache" / "pypoetry" / "virtualenvs",
    Path.home() / ".local" / "share" / "virtualenvs",
]
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
MAX_SITE_SEARCH_DEPTH = 8
VERSION_RE = re.compile(r"^litellm-(?P<version>[0-9][A-Za-z0-9.\-+]*)\.dist-info$")
ARTIFACT_RE = re.compile(
    r"^litellm-(?P<version>1\.82\.(?:7|8))(?:[A-Za-z0-9_.\-+]*)\.(?:whl|zip|tar\.gz)$",
    re.IGNORECASE,
)
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
    parser.add_argument(
        "--strict-exit",
        action="store_true",
        help="Return exit code 1 for warnings as well as critical findings.",
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
        Path.cwd(),
    ]
    common_roots.extend(COMMON_ENV_ROOTS)
    common_roots.extend(extra_roots)
    for root in dedupe_paths(common_roots):
        if not root.exists():
            continue
        try:
            for current, dirnames, _filenames in os.walk(root):
                current_path = Path(current)
                try:
                    rel_parts = current_path.relative_to(root).parts
                except ValueError:
                    rel_parts = ()
                if current_path.name in {"site-packages", "dist-packages"}:
                    candidates.append(current_path)
                    dirnames[:] = []
                    continue
                if len(rel_parts) >= MAX_SITE_SEARCH_DEPTH:
                    dirnames[:] = []
        except (OSError, PermissionError):
            continue
    return dedupe_paths(candidates)


def inspect_site_dir(site_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not site_dir.exists():
        return findings

    pth = site_dir / CONFIRMED_IOCS["pth_name"]
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
                if CONFIRMED_IOCS["pth_name"] in text:
                    findings.append(
                        Finding(
                            kind="record-indicator",
                            severity="critical",
                            path=str(record),
                            detail=f"RECORD references {CONFIRMED_IOCS['pth_name']}.",
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
    for path in COMMUNITY_REPORTED_PATHS:
        if path.exists():
            findings.append(
                Finding(
                    kind="community-persistence",
                    severity="warning",
                    path=str(path),
                    detail="Found a community-reported persistence path. Treat this as suspicious, but not independently verified by the primary incident report.",
                )
            )
    return findings


def candidate_repo_env_dirs(extra_roots: Iterable[Path]) -> list[Path]:
    candidates: list[Path] = []
    env_dir_names = {".venv", "venv", "env"}
    for root in dedupe_paths(extra_roots):
        if not root.exists() or root.is_file():
            continue
        for name in env_dir_names:
            path = root / name
            if not path.exists() or not path.is_dir():
                continue
            for pattern in ("**/site-packages", "**/dist-packages"):
                candidates.extend(path.glob(pattern))
    return dedupe_paths(candidates)


def candidate_artifact_dirs(extra_roots: Iterable[Path]) -> list[Path]:
    candidates: list[Path] = [
        Path.home() / ".cache" / "pip",
        Path.home() / "Library" / "Caches" / "pip",
    ]
    if os.environ.get("PIP_CACHE_DIR"):
        candidates.append(Path(os.environ["PIP_CACHE_DIR"]))
    candidates.extend(extra_roots)
    return [path for path in dedupe_paths(candidates) if path.exists()]


def inspect_zip_artifact(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except (OSError, zipfile.BadZipFile):
        return findings

    if any(name.endswith(CONFIRMED_IOCS["pth_name"]) for name in names):
        findings.append(
            Finding(
                kind="cached-artifact",
                severity="critical",
                path=str(path),
                detail=f"Artifact contains {CONFIRMED_IOCS['pth_name']}.",
            )
        )
        return findings

    match = ARTIFACT_RE.match(path.name)
    if match:
        findings.append(
            Finding(
                kind="cached-artifact-version",
                severity="warning",
                path=str(path),
                detail=f"Artifact filename references reported malicious version {match.group('version')}.",
            )
        )
    return findings


def inspect_tar_artifact(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with tarfile.open(path) as archive:
            names = archive.getnames()
    except (OSError, tarfile.TarError):
        return findings

    if any(name.endswith(CONFIRMED_IOCS["pth_name"]) for name in names):
        findings.append(
            Finding(
                kind="cached-artifact",
                severity="critical",
                path=str(path),
                detail=f"Artifact contains {CONFIRMED_IOCS['pth_name']}.",
            )
        )
        return findings

    match = ARTIFACT_RE.match(path.name)
    if match:
        findings.append(
            Finding(
                kind="cached-artifact-version",
                severity="warning",
                path=str(path),
                detail=f"Artifact filename references reported malicious version {match.group('version')}.",
            )
        )
    return findings


def inspect_artifact_dir(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        for current, dirnames, filenames in os.walk(root):
            current_path = Path(current)
            try:
                rel_parts = current_path.relative_to(root).parts
            except ValueError:
                rel_parts = ()
            if len(rel_parts) >= MAX_SITE_SEARCH_DEPTH:
                dirnames[:] = []
            for filename in filenames:
                if not filename.startswith("litellm-") and filename != CONFIRMED_IOCS["pth_name"]:
                    continue
                path = current_path / filename
                if filename == CONFIRMED_IOCS["pth_name"]:
                    findings.append(
                        Finding(
                            kind="artifact-indicator",
                            severity="critical",
                            path=str(path),
                            detail=f"Found unpacked {CONFIRMED_IOCS['pth_name']} in an artifact directory.",
                        )
                    )
                    continue
                if filename.endswith((".whl", ".zip")):
                    findings.extend(inspect_zip_artifact(path))
                elif filename.endswith(".tar.gz"):
                    findings.extend(inspect_tar_artifact(path))
                else:
                    match = ARTIFACT_RE.match(filename)
                    if match:
                        findings.append(
                            Finding(
                                kind="cached-artifact-version",
                                severity="warning",
                                path=str(path),
                                detail=f"Artifact filename references reported malicious version {match.group('version')}.",
                            )
                        )
    except (OSError, PermissionError):
        findings.append(
            Finding(
                kind="scan-error",
                severity="info",
                path=str(root),
                detail="Could not fully inspect this artifact or cache directory.",
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
            elif CONFIRMED_IOCS["pth_name"] in line or any(
                domain in line for domain in CONFIRMED_IOCS["domains"]
            ):
                findings.append(
                    Finding(
                        kind="ioc-reference",
                        severity="critical",
                        path=f"{path}:{index}",
                        detail=line.strip()[:300],
                    )
                )
            elif any(domain in line for domain in COMMUNITY_REPORTED_IOCS["domains"]):
                findings.append(
                    Finding(
                        kind="community-ioc-reference",
                        severity="warning",
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


def print_human(
    findings: list[Finding],
    scanned_paths: list[Path],
    scanned_site_dirs: list[Path],
    scanned_artifact_dirs: list[Path],
) -> None:
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

    if scanned_artifact_dirs:
        print("Artifact/cache paths checked:")
        for path in scanned_artifact_dirs:
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
        print("  4. Check pip caches, repo-local virtualenvs, Docker images, and CI runners for cached malicious LiteLLM wheels.")
        print("  5. Search logs and infra for outbound traffic to the confirmed domain:")
        for domain in CONFIRMED_IOCS["domains"]:
            print(f"     - {domain}")
        if COMMUNITY_REPORTED_IOCS["domains"]:
            print("  6. Review community-reported domains as lower-confidence leads:")
            for domain in COMMUNITY_REPORTED_IOCS["domains"]:
                print(f"     - {domain}")
    elif status == "WARNING":
        print("  1. Update manifests and lockfiles to avoid LiteLLM 1.82.7 and 1.82.8.")
        print("  2. Verify no developer or CI environment ever installed those versions.")
        print("  3. Re-run this script inside repo-local virtualenvs, CI runners, containers, and pip caches that may have used the package.")
    else:
        print("  1. If you used LiteLLM recently, still verify your repo-local virtualenvs, CI logs, and ephemeral runners.")
        print("  2. Pin to a known-good version and prefer hash-locked installs for future releases.")


def main() -> int:
    args = parse_args()
    if args.site_only and args.repo_only:
        print("Choose either --site-only or --repo-only, not both.", file=sys.stderr)
        return 2

    repo_paths = dedupe_paths(Path(path) for path in args.paths)
    findings: list[Finding] = []
    site_dirs: list[Path] = []
    artifact_dirs: list[Path] = []
    visible_repo_paths = [] if args.site_only else repo_paths
    artifact_roots = repo_paths
    if args.site_only and repo_paths == [Path.cwd().resolve()]:
        artifact_roots = []

    if not args.repo_only:
        site_dirs = candidate_python_dirs(repo_paths)
        site_dirs.extend(candidate_repo_env_dirs(repo_paths))
        site_dirs = dedupe_paths(site_dirs)
        for site_dir in site_dirs:
            findings.extend(inspect_site_dir(site_dir))
        artifact_dirs = candidate_artifact_dirs(artifact_roots)
        for artifact_dir in artifact_dirs:
            findings.extend(inspect_artifact_dir(artifact_dir))
        findings.extend(inspect_persistence_paths())

    if not args.site_only:
        for repo_path in repo_paths:
            findings.extend(inspect_repo_path(repo_path))

    if args.json:
        payload = {
            "status": overall_status(findings),
            "repo_paths": [str(path) for path in visible_repo_paths],
            "python_paths": [str(path) for path in site_dirs],
            "artifact_paths": [str(path) for path in artifact_dirs],
            "findings": [asdict(finding) for finding in findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        print_human(findings, visible_repo_paths, site_dirs, artifact_dirs)
    status = overall_status(findings)
    if status == "CRITICAL":
        return 1
    if args.strict_exit and status == "WARNING":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
