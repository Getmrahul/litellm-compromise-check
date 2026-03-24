# LiteLLM Compromise Check

Offline single-file CLI to check for known indicators from the malicious `litellm` `1.82.7` / `1.82.8` PyPI releases.

## Quick Run

```bash
curl -fsSLO https://raw.githubusercontent.com/Getmrahul/litellm-compromise-check/main/litellm_compromise_check.py
python3 litellm_compromise_check.py
```

Scan a repo or lockfile directory:

```bash
python3 litellm_compromise_check.py /path/to/repo
```

Fail CI on bad version references:

```bash
python3 litellm_compromise_check.py --repo-only /path/to/repo --strict-exit
```

## What It Checks

- installed `litellm` `1.82.7` / `1.82.8` package metadata
- `litellm_init.pth` in Python package directories
- cached LiteLLM wheels and tarballs in pip cache
- repo manifests and lockfiles for bad LiteLLM references
- community-reported persistence paths under `~/.config/sysmon`

## Exit Codes

- `0`: no critical machine indicators found
- `1`: critical indicator found, or any warning with `--strict-exit`
- `2`: invalid CLI usage

## Notes

- This script is offline and has no third-party dependencies.
- `1.82.8` and `litellm_init.pth` are publicly documented indicators.
- `1.82.7` and `~/.config/sysmon` checks are included as precautionary community-reported indicators.

Avoid `curl | bash`. Download the file first, then run it locally.
