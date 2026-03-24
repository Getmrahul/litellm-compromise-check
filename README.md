# LiteLLM Compromise Checker

Single-file offline CLI for the reported `litellm==1.82.7` / `1.82.8` compromise.

It checks:

- local Python package directories for `litellm_init.pth`
- installed `litellm-1.82.7.dist-info` / `litellm-1.82.8.dist-info`
- reported persistence paths under `~/.config/sysmon`
- repo manifests and lockfiles for bad LiteLLM references

## Usage

```bash
python3 litellm_compromise_check.py
python3 litellm_compromise_check.py /path/to/repo
python3 litellm_compromise_check.py --site-only
python3 litellm_compromise_check.py --json
```

Exit code:

- `0`: no critical machine indicators found
- `1`: critical machine indicator found
- `2`: invalid CLI usage

## Distribution

For this kind of incident, a Gist is easy to share but not ideal for trust. Better options:

- a tiny public GitHub repo with one script and a short README
- a signed release with the script checksum in the release notes
- copy-pasteable commands that download the file first, then run it separately

Avoid `curl | bash` here. Asking users to pipe remote code into a shell while responding to a supply-chain compromise is the wrong trust model.
