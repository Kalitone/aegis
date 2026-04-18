"""
AEGIS YARA Rule Updater
==========================
Pulls community YARA rulesets into rules/yara/. Uses git when available,
falls back to tarball download via urllib if git is missing.

Sources (easy to extend):
  * Florian Roth — signature-base
  * YARA-Rules   — community
"""

import os
import sys
import shutil
import logging
import subprocess
import urllib.request
import tarfile
import tempfile
from pathlib import Path

logger = logging.getLogger("aegis.utils.rule_updater")


SOURCES = [
    {
        "name": "signature-base",
        "git": "https://github.com/Neo23x0/signature-base.git",
        "tarball": "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.tar.gz",
        "subdir": "yara",   # only this subtree contains .yar files
    },
    {
        "name": "community",
        "git": "https://github.com/Yara-Rules/rules.git",
        "tarball": "https://github.com/Yara-Rules/rules/archive/refs/heads/master.tar.gz",
        "subdir": "",
    },
]


def _have_git() -> bool:
    return shutil.which("git") is not None


def _clone_or_pull(repo_url: str, dest: Path):
    if dest.exists() and (dest / ".git").exists():
        logger.info(f"Pulling updates: {dest}")
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"],
                       check=True)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            shutil.rmtree(dest)
        logger.info(f"Cloning {repo_url} → {dest}")
        subprocess.run(["git", "clone", "--depth", "1", repo_url, str(dest)],
                       check=True)


def _download_tarball(url: str, dest: Path, subdir: str = ""):
    dest.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Downloading tarball {url}")
    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / "archive.tar.gz"
        with urllib.request.urlopen(url, timeout=60) as resp:
            tar_path.write_bytes(resp.read())
        with tarfile.open(tar_path) as t:
            t.extractall(tmp)
        # Move extracted root into place
        roots = [p for p in Path(tmp).iterdir() if p.is_dir() and p.name != "__pycache__"]
        if not roots:
            raise RuntimeError("Empty tarball")
        src = roots[0]
        if subdir:
            src = src / subdir
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)


def update(rules_dir: str = "rules/yara") -> dict:
    """
    Sync all sources into rules_dir/<source_name>/.
    Returns a dict of source name → status.
    """
    results: dict[str, str] = {}
    target_root = Path(rules_dir)
    target_root.mkdir(parents=True, exist_ok=True)

    for src in SOURCES:
        name = src["name"]
        dest = target_root / name
        try:
            if _have_git() and src.get("git"):
                _clone_or_pull(src["git"], dest)
            else:
                _download_tarball(src["tarball"], dest, src.get("subdir", ""))
            results[name] = f"ok — {dest}"
        except Exception as e:
            logger.error(f"Failed to update {name}: {e}")
            results[name] = f"error: {e}"

    return results


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else "rules/yara"
    results = update(rules_dir)
    print("\nRule update summary:")
    for name, status in results.items():
        print(f"  {name:20s} {status}")


if __name__ == "__main__":
    main()
