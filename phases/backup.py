"""
Phase VII — ADB Backup Analysis.

Creates an ADB backup, extracts it, and scans for sensitive data.
"""

from __future__ import annotations

import re
import subprocess
import zlib
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from core.config import Config, SENSITIVE_PATTERNS
from core.adb import ADB

console = Console()
PHASE = "Phase VII — ADB Backup Analysis"


def run_backup_analysis(config: Config, adb: ADB) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    pkg = config.package_name
    backup_ab = str(config.output_dir / "backup.ab")
    backup_tar = str(config.output_dir / "backup.tar")
    backup_dir = config.output_dir / "backup_unpacked"

    if config.auto_mode:
        is_logged_in = False
        console.print("[yellow]Auto-mode: assuming logged-out state for backup.[/yellow]")
    else:
        is_logged_in = Confirm.ask("Is the app currently logged in?", default=True)
    config.log_command(PHASE, "User confirmed login state", f"Logged in: {is_logged_in}")

    # ── Create ADB backup ──
    console.print("[cyan]Creating ADB backup (you may need to confirm on device)...[/cyan]")
    console.print("[yellow]  If prompted on device, tap 'Back up my data' (do NOT set a password).[/yellow]")

    result = adb.backup(pkg, backup_ab)
    config.log_command(
        PHASE,
        f"adb backup -apk -f {backup_ab} {pkg}",
        result.stdout,
        result.stderr,
    )
    if result.returncode != 0:
        console.print("[red]ADB backup command failed.[/red]")
        config.add_finding(
            PHASE,
            "ADB backup command failed",
            "Medium",
            f"adb backup returned non-zero exit code.\n\nstderr:\n{result.stderr or '(empty)'}",
        )
        return

    backup_path = Path(backup_ab)
    if not backup_path.exists() or backup_path.stat().st_size < 100:
        console.print("[yellow]Backup file is empty or missing — app may have android:allowBackup=false.[/yellow]")
        config.add_finding(
            PHASE,
            "ADB backup returned empty",
            "Info",
            "The backup file was empty. This may indicate allowBackup=false (good security practice) "
            "or the user did not confirm the backup on the device.",
        )
        return

    console.print(f"  [green]Backup created: {backup_path.stat().st_size} bytes[/green]")

    # ── Extract backup ──
    console.print("[cyan]Extracting backup...[/cyan]")
    extracted = _extract_backup(backup_ab, backup_tar, str(backup_dir))
    config.log_command(PHASE, f"extract {backup_ab} → {backup_dir}", "Extracted" if extracted else "Failed")

    if not extracted:
        # Try alternative extraction with ABE
        console.print("[yellow]Standard extraction failed. Trying alternative methods...[/yellow]")
        extracted = _extract_backup_abe(backup_ab, backup_tar, str(backup_dir))

    if not extracted:
        console.print("[yellow]Could not extract backup. Manual analysis required.[/yellow]")
        config.add_finding(
            PHASE,
            "Backup extraction failed",
            "Info",
            "Could not automatically extract the .ab backup file. "
            "Try manually with: java -jar abe.jar unpack backup.ab backup.tar",
        )
        return

    # ── Scan extracted backup for sensitive data ──
    console.print("[cyan]Scanning backup contents for sensitive data...[/cyan]")
    _scan_backup_contents(config, backup_dir)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _extract_backup(ab_path: str, tar_path: str, output_dir: str) -> bool:
    """Extract .ab backup by stripping 24-byte header and zlib decompressing payload."""
    try:
        raw = Path(ab_path).read_bytes()
        if len(raw) <= 24:
            return False
        payload = raw[24:]
        tar_bytes = zlib.decompress(payload)
        Path(tar_path).parent.mkdir(parents=True, exist_ok=True)
        Path(tar_path).write_bytes(tar_bytes)

        tar_file = Path(tar_path)
        if tar_file.exists() and tar_file.stat().st_size > 0:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            tar_result = subprocess.run(
                ["tar", "xf", tar_path, "-C", output_dir],
                timeout=60,
                capture_output=True,
            )
            if tar_result.returncode == 0:
                return True
    except (OSError, zlib.error, subprocess.TimeoutExpired):
        return False
    return False


def _extract_backup_abe(ab_path: str, tar_path: str, output_dir: str) -> bool:
    """Try extraction using Android Backup Extractor (abe.jar)."""
    try:
        result = subprocess.run(
            ["java", "-jar", "abe.jar", "unpack", ab_path, tar_path],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            return False
        if Path(tar_path).exists() and Path(tar_path).stat().st_size > 0:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            tar_result = subprocess.run(
                ["tar", "xf", tar_path, "-C", output_dir],
                timeout=60,
                capture_output=True,
            )
            if tar_result.returncode == 0:
                return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
    return False


def _scan_backup_contents(config: Config, backup_dir: Path) -> None:
    if not backup_dir.exists():
        return

    # Recursive grep
    try:
        result = subprocess.run(
            ["grep", "-rniE", SENSITIVE_PATTERNS, str(backup_dir)],
            capture_output=True, text=True, timeout=60,
        )
        if result.stdout.strip():
            lines = result.stdout.strip().splitlines()
            config.add_finding(
                PHASE,
                f"Sensitive data in ADB backup ({len(lines)} matches)",
                "High",
                f"Backup extraction revealed sensitive data:\n\n{result.stdout[:5000]}",
            )
            console.print(f"  [red]Found {len(lines)} sensitive match(es) in backup![/red]")

            backup_grep_path = config.output_dir / "backup_grep_results.txt"
            backup_grep_path.parent.mkdir(parents=True, exist_ok=True)
            backup_grep_path.write_text(result.stdout, encoding="utf-8")
        else:
            console.print("  [green]No obvious sensitive data in backup contents.[/green]")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check for specific file types
    for pattern in ["*.db", "*.sqlite", "*.xml", "*.json", "*.txt", "*.log"]:
        files = list(backup_dir.rglob(pattern))
        if files:
            config.log_command(
                PHASE,
                f"find backup -name '{pattern}'",
                "\n".join(str(f) for f in files[:50]),
            )
