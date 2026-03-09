"""
Phase III — Local File System Analysis.

Pulls the app's data directory from the device and scans for sensitive data
in shared preferences, databases, internal files, cache, and external storage.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from core.config import Config, SENSITIVE_PATTERNS
from core.adb import ADB

console = Console()
PHASE = "Phase III — Local File System Analysis"


def run_filesystem_analysis(config: Config, adb: ADB) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    pkg = config.package_name
    device_base = adb.get_app_data_path(pkg)
    local_base = config.output_dir / "filesystem"
    local_base.mkdir(parents=True, exist_ok=True)

    rooted = adb.is_rooted()
    if rooted:
        console.print("  [green]Device is rooted — using root shell to pull app data.[/green]")
    else:
        console.print("  [yellow]Device is not rooted — pull may fail for /data/data/ paths.[/yellow]")

    # Paths under /data/data require root; /sdcard paths do not.
    root_targets = [
        (f"{device_base}/shared_prefs/", str(local_base / "shared_prefs")),
        (f"{device_base}/databases/", str(local_base / "databases")),
        (f"{device_base}/files/", str(local_base / "files")),
        (f"{device_base}/cache/", str(local_base / "cache")),
        (f"{device_base}/app_webview/", str(local_base / "app_webview")),
    ]
    non_root_targets = [
        (f"/sdcard/Android/data/{pkg}/", str(local_base / "external")),
    ]

    for remote, local in root_targets:
        console.print(f"  [cyan]Pulling (root):[/cyan] {remote}")
        Path(local).mkdir(parents=True, exist_ok=True)
        try:
            if rooted:
                result = adb.pull_as_root(remote, local)
            else:
                result = adb.pull(remote, local)
            config.log_command(PHASE, f"adb pull {remote} {local}", result)
            file_count = sum(1 for _ in Path(local).rglob("*") if _.is_file())
            if file_count > 0:
                console.print(f"    [green]Pulled {file_count} file(s)[/green]")
            else:
                console.print(f"    [yellow]Directory empty or inaccessible[/yellow]")
        except Exception as e:
            console.print(f"    [yellow]Could not pull {remote}: {e}[/yellow]")
            config.log_command(PHASE, f"adb pull {remote} {local}", "", str(e))

    for remote, local in non_root_targets:
        console.print(f"  [cyan]Pulling:[/cyan] {remote}")
        Path(local).mkdir(parents=True, exist_ok=True)
        try:
            result = adb.pull(remote, local)
            config.log_command(PHASE, f"adb pull {remote} {local}", result)
        except Exception as e:
            console.print(f"    [yellow]Could not pull {remote}: {e}[/yellow]")
            config.log_command(PHASE, f"adb pull {remote} {local}", "", str(e))

    # ── Also pull entire data dir for completeness ──
    console.print(f"  [cyan]Pulling full data directory (root)...[/cyan]")
    try:
        if rooted:
            full_pull = adb.pull_as_root(f"{device_base}/", str(local_base / "full_data"))
        else:
            full_pull = adb.pull(f"{device_base}/", str(local_base / "full_data"))
        config.log_command(PHASE, f"adb pull {device_base}/ {local_base}/full_data", full_pull)
    except Exception:
        pass

    # ── Grep scan for sensitive data ──
    console.print("\n[cyan]Scanning pulled files for sensitive data...[/cyan]")
    grep_results = _grep_sensitive(str(local_base))

    grep_output_path = config.output_dir / "grep_results.txt"
    grep_output_path.parent.mkdir(parents=True, exist_ok=True)
    grep_output_path.write_text(grep_results, encoding="utf-8")
    config.log_command(PHASE, f"grep -rniE '<patterns>' {local_base}", grep_results)

    if grep_results.strip():
        lines = grep_results.strip().splitlines()
        config.add_finding(
            PHASE,
            f"Sensitive data found in local storage ({len(lines)} matches)",
            "High",
            grep_results[:5000],
        )
        console.print(f"  [red]Found {len(lines)} sensitive data match(es) — saved to grep_results.txt[/red]")
    else:
        console.print("  [green]No obvious sensitive data patterns found in pulled files.[/green]")

    # ── SQLite database analysis ──
    _analyze_databases(config, str(local_base))

    # ── Shared preferences analysis ──
    _analyze_shared_prefs(config, str(local_base / "shared_prefs"))

    # ── NoSQL / Realm analysis ──
    _analyze_nosql(config, adb, pkg, str(local_base))

    # ── File permission analysis ──
    _check_file_permissions(config, adb, pkg)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _grep_sensitive(directory: str) -> str:
    try:
        result = subprocess.run(
            ["grep", "-rniE", SENSITIVE_PATTERNS, directory],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _analyze_databases(config: Config, base_dir: str) -> None:
    console.print("\n[cyan]Analyzing SQLite databases...[/cyan]")
    db_dir = Path(base_dir) / "databases"
    if not db_dir.exists():
        console.print("  [yellow]No databases directory found.[/yellow]")
        return

    db_files = list(db_dir.glob("*.db")) + list(db_dir.glob("*.sqlite")) + list(db_dir.glob("*.sqlite3"))
    # Also check for journal-less databases
    for f in db_dir.iterdir():
        if f.is_file() and f.suffix not in [".journal", ".wal", ".shm", "-journal", "-wal", "-shm"]:
            if f not in db_files:
                db_files.append(f)

    if not db_files:
        console.print("  [yellow]No database files found.[/yellow]")
        return

    for db_file in db_files:
        console.print(f"  [cyan]Analyzing:[/cyan] {db_file.name}")
        try:
            # List tables
            tables_result = subprocess.run(
                ["sqlite3", str(db_file), ".tables"],
                capture_output=True, text=True, timeout=10,
            )
            tables = tables_result.stdout.strip()
            config.log_command(PHASE, f"sqlite3 {db_file.name} '.tables'", tables)

            if not tables:
                continue

            # Dump schema
            schema_result = subprocess.run(
                ["sqlite3", str(db_file), ".schema"],
                capture_output=True, text=True, timeout=10,
            )
            config.log_command(PHASE, f"sqlite3 {db_file.name} '.schema'", schema_result.stdout)

            # Full dump and grep
            dump_result = subprocess.run(
                ["sqlite3", str(db_file), ".dump"],
                capture_output=True, text=True, timeout=30,
            )

            # Save full dump
            dump_path = config.output_dir / f"db_dump_{db_file.name}.sql"
            dump_path.parent.mkdir(parents=True, exist_ok=True)
            dump_path.write_text(dump_result.stdout, encoding="utf-8")

            sensitive_in_db = _grep_string(dump_result.stdout)
            if sensitive_in_db:
                config.add_finding(
                    PHASE,
                    f"Sensitive data in database: {db_file.name}",
                    "High",
                    f"Tables: {tables}\n\nSensitive matches:\n{sensitive_in_db[:3000]}",
                )
                console.print(f"    [red]Sensitive data found in {db_file.name}[/red]")
        except FileNotFoundError:
            console.print("  [yellow]sqlite3 not available — skipping DB analysis.[/yellow]")
            break
        except Exception as e:
            console.print(f"  [yellow]Error analyzing {db_file.name}: {e}[/yellow]")


def _analyze_shared_prefs(config: Config, prefs_dir: str) -> None:
    console.print("\n[cyan]Analyzing shared preferences...[/cyan]")
    prefs_path = Path(prefs_dir)
    if not prefs_path.exists():
        console.print("  [yellow]No shared_prefs directory found.[/yellow]")
        return

    xml_files = list(prefs_path.glob("*.xml"))
    if not xml_files:
        console.print("  [yellow]No XML preference files found.[/yellow]")
        return

    for xml_file in xml_files:
        console.print(f"  [cyan]Checking:[/cyan] {xml_file.name}")
        try:
            content = xml_file.read_text(encoding="utf-8", errors="replace")
            config.log_command(PHASE, f"cat shared_prefs/{xml_file.name}", content[:2000])

            sensitive = _grep_string(content)
            if sensitive:
                config.add_finding(
                    PHASE,
                    f"Sensitive data in shared_prefs: {xml_file.name}",
                    "High",
                    f"File: {xml_file.name}\n\nMatches:\n{sensitive[:3000]}",
                )
                console.print(f"    [red]Sensitive data found in {xml_file.name}[/red]")
        except Exception as e:
            console.print(f"  [yellow]Error reading {xml_file.name}: {e}[/yellow]")


def _analyze_nosql(config: Config, adb: ADB, pkg: str, base_dir: str) -> None:
    console.print("\n[cyan]Checking for NoSQL / Realm databases...[/cyan]")

    extensions = ["*.realm", "*.json", "*.bson", "*.cblite2"]
    found_files: list[Path] = []
    base = Path(base_dir)
    for ext in extensions:
        found_files.extend(base.rglob(ext))

    if not found_files:
        # Try finding on device
        result = adb.shell(f"find /data/data/{pkg} -name '*.realm' -o -name '*.json' -o -name '*.bson' 2>/dev/null", root=True)
        config.log_command(PHASE, f"find /data/data/{pkg} -name '*.realm' ...", result.stdout)
        if result.stdout.strip():
            console.print(f"  [yellow]NoSQL files found on device:[/yellow]\n{result.stdout}")
        else:
            console.print("  [green]No NoSQL database files found.[/green]")
        return

    for f in found_files:
        console.print(f"  [cyan]Found:[/cyan] {f}")
        try:
            result = subprocess.run(
                ["strings", str(f)],
                capture_output=True, text=True, timeout=30,
            )
            sensitive = _grep_string(result.stdout)
            if sensitive:
                config.add_finding(
                    PHASE,
                    f"Sensitive data in NoSQL file: {f.name}",
                    "High",
                    f"File: {f}\n\nSensitive strings:\n{sensitive[:3000]}",
                )
        except FileNotFoundError:
            pass


def _check_file_permissions(config: Config, adb: ADB, pkg: str) -> None:
    console.print("\n[cyan]Checking file permissions...[/cyan]")

    # World-readable files
    result = adb.shell(
        f"find /data/data/{pkg} -type f -perm -o=r 2>/dev/null", root=True
    )
    if result.stdout.strip():
        config.add_finding(
            PHASE,
            "World-readable files in app data directory",
            "Medium",
            f"The following files are world-readable:\n{result.stdout[:3000]}",
        )
        config.log_command(PHASE, f"find /data/data/{pkg} -type f -perm -o=r", result.stdout)

    # World-writable files
    result = adb.shell(
        f"find /data/data/{pkg} -type f -perm -o=w 2>/dev/null", root=True
    )
    if result.stdout.strip():
        config.add_finding(
            PHASE,
            "World-writable files in app data directory",
            "High",
            f"The following files are world-writable:\n{result.stdout[:3000]}",
        )
        config.log_command(PHASE, f"find /data/data/{pkg} -type f -perm -o=w", result.stdout)


def _grep_string(text: str) -> str:
    """Run a case-insensitive regex search over a string for sensitive patterns."""
    import re
    matches = []
    for line in text.splitlines():
        if re.search(SENSITIVE_PATTERNS, line, re.IGNORECASE):
            matches.append(line.strip())
    return "\n".join(matches[:200])
